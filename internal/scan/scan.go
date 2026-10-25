// Package scan composes and executes explicit collection requests independently of the CLI.
package scan

import (
	"context"
	"fmt"

	"ciphertrail/internal/inventory"
)

// Request associates a collector with its user-selected target and report identity.
type Request struct {
	Name, Target string
	Collector    inventory.Collector
}

// Run accounts for every requested target and preserves partial collection results.
func Run(ctx context.Context, requests []Request) []inventory.Collection {
	collections := make([]inventory.Collection, 0, len(requests))
	for _, request := range requests {
		collection := inventory.Collection{Collector: request.Name, Target: request.Target}
		if err := ctx.Err(); err != nil {
			collection.Err = err
		} else if request.Collector == nil {
			collection.Err = fmt.Errorf("scan request has no collector")
		} else {
			collection.Result, collection.Err = request.Collector.Collect(ctx)
		}
		if request.Name == "tls" || request.Name == "ssh" {
			status := "completed"
			if collection.Err != nil {
				status = "failed"
			}
			refs := map[string]bool{}
			for _, entry := range collection.Result.Entries {
				if entry.Component.CryptoProperties != nil {
					refs[entry.Component.BOMRef] = true
				}
			}
			collection.Result.Coverage = append(collection.Result.Coverage,
				inventory.Coverage{Analyzer: request.Name, Status: status, Findings: len(refs)})
		}
		collections = append(collections, collection)
	}
	return collections
}
