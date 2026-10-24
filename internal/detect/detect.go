// Package detect dispatches bounded file inputs to explicitly registered detectors.
package detect

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"ciphertrail/internal/input"
	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Detector identifies a file format without owning input acquisition or export.
type Detector interface {
	Name() string
	Match(*input.File, []byte) bool
	Detect(context.Context, *input.File) (inventory.Result, bool, error)
}

// Collector applies all matching detectors while preserving independent failures.
// Fallback may inspect otherwise unrecognized explicit files, but never directory entries.
type Collector struct {
	Source    input.Source
	Detectors []Detector
	Fallback  Detector
}

// Collect returns input metadata and detector findings, including partial results.
func (c Collector) Collect(ctx context.Context) (inventory.Result, error) {
	var findings inventory.Result
	if c.Source == nil || len(c.Detectors) == 0 {
		return findings, fmt.Errorf("file collection requires an input and at least one detector")
	}
	if c.Fallback != nil && c.Fallback.Name() == "" {
		return findings, fmt.Errorf("fallback detector must have a name")
	}
	var names []string
	for _, detector := range c.Detectors {
		if detector == nil || detector.Name() == "" {
			return findings, fmt.Errorf("file detector must have a name")
		}
		names = append(names, detector.Name())
	}
	acquired, err := c.Source.Walk(ctx, func(file *input.File) error {
		prefix, err := file.Prefix(ctx, 512)
		if err != nil {
			return err
		}
		found := false
		var failures error
		fallbackTried := false
		for _, detector := range c.Detectors {
			if err := ctx.Err(); err != nil {
				return errors.Join(failures, err)
			}
			if !detector.Match(file, prefix) {
				continue
			}
			partial, recognized, err := detector.Detect(ctx, file)
			fallbackTried = fallbackTried || c.Fallback != nil && detector.Name() == c.Fallback.Name()
			findings.Merge(partial)
			found = found || recognized
			if err != nil {
				failures = errors.Join(failures, fmt.Errorf("%s detection: %w", detector.Name(), err))
			}
			if file.Explicit && !found && failures == nil && c.Fallback != nil && !fallbackTried {
				partial, recognized, err := c.Fallback.Detect(ctx, file)
				findings.Merge(partial)
				found = recognized
				if err != nil {
					failures = fmt.Errorf("%s detection: %w", c.Fallback.Name(), err)
				}
			}
		}
		if file.Explicit && !found && failures == nil {
			return fmt.Errorf("no supported assets for the selected detectors in %s", file.Evidence.Location)
		}
		return failures
	})
	acquired.Merge(findings)
	acquired.Properties = append(acquired.Properties, cdx.Property{
		Name: "ciphertrail:detectors", Value: strings.Join(names, ", "),
	})
	if len(acquired.Entries) == 0 && len(acquired.Diagnostics) == 0 && err == nil {
		acquired.Diagnostics = append(acquired.Diagnostics, inventory.Diagnostic{
			Message: "no supported assets found by the selected detectors",
		})
	}
	return acquired, errors.Join(err, ctx.Err())
}
