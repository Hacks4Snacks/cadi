// Package detect dispatches bounded file inputs to explicitly registered detectors.
package detect

import (
	"context"
	"errors"
	"fmt"

	"ciphertrail/internal/input"
	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Detector identifies a file format without owning input acquisition or export.
type Detector interface {
	Name() string
	Match(*input.File, []byte) Match
	Detect(context.Context, *input.File) (inventory.Result, bool, error)
}

// Match distinguishes applicable content from content that requires preparation.
type Match struct {
	Applicable bool
	Deferred   string
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
	coverage := map[string]*inventory.Coverage{}
	recognizedFiles := map[string]int{}
	findingRefs := map[string]map[string]bool{}
	for _, detector := range c.Detectors {
		if detector == nil || detector.Name() == "" {
			return findings, fmt.Errorf("file detector must have a name")
		}
		names = append(names, detector.Name())
		coverage[detector.Name()] = &inventory.Coverage{Analyzer: detector.Name(), Status: "not-applicable"}
		findingRefs[detector.Name()] = map[string]bool{}
	}
	if c.Fallback != nil && coverage[c.Fallback.Name()] == nil {
		return findings, fmt.Errorf("fallback detector must be registered")
	}
	detectFile := func(detector Detector, file *input.File) (bool, error) {
		partial, recognized, err := detector.Detect(ctx, file)
		findings.Merge(partial)
		stats := coverage[detector.Name()]
		stats.Files++
		if recognized {
			recognizedFiles[detector.Name()]++
		}
		for _, entry := range partial.Entries {
			if entry.Component.Type == cdx.ComponentTypeCryptographicAsset {
				findingRefs[detector.Name()][entry.Component.BOMRef] = true
			}
		}
		if err != nil {
			stats.Status = "failed"
			return recognized, fmt.Errorf("%s detection: %w", detector.Name(), err)
		}
		return recognized, nil
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
			match := detector.Match(file, prefix)
			if match.Deferred != "" {
				coverage[detector.Name()].Skipped++
				coverage[detector.Name()].Reason = match.Deferred
				continue
			}
			if !match.Applicable {
				continue
			}
			recognized, err := detectFile(detector, file)
			fallbackTried = fallbackTried || c.Fallback != nil && detector.Name() == c.Fallback.Name()
			found = found || recognized
			if err != nil {
				failures = errors.Join(failures, err)
			}
		}
		if file.Explicit && !found && failures == nil && c.Fallback != nil && !fallbackTried {
			found, failures = detectFile(c.Fallback, file)
		}
		if file.Explicit && !found && failures == nil {
			return fmt.Errorf("no supported assets for the selected detectors in %s", file.Evidence.Location)
		}
		return failures
	})
	acquired.Merge(findings)
	for _, name := range names {
		stats := coverage[name]
		stats.Findings = len(findingRefs[name])
		if stats.Status != "failed" {
			switch {
			case stats.Skipped > 0:
				stats.Status = "needs-rendering"
			case recognizedFiles[name] > 0:
				stats.Status = "completed"
			default:
				stats.Status = "not-applicable"
				stats.Reason = "no recognized inputs"
			}
		}
		acquired.Coverage = append(acquired.Coverage, *stats)
	}
	return acquired, errors.Join(err, ctx.Err())
}
