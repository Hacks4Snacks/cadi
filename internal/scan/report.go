package scan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Report is a structured execution record, separate from cryptographic inventory.
type Report struct {
	ReportFormat  string             `json:"reportFormat"`
	ReportVersion int                `json:"reportVersion"`
	Timestamp     string             `json:"timestamp"`
	Tool          ReportTool         `json:"tool"`
	Status        string             `json:"status"`
	OutputScope   string             `json:"outputScope"`
	OutputError   string             `json:"outputError,omitempty"`
	Statistics    ReportStatistics   `json:"statistics"`
	Collections   []CollectionReport `json:"collections"`
}

// ReportTool identifies the scanner build that produced the report.
type ReportTool struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// ReportStatistics distinguishes collected context from exported inventory.
type ReportStatistics struct {
	CollectedComponents int  `json:"collectedComponents"`
	ExportedComponents  *int `json:"exportedComponents,omitempty"`
	OmittedComponents   *int `json:"omittedComponents,omitempty"`
	CryptographicAssets *int `json:"cryptographicAssets,omitempty"`
}

// CollectionReport retains the outcome and public execution details of one input.
type CollectionReport struct {
	Collector   string                  `json:"collector"`
	Target      string                  `json:"target"`
	Status      string                  `json:"status"`
	Error       string                  `json:"error,omitempty"`
	Details     []inventory.RunMetadata `json:"details,omitempty"`
	Diagnostics []inventory.Diagnostic  `json:"diagnostics,omitempty"`
	Coverage    []inventory.Coverage    `json:"coverage,omitempty"`
}

// ReportOptions links execution details to the generated CBOM or its output failure.
type ReportOptions struct {
	ToolVersion         string
	IncludeDependencies bool
	CBOM                []byte
	OutputError         error
}

// EncodeReport preserves detailed outcomes without adding them to the CBOM.
func EncodeReport(collections []inventory.Collection, options ReportOptions) ([]byte, error) {
	if len(options.CBOM) == 0 && options.OutputError == nil {
		return nil, errors.New("scan report requires a generated CBOM or an output failure")
	}
	report := Report{
		ReportFormat: inventory.ScanReportFormat, ReportVersion: 1,
		Timestamp: time.Now().UTC().Format(time.RFC3339), Tool: ReportTool{Name: "ciphertrail", Version: options.ToolVersion},
		Status: "succeeded", OutputScope: "crypto-focused", Collections: []CollectionReport{},
	}
	if options.IncludeDependencies {
		report.OutputScope = "full-dependencies"
	}
	if options.OutputError != nil {
		report.Status, report.OutputError = "incomplete", options.OutputError.Error()
	}
	collected := map[string]bool{}
	for _, collection := range collections {
		outcome := CollectionReport{
			Collector: collection.Collector, Target: collection.Target, Status: "succeeded",
			Details: slices.Clone(collection.Result.Details), Diagnostics: collection.Result.Diagnostics,
			Coverage: collection.Result.Coverage,
		}
		if err := errors.Join(collection.Err, collection.Result.Err()); err != nil {
			outcome.Status, outcome.Error, report.Status = "incomplete", err.Error(), "incomplete"
		}
		slices.SortFunc(outcome.Details, func(a, b inventory.RunMetadata) int {
			if order := strings.Compare(a.Name, b.Name); order != 0 {
				return order
			}
			return bytes.Compare(a.Value, b.Value)
		})
		outcome.Details = slices.CompactFunc(outcome.Details, func(a, b inventory.RunMetadata) bool {
			return a.Name == b.Name && bytes.Equal(a.Value, b.Value)
		})
		report.Collections = append(report.Collections, outcome)
		for _, entry := range collection.Result.Entries {
			if entry.Component.BOMRef != "" {
				collected[entry.Component.BOMRef] = true
			}
		}
	}
	report.Statistics.CollectedComponents = len(collected)
	if len(options.CBOM) > 0 {
		var bom cdx.BOM
		if err := json.Unmarshal(options.CBOM, &bom); err != nil {
			return nil, fmt.Errorf("read generated CBOM statistics: %w", err)
		}
		if bom.Metadata != nil && bom.Metadata.Timestamp != "" {
			report.Timestamp = bom.Metadata.Timestamp
		}
		exported, crypto := 0, 0
		if bom.Components != nil {
			exported = len(*bom.Components)
			for _, component := range *bom.Components {
				if component.Type == cdx.ComponentTypeCryptographicAsset {
					crypto++
				}
			}
		}
		omitted := len(collected) - exported
		if omitted < 0 {
			return nil, errors.New("CBOM contains more components than the collected inventory")
		}
		report.Statistics.ExportedComponents = &exported
		report.Statistics.OmittedComponents = &omitted
		report.Statistics.CryptographicAssets = &crypto
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode scan report: %w", err)
	}
	return append(data, '\n'), nil
}
