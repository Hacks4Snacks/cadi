package scan

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"cadi/internal/export/cyclonedx"
	"cadi/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestScanReportKeepsStructuredRunDetailsOutOfCBOM(t *testing.T) {
	var result inventory.Result
	result.Metadata("build-context", map[string]string{"GOOS": "linux", "GOARCH": "amd64"})
	result.Metadata("source-exclusion-paths", []string{"fixtures", "examples"})
	result.Metadata("literal", `{"this":"remains a string"}`)
	result.Metadata("source-exclusion-paths", []string{"fixtures", "examples"})
	result.Coverage = []inventory.Coverage{{Analyzer: "go", Status: "completed", Files: 2, Findings: 1}}
	result.Diagnostics = []inventory.Diagnostic{{Location: "app.go", Line: 2, Message: "RUN_DIAGNOSTIC"}}
	result.Add(inventory.Algorithm("SHA-256", cdx.CryptoPrimitiveHash), inventory.Evidence{Kind: "configured", Location: "app.go", Line: 1}, "")
	result.Add(cdx.Component{Type: cdx.ComponentTypeLibrary, Name: "unrelated"}, inventory.Evidence{}, "")
	collections := []inventory.Collection{{Collector: "repository", Target: "/local/RUN_TARGET", Result: result}}
	bom, err := cyclonedx.EncodeWithOptions(collections, cyclonedx.EncodeOptions{ToolVersion: "1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := EncodeReport(collections, ReportOptions{CBOM: bom, ToolVersion: "1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bom), "RUN_DIAGNOSTIC") || strings.Contains(string(bom), "RUN_TARGET") {
		t.Fatal("execution details remain in the CBOM")
	}
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.ReportFormat != inventory.ScanReportFormat || report.ReportVersion != 1 || report.Status != "succeeded" ||
		report.Tool.Version != "1.2.3" || report.Statistics.CollectedComponents != 2 ||
		report.Statistics.OmittedComponents == nil || *report.Statistics.OmittedComponents != 1 ||
		report.Statistics.CryptographicAssets == nil || *report.Statistics.CryptographicAssets != 1 {
		t.Fatalf("incorrect report identity or statistics: %+v", report)
	}
	if len(report.Collections) != 1 || report.Collections[0].Target != "/local/RUN_TARGET" ||
		len(report.Collections[0].Details) != 3 || !reflect.DeepEqual(report.Collections[0].Coverage, result.Coverage) ||
		!reflect.DeepEqual(report.Collections[0].Diagnostics, result.Diagnostics) {
		t.Fatalf("run context was lost: %+v", report.Collections)
	}
	details := map[string]json.RawMessage{}
	for _, detail := range report.Collections[0].Details {
		details[detail.Name] = detail.Value
	}
	var build map[string]string
	var exclusions []string
	var literal string
	if json.Unmarshal(details["build-context"], &build) != nil || build["GOOS"] != "linux" ||
		json.Unmarshal(details["source-exclusion-paths"], &exclusions) != nil || len(exclusions) != 2 ||
		json.Unmarshal(details["literal"], &literal) != nil || literal != `{"this":"remains a string"}` {
		t.Fatal("metadata types were lost or inferred from string contents")
	}
	if len(result.Details) != 4 {
		t.Fatal("report construction modified collector metadata")
	}
}

func TestScanReportPreservesPartialAndOutputFailures(t *testing.T) {
	collections := []inventory.Collection{{Collector: "go", Target: "example", Err: errors.New("load failure")}}
	bom, err := cyclonedx.Encode(collections)
	if err != nil {
		t.Fatal(err)
	}
	for _, options := range []ReportOptions{
		{CBOM: bom},
		{OutputError: errors.New("CBOM encoding failed")},
		{CBOM: bom, OutputError: errors.New("CBOM write failed")},
	} {
		data, err := EncodeReport(collections, options)
		if err != nil {
			t.Fatal(err)
		}
		var report Report
		if err := json.Unmarshal(data, &report); err != nil {
			t.Fatal(err)
		}
		if report.Status != "incomplete" || report.Collections[0].Error != "load failure" ||
			report.Collections[0].Status != "incomplete" || (report.OutputError != "") != (options.OutputError != nil) {
			t.Fatalf("failure was lost: %+v", report)
		}
		if (report.BOMLink != "") != (len(options.CBOM) != 0) {
			t.Fatal("report lost its generated CBOM link or invented one after encoding failure")
		}
	}
}

func TestScanReportRejectsInvalidCBOMIdentity(t *testing.T) {
	for _, data := range []string{
		`{"version":1}`,
		`{"serialNumber":"not-a-uuid","version":1}`,
		`{"serialNumber":"urn:uuid:63304c0b-0d43-43cb-b0a7-f75b4b7ecf98","version":0}`,
	} {
		if _, err := EncodeReport(nil, ReportOptions{CBOM: []byte(data)}); err == nil {
			t.Fatal("invalid CBOM identity produced a success-shaped report")
		}
	}
}

func TestRunMetadataEncodingErrorsAreNotSilent(t *testing.T) {
	var result inventory.Result
	result.Metadata("invalid", make(chan int))
	if result.Err() == nil || len(result.Details) != 0 {
		t.Fatal("unencodable run metadata was accepted")
	}
}
