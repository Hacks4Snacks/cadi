package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"ciphertrail/internal/export/cyclonedx"
	"ciphertrail/internal/inventory"
	"ciphertrail/internal/scan"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func readScanReport(t *testing.T, path string) scan.Report {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report scan.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	return report
}

func TestReportIdentityAndPrimarySubject(t *testing.T) {
	for _, scenario := range []string{"go", "nested-modules", "single-nested-module", "workspace", "no-crypto", "python", "overlap", "two-roots", "mixed-languages", "failed-additional-root"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			paths := []string{root}
			expectedName := "example.test/subject"
			expectedType := cdx.ComponentTypeLibrary
			exit := 0
			if scenario == "python" {
				writeRepositoryFile(t, root, "app.py", "import hashlib\nhashlib.sha256(b'value')\n")
				expectedName, expectedType = filepath.Base(root)+" (Python source)", cdx.ComponentTypeApplication
			} else if scenario == "workspace" || scenario == "single-nested-module" {
				writeRepositoryFile(t, root, "child/go.mod", "module example.test/child\n\ngo 1.27.0\n")
				writeRepositoryFile(t, root, "child/main.go", "package child\nimport \"crypto/sha256\"\nfunc Run() { _ = sha256.Sum256(nil) }\n")
				expectedName = "example.test/child"
				if scenario == "workspace" {
					writeRepositoryFile(t, root, "second/go.mod", "module example.test/second\n\ngo 1.27.0\n")
					writeRepositoryFile(t, root, "second/main.go", "package second\nimport \"crypto/sha512\"\nfunc Run() { _ = sha512.Sum512(nil) }\n")
					writeRepositoryFile(t, root, "go.work", "go 1.27.0\nuse (\n./child\n./second\n)\n")
					expectedName = ""
				}
			} else {
				writeRepositoryFile(t, root, "go.mod", "module example.test/subject\n\ngo 1.27.0\n")
				source := "package subject\nimport \"crypto/sha256\"\nfunc Run() { _ = sha256.Sum256(nil) }\n"
				if scenario == "no-crypto" {
					source = "package subject\nfunc Run() {}\n"
				}
				writeRepositoryFile(t, root, "main.go", source)
			}
			switch scenario {
			case "nested-modules":
				writeRepositoryFile(t, root, "child/go.mod", "module example.test/child\n\ngo 1.27.0\n")
				writeRepositoryFile(t, root, "child/main.go", "package child\nimport \"crypto/sha512\"\nfunc Run() { _ = sha512.Sum512(nil) }\n")
			case "overlap":
				paths = append(paths, filepath.Join(root, "main.go"))
			case "two-roots":
				second := t.TempDir()
				writeRepositoryFile(t, second, "go.mod", "module example.test/second\n\ngo 1.27.0\n")
				writeRepositoryFile(t, second, "main.go", "package second\nimport \"crypto/sha512\"\nfunc Run() { _ = sha512.Sum512(nil) }\n")
				paths, expectedName = append(paths, second), ""
			case "mixed-languages":
				writeRepositoryFile(t, root, "app.py", "import hashlib\nhashlib.sha256(b'value')\n")
				expectedName = ""
			case "failed-additional-root":
				paths = append(paths, filepath.Join(t.TempDir(), "missing"))
				expectedName, exit = "", 1
			}
			for _, full := range []bool{false, true} {
				reportPath := filepath.Join(t.TempDir(), "scan.json")
				args := append([]string{"scan", "--offline", "--summary", "--analyzers", "go,python", "--scan-report", reportPath}, paths...)
				if full {
					args = append(args, "--include-dependencies")
				}
				var stdout, stderr bytes.Buffer
				if code := Run(context.Background(), args, &stdout, &stderr); code != exit {
					t.Fatalf("scan returned %d; want %d: %s", code, exit, stderr.String())
				}
				var bom cdx.BOM
				if err := json.Unmarshal(stdout.Bytes(), &bom); err != nil {
					t.Fatal(err)
				}
				subject := bom.Metadata.Component
				if expectedName == "" {
					if subject != nil {
						t.Errorf("ambiguous input was assigned an invented primary subject: %+v", subject)
					}
				} else if subject == nil || subject.Name != expectedName || subject.Type != expectedType || subject.BOMRef == "" {
					t.Errorf("primary subject missing or incorrect: %+v", subject)
				}
				components := map[string]cdx.Component{}
				if subject != nil {
					components[subject.BOMRef] = *subject
				}
				crypto := 0
				for _, component := range *bom.Components {
					if _, duplicate := components[component.BOMRef]; duplicate {
						t.Errorf("subject duplicated in components: %s", component.BOMRef)
					}
					components[component.BOMRef] = component
					if component.Type == cdx.ComponentTypeCryptographicAsset {
						crypto++
					}
				}
				for _, dependency := range *bom.Dependencies {
					if _, exists := components[dependency.Ref]; !exists {
						t.Errorf("dependency source missing: %s", dependency.Ref)
					}
					for _, ref := range *dependency.Dependencies {
						if _, exists := components[ref]; !exists {
							t.Errorf("dependency target missing: %s", ref)
						}
					}
				}
				data, err := os.ReadFile(reportPath)
				if err != nil {
					t.Fatal(err)
				}
				var report struct {
					BOMLink    string
					Tool       scan.ReportTool
					Statistics scan.ReportStatistics
				}
				if err := json.Unmarshal(data, &report); err != nil {
					t.Fatal(err)
				}
				link, err := cdx.NewBOMLink(bom.SerialNumber, bom.Version, nil)
				if err != nil || report.BOMLink != link.String() {
					t.Errorf("scan report is not linked to this CBOM: %q, %v", report.BOMLink, err)
				}
				if report.Tool.Version != (*bom.Metadata.Tools.Components)[0].Version {
					t.Error("scanner versions differ between output artifacts")
				}
				if report.Statistics.ExportedComponents == nil || *report.Statistics.ExportedComponents != len(components) ||
					report.Statistics.CryptographicAssets == nil || *report.Statistics.CryptographicAssets != crypto {
					t.Errorf("subject promotion corrupted report statistics: %+v", report.Statistics)
				}
			}
		})
	}
}

func TestSummaryResolvesMetadataSubjectReferences(t *testing.T) {
	var result inventory.Result
	provider := result.Add(cdx.Component{Type: cdx.ComponentTypeLibrary, Name: "crypto-provider"}, inventory.Evidence{}, "")
	result.Subjects = []string{provider}
	hash := result.Add(inventory.Algorithm("SHA-256", cdx.CryptoPrimitiveHash),
		inventory.Evidence{Kind: "configured", Collector: "go", Location: "hash.go", Line: 3}, provider)
	result.DependOn(hash, provider)
	data, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
	if err != nil {
		t.Fatal(err)
	}
	var summary bytes.Buffer
	if err := writeSummary(&summary, data, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary.String(), "Cryptographic findings: 1") ||
		!strings.Contains(summary.String(), "crypto-provider") {
		t.Fatal("primary library was lost as implementation context or counted as a crypto finding")
	}
}

func TestCLISeparateScanReportAndCompactCBOM(t *testing.T) {
	root := t.TempDir()
	writeRepositoryFile(t, root, "certificate.yaml", "apiVersion: cert-manager.io/v1\nkind: Certificate\nmetadata: {name: example}\nspec: {}\n")
	cbomPath, reportPath := filepath.Join(root, "cbom.json"), filepath.Join(root, "scan.json")
	for range 2 {
		var stdout, stderr bytes.Buffer
		code := Run(context.Background(), []string{"scan", root, "--offline", "--output", cbomPath, "--scan-report", reportPath}, &stdout, &stderr)
		if code != 0 || stdout.Len() != 0 {
			t.Fatalf("dual output failed: %d %s", code, stderr.String())
		}
		data, err := os.ReadFile(cbomPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := cyclonedx.Validate(data); err != nil {
			t.Fatal(err)
		}
		var bom cdx.BOM
		if err := json.Unmarshal(data, &bom); err != nil {
			t.Fatal(err)
		}
		header, _ := json.Marshal(bom.Metadata)
		if strings.Contains(string(header), root) || strings.Contains(string(header), "ciphertrail:collection\"") {
			t.Fatal("run context leaked into the CBOM header")
		}
		report := readScanReport(t, reportPath)
		if report.ReportFormat != inventory.ScanReportFormat || len(report.Collections) != 1 || report.Status != "succeeded" ||
			report.Statistics.CryptographicAssets == nil || *report.Statistics.CryptographicAssets != 1 {
			t.Fatalf("missing scan report detail: %+v", report)
		}
		if report.Tool.Version != (*bom.Metadata.Tools.Components)[0].Version || report.Timestamp != bom.Metadata.Timestamp {
			t.Fatal("CBOM and report identify different scanner runs")
		}
	}
}

func TestScanReportOutputSafety(t *testing.T) {
	for _, scenario := range []string{"same-output", "input", "unrelated", "symlink", "hardlink", "cbom-as-report", "report-as-cbom", "shared-output-hardlink", "stdout", "empty"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			input := filepath.Join(root, "source.yaml")
			content := "apiVersion: cert-manager.io/v1\nkind: Certificate\nmetadata: {name: example}\nspec: {}\n"
			writeRepositoryFile(t, root, "source.yaml", content)
			output, report := filepath.Join(root, "cbom.json"), filepath.Join(root, "report.json")
			switch scenario {
			case "same-output":
				report = output
			case "input":
				report = input
			case "unrelated":
				writeRepositoryFile(t, root, "report.json", "important unrelated data")
			case "symlink":
				if err := os.Symlink(input, report); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(input, report); err != nil {
					t.Fatal(err)
				}
			case "cbom-as-report":
				writeRepositoryFile(t, root, "report.json", `{"bomFormat":"CycloneDX","metadata":{"tools":{"components":[{"name":"ciphertrail"}]}}}`)
			case "report-as-cbom":
				writeRepositoryFile(t, root, "cbom.json", `{"reportFormat":"CipherTrailScanReport","reportVersion":1,"tool":{"name":"ciphertrail"}}`)
			case "shared-output-hardlink":
				writeRepositoryFile(t, root, "cbom.json", `{"bomFormat":"CycloneDX","metadata":{"tools":{"components":[{"name":"ciphertrail"}]}},"reportFormat":"CipherTrailScanReport","reportVersion":1,"tool":{"name":"ciphertrail"}}`)
				if err := os.Link(output, report); err != nil {
					t.Fatal(err)
				}
			case "stdout":
				report = "-"
			case "empty":
				report = ""
			}
			previousOutput, previousErr := os.ReadFile(output)
			var stdout, stderr bytes.Buffer
			args := []string{"scan", input, "--output", output, "--scan-report=" + report}
			if code := Run(context.Background(), args, &stdout, &stderr); code == 0 {
				t.Fatal("unsafe report output was accepted")
			}
			after, err := os.ReadFile(input)
			if err != nil || string(after) != content {
				t.Fatal("input was modified")
			}
			if scenario == "unrelated" {
				after, err := os.ReadFile(report)
				if err != nil || string(after) != "important unrelated data" {
					t.Fatal("unrelated output was overwritten")
				}
			}
			if previousErr == nil {
				currentOutput, err := os.ReadFile(output)
				if err != nil || !bytes.Equal(previousOutput, currentOutput) {
					t.Fatal("invalid report output overwrote the existing CBOM destination")
				}
			} else if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("invalid report output created a CBOM anyway")
			}
		})
	}
}

func TestScanReportSurvivesPartialCollectionAndOutputFailure(t *testing.T) {
	root := t.TempDir()
	reportPath := filepath.Join(root, "report.json")
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"scan", filepath.Join(root, "missing.yaml"), "--scan-report", reportPath}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("partial collection returned %d", code)
	}
	if report := readScanReport(t, reportPath); report.Status != "incomplete" || report.Collections[0].Error == "" {
		t.Fatal("collection failure was lost")
	}
	writeRepositoryFile(t, root, "source.txt", "no crypto")
	stderr.Reset()
	code = Run(context.Background(), []string{"scan", root, "--scan-report", reportPath}, summaryFailingWriter{}, &stderr)
	if code != 1 {
		t.Fatalf("CBOM output failure returned %d", code)
	}
	if report := readScanReport(t, reportPath); report.Status != "incomplete" || !strings.Contains(report.OutputError, "CBOM") {
		t.Fatal("output failure was not recorded")
	}
}

func TestRenderedInputGapsRemainVisibleAlongsideFindings(t *testing.T) {
	root := t.TempDir()
	writeRepositoryFile(t, root, "chart/Chart.yaml", "apiVersion: v2\nname: fixture\nversion: 1.0.0\n")
	writeRepositoryFile(t, root, "chart/templates/raw.yaml", "{{ template requiring rendering }}")
	writeRepositoryFile(t, root, "rendered.yaml", "apiVersion: cert-manager.io/v1\nkind: Certificate\nmetadata: {name: example}\nspec: {}\n")
	reportPath := filepath.Join(t.TempDir(), "scan.json")
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"scan", root, "--scan-report", reportPath}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "rendered inputs required") {
		t.Fatalf("partial rendering coverage was hidden: %d %s", code, stderr.String())
	}
	report := readScanReport(t, reportPath)
	for _, coverage := range report.Collections[0].Coverage {
		if coverage.Analyzer == "kubernetes" {
			if coverage.Status != "needs-rendering" || coverage.Findings != 1 || coverage.Skipped == 0 {
				t.Fatalf("incorrect rendering status: %+v", coverage)
			}
			return
		}
	}
	t.Fatal("Kubernetes coverage missing from scan report")
}

func TestExplicitToolVersionIsConsistent(t *testing.T) {
	before := Version
	Version = "1.2.3"
	t.Cleanup(func() { Version = before })
	var version, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"version"}, &version, &stderr); code != 0 || version.String() != "ciphertrail 1.2.3\n" {
		t.Fatal("CLI ignored the explicit build version")
	}
	root := t.TempDir()
	writeRepositoryFile(t, root, "source.txt", "no cryptography")
	reportPath := filepath.Join(t.TempDir(), "scan.json")
	var stdout bytes.Buffer
	if code := Run(context.Background(), []string{"scan", root, "--scan-report", reportPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("scan failed: %s", stderr.String())
	}
	var bom cdx.BOM
	if err := json.Unmarshal(stdout.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	if (*bom.Metadata.Tools.Components)[0].Version != "1.2.3" || readScanReport(t, reportPath).Tool.Version != "1.2.3" {
		t.Fatal("CBOM/report scanner versions differ from the CLI")
	}
}

func TestToolVersionPrefersReleaseThenBuildIdentity(t *testing.T) {
	for _, test := range []struct {
		name, version string
		info          *debug.BuildInfo
		want          string
	}{
		{"release", "1.2.3", &debug.BuildInfo{}, "1.2.3"},
		{"module", "dev", &debug.BuildInfo{Main: debug.Module{Version: "v1.2.4"}}, "v1.2.4"},
		{"revision", "dev", &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "0123456789abcdef"}}}, "dev+0123456789ab"},
		{"dirty", "dev", &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "0123456789abcdef"}, {Key: "vcs.modified", Value: "true"}}}, "dev+0123456789ab.dirty"},
		{"unknown", "dev", nil, "dev"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := versionFromBuildInfo(test.version, test.info); got != test.want {
				t.Fatalf("version=%q; want %q", got, test.want)
			}
		})
	}
}
