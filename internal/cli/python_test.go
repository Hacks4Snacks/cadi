package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"ciphertrail/internal/export/cyclonedx"
	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestPythonMixedRepositorySelectionAndOverlap(t *testing.T) {
	root := t.TempDir()
	writeRepositoryFile(t, root, "go.mod", "module example.test/pythonmixed\n\ngo 1.27.0\n")
	writeRepositoryFile(t, root, "main.go", "package example\nimport \"crypto/sha256\"\nfunc Run() { _ = sha256.Sum256(nil) }\n")
	writeRepositoryFile(t, root, "app.py", "import hashlib\nhashlib.sha384(b'private')\n")
	writeRepositoryFile(t, root, "certificate.yaml", "apiVersion: cert-manager.io/v1\nkind: Certificate\nmetadata: {name: example}\nspec: {}\n")
	for _, test := range []struct {
		analyzers        string
		goCode, py, cert bool
	}{
		{"", true, true, true},
		{"python", false, true, false},
		{"go,kubernetes", true, false, true},
	} {
		t.Run("analyzers="+test.analyzers, func(t *testing.T) {
			args := []string{"scan", root, "--offline"}
			if test.analyzers == "" {
				args = append(args, filepath.Join(root, "app.py"))
			} else {
				args = append(args, "--analyzers", test.analyzers)
			}
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), args, &stdout, &stderr); code != 0 {
				t.Fatalf("mixed Python scan failed: %d %s", code, stderr.String())
			}
			var bom cdx.BOM
			if err := json.Unmarshal(stdout.Bytes(), &bom); err != nil {
				t.Fatal(err)
			}
			counts := map[string]int{}
			for _, component := range *bom.Components {
				counts[component.Name]++
			}
			if (counts["SHA-256"] == 1) != test.goCode || (counts["SHA-384"] == 1) != test.py ||
				(counts["cert-manager Certificate configuration"] == 1) != test.cert {
				t.Fatalf("incorrect mixed findings: %v", counts)
			}
			if test.py && !strings.Contains(stderr.String(), "python=completed files=1") {
				t.Fatalf("Python coverage missing or work repeated: %s", stderr.String())
			}
		})
	}
}

func TestPythonSelectionsShareMutationFacts(t *testing.T) {
	for _, test := range []struct {
		name, app, patch string
		hmac             bool
	}{
		{
			name: "parameter",
			app: "import secrets\nimport hmac\nimport patch\n" +
				"hmac.new(secrets.token_bytes(32), b'message', digestmod='sha256')\n",
			patch: "import secrets\nsecrets.token_bytes = lambda n: b'x' * 16\n",
			hmac:  true,
		},
		{
			name: "constructor",
			app: "import requests\nimport patch\n" +
				"session = requests.Session()\nsession.get('https://example.test')\n",
			patch: "import requests\nrequests.Session = custom\n",
		},
		{
			name: "method",
			app: "import requests\nimport patch\n" +
				"session = requests.Session()\nsession.get('https://example.test')\n",
			patch: "import requests\nrequests.Session.get = custom\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeRepositoryFile(t, root, "app.py", test.app)
			writeRepositoryFile(t, root, "patch.py", test.patch)
			app, patch := filepath.Join(root, "app.py"), filepath.Join(root, "patch.py")
			for _, selection := range []struct {
				name  string
				paths []string
			}{
				{"directory", []string{root}},
				{"explicit-files", []string{app, patch}},
				{"reversed-files", []string{patch, app}},
				{"overlap", []string{root, app, patch}},
			} {
				t.Run(selection.name, func(t *testing.T) {
					args := append([]string{"scan", "--analyzers", "python", "--offline"}, selection.paths...)
					reportPath := filepath.Join(t.TempDir(), "scan.json")
					args = append(args, "--scan-report", reportPath)
					var stdout, stderr bytes.Buffer
					if code := Run(context.Background(), args, &stdout, &stderr); code != 0 {
						t.Fatalf("scan failed: %d %s", code, stderr.String())
					}
					var bom cdx.BOM
					if err := json.Unmarshal(stdout.Bytes(), &bom); err != nil {
						t.Fatal(err)
					}
					findings := 0
					for _, component := range *bom.Components {
						if component.Type != cdx.ComponentTypeCryptographicAsset {
							continue
						}
						findings++
						if !test.hmac || component.Name != "HMAC-SHA-256" {
							t.Errorf("mutated API produced a finding: %s", component.Name)
							continue
						}
						if component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier != "" {
							t.Error("mutated byte factory established an unconditional HMAC key size")
						}
						if component.Evidence == nil || component.Evidence.Occurrences == nil ||
							len(*component.Evidence.Occurrences) != 1 ||
							filepath.Base((*component.Evidence.Occurrences)[0].Location) != "app.py" {
							t.Error("source occurrence missing or duplicated")
						}
					}
					want := 0
					if test.hmac {
						want = 1
					}
					if findings != want {
						t.Errorf("crypto findings = %d; want %d", findings, want)
					}
					files, diagnostics := 0, 0
					targets := map[string]bool{}
					for _, collection := range readScanReport(t, reportPath).Collections {
						targets[collection.Target] = true
						diagnostics += len(collection.Diagnostics)
						for _, coverage := range collection.Coverage {
							if coverage.Analyzer == "python" {
								files += coverage.Files
							}
						}
					}
					if files != 2 || diagnostics == 0 {
						t.Errorf("work repeated or mutation diagnostics lost: files=%d diagnostics=%d", files, diagnostics)
					}
					for _, path := range selection.paths {
						resolved, err := filepath.EvalSymlinks(path)
						if err != nil {
							t.Fatal(err)
						}
						if !targets[resolved] {
							t.Errorf("requested input lost its collection context: %s", path)
						}
					}
				})
			}
		})
	}
}

func TestPythonSelectionsKeepIndependentScopes(t *testing.T) {
	root := t.TempDir()
	writeRepositoryFile(t, root, "app.py", "import secrets\nimport hmac\nhmac.new(secrets.token_bytes(32), b'message', digestmod='sha256')\n")
	writeRepositoryFile(t, root, "helper.py", "pass\n")
	writeRepositoryFile(t, root, "nested/.git", "gitdir: unused\n")
	writeRepositoryFile(t, root, "nested/patch.py", "import secrets\nsecrets.token_bytes = custom\n")
	writeRepositoryFile(t, root, "nested/helper.py", "pass\n")
	nested := filepath.Join(root, "nested")
	for _, selection := range []struct {
		name  string
		paths []string
	}{
		{"repositories", []string{root, nested}},
		{"explicit-files", []string{filepath.Join(root, "app.py"), filepath.Join(root, "helper.py"), filepath.Join(nested, "patch.py"), filepath.Join(nested, "helper.py")}},
		{"repository-and-nested-files", []string{root, filepath.Join(nested, "patch.py"), filepath.Join(nested, "helper.py")}},
		{"overlap", []string{root, nested, filepath.Join(nested, "patch.py")}},
	} {
		t.Run(selection.name, func(t *testing.T) {
			args := append([]string{"scan", "--analyzers", "python", "--offline"}, selection.paths...)
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), args, &stdout, &stderr); code != 0 {
				t.Fatalf("scan failed: %d %s", code, stderr.String())
			}
			var bom cdx.BOM
			if err := json.Unmarshal(stdout.Bytes(), &bom); err != nil {
				t.Fatal(err)
			}
			hmac := 0
			for _, component := range *bom.Components {
				if component.Name == "HMAC-SHA-256" {
					hmac++
					if component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier != "256" {
						t.Error("a separate repository's mutation invalidated the local key size")
					}
				}
			}
			if hmac != 1 {
				t.Fatalf("HMAC findings = %d; want 1", hmac)
			}
		})
	}
}

func TestPythonSharedAnalysisHonorsExplicitFilesAndExclusions(t *testing.T) {
	for _, excluded := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit-test-file", true: "hard-exclusion"}[excluded], func(t *testing.T) {
			root := t.TempDir()
			writeRepositoryFile(t, root, "app.py", "import secrets\nimport hmac\nhmac.new(secrets.token_bytes(32), b'message', digestmod='sha256')\n")
			writeRepositoryFile(t, root, "tests/patch.py", "import secrets\nsecrets.token_bytes = custom\n")
			if excluded {
				writeRepositoryFile(t, root, ".ciphertrailignore", "tests/\n")
			}
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), []string{"scan", root, filepath.Join(root, "tests/patch.py"),
				"--analyzers", "python", "--offline"}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("scan failed: %d %s", code, stderr.String())
			}
			var bom cdx.BOM
			if err := json.Unmarshal(stdout.Bytes(), &bom); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, component := range *bom.Components {
				if component.Name != "HMAC-SHA-256" {
					continue
				}
				found = true
				size := component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier
				if excluded && size != "256" || !excluded && size != "" {
					t.Errorf("selection did not preserve mutation scope: key size=%q", size)
				}
			}
			if !found {
				t.Fatal("HMAC finding lost")
			}
		})
	}
}

func TestPythonSharedAnalysisPreservesPartialFailures(t *testing.T) {
	root := t.TempDir()
	writeRepositoryFile(t, root, "app.py", "import hashlib\nhashlib.sha256(b'PRIVATE_INPUT')\n")
	writeRepositoryFile(t, root, "broken.py", "def broken(\n")
	reportPath := filepath.Join(t.TempDir(), "scan.json")
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"scan", filepath.Join(root, "app.py"), filepath.Join(root, "broken.py"),
		"--analyzers", "python", "--offline", "--summary", "--scan-report", reportPath}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "INCOMPLETE") {
		t.Fatalf("shared analysis hid a parser failure: %d %s", code, stderr.String())
	}
	var bom cdx.BOM
	if err := json.Unmarshal(stdout.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	hashes, files, failed := 0, 0, false
	for _, component := range *bom.Components {
		if component.Name == "SHA-256" {
			hashes++
		}
	}
	for _, collection := range readScanReport(t, reportPath).Collections {
		for _, coverage := range collection.Coverage {
			if coverage.Analyzer == "python" {
				files += coverage.Files
				failed = failed || coverage.Status == "failed" && collection.Status == "incomplete"
			}
		}
	}
	if hashes != 1 || files != 2 || !failed || strings.Contains(stdout.String(), "PRIVATE_INPUT") {
		t.Fatalf("incorrect partial report: hashes=%d files=%d failed=%v", hashes, files, failed)
	}
}

func TestPythonTruncationProducesIncompleteReportAndSummary(t *testing.T) {
	root := t.TempDir()
	source := "import hashlib\nhashlib.sha256(b'PRIVATE_SENTINEL')\nconsume(" + strings.Repeat("1,", 65) + ")\n"
	writeRepositoryFile(t, root, "app.py", source)
	reportPath := filepath.Join(t.TempDir(), "scan.json")
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"scan", root, "--analyzers", "python", "--offline", "--summary", "--scan-report", reportPath}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "Cryptographic findings: 1 (INCOMPLETE)") ||
		!strings.Contains(stdout.String(), `"value": "incomplete"`) || strings.Contains(stdout.String(), "PRIVATE_SENTINEL") {
		t.Fatalf("truncation had success-shaped output: exit=%d %s", code, stderr.String())
	}
	report := readScanReport(t, reportPath)
	if report.Status != "incomplete" || report.Collections[0].Coverage[0].Status != "failed" {
		t.Fatalf("scan report hid truncation: %+v", report)
	}
	if err := cyclonedx.Validate(stdout.Bytes()); err != nil {
		t.Fatal(err)
	}
}

func TestExplicitPythonFilesDoNotRequireArtifactFindings(t *testing.T) {
	root := t.TempDir()
	writeRepositoryFile(t, root, "app.py", "x = 1\n")
	writeRepositoryFile(t, root, "tests/test_app.py", "import hashlib\nhashlib.md5(b'test')\n")
	for _, name := range []string{"app.py", "tests/test_app.py"} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), []string{"scan", filepath.Join(root, name)}, &stdout, &stderr)
			if code != 0 || !strings.Contains(stderr.String(), "python=completed files=1") {
				t.Fatalf("explicit Python input fell through to an unrelated detector: %d %s", code, stderr.String())
			}
		})
	}
}

func TestPythonSharedScopeAndVirtualEnvironments(t *testing.T) {
	root := t.TempDir()
	writeRepositoryFile(t, root, "env/app.py", "import hashlib\nhashlib.sha256(b'production')\n")
	writeRepositoryFile(t, root, "environment/pyvenv.cfg", "home = /unused\n")
	writeRepositoryFile(t, root, ".ciphertrailignore", "ignored/\n")
	for _, path := range []string{
		"environment/dependency.py", "ignored/ignored.py", "excluded/excluded.py", "tests/fixture.py",
		"test_crypto.py", "crypto_test.py", "conftest.py",
	} {
		writeRepositoryFile(t, root, path, "import hashlib\nhashlib.md5(b'out-of-scope')\n")
	}
	reportPath := filepath.Join(t.TempDir(), "scan.json")
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"scan", root, "--analyzers", "python", "--exclude", "excluded", "--scan-report", reportPath}, &stdout, &stderr)
	reportData, err := json.Marshal(readScanReport(t, reportPath))
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 || !strings.Contains(stdout.String(), "SHA-256") || strings.Contains(stdout.String(), `"name": "MD5"`) ||
		!strings.Contains(stderr.String(), "files=1") || !strings.Contains(string(reportData), "python-virtual-environment") {
		t.Fatalf("Python scope was not honored: %d %s", code, stderr.String())
	}
}

func TestPythonHTTPSCLIUsesStaticSourceOnly(t *testing.T) {
	root := t.TempDir()
	writeRepositoryFile(t, root, "app.py", `import requests
def onboard(subscription, token):
    url = f"https://management.azure.com/subscriptions/{subscription}/providers/example?token=PRIVATE_URL"
    return requests.get(url, headers={"Authorization": token}, timeout=60)
`)
	writeRepositoryFile(t, root, "hash.py", "import hashlib\nhashlib.sha256(b'PRIVATE_INPUT')\n")
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"scan", root, filepath.Join(root, "app.py"), "--analyzers", "python", "--offline"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("HTTPS analysis failed: %d %s", code, stderr.String())
	}
	var bom cdx.BOM
	if err := json.Unmarshal(stdout.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	tls, hashes := 0, 0
	for _, component := range *bom.Components {
		if component.Name == "Python HTTPS request configuration" {
			tls++
			if component.Evidence == nil || component.Evidence.Occurrences == nil || (*component.Evidence.Occurrences)[0].Location != "app.py" {
				t.Fatal("HTTPS source occurrence missing")
			}
		}
		if component.Name == "SHA-256" {
			hashes++
		}
	}
	if tls != 1 || hashes != 1 || strings.Contains(stdout.String(), "PRIVATE_") ||
		strings.Contains(stdout.String(), "management.azure.com") || !strings.Contains(stderr.String(), "files=2") {
		t.Fatalf("findings lost, duplicated, or exposed request data: TLS=%d hashes=%d %s", tls, hashes, stderr.String())
	}
}

func TestPythonCryptoSummaryPreservesJSON(t *testing.T) {
	root := t.TempDir()
	writeRepositoryFile(t, root, "app.py", "import requests\nrequests.get('https://example.invalid/PRIVATE_URL')\n")
	for _, summary := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "summary"}[summary], func(t *testing.T) {
			args := []string{"scan", root, "--analyzers", "python", "--offline"}
			if summary {
				args = append(args, "--summary", "--include-dependencies")
			}
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), args, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("scan failed: %d %s", code, stderr.String())
			}
			var bom cdx.BOM
			if err := json.Unmarshal(stdout.Bytes(), &bom); err != nil {
				t.Fatalf("summary polluted JSON stdout: %v", err)
			}
			crypto, libraries := 0, 0
			for _, component := range *bom.Components {
				if component.Type == cdx.ComponentTypeCryptographicAsset {
					crypto++
				}
				if component.Type == cdx.ComponentTypeLibrary && component.Name == "requests" {
					libraries++
				}
			}
			if crypto != 1 || libraries != 1 {
				t.Fatalf("summary changed the JSON graph: crypto=%d libraries=%d", crypto, libraries)
			}
			if !summary {
				if strings.Contains(stderr.String(), "Cryptographic findings:") {
					t.Fatal("summary must remain opt-in")
				}
				return
			}
			if !strings.Contains(stderr.String(), "Cryptographic findings: 1") ||
				strings.Count(stderr.String(), "Python HTTPS request configuration") != 1 ||
				strings.Count(stderr.String(), "requests") != 1 ||
				!strings.Contains(stderr.String(), "app.py:2") ||
				!strings.Contains(stderr.String(), "configured") ||
				strings.Contains(stderr.String(), "PRIVATE_") {
				t.Fatalf("summary does not show one qualified crypto finding: %s", stderr.String())
			}
		})
	}
}

func TestCryptoSummaryGroupsEvidenceAndEscapesCells(t *testing.T) {
	var result inventory.Result
	providerRef := result.Add(cdx.Component{Type: cdx.ComponentTypeLibrary, Name: "requests\tlibrary"},
		inventory.Evidence{Kind: "configured"}, "")
	asset := inventory.Algorithm("TLS\tconfig\n\x1b[31m", cdx.CryptoPrimitiveOther)
	asset.BOMRef = result.Add(asset, inventory.Evidence{Kind: "configured", Location: "z.py", Line: 12}, "")
	result.Add(asset, inventory.Evidence{Kind: "present", Location: "a.pem"}, "")
	result.DependOn(asset.BOMRef, providerRef)
	result.DependOn(asset.BOMRef, providerRef)
	result.Add(cdx.Component{Type: cdx.ComponentTypeLibrary, Name: "unrelated-library"}, inventory.Evidence{}, "")
	var outputs []string
	for range 2 {
		data, err := cyclonedx.EncodeWithOptions([]inventory.Collection{{Result: result}}, cyclonedx.EncodeOptions{IncludeDependencies: true})
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if err := writeSummary(&output, data, false); err != nil {
			t.Fatal(err)
		}
		outputs = append(outputs, output.String())
		slices.Reverse(result.Entries)
	}
	if outputs[0] != outputs[1] || strings.Count(outputs[0], `TLS\tconfig\n\x1b[31m`) != 1 ||
		!strings.Contains(outputs[0], "configured; present") || !strings.Contains(outputs[0], "a.pem; z.py:12") ||
		strings.Count(outputs[0], `requests\tlibrary`) != 1 || strings.Contains(outputs[0], "unrelated-library") ||
		strings.Contains(outputs[0], "\x1b") {
		t.Fatalf("summary lost grouping, determinism or escaping: %q", outputs[0])
	}
}

func TestCryptoSummaryEmptyAndIncomplete(t *testing.T) {
	data, err := cyclonedx.Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, incomplete := range []bool{false, true} {
		var output bytes.Buffer
		if err := writeSummary(&output, data, incomplete); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output.String(), "Cryptographic findings: 0") ||
			!strings.Contains(output.String(), "does not establish absence") ||
			strings.Contains(output.String(), "INCOMPLETE") != incomplete {
			t.Fatalf("misleading empty summary: %s", output.String())
		}
	}
}

func TestCryptoSummaryPreservesPartialAndFileOutput(t *testing.T) {
	root := t.TempDir()
	writeRepositoryFile(t, root, "app.py", "import requests\nrequests.get('https://example.invalid')\n")
	output := filepath.Join(root, "cbom.json")
	for range 2 {
		var stdout, stderr bytes.Buffer
		code := Run(context.Background(), []string{"scan", root, filepath.Join(root, "missing.py"),
			"--analyzers", "python", "--offline", "--summary", "--output", output}, &stdout, &stderr)
		if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "Cryptographic findings: 1 (INCOMPLETE)") {
			t.Fatalf("partial collection or output behavior changed: %d %s", code, stderr.String())
		}
		data, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if err := cyclonedx.Validate(data); err != nil {
			t.Fatalf("summary replaced JSON file output: %v", err)
		}
	}
}

type summaryFailingWriter struct{ short bool }

func (w summaryFailingWriter) Write([]byte) (int, error) {
	if w.short {
		return 0, nil
	}
	return 0, io.ErrClosedPipe
}

func TestCryptoSummaryWriteFailuresAreExplicit(t *testing.T) {
	data, err := cyclonedx.Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, short := range []bool{false, true} {
		expected := io.ErrClosedPipe
		if short {
			expected = io.ErrShortWrite
		}
		if err := writeSummary(summaryFailingWriter{short: short}, data, false); !errors.Is(err, expected) {
			t.Fatalf("summary write failure was ignored: %v", err)
		}
	}
	root := t.TempDir()
	writeRepositoryFile(t, root, "app.py", "x = 1\n")
	var stdout bytes.Buffer
	if code := Run(context.Background(), []string{"scan", root, "--analyzers", "python", "--summary"}, &stdout, summaryFailingWriter{}); code != 1 {
		t.Fatalf("failed requested summary returned success: %d", code)
	}
	if err := cyclonedx.Validate(stdout.Bytes()); err != nil {
		t.Fatalf("summary failure lost the JSON report: %v", err)
	}
}

func TestNoPythonSourceDoesNotLookUpAnInterpreter(t *testing.T) {
	root := t.TempDir()
	writeRepositoryFile(t, root, "notes.txt", "No applicable source\n")
	t.Setenv("PATH", t.TempDir())
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"scan", root}, &stdout, &stderr); code != 0 ||
		!strings.Contains(stderr.String(), "python=not-applicable") {
		t.Fatalf("repository without Python required an interpreter: %d %s", code, stderr.String())
	}
}
