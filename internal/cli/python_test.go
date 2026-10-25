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
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"scan", root, "--analyzers", "python", "--exclude", "excluded"}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "SHA-256") || strings.Contains(stdout.String(), `"name": "MD5"`) ||
		!strings.Contains(stderr.String(), "files=1") || !strings.Contains(stdout.String(), "python-virtual-environment") {
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
