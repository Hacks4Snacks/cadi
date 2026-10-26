package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ciphertrail/internal/testutil"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestMixedRepositoryInputsAndAnalyzerSelection(t *testing.T) {
	root := t.TempDir()
	for name, data := range map[string]string{
		"go.mod":           "module example.test/mixed\n\ngo 1.27.0\n",
		"main.go":          "package example\nimport \"crypto/sha256\"\nfunc Run() { _ = sha256.Sum256(nil) }\n",
		"certificate.yaml": "apiVersion: cert-manager.io/v1\nkind: Certificate\nmetadata: {name: example}\nspec: {privateKey: {algorithm: RSA, size: 2048}}\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct {
		analyzers  string
		hash, cert bool
	}{
		{"go,kubernetes,artifact", true, true},
		{"go", true, false},
		{"kubernetes", false, true},
	} {
		t.Run(test.analyzers, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), []string{"scan", root, "--analyzers", test.analyzers, "--offline"}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("scan failed: %d %s", code, stderr.String())
			}
			var bom cdx.BOM
			if err := json.Unmarshal(stdout.Bytes(), &bom); err != nil {
				t.Fatal(err)
			}
			hash, certificate := false, false
			for _, component := range *bom.Components {
				hash = hash || component.Name == "SHA-256"
				certificate = certificate || component.Name == "cert-manager Certificate configuration"
			}
			if hash != test.hash || certificate != test.cert {
				t.Fatalf("analyzer selection ignored: hash=%v certificate=%v", hash, certificate)
			}
			if !strings.Contains(stderr.String(), "INFO:") {
				t.Fatal("coverage summary missing")
			}
		})
	}
}

func TestRepositoryWithoutGoHasExplicitCoverage(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "certificate.yaml"), []byte("apiVersion: cert-manager.io/v1\nkind: Certificate\nmetadata: {name: example}\nspec: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(t.TempDir(), "scan.json")
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"scan", root, "--scan-report", reportPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("non-Go repository failed: %d %s", code, stderr.String())
	}
	var bom cdx.BOM
	if err := json.Unmarshal(stdout.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, collection := range readScanReport(t, reportPath).Collections {
		for _, coverage := range collection.Coverage {
			found = found || coverage.Analyzer == "go" && coverage.Status == "not-applicable"
		}
	}
	if !found {
		t.Fatal("Go applicability was not recorded")
	}
}

func TestOverlappingInputsDoNotRepeatModuleOrFileAnalysis(t *testing.T) {
	root := t.TempDir()
	writeRepositoryFile(t, root, "go.mod", "module example.test/root\n\ngo 1.27.0\n")
	writeRepositoryFile(t, root, "main.go", "package example\nimport \"crypto/sha256\"\nfunc Run() { _ = sha256.Sum256(nil) }\n")
	writeRepositoryFile(t, root, "child/go.mod", "module example.test/child\n\ngo 1.27.0\n")
	writeRepositoryFile(t, root, "child/main.go", "package example\nimport \"crypto/sha512\"\nfunc Run() { _ = sha512.Sum512(nil) }\n")
	_, _, certificate, _ := testutil.Identity(t)
	writeRepositoryFile(t, root, "cert.pem", string(certificate))
	reportPath := filepath.Join(t.TempDir(), "scan.json")
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"scan", root, root, filepath.Join(root, "child"),
		filepath.Join(root, "cert.pem"), "--offline", "--scan-report", reportPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("overlapping scan failed: %d %s", code, stderr.String())
	}
	var bom cdx.BOM
	if err := json.Unmarshal(stdout.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	modules, artifactFiles := 0, 0
	for _, collection := range readScanReport(t, reportPath).Collections {
		for _, c := range collection.Coverage {
			modules += c.Modules
			if c.Analyzer == "artifact" {
				artifactFiles += c.Files
			}
		}
	}
	if modules != 2 || artifactFiles != 1 || !strings.Contains(stderr.String(), "deduplicated") {
		t.Fatalf("work was repeated: modules=%d artifactFiles=%d %s", modules, artifactFiles, stderr.String())
	}
}

func TestSharedExclusionsAndGeneratedOutputDoNotPolluteRepositoryScans(t *testing.T) {
	root := t.TempDir()
	writeRepositoryFile(t, root, ".ciphertrailignore", "ignored/\n")
	writeRepositoryFile(t, root, "go.mod", "module example.test/scope\n\ngo 1.27.0\n")
	writeRepositoryFile(t, root, "main.go", "package example\nimport \"crypto/sha256\"\nfunc Run() { _ = sha256.Sum256(nil) }\n")
	for _, directory := range []string{"ignored", "excluded", "testdata", "samples", "examples", "out"} {
		writeRepositoryFile(t, root, directory+"/bad.go", "package bad\nimport \"crypto/md5\"\nfunc Run() { _ = md5.Sum(nil) }\n")
		writeRepositoryFile(t, root, directory+"/bad.yaml", "apiVersion: cert-manager.io/v1\nkind: Certificate\nmetadata: {name: excluded}\nspec: {secretName: PRIVATE_SCOPE_SENTINEL}\n")
	}
	writeRepositoryFile(t, root, "history.json", `{"bomFormat":"CycloneDX","data":"`)
	if err := os.Truncate(filepath.Join(root, "history.json"), 20<<20); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "result.yaml")
	for range 2 {
		var stdout, stderr bytes.Buffer
		code := Run(context.Background(), []string{"scan", root, "--exclude", "excluded", "--output", output, "--offline"}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("scoped scan failed: %d %s", code, stderr.String())
		}
		data, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "SHA-256") || strings.Contains(string(data), `"name": "MD5"`) ||
			strings.Contains(string(data), "PRIVATE_SCOPE_SENTINEL") {
			t.Fatal("shared exclusions were not applied to every analyzer")
		}
	}
}

func TestHelmDiscoveryProducesOnePreparationSummary(t *testing.T) {
	root := t.TempDir()
	writeRepositoryFile(t, root, "chart/Chart.yaml", "apiVersion: v2\nname: example\nversion: 1.0.0\n")
	for _, name := range []string{"one.yaml", "two.yaml", "_helpers.tpl"} {
		writeRepositoryFile(t, root, "chart/templates/"+name, "{{ unrendered template }}")
	}
	reportPath := filepath.Join(t.TempDir(), "scan.json")
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"scan", root, "--offline", "--scan-report", reportPath}, &stdout, &stderr)
	reportData, err := json.Marshal(readScanReport(t, reportPath))
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 || !strings.Contains(stderr.String(), "kubernetes=needs-rendering") ||
		strings.Contains(stderr.String(), "NOTE:") || !strings.Contains(string(reportData), "helmCharts") ||
		!strings.Contains(stdout.String(), "rendered inputs required") {
		t.Fatalf("Helm preparation was hidden or noisy: %d %s", code, stderr.String())
	}
}

func TestExplicitDERInputUsesFallbackWithoutARecognizedSuffix(t *testing.T) {
	_, certificate, _, _ := testutil.Identity(t)
	root := t.TempDir()
	file := filepath.Join(root, "material")
	if err := os.WriteFile(file, certificate.Raw, 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"scan", file}, &stdout, &stderr); code != 0 ||
		!strings.Contains(stdout.String(), "X.509 certificate") {
		t.Fatalf("explicit fallback failed: %d %s", code, stderr.String())
	}
}

func writeRepositoryFile(t *testing.T, root, name, contents string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestGoOnlyDoesNotValidateUnselectedChartContents(t *testing.T) {
	root := t.TempDir()
	writeRepositoryFile(t, root, "go.mod", "module example.test/goonly\n\ngo 1.27.0\n")
	writeRepositoryFile(t, root, "main.go", "package example\nimport \"crypto/sha256\"\nfunc Run() { _ = sha256.Sum256(nil) }\n")
	writeRepositoryFile(t, root, "chart/Chart.yaml", "invalid: [")
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"scan", root, "--analyzers", "go", "--offline"}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "SHA-256") {
		t.Fatalf("unselected chart parsing affected Go analysis: %d %s", code, stderr.String())
	}
}

func TestDoubleDashSupportsDashPrefixedFileNames(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	_, _, certificate, _ := testutil.Identity(t)
	writeRepositoryFile(t, root, "-certificate.pem", string(certificate))
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"scan", "--analyzers", "artifact", "--", "-certificate.pem"}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "X.509 certificate") {
		t.Fatalf("dash-prefixed input failed: %d %s", code, stderr.String())
	}
}

func TestRemovedInputFlagsAreNotKeptAsAliases(t *testing.T) {
	for _, flag := range []string{"--source", "--file", "--manifest", "--repo"} {
		var stdout, stderr bytes.Buffer
		code := Run(context.Background(), []string{"scan", flag, "."}, &stdout, &stderr)
		if code != 2 || stdout.Len() != 0 {
			t.Fatalf("removed flag still accepted: %s", flag)
		}
	}
}
