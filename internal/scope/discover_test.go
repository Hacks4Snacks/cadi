package scope

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"ciphertrail/internal/inventory"
)

func TestScanReportsAndAllOutputsAreExcluded(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"source.py":    "value = 1\n",
		"history.json": `{"reportFormat":"` + inventory.ScanReportFormat + `","reportVersion":1,"tool":{"name":"ciphertrail"}}`,
		"cbom.out":     "unrelated output bytes",
		"scan.out":     "unrelated output bytes",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	selection, err := Discover(context.Background(), root, Options{
		SkipReports: true, Outputs: []string{filepath.Join(root, "cbom.out"), filepath.Join(root, "scan.out")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(selection.Files) != 1 || selection.Files[0].Location != "source.py" {
		t.Fatalf("reports or output destinations were selected as inputs: %+v", selection.Files)
	}
}

func TestSharedScopeAndHelmClassification(t *testing.T) {
	root := t.TempDir()
	for name, contents := range map[string]string{
		".ciphertrailignore":               "fixtures/\n",
		"go.mod":                           "module example.test/scope\n",
		"main.go":                          "package example",
		"fixtures/key.pem":                 "PRIVATE_EXCLUDED",
		"out/report.json":                  "PRIVATE_GENERATED",
		"test/example.yaml":                "PRIVATE_TEST",
		"nested/.git":                      "gitdir: unused",
		"nested/go.mod":                    "module nested",
		"arbitrary-report.json":            `{"bomFormat":"CycloneDX","components":[]}`,
		"chart/Chart.yaml":                 "apiVersion: v2\nname: example\nversion: 1.0.0\ndependencies: []",
		"chart/templates/certificate.yaml": "apiVersion: cert-manager.io/v1\nkind: Certificate",
		"chart/files/root.crt":             "PUBLIC_CERTIFICATE",
	} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	selection, err := Discover(context.Background(), root, Options{ClassifyHelm: true, SkipReports: true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(selection.Modules, []string{selection.Root}) || len(selection.Charts) != 1 {
		t.Fatalf("incorrect discovery: %+v", selection)
	}
	var names []string
	for _, file := range selection.Files {
		names = append(names, file.Location)
		if file.Location == "chart/templates/certificate.yaml" && !file.HelmTemplate {
			t.Fatal("unrendered template not classified")
		}
	}
	for _, excluded := range []string{"fixtures/key.pem", "out/report.json", "test/example.yaml", "nested/go.mod", "arbitrary-report.json"} {
		if slices.Contains(names, excluded) {
			t.Fatalf("excluded content selected: %s", excluded)
		}
	}
	if !slices.Contains(names, "chart/files/root.crt") {
		t.Fatal("chart assets were excluded along with templates")
	}
}
