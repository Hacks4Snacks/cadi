package scope

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"cadi/internal/inventory"
)

func TestScanReportsAndAllOutputsAreExcluded(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"source.py":          "value = 1\n",
		"history.json":       `{"reportFormat":"` + inventory.ScanReportFormat + `","reportVersion":1,"tool":{"name":"cadi"}}`,
		"legacy-report.json": `{"reportFormat":"CipherTrailScanReport","reportVersion":1,"tool":{"name":"ciphertrail"}}`,
		"cbom.out":           "unrelated output bytes",
		"scan.out":           "unrelated output bytes",
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

func TestCurrentAndLegacyIgnoreFilesAreCombined(t *testing.T) {
	for _, names := range [][]string{{".cadiignore"}, {".ciphertrailignore"}, {".cadiignore", ".ciphertrailignore"}} {
		t.Run(strings.Join(names, "+"), func(t *testing.T) {
			root := t.TempDir()
			want := []string{"cli", "shared"}
			for index, name := range names {
				entry := "current"
				if index > 0 {
					entry = "legacy"
				}
				if err := os.WriteFile(filepath.Join(root, name), []byte(entry+"/\nshared/\n"), 0600); err != nil {
					t.Fatal(err)
				}
				want = append(want, entry)
			}
			slices.Sort(want)
			got, err := LoadExclusions(root, []string{"cli", "shared"})
			if err != nil || !slices.Equal(got, want) {
				t.Fatalf("ignore migration changed scope: got=%v want=%v err=%v", got, want, err)
			}
		})
	}
}

func TestLegacyIgnoreFileFailuresRemainExplicit(t *testing.T) {
	for _, scenario := range []string{"invalid-rule", "oversized", "symlink"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, ".cadiignore"), []byte("current/\n"), 0600); err != nil {
				t.Fatal(err)
			}
			legacy := filepath.Join(root, ".ciphertrailignore")
			var err error
			switch scenario {
			case "invalid-rule":
				err = os.WriteFile(legacy, []byte("../outside\n"), 0600)
			case "oversized":
				err = os.WriteFile(legacy, []byte(strings.Repeat("x", (64<<10)+1)), 0600)
			case "symlink":
				target := filepath.Join(t.TempDir(), "target")
				if err := os.WriteFile(target, []byte("PRIVATE_SENTINEL"), 0600); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(target, legacy)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := LoadExclusions(root, nil); err == nil ||
				!strings.Contains(err.Error(), ".ciphertrailignore") || strings.Contains(err.Error(), "PRIVATE_SENTINEL") {
				t.Fatalf("legacy ignore file was silently bypassed or read unsafely: %v", err)
			}
		})
	}
}

func TestSharedScopeAndHelmClassification(t *testing.T) {
	root := t.TempDir()
	for name, contents := range map[string]string{
		".cadiignore":                      "fixtures/\n",
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
