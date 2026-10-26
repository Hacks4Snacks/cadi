package goscan

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cadi/internal/export/cyclonedx"
	"cadi/internal/inventory"
	"cadi/internal/scope"

	"golang.org/x/tools/go/packages"
)

func coldModuleProxy(t *testing.T, deny bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	const mod = "module example.test/colddep\n\ngo 1.27.0\n"
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for name, data := range map[string]string{"go.mod": mod, "dep.go": "package colddep\nfunc Use() {}\n"} {
		file, err := writer.Create("example.test/colddep@v1.0.0/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if deny {
			http.Error(w, "PRIVATE_SENTINEL", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/example.test/colddep/@v/v1.0.0.mod":
			fmt.Fprint(w, mod)
		case "/example.test/colddep/@v/v1.0.0.info":
			fmt.Fprint(w, `{"Version":"v1.0.0","Time":"2026-01-01T00:00:00Z"}`)
		case "/example.test/colddep/@v/v1.0.0.zip":
			w.Write(archive.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("GOPROXY", server.URL)
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GOPRIVATE", "")
	t.Setenv("GONOPROXY", "none")
	t.Setenv("GONOSUMDB", "")
	t.Setenv("GOMODCACHE", t.TempDir())
	t.Setenv("GOFLAGS", "-modcacherw")
	return server, &requests
}

func coldModuleFixture(t *testing.T, workspace bool) (string, map[string][]byte) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "helper"), 0700); err != nil {
		t.Fatal(err)
	}
	mod := "module example.test/root\n\ngo 1.27.0\nrequire example.test/colddep v1.0.0\n"
	files := map[string][]byte{
		"root.go":          []byte("package root\nimport (\"crypto/sha256\"; \"example.test/colddep\"; \"example.test/helper\")\nfunc Run() { _ = sha256.Sum256(nil); colddep.Use(); helper.Use() }\n"),
		"helper/go.mod":    []byte("module example.test/helper\n\ngo 1.27.0\n"),
		"helper/helper.go": []byte("package helper\nfunc Use() {}\n"),
	}
	if workspace {
		files["go.work"] = []byte("go 1.27.0\nuse (\n.\n./helper\n)\n")
	} else {
		mod += "require example.test/helper v0.0.0\nreplace example.test/helper => ./helper\n"
	}
	files["go.mod"] = []byte(mod)
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return directory, files
}

func TestColdCachePreparationPreservesManifests(t *testing.T) {
	for _, workspace := range []bool{false, true} {
		t.Run(fmt.Sprintf("workspace=%v", workspace), func(t *testing.T) {
			_, requests := coldModuleProxy(t, false)
			directory, originals := coldModuleFixture(t, workspace)
			if _, err := (Source{Path: directory, Offline: true}).Collect(context.Background()); err == nil {
				t.Fatal("cold offline scan unexpectedly succeeded")
			}
			if requests.Load() != 0 {
				t.Fatal("offline scan made a network request")
			}
			result, err := (Source{Path: directory}).Collect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if requests.Load() == 0 {
				t.Fatal("automatic preparation did not fetch the missing declared dependency")
			}
			if _, err := cyclonedx.Encode([]inventory.Collection{{Result: result}}); err != nil {
				t.Fatal(err)
			}
			for name, before := range originals {
				after, err := os.ReadFile(filepath.Join(directory, name))
				if err != nil || !bytes.Equal(before, after) {
					t.Fatalf("source input changed: %s", name)
				}
			}
			for _, sum := range []string{"go.sum", "go.work.sum", "helper/go.sum"} {
				if _, err := os.Stat(filepath.Join(directory, sum)); !os.IsNotExist(err) {
					t.Fatalf("created target checksum file: %s", sum)
				}
			}
			before := requests.Load()
			if _, err := (Source{Path: directory, Offline: true}).Collect(context.Background()); err != nil {
				t.Fatalf("prepared cache could not be reused offline: %v", err)
			}
			if requests.Load() != before {
				t.Fatal("offline cache reuse accessed the proxy")
			}
		})
	}
}

func TestTaggedColdCachePreparationUsesSelectedBuildContext(t *testing.T) {
	for _, workspace := range []bool{false, true} {
		for _, untaggedSource := range []bool{false, true} {
			t.Run(fmt.Sprintf("workspace=%v/untagged-source=%v", workspace, untaggedSource), func(t *testing.T) {
				_, requests := coldModuleProxy(t, false)
				t.Setenv("GOFLAGS", "-modcacherw -tags=unselected")
				directory, originals := coldModuleFixture(t, workspace)
				originals["root.go"] = append([]byte("//go:build production && integration && linux && amd64\n\n"), originals["root.go"]...)
				if untaggedSource {
					originals["base.go"] = []byte("package root\nfunc Base() {}\n")
				}
				for name, data := range originals {
					if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				source := Source{Path: directory, Tags: "production,integration", GOOS: "linux", GOARCH: "amd64", Offline: true}
				if _, err := source.Collect(context.Background()); err == nil {
					t.Fatal("cold offline scan unexpectedly succeeded")
				}
				if requests.Load() != 0 {
					t.Fatal("offline tagged scan contacted the proxy")
				}
				source.Offline = false
				result, err := source.Collect(context.Background())
				if err != nil {
					t.Fatalf("tagged automatic preparation failed: %v", err)
				}
				if requests.Load() == 0 {
					t.Fatal("missing tagged dependency was not downloaded")
				}
				hashes := 0
				for _, entry := range result.Entries {
					if entry.Component.Name == "SHA-256" && entry.Evidence.Location == "root.go" {
						hashes++
					}
				}
				if hashes != 1 {
					t.Fatalf("selected build context lost its crypto call: %d findings", hashes)
				}
				if _, err := cyclonedx.Encode([]inventory.Collection{{Result: result}}); err != nil {
					t.Fatal(err)
				}
				before := requests.Load()
				source.Offline = true
				if _, err := source.Collect(context.Background()); err != nil {
					t.Fatalf("prepared tagged dependency was not reusable offline: %v", err)
				}
				if requests.Load() != before {
					t.Fatal("warm offline scan contacted the proxy")
				}
				for name, before := range originals {
					after, err := os.ReadFile(filepath.Join(directory, name))
					if err != nil || !bytes.Equal(before, after) {
						t.Fatalf("target input changed: %s", name)
					}
				}
				for _, sum := range []string{"go.sum", "go.work.sum", "helper/go.sum"} {
					if _, err := os.Stat(filepath.Join(directory, sum)); !os.IsNotExist(err) {
						t.Fatalf("created target checksum file: %s", sum)
					}
				}
			})
		}
	}
}

func TestPreparationDoesNotDownloadUnusedTransitivePlaceholders(t *testing.T) {
	_, _ = coldModuleProxy(t, false)
	directory, _ := coldModuleFixture(t, false)
	helperMod := filepath.Join(directory, "helper", "go.mod")
	data := []byte("module example.test/helper\n\ngo 1.27.0\nrequire example.test/unused-placeholder v0.0.0\n")
	if err := os.WriteFile(helperMod, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Source{Path: directory}).Collect(context.Background()); err != nil {
		t.Fatalf("package-scoped preparation fetched an unused placeholder: %v", err)
	}
	after, err := os.ReadFile(helperMod)
	if err != nil || !bytes.Equal(data, after) {
		t.Fatal("replacement module manifest changed")
	}
}

func TestUndeclaredImportsAreNotPreparedAsLatestDependencies(t *testing.T) {
	loaded := []*packages.Package{{
		PkgPath: "example.test/root",
		Errors: []packages.Error{
			{Kind: packages.ListError, Msg: "module lookup disabled by GOPROXY=off"},
			{Kind: packages.ListError, Msg: "no required module provides package private.example.test/undeclared"},
		},
	}}
	if needsDependencyPreparation(loaded, nil) {
		t.Fatal("preparation would attempt to repair an undeclared import")
	}
}

func TestPreparationFailureIsExplicitAndPrivate(t *testing.T) {
	_, requests := coldModuleProxy(t, true)
	directory, _ := coldModuleFixture(t, false)
	result, err := (Source{Path: directory}).Collect(context.Background())
	if err == nil || requests.Load() == 0 {
		t.Fatalf("preparation failure was not exercised: %v", err)
	}
	data, encodeErr := cyclonedx.Encode([]inventory.Collection{{Result: result, Err: err}})
	if encodeErr != nil || strings.Contains(string(data), "PRIVATE_SENTINEL") || !strings.Contains(string(data), "incomplete") {
		t.Fatalf("unsafe or misleading failure report: %v", encodeErr)
	}
}

func TestDependencyPreparationCanBeCancelled(t *testing.T) {
	started := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	defer server.Close()
	t.Setenv("GOPROXY", server.URL)
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GONOPROXY", "none")
	t.Setenv("GOMODCACHE", t.TempDir())
	t.Setenv("GOFLAGS", "-modcacherw")
	directory, _ := coldModuleFixture(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := (Source{Path: directory}).Collect(ctx)
		done <- err
	}()
	select {
	case <-started:
		cancel()
	case err := <-done:
		t.Fatalf("preparation exited before the proxy request: %v", err)
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("preparation never reached the proxy")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation lost: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("dependency preparation did not terminate after cancellation")
	}
}

func TestPreparationPreservesPrivateModuleRouting(t *testing.T) {
	t.Setenv("GOPROXY", "https://proxy.example.test")
	t.Setenv("GOPRIVATE", "private.example.test/*")
	t.Setenv("GONOPROXY", "private.example.test/*")
	t.Setenv("GONOSUMDB", "private.example.test/*")
	t.Setenv("GOSUMDB", "sum.golang.org")
	source := Source{}
	online, offline := source.environment(false), source.environment(true)
	for name, want := range map[string]string{
		"GOPROXY": "https://proxy.example.test", "GOPRIVATE": "private.example.test/*",
		"GONOPROXY": "private.example.test/*", "GONOSUMDB": "private.example.test/*",
		"GOSUMDB": "sum.golang.org",
	} {
		if envValue(online, name) != want {
			t.Errorf("preparation changed %s", name)
		}
	}
	if envValue(offline, "GOPROXY") != "off" || envValue(offline, "GONOPROXY") != "none" ||
		envValue(online, "GOTOOLCHAIN") != "local" || envValue(online, "GOPACKAGESDRIVER") != "off" {
		t.Fatal("dependency network/toolchain safeguards were not preserved")
	}
}

func TestWorkspaceIsHonoredWithoutModifyingInputs(t *testing.T) {
	directory := fixture(t, `package example
import "example.test/nested"
func Run() { nested.Run() }
`)
	if err := os.Mkdir(filepath.Join(directory, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"go.work":        []byte("go 1.27.0\nuse (\n.\n./nested\n)\n"),
		"nested/go.mod":  []byte("module example.test/nested\n\ngo 1.27.0\n"),
		"nested/hash.go": []byte("package nested; import \"crypto/sha256\"; func Run() { _ = sha256.Sum256(nil) }\n"),
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(directory, name), contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"go.mod", "go.sum"} {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		files[name] = data
	}
	result, err := (Source{Path: directory}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range result.Entries {
		found = found || entry.Component.Name == "SHA-256"
	}
	if !found {
		t.Fatal("workspace dependency not inventoried")
	}
	for name, before := range files {
		after, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("scan modified %s", name)
		}
	}
	if _, err := os.Stat(filepath.Join(directory, "go.work.sum")); !os.IsNotExist(err) {
		t.Fatal("scanner created a checksum file in the source workspace")
	}
}

func TestDiscoveredModulesOutsideWorkspaceUseOwnManifests(t *testing.T) {
	for _, standalone := range []string{"standalone", "member/standalone"} {
		t.Run(standalone, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("GOWORK", "")
			t.Setenv("GOFLAGS", "")
			files := map[string]string{
				"go.work":               "go 1.27.0\nuse (\n./member\n./helper\n)\n",
				"member/go.mod":         "module example.test/member\n\ngo 1.27.0\n",
				"member/main.go":        "package member\nimport \"example.test/helper\"\nfunc Run() { helper.Run() }\n",
				"helper/go.mod":         "module example.test/helper\n\ngo 1.27.0\n",
				"helper/helper.go":      "package helper\nimport \"crypto/sha256\"\nfunc Run() { _ = sha256.Sum256(nil) }\n",
				standalone + "/go.mod":  "module example.test/standalone\n\ngo 1.27.0\n",
				standalone + "/hash.go": "package standalone\nimport \"crypto/sha512\"\nfunc Run() { _ = sha512.Sum512(nil) }\n",
			}
			for name, content := range files {
				path := filepath.Join(root, name)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			for _, explicitWorkspace := range []bool{false, true} {
				if explicitWorkspace {
					t.Setenv("GOWORK", filepath.Join(root, "go.work"))
				}
				for _, target := range []string{root, filepath.Join(root, standalone)} {
					result, err := (Source{Path: target, Offline: true}).Collect(context.Background())
					if err != nil {
						t.Fatalf("independent module inherited an unrelated workspace (explicit=%v): %v", explicitWorkspace, err)
					}
					hashes := map[string]int{}
					for _, entry := range result.Entries {
						if entry.Component.CryptoProperties != nil {
							hashes[entry.Component.Name]++
						}
					}
					if hashes["SHA-512"] != 1 || target == root && hashes["SHA-256"] != 1 {
						t.Fatalf("standalone or workspace evidence missing: %v", hashes)
					}
					contexts := map[string]bool{}
					for _, detail := range result.Details {
						if detail.Name != "module-context" {
							continue
						}
						var context struct {
							Module    string
							Workspace bool
						}
						if err := json.Unmarshal(detail.Value, &context); err != nil {
							t.Fatal(err)
						}
						contexts[context.Module] = context.Workspace
					}
					if target == root {
						workspace, exists := contexts[standalone]
						if !exists || workspace || !contexts["member"] || !contexts["helper"] {
							t.Fatalf("per-module workspace selection was not recorded correctly: %v", contexts)
						}
					} else if workspace, exists := contexts["."]; !exists || workspace {
						t.Fatalf("standalone target was not marked as such: %v", contexts)
					}
					if _, err := cyclonedx.Encode([]inventory.Collection{{Result: result}}); err != nil {
						t.Fatal(err)
					}
				}
			}
			for name, before := range files {
				after, err := os.ReadFile(filepath.Join(root, name))
				if err != nil || string(after) != before {
					t.Fatalf("workspace selection modified target input: %s", name)
				}
			}
			for _, name := range []string{"go.work.sum", "member/go.sum", "helper/go.sum", standalone + "/go.sum"} {
				if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
					t.Fatalf("workspace selection created a target checksum file: %s", name)
				}
			}
			if err := os.WriteFile(filepath.Join(root, "member", "main.go"), []byte("package member\nfunc Run() { undefined() }\n"), 0600); err != nil {
				t.Fatal(err)
			}
			partial, err := (Source{Path: root, Offline: true}).Collect(context.Background())
			if err == nil {
				t.Fatal("workspace selection hid a genuine member type error")
			}
			found := false
			for _, entry := range partial.Entries {
				found = found || entry.Component.Name == "SHA-512"
			}
			if !found {
				t.Fatal("a failed workspace member discarded valid standalone evidence")
			}
		})
	}
}

func TestWorkspaceMembershipResolvesAbsolutePathsAndSymlinks(t *testing.T) {
	root := t.TempDir()
	member := filepath.Join(root, "member")
	if err := os.Mkdir(member, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(member, "go.mod"), []byte("module example.test/member\n\ngo 1.27.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(member, "hash.go"), []byte("package member\nimport \"crypto/sha256\"\nfunc Run() { _ = sha256.Sum256(nil) }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "alias")
	if err := os.Symlink(member, link); err != nil {
		t.Fatal(err)
	}
	workPath := filepath.Join(root, "go.work")
	content := "go 1.27.0\nuse " + fmt.Sprintf("%q", link) + "\n"
	if err := os.WriteFile(workPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOWORK", workPath)
	env, cleanup, err := isolatedWorkspace(context.Background(), member, (Source{}).environment(true))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	})
	if got := envValue(env, "GOWORK"); got == "" || got == "off" || got == workPath {
		t.Fatalf("a real workspace member was detached or not isolated: %q", got)
	}
	if _, err := (Source{Path: member, Offline: true}).Collect(context.Background()); err != nil {
		t.Fatalf("workspace path alias prevented analysis: %v", err)
	}
	after, err := os.ReadFile(workPath)
	if err != nil || string(after) != content {
		t.Fatal("workspace alias normalization modified the original")
	}
}

func TestOfflineLoadErrorsAreGroupedWithDetailedMetadata(t *testing.T) {
	var problems []loadProblem
	for _, path := range []string{"k8s.io/api/core/v1", "k8s.io/api/apps/v1", "k8s.io/client-go/rest"} {
		problems = append(problems, packageLoadProblems(&packages.Package{
			PkgPath: path, Errors: []packages.Error{{Kind: packages.ListError, Msg: "module lookup disabled by GOPROXY=off", Pos: "main.go:7:2"}},
		})...)
	}
	var result inventory.Result
	err := reportLoadProblems(&result, "images/example", problems)
	if err == nil || !strings.Contains(err.Error(), "3 packages") || !strings.Contains(err.Error(), "GOPROXY=off") ||
		!strings.Contains(err.Error(), "go mod download") || strings.Contains(err.Error(), "kind 1") || strings.Contains(err.Error(), "\n") {
		t.Fatalf("unhelpful or ungrouped loader error: %v", err)
	}
	if len(result.Details) != 1 || result.Details[0].Name != "package-load-errors" {
		t.Fatal("detailed package errors were not retained")
	}
	var details []loadProblem
	if err := json.Unmarshal(result.Details[0].Value, &details); err != nil {
		t.Fatal(err)
	}
	if len(details) != 3 {
		t.Fatalf("lost affected packages: %+v", details)
	}
	data, encodeErr := cyclonedx.Encode([]inventory.Collection{{Collector: "go", Result: result, Err: err}})
	if encodeErr != nil || !strings.Contains(string(data), "incomplete") {
		t.Fatalf("loader failure was not preserved: %v", encodeErr)
	}
}

func TestLoaderCausesDoNotExposeSourceOrCredentials(t *testing.T) {
	for _, tt := range []struct {
		kind          packages.ErrorKind
		message, want string
	}{
		{packages.ListError, "missing go.sum entry for module providing package x", "checksum"},
		{packages.ListError, "updates to go.mod needed, disabled by -mod=readonly", "module metadata"},
		{packages.ListError, "no required module provides package x", "required module"},
		{packages.TypeError, `cannot use "PRIVATE_SENTINEL" as int`, "type checking"},
		{packages.ParseError, `unexpected "PRIVATE_SENTINEL"`, "syntax"},
		{packages.UnknownError, "https://user:PRIVATE_SENTINEL@example.test", "loading"},
	} {
		var result inventory.Result
		err := reportLoadProblems(&result, ".", packageLoadProblems(&packages.Package{
			PkgPath: "example.test/project", Errors: []packages.Error{{Kind: tt.kind, Msg: tt.message, Pos: "main.go:3"}},
		}))
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Fatalf("wrong loader cause for %v: %v", tt.kind, err)
		}
		data, encodeErr := cyclonedx.Encode([]inventory.Collection{{Result: result, Err: err}})
		if encodeErr != nil || strings.Contains(string(data), "PRIVATE_SENTINEL") {
			t.Fatalf("unsafe loader output: %v", encodeErr)
		}
	}
}

func TestSourceExclusionsAreLiteralRootRelativePaths(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".cadiignore"), []byte("# comment\n\n./internal/testutil/\n"), 0600); err != nil {
		t.Fatal(err)
	}
	exclusions, err := scope.LoadExclusions(root, []string{"fixtures.go", "internal/testutil"})
	if err != nil || len(exclusions) != 2 {
		t.Fatalf("exclusion composition failed: %v %v", exclusions, err)
	}
	for _, tt := range []struct {
		path     string
		excluded bool
	}{
		{"internal/testutil/crypto.go", true},
		{"internal/testutil", true},
		{"fixtures.go", true},
		{"fixtures.go.bak", false},
		{"internal/testutilities/crypto.go", false},
		{"other/internal/testutil/crypto.go", false},
	} {
		if got := scope.PathExcluded(root, filepath.Join(root, tt.path), exclusions); got != tt.excluded {
			t.Errorf("%s: excluded=%v", tt.path, got)
		}
	}
	for _, invalid := range []string{"", ".", "..", "../secret", "/absolute", "a/../b", "**/testutil", "!keep", "a\\b", "https://example.test/path"} {
		if _, err := scope.LoadExclusions(root, []string{invalid}); err == nil {
			t.Errorf("invalid exclusion accepted: %q", invalid)
		}
	}
}

func TestInvalidIgnoreFileFailsExplicitly(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".cadiignore"), []byte("../outside\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := scope.LoadExclusions(root, nil); err == nil || !strings.Contains(err.Error(), ".cadiignore:1") {
		t.Fatalf("invalid file rule was ignored: %v", err)
	}
}

func TestIgnoreFileCannotBeASymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(target, []byte("PRIVATE_SENTINEL"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, ".cadiignore")); err != nil {
		t.Fatal(err)
	}
	if _, err := scope.LoadExclusions(root, nil); err == nil || strings.Contains(err.Error(), "PRIVATE_SENTINEL") {
		t.Fatalf("unsafe configuration read: %v", err)
	}
}

func TestNestedRepositoryBoundariesAndExplicitInclusion(t *testing.T) {
	directory := fixture(t, "package example\nimport \"crypto/sha256\"\nfunc Run() { _ = sha256.Sum256(nil) }\n")
	files := map[string]string{
		"ordinary/go.mod":  "module example.test/ordinary\n\ngo 1.27.0\n",
		"ordinary/hash.go": "package ordinary\nimport \"crypto/sha512\"\nfunc Run() { _ = sha512.Sum512(nil) }\n",
		"checkout/go.mod":  "module example.test/checkout\n\ngo 1.27.0\n",
		"checkout/hash.go": "package checkout\nimport \"crypto/md5\"\nfunc Run() { _ = md5.Sum(nil) }\n",
		"worktree/.git":    "gitdir: /not/read/by/cadi\n",
		"worktree/hash.go": "package worktree\nimport \"crypto/sha1\"\nfunc Run() { _ = sha1.Sum(nil) }\n",
	}
	for _, dir := range []string{".git", "checkout/.git", "ordinary", "worktree"} {
		if err := os.MkdirAll(filepath.Join(directory, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, include := range []bool{false, true} {
		result, err := (Source{Path: directory, IncludeNestedRepos: include}).Collect(context.Background())
		if err != nil || len(result.Diagnostics) != 0 {
			t.Fatalf("include=%v: %v %+v", include, err, result.Diagnostics)
		}
		names := map[string]bool{}
		for _, entry := range result.Entries {
			if entry.Component.CryptoProperties != nil {
				names[entry.Component.Name] = true
			}
		}
		if !names["SHA-256"] || !names["SHA-512"] || names["MD5"] != include || names["SHA-1"] != include {
			t.Fatalf("incorrect boundary handling with include=%v: %v", include, names)
		}
		if !include {
			recorded := false
			for _, property := range result.Details {
				recorded = recorded || property.Name == "excluded-nested-repositories" &&
					strings.Contains(string(property.Value), "checkout") && strings.Contains(string(property.Value), "worktree")
			}
			if !recorded {
				t.Fatal("nested repository exclusions were not recorded")
			}
		}
	}
	result, err := (Source{Path: filepath.Join(directory, "checkout")}).Collect(context.Background())
	if err != nil || len(result.Diagnostics) != 0 {
		t.Fatalf("explicit nested repository scan failed: %v", err)
	}
	found := false
	for _, entry := range result.Entries {
		found = found || entry.Component.Name == "MD5"
	}
	if !found {
		t.Fatal("explicit scan root was incorrectly skipped")
	}
}

func TestNestedBoundaryDoesNotHideRequiredCompilationErrors(t *testing.T) {
	directory := fixture(t, "package example\nimport \"example.test/fixture/checkout\"\nfunc Run() { checkout.Broken() }\n")
	checkout := filepath.Join(directory, "checkout")
	if err := os.MkdirAll(filepath.Join(checkout, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(checkout, "source.go"), []byte("package checkout\nfunc Broken() { undefined() }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Source{Path: directory}).Collect(context.Background()); err == nil {
		t.Fatal("repository boundary hid a required dependency's compilation error")
	}
}

func TestMissingDependencyDoesNotContactProxy(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	t.Setenv("GOPROXY", server.URL)
	t.Setenv("GONOPROXY", "*")
	directory := fixture(t, `package example; import _ "example.invalid/cadi-missing"`)
	if err := os.WriteFile(filepath.Join(directory, "go.mod"), []byte("module example.test/offline\n\ngo 1.27.0\nrequire example.invalid/cadi-missing v0.0.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Source{Path: directory, Offline: true}).Collect(context.Background()); err == nil {
		t.Fatal("missing dependency accepted")
	}
	if requests.Load() != 0 {
		t.Fatal("scanner contacted a module proxy")
	}
}
