package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

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
