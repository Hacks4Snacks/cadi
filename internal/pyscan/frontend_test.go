package pyscan

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPythonSyntaxErrorsArePartialAndSanitized(t *testing.T) {
	selection := fixture(t, map[string]string{
		"good.py": "import hashlib\nhashlib.sha256(b'x')\n",
		"bad.py":  "PRIVATE_ERROR_SENTINEL = (\n",
	})
	result, err := (Source{Selection: selection}).Collect(context.Background())
	if err == nil || strings.Contains(err.Error(), "PRIVATE_ERROR_SENTINEL") || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("syntax error was missing or exposed source: %v", err)
	}
	found := false
	for _, entry := range result.Entries {
		found = found || entry.Component.Name == "SHA-256"
	}
	if !found || result.Coverage[0].Status != "failed" || result.Coverage[0].Files != 2 {
		t.Fatal("successful source or incomplete coverage was lost")
	}
}

func TestPythonInterpreterIsOnlyRequiredForApplicableSource(t *testing.T) {
	empty := fixture(t, map[string]string{"notes.txt": "not Python"})
	source := fixture(t, map[string]string{"app.py": "import hashlib\n"})
	t.Setenv("PATH", t.TempDir())
	result, err := (Source{Selection: empty}).Collect(context.Background())
	if err != nil || result.Coverage[0].Status != "not-applicable" {
		t.Fatalf("non-Python input required an interpreter: %v", err)
	}
	result, err = (Source{Selection: source}).Collect(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Python 3.10+") || result.Coverage[0].Status != "failed" {
		t.Fatalf("missing interpreter was not explicit: %v", err)
	}
}

func trustedInterpreter(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("process-failure fixtures use a POSIX shell")
	}
	path := filepath.Join(t.TempDir(), "interpreter")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPythonFrontendFailures(t *testing.T) {
	for _, test := range []struct {
		name, script, message string
	}{
		{"old-interpreter", `printf '%s' '{"protocol":1,"version":"3.9.0","error":{"kind":"runtime"}}'`, "Python 3.10+"},
		{"broken-json", `printf '%s' 'PRIVATE_RESPONSE_SENTINEL'`, "invalid response"},
		{"missing-protocol", `printf '%s' '{}'`, "invalid response"},
		{"invalid-version", `printf '%s' '{"protocol":1,"version":"PRIVATE_VERSION_SENTINEL"}'`, "invalid response"},
		{"process-error", `printf '%s' 'PRIVATE_ERROR_SENTINEL' >&2; exit 1`, "frontend failed"},
		{"stdout-limit", "exec /usr/bin/yes PRIVATE_OUTPUT_SENTINEL", "output limit"},
		{"stderr-limit", "exec /usr/bin/yes PRIVATE_ERROR_SENTINEL >&2", "output limit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := parse(context.Background(), trustedInterpreter(t, test.script), []byte("unused"))
			if err == nil || !strings.Contains(err.Error(), test.message) || strings.Contains(err.Error(), "PRIVATE_") {
				t.Fatalf("incorrect or unsanitized error: %v", err)
			}
			if strings.Contains(parsed.Version, "PRIVATE_") {
				t.Fatal("unvalidated frontend metadata escaped a failed parse")
			}

		})
	}
}

func TestPythonInterpreterCannotComeFromScannedSource(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("interpreter-path fixture uses a POSIX executable")
	}
	selection := fixture(t, map[string]string{"app.py": "import hashlib\nhashlib.sha256(b'x')\n"})
	path := filepath.Join(selection.Root, "python3")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 99\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", selection.Root)
	_, err := (Source{Selection: selection}).Collect(context.Background())
	if err == nil || !strings.Contains(err.Error(), "inside the source") {
		t.Fatalf("an interpreter in the target tree was not rejected: %v", err)
	}
}

func TestPythonFrontendBoundsAndCancellation(t *testing.T) {
	interpreter, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	_, err = parse(context.Background(), interpreter, make([]byte, maxSourceBytes+1))
	if err == nil || !strings.Contains(err.Error(), "byte") {
		t.Fatal("source limit was not enforced")
	}
	_, err = parse(context.Background(), interpreter, []byte(strings.Repeat("x = 1\n", 30000)))
	if err == nil || !strings.Contains(err.Error(), "complexity limit") {
		t.Fatalf("AST node limit was not enforced: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = parse(ctx, interpreter, []byte("x = 1"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation was not preserved: %v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = parse(ctx, trustedInterpreter(t, "exec sleep 20"), []byte("unused"))
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 3*time.Second {
		t.Fatalf("running interpreter was not stopped: %v", err)
	}
}
