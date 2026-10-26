package pyscan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPythonExpressionLimitsPreservePartialFindings(t *testing.T) {
	depth := "import hashlib\nhashlib.sha256(b'PRIVATE_SENTINEL')\na0 = hashlib.sha512\n"
	for index := 1; index <= 40; index++ {
		depth += fmt.Sprintf("a%d = a%d\n", index, index-1)
	}
	depth += "a40(b'value')\n"
	values := "import hashlib\nhashlib.sha256(b'PRIVATE_SENTINEL')\na0 = b'value'\n"
	for index := 1; index <= 25; index++ {
		values += fmt.Sprintf("a%d = a%d\n", index, index-1)
	}
	values += strings.Repeat("consume(a25)\n", 9000)
	for _, test := range []struct{ name, source string }{
		{"depth", depth},
		{"values", values},
		{"arguments", "import hashlib\nhashlib.sha256(b'PRIVATE_SENTINEL')\nconsume(" + strings.Repeat("1,", 65) + ")\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			selection := fixture(t, map[string]string{"limited.py": test.source, "other.py": "import hashlib\nhashlib.sha384(b'value')\n"})
			result, err := (Source{Selection: selection}).Collect(context.Background())
			if err == nil || !strings.Contains(err.Error(), "limit") || strings.Contains(err.Error(), "PRIVATE_SENTINEL") {
				t.Fatalf("truncated analysis did not fail explicitly: %v", err)
			}
			names := map[string]bool{}
			for _, entry := range result.Entries {
				names[entry.Component.Name] = true
			}
			if !names["SHA-256"] || !names["SHA-384"] || result.Coverage[0].Status != "failed" || result.Coverage[0].Files != 2 {
				t.Fatalf("partial file evidence or failed coverage lost: %v %+v", names, result.Coverage)
			}
		})
	}
}

func TestTruncatedPythonFilesStillContributeMutationFacts(t *testing.T) {
	selection := fixture(t, map[string]string{
		"a.py":       "import hashlib\nhashlib.sha256(b'value')\n",
		"z_patch.py": "import hashlib\nhashlib.sha256 = replacement\nconsume(" + strings.Repeat("1,", 65) + ")\n",
	})
	result, err := (Source{Selection: selection}).Collect(context.Background())
	if !errors.Is(err, errAnalysisTruncated) || result.Coverage[0].Status != "failed" {
		t.Fatalf("truncation was not propagated: %v %+v", err, result.Coverage)
	}
	for _, entry := range result.Entries {
		if entry.Component.CryptoProperties != nil {
			t.Fatal("discarded mutations from a truncated file produced a guessed crypto finding")
		}
	}
}

func TestUnsupportedPythonExpressionsRemainQualifiedUnknowns(t *testing.T) {
	selection := fixture(t, map[string]string{"app.py": "import hashlib\nhashlib.new(select_algorithm())\n"})
	result, err := (Source{Selection: selection}).Collect(context.Background())
	if err != nil || result.Coverage[0].Status != "completed" {
		t.Fatalf("unsupported expression was confused with budget exhaustion: %v %+v", err, result.Coverage)
	}
}

const hashFrontendResponse = `{"protocol":1,"version":"3.10.0","calls":[{"line":2,"value":{"kind":"call","base":{"kind":"symbol","text":"hashlib.sha256"}}}],"settings":[],"mutations":[],"issues":[],"truncated":false}`

func TestPythonAggregateFactBudget(t *testing.T) {
	selection := fixture(t, map[string]string{
		"a.py": "import hashlib\nhashlib.sha256(b'value')\n",
		"b.py": "import hashlib\nhashlib.sha256(b'value')\n",
	})
	source := Source{Selection: selection, interpreter: trustedInterpreter(t, "printf '%s' '"+hashFrontendResponse+"'")}
	size := len(hashFrontendResponse)
	for _, test := range []struct {
		name                          string
		limit, files, skipped, hashes int
		fail                          bool
	}{
		{"exact-total", 2 * size, 2, 0, 2, false},
		{"one-byte-over", 2*size - 1, 2, 1, 1, true},
		{"exact-first", size, 1, 1, 1, true},
		{"first-cannot-fit", size - 1, 1, 2, 0, true},
		{"empty-budget", 0, 0, 2, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := source.collect(context.Background(), test.limit, collectionTimeout)
			if (err != nil) != test.fail || test.fail && !strings.Contains(err.Error(), "retained-fact budget") {
				t.Fatalf("incorrect budget outcome: %v", err)
			}
			hashes := 0
			for _, entry := range result.Entries {
				if entry.Component.Name == "SHA-256" {
					hashes++
				}
			}
			coverage := result.Coverage[0]
			if hashes != test.hashes || coverage.Files != test.files || coverage.Skipped != test.skipped ||
				(coverage.Status == "failed") != test.fail || test.fail && !strings.Contains(coverage.Reason, "retained-fact budget") {
				t.Errorf("incorrect partial evidence/coverage: hashes=%d %+v", hashes, coverage)
			}
		})
	}
}

func TestPythonCollectionDeadlinePreservesCompletedFiles(t *testing.T) {
	selection := fixture(t, map[string]string{
		"a.py": "import hashlib\nhashlib.sha256(b'value')\n",
		"b.py": "# slow\nimport hashlib\nhashlib.sha256(b'value')\n",
		"c.py": "import hashlib\nhashlib.sha256(b'value')\n",
	})
	script := "IFS= read -r first\nif [ \"$first\" = '# slow' ]; then exec sleep 20; fi\nprintf '%s' '" + hashFrontendResponse + "'"
	source := Source{Selection: selection, interpreter: trustedInterpreter(t, script)}
	start := time.Now()
	result, err := source.collect(context.Background(), maxCollectedFactBytes, 2*time.Second)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Fatalf("collection deadline did not stop the frontend: %v", err)
	}
	coverage := result.Coverage[0]
	if coverage.Status != "failed" || coverage.Files != 2 || coverage.Skipped != 1 || coverage.Findings != 1 ||
		!strings.Contains(coverage.Reason, "time limit") {
		t.Fatalf("deadline lost earlier evidence or hid skipped files: %+v", coverage)
	}
}

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
