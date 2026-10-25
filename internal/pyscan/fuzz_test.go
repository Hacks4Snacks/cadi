package pyscan

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

func FuzzPythonFrontend(f *testing.F) {
	for _, source := range []string{
		"import hashlib\nhashlib.sha256(b'data')\n",
		"def f():\n global missing\n missing.operation()\n",
		"from ssl import SSLContext as C\nc = C(unknown)\nc.minimum_version = version\n",
		"import hashlib\nitems = [(hashlib := x) for x in values]\n",
	} {
		f.Add([]byte(source))
	}
	interpreter, err := exec.LookPath("python3")
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, source []byte) {
		if len(source) > 4096 {
			t.Skip()
		}
		_, err := parse(context.Background(), interpreter, source)
		if err != nil && (strings.Contains(err.Error(), "frontend failed") || strings.Contains(err.Error(), "invalid response")) {
			t.Fatalf("frontend crashed on source data: %v", err)
		}
	})
}
