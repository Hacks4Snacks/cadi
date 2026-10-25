package pyscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ciphertrail/internal/inventory"
)

func TestPythonLexicalBindings(t *testing.T) {
	for _, test := range []struct {
		name, code string
		hashes     int
	}{
		{"alias", "import hashlib as h\nf = h.sha256\nf(b'x')\n", 1},
		{"from-import", "from hashlib import sha256 as h\nh(b'x')\n", 1},
		{"reassignment", "import hashlib\nhashlib = custom\nhashlib.sha256(b'x')\n", 0},
		{"parameter", "import hashlib\ndef f(hashlib):\n hashlib.sha256(b'x')\n", 0},
		{"wildcard", "import hashlib\nfrom other import *\nhashlib.sha256(b'x')\n", 0},
		{"relative", "from . import hashlib\nhashlib.sha256(b'x')\n", 0},
		{"attribute-write", "import hashlib\nhashlib.sha256 = custom\nhashlib.sha256(b'x')\n", 0},
		{"attribute-alias-write", "import hashlib\nh = hashlib\nh.sha256 = custom\nhashlib.sha256(b'x')\n", 0},
		{"global-write", "import hashlib\ndef f():\n global hashlib\n hashlib = custom\nhashlib.sha256(b'x')\n", 0},
		{"nonlocal-write", "def f():\n import hashlib\n def change():\n  nonlocal hashlib\n  hashlib = custom\n hashlib.sha256(b'x')\n", 0},
		{"unbound-global", "def f():\n global missing\n missing.sha256()\n", 0},
		{"comprehension", "import hashlib\nvalues = [hashlib.sha256(b'x') for hashlib in unknown]\nhashlib.sha256(b'x')\n", 1},
		{"walrus-comprehension", "import hashlib\nvalues = [(hashlib := x) for x in unknown]\nhashlib.sha256(b'x')\n", 0},
		{"nested-class", "class Outer:\n import hashlib\n class Inner:\n  def f(self):\n   hashlib.sha256(b'x')\n", 0},
		{"method-global", "import hashlib\nclass C:\n hashlib = custom\n def f(self):\n  hashlib.sha256(b'x')\n", 1},
		{"match-capture", "import hashlib\nmatch unknown:\n case {'a': a, **hashlib}:\n  hashlib.sha256(b'x')\n", 0},
		{"exception-capture", "import hashlib\ntry:\n pass\nexcept Exception as hashlib:\n hashlib.sha256(b'x')\n", 0},
		{"late-import", "hashlib.sha256(b'x')\nimport hashlib\n", 0},
		{"setattr", "import hashlib\nsetattr(hashlib, 'sha256', custom)\nhashlib.sha256(b'x')\n", 0},
		{"module-dictionary-write", "import hashlib\nhashlib.__dict__['sha256'] = custom\nhashlib.sha256(b'x')\n", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			selection := fixture(t, map[string]string{"app.py": test.code})
			result, err := (Source{Selection: selection}).Collect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			found := 0
			for _, entry := range result.Entries {
				if entry.Component.Name == "SHA-256" {
					found++
				}
			}
			if found != test.hashes {
				t.Fatalf("SHA-256 findings = %d; want %d", found, test.hashes)
			}
		})
	}
}

func TestPythonLocalModuleShadowingIncludesExcludedFiles(t *testing.T) {
	for _, shadow := range []string{"hashlib.py", "hashlib/__init__.py", "src/hashlib.py", "app/hashlib.py"} {
		t.Run(shadow, func(t *testing.T) {
			selection := fixture(t, map[string]string{
				".ciphertrailignore": shadow + "\n",
				shadow:               "NOT VALID PYTHON PRIVATE_SENTINEL",
				"app/main.py":        "import hashlib\nhashlib.sha256(b'x')\n",
			})
			before, err := os.ReadFile(filepath.Join(selection.Root, shadow))
			if err != nil {
				t.Fatal(err)
			}
			result, err := (Source{Selection: selection}).Collect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range result.Entries {
				if entry.Component.Name == "SHA-256" {
					t.Fatal("local shadow was attributed to the standard library")
				}
			}
			if len(result.Diagnostics) == 0 {
				t.Fatal("shadowed provider was not explained")
			}
			after, err := os.ReadFile(filepath.Join(selection.Root, shadow))
			if err != nil || string(before) != string(after) {
				t.Fatal("excluded source was modified")
			}
		})
	}
}

func TestPythonMutationInvalidatesNestedValueFacts(t *testing.T) {
	selection := fixture(t, map[string]string{
		"patch.py": "import secrets\nsecrets.token_bytes = custom\n",
		"app.py":   "from Crypto.Cipher import AES\nimport secrets\nAES.new(secrets.token_bytes(32), AES.MODE_GCM)\n",
	})
	result, err := (Source{Selection: selection}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range result.Entries {
		if entry.Component.Name == "AES-GCM" {
			found = true
			if entry.Component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier != "" {
				t.Fatal("a mutated byte factory established a key size")
			}
		}
	}
	if !found {
		t.Fatal("an unresolved key must not discard the AES operation")
	}
}

func TestPythonMutableLengthsAreNotConstants(t *testing.T) {
	selection := fixture(t, map[string]string{"app.py": `
from Crypto.Cipher import AES
key = bytearray(32)
key.append(0)
AES.new(key, AES.MODE_GCM)
`})
	result, err := (Source{Selection: selection}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range result.Entries {
		if entry.Component.Name == "AES-GCM" && entry.Component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier != "" {
			t.Fatal("mutable bytearray length was treated as immutable")
		}
	}
}

func TestPythonUnmodeledResolvedAPIsHaveDiagnostics(t *testing.T) {
	result, err := (Source{Selection: fixture(t, map[string]string{"app.py": "import hashlib\nhashlib.unmodeled_operation(b'PRIVATE_PAYLOAD')\n"})}).Collect(context.Background())
	if err != nil || len(result.Diagnostics) != 1 ||
		result.Diagnostics[0].Line != 2 || !strings.Contains(result.Diagnostics[0].Message, "hashlib.unmodeled_operation") {
		t.Fatalf("missing precise coverage note: %+v, %v", result.Diagnostics, err)
	}
}

func TestPythonExpandedArgumentsDoNotEstablishPositions(t *testing.T) {
	selection := fixture(t, map[string]string{"app.py": `
from cryptography.hazmat.primitives.asymmetric import rsa
rsa.generate_private_key(*parameters, 4096)
rsa.generate_private_key(65537, 4096, **options)
`})
	result, err := (Source{Selection: selection}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, entry := range result.Entries {
		if entry.Component.Name == "RSA" {
			found++
			if entry.Component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier != "" {
				t.Fatal("unpacking was treated as a fixed argument list")
			}
		}
	}
	if found != 2 {
		t.Fatal("opaque parameters removed recognized API operations")
	}
}

func property(entry inventory.Entry, name string) string {
	if entry.Component.Properties != nil {
		for _, property := range *entry.Component.Properties {
			if property.Name == "ciphertrail:"+name {
				return property.Value
			}
		}
	}
	return ""
}
