package pyscan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ciphertrail/internal/export/cyclonedx"
	"ciphertrail/internal/inventory"
	"ciphertrail/internal/scope"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func fixture(t *testing.T, files map[string]string) scope.Selection {
	t.Helper()
	root := t.TempDir()
	for name, source := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	selection, err := scope.Discover(context.Background(), root, scope.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return selection
}

func TestPythonImportsParametersAndPrivateValues(t *testing.T) {
	selection := fixture(t, map[string]string{"app.py": `
import hashlib as hashes
from hmac import new as authenticate
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import AES
import secrets
bits = 4096
key = b"PRIVATE_KEY_SENTINEL"
hashes.sha256(b"PRIVATE_PAYLOAD_SENTINEL")
authenticate(key, b"PRIVATE_MESSAGE_SENTINEL", digestmod=hashes.sha256)
rsa.generate_private_key(public_exponent=65537, key_size=bits)
AESGCM.generate_key(bit_length=256)
AES.new(secrets.token_bytes(32), AES.MODE_GCM, nonce=b"x" * 12)
`})
	result, err := (Source{Selection: selection}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, entry := range result.Entries {
		if entry.Component.Type != cdx.ComponentTypeCryptographicAsset {
			continue
		}
		found[entry.Component.Name] = true
		if entry.Evidence.Kind != "configured" || entry.Evidence.Collector != "python" ||
			entry.Evidence.Location != "app.py" || entry.Evidence.Line == 0 || entry.Evidence.Symbol == "" {
			t.Fatalf("missing source evidence: %+v", entry.Evidence)
		}
		if entry.Component.Name == "RSA" && entry.Component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier != "4096" {
			t.Fatal("constant RSA key size was missed")
		}
		if entry.Evidence.Symbol == "Crypto.Cipher.AES.new" {
			a := entry.Component.CryptoProperties.AlgorithmProperties
			if a.Mode != cdx.CryptoAlgorithmModeGCM || a.ParameterSetIdentifier != "256" {
				t.Fatalf("AES parameters missing: %+v", a)
			}
		}
	}
	for _, name := range []string{"SHA-256", "HMAC-SHA-256", "RSA", "AES-GCM"} {
		if !found[name] {
			t.Errorf("missing %s", name)
		}
	}
	data, err := cyclonedx.Encode([]inventory.Collection{{Collector: "python", Result: result}})
	if err != nil || strings.Contains(string(data), "PRIVATE_") {
		t.Fatalf("private values leaked or schema failed: %v", err)
	}
}

func TestPythonDoesNotExecuteImportsOrStartupHooks(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "executed")
	selection := fixture(t, map[string]string{
		"app.py":           "import hashlib\nopen(" + quote(marker) + ", 'w').write('executed')\nhashlib.sha256(b'value')\n",
		"sitecustomize.py": "raise RuntimeError('PRIVATE_STARTUP_SENTINEL')\n",
		"json.py":          "raise RuntimeError('PRIVATE_SHADOW_SENTINEL')\n",
	})
	t.Setenv("PYTHONPATH", selection.Root)
	result, err := (Source{Selection: selection}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("target code was executed")
	}
	data, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
	if err != nil || strings.Contains(string(data), "PRIVATE_") {
		t.Fatalf("startup hook or shadow module affected the frontend: %v", err)
	}
	if _, err := os.Stat(filepath.Join(selection.Root, "__pycache__")); !os.IsNotExist(err) {
		t.Fatal("analysis wrote bytecode into the target")
	}
}

func quote(value string) string {
	data, _ := json.Marshal(value)
	return string(data)
}

func TestPythonShadowingAndUnknownValues(t *testing.T) {
	selection := fixture(t, map[string]string{"app.py": `
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
def shadow(hashlib):
    hashlib.sha256(b"not a known provider")
def build(bits):
    rsa.generate_private_key(65537, bits)
`})
	result, err := (Source{Selection: selection}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range result.Entries {
		if entry.Component.Name == "SHA-256" {
			t.Fatal("a shadowed parameter was mistaken for hashlib")
		}
		if entry.Component.Name == "RSA" {
			found = true
			if entry.Component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier != "" ||
				len(entry.Evidence.Unresolved) == 0 {
				t.Fatal("an unconstrained Python parameter was given a guessed size")
			}
		}
	}
	if !found {
		t.Fatal("RSA operation disappeared with an unknown key size")
	}
}
