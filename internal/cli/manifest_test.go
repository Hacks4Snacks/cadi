package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ciphertrail/internal/export/cyclonedx"
	"ciphertrail/internal/testutil"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestManifestAndFileInputsUseKubernetesDetection(t *testing.T) {
	_, _, certificate, privateKey := testutil.Identity(t)
	document := map[string]any{
		"apiVersion": "v1", "kind": "Secret", "metadata": map[string]string{"name": "fixture"},
		"type":       "kubernetes.io/tls",
		"data":       map[string]string{"tls.crt": base64.StdEncoding.EncodeToString(certificate)},
		"stringData": map[string]string{"tls.key": string(privateKey), "password": "PRIVATE_SENTINEL"},
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "secret.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	archive := testutil.ImageArchive(t, map[string][]byte{"manifests/secret.json": data})
	for _, test := range []struct{ option, path string }{{"--manifest", path}, {"--file", path}, {"--image", archive}} {
		t.Run(test.option, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), []string{"scan", test.option, test.path, "--offline"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
				t.Fatalf("input failed: code=%d stderr=%s", code, stderr.String())
			}
			if err := cyclonedx.Validate(stdout.Bytes()); err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(stdout.Bytes(), privateKey[35:75]) || bytes.Contains(stdout.Bytes(), []byte("PRIVATE_SENTINEL")) {
				t.Fatal("Secret payload leaked")
			}
			var bom cdx.BOM
			if err := json.Unmarshal(stdout.Bytes(), &bom); err != nil {
				t.Fatal(err)
			}
			certFound := false
			for _, component := range *bom.Components {
				certFound = certFound || component.CryptoProperties != nil && component.CryptoProperties.CertificateProperties != nil
			}
			if !certFound {
				t.Fatal("embedded certificate missing")
			}
		})
	}
}

func TestManifestFailuresArePartialAndOutputIsProtected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.yaml")
	document := "apiVersion: cert-manager.io/v1\nkind: Certificate\nmetadata: {name: example}\nspec: {}\n---\napiVersion: v1\nkind: Secret\nmetadata: {name: broken}\ntype: kubernetes.io/tls\ndata: {tls.crt: 'PRIVATE_SENTINEL!'}\n"
	if err := os.WriteFile(path, []byte(document), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"scan", "--manifest", path}, &stdout, &stderr); code != 1 {
		t.Fatalf("malformed resource did not fail operationally: %d %s", code, stderr.String())
	}
	if err := cyclonedx.Validate(stdout.Bytes()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stderr.String(), "PRIVATE_SENTINEL") || strings.Contains(stdout.String(), "PRIVATE_SENTINEL") ||
		!strings.Contains(stdout.String(), "cert-manager Certificate configuration") {
		t.Fatal("partial results were lost or parser contents were exposed")
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run(context.Background(), []string{"scan", "--manifest", path, "--output", path}, &stdout, &stderr); code != 1 {
		t.Fatal("manifest output protection was bypassed")
	}
	actual, err := os.ReadFile(path)
	if err != nil || string(actual) != document {
		t.Fatal("manifest input was overwritten")
	}
}

func TestEmbeddedConfigMapUsesAllFileInputModes(t *testing.T) {
	document := map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]string{"name": "encryption"},
		"data": map[string]string{"encryption.yaml": "apiVersion: apiserver.config.k8s.io/v1\nkind: EncryptionConfiguration\nresources:\n- resources: [secrets]\n  providers:\n  - aesgcm:\n      keys:\n      - name: first\n        secret: PRIVATE_EMBEDDED_SENTINEL\n"},
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "configmap.json")
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	image := testutil.ImageArchive(t, map[string][]byte{"manifests/configmap.json": data})
	for _, target := range []struct{ flag, path string }{{"--manifest", file}, {"--file", file}, {"--image", image}} {
		t.Run(target.flag, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), []string{"scan", target.flag, target.path, "--offline"}, &stdout, &stderr)
			if code != 0 || stderr.Len() != 0 {
				t.Fatalf("embedded scan failed: %d %s", code, stderr.String())
			}
			var bom cdx.BOM
			if err := json.Unmarshal(stdout.Bytes(), &bom); err != nil {
				t.Fatal(err)
			}
			crypto := 0
			for _, component := range *bom.Components {
				if component.Type == cdx.ComponentTypeCryptographicAsset {
					crypto++
				}
			}
			if crypto != 2 || strings.Contains(stdout.String(), "PRIVATE_EMBEDDED_SENTINEL") {
				t.Fatalf("wrong crypto coverage or secret leakage: %d assets", crypto)
			}
		})
	}
}

func TestExplicitMaterialWithoutExtensionStillUsesFallback(t *testing.T) {
	_, _, certificate, _ := testutil.Identity(t)
	path := filepath.Join(t.TempDir(), "material")
	if err := os.WriteFile(path, certificate, 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"scan", "--file", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("explicit material detection regressed: %d %s", code, stderr.String())
	}
}
