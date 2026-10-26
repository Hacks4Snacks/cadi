package kubernetes

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"ciphertrail/internal/export/cyclonedx"
	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"go.yaml.in/yaml/v3"
)

func TestMalformedEmbeddedPayloadsPreserveOtherFindings(t *testing.T) {
	for _, payload := range []string{
		"apiVersion: apiserver.config.k8s.io/v1\nkind: EncryptionConfiguration\nresources: [PRIVATE_MALFORMED_SENTINEL:\n",
		"apiVersion: apiserver.config.k8s.io/v1\nkind: EncryptionConfiguration\nresources: []\nresources: PRIVATE_MALFORMED_SENTINEL\n",
		"apiVersion: apiserver.config.k8s.io/v1\nkind: EncryptionConfiguration\nresources: &alias [*alias]\n",
		"apiVersion: apiserver.config.k8s.io/v1\nkind: EncryptionConfiguration\nresources: [{resources: [secrets], providers: [{aesgcm: {}, identity: {}}]}]\n",
		"'apiVersion': apiserver.config.k8s.io/v1\n'kind': EncryptionConfiguration\nresources: []\nresources: PRIVATE_MALFORMED_SENTINEL\n",
		`{"\u0061piVersion":"apiserver.config.k8s.io/v1","k\u0069nd":"EncryptionConfiguration","resources":[],"resources":"PRIVATE_MALFORMED_SENTINEL"}`,
	} {
		data := certificateManifest + "---\n" + configMapDocument(t, payload, false)
		result, err := collectManifest(t, data)
		if err == nil || strings.Contains(err.Error(), "PRIVATE_MALFORMED_SENTINEL") {
			t.Fatalf("malformed payload was accepted or leaked: %v", err)
		}
		encoded, encodeErr := cyclonedx.Encode([]inventory.Collection{{Result: result, Err: err}})
		if encodeErr != nil || strings.Contains(string(encoded), "PRIVATE_MALFORMED_SENTINEL") ||
			!strings.Contains(string(encoded), "cert-manager Certificate configuration") {
			t.Fatalf("partial result was lost or exposed input: %v", encodeErr)
		}
	}
}

func TestEmbeddedDepthAndAggregateBudgets(t *testing.T) {
	leaf := configMapDocument(t, "PRIVATE_UNRELATED_SENTINEL", false)
	for range MaxEmbeddedDepth {
		leaf = configMapDocument(t, leaf, false)
	}
	if _, err := collectManifest(t, leaf); err != nil {
		t.Fatalf("non-resource leaf consumed an additional resource nesting level: %v", err)
	}
	data := encryptionManifest
	for range MaxEmbeddedDepth + 1 {
		data = configMapDocument(t, data, false)
	}
	if _, err := collectManifest(t, data); err == nil || !strings.Contains(err.Error(), "decoded levels") {
		t.Fatalf("embedded depth was not bounded: %v", err)
	}
	for _, test := range []struct {
		name  string
		bytes int64
		nodes int
		fail  bool
	}{
		{"exact-byte-boundary", MaxDecodedBytes - int64(len(encryptionManifest)), 0, false},
		{"one-byte-over", MaxDecodedBytes - int64(len(encryptionManifest)) + 1, 0, true},
		{"shared-node-limit", 0, 100000, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var result inventory.Result
			scanner := resource{result: &result, evidence: inventory.Evidence{Location: "fixture.yaml"},
				budget: &decodeBudget{bytes: test.bytes, nodes: test.nodes}}
			_, err := scanner.documents(context.Background(), []byte(encryptionManifest), true)
			if (err != nil) != test.fail {
				t.Fatalf("budget result: %v", err)
			}
		})
	}
}

func TestBootstrapUnknownEncodingDoesNotAssumePlaintext(t *testing.T) {
	for _, encoding := range []string{"", "${FILE_ENCODING}", "unsupported"} {
		file := map[string]string{"path": "${FILE_PATH}", "content": encryptionManifest}
		if encoding != "" {
			file["encoding"] = encoding
		}
		profile, err := yaml.Marshal(map[string]any{
			"apiVersion": "bootstrap.cluster.x-k8s.io/v1beta2", "kind": "KubeadmConfigTemplate",
			"metadata": map[string]string{"name": "${RACK_ID}-nodes"},
			"spec":     map[string]any{"template": map[string]any{"spec": map[string]any{"files": []map[string]string{file}}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		result, err := collectManifest(t, configMapDocument(t, string(profile), false))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, entry := range result.Entries {
			if entry.Component.Name == "AES-GCM" {
				found = true
				last := entry.Evidence.Context.Embedded[len(entry.Evidence.Context.Embedded)-1]
				if last.File != "" || !slices.Contains(last.Unresolved, "file") {
					t.Fatal("runtime file path was treated as known")
				}
			}
		}
		if found != (encoding == "") {
			t.Fatalf("unknown encoding was interpreted: %q found=%v", encoding, found)
		}
		encoded, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
		if err != nil || strings.Contains(string(encoded), "FILE_PATH") || strings.Contains(string(encoded), "FILE_ENCODING") ||
			strings.Contains(string(encoded), "RACK_ID") {
			t.Fatal("runtime expressions leaked instead of unresolved provenance")
		}
	}
}

func TestIdentityAndUnknownProvidersAreNotInventedAlgorithms(t *testing.T) {
	for _, provider := range []string{"identity: {}", "kms: {apiVersion: v2, endpoint: 'PRIVATE_ENDPOINT_SENTINEL'}"} {
		result, err := collectManifest(t, "apiVersion: apiserver.config.k8s.io/v1\nkind: EncryptionConfiguration\nresources:\n- resources: [secrets]\n  providers:\n  - "+provider+"\n")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range result.Entries {
			if entry.Component.Type == cdx.ComponentTypeCryptographicAsset {
				t.Fatal("passthrough or provider-dependent encryption invented an algorithm")
			}
		}
		data, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
		if err != nil || strings.Contains(string(data), "PRIVATE_ENDPOINT_SENTINEL") {
			t.Fatal("unmodeled provider data leaked")
		}
	}
}

func TestBootstrapArgumentMapsAndListsHaveEquivalentCrypto(t *testing.T) {
	var properties []*cdx.CryptoProperties
	for _, args := range []any{
		map[string]string{"tls-min-version": "VersionTLS12", "tls-cipher-suites": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		[]map[string]string{{"name": "tls-min-version", "value": "VersionTLS12"}, {"name": "tls-cipher-suites", "value": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}},
	} {
		data, err := json.Marshal(map[string]any{"apiVersion": "kubeadm.k8s.io/v1beta4", "kind": "ClusterConfiguration",
			"apiServer": map[string]any{"extraArgs": args}})
		if err != nil {
			t.Fatal(err)
		}
		result, err := collectManifest(t, string(data))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range result.Entries {
			if entry.Component.CryptoProperties != nil {
				properties = append(properties, entry.Component.CryptoProperties)
			}
		}
	}
	if len(properties) != 2 || !reflect.DeepEqual(properties[0], properties[1]) {
		t.Fatal("equivalent argument forms produced different cryptography")
	}
}

func TestProviderAndKeyOrderingRemainConfiguredFacts(t *testing.T) {
	data := `apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources: ["*.*"]
  providers:
  - aescbc:
      keys:
      - {name: first, secret: PRIVATE_FIRST_SENTINEL}
      - {name: old, secret: PRIVATE_OLD_SENTINEL}
  - identity: {}
`
	result, err := collectManifest(t, data)
	if err != nil {
		t.Fatal(err)
	}
	var cbc bool
	roles := map[string]string{}
	for _, entry := range result.Entries {
		properties := map[string]string{}
		if entry.Component.Properties != nil {
			for _, p := range *entry.Component.Properties {
				properties[p.Name] = p.Value
			}
		}
		if entry.Component.Name == "AES-CBC" {
			a := entry.Component.CryptoProperties.AlgorithmProperties
			cbc = a.Mode == cdx.CryptoAlgorithmModeCBC && a.Padding == cdx.CryptoPaddingPKCS7 &&
				reflect.DeepEqual(*a.CryptoFunctions, []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt}) &&
				properties["ciphertrail:encryption.resources"] == "*.*"
		}
		if entry.Component.Name == "Kubernetes encryption key reference" {
			roles[properties["ciphertrail:encryption.key-name"]] = properties["ciphertrail:encryption.key-role"]
		}
	}
	if !cbc || roles["first"] != "encrypt, decrypt" || roles["old"] != "decrypt" {
		t.Fatalf("provider/key roles changed: cbc=%v roles=%v", cbc, roles)
	}
}

func TestAmbiguousTLSAndCredentialReferencesAreNotExportedAsValues(t *testing.T) {
	result, err := collectManifest(t, `apiVersion: kubeadm.k8s.io/v1beta4
kind: ClusterConfiguration
apiServer:
  extraArgs:
  - {name: tls-min-version, value: VersionTLS12}
  - {name: tls-min-version, value: VersionTLS13}
  - {name: tls-cert-file, value: "https://user:PRIVATE_URL_SENTINEL@example.test"}
`)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range result.Entries {
		if entry.Component.Name != "Kubeadm apiServer TLS configuration" {
			continue
		}
		found = slices.Contains(entry.Evidence.Unresolved, "tls.min-version") &&
			slices.Contains(entry.Evidence.Unresolved, "tls.certificate-file")
		if entry.Component.Properties != nil && len(*entry.Component.Properties) != 0 {
			t.Fatal("ambiguous or unsafe input was exported as a known value")
		}
	}
	encoded, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
	if err != nil || !found || strings.Contains(string(encoded), "PRIVATE_URL_SENTINEL") {
		t.Fatalf("uncertainty or credential safety failed: %v", err)
	}
}

func TestBootstrapCASettingsDoNotAssumeAnAlgorithm(t *testing.T) {
	for _, algorithm := range []string{"", "RSA-2048", "ECDSA-P256"} {
		data := "apiVersion: kubeadm.k8s.io/v1beta4\nkind: ClusterConfiguration\ncaCertificateValidityPeriodDays: 730\n"
		if algorithm != "" {
			data += "encryptionAlgorithm: " + algorithm + "\n"
		}
		result, err := collectManifest(t, data)
		if err != nil {
			t.Fatal(err)
		}
		algorithms, certificates := 0, 0
		for _, entry := range result.Entries {
			if p := entry.Component.CryptoProperties; p != nil {
				if p.AlgorithmProperties != nil {
					algorithms++
				}
				if p.CertificateProperties != nil {
					certificates++
					if p.CertificateProperties.SerialNumber != "" || p.CertificateProperties.NotValidAfter != "" {
						t.Fatal("configured validity was turned into issued certificate metadata")
					}
				}
			}
		}
		if certificates != 1 || (algorithms == 1) != (algorithm != "") {
			t.Fatalf("algorithm was guessed or omitted: %q algorithms=%d certificates=%d", algorithm, algorithms, certificates)
		}
	}
}

func TestScriptPayloadsAreNotTreatedAsConfiguration(t *testing.T) {
	result, err := collectManifest(t, configMapDocument(t, "#!/bin/sh\ncat <<'EOF'\n"+encryptionManifest+"EOF\n", false))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range result.Entries {
		if entry.Component.CryptoProperties != nil {
			t.Fatal("a shell here-document was interpreted as a resolved configuration")
		}
	}
}
