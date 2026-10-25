package kubernetes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"ciphertrail/internal/export/cyclonedx"
	"ciphertrail/internal/input"
	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"go.yaml.in/yaml/v3"
)

const encryptionManifest = `apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources: [secrets, configmaps]
    providers:
      - secretbox:
          keys:
            - name: keyVERSIONSUB
              secret: PRIVATE_SYMMETRIC_SENTINEL
      - aesgcm:
          keys:
            - name: fallback
              secret: PRIVATE_SYMMETRIC_SENTINEL
      - identity: {}
`

func configMapDocument(t *testing.T, payload string, binary bool) string {
	t.Helper()
	section, value := "data", payload
	unrelated := "PRIVATE_UNRELATED_SENTINEL"
	if binary {
		section, value = "binaryData", base64.StdEncoding.EncodeToString([]byte(payload))
		unrelated = base64.StdEncoding.EncodeToString([]byte(unrelated))
	}
	data, err := json.Marshal(map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]string{"name": "profile", "namespace": "nc-system"},
		section:    map[string]string{"profile.yaml": value, "unrelated": unrelated},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func bootstrapProfile(t *testing.T) string {
	t.Helper()
	data, err := yaml.Marshal(map[string]any{
		"apiVersion": "controlplane.cluster.x-k8s.io/v1beta2", "kind": "KubeadmControlPlane",
		"metadata": map[string]string{"name": "control-plane", "namespace": "${CUSTOM_LOCATION_NAMESPACE}"},
		"spec": map[string]any{
			"kubeadmConfigSpec": map[string]any{
				"clusterConfiguration": map[string]any{
					"caCertificateValidityPeriodDays": 730,
					"apiServer": map[string]any{"extraArgs": []map[string]string{
						{"name": "tls-min-version", "value": "VersionTLS12"},
						{"name": "tls-cipher-suites", "value": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
						{"name": "encryption-provider-config", "value": "/etc/kubernetes/enc/enc.yaml"},
					}},
				},
				"files": []map[string]string{
					{"path": "/etc/kubernetes/enc/enc.yaml.template", "content": encryptionManifest},
					{"path": "/usr/local/bin/opaque.sh", "content": "#!/bin/sh\ncryptsetup luksFormat \"$DEVICE\"\necho PRIVATE_SCRIPT_SENTINEL\n"},
				},
				"joinConfiguration": map[string]any{"nodeRegistration": map[string]any{
					"name":             "{{ ds.meta_data.local_hostname }}",
					"kubeletExtraArgs": []map[string]string{{"name": "tls-cipher-suites", "value": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestConfigMapTraversesRuntimeBootstrapAndEncryption(t *testing.T) {
	result, err := collectManifest(t, configMapDocument(t, bootstrapProfile(t), false))
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, entry := range result.Entries {
		if entry.Component.Type != cdx.ComponentTypeCryptographicAsset {
			continue
		}
		found[entry.Component.Name] = true
		context := entry.Evidence.Context
		if entry.Evidence.Line != 1 || context.Resource.Kind != "ConfigMap" ||
			context.Field != "/data/profile.yaml" || len(context.Embedded) == 0 ||
			context.Embedded[0].Resource.Kind != "KubeadmControlPlane" ||
			context.Embedded[0].Resource.Namespace != "" ||
			!slices.Contains(context.Embedded[0].Unresolved, "resource.namespace") {
			t.Fatalf("outer location or unresolved profile identity was lost: %+v", entry.Evidence)
		}
		if entry.Component.Name == "AES-GCM" || entry.Component.Name == "XSalsa20-Poly1305" {
			if len(context.Embedded) != 2 {
				t.Fatalf("missing file-content provenance: %+v", context)
			}
			last := context.Embedded[1]
			if last.File != "/etc/kubernetes/enc/enc.yaml.template" ||
				last.Resource.Kind != "EncryptionConfiguration" || last.Document != 1 ||
				last.Line == 0 || !strings.HasPrefix(last.Field, "/resources/0/providers/") {
				t.Fatalf("incorrect encryption origin: %+v", last)
			}
			a := entry.Component.CryptoProperties.AlgorithmProperties
			if a.ParameterSetIdentifier != "" {
				t.Fatal("a key size was inferred from unread symmetric material")
			}
			if entry.Component.Name == "AES-GCM" && (a.Mode != cdx.CryptoAlgorithmModeGCM ||
				!reflect.DeepEqual(*a.CryptoFunctions, []cdx.CryptoFunction{cdx.CryptoFunctionDecrypt})) {
				t.Fatal("fallback provider was incorrectly claimed as the write provider")
			}
		}
		if entry.Component.Name == "Kubeadm apiServer TLS configuration" {
			p := entry.Component.CryptoProperties.ProtocolProperties
			if p.Version != "" || p.CipherSuites == nil || len(*p.CipherSuites) != 2 {
				t.Fatal("configured TLS was mistaken for negotiation or lost suites")
			}
		}
	}
	for _, name := range []string{"AES-GCM", "XSalsa20-Poly1305", "Kubernetes encryption key reference",
		"Kubeadm apiServer TLS configuration", "Kubeadm join kubelet TLS configuration", "Kubeadm certificate configuration"} {
		if !found[name] {
			t.Errorf("missing %s", name)
		}
	}
	encoded, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"PRIVATE_SYMMETRIC_SENTINEL", "PRIVATE_UNRELATED_SENTINEL", "PRIVATE_SCRIPT_SENTINEL", "CUSTOM_LOCATION_NAMESPACE", "ds.meta_data"} {
		if strings.Contains(string(encoded), private) {
			t.Fatalf("private content or unresolved expressions leaked: %s", private)
		}
	}
}

func TestSymmetricValuesDoNotAffectPublicKeyReferenceIdentity(t *testing.T) {
	var refs [][]string
	for _, secret := range []string{"PRIVATE_SYMMETRIC_SENTINEL", "DIFFERENT_PRIVATE_SENTINEL"} {
		data := configMapDocument(t, strings.ReplaceAll(encryptionManifest, "PRIVATE_SYMMETRIC_SENTINEL", secret), false)
		result, err := collectManifest(t, data)
		if err != nil {
			t.Fatal(err)
		}
		var current []string
		for _, entry := range result.Entries {
			current = append(current, entry.Component.BOMRef)
			if p := entry.Component.CryptoProperties; p != nil && p.RelatedCryptoMaterialProperties != nil {
				key := p.RelatedCryptoMaterialProperties
				if key.Type != cdx.RelatedCryptoMaterialTypeSecretKey || key.ID != "" || key.Value != "" || key.Size != nil {
					t.Fatal("a declared key reference was treated as observed symmetric material")
				}
			}
		}
		slices.Sort(current)
		refs = append(refs, current)
	}
	if len(refs[0]) == 0 || !reflect.DeepEqual(refs[0], refs[1]) {
		t.Fatal("secret values influenced public identifiers")
	}
}

func TestConfigMapBinaryDataAndStandaloneEncryptionAreSupported(t *testing.T) {
	for _, data := range []string{encryptionManifest, configMapDocument(t, encryptionManifest, true)} {
		result, err := collectManifest(t, data)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, entry := range result.Entries {
			found = found || entry.Component.Name == "AES-GCM"
		}
		if !found {
			t.Fatal("encryption configuration was missed")
		}
		if _, err := cyclonedx.Encode([]inventory.Collection{{Result: result}}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEmbeddedCancellationIsPreserved(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	data := configMapDocument(t, encryptionManifest, false)
	file := input.NewFile("cancelled.json", int64(len(data)), strings.NewReader(data))
	if _, _, err := (Detector{Strict: true}).Detect(ctx, file); err != context.Canceled {
		t.Fatalf("cancellation was obscured: %v", err)
	}
}
