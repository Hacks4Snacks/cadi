package kubernetes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ciphertrail/internal/detect"
	"ciphertrail/internal/export/cyclonedx"
	"ciphertrail/internal/input"
	"ciphertrail/internal/inventory"
	"ciphertrail/internal/testutil"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

const certificateManifest = `apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: service-tls
  namespace: workload
spec:
  secretName: service-tls
  isCA: false
  privateKey:
    algorithm: ECDSA
    size: 256
    rotationPolicy: Always
  duration: 720h
  renewBefore: 240h
  usages: [digital signature, server auth]
  issuerRef:
    name: internal-ca
    kind: Issuer
    group: cert-manager.io
`

func collectManifest(t *testing.T, data string) (inventory.Result, error) {
	t.Helper()
	file := input.NewFile("rendered.yaml", int64(len(data)), strings.NewReader(data))
	file.Evidence = inventory.Evidence{Kind: "present", Collector: "file", Location: "rendered.yaml"}
	result, recognized, err := (Detector{Strict: true}).Detect(context.Background(), file)
	if err == nil && !recognized {
		t.Fatal("manifest was not recognized")
	}
	return result, err
}

func TestCertificateAndIngressDeclarationsRetainTypedProvenance(t *testing.T) {
	result, err := collectManifest(t, "# Source: example/templates/certificate.yaml\n"+certificateManifest+`---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: frontend
  namespace: workload
spec:
  tls:
    - hosts: [service.example.test]
      secretName: service-tls
`)
	if err != nil || len(result.Diagnostics) != 0 {
		t.Fatalf("manifest failed: %v %+v", err, result.Diagnostics)
	}
	var certificate, key, algorithm, ingress bool
	for _, entry := range result.Entries {
		if entry.Component.Type != cdx.ComponentTypeCryptographicAsset {
			continue
		}
		context := entry.Evidence.Context
		if entry.Evidence.Kind != "configured" || entry.Evidence.Line == 0 ||
			context == nil || context.Resource == nil || context.Resource.Namespace != "workload" {
			t.Fatalf("configuration provenance missing: %+v", entry.Evidence)
		}
		switch entry.Component.Name {
		case "cert-manager Certificate configuration":
			certificate = true
			if context.Document != 1 || context.Field != "/spec" ||
				context.Resource.APIVersion != "cert-manager.io/v1" || context.Resource.Name != "service-tls" ||
				context.RenderedFrom != "example/templates/certificate.yaml" ||
				entry.Component.CryptoProperties.CertificateProperties.SerialNumber != "" {
				t.Fatalf("certificate configuration was misrepresented: %+v", entry)
			}
			properties := map[string]string{}
			for _, property := range *entry.Component.Properties {
				properties[property.Name] = property.Value
			}
			if properties["ciphertrail:cert-manager.duration"] != "720h0m0s" ||
				properties["ciphertrail:cert-manager.renew-before"] != "240h0m0s" ||
				properties["ciphertrail:cert-manager.is-ca"] != "false" {
				t.Fatalf("configured values changed: %v", properties)
			}
		case "cert-manager Private key configuration":
			key = context.Field == "/spec/privateKey" &&
				entry.Component.CryptoProperties.RelatedCryptoMaterialProperties.Size != nil &&
				*entry.Component.CryptoProperties.RelatedCryptoMaterialProperties.Size == 256
		case "ECDSA":
			algorithm = entry.Component.CryptoProperties.AlgorithmProperties.EllipticCurve == "nist/P-256"
		case "Kubernetes Ingress TLS configuration":
			ingress = context.Document == 2 && context.Field == "/spec/tls/0" &&
				entry.Component.CryptoProperties.ProtocolProperties.Version == "" &&
				entry.Component.CryptoProperties.ProtocolProperties.RelatedCryptographicAssets != nil
		}
	}
	if !certificate || !key || !algorithm || !ingress {
		t.Fatalf("coverage missing: certificate=%v key=%v algorithm=%v ingress=%v", certificate, key, algorithm, ingress)
	}
	if _, err := cyclonedx.Encode([]inventory.Collection{{Collector: "kubernetes", Result: result}}); err != nil {
		t.Fatal(err)
	}
}

func TestTLSSecretReusesMaterialParserWithoutExportingSecrets(t *testing.T) {
	_, _, certificate, privateKey := testutil.Identity(t)
	document := map[string]any{
		"apiVersion": "v1", "kind": "Secret",
		"metadata": map[string]string{"name": "service-tls", "namespace": "workload"},
		"type":     "kubernetes.io/tls",
		"data": map[string]string{
			"tls.crt":  base64.StdEncoding.EncodeToString(certificate),
			"tls.key":  "invalid-base64-overridden-by-stringData",
			"password": base64.StdEncoding.EncodeToString([]byte("PRIVATE_SENTINEL")),
		},
		"stringData": map[string]string{"tls.key": string(privateKey), "token": "PRIVATE_SENTINEL"},
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	result, err := collectManifest(t, string(data))
	if err != nil {
		t.Fatal(err)
	}
	var foundCert, foundKey bool
	for _, entry := range result.Entries {
		if entry.Component.Type != cdx.ComponentTypeCryptographicAsset {
			continue
		}
		if entry.Evidence.Kind != "present" || entry.Evidence.Line != 1 ||
			entry.Evidence.Context.Document != 1 || entry.Evidence.Context.ContentLine < 1 {
			t.Fatalf("embedded content replaced the host source location: %+v", entry.Evidence)
		}
		if p := entry.Component.CryptoProperties.CertificateProperties; p != nil {
			foundCert = entry.Evidence.Context.Field == "/data/tls.crt" && p.SerialNumber != ""
		}
		if p := entry.Component.CryptoProperties.RelatedCryptoMaterialProperties; p != nil && p.Type == cdx.RelatedCryptoMaterialTypePrivateKey {
			foundKey = entry.Evidence.Context.Field == "/stringData/tls.key"
		}
	}
	if !foundCert || !foundKey {
		t.Fatal("TLS Secret material was not inventoried with field provenance")
	}
	encoded, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
	if err != nil || strings.Contains(string(encoded), "PRIVATE_SENTINEL") ||
		strings.Contains(string(encoded), string(privateKey[35:75])) ||
		strings.Contains(string(encoded), document["data"].(map[string]string)["tls.crt"]) {
		t.Fatalf("unsafe or invalid Secret output: %v", err)
	}
}

func TestManifestDetectorRunsUnchangedOnDirectoriesAndImages(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "certificate.yaml"), []byte(certificateManifest), 0600); err != nil {
		t.Fatal(err)
	}
	archive := testutil.ImageArchive(t, map[string][]byte{"manifests/certificate.yaml": []byte(certificateManifest)})
	for name, source := range map[string]input.Source{
		"local": input.Local{Path: directory},
		"image": input.Image{Path: archive},
	} {
		t.Run(name, func(t *testing.T) {
			result, err := (detect.Collector{Source: source, Detectors: []detect.Detector{Detector{}}}).Collect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			crypto := 0
			for _, entry := range result.Entries {
				if entry.Component.Type == cdx.ComponentTypeCryptographicAsset {
					crypto++
					if !strings.HasSuffix(entry.Evidence.Location, "certificate.yaml") {
						t.Fatal("input provenance lost")
					}
				}
			}
			if crypto != 3 {
				t.Fatalf("expected certificate/key/algorithm findings, got %d", crypto)
			}
			if _, err := cyclonedx.Encode([]inventory.Collection{{Result: result}}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
