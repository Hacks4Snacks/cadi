package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"ciphertrail/internal/export/cyclonedx"
	"ciphertrail/internal/input"
	"ciphertrail/internal/inventory"
)

func TestManifestLimitsDoNotLeakParserInput(t *testing.T) {
	for _, test := range []struct {
		name, document string
	}{
		{"duplicate-key", "apiVersion: cert-manager.io/v1\nkind: Certificate\nmetadata: {name: public}\nspec: {secretName: PRIVATE_SENTINEL, secretName: duplicate}\n"},
		{"alias", "apiVersion: cert-manager.io/v1\nkind: Certificate\nmetadata: {name: public}\nspec: {secretName: &private PRIVATE_SENTINEL, commonName: *private}\n"},
		{"invalid-yaml", "apiVersion: cert-manager.io/v1\nkind: Certificate\nmetadata: {name: public}\nspec: [PRIVATE_SENTINEL: [\n"},
		{"wrong-field-type", "apiVersion: cert-manager.io/v1\nkind: Certificate\nmetadata: {name: public}\nspec: {duration: {PRIVATE_SENTINEL: invalid}}\n"},
		{"invalid-base64", "apiVersion: v1\nkind: Secret\nmetadata: {name: public}\ntype: kubernetes.io/tls\ndata: {tls.crt: 'PRIVATE_SENTINEL!'}\n"},
		{"invalid-material", "apiVersion: v1\nkind: Secret\nmetadata: {name: public}\ntype: kubernetes.io/tls\nstringData: {tls.crt: PRIVATE_SENTINEL}\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := collectManifest(t, certificateManifest+"---\n"+test.document)
			if err == nil {
				t.Fatal("malformed selected resource was accepted")
			}
			if strings.Contains(err.Error(), "PRIVATE_SENTINEL") {
				t.Fatal("parser diagnostics leaked input")
			}
			data, encodeErr := cyclonedx.Encode([]inventory.Collection{{Result: result, Err: err}})
			if encodeErr != nil || strings.Contains(string(data), "PRIVATE_SENTINEL") {
				t.Fatalf("unsafe partial result: %v", encodeErr)
			}
			found := false
			for _, entry := range result.Entries {
				found = found || entry.Component.Name == "cert-manager Certificate configuration" && entry.Evidence.Context.Document == 1
			}
			if !found {
				t.Fatal("later failure discarded a successful earlier document")
			}
		})
	}
}

func TestTemplatesAndUnsupportedResourcesAreExplicitLimitations(t *testing.T) {
	for _, document := range []string{
		"apiVersion: cert-manager.io/v1\nkind: Certificate\nmetadata:\n  name: {{ .Release.Name }}\n",
		"apiVersion: example.test/v1\nkind: Certificate\nmetadata: {name: lookalike}\n",
		"apiVersion: v1\nkind: Secret\nmetadata: {name: ignored}\ntype: Opaque\nstringData: {password: PRIVATE_SENTINEL}\n",
	} {
		result, err := collectManifest(t, document)
		if err != nil || len(result.Diagnostics) == 0 {
			t.Fatalf("scope limitation was not reported: %v", err)
		}
		data, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
		if err != nil || strings.Contains(string(data), "PRIVATE_SENTINEL") {
			t.Fatalf("unsupported contents leaked: %v", err)
		}
		for _, entry := range result.Entries {
			if entry.Component.CryptoProperties != nil {
				t.Fatal("unsupported resource or template produced invented crypto")
			}
		}
	}
}

func TestListItemsHaveDistinctResourceAndFieldContexts(t *testing.T) {
	document := `{"apiVersion":"v1","kind":"List","items":[
{"apiVersion":"cert-manager.io/v1","kind":"Certificate","metadata":{"name":"same","namespace":"one"},"spec":{}},
{"apiVersion":"cert-manager.io/v1","kind":"Certificate","metadata":{"name":"same","namespace":"two"},"spec":{}}
]}`
	result, err := collectManifest(t, document)
	if err != nil {
		t.Fatal(err)
	}
	fields, namespaces := map[string]bool{}, map[string]bool{}
	for _, entry := range result.Entries {
		if entry.Component.Name != "cert-manager Certificate configuration" {
			continue
		}
		fields[entry.Evidence.Context.Field] = true
		namespaces[entry.Evidence.Context.Resource.Namespace] = true
		if entry.Component.Properties != nil && len(*entry.Component.Properties) != 0 {
			t.Fatal("empty spec invented defaults")
		}
	}
	if !fields["/items/0/spec"] || !fields["/items/1/spec"] || len(namespaces) != 2 {
		t.Fatal("List items lost their identities")
	}
	if _, err := cyclonedx.Encode([]inventory.Collection{{Result: result}}); err != nil {
		t.Fatal(err)
	}
}

func TestLiteralTemplateTextOutsideSupportedFieldsDoesNotHideResources(t *testing.T) {
	document := strings.Replace(certificateManifest, "  secretName: service-tls",
		"  secretName: service-tls\n  ignored: '{{ runtime.expression }}'\n  commonName: '{{ .Values.commonName }}'", 1)
	result, err := collectManifest(t, document)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range result.Entries {
		if entry.Component.Name != "cert-manager Certificate configuration" {
			continue
		}
		found = true
		unresolved := false
		for _, name := range entry.Evidence.Unresolved {
			unresolved = unresolved || name == "cert-manager.common-name"
		}
		if !unresolved {
			t.Fatal("templated field was reported as a resolved literal")
		}
	}
	if !found {
		t.Fatal("a templated field hid otherwise resolvable certificate configuration")
	}
	data, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
	if err != nil || strings.Contains(string(data), "runtime.expression") || strings.Contains(string(data), ".Values.commonName") {
		t.Fatalf("template bodies were exported: %v", err)
	}
}

func TestManifestCancellationAndSizeLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	file := input.NewFile("cancelled.yaml", 0, strings.NewReader(""))
	if _, _, err := (Detector{Strict: true}).Detect(ctx, file); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation ignored: %v", err)
	}
	file = input.NewFile("oversized.yaml", MaxManifestBytes+1, strings.NewReader(""))
	if _, _, err := (Detector{Strict: true}).Detect(context.Background(), file); err == nil {
		t.Fatal("manifest limit not enforced")
	}
}

func TestOrdinaryJSONIsNotTreatedAsKubernetes(t *testing.T) {
	data := `{"kind":"not-a-resource","password":"PRIVATE_SENTINEL"}`
	file := input.NewFile("config.json", int64(len(data)), strings.NewReader(data))
	result, recognized, err := (Detector{}).Detect(context.Background(), file)
	if err != nil || recognized || len(result.Entries) != 0 {
		t.Fatalf("ordinary JSON was mistaken for Kubernetes: %v", err)
	}
	encoded, err := json.Marshal(result.Diagnostics)
	if err != nil || strings.Contains(string(encoded), "PRIVATE_SENTINEL") {
		t.Fatal("unrelated JSON content leaked")
	}
}

func TestMixedTemplatesAndTypedListsPreserveOtherDocuments(t *testing.T) {
	result, err := collectManifest(t, certificateManifest+`---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: "{{ .Release.Name }}"}
---
apiVersion: cert-manager.io/v1
kind: CertificateList
items:
  - metadata: {name: another}
    spec: {commonName: "unknown", isCA: false, privateKey: {algorithm: RSA, size: 0}}
`)
	if err != nil || len(result.Diagnostics) != 1 {
		t.Fatalf("mixed documents failed: %v %+v", err, result.Diagnostics)
	}
	documents := map[int]bool{}
	for _, entry := range result.Entries {
		if entry.Component.Name == "cert-manager Certificate configuration" {
			documents[entry.Evidence.Context.Document] = true
			if entry.Evidence.Context.Document == 3 {
				if entry.Evidence.Context.Resource.Namespace != "" {
					t.Fatal("omitted namespace was assumed to be default")
				}
				properties := map[string]string{}
				for _, p := range *entry.Component.Properties {
					properties[p.Name] = p.Value
				}
				if properties["ciphertrail:cert-manager.common-name"] != "unknown" || properties["ciphertrail:cert-manager.is-ca"] != "false" {
					t.Fatal("literal unknown/false values were discarded")
				}
			}
		}
	}
	if len(documents) != 2 || !documents[1] || !documents[3] {
		t.Fatal("one unrendered document suppressed other configured resources")
	}
}

func TestBlockScalarDoesNotCreatePhantomDocuments(t *testing.T) {
	result, err := collectManifest(t, strings.Replace(certificateManifest, "  secretName: service-tls",
		"  secretName: service-tls\n  ignored: |\n    ---\n    PRIVATE_SENTINEL", 1))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range result.Entries {
		if entry.Evidence.Context.Document != 1 {
			t.Fatal("an indented scalar separator split the document")
		}
	}
	data, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
	if err != nil || strings.Contains(string(data), "PRIVATE_SENTINEL") {
		t.Fatal("unrelated scalar contents were exported")
	}
}
