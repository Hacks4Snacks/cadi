package kubernetes

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
	"unicode/utf16"

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
		{"wrong-field-type", "apiVersion: cert-manager.io/v1\nkind: Certificate\nmetadata: {name: public}\nspec: {isCA: {PRIVATE_SENTINEL: invalid}}\n"},
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
		if unresolved {
			t.Fatal("ignored deployment detail was still analyzed")
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
    spec: {commonName: "unknown", isCA: false, privateKey: {algorithm: RSA, size: 0, encoding: "unknown"}}
`)
	if err != nil || len(result.Diagnostics) != 1 {
		t.Fatalf("mixed documents failed: %v %+v", err, result.Diagnostics)
	}
	documents := map[int]bool{}
	literalEncoding := false
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
				if properties["ciphertrail:cert-manager.common-name"] != "" || properties["ciphertrail:cert-manager.is-ca"] != "false" {
					t.Fatal("omitted identity or retained CA setting changed")
				}
			}
		}
		if entry.Component.Name == "cert-manager Private key configuration" && entry.Evidence.Context.Document == 3 {
			for _, property := range *entry.Component.Properties {
				literalEncoding = literalEncoding || property.Name == "ciphertrail:cert-manager.key-encoding" && property.Value == "unknown"
			}
		}
	}
	if len(documents) != 2 || !documents[1] || !documents[3] || !literalEncoding {
		t.Fatal("one unrendered document suppressed other configured resources")
	}
}

func TestYAMLDocumentFramingMatchesStreamGrammar(t *testing.T) {
	first := "{apiVersion: cert-manager.io/v1, kind: Certificate, metadata: {name: first}, spec: {}}\n"
	second := "{apiVersion: cert-manager.io/v1, kind: Certificate, metadata: {name: second}, spec: {}}\n"
	type frameCase struct {
		name, document string
		lines          []int
		documents      []int
		fail           bool
	}
	tests := []frameCase{
		{"inline", "--- " + first + "--- " + second, []int{1, 2}, []int{1, 2}, false},
		{"standalone", "---\n" + first + "---\n" + second, []int{2, 4}, []int{1, 2}, false},
		{"tabs", "---\t" + first + "---\t" + second, []int{1, 2}, []int{1, 2}, false},
		{"directives", "%YAML 1.1\n--- " + first + "...\n%YAML 1.1\n--- " + second + "...\n", []int{2, 5}, []int{1, 2}, false},
		{"tag-directive", "%TAG !e! tag:example.test,2026:\n--- !e!resource " + first, []int{2}, []int{1}, false},
		{"end-markers", "--- " + first + "... # end\n--- " + second + "...\n", []int{1, 3}, []int{1, 2}, false},
		{"bare-after-end", first + "...\n" + second, []int{1, 3}, []int{1, 2}, false},
		{"utf8-bom-directives", "\xef\xbb\xbf%YAML 1.1\n--- " + first + "--- " + second, []int{2, 3}, []int{1, 2}, false},
		{"empty-document", "---\n--- " + first, []int{2}, []int{2}, false},
		{"malformed-middle", "--- " + first + "--- {apiVersion: cert-manager.io/v1, kind: Certificate, spec: [PRIVATE_SENTINEL\n--- " + second, []int{1, 3}, []int{1, 3}, true},
	}
	for _, ending := range []string{"\r\n", "\r", "\u0085", "\u2028", "\u2029"} {
		tests = append(tests, frameCase{"line-ending-" + strconv.Quote(ending),
			strings.ReplaceAll("--- "+first+"--- "+second, "\n", ending), []int{1, 2}, []int{1, 2}, false})
	}
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		units := utf16.Encode([]rune("--- " + first + "--- " + second))
		data := make([]byte, 2+2*len(units))
		order.PutUint16(data, 0xfeff)
		for index, unit := range units {
			order.PutUint16(data[2+index*2:], unit)
		}
		tests = append(tests, frameCase{"utf16-" + order.String(), string(data), []int{1, 2}, []int{1, 2}, false})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := collectManifest(t, test.document)
			if (err != nil) != test.fail || err != nil && strings.Contains(err.Error(), "PRIVATE_SENTINEL") {
				t.Fatalf("incorrect framing outcome: %v", err)
			}
			var lines, documents []int
			for _, entry := range result.Entries {
				if entry.Component.Name == "cert-manager Certificate configuration" {
					lines = append(lines, entry.Evidence.Line)
					documents = append(documents, entry.Evidence.Context.Document)
				}
			}
			if !slices.Equal(lines, test.lines) || !slices.Equal(documents, test.documents) {
				t.Errorf("wrong document evidence: lines=%v documents=%v", lines, documents)
			}
			encoded, encodeErr := cyclonedx.Encode([]inventory.Collection{{Result: result, Err: err}})
			if encodeErr != nil || strings.Contains(string(encoded), "PRIVATE_SENTINEL") {
				t.Fatalf("unsafe partial inventory: %v", encodeErr)
			}
		})
	}
}

func TestYAMLFramingPreservesRenderedAndEmbeddedLocations(t *testing.T) {
	document := "%YAML 1.1\n# Source: first/templates/certificate.yaml\n" +
		"--- {apiVersion: cert-manager.io/v1, kind: Certificate, metadata: {name: first}, spec: {}}\n...\n" +
		"%YAML 1.1\n# Source: second/templates/certificate.yaml\n" +
		"--- {apiVersion: cert-manager.io/v1, kind: Certificate, metadata: {name: second}, spec: {}}\n...\n"
	for _, embedded := range []bool{false, true} {
		t.Run(strconv.FormatBool(embedded), func(t *testing.T) {
			data := document
			if embedded {
				data = configMapDocument(t, document, true)
			}
			result, err := collectManifest(t, data)
			if err != nil {
				t.Fatal(err)
			}
			var lines, documents []int
			var origins []string
			for _, entry := range result.Entries {
				if entry.Component.Name != "cert-manager Certificate configuration" {
					continue
				}
				context := entry.Evidence.Context
				if embedded {
					if entry.Evidence.Line != 1 || len(context.Embedded) != 1 {
						t.Fatalf("embedded document overwrote its containing location: %+v", entry.Evidence)
					}
					frame := context.Embedded[0]
					lines, documents = append(lines, frame.Line), append(documents, frame.Document)
				} else {
					lines, documents = append(lines, entry.Evidence.Line), append(documents, context.Document)
					origins = append(origins, context.RenderedFrom)
				}
			}
			if !slices.Equal(lines, []int{3, 7}) || !slices.Equal(documents, []int{1, 2}) {
				t.Fatalf("framing lost logical positions: lines=%v documents=%v", lines, documents)
			}
			if !embedded && !slices.Equal(origins, []string{"first/templates/certificate.yaml", "second/templates/certificate.yaml"}) {
				t.Errorf("framing lost source comments: %v", origins)
			}
		})
	}
}

func TestOversizedJSONRecognitionIsStructuralAndExact(t *testing.T) {
	for _, test := range []struct {
		data           string
		resource, fail bool
	}{
		{`{"apiVersion":"v1","kind":"ConfigMap"}`, true, false},
		{`{"\u0061piVersion":"v1","\u006bind":"ConfigMap"}`, true, false},
		{`{"ApiVersion":"v1","Kind":"ConfigMap"}`, false, false},
		{`{"nested":{"apiVersion":"v1","kind":"ConfigMap"}}`, false, false},
		{`[{"apiVersion":"v1","kind":"ConfigMap"}]`, false, false},
		{`"apiVersion: v1 kind: ConfigMap"`, false, false},
		{`null`, false, false},
		{`{"apiVersion":"v1","kind":"ConfigMap"} PRIVATE_SENTINEL`, false, true},
		{`apiVersion: v1\nkind: ConfigMap\nPRIVATE_SENTINEL`, false, true},
	} {
		found, err := oversizedJSONResource(context.Background(), []byte(test.data))
		if found != test.resource || (err != nil) != test.fail || err != nil && strings.Contains(err.Error(), "PRIVATE_SENTINEL") {
			t.Errorf("incorrect or unsafe structural recognition: resource=%v error=%v", found, err)
		}
	}
}

func TestKubernetesRecognitionBudgetAndReadErrorsAreExplicit(t *testing.T) {
	file := input.NewFile("unknown.json", maxRecognitionBytes+1, strings.NewReader(""))
	_, found, err := (Detector{}).Detect(context.Background(), file)
	if err == nil || found || !strings.Contains(err.Error(), "applicability undetermined") ||
		!strings.Contains(err.Error(), strconv.FormatInt(maxRecognitionBytes, 10)) {
		t.Fatalf("unclassifiable input was mislabeled as a manifest failure: %v", err)
	}
	readErr := errors.New("read failure")
	file = input.NewFile("unreadable.json", -1, iotest.ErrReader(readErr))
	_, found, err = (Detector{}).Detect(context.Background(), file)
	if !errors.Is(err, readErr) || found {
		t.Fatalf("recognition hid an input read failure: %v", err)
	}
}

func TestAutomaticManifestSizeBoundary(t *testing.T) {
	base := `{"apiVersion":"cert-manager.io/v1","kind":"Certificate","metadata":{"name":"size-boundary"},"spec":{}}`
	for _, extra := range []int{0, 1} {
		t.Run(strconv.Itoa(extra), func(t *testing.T) {
			data := base + strings.Repeat(" ", int(MaxManifestBytes)-len(base)+extra)
			file := input.NewFile("manifest.json", int64(len(data)), strings.NewReader(data))
			file.Evidence = inventory.Evidence{Kind: "present", Collector: "file", Location: "manifest.json"}
			result, found, err := (Detector{}).Detect(context.Background(), file)
			if !found || (err != nil) != (extra > 0) {
				t.Fatalf("manifest parsing boundary changed: found=%v err=%v", found, err)
			}
			if extra == 0 && len(result.Entries) == 0 || extra > 0 && len(result.Entries) != 0 {
				t.Fatal("incorrect findings at manifest parsing boundary")
			}
		})
	}
}

func TestLargeNonResourceJSONDoesNotFailKubernetesDetection(t *testing.T) {
	padding := strings.Repeat("x", 17<<20)
	for _, test := range []struct {
		name, data string
		explicit   bool
		resource   bool
		fail       bool
	}{
		{"ordinary", `{"data":"` + padding + `"}`, false, false, false},
		{"array", `["` + padding + `"]`, false, false, false},
		{"nested-header", `{"data":"` + padding + `","nested":{"apiVersion":"v1","kind":"Secret"}}`, false, false, false},
		{"manifest-header-last", `{"data":"` + padding + `","apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"large"}}`, false, true, true},
		{"explicit", `{"data":"` + padding + `"}`, true, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			file := input.NewFile("large.json", int64(len(test.data)), strings.NewReader(test.data))
			file.Explicit = test.explicit
			file.Evidence = inventory.Evidence{Kind: "present", Collector: "file", Location: "large.json"}
			result, recognized, err := (Detector{}).Detect(context.Background(), file)
			if (err != nil) != test.fail || recognized != test.resource {
				t.Fatalf("unrelated JSON and confirmed manifests were conflated: recognized=%v err=%v", recognized, err)
			}
			if len(result.Entries) != 0 {
				t.Fatal("oversized/unrelated JSON created guessed findings")
			}
		})
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
