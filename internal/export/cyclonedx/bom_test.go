package cyclonedx

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestEncodeStableReferencesAndEvidence(t *testing.T) {
	evidence := inventory.Evidence{
		Kind: "configured", Collector: "go", Location: "main.go", Line: 12, Symbol: "crypto/rsa.GenerateKey",
		Parameters: []inventory.ParameterEvidence{{
			Name: "key-size-bits", Value: "4096", Basis: "field-initializer", Location: "factory.go", Line: 8,
			Symbol: "example.Generator.bits", Limitation: "zero values and other constructions remain possible",
		}},
	}
	var first inventory.Result
	parent := first.Add(cdx.Component{Type: "application", Name: "example"}, inventory.Evidence{Kind: "present"}, "")
	algorithm := inventory.Algorithm("RSA", cdx.CryptoPrimitivePKE)
	ref := first.Add(algorithm, evidence, parent)
	first.Add(algorithm, evidence, parent)

	var second inventory.Result
	if got := second.Add(algorithm, evidence, parent); got != ref {
		t.Fatalf("unstable references: %s != %s", got, ref)
	}
	data, err := Encode([]inventory.Collection{{Collector: "go", Target: ".", Result: first}})
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(data); err != nil {
		t.Fatal(err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatal(err)
	}
	if len(*bom.Components) != 2 {
		t.Fatalf("expected deduplicated components, got %d", len(*bom.Components))
	}
	cryptoCount := 0
	var encodedEvidence provenance
	var occurrence cdx.EvidenceOccurrence
	for _, component := range *bom.Components {
		if component.Type == cdx.ComponentTypeCryptographicAsset && component.CryptoProperties != nil {
			cryptoCount++
			if component.Evidence == nil || component.Evidence.Occurrences == nil || len(*component.Evidence.Occurrences) != 1 {
				t.Fatal("missing or duplicated native occurrence")
			}
			occurrence = (*component.Evidence.Occurrences)[0]
			for _, property := range *component.Properties {
				if property.Name == "ciphertrail:provenance" {
					if err := json.Unmarshal([]byte(property.Value), &encodedEvidence); err != nil {
						t.Fatal(err)
					}
				} else if property.Name == "ciphertrail:evidence" {
					t.Fatal("legacy duplicate evidence is still emitted")
				}
			}
		}
	}
	if cryptoCount != 1 {
		t.Fatal("serialization changed or dropped a cryptographic-asset component")
	}
	if encodedEvidence.Occurrence == "" || encodedEvidence.Occurrence != occurrence.BOMRef ||
		encodedEvidence.Kind != evidence.Kind || encodedEvidence.Collector != evidence.Collector ||
		occurrence.Location != evidence.Location || occurrence.Line == nil || *occurrence.Line != evidence.Line || occurrence.Symbol != evidence.Symbol ||
		len(encodedEvidence.Parameters) != 1 || len(encodedEvidence.Parameters[0].Values) != 1 ||
		encodedEvidence.Parameters[0].Basis != evidence.Parameters[0].Basis ||
		encodedEvidence.Parameters[0].Limitation != evidence.Parameters[0].Limitation ||
		encodedEvidence.Parameters[0].Values[0].Location != "factory.go" ||
		encodedEvidence.Parameters[0].Values[0].Value != "4096" {
		t.Fatalf("parameter provenance was lost or rewritten: %+v", encodedEvidence)
	}
	if bom.SpecVersion != cdx.SpecVersion1_7 || bom.JSONSchema != "http://cyclonedx.org/schema/bom-1.7.schema.json" || !strings.Contains(string(data), "configured") {
		t.Fatalf("missing format or evidence: %s", data)
	}
}

func TestProvenancePreservesOccurrenceAssociationsAndGroupsLimitations(t *testing.T) {
	component := inventory.Algorithm("shared key algorithm", cdx.CryptoPrimitivePKE)
	component.BOMRef = "shared"
	inventory.
		Property(&component, "label", "unknown")
	evidence := inventory.Evidence{
		Kind: "configured", Collector: "go", Location: "main.go", Line: 4, Symbol: "example.Build",
		Unresolved: []string{"key-size-bits", "iv-size-bits", "iv-size-bits"},
		Parameters: []inventory.ParameterEvidence{
			{Name: "key-size-bits", Value: "4096", Location: "factory.go", Line: 12, Basis: "field-initializer", Limitation: "other constructions are possible"},
			{Name: "key-size-bits", Value: "2048", Location: "factory.go", Line: 6, Basis: "field-initializer", Limitation: "other constructions are possible"},
		},
	}
	var result inventory.Result
	result.Add(component, evidence, "")
	observed := inventory.Evidence{Kind: "observed", Collector: "tls", Location: "localhost:443",
		Time: "2026-10-24T00:00:00Z", Unresolved: []string{"key-size-bits"}}
	result.Add(component, observed, "")
	result.Add(component, observed, "")
	other := inventory.Algorithm("another key algorithm", cdx.CryptoPrimitivePKE)
	other.BOMRef = "other"
	result.Add(other, evidence, "")
	result.Add(inventory.Algorithm("location-free algorithm", cdx.CryptoPrimitiveHash), inventory.
		Evidence{Kind: "present", Collector: "binary", Symbol: "public-symbol"}, "")

	data, err := Encode([]inventory.Collection{{Result: result}})
	if err != nil {
		t.Fatal(err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatal(err)
	}
	globalRefs := map[string]bool{}
	foundConfigured, foundObserved, foundLocationFree, foundLiteral := false, false, false, false
	for _, component := range *bom.Components {
		localRefs := map[string]bool{}
		if component.Evidence != nil && component.Evidence.Occurrences != nil {
			for _, occurrence := range *component.Evidence.Occurrences {
				if occurrence.BOMRef == "" || globalRefs[occurrence.BOMRef] {
					t.Fatalf("missing or nonunique occurrence reference: %+v", occurrence)
				}
				globalRefs[occurrence.BOMRef], localRefs[occurrence.BOMRef] = true, true
			}
		}
		provenanceCount := 0
		for _, property := range *component.Properties {
			if property.Name == "ciphertrail:evidence" {
				t.Fatal("duplicate evidence location remains")
			}
			if property.Name == "ciphertrail:label" {
				foundLiteral = true
				if property.Value != "unknown" {
					t.Fatal("a known literal equal to unknown was rewritten")
				}
			}
			if property.Name != "ciphertrail:provenance" {
				continue
			}
			provenanceCount++
			var record provenance
			if err := json.Unmarshal([]byte(property.Value), &record); err != nil {
				t.Fatal(err)
			}
			var object map[string]json.RawMessage
			if err := json.Unmarshal([]byte(property.Value), &object); err != nil {
				t.Fatal(err)
			}
			if object["location"] != nil || object["line"] != nil {
				t.Fatal("native location duplicated in supplemental provenance")
			}
			if record.Occurrence == "" {
				foundLocationFree = component.Name == "location-free algorithm" && component.Evidence == nil &&
					record.Kind == "present" && record.Collector == "binary" && record.Symbol == "public-symbol"
				continue
			}
			if !localRefs[record.Occurrence] || object["symbol"] != nil {
				t.Fatal("provenance has a dangling occurrence reference or duplicate symbol")
			}
			switch record.Kind {
			case "configured":
				foundConfigured = true
				if !reflect.DeepEqual(record.Unresolved, []string{"iv-size-bits"}) ||
					len(record.Parameters) != 1 || len(record.Parameters[0].Values) != 2 ||
					record.Parameters[0].Values[0].Value != "2048" ||
					strings.Count(property.Value, "other constructions are possible") != 1 {
					t.Fatalf("parameter grouping, ordering, or declared-value handling failed: %+v", record)
				}
			case "observed":
				foundObserved = true
				if record.Time != observed.Time || !reflect.DeepEqual(record.Unresolved, []string{"key-size-bits"}) {
					t.Fatal("another occurrence's declaration hid an unresolved observation")
				}
			}
		}
		if component.BOMRef == "shared" && (provenanceCount != 2 || len(localRefs) != 2) {
			t.Fatal("distinct observations were collapsed or duplicates retained")
		}
	}
	if !foundConfigured || !foundObserved || !foundLocationFree || !foundLiteral {
		t.Fatal("an evidence category disappeared")
	}
	if !reflect.DeepEqual(evidence.Unresolved, []string{"key-size-bits", "iv-size-bits", "iv-size-bits"}) ||
		evidence.Parameters[0].Value != "4096" {
		t.Fatal("encoding mutated collector-owned evidence")
	}
	repeated, err := Encode([]inventory.Collection{{Result: result}})
	if err != nil {
		t.Fatal(err)
	}
	var again cdx.BOM
	if err := json.Unmarshal(repeated, &again); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(bom.Components, again.Components) {
		t.Fatal("occurrence references or compact provenance are not deterministic")
	}
}

func TestFailureBeforeAnyFindingsStillProducesValidPartialBOM(t *testing.T) {
	data, err := Encode([]inventory.Collection{{Collector: "tls", Target: "localhost:443", Err: errors.New("connection failed")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(data); err != nil {
		t.Fatal(err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatal(err)
	}
	if bom.Components != nil && len(*bom.Components) != 0 {
		t.Fatal("failed collection invented components")
	}
	incomplete := false
	for _, property := range *bom.Metadata.Properties {
		incomplete = incomplete || property.Name == "ciphertrail:collection-status" && property.Value == "incomplete"
	}
	if !incomplete {
		t.Fatal("missing incomplete collection status")
	}
}

func TestStructuredFieldsKeepDistinctOccurrencesAtTheSameSourceLine(t *testing.T) {
	var result inventory.Result
	component := inventory.Algorithm("shared", cdx.CryptoPrimitiveOther)
	component.BOMRef = "shared"
	for _, field := range []string{"/data/tls.crt", "/stringData/tls.key"} {
		evidence := inventory.Evidence{Kind: "present", Collector: "kubernetes", Location: "secret.json", Line: 1,
			Context: &inventory.SourceContext{Document: 1, Field: field, ContentLine: 1,
				Resource: &inventory.ResourceIdentity{APIVersion: "v1", Kind: "Secret", Namespace: "workload", Name: "shared"}}}
		result.Add(component, evidence, "")
	}
	bom := encodeForTest(t, []inventory.Collection{{Result: result}}, EncodeOptions{})
	got := (*bom.Components)[0]
	if got.Evidence == nil || len(*got.Evidence.Occurrences) != 2 {
		t.Fatal("same-line resource fields collapsed into one occurrence")
	}
	refs := map[string]bool{}
	for _, occurrence := range *got.Evidence.Occurrences {
		refs[occurrence.BOMRef] = true
	}
	if len(refs) != 2 {
		t.Fatal("structured occurrence references are not unique")
	}
	fields := map[string]bool{}
	for _, property := range *got.Properties {
		if property.Name != "ciphertrail:provenance" {
			continue
		}
		var record provenance
		if err := json.Unmarshal([]byte(property.Value), &record); err != nil {
			t.Fatal(err)
		}
		if !refs[record.Occurrence] || record.Context == nil || record.Context.Resource.Name != "shared" {
			t.Fatal("structured context lost its occurrence association")
		}
		fields[record.Context.Field] = true
	}
	if len(fields) != 2 {
		t.Fatal("resource field provenance disappeared")
	}
}

func TestValidateRejectsInvalidBOM(t *testing.T) {
	if err := Validate([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7","version":1,"components":[{"type":"cryptographic-asset"}]}`)); err == nil {
		t.Fatal("invalid component passed schema validation")
	}
}

func TestValidateRequires17AndItsCryptographyDefinitions(t *testing.T) {
	if err := Validate([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`)); err == nil {
		t.Fatal("validator accepted a document claiming the old format")
	}
	for _, curve := range []string{"nist/P-256", "other/Ed25519", "other/Curve25519"} {
		data := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.7","version":1,"components":[{"type":"cryptographic-asset","name":"curve","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"ellipticCurve":"` + curve + `"}}}]}`)
		if err := Validate(data); err != nil {
			t.Errorf("valid 1.7 curve %s failed offline validation: %v", curve, err)
		}
	}
	if err := Validate([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7","version":1,"components":[{"type":"cryptographic-asset","name":"curve","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"ellipticCurve":"P-256"}}}]}`)); err == nil {
		t.Fatal("noncanonical curve bypassed the 1.7 enum")
	}
}

func TestNativeRelatedCryptoReferencesAreValidated(t *testing.T) {
	for _, properties := range []*cdx.CryptoProperties{
		{AssetType: cdx.CryptoAssetTypeCertificate, CertificateProperties: &cdx.CertificateProperties{RelatedCryptographicAssets: &[]cdx.RelatedCryptographicAsset{{Type: "publicKey", Ref: "missing"}}}},
		{AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial, RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{RelatedCryptographicAssets: &[]cdx.RelatedCryptographicAsset{{Type: "algorithm", Ref: "missing"}}}},
		{AssetType: cdx.CryptoAssetTypeProtocol, ProtocolProperties: &cdx.CryptoProtocolProperties{RelatedCryptographicAssets: &[]cdx.RelatedCryptographicAsset{{Type: "certificate", Ref: "missing"}}}},
	} {
		var result inventory.Result
		result.Add(cdx.Component{Type: cdx.ComponentTypeCryptographicAsset, Name: "asset", CryptoProperties: properties}, inventory.Evidence{}, "")
		if _, err := Encode([]inventory.Collection{{Result: result}}); err == nil {
			t.Errorf("dangling native 1.7 relationship accepted for %s", properties.AssetType)
		}
	}
}

func TestGoCurveIdentifiers(t *testing.T) {
	for name, want := range map[string]string{
		"P-224": "nist/P-224", "P-256": "nist/P-256", "P-384": "nist/P-384", "P-521": "nist/P-521",
		"Ed25519": "other/Ed25519", "X25519": "other/Curve25519", "": "", "unsupported": "unsupported",
	} {
		if got := inventory.CurveID(name); got != want {
			t.Errorf("%s: got %s, want %s", name, got, want)
		}
	}
}

func TestEncodeRejectsDanglingReferences(t *testing.T) {
	var result inventory.Result
	result.Add(inventory.Algorithm("SHA-256", cdx.CryptoPrimitiveHash), inventory.Evidence{}, "missing")
	if _, err := Encode([]inventory.Collection{{Result: result}}); err == nil {
		t.Fatal("dangling dependency accepted")
	}

}

func TestFocusedExportKeepsCryptoContextWithoutImportingUnrelatedLibraries(t *testing.T) {
	var result inventory.Result
	present := inventory.Evidence{Kind: "present", Collector: "go", Location: "go.mod"}
	image := result.Add(cdx.Component{Type: "container", Name: "image"}, present, "")
	owner := result.Add(cdx.Component{Type: "application", Name: "owner"}, present, image)
	provider := result.Add(cdx.Component{Type: "library", Name: "crypto-provider"}, present, "")
	xml := result.Add(cdx.Component{Type: "library", Name: "xmlquery"}, present, "")
	format := result.Add(cdx.Component{Type: "library", Name: "tabwriter"}, present, "")
	result.DependOn(owner, xml)
	result.DependOn(owner, provider)
	result.DependOn(xml, format)
	result.DependOn(format, xml)
	result.DependOn(format, provider)
	hash := result.Add(inventory.Algorithm("SHA-256", cdx.CryptoPrimitiveHash), inventory.Evidence{Kind: "configured", Location: "main.go"}, owner)
	result.DependOn(hash, provider)

	full := encodeForTest(t, []inventory.Collection{{Result: result}}, EncodeOptions{IncludeDependencies: true})
	focused := encodeForTest(t, []inventory.Collection{{Result: result}}, EncodeOptions{})
	want := map[string]bool{image: true, owner: true, provider: true, hash: true}
	if len(*full.Components) != 6 || len(*focused.Components) != len(want) {
		t.Fatalf("wrong component counts: full=%d focused=%d", len(*full.Components), len(*focused.Components))
	}
	for _, component := range *focused.Components {
		if !want[component.BOMRef] {
			t.Fatalf("unrelated component retained: %s", component.Name)
		}
		if component.Type == cdx.ComponentTypeCryptographicAsset {
			for _, original := range *full.Components {
				if original.BOMRef == component.BOMRef && !reflect.DeepEqual(original, component) {
					t.Fatal("scope selection changed cryptographic properties or evidence")
				}
			}
		}
	}
	assertClosedGraph(t, focused)
	assertClosedGraph(t, full)
	edges := map[string][]string{}
	for _, dependency := range *focused.Dependencies {
		edges[dependency.Ref] = *dependency.Dependencies
	}
	if len(edges[hash]) != 1 || edges[hash][0] != provider {
		t.Fatal("implementation provider link lost")
	}
	for _, dependency := range edges[owner] {
		if dependency == xml || dependency == format {
			t.Fatal("dangling unrelated dependency retained")
		}
	}
	data, err := Encode([]inventory.Collection{{Result: result}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "xmlquery") || !strings.Contains(string(data), "crypto-focused") {
		t.Fatal("Encode did not use crypto-focused output by default")
	}
}

func TestFocusedExportPreservesCryptoReferencesAndSharedOwnership(t *testing.T) {
	var result inventory.Result
	evidence := inventory.Evidence{Kind: "observed", Collector: "tls"}
	a := result.Add(cdx.Component{Type: "application", Name: "a"}, evidence, "")
	b := result.Add(cdx.Component{Type: "application", Name: "b"}, evidence, "")
	algorithm := inventory.Algorithm("RSA", cdx.CryptoPrimitiveSignature)
	algorithmRef := result.Add(algorithm, evidence, a)
	algorithm.BOMRef = algorithmRef
	result.Add(algorithm, evidence, b)
	key := cdx.Component{Type: "cryptographic-asset", Name: "public key", CryptoProperties: &cdx.CryptoProperties{
		AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
		RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
			Type:                       cdx.RelatedCryptoMaterialTypePublicKey,
			RelatedCryptographicAssets: &[]cdx.RelatedCryptographicAsset{{Type: "algorithm", Ref: algorithmRef}},
		},
	}}
	keyRef := result.Add(key, evidence, a)
	certificate := cdx.Component{Type: "cryptographic-asset", Name: "certificate", CryptoProperties: &cdx.CryptoProperties{
		AssetType: cdx.CryptoAssetTypeCertificate,
		CertificateProperties: &cdx.CertificateProperties{
			RelatedCryptographicAssets: &[]cdx.RelatedCryptographicAsset{
				{Type: "publicKey", Ref: keyRef}, {Type: "signatureAlgorithm", Ref: algorithmRef},
			},
		},
	}}
	certificateRef := result.Add(certificate, evidence, a)
	protocol := cdx.Component{Type: "cryptographic-asset", Name: "TLS", CryptoProperties: &cdx.CryptoProperties{
		AssetType: cdx.CryptoAssetTypeProtocol,
		ProtocolProperties: &cdx.CryptoProtocolProperties{
			Type:                       cdx.CryptoProtocolTypeTLS,
			RelatedCryptographicAssets: &[]cdx.RelatedCryptographicAsset{{Type: "certificate", Ref: certificateRef}},
			CipherSuites:               &[]cdx.CipherSuite{{Name: "fixture", Algorithms: &[]cdx.BOMReference{cdx.BOMReference(algorithmRef)}}},
		},
	}}
	result.Add(protocol, evidence, a)
	result.Add(cdx.Component{Type: "library", Name: "unrelated"}, evidence, "")
	bom := encodeForTest(t, []inventory.Collection{{Result: result}}, EncodeOptions{})
	if len(*bom.Components) != 6 {
		t.Fatalf("lost shared ownership or crypto context: %d components", len(*bom.Components))
	}
	assertClosedGraph(t, bom)
}

func TestFocusedEmptyReportPreservesScopeAndErrors(t *testing.T) {
	var result inventory.Result
	result.Add(cdx.Component{Type: "library", Name: "unrelated"}, inventory.Evidence{Kind: "present"}, "")
	result.Properties = []cdx.Property{{Name: "ciphertrail:analysis-scope", Value: "configured, not executed"}}
	result.Diagnostics = []inventory.Diagnostic{{Message: "unmodeled API", Location: "main.go", Line: 3}}
	collections := []inventory.Collection{{Collector: "go", Target: ".", Result: result, Err: errors.New("load failed")}}
	bom := encodeForTest(t, collections, EncodeOptions{})
	if len(*bom.Components) != 0 || len(*bom.Dependencies) != 0 {
		t.Fatal("crypto-free input was not pruned")
	}
	data, err := json.Marshal(bom)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"configured, not executed", "unmodeled API", "load failed", "incomplete", "crypto-focused"} {
		if !strings.Contains(string(data), value) {
			t.Errorf("lost collection context %q", value)
		}
	}
	full := encodeForTest(t, collections, EncodeOptions{IncludeDependencies: true})
	if len(*full.Components) != 1 {
		t.Fatal("full inventory omitted collected software")
	}
}

func TestPruningDoesNotHideInvalidDependencies(t *testing.T) {
	for _, include := range []bool{false, true} {
		var result inventory.Result
		ref := result.Add(cdx.Component{Type: "library", Name: "unrelated"}, inventory.Evidence{}, "")
		result.DependOn(ref, "missing")
		if _, err := EncodeWithOptions([]inventory.Collection{{Result: result}}, EncodeOptions{IncludeDependencies: include}); err == nil {
			t.Fatal("invalid graph was hidden by pruning")
		}
	}
}

func TestFocusedExportHandlesOwnershipCycles(t *testing.T) {
	var result inventory.Result
	a, b := inventory.Ref("owner-a"), inventory.Ref("owner-b")
	result.Add(cdx.Component{BOMRef: a, Type: "application", Name: "a"}, inventory.Evidence{}, b)
	result.Add(cdx.Component{BOMRef: b, Type: "application", Name: "b"}, inventory.Evidence{}, a)
	result.Add(inventory.Algorithm("SHA-256", cdx.CryptoPrimitiveHash), inventory.Evidence{}, a)
	result.Add(cdx.Component{Type: "library", Name: "unrelated"}, inventory.Evidence{}, "")
	bom := encodeForTest(t, []inventory.Collection{{Result: result}}, EncodeOptions{})
	if len(*bom.Components) != 3 {
		t.Fatal("ownership cycle lost context or retained unrelated components")
	}
	assertClosedGraph(t, bom)
}

func TestSecuredByReferencesAreValidatedBeforePruning(t *testing.T) {
	var result inventory.Result
	component := cdx.Component{Type: "cryptographic-asset", Name: "encrypted key", CryptoProperties: &cdx.CryptoProperties{
		AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
		RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
			Type:      cdx.RelatedCryptoMaterialTypePrivateKey,
			SecuredBy: &cdx.SecuredBy{AlgorithmRef: cdx.BOMReference("missing")},
		},
	}}
	result.Add(component, inventory.Evidence{}, "")
	if _, err := Encode([]inventory.Collection{{Result: result}}); err == nil {
		t.Fatal("dangling key-protection reference accepted")
	}
}

func encodeForTest(t *testing.T, collections []inventory.Collection, options EncodeOptions) cdx.BOM {
	t.Helper()
	data, err := EncodeWithOptions(collections, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(data); err != nil {
		t.Fatal(err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatal(err)
	}
	return bom
}

func assertClosedGraph(t *testing.T, bom cdx.BOM) {
	t.Helper()
	refs := map[string]bool{}
	for _, component := range *bom.Components {
		refs[component.BOMRef] = true
	}
	for _, dependency := range *bom.Dependencies {
		if !refs[dependency.Ref] {
			t.Errorf("dangling dependency source %s", dependency.Ref)
		}
		for _, ref := range *dependency.Dependencies {
			if !refs[ref] {
				t.Errorf("dangling dependency target %s", ref)
			}
		}
	}
	for _, component := range *bom.Components {
		for _, ref := range cryptoReferences(&component) {
			if !refs[ref] {
				t.Errorf("dangling crypto reference %s", ref)
			}
		}
	}
}

func TestEncodePreservesCrossCollectorEnrichment(t *testing.T) {
	var result inventory.Result
	first := inventory.Algorithm("RSA", cdx.CryptoPrimitivePKE)
	first.BOMRef = inventory.Ref("same-key")
	result.Add(first, inventory.Evidence{Kind: "present", Collector: "file"}, "")
	second := first
	inventory.
		Property(&second, "ssh-key-format", "ssh-rsa")
	result.Add(second, inventory.Evidence{Kind: "observed", Collector: "ssh"}, "")
	data, err := Encode([]inventory.Collection{{Result: result}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "ssh-key-format") || !strings.Contains(string(data), "observed") {
		t.Fatal("cross-collector metadata was discarded")
	}
}
