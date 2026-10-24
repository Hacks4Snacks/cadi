package inventory

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestEncodeStableReferencesAndEvidence(t *testing.T) {
	evidence := Evidence{Kind: "configured", Collector: "go", Location: "main.go", Line: 12, Symbol: "crypto/rsa.GenerateKey"}
	var first Result
	parent := first.Add(cdx.Component{Type: "application", Name: "example"}, Evidence{Kind: "present"}, "")
	algorithm := Algorithm("RSA", cdx.CryptoPrimitivePKE)
	ref := first.Add(algorithm, evidence, parent)
	first.Add(algorithm, evidence, parent)

	var second Result
	if got := second.Add(algorithm, evidence, parent); got != ref {
		t.Fatalf("unstable references: %s != %s", got, ref)
	}
	data, err := Encode([]Collection{{Collector: "go", Target: ".", Result: first}})
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
	for _, component := range *bom.Components {
		if component.Type == cdx.ComponentTypeCryptographicAsset && component.CryptoProperties != nil {
			cryptoCount++
		}
	}
	if cryptoCount != 1 {
		t.Fatal("serialization changed or dropped a cryptographic-asset component")
	}
	if bom.SpecVersion != cdx.SpecVersion1_7 || bom.JSONSchema != "http://cyclonedx.org/schema/bom-1.7.schema.json" || !strings.Contains(string(data), "configured") {
		t.Fatalf("missing format or evidence: %s", data)
	}
}

func TestFailureBeforeAnyFindingsStillProducesValidPartialBOM(t *testing.T) {
	data, err := Encode([]Collection{{Collector: "tls", Target: "localhost:443", Err: errors.New("connection failed")}})
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
		var result Result
		result.Add(cdx.Component{Type: cdx.ComponentTypeCryptographicAsset, Name: "asset", CryptoProperties: properties}, Evidence{}, "")
		if _, err := Encode([]Collection{{Result: result}}); err == nil {
			t.Errorf("dangling native 1.7 relationship accepted for %s", properties.AssetType)
		}
	}
}

func TestGoCurveIdentifiers(t *testing.T) {
	for name, want := range map[string]string{
		"P-224": "nist/P-224", "P-256": "nist/P-256", "P-384": "nist/P-384", "P-521": "nist/P-521",
		"Ed25519": "other/Ed25519", "X25519": "other/Curve25519", "": "", "unsupported": "unsupported",
	} {
		if got := CurveID(name); got != want {
			t.Errorf("%s: got %s, want %s", name, got, want)
		}
	}
}

func TestEncodeRejectsDanglingReferences(t *testing.T) {
	var result Result
	result.Add(Algorithm("SHA-256", cdx.CryptoPrimitiveHash), Evidence{}, "missing")
	if _, err := Encode([]Collection{{Result: result}}); err == nil {
		t.Fatal("dangling dependency accepted")
	}

}

func TestFocusedExportKeepsCryptoContextWithoutImportingUnrelatedLibraries(t *testing.T) {
	var result Result
	present := Evidence{Kind: "present", Collector: "go", Location: "go.mod"}
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
	hash := result.Add(Algorithm("SHA-256", cdx.CryptoPrimitiveHash), Evidence{Kind: "configured", Location: "main.go"}, owner)
	result.DependOn(hash, provider)

	full := encodeForTest(t, []Collection{{Result: result}}, EncodeOptions{IncludeDependencies: true})
	focused := encodeForTest(t, []Collection{{Result: result}}, EncodeOptions{})
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
	data, err := Encode([]Collection{{Result: result}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "xmlquery") || !strings.Contains(string(data), "crypto-focused") {
		t.Fatal("Encode did not use crypto-focused output by default")
	}
}

func TestFocusedExportPreservesCryptoReferencesAndSharedOwnership(t *testing.T) {
	var result Result
	evidence := Evidence{Kind: "observed", Collector: "tls"}
	a := result.Add(cdx.Component{Type: "application", Name: "a"}, evidence, "")
	b := result.Add(cdx.Component{Type: "application", Name: "b"}, evidence, "")
	algorithm := Algorithm("RSA", cdx.CryptoPrimitiveSignature)
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
	bom := encodeForTest(t, []Collection{{Result: result}}, EncodeOptions{})
	if len(*bom.Components) != 6 {
		t.Fatalf("lost shared ownership or crypto context: %d components", len(*bom.Components))
	}
	assertClosedGraph(t, bom)
}

func TestFocusedEmptyReportPreservesScopeAndErrors(t *testing.T) {
	var result Result
	result.Add(cdx.Component{Type: "library", Name: "unrelated"}, Evidence{Kind: "present"}, "")
	result.Properties = []cdx.Property{{Name: "ciphertrail:analysis-scope", Value: "configured, not executed"}}
	result.Diagnostics = []Diagnostic{{Message: "unmodeled API", Location: "main.go", Line: 3}}
	collections := []Collection{{Collector: "go", Target: ".", Result: result, Err: errors.New("load failed")}}
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
		var result Result
		ref := result.Add(cdx.Component{Type: "library", Name: "unrelated"}, Evidence{}, "")
		result.DependOn(ref, "missing")
		if _, err := EncodeWithOptions([]Collection{{Result: result}}, EncodeOptions{IncludeDependencies: include}); err == nil {
			t.Fatal("invalid graph was hidden by pruning")
		}
	}
}

func TestFocusedExportHandlesOwnershipCycles(t *testing.T) {
	var result Result
	a, b := Ref("owner-a"), Ref("owner-b")
	result.Add(cdx.Component{BOMRef: a, Type: "application", Name: "a"}, Evidence{}, b)
	result.Add(cdx.Component{BOMRef: b, Type: "application", Name: "b"}, Evidence{}, a)
	result.Add(Algorithm("SHA-256", cdx.CryptoPrimitiveHash), Evidence{}, a)
	result.Add(cdx.Component{Type: "library", Name: "unrelated"}, Evidence{}, "")
	bom := encodeForTest(t, []Collection{{Result: result}}, EncodeOptions{})
	if len(*bom.Components) != 3 {
		t.Fatal("ownership cycle lost context or retained unrelated components")
	}
	assertClosedGraph(t, bom)
}

func TestSecuredByReferencesAreValidatedBeforePruning(t *testing.T) {
	var result Result
	component := cdx.Component{Type: "cryptographic-asset", Name: "encrypted key", CryptoProperties: &cdx.CryptoProperties{
		AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
		RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
			Type:      cdx.RelatedCryptoMaterialTypePrivateKey,
			SecuredBy: &cdx.SecuredBy{AlgorithmRef: cdx.BOMReference("missing")},
		},
	}}
	result.Add(component, Evidence{}, "")
	if _, err := Encode([]Collection{{Result: result}}); err == nil {
		t.Fatal("dangling key-protection reference accepted")
	}
}

func encodeForTest(t *testing.T, collections []Collection, options EncodeOptions) cdx.BOM {
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
	var result Result
	first := Algorithm("RSA", cdx.CryptoPrimitivePKE)
	first.BOMRef = Ref("same-key")
	result.Add(first, Evidence{Kind: "present", Collector: "file"}, "")
	second := first
	Property(&second, "ssh-key-format", "ssh-rsa")
	result.Add(second, Evidence{Kind: "observed", Collector: "ssh"}, "")
	data, err := Encode([]Collection{{Result: result}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "ssh-key-format") || !strings.Contains(string(data), "observed") {
		t.Fatal("cross-collector metadata was discarded")
	}
}
