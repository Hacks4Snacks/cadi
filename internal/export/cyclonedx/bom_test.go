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

func TestKnownHashFactsUseNativeFields(t *testing.T) {
	var result inventory.Result
	for _, test := range []struct {
		name, family, parameter, oid string
	}{
		{"MD5", "MD5", "128", "1.2.840.113549.2.5"},
		{"SHA-1", "SHA-1", "160", "1.3.14.3.2.26"},
		{"SHA-224", "SHA-2", "224", "2.16.840.1.101.3.4.2.4"},
		{"SHA-256", "SHA-2", "256", "2.16.840.1.101.3.4.2.1"},
		{"SHA-384", "SHA-2", "384", "2.16.840.1.101.3.4.2.2"},
		{"SHA-512", "SHA-2", "512", "2.16.840.1.101.3.4.2.3"},
		{"SHA-512/224", "SHA-2", "224", "2.16.840.1.101.3.4.2.5"},
		{"SHA-512/256", "SHA-2", "256", "2.16.840.1.101.3.4.2.6"},
		{"SHA3-224", "SHA-3", "224", "2.16.840.1.101.3.4.2.7"},
		{"SHA3-256", "SHA-3", "256", "2.16.840.1.101.3.4.2.8"},
		{"SHA3-384", "SHA-3", "384", "2.16.840.1.101.3.4.2.9"},
		{"SHA3-512", "SHA-3", "512", "2.16.840.1.101.3.4.2.10"},
		{"SHAKE128", "SHA-3", "128", "2.16.840.1.101.3.4.2.11"},
		{"SHAKE256", "SHA-3", "256", "2.16.840.1.101.3.4.2.12"},
		{"BLAKE2b", "BLAKE2", "", ""},
		{"BLAKE2s", "BLAKE2", "", ""},
		{"BLAKE2b-256", "BLAKE2", "256", ""},
		{"BLAKE2b-384", "BLAKE2", "384", ""},
		{"BLAKE2b-512", "BLAKE2", "512", ""},
		{"BLAKE2s-128", "BLAKE2", "128", ""},
		{"BLAKE2s-256", "BLAKE2", "256", ""},
	} {
		component, known := inventory.HashAlgorithm(test.name)
		if !known {
			t.Fatalf("missing modeled hash %s", test.name)
		}
		a := component.CryptoProperties.AlgorithmProperties
		if a.AlgorithmFamily != test.family || a.ParameterSetIdentifier != test.parameter ||
			component.CryptoProperties.OID != test.oid || a.CryptoFunctions == nil ||
			!reflect.DeepEqual(*a.CryptoFunctions, []cdx.CryptoFunction{cdx.CryptoFunctionDigest}) {
			t.Fatalf("%s lost native hash facts: %+v", test.name, component.CryptoProperties)
		}
		if a.ClassicalSecurityLevel != nil || a.NistQuantumSecurityLevel != nil ||
			a.CertificationLevel != nil || component.Properties != nil {
			t.Fatalf("%s has inferred policy or duplicate extension facts", test.name)
		}
		result.Add(component, inventory.Evidence{Kind: "configured", Collector: "fixture", Location: "hash.go", Line: 1}, "")
	}
	for _, full := range []bool{false, true} {
		bom := encodeForTest(t, []inventory.Collection{{Result: result}}, EncodeOptions{IncludeDependencies: full})
		if len(*bom.Components) != len(result.Entries) {
			t.Fatal("native enrichment changed the retained hash inventory")
		}
	}
	for _, name := range []string{"", "RSA", "SHA-256-like", "HMAC-SHA-256"} {
		if _, known := inventory.HashAlgorithm(name); known {
			t.Fatalf("unmodeled identity was guessed: %q", name)
		}
	}
	generic := inventory.Algorithm("SHA-256", cdx.CryptoPrimitiveHash)
	if generic.CryptoProperties.OID != "" || generic.CryptoProperties.AlgorithmProperties.AlgorithmFamily != "" {
		t.Fatal("the generic constructor interpreted a display name")
	}
	first, _ := inventory.HashAlgorithm("SHA-256")
	*first.CryptoProperties.AlgorithmProperties.CryptoFunctions = []cdx.CryptoFunction{cdx.CryptoFunctionVerify}
	second, _ := inventory.HashAlgorithm("SHA-256")
	if (*second.CryptoProperties.AlgorithmProperties.CryptoFunctions)[0] != cdx.CryptoFunctionDigest {
		t.Fatal("mutable component fields escaped into shared model definitions")
	}
}

func TestNativeHMACAndAESFactsPreserveUnknowns(t *testing.T) {
	var result inventory.Result
	for _, test := range []struct{ hash, oid string }{
		{"SHA-256", "1.2.840.113549.2.9"}, {"SHA3-256", "2.16.840.1.101.3.4.2.14"},
		{"BLAKE2b", ""}, {"", ""},
	} {
		component := inventory.HMACAlgorithm(test.hash)
		a := component.CryptoProperties.AlgorithmProperties
		if a.AlgorithmFamily != "HMAC" || a.ParameterSetIdentifier != "" ||
			component.CryptoProperties.OID != test.oid || a.CryptoFunctions == nil ||
			!reflect.DeepEqual(*a.CryptoFunctions, []cdx.CryptoFunction{cdx.CryptoFunctionTag}) {
			t.Fatal("HMAC digest identity was lost or mistaken for a key length")
		}
		result.Add(component, inventory.Evidence{Kind: "configured"}, "")
	}
	for _, test := range []struct {
		mode           cdx.CryptoAlgorithmMode
		parameter, oid string
	}{
		{cdx.CryptoAlgorithmModeECB, "128", "2.16.840.1.101.3.4.1.1"},
		{cdx.CryptoAlgorithmModeCBC, "128", "2.16.840.1.101.3.4.1.2"},
		{cdx.CryptoAlgorithmModeOFB, "192", "2.16.840.1.101.3.4.1.23"},
		{cdx.CryptoAlgorithmModeCFB, "256", "2.16.840.1.101.3.4.1.44"},
		{cdx.CryptoAlgorithmModeGCM, "256", "2.16.840.1.101.3.4.1.46"},
		{cdx.CryptoAlgorithmModeCCM, "192", "2.16.840.1.101.3.4.1.27"},
		{"", "256", ""}, {cdx.CryptoAlgorithmModeGCM, "", ""},
		{cdx.CryptoAlgorithmModeGCM, "255", ""}, {cdx.CryptoAlgorithmModeCTR, "256", ""},
	} {
		if oid := inventory.AESOID(test.mode, test.parameter); oid != test.oid {
			t.Errorf("AES %s/%s OID=%q; want %q", test.mode, test.parameter, oid, test.oid)
		}
	}
	for _, provider := range []string{"aesgcm", "aescbc", "secretbox"} {
		component, known := inventory.ConfiguredEncryptionAlgorithm(provider, true, nil)
		if !known || component.CryptoProperties.AlgorithmProperties.AlgorithmFamily == "" ||
			component.CryptoProperties.OID != "" || component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier != "" {
			t.Fatalf("%s lost its family or invented a key size/OID", provider)
		}
		result.Add(component, inventory.Evidence{Kind: "configured"}, "")
	}
	encodeForTest(t, []inventory.Collection{{Result: result}}, EncodeOptions{})
}

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
			if object["unresolved"] != nil {
				t.Fatal("internal unresolved metadata was exported")
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
				if len(record.Parameters) != 1 || len(record.Parameters[0].Values) != 2 ||
					record.Parameters[0].Values[0].Value != "2048" ||
					strings.Count(property.Value, "other constructions are possible") != 1 {
					t.Fatalf("parameter grouping, ordering, or declared-value handling failed: %+v", record)
				}
			case "observed":
				foundObserved = true
				if record.Time != observed.Time {
					t.Fatal("another occurrence's declaration hid the observation time")
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

func TestNativeFirstRSAPropertiesAndStableEvidence(t *testing.T) {
	component := inventory.Algorithm("RSA", cdx.CryptoPrimitivePKE)
	component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "4096"
	component.CryptoProperties.AlgorithmProperties.CryptoFunctions = &[]cdx.CryptoFunction{cdx.CryptoFunctionKeygen}
	evidence := inventory.Evidence{Kind: "configured", Collector: "go", Location: "helper.go", Line: 64,
		Symbol: "func crypto/rsa.GenerateKey(random io.Reader, bits int) (*crypto/rsa.PrivateKey, error)"}
	var result inventory.Result
	ref := result.Add(component, evidence, "")
	original, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	line := 64
	expectedOccurrence := inventory.Ref("occurrence", ref, occurrenceKey(cdx.EvidenceOccurrence{
		Location: evidence.Location, Line: &line, Symbol: evidence.Symbol,
	}))
	for _, full := range []bool{false, true} {
		bom := encodeForTest(t, []inventory.Collection{{Result: result}}, EncodeOptions{IncludeDependencies: full})
		got := (*bom.Components)[0]
		if got.BOMRef != ref || !reflect.DeepEqual(got.CryptoProperties, component.CryptoProperties) ||
			got.Evidence == nil || len(*got.Evidence.Occurrences) != 1 || (*got.Evidence.Occurrences)[0].BOMRef != expectedOccurrence {
			t.Fatal("native fields or stable references changed")
		}
		properties := map[string]string{}
		for _, property := range *got.Properties {
			properties[property.Name] = property.Value
		}
		expected := map[string]string{"ciphertrail:evidence-kind": "configured", "ciphertrail:collector": "go"}
		if !reflect.DeepEqual(properties, expected) {
			t.Fatalf("RSA extensions were not compacted: %v", properties)
		}
	}
	after, err := json.Marshal(result)
	if err != nil || string(original) != string(after) {
		t.Fatal("export normalization modified collector-owned facts")
	}
}

func TestSimpleProvenanceIsFlatOnlyWhenUniform(t *testing.T) {
	for _, test := range []struct {
		name                   string
		secondKind, secondTool string
		simple                 bool
	}{
		{"uniform", "configured", "go", true},
		{"mixed-kind", "observed", "go", false},
		{"mixed-collector", "configured", "python", false},
		{"missing-classification", "", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			component := inventory.Algorithm("shared", cdx.CryptoPrimitivePKE)
			component.BOMRef = "shared"
			var result inventory.Result
			result.Add(component, inventory.Evidence{Kind: "configured", Collector: "go", Location: "a.go", Line: 1}, "")
			result.Add(component, inventory.Evidence{Kind: test.secondKind, Collector: test.secondTool, Location: "b.go", Line: 2}, "")
			bom := encodeForTest(t, []inventory.Collection{{Result: result}}, EncodeOptions{})
			got := (*bom.Components)[0]
			flat, detailed := 0, 0
			for _, property := range *got.Properties {
				switch property.Name {
				case "ciphertrail:evidence-kind", "ciphertrail:collector":
					flat++
				case "ciphertrail:provenance":
					detailed++
					var record provenance
					if err := json.Unmarshal([]byte(property.Value), &record); err != nil {
						t.Fatal(err)
					}
					if record.Occurrence == "" {
						t.Fatal("mixed evidence lost its occurrence association")
					}
				}
			}
			if test.simple && (flat != 2 || detailed != 0) || !test.simple && (flat != 0 || detailed == 0) ||
				len(*got.Evidence.Occurrences) != 2 {
				t.Fatalf("incorrect provenance shape: flat=%d detailed=%d", flat, detailed)
			}
		})
	}
}

func TestExporterDoesNotInterpretAPISymbolStrings(t *testing.T) {
	for _, test := range []struct {
		name, api, symbol, location string
	}{
		{"exact", "crypto/rsa.GenerateKey", "crypto/rsa.GenerateKey", "main.go"},
		{"signature", "crypto/rsa.GenerateKey", "func crypto/rsa.GenerateKey(random io.Reader, bits int) (*crypto/rsa.PrivateKey, error)", "main.go"},
		{"method", "crypto/rsa.Sign", "func (*crypto/rsa.PrivateKey).Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)", "main.go"},
		{"prefix-only", "crypto/rsa.GenerateKey", "func crypto/rsa.GenerateKeyOther() error", "main.go"},
		{"different-package", "crypto/rsa.Sign", "func (*other.PrivateKey).Sign() error", "main.go"},
		{"package-prefix-only", "crypto/rsa.Sign", "func (*crypto/rsa.extra.PrivateKey).Sign() error", "main.go"},
		{"no-symbol", "crypto/rsa.GenerateKey", "", "main.go"},
		{"no-location", "crypto/rsa.GenerateKey", "crypto/rsa.GenerateKey", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			component := inventory.Algorithm("RSA", cdx.CryptoPrimitivePKE)
			inventory.Property(&component, "api", test.api)
			var result inventory.Result
			result.Add(component, inventory.Evidence{Kind: "configured", Collector: "go", Location: test.location, Symbol: test.symbol}, "")
			bom := encodeForTest(t, []inventory.Collection{{Result: result}}, EncodeOptions{})
			retained := false
			for _, property := range *(*bom.Components)[0].Properties {
				retained = retained || property.Name == "ciphertrail:api" && property.Value == test.api
			}
			if !retained {
				t.Fatal("exporter interpreted source-symbol text to discard a supplied property")
			}
		})
	}
}

func TestExporterDoesNotInferPropertyMeaningFromAlgorithmNames(t *testing.T) {
	for _, test := range []struct {
		name, parameter, size string
		primitive             cdx.CryptoPrimitive
	}{
		{"RSA", "4096", "4096", cdx.CryptoPrimitivePKE},
		{"AES", "256", "256", cdx.CryptoPrimitiveBlockCipher},
		{"RSA", "4096", "2048", cdx.CryptoPrimitivePKE},
		{"RSA", "", "4096", cdx.CryptoPrimitivePKE},
		{"SHA-256", "256", "256", cdx.CryptoPrimitiveHash},
		{"SHAKE128", "128", "128", cdx.CryptoPrimitiveXOF},
		{"ML-KEM", "768", "768", cdx.CryptoPrimitiveKEM},
		{"ML-DSA", "65", "65", cdx.CryptoPrimitiveSignature},
		{"HMAC-SHA-256", "256", "256", cdx.CryptoPrimitiveMAC},
		{"Unknown PKE parameters", "4096", "4096", cdx.CryptoPrimitivePKE},
		{"ECDSA", "256", "256", cdx.CryptoPrimitiveSignature},
	} {
		t.Run(test.name+"/"+test.parameter+"/"+test.size, func(t *testing.T) {
			component := inventory.Algorithm(test.name, test.primitive)
			component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = test.parameter
			inventory.Property(&component, "key-size-bits", test.size)
			inventory.Property(&component, "key-size-bits:declared", test.size)
			inventory.Property(&component, "scope", "declared configuration only")
			var result inventory.Result
			result.Add(component, inventory.Evidence{Kind: "configured", Collector: "go", Location: "main.go"}, "")
			bom := encodeForTest(t, []inventory.Collection{{Result: result}}, EncodeOptions{})
			properties := map[string]string{}
			for _, property := range *(*bom.Components)[0].Properties {
				properties[property.Name] = property.Value
			}
			if properties["ciphertrail:key-size-bits"] != test.size || properties["ciphertrail:key-size-bits:declared"] != test.size ||
				properties["ciphertrail:scope"] != "declared configuration only" {
				t.Fatalf("lost non-native or semantically distinct metadata: %v", properties)
			}
		})
	}
}

func TestNativeKeySizeAndEmptyExtensions(t *testing.T) {
	size := 4096
	component := cdx.Component{Type: cdx.ComponentTypeCryptographicAsset, Name: "Private key",
		CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type: cdx.RelatedCryptoMaterialTypePrivateKey, Size: &size,
			}}}
	var result inventory.Result
	ref := result.Add(component, inventory.Evidence{Location: "key.go", Symbol: "example.Key"}, "")
	bom := encodeForTest(t, []inventory.Collection{{Result: result}}, EncodeOptions{})
	got := (*bom.Components)[0]
	if got.Properties != nil || got.Evidence == nil || got.BOMRef != ref || *got.CryptoProperties.RelatedCryptoMaterialProperties.Size != 4096 {
		t.Fatal("native key fields were lost or an empty extension array remains")
	}
}

func TestSingleDetailedEvidenceDoesNotFlatten(t *testing.T) {
	for _, test := range []struct {
		name     string
		evidence inventory.Evidence
	}{
		{"time", inventory.Evidence{Kind: "observed", Collector: "tls", Location: "localhost:443", Time: "2026-10-25T00:00:00Z"}},
		{"context", inventory.Evidence{Kind: "configured", Collector: "kubernetes", Location: "config.yaml", Context: &inventory.SourceContext{Document: 1, Field: "/spec"}}},
		{"declaration", inventory.Evidence{Kind: "configured", Collector: "go", Location: "main.go", Parameters: []inventory.ParameterEvidence{
			{Name: "key-size-bits", Value: "4096", Location: "policy.go", Line: 8, Basis: "declared", Limitation: "mutable policy"},
		}}},
		{"location-free-symbol", inventory.Evidence{Kind: "present", Collector: "binary", Symbol: "public-symbol"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var result inventory.Result
			result.Add(inventory.Algorithm("RSA", cdx.CryptoPrimitivePKE), test.evidence, "")
			bom := encodeForTest(t, []inventory.Collection{{Result: result}}, EncodeOptions{})
			got := (*bom.Components)[0]
			records := 0
			for _, property := range *got.Properties {
				if property.Name == "ciphertrail:evidence-kind" || property.Name == "ciphertrail:collector" {
					t.Fatal("detailed evidence was flattened")
				}
				if property.Name == "ciphertrail:provenance" {
					records++
					var record provenance
					if err := json.Unmarshal([]byte(property.Value), &record); err != nil {
						t.Fatal(err)
					}
					if !record.detailed() || record.Kind != test.evidence.Kind || record.Collector != test.evidence.Collector {
						t.Fatal("detailed evidence fields were lost")
					}
				}
			}
			if records != 1 {
				t.Fatalf("detailed records=%d; want 1", records)
			}
		})
	}
}

func TestUnresolvedOnlyEvidenceBecomesFlatWithoutChangingAnalysis(t *testing.T) {
	evidence := inventory.Evidence{Kind: "configured", Collector: "go", Location: "storage/strgmgmt.go", Line: 76,
		Symbol: "certmanager.CertificatePrivateKey", Unresolved: []string{"cert-manager.rotation-policy"}}
	component := inventory.Algorithm("RSA", cdx.CryptoPrimitivePKE)
	component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "2048"
	var result inventory.Result
	result.Add(component, evidence, "")
	for _, full := range []bool{false, true} {
		bom := encodeForTest(t, []inventory.Collection{{Result: result}}, EncodeOptions{IncludeDependencies: full})
		asset := (*bom.Components)[0]
		properties := map[string]string{}
		for _, property := range *asset.Properties {
			properties[property.Name] = property.Value
		}
		if len(properties) != 2 || properties["ciphertrail:evidence-kind"] != "configured" || properties["ciphertrail:collector"] != "go" {
			t.Fatalf("unresolved-only evidence was not omitted/flattened: %v", properties)
		}
	}
	if !reflect.DeepEqual(evidence.Unresolved, []string{"cert-manager.rotation-policy"}) ||
		!reflect.DeepEqual(result.Entries[0].Evidence.Unresolved, evidence.Unresolved) {
		t.Fatal("output cleanup modified internal analysis uncertainty")
	}
}

func TestUnresolvedResourceOnlyContextDoesNotCreateProvenance(t *testing.T) {
	var result inventory.Result
	result.Add(inventory.Algorithm("RSA", cdx.CryptoPrimitivePKE), inventory.Evidence{
		Kind: "configured", Collector: "kubernetes", Location: "manifest.yaml",
		Context: &inventory.SourceContext{
			Resource:   &inventory.ResourceIdentity{Kind: "Certificate", Name: "RESOURCE_SENTINEL"},
			Unresolved: []string{"UNRESOLVED_SENTINEL"},
			Embedded:   []inventory.EmbeddedContext{{Resource: &inventory.ResourceIdentity{Kind: "Certificate"}, Unresolved: []string{"ignored"}}},
		},
	}, "")
	data, err := Encode([]inventory.Collection{{Result: result}})
	if err != nil || strings.Contains(string(data), "ciphertrail:provenance") ||
		strings.Contains(string(data), "SENTINEL") || strings.Contains(string(data), "ignored") {
		t.Fatalf("empty projected context was retained: %v", err)
	}
}

func TestContextProjectionKeepsLocatorsNotResourceMetadata(t *testing.T) {
	context := &inventory.SourceContext{Document: 2, Field: "/data/config", RenderedFrom: "chart/templates/config.yaml",
		ContentLine: 8, Resource: &inventory.ResourceIdentity{APIVersion: "v1", Kind: "ConfigMap", Name: "RESOURCE_SENTINEL"},
		Unresolved: []string{"UNRESOLVED_SENTINEL"},
		Embedded: []inventory.EmbeddedContext{
			{Document: 1, Field: "/spec", File: "/etc/example.yaml", Line: 3,
				Resource:   &inventory.ResourceIdentity{Kind: "Certificate", Name: "RESOURCE_SENTINEL"},
				Unresolved: []string{"UNRESOLVED_SENTINEL"}},
		}}
	before, err := json.Marshal(context)
	if err != nil {
		t.Fatal(err)
	}
	var result inventory.Result
	result.Add(inventory.Algorithm("RSA", cdx.CryptoPrimitivePKE),
		inventory.Evidence{Kind: "configured", Collector: "kubernetes", Location: "manifest.yaml", Line: 20, Context: context}, "")
	data, err := Encode([]inventory.Collection{{Result: result}})
	if err != nil || strings.Contains(string(data), "RESOURCE_SENTINEL") || strings.Contains(string(data), "UNRESOLVED_SENTINEL") {
		t.Fatalf("resource or unresolved metadata leaked into CBOM: %v", err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, property := range *(*bom.Components)[0].Properties {
		if property.Name != "ciphertrail:provenance" {
			continue
		}
		var record provenance
		if err := json.Unmarshal([]byte(property.Value), &record); err != nil {
			t.Fatal(err)
		}
		found = record.Context != nil && record.Context.Document == 2 && record.Context.Field == "/data/config" &&
			record.Context.RenderedFrom == "chart/templates/config.yaml" && record.Context.ContentLine == 8 &&
			len(record.Context.Embedded) == 1 && record.Context.Embedded[0].File == "/etc/example.yaml" &&
			record.Context.Embedded[0].Line == 3 && record.Context.Resource == nil && record.Context.Embedded[0].Resource == nil
	}
	if !found {
		t.Fatal("source locator context was lost with resource metadata")
	}
	after, err := json.Marshal(context)
	if err != nil || string(before) != string(after) {
		t.Fatal("export projection modified collector-owned context")
	}
}

func TestCBOMHeaderIsCompactAndDoesNotSerializeRunDetails(t *testing.T) {
	var result inventory.Result
	result.Metadata("execution-detail", strings.Repeat("RUN_DETAIL_SENTINEL", 10000))
	result.Diagnostics = []inventory.Diagnostic{{Location: "/private/worktree/source.go", Message: "DIAGNOSTIC_SENTINEL"}}
	result.Coverage = []inventory.Coverage{
		{Analyzer: "kubernetes", Status: "needs-rendering", Skipped: 295, Reason: "Helm templates require rendered YAML/JSON"},
	}
	result.Add(inventory.Algorithm("RSA", cdx.CryptoPrimitivePKE),
		inventory.Evidence{Kind: "configured", Collector: "go", Location: "main.go", Line: 1}, "")
	for _, full := range []bool{false, true} {
		bom := encodeForTest(t, []inventory.Collection{{Collector: "repository", Target: "/private/worktree", Result: result}},
			EncodeOptions{IncludeDependencies: full})
		header, err := json.Marshal(bom.Metadata)
		if err != nil {
			t.Fatal(err)
		}
		if len(header) > 1024 || strings.Contains(string(header), "SENTINEL") || strings.Contains(string(header), "/private/worktree") {
			t.Fatalf("CBOM header contains execution details: %d bytes", len(header))
		}
		limited := false
		for _, property := range *bom.Metadata.Properties {
			switch property.Name {
			case "ciphertrail:output-scope", "ciphertrail:collection-status":
			case "ciphertrail:coverage-limitation":
				limited = limited || strings.Contains(property.Value, "render")
			default:
				t.Fatalf("unexpected CBOM header property: %s", property.Name)
			}
		}
		if !limited {
			t.Fatal("material rendering limitation disappeared with run metadata")
		}
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
		if !refs[record.Occurrence] || record.Context == nil || record.Context.Document != 1 || record.Context.Resource != nil {
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
	result.Metadata("analysis-scope", "configured, not executed")
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
	for _, value := range []string{"incomplete", "crypto-focused", "analysis diagnostics were reported"} {
		if !strings.Contains(string(data), value) {
			t.Errorf("lost collection context %q", value)
		}
	}
	for _, value := range []string{"configured, not executed", "unmodeled API", "load failed", "ciphertrail:collection\""} {
		if strings.Contains(string(data), value) {
			t.Errorf("execution details leaked into the CBOM header: %q", value)
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
