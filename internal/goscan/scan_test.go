package goscan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"ciphertrail/internal/export/cyclonedx"
	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func fixture(t *testing.T, source string) string {
	t.Helper()
	directory := t.TempDir()
	mod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	sum, err := os.ReadFile("../../go.sum")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"go.mod": []byte(strings.Replace(string(mod), "module ciphertrail", "module example.test/fixture", 1)),
		"go.sum": sum, "main.go": []byte(source),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(directory, name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return directory
}

func TestGoSourceFunctionEnumeration(t *testing.T) {
	const source = `package example
import "crypto/sha256"
var Global = sha256.Sum256(nil)
var GlobalClosure = func() { _ = sha256.Sum256(nil) }
func init() { _ = sha256.Sum256(nil) }
func init() { _ = sha256.Sum256(nil) }
func _() { _ = sha256.Sum256(nil) }
func Named() { _ = sha256.Sum256(nil) }
func Closure() func() { return func() { _ = sha256.Sum256(nil) } }
func Nested() func() func() { return func() func() { return func() { _ = sha256.Sum256(nil) } } }
func Generic[T any](value T) { _ = sha256.Sum256(nil) }
type hasher struct{}
func New() hasher { return hasher{} }
func (hasher) Sum(data []byte) [32]byte { return sha256.Sum256(data) }
func (*hasher) private() { _ = sha256.Sum256(nil) }
type Alias = hasher
func (*Alias) ThroughAlias() { _ = sha256.Sum256(nil) }
type Public struct{}
func (Public) Sum() { _ = sha256.Sum256(nil) }
func (*Public) private() { _ = sha256.Sum256(nil) }
type GenericHasher[T any] struct{}
func (GenericHasher[T]) Sum(data []byte) [32]byte { return sha256.Sum256(data) }
func (*GenericHasher[T]) private() { _ = sha256.Sum256(nil) }
type hiddenGeneric[T any] struct{}
func (hiddenGeneric[T]) Sum() { _ = sha256.Sum256(nil) }
`
	const consumer = `package example
func Consumer() {
 New().Sum(nil)
 GenericHasher[int]{}.Sum(nil)
 GenericHasher[string]{}.Sum(nil)
 new(GenericHasher[int]).private()
 new(hasher).ThroughAlias()
 hiddenGeneric[int]{}.Sum()
 Generic(1)
 Generic("value")
 Closure()()
 Nested()()()
}
`
	var expectedLines []int
	for index, line := range strings.Split(source, "\n") {
		if strings.Contains(line, "sha256.Sum256") {
			expectedLines = append(expectedLines, index+1)
		}
	}
	for _, withConsumer := range []bool{false, true} {
		t.Run(map[bool]string{false: "library", true: "local-consumer"}[withConsumer], func(t *testing.T) {
			directory := fixture(t, source)
			if withConsumer {
				if err := os.WriteFile(filepath.Join(directory, "consumer.go"), []byte(consumer), 0600); err != nil {
					t.Fatal(err)
				}
			}
			result, err := (Source{Path: directory, Offline: true}).Collect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			var lines []int
			for _, entry := range result.Entries {
				if entry.Component.CryptoProperties == nil {
					continue
				}
				if entry.Component.Name != "SHA-256" || entry.Evidence.Location != "main.go" ||
					entry.Evidence.Kind != "configured" || !strings.Contains(entry.Evidence.Symbol, "crypto/sha256.Sum256") ||
					entry.Parent == "" {
					t.Fatalf("incorrect source ownership or evidence: %+v", entry)
				}
				lines = append(lines, entry.Evidence.Line)
			}
			slices.Sort(lines)
			if !slices.Equal(lines, expectedLines) {
				t.Errorf("crypto call-site lines = %v; want exactly once at %v", lines, expectedLines)
			}
			if len(result.Diagnostics) != 0 {
				t.Errorf("unexpected diagnostics: %+v", result.Diagnostics)
			}
			if _, err := cyclonedx.Encode([]inventory.Collection{{Collector: "go", Result: result}}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGoRSAUsesNativeFieldsInBothOutputScopes(t *testing.T) {
	directory := fixture(t, `package example
import ("crypto/rand"; "crypto/rsa")
func Generate() { _, _ = rsa.GenerateKey(rand.Reader, 4096) }
`)
	result, err := (Source{Path: directory, Offline: true}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, full := range []bool{false, true} {
		data, err := cyclonedx.EncodeWithOptions([]inventory.Collection{{Collector: "go", Result: result}},
			cyclonedx.EncodeOptions{IncludeDependencies: full})
		if err != nil {
			t.Fatal(err)
		}
		var bom cdx.BOM
		if err := json.Unmarshal(data, &bom); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, component := range *bom.Components {
			if component.Type != cdx.ComponentTypeCryptographicAsset || component.Name != "RSA" {
				continue
			}
			found = true
			if component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier != "4096" ||
				component.Evidence == nil || !strings.Contains((*component.Evidence.Occurrences)[0].Symbol, "crypto/rsa.GenerateKey") {
				t.Fatal("native RSA facts or source API evidence were lost")
			}
			properties := map[string]string{}
			for _, property := range *component.Properties {
				properties[property.Name] = property.Value
			}
			if len(properties) != 2 || properties["ciphertrail:evidence-kind"] != "configured" || properties["ciphertrail:collector"] != "go" {
				t.Fatalf("RSA did not use simple native-first output: %v", properties)
			}
		}
		if !found {
			t.Fatal("RSA finding missing")
		}
	}
}

func TestGoKnownNativeAlgorithmFacts(t *testing.T) {
	directory := fixture(t, `package example
import (
 "crypto"
 "crypto/cipher"
 "crypto/ecdh"
 "crypto/ecdsa"
 "crypto/ed25519"
 "crypto/mlkem"
 "crypto/rand"
 "crypto/rsa"
 "crypto/sha256"
 "crypto/sha512"
 "crypto/sha3"
 "golang.org/x/crypto/pbkdf2"
)
func Run(r *rsa.PrivateKey, e *ecdsa.PrivateKey, ed ed25519.PrivateKey, opts crypto.SignerOpts, curve ecdh.Curve, key *ecdh.PrivateKey, peer *ecdh.PublicKey, dk *mlkem.DecapsulationKey768, ek *mlkem.EncapsulationKey1024, block cipher.Block) {
 _ = sha256.Sum256([]byte("PRIVATE_SENTINEL"))
 _ = sha512.Sum512_256(nil)
 _ = sha3.NewSHAKE128()
 _, _ = rsa.GenerateKey(rand.Reader, 4096)
 _, _ = rsa.EncryptOAEP(sha256.New(), rand.Reader, &r.PublicKey, nil, nil)
 _, _ = rsa.SignPSS(rand.Reader, r, crypto.SHA256, nil, nil)
 _, _ = rsa.SignPKCS1v15(rand.Reader, r, crypto.SHA256, nil)
 _, _, _ = ecdsa.Sign(rand.Reader, e, nil)
 _ = ed25519.Sign(ed, nil)
 _, _ = ed.Sign(rand.Reader, nil, opts)
 _ = ecdh.X25519()
 _, _ = curve.GenerateKey(rand.Reader)
 _, _ = key.ECDH(peer)
 _, _ = rand.Read(nil)
 _, _ = mlkem.GenerateKey768()
 _, _ = dk.Decapsulate(nil)
 _, _ = ek.Encapsulate()
 _ = cipher.NewCBCEncrypter(block, nil)
 _ = pbkdf2.Key(nil, nil, 10, 32, sha256.New)
}`)
	expected := map[string]struct {
		family, parameter, oid string
		function               cdx.CryptoFunction
	}{
		"crypto/sha256.Sum256":                             {"SHA-2", "256", "2.16.840.1.101.3.4.2.1", cdx.CryptoFunctionDigest},
		"crypto/sha512.Sum512_256":                         {"SHA-2", "256", "2.16.840.1.101.3.4.2.6", cdx.CryptoFunctionDigest},
		"crypto/sha3.NewSHAKE128":                          {"SHA-3", "128", "2.16.840.1.101.3.4.2.11", cdx.CryptoFunctionDigest},
		"crypto/rsa.GenerateKey":                           {"", "4096", "", cdx.CryptoFunctionKeygen},
		"crypto/rsa.EncryptOAEP":                           {"RSAES-OAEP", "", "1.2.840.113549.1.1.7", cdx.CryptoFunctionEncrypt},
		"crypto/rsa.SignPSS":                               {"RSASSA-PSS", "", "1.2.840.113549.1.1.10", cdx.CryptoFunctionSign},
		"crypto/rsa.SignPKCS1v15":                          {"RSASSA-PKCS1", "", "", cdx.CryptoFunctionSign},
		"crypto/ecdsa.Sign":                                {"ECDSA", "", "", cdx.CryptoFunctionSign},
		"crypto/ed25519.Sign":                              {"EdDSA", "", "1.3.101.112", cdx.CryptoFunctionSign},
		"(crypto/ed25519.PrivateKey).Sign":                 {"EdDSA", "", "", cdx.CryptoFunctionSign},
		"crypto/ecdh.X25519":                               {"ECDH", "", "1.3.101.110", ""},
		"(crypto/ecdh.Curve).GenerateKey":                  {"ECDH", "", "", cdx.CryptoFunctionKeygen},
		"(*crypto/ecdh.PrivateKey).ECDH":                   {"ECDH", "", "", cdx.CryptoFunctionKeyderive},
		"crypto/rand.Read":                                 {"", "", "", cdx.CryptoFunctionGenerate},
		"crypto/mlkem.GenerateKey768":                      {"ML-KEM", "768", "2.16.840.1.101.3.4.4.2", cdx.CryptoFunctionKeygen},
		"(*crypto/mlkem.DecapsulationKey768).Decapsulate":  {"ML-KEM", "768", "2.16.840.1.101.3.4.4.2", cdx.CryptoFunctionDecapsulate},
		"(*crypto/mlkem.EncapsulationKey1024).Encapsulate": {"ML-KEM", "1024", "2.16.840.1.101.3.4.4.3", cdx.CryptoFunctionEncapsulate},
		"crypto/cipher.NewCBCEncrypter":                    {"", "", "", cdx.CryptoFunctionEncrypt},
		"golang.org/x/crypto/pbkdf2.Key":                   {"PBKDF2", "", "", cdx.CryptoFunctionKeyderive},
	}
	result, err := (Source{Path: directory, Offline: true}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, entry := range result.Entries {
		if entry.Component.CryptoProperties == nil || entry.Component.CryptoProperties.AlgorithmProperties == nil {
			continue
		}
		for symbol, want := range expected {
			if entry.Evidence.Symbol != symbol && !strings.Contains(entry.Evidence.Symbol, symbol+"(") {
				continue
			}
			seen[symbol] = true
			properties := entry.Component.CryptoProperties
			a := properties.AlgorithmProperties
			if a.AlgorithmFamily != want.family || a.ParameterSetIdentifier != want.parameter || properties.OID != want.oid {
				t.Errorf("%s: family=%q parameter=%q oid=%q; want %+v", symbol, a.AlgorithmFamily, a.ParameterSetIdentifier, properties.OID, want)
			}
			if want.function == "" {
				if a.CryptoFunctions != nil {
					t.Errorf("%s invented an operation: %v", symbol, *a.CryptoFunctions)
				}
			} else if a.CryptoFunctions == nil || !slices.Equal(*a.CryptoFunctions, []cdx.CryptoFunction{want.function}) {
				t.Errorf("%s did not retain the precise operation %s", symbol, want.function)
			}
			if a.ClassicalSecurityLevel != nil || a.NistQuantumSecurityLevel != nil || a.CertificationLevel != nil {
				t.Errorf("%s inferred security or certification claims", symbol)
			}
		}
	}
	for symbol := range expected {
		if !seen[symbol] {
			t.Errorf("missing %s", symbol)
		}
	}
	for _, full := range []bool{false, true} {
		data, err := cyclonedx.EncodeWithOptions([]inventory.Collection{{Result: result}}, cyclonedx.EncodeOptions{IncludeDependencies: full})
		if err != nil || strings.Contains(string(data), "PRIVATE_SENTINEL") {
			t.Fatalf("invalid or unsafe enriched output: %v", err)
		}
	}
}

func TestReportedKubernetesAPIsAreClassified(t *testing.T) {
	directory := fixture(t, `package example
import (
 "crypto"
 "crypto/cipher"
 "crypto/ecdsa"
 "crypto/ed25519"
 "crypto/mldsa"
 "crypto/rsa"
 "crypto/subtle"
 "crypto/tls"
 "crypto/x509"
 "net"
 "golang.org/x/crypto/cryptobyte"
 "golang.org/x/crypto/nacl/secretbox"
)
func Run(aead cipher.AEAD, mode cipher.BlockMode, hash crypto.Hash, params mldsa.Parameters, rsaPublic *rsa.PublicKey, edPublic ed25519.PublicKey, ecPublic *ecdsa.PublicKey, mlPublic *mldsa.PublicKey, ecPrivate *ecdsa.PrivateKey, mlPrivate *mldsa.PrivateKey, pool *x509.CertPool, cert, parent *x509.Certificate, config *tls.Config, conn *tls.Conn, listener net.Listener, builder *cryptobyte.Builder, encoded *cryptobyte.String, nonce *[24]byte, key *[32]byte) {
 _ = aead.NonceSize()
 _ = aead.Seal(nil, nil, []byte("PRIVATE_PAYLOAD_SENTINEL"), nil)
 _, _ = aead.Open(nil, nil, nil, nil)
 _ = hash.New()
 _ = mldsa.MLDSA44()
 _, _ = mldsa.GenerateKey(params)
 _ = mldsa.MLDSA65()
 _ = mldsa.MLDSA87()
 _ = cryptobyte.NewBuilder(nil)
 builder.AddUint16LengthPrefixed(func(*cryptobyte.Builder) {})
 builder.AddBytes([]byte("PRIVATE_ENCODING_SENTINEL"))
 builder.AddUint32(7)
 _, _ = builder.Bytes()
 _ = rsaPublic.Size()
 _ = mlPublic.Parameters()
 _ = params.String()
 _ = edPublic.Equal(nil)
 _ = ecPublic.Equal(nil)
 _ = mlPublic.Equal(nil)
 _ = subtle.ConstantTimeCompare(nil, nil)
 pool.AddCert(cert)
 _, _ = cert.Verify(x509.VerifyOptions{})
 _ = cert.VerifyHostname("PRIVATE_HOST_SENTINEL")
 _ = cert.CheckSignatureFrom(parent)
 _ = config.Clone()
 _ = ecPrivate.Public()
 _, _ = secretbox.Open(nil, nil, nonce, key)
 _ = secretbox.Seal(nil, []byte("PRIVATE_BOX_SENTINEL"), nonce, key)
 var output cryptobyte.String
 _ = encoded.ReadUint16LengthPrefixed(&output)
 _ = aead.Overhead()
 mode.CryptBlocks(nil, nil)
 _ = tls.NewListener(listener, config)
 _ = mlPrivate.PublicKey()
 _ = conn.Close()
 _ = tls.CurveID(0).String()
 _ = tls.CipherSuites()
 _ = tls.InsecureCipherSuites()
}`)
	result, err := (Source{Path: directory, Offline: true}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("%d reported APIs remain unclassified; first: %+v", len(result.Diagnostics), result.Diagnostics[0])
	}
	assets := 0
	for _, entry := range result.Entries {
		if entry.Component.CryptoProperties == nil {
			continue
		}
		assets++
		if entry.Evidence.Kind != "configured" || entry.Evidence.Collector != "go" || entry.Evidence.Line == 0 {
			t.Fatal("new models lost source evidence")
		}
		if properties := entry.Component.CryptoProperties.RelatedCryptoMaterialProperties; properties != nil {
			if properties.Type != cdx.RelatedCryptoMaterialTypePublicKey || properties.Value != "" || properties.Size != nil {
				t.Fatal("public-key access inferred material or a key size")
			}
		}
	}
	if assets != 16 {
		t.Fatalf("crypto assets=%d; want 16 operations/selections and no assets for 21 helper APIs", assets)
	}
	for _, full := range []bool{false, true} {
		data, err := cyclonedx.EncodeWithOptions([]inventory.Collection{{Result: result}}, cyclonedx.EncodeOptions{IncludeDependencies: full})
		if err != nil || strings.Contains(string(data), "PRIVATE_") {
			t.Fatalf("invalid output or private argument leakage: %v", err)
		}
	}
}

func TestReportedNonAssetAPIsRequireExactIdentity(t *testing.T) {
	for _, api := range []apiIdentity{
		{"crypto/cipher", "AEAD", "NonceSize"},
		{"crypto/cipher", "AEAD", "Overhead"},
		{"crypto/rsa", "PublicKey", "Size"},
		{"crypto/mldsa", "PublicKey", "Parameters"},
		{"crypto/mldsa", "Parameters", "String"},
		{"crypto/ed25519", "PublicKey", "Equal"},
		{"crypto/ecdsa", "PublicKey", "Equal"},
		{"crypto/mldsa", "PublicKey", "Equal"},
		{"crypto/subtle", "", "ConstantTimeCompare"},
		{"crypto/x509", "Certificate", "VerifyHostname"},
		{"crypto/tls", "Config", "Clone"},
		{"crypto/tls", "Conn", "Close"},
		{"crypto/tls", "CurveID", "String"},
		{"crypto/tls", "", "CipherSuites"},
		{"crypto/tls", "", "InsecureCipherSuites"},
		{"golang.org/x/crypto/cryptobyte", "", "NewBuilder"},
		{"golang.org/x/crypto/cryptobyte", "Builder", "AddUint16LengthPrefixed"},
		{"golang.org/x/crypto/cryptobyte", "Builder", "AddBytes"},
		{"golang.org/x/crypto/cryptobyte", "Builder", "AddUint32"},
		{"golang.org/x/crypto/cryptobyte", "Builder", "Bytes"},
		{"golang.org/x/crypto/cryptobyte", "String", "ReadUint16LengthPrefixed"},
	} {
		if !nonAssetAPI(api) {
			t.Errorf("helper remains a coverage gap: %+v", api)
		}
		for _, other := range []apiIdentity{
			{"example.test/other", api.receiver, api.name},
			{api.path, "DifferentReceiver", api.name},
			{api.path, api.receiver, "Unmodeled" + api.name},
		} {
			if nonAssetAPI(other) {
				t.Errorf("helper classification is too broad: %+v", other)
			}
		}
	}
}

func TestNewOperationModelsPreserveKnownAndUnknownParameters(t *testing.T) {
	source := `package example
import (
 "crypto"
 "crypto/cipher"
 "crypto/mldsa"
 "golang.org/x/crypto/nacl/secretbox"
)
func Run(hash crypto.Hash, params mldsa.Parameters, aead cipher.AEAD, mode cipher.BlockMode, block cipher.Block, choose bool, nonce *[24]byte, key *[32]byte) {
 gcm, _ := cipher.NewGCM(block)
 encryptor := cipher.NewCBCEncrypter(block, nil)
 decryptor := cipher.NewCBCDecrypter(block, nil)
 var ambiguous cipher.BlockMode
 if choose { ambiguous = encryptor } else { ambiguous = decryptor }
 var same, different mldsa.Parameters
 if choose { same = mldsa.MLDSA65(); different = mldsa.MLDSA44() } else { same = mldsa.MLDSA65(); different = mldsa.MLDSA87() }
`
	tests := []struct {
		code, symbol, family, parameter, oid string
		mode                                 cdx.CryptoAlgorithmMode
		functions                            []cdx.CryptoFunction
	}{
		{"_ = crypto.SHA256.New()", "(crypto.Hash).New", "SHA-2", "256", "2.16.840.1.101.3.4.2.1", "", []cdx.CryptoFunction{cdx.CryptoFunctionDigest}},
		{"_ = crypto.Hash.New(crypto.SHA512_256)", "(crypto.Hash).New", "SHA-2", "256", "2.16.840.1.101.3.4.2.6", "", []cdx.CryptoFunction{cdx.CryptoFunctionDigest}},
		{"_ = crypto.MD4.New()", "(crypto.Hash).New", "MD4", "128", "", "", []cdx.CryptoFunction{cdx.CryptoFunctionDigest}},
		{"_ = crypto.RIPEMD160.New()", "(crypto.Hash).New", "RIPEMD", "160", "", "", []cdx.CryptoFunction{cdx.CryptoFunctionDigest}},
		{"_ = hash.New()", "(crypto.Hash).New", "", "", "", "", []cdx.CryptoFunction{cdx.CryptoFunctionDigest}},
		{"_ = crypto.Hash(999).New()", "(crypto.Hash).New", "", "", "", "", []cdx.CryptoFunction{cdx.CryptoFunctionDigest}},
		{"_ = crypto.MD5SHA1.New()", "(crypto.Hash).New", "", "", "", "", []cdx.CryptoFunction{cdx.CryptoFunctionDigest}},
		{"_ = crypto.MLDSAMu.New()", "(crypto.Hash).New", "", "", "", "", []cdx.CryptoFunction{cdx.CryptoFunctionDigest}},
		{"_, _ = mldsa.GenerateKey(mldsa.MLDSA44())", "crypto/mldsa.GenerateKey", "ML-DSA", "44", "2.16.840.1.101.3.4.3.17", "", []cdx.CryptoFunction{cdx.CryptoFunctionKeygen}},
		{"_, _ = mldsa.GenerateKey(mldsa.MLDSA87())", "crypto/mldsa.GenerateKey", "ML-DSA", "87", "2.16.840.1.101.3.4.3.19", "", []cdx.CryptoFunction{cdx.CryptoFunctionKeygen}},
		{"_, _ = mldsa.GenerateKey(same)", "crypto/mldsa.GenerateKey", "ML-DSA", "65", "2.16.840.1.101.3.4.3.18", "", []cdx.CryptoFunction{cdx.CryptoFunctionKeygen}},
		{"_, _ = mldsa.GenerateKey(different)", "crypto/mldsa.GenerateKey", "ML-DSA", "", "", "", []cdx.CryptoFunction{cdx.CryptoFunctionKeygen}},
		{"_, _ = mldsa.GenerateKey(params)", "crypto/mldsa.GenerateKey", "ML-DSA", "", "", "", []cdx.CryptoFunction{cdx.CryptoFunctionKeygen}},
		{"_ = aead.Seal(nil, nil, nil, nil)", "(crypto/cipher.AEAD).Seal", "", "", "", "", []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionTag}},
		{"_, _ = aead.Open(nil, nil, nil, nil)", "(crypto/cipher.AEAD).Open", "", "", "", "", []cdx.CryptoFunction{cdx.CryptoFunctionDecrypt, cdx.CryptoFunctionVerify}},
		{"_ = gcm.Seal(nil, nil, nil, nil)", "(crypto/cipher.AEAD).Seal", "", "", "", cdx.CryptoAlgorithmModeGCM, []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionTag}},
		{"_ = cipher.AEAD.Seal(gcm, nil, nil, nil, nil)", "(crypto/cipher.AEAD).Seal", "", "", "", cdx.CryptoAlgorithmModeGCM, []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionTag}},
		{"encryptor.CryptBlocks(nil, nil)", "(crypto/cipher.BlockMode).CryptBlocks", "", "", "", cdx.CryptoAlgorithmModeCBC, []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt}},
		{"decryptor.CryptBlocks(nil, nil)", "(crypto/cipher.BlockMode).CryptBlocks", "", "", "", cdx.CryptoAlgorithmModeCBC, []cdx.CryptoFunction{cdx.CryptoFunctionDecrypt}},
		{"mode.CryptBlocks(nil, nil)", "(crypto/cipher.BlockMode).CryptBlocks", "", "", "", "", nil},
		{"ambiguous.CryptBlocks(nil, nil)", "(crypto/cipher.BlockMode).CryptBlocks", "", "", "", "", nil},
		{"_ = secretbox.Seal(nil, nil, nonce, key)", "golang.org/x/crypto/nacl/secretbox.Seal", "Salsa20", "256", "", "", []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionTag}},
		{"_, _ = secretbox.Open(nil, nil, nonce, key)", "golang.org/x/crypto/nacl/secretbox.Open", "Salsa20", "256", "", "", []cdx.CryptoFunction{cdx.CryptoFunctionDecrypt, cdx.CryptoFunctionVerify}},
	}
	firstLine := strings.Count(source, "\n") + 1
	for _, test := range tests {
		source += test.code + "\n"
	}
	source += "}\n"
	result, err := (Source{Path: fixture(t, source), Offline: true}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for _, entry := range result.Entries {
		index := entry.Evidence.Line - firstLine
		if index < 0 || index >= len(tests) || entry.Component.CryptoProperties == nil {
			continue
		}
		want := tests[index]
		if entry.Evidence.Symbol != want.symbol && !strings.Contains(entry.Evidence.Symbol, want.symbol+"(") {
			continue
		}
		seen[index] = true
		p := entry.Component.CryptoProperties
		a := p.AlgorithmProperties
		if a == nil {
			t.Errorf("%s is not an algorithm operation", want.code)
			continue
		}
		var functions []cdx.CryptoFunction
		if a.CryptoFunctions != nil {
			functions = *a.CryptoFunctions
		}
		if a.AlgorithmFamily != want.family || a.ParameterSetIdentifier != want.parameter || p.OID != want.oid ||
			a.Mode != want.mode || !slices.Equal(functions, want.functions) {
			t.Errorf("%s: incorrect resolved or guessed facts: %+v, oid=%q", want.code, a, p.OID)
		}
		if a.ClassicalSecurityLevel != nil || a.NistQuantumSecurityLevel != nil {
			t.Fatal("API recognition inferred a security verdict")
		}
	}
	for index, test := range tests {
		if !seen[index] {
			t.Errorf("missing operation: %s", test.code)
		}
	}
	if len(result.Diagnostics) != 0 {
		t.Errorf("modeled operations still produce diagnostics: %+v", result.Diagnostics)
	}
	if _, err := cyclonedx.Encode([]inventory.Collection{{Result: result}}); err != nil {
		t.Fatal(err)
	}
}

func TestGoSourceSymbolsParametersAndGaps(t *testing.T) {
	directory := fixture(t, `package example
import (
 "crypto/aes"
 "crypto/rand"
 alias "crypto/rsa"
 "crypto/sha256"
 "crypto/tls"
 "crypto/x509"
 "golang.org/x/crypto/ssh"
)
func local(bits int) { _, _ = alias.GenerateKey(rand.Reader, bits) }
type fake struct{}
func (fake) GenerateKey(int) {}
func Run(dynamic int) {
 local(2048)
 _, _ = alias.GenerateKey(rand.Reader, dynamic)
 _, _ = aes.NewCipher(make([]byte, 32))
 _ = sha256.Sum256([]byte("PRIVATE_SENTINEL"))
 _, _ = x509.ParseCertificate(nil)
 _, _, _, _, _ = ssh.ParseAuthorizedKey(nil)
 _ = &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: false}
 fake{}.GenerateKey(999)
}`)
	result, err := (Source{Path: directory}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var rsaKnown, rsaUnknown, aes, certificate, ssh, tls bool
	for _, entry := range result.Entries {
		p := entry.Component.CryptoProperties
		if p == nil {
			continue
		}
		if strings.Contains(entry.Evidence.Symbol, "fake") {
			t.Fatal("shadowed name produced a crypto finding")
		}
		if entry.Component.Name == "RSA" {
			size := p.AlgorithmProperties.ParameterSetIdentifier
			rsaKnown = rsaKnown || size == "2048"
			rsaUnknown = rsaUnknown || size == ""
		}
		if entry.Component.Name == "AES" {
			aes = p.AlgorithmProperties.ParameterSetIdentifier == "256"
		}
		certificate = certificate || strings.Contains(entry.Evidence.Symbol, "x509.ParseCertificate")
		ssh = ssh || strings.Contains(entry.Evidence.Symbol, "ssh.ParseAuthorizedKey")
		if entry.Evidence.Symbol == "crypto/tls.Config" && entry.Component.Properties != nil {
			for _, property := range *entry.Component.Properties {
				tls = tls || property.Name == "ciphertrail:tls.min-version" && property.Value == "1.3"
			}
		}
		if entry.Evidence.Line == 0 || entry.Evidence.Location == "" || entry.Evidence.Kind != "configured" {
			t.Fatal("missing source evidence")
		}
		if entry.Component.Properties != nil {
			for _, property := range *entry.Component.Properties {
				if property.Name == "ciphertrail:api" {
					t.Fatal("typed source API evidence was duplicated as a property")
				}
				if property.Name == "ciphertrail:key-size-bits" && p.AlgorithmProperties != nil &&
					p.AlgorithmProperties.ParameterSetIdentifier != "" {
					t.Fatal("a native algorithm parameter was duplicated as a property")
				}
			}
		}
	}
	if !rsaKnown || !rsaUnknown || !aes || !certificate || !ssh || !tls {
		t.Fatalf("coverage: rsaKnown=%v unknown=%v aes=%v x509=%v ssh=%v tls=%v", rsaKnown, rsaUnknown, aes, certificate, ssh, tls)
	}
	componentNames := map[string]string{}
	for _, entry := range result.Entries {
		componentNames[entry.Component.BOMRef] = entry.Component.Name
	}
	for _, entry := range result.Entries {
		if entry.Component.CryptoProperties == nil {
			continue
		}
		wantProvider := "Go standard library"
		if strings.Contains(entry.Evidence.Symbol, "golang.org/x/crypto/") {
			wantProvider = "golang.org/x/crypto"
		}
		found := false
		for _, dependency := range result.Dependencies {
			found = found || dependency.Source == entry.Component.BOMRef && componentNames[dependency.Target] == wantProvider
		}
		if !found {
			t.Errorf("missing %s implementation context for %s", wantProvider, entry.Evidence.Symbol)
		}
	}
	data, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "PRIVATE_SENTINEL") {
		t.Fatal("source literal leaked")
	}
}

func TestNestedModulesAndBuildTags(t *testing.T) {
	directory := fixture(t, `package example; import "crypto/sha256"; func Run(){ _ = sha256.Sum256(nil) }`)
	nested := filepath.Join(directory, "nested")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"nested/go.mod":   "module example.test/nested\n\ngo 1.27.0\n",
		"nested/hash.go":  "package nested; import \"crypto/sha512\"; func Run(){ _ = sha512.Sum512(nil) }\n",
		"excluded.go":     "//go:build special\n\npackage example; import \"crypto/md5\"; func Extra(){ _ = md5.Sum(nil) }\n",
		"ignored_test.go": "package example; import \"crypto/sha1\"; func TestHelper(){ _ = sha1.Sum(nil) }\n",
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	result, err := (Source{Path: directory}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, entry := range result.Entries {
		names[entry.Component.Name] = true
	}
	if !names["SHA-256"] || !names["SHA-512"] || names["MD5"] || names["SHA-1"] {
		t.Fatalf("incorrect build/module scope: %v", names)
	}
}

func TestExportedAndAmbiguousWrapperParametersRemainUnknown(t *testing.T) {
	directory := fixture(t, `package example
import ("crypto/rsa"; "crypto/rand")
func Exported(bits int) { _, _ = rsa.GenerateKey(rand.Reader, bits) }
func local(bits int) { _, _ = rsa.GenerateKey(rand.Reader, bits) }
func Run() { Exported(2048); local(2048); local(4096) }
`)
	result, err := (Source{Path: directory}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range result.Entries {
		if entry.Component.Name == "RSA" {
			count++
			if entry.Component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier != "" {
				t.Fatal("incomplete caller set produced a falsely precise key size")
			}
		}
	}
	if count != 2 {
		t.Fatalf("expected two RSA sites, got %d", count)
	}
}

func TestTypeAliasesAndHashPackageIdentity(t *testing.T) {
	directory := fixture(t, `package example
import ("crypto/hmac"; "crypto/tls"; fake "example.test/fixture/fake")
type Settings = tls.Config
func Run() { _ = &Settings{MinVersion: tls.VersionTLS13}; _ = hmac.New(fake.New, nil) }
`)
	if err := os.Mkdir(filepath.Join(directory, "fake"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "fake", "hash.go"), []byte(`package sha256
import ("crypto/sha512"; "hash")
func New() hash.Hash { return sha512.New() }
`), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := (Source{Path: directory}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var config, genericHMAC bool
	for _, entry := range result.Entries {
		config = config || entry.Evidence.Symbol == "crypto/tls.Config"
		genericHMAC = genericHMAC || entry.Component.Name == "HMAC"
		if entry.Component.Name == "HMAC-SHA-256" {
			t.Fatal("package name was mistaken for cryptographic package identity")
		}
	}
	if !config || !genericHMAC {
		t.Fatal("missing type-alias or generic HMAC evidence")
	}
}

func TestInvalidSourceAndCancellationAreReported(t *testing.T) {
	directory := fixture(t, "package example\nfunc broken( {}")
	result, err := (Source{Path: directory}).Collect(context.Background())
	if err == nil {
		t.Fatal("invalid source accepted")
	}
	if _, encodeErr := cyclonedx.Encode([]inventory.Collection{{Result: result, Err: err}}); encodeErr != nil {
		t.Fatal(encodeErr)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Source{Path: directory}).Collect(ctx); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestSelfScanAPIsHaveExplicitModelsOrNonAssetClassification(t *testing.T) {
	directory := fixture(t, `package example
import (
 "context"
 "crypto"
 "crypto/ecdh"
 "crypto/elliptic"
 "crypto/tls"
 "crypto/x509"
 "crypto/x509/pkix"
 "golang.org/x/crypto/ssh"
)
func Run(signer crypto.Signer, private *ecdh.PrivateKey, public *ecdh.PublicKey,
 curve elliptic.Curve, signature x509.SignatureAlgorithm, name pkix.Name,
 key ssh.PublicKey, native ssh.CryptoPublicKey, connection *tls.Conn,
 remote ssh.Conn, auth tls.ClientAuthType, pool *x509.CertPool) {
 _ = elliptic.P256()
 _ = signer.Public()
 _ = private.PublicKey()
 _ = curve.Params()
 _ = public.Curve()
 _ = signature.String()
 _ = name.String()
 _ = key.Type()
 _ = native.CryptoPublicKey()
 _ = ssh.FingerprintSHA256(key)
 _ = x509.NewCertPool()
 _ = pool.AppendCertsFromPEM(nil)
 _ = pool.Clone()
 _ = connection.HandshakeContext(context.Background())
 _ = connection.ConnectionState()
 _ = tls.CipherSuiteName(tls.TLS_AES_128_GCM_SHA256)
 _ = remote.Close()
 _ = auth.String()
}`)
	result, err := (Source{Path: directory}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("known APIs still report coverage gaps: %+v", result.Diagnostics)
	}
	tests := []struct {
		symbol string
		kind   cdx.CryptoAssetType
	}{
		{"crypto/elliptic.P256", cdx.CryptoAssetTypeAlgorithm},
		{"crypto.Signer).Public", cdx.CryptoAssetTypeRelatedCryptoMaterial},
		{"crypto/ecdh.PrivateKey).PublicKey", cdx.CryptoAssetTypeRelatedCryptoMaterial},
		{"ssh.CryptoPublicKey).CryptoPublicKey", cdx.CryptoAssetTypeRelatedCryptoMaterial},
		{"ssh.FingerprintSHA256", cdx.CryptoAssetTypeAlgorithm},
		{"x509.CertPool).AppendCertsFromPEM", cdx.CryptoAssetTypeCertificate},
		{"tls.Conn).HandshakeContext", cdx.CryptoAssetTypeProtocol},
	}
	for _, tt := range tests {
		t.Run(tt.symbol, func(t *testing.T) {
			var matches []inventory.Entry
			for _, entry := range result.Entries {
				if entry.Component.CryptoProperties != nil && strings.Contains(entry.Evidence.Symbol, tt.symbol) {
					matches = append(matches, entry)
				}
			}
			if len(matches) != 1 {
				t.Fatalf("expected one modeled site, got %d", len(matches))
			}
			entry := matches[0]
			properties := entry.Component.CryptoProperties
			if properties.AssetType != tt.kind || entry.Evidence.Kind != "configured" || entry.Evidence.Line <= 0 || entry.Evidence.Location != "main.go" {
				t.Fatalf("incorrect type or provenance: %+v", entry)
			}
			switch tt.kind {
			case cdx.CryptoAssetTypeRelatedCryptoMaterial:
				key := properties.RelatedCryptoMaterialProperties
				if key == nil || key.Type != cdx.RelatedCryptoMaterialTypePublicKey || key.Value != "" || key.Size != nil {
					t.Fatalf("key accessor invented runtime key material: %+v", key)
				}
			case cdx.CryptoAssetTypeAlgorithm:
				algorithm := properties.AlgorithmProperties
				if strings.Contains(tt.symbol, "P256") {
					if algorithm == nil || algorithm.EllipticCurve != "nist/P-256" || algorithm.Curve != "" || algorithm.Primitive != cdx.CryptoPrimitiveOther {
						t.Fatalf("curve selection was misclassified: %+v", algorithm)
					}
				} else if algorithm == nil || algorithm.Primitive != cdx.CryptoPrimitiveHash || entry.Component.Name != "SHA-256" {
					t.Fatal("SSH fingerprint was not identified as SHA-256 hashing")
				}
			case cdx.CryptoAssetTypeCertificate:
				if certificate := properties.CertificateProperties; certificate != nil && (certificate.SubjectName != "" || certificate.NotValidAfter != "") {
					t.Fatal("PEM import invented a runtime certificate")
				}
			case cdx.CryptoAssetTypeProtocol:
				protocol := properties.ProtocolProperties
				if protocol == nil || protocol.Type != cdx.CryptoProtocolTypeTLS || protocol.Version != "" || protocol.CipherSuites != nil {
					t.Fatal("source handshake was mistaken for negotiated runtime evidence")
				}
			}
		})
	}
	count := 0
	for _, entry := range result.Entries {
		if entry.Component.CryptoProperties != nil {
			count++
		}
		if entry.Component.Properties != nil {
			for _, property := range *entry.Component.Properties {
				if property.Name == "ciphertrail:analysis-scope" {
					t.Fatal("generic analysis boilerplate was copied into component metadata")
				}
			}
		}
	}
	if count != len(tests) {
		t.Fatalf("non-asset helpers created cryptographic assets: got %d, want %d", count, len(tests))
	}
	data, err := cyclonedx.Encode([]inventory.Collection{{Collector: "go", Result: result}})
	if err != nil || cyclonedx.Validate(data) != nil {
		t.Fatalf("invalid CBOM: %v", err)
	}
}

func certificateFixture(t *testing.T, source string) string {
	t.Helper()
	directory := fixture(t, source)
	modFile := filepath.Join(directory, "go.mod")
	mod, err := os.ReadFile(modFile)
	if err != nil {
		t.Fatal(err)
	}
	mod = append(mod, []byte("\nrequire github.com/cert-manager/cert-manager v0.0.0\nreplace github.com/cert-manager/cert-manager => ./certmanager\n")...)
	if err := os.WriteFile(modFile, mod, 0600); err != nil {
		t.Fatal(err)
	}
	typesDir := filepath.Join(directory, "certmanager", "pkg", "apis", "certmanager", "v1")
	if err := os.MkdirAll(typesDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "certmanager", "go.mod"), []byte("module github.com/cert-manager/cert-manager\n\ngo 1.27.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(typesDir, "types.go"), []byte(`package v1
import "time"
type PrivateKeyAlgorithm string
type KeyUsage string
const RSAKeyAlgorithm PrivateKeyAlgorithm = "RSA"
const RotationPolicyAlways = "Always"
const PKCS1 = "PKCS1"
const UsageServerAuth KeyUsage = "server auth"
const UsageDigitalSignature KeyUsage = "digital signature"
type CertificatePrivateKey struct { Algorithm PrivateKeyAlgorithm; Size int; Encoding, RotationPolicy string }
type Duration struct { Duration time.Duration }
type ObjectReference struct { Name, Kind, Group string }
type CertificateSpec struct { CommonName, SecretName string; PrivateKey *CertificatePrivateKey; Duration, RenewBefore *Duration; Usages []KeyUsage; IssuerRef ObjectReference; IsCA bool }
type Certificate struct { Spec CertificateSpec }
`), 0600); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestCertificateManagerDeclarationsResolveCopiedSettings(t *testing.T) {
	directory := certificateFixture(t, `package example
import ("time"; cm "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1")
var keyPolicy = &cm.CertificatePrivateKey{Algorithm:cm.RSAKeyAlgorithm, Size:2048, Encoding:cm.PKCS1, RotationPolicy:cm.RotationPolicyAlways}
var lifetime = &cm.Duration{Duration:30*24*time.Hour}
var renewal = &cm.Duration{Duration:10*24*time.Hour}
var usages = []cm.KeyUsage{cm.UsageDigitalSignature,cm.UsageServerAuth}
func Build(issuer, secret string) cm.Certificate {
 key := *keyPolicy
 duration := *lifetime
 renew := *renewal
 use := append([]cm.KeyUsage(nil), usages...)
 return cm.Certificate{Spec:cm.CertificateSpec{SecretName:secret, PrivateKey:&key, Duration:&duration, RenewBefore:&renew, Usages:use, IssuerRef:cm.ObjectReference{Name:issuer,Kind:"Issuer",Group:"cert-manager.io"}}}
}`)
	result, err := (Source{Path: directory}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	components := map[string]cdx.Component{}
	for _, entry := range result.Entries {
		components[entry.Component.BOMRef] = entry.Component
	}
	found := false
	for _, entry := range result.Entries {
		if entry.Component.Name != "cert-manager Certificate configuration" {
			continue
		}
		found = true
		p := entry.Component.CryptoProperties.CertificateProperties
		if entry.Evidence.Symbol != "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1.CertificateSpec" ||
			entry.Evidence.Kind != "configured" || entry.Evidence.Location != "main.go" ||
			p.SerialNumber != "" || p.NotValidAfter != "" || p.RelatedCryptographicAssets == nil {
			t.Fatalf("incorrect certificate declaration evidence: %+v", entry)
		}
		properties := map[string]string{}
		for _, property := range *entry.Component.Properties {
			properties[property.Name] = property.Value
		}
		if !strings.Contains(properties["ciphertrail:cert-manager.usages"], "server auth") {
			t.Fatalf("incorrect or guessed declaration settings: %v", properties)
		}
		for _, field := range []string{"duration", "renew-before", "issuer.name", "issuer.kind", "issuer.group", "secret-name", "common-name"} {
			if _, exists := properties["ciphertrail:cert-manager."+field]; exists {
				t.Fatalf("deployment-only field was retained: %s", field)
			}
		}
		key := components[(*p.RelatedCryptographicAssets)[0].Ref].CryptoProperties.RelatedCryptoMaterialProperties
		if key == nil || key.Type != cdx.RelatedCryptoMaterialTypePrivateKey || key.Size == nil || *key.Size != 2048 || key.Value != "" {
			t.Fatalf("missing configured RSA key size: %+v", key)
		}
		algorithm := components[(*key.RelatedCryptographicAssets)[0].Ref]
		if algorithm.Name != "RSA" || algorithm.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier != "2048" {
			t.Fatal("missing configured RSA algorithm relationship")
		}
		provider := false
		for _, dependency := range result.Dependencies {
			provider = provider || dependency.Source == entry.Component.BOMRef &&
				components[dependency.Target].Name == "github.com/cert-manager/cert-manager"
		}
		if !provider {
			t.Fatal("missing cert-manager provider context")
		}
	}
	if !found {
		t.Fatal("declarative certificate configuration was missed")
	}
	if _, err := cyclonedx.Encode([]inventory.Collection{{Result: result}}); err != nil {
		t.Fatal(err)
	}
}

func TestMutableCertificateSettingsRemainUnknown(t *testing.T) {
	directory := certificateFixture(t, `package example
import cm "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
var keyPolicy = &cm.CertificatePrivateKey{Algorithm:cm.RSAKeyAlgorithm, Size:2048}
func Mutate() { alias := keyPolicy; alias.Size = 4096 }
func Build() cm.CertificateSpec { key := *keyPolicy; return cm.CertificateSpec{PrivateKey:&key} }
`)
	result, err := (Source{Path: directory}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	components := map[string]cdx.Component{}
	for _, entry := range result.Entries {
		components[entry.Component.BOMRef] = entry.Component
	}
	found := false
	for _, entry := range result.Entries {
		if entry.Component.Name == "cert-manager Certificate configuration" {
			found = true
			related := entry.Component.CryptoProperties.CertificateProperties.RelatedCryptographicAssets
			if related == nil || len(*related) != 1 {
				t.Fatal("unknown key configuration was not represented")
			}
			key := components[(*related)[0].Ref].CryptoProperties.RelatedCryptoMaterialProperties
			if key.Size != nil || key.RelatedCryptographicAssets != nil {
				t.Fatal("mutable settings were incorrectly attributed to the certificate")
			}
		}
	}
	if !found {
		t.Fatal("certificate declaration disappeared when its key settings were unknown")
	}
}

func TestEscapingGlobalCertificateSettingsRemainUnknown(t *testing.T) {
	directory := certificateFixture(t, `package example
import cm "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
var policy = &cm.CertificatePrivateKey{Algorithm:cm.RSAKeyAlgorithm, Size:2048}
type Holder struct { Key *cm.CertificatePrivateKey }
var holder = Holder{Key:policy}
func Mutate() { holder.Key.Size = 4096 }
func Build() cm.CertificateSpec { key := *policy; return cm.CertificateSpec{PrivateKey:&key} }
`)
	result, err := (Source{Path: directory}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	components := map[string]cdx.Component{}
	for _, entry := range result.Entries {
		components[entry.Component.BOMRef] = entry.Component
	}
	found := false
	for _, entry := range result.Entries {
		if entry.Component.Name == "cert-manager Certificate configuration" {
			found = true
			ref := (*entry.Component.CryptoProperties.CertificateProperties.RelatedCryptographicAssets)[0].Ref
			key := components[ref].CryptoProperties.RelatedCryptoMaterialProperties
			if key.Size != nil || key.RelatedCryptographicAssets != nil {
				t.Fatal("escaped global parameters were guessed from initialization")
			}
		}
	}
	if !found {
		t.Fatal("unknown declaration was lost")
	}
}

func TestCertificateDeclarationsUseTypeIdentityAndHonorExclusions(t *testing.T) {
	directory := certificateFixture(t, `package example
import cm "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
type Spec = cm.CertificateSpec
type CertificateSpec struct { SecretName string }
var lookalike = CertificateSpec{SecretName:"PRIVATE_SENTINEL"}
func Build() Spec { return Spec{PrivateKey:&cm.CertificatePrivateKey{Algorithm:cm.RSAKeyAlgorithm,Size:2048}} }
`)
	fixturePath := filepath.Join(directory, "fixture.go")
	if err := os.WriteFile(fixturePath, []byte(`package example
import cm "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
func Fixture() cm.CertificateSpec { return cm.CertificateSpec{SecretName:"EXCLUDED_SENTINEL"} }
`), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := (Source{Path: directory, Exclude: []string{"fixture.go"}}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range result.Entries {
		if entry.Component.Name == "cert-manager Certificate configuration" {
			count++
			if entry.Evidence.Location != "main.go" {
				t.Fatal("excluded declaration was inventoried")
			}
		}
	}
	if count != 1 {
		t.Fatalf("alias or lookalike classification failed: %d declarations", count)
	}
	data, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
	if err != nil || strings.Contains(string(data), "PRIVATE_SENTINEL") || strings.Contains(string(data), "EXCLUDED_SENTINEL") {
		t.Fatalf("unrelated or excluded data leaked: %v", err)
	}
}

func TestCertificateKeyAlgorithmsDoNotAssumeDefaults(t *testing.T) {
	directory := certificateFixture(t, `package example
import cm "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
var A = cm.CertificatePrivateKey{Algorithm:"ECDSA",Size:384}
var B = cm.CertificatePrivateKey{Algorithm:"Ed25519",Size:2048}
var C = cm.CertificatePrivateKey{Algorithm:"RSA"}
var D = cm.CertificatePrivateKey{}
`)
	result, err := (Source{Path: directory}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var ecdsa, ed25519, rsa, unknown bool
	for _, entry := range result.Entries {
		p := entry.Component.CryptoProperties
		if p == nil {
			continue
		}
		if a := p.AlgorithmProperties; a != nil {
			switch entry.Component.Name {
			case "ECDSA":
				ecdsa = a.EllipticCurve == "nist/P-384" && a.ParameterSetIdentifier == "384"
			case "Ed25519":
				ed25519 = a.EllipticCurve == "other/Ed25519" && a.ParameterSetIdentifier == ""
			case "RSA":
				rsa = a.ParameterSetIdentifier == ""
			}
		}
		if key := p.RelatedCryptoMaterialProperties; key != nil && key.RelatedCryptographicAssets == nil {
			unknown = key.Size == nil
		}
	}
	if !ecdsa || !ed25519 || !rsa || !unknown {
		t.Fatalf("incorrect defaults or ignored key size: ecdsa=%v ed25519=%v rsa=%v unknown=%v", ecdsa, ed25519, rsa, unknown)
	}
	if _, err := cyclonedx.Encode([]inventory.Collection{{Result: result}}); err != nil {
		t.Fatal(err)
	}
}

func TestCompactDeclarationsDistinguishAbsentDynamicAndLiteralValues(t *testing.T) {
	directory := certificateFixture(t, `package example
import ("time"; "crypto/tls"; cm "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1")
var Duration = &cm.Duration{Duration:30*24*time.Hour}
func CopyDuration() cm.Duration { return *Duration }
func Build(commonName, secretName string) cm.CertificateSpec {
 duration := CopyDuration()
 return cm.CertificateSpec{
  CommonName:commonName, SecretName:secretName, IsCA:false, Duration:&duration,
  IssuerRef:cm.ObjectReference{Name:"unknown",Kind:"Issuer"},
  PrivateKey:&cm.CertificatePrivateKey{Algorithm:"RSA",Size:0,Encoding:"unknown"},
 }
}
func Empty() cm.CertificateSpec { return cm.CertificateSpec{} }
func TLS(version uint16) *tls.Config { return &tls.Config{MinVersion:version,InsecureSkipVerify:false} }
`)
	result, err := (Source{Path: directory}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var configured, empty, key, tlsConfig bool
	for _, entry := range result.Entries {
		p := map[string]string{}
		if entry.Component.Properties != nil {
			for _, property := range *entry.Component.Properties {
				p[property.Name] = property.Value
			}
		}
		if entry.Component.Name == "cert-manager Certificate configuration" {
			if _, hasCASetting := p["ciphertrail:cert-manager.is-ca"]; hasCASetting {
				configured = true
				if p["ciphertrail:cert-manager.is-ca"] != "false" ||
					len(entry.Evidence.Parameters) != 0 || len(entry.Evidence.Unresolved) != 0 {
					t.Fatalf("crypto settings changed or ignored spec details were still analyzed: %+v %v", entry.Evidence, p)
				}
				for _, name := range []string{"duration", "duration:declared", "renew-before", "issuer.name", "issuer.kind", "issuer.group", "common-name", "secret-name", "usages"} {
					if _, exists := p["ciphertrail:cert-manager."+name]; exists {
						t.Fatalf("absent or unresolved value placeholder retained: %s", name)
					}
				}
			} else {
				empty = true
				if len(p) != 0 || len(entry.Evidence.Unresolved) != 0 {
					t.Fatalf("empty initializer invented settings or unknowns: %v %+v", p, entry.Evidence)
				}
			}
		}
		if entry.Component.Name == "cert-manager Private key configuration" {
			key = true
			if p["ciphertrail:cert-manager.key-size"] != "0" ||
				p["ciphertrail:cert-manager.key-encoding"] != "unknown" ||
				len(entry.Evidence.Unresolved) != 0 {
				t.Fatalf("literal zero/unknown value or key evidence scope changed: %v %+v", p, entry.Evidence)
			}
		}
		if entry.Evidence.Symbol == "crypto/tls.Config" {
			tlsConfig = true
			if p["ciphertrail:tls.insecure-skip-verify"] != "false" ||
				p["ciphertrail:tls.min-version"] != "" ||
				!slices.Contains(entry.Evidence.Unresolved, "tls.min-version") {
				t.Fatalf("TLS literal and dynamic values were conflated: %v %+v", p, entry.Evidence)
			}
		}
	}
	if !configured || !empty || !key || !tlsConfig {
		t.Fatal("compact output dropped a declaration")
	}
	data, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
	if err != nil {
		t.Fatal(err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatal(err)
	}
	for _, component := range *bom.Components {
		if component.Properties == nil {
			continue
		}
		for _, property := range *component.Properties {
			if property.Name == "ciphertrail:evidence" || property.Name == "ciphertrail:parameters" {
				t.Fatal("duplicate evidence or generic unknown disclaimer remains")
			}
		}
	}
}

func TestCSRSignatureCheckIsVerificationNotIssuance(t *testing.T) {
	directory := fixture(t, `package example
import "crypto/x509"
func Check(request *x509.CertificateRequest) error { return request.CheckSignature() }
`)
	result, err := (Source{Path: directory}).Collect(context.Background())
	if err != nil || len(result.Diagnostics) != 0 {
		t.Fatalf("CSR check remains unmodeled: %v %+v", err, result.Diagnostics)
	}
	found := false
	for _, entry := range result.Entries {
		if strings.Contains(entry.Evidence.Symbol, "CertificateRequest).CheckSignature") {
			found = true
			a := entry.Component.CryptoProperties.AlgorithmProperties
			if a == nil || a.Primitive != cdx.CryptoPrimitiveSignature || a.CryptoFunctions == nil ||
				len(*a.CryptoFunctions) != 1 || (*a.CryptoFunctions)[0] != cdx.CryptoFunctionVerify ||
				a.ParameterSetIdentifier != "" || entry.Evidence.Kind != "configured" {
				t.Fatalf("CSR verification was misrepresented: %+v", entry)
			}
		}
	}
	if !found {
		t.Fatal("CSR verification finding missing")
	}
}

func TestReceiverKeySizeHasQualifiedConstructorEvidence(t *testing.T) {
	directory := fixture(t, `package example
import ("crypto/rsa"; "crypto/rand")
type Generator struct { keySize int }
type Other struct { keySize int }
var _ interface{} = Generator{}
func New() Generator { return Generator{keySize:4096} }
func Unrelated() Other { return Other{keySize:1024} }
func (g Generator) Generate() { _, _ = rsa.GenerateKey(rand.Reader, g.keySize) }
`)
	result, err := (Source{Path: directory}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range result.Entries {
		if entry.Component.Name != "RSA" {
			continue
		}
		found = true
		if entry.Component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier != "" {
			t.Fatal("an unconstrained exported receiver was given an unconditional key size")
		}
		if len(entry.Evidence.Parameters) != 1 {
			t.Fatalf("missing constructor evidence: %+v", entry.Evidence)
		}
		fact := entry.Evidence.Parameters[0]
		if fact.Name != "key-size-bits" || fact.Value != "4096" || fact.Basis != "field-initializer" ||
			!strings.HasSuffix(fact.Symbol, ".Generator.keySize") ||
			fact.Location != "main.go" || fact.Line == 0 || fact.Limitation == "" {
			t.Fatalf("incorrect or unqualified field inference: %+v", fact)
		}
	}
	if !found {
		t.Fatal("RSA call was lost")
	}
}

func TestCopiedExportedPolicyHasQualifiedDefinitionEvidence(t *testing.T) {
	directory := certificateFixture(t, `package example
import (cm "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"; "example.test/fixture/policy")
func Build() cm.CertificateSpec { key := policy.CopyKey(); duration := policy.CopyDuration(); return cm.CertificateSpec{PrivateKey:&key,Duration:&duration} }
`)
	policy := filepath.Join(directory, "policy")
	if err := os.Mkdir(policy, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policy, "policy.go"), []byte(`package policy
import ("time"; cm "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1")
const bits = 256
var Rotation = cm.RotationPolicyAlways
var Key = &cm.CertificatePrivateKey{Algorithm:"ECDSA",Size:bits,RotationPolicy:Rotation}
var Duration = &cm.Duration{Duration:30*24*time.Hour}
func CopyKey() cm.CertificatePrivateKey { return *Key }
func CopyDuration() cm.Duration { return *Duration }
`), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := (Source{Path: directory}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	components := map[string]cdx.Component{}
	for _, entry := range result.Entries {
		components[entry.Component.BOMRef] = entry.Component
	}
	var keyFound, durationFound, rotationFound bool
	for _, entry := range result.Entries {
		if entry.Evidence.Location != "main.go" {
			continue
		}
		for _, fact := range entry.Evidence.Parameters {
			if fact.Location != "policy/policy.go" || fact.Limitation == "" {
				t.Fatalf("missing policy origin/uncertainty: %+v", fact)
			}
			keyFound = keyFound || fact.Name == "cert-manager.key-size" && fact.Value == "256"
			durationFound = durationFound || fact.Name == "cert-manager.duration" && fact.Value == "720h0m0s"
			rotationFound = rotationFound || fact.Name == "cert-manager.rotation-policy" && fact.Value == "Always"
			if entry.Component.Name == "cert-manager Private key configuration" && fact.Name == "cert-manager.duration" {
				t.Fatal("certificate lifetime evidence leaked into the private-key finding")
			}
		}
		if entry.Component.Name == "cert-manager Private key configuration" {
			key := entry.Component.CryptoProperties.RelatedCryptoMaterialProperties
			if key.Size != nil || key.RelatedCryptographicAssets == nil {
				t.Fatal("mutable policy was treated as certain or its definition link was lost")
			}
			relation := (*key.RelatedCryptographicAssets)[0]
			if relation.Type != "declaredPolicy" || components[relation.Ref].CryptoProperties.RelatedCryptoMaterialProperties.Size == nil {
				t.Fatal("declared policy was not linked to its typed definition")
			}
		}
	}
	if !keyFound || durationFound || !rotationFound {
		t.Fatalf("crypto policy facts or omitted spec scope changed: key=%v duration=%v rotation=%v", keyFound, durationFound, rotationFound)
	}
	if _, err := cyclonedx.Encode([]inventory.Collection{{Result: result}}); err != nil {
		t.Fatal(err)
	}
}

func TestReceiverKeySizeCandidatesHonorScopeAndKeepAlternatives(t *testing.T) {
	directory := fixture(t, `package example
import ("crypto/rsa"; "crypto/rand")
type Generator struct { keySize int }
type Other struct { keySize int }
func First() *Generator { return &Generator{keySize:4096} }
func Second() Generator { return Generator{keySize:3072} }
func Zero() Generator { return Generator{} }
func Unrelated() Other { return Other{keySize:1024} }
func Change(g *Generator) { g.keySize = 2048 }
func (g *Generator) Generate() { _, _ = rsa.GenerateKey(rand.Reader, g.keySize) }
`)
	for name, code := range map[string]string{
		"excluded.go": `package example; var excluded = Generator{keySize:8192}`,
		"key_test.go": `package example; var fixture = Generator{keySize:1536}`,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(code), 0600); err != nil {
			t.Fatal(err)
		}
	}
	result, err := (Source{Path: directory, Exclude: []string{"excluded.go"}}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range result.Entries {
		if entry.Component.Name != "RSA" {
			continue
		}
		found = true
		if entry.Component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier != "" {
			t.Fatal("constructor alternatives or subsequent mutations were collapsed into an exact size")
		}
		candidates := map[string]int{}
		for _, fact := range entry.Evidence.Parameters {
			candidates[fact.Value]++
			if fact.Location != "main.go" || fact.Basis != "field-initializer" || fact.Limitation == "" {
				t.Fatalf("excluded or unqualified constructor evidence: %+v", fact)
			}
		}
		if len(candidates) != 2 || candidates["4096"] != 1 || candidates["3072"] != 1 {
			t.Fatalf("missing alternatives or unrelated constructors included: %v", candidates)
		}
	}
	if !found {
		t.Fatal("pointer-receiver RSA operation disappeared")
	}
}

func TestPurePrivatePolicyGettersResolveAcrossPackages(t *testing.T) {
	directory := certificateFixture(t, `package example
import (cm "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"; "example.test/fixture/policy")
func Build() cm.CertificateSpec {
 key := policy.CopyKey()
 duration := policy.CopyDuration()
 return cm.CertificateSpec{PrivateKey:&key,Duration:&duration,Usages:policy.CopyUsages()}
}
`)
	policy := filepath.Join(directory, "policy")
	if err := os.Mkdir(policy, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policy, "policy.go"), []byte(`package policy
import ("time"; cm "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1")
var rotation = cm.RotationPolicyAlways
var key = &cm.CertificatePrivateKey{Algorithm:"ECDSA",Size:256,RotationPolicy:rotation}
var duration = &cm.Duration{Duration:30*24*time.Hour}
var usages = []cm.KeyUsage{cm.UsageDigitalSignature}
func CopyKey() cm.CertificatePrivateKey { return *key }
func CopyDuration() cm.Duration { return *duration }
func CopyUsages() []cm.KeyUsage { return append([]cm.KeyUsage(nil), usages...) }
func MutateCopy() { copy := CopyKey(); copy.Size = 384 }
`), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := (Source{Path: directory}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var keyFound, durationFound, usageFound bool
	for _, entry := range result.Entries {
		if entry.Evidence.Location != "main.go" {
			continue
		}
		if entry.Component.Name == "cert-manager Private key configuration" {
			key := entry.Component.CryptoProperties.RelatedCryptoMaterialProperties
			keyFound = key.Size != nil && *key.Size == 256 && len(entry.Evidence.Parameters) == 0
		}
		if entry.Component.Name == "cert-manager Certificate configuration" {
			for _, property := range *entry.Component.Properties {
				durationFound = durationFound || property.Name == "ciphertrail:cert-manager.duration" && property.Value == "720h0m0s"
				usageFound = usageFound || property.Name == "ciphertrail:cert-manager.usages" && property.Value == "digital signature"
			}
		}
	}
	if !keyFound || durationFound || !usageFound {
		t.Fatalf("retained or omitted policy settings incorrect: key=%v duration=%v usage=%v", keyFound, durationFound, usageFound)
	}
}

func TestPolicyGettersRejectMutationUnsupportedFlowsAndExcludedOrigins(t *testing.T) {
	for _, test := range []struct {
		name, helper, extra, caller string
		exclude                     []string
		private                     bool
	}{
		{name: "cross-package-field-write", extra: `func Mutate() { policy.Key.Size = 4096 }`},
		{name: "cross-package-reassignment", extra: `func Mutate() { policy.Key = &cm.CertificatePrivateKey{Algorithm:"RSA",Size:4096} }`},
		{name: "cross-package-escape", extra: `func Escape() *cm.CertificatePrivateKey { return policy.Key }`},
		{name: "cross-package-alias-write", extra: `func Mutate() { alias := policy.Key; alias.Size = 4096 }`},
		{name: "branched-helper", helper: `func CopyKey() cm.CertificatePrivateKey { if Key == nil { return cm.CertificatePrivateKey{} }; return *Key }`},
		{name: "side-effecting-helper", helper: `func CopyKey() cm.CertificatePrivateKey { Key.Size = 4096; return *Key }`},
		{name: "recursive-helper", helper: `func CopyKey() cm.CertificatePrivateKey { return again() }; func again() cm.CertificatePrivateKey { return CopyKey() }`},
		{name: "parameterized-helper", helper: `func CopyKey(n int) cm.CertificatePrivateKey { return *Key }`, caller: `policy.CopyKey(1)`},
		{name: "method-helper", helper: `type Factory struct{}; func (Factory) CopyKey() cm.CertificatePrivateKey { return *Key }`, caller: `policy.Factory{}.CopyKey()`},
		{name: "excluded-getter", exclude: []string{"policy/getter.go"}},
		{name: "excluded-initializer", exclude: []string{"policy/definition.go"}},
		{name: "excluded-private-initializer", exclude: []string{"policy/definition.go"}, private: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			caller := test.caller
			if caller == "" {
				caller = "policy.CopyKey()"
			}
			directory := certificateFixture(t, `package example
import (cm "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"; "example.test/fixture/policy")
func Build() cm.CertificateSpec { key := `+caller+`; return cm.CertificateSpec{PrivateKey:&key} }
`+test.extra)
			policy := filepath.Join(directory, "policy")
			if err := os.Mkdir(policy, 0700); err != nil {
				t.Fatal(err)
			}
			helper := test.helper
			if helper == "" {
				helper = "func CopyKey() cm.CertificatePrivateKey { return *Key }"
			}
			for name, code := range map[string]string{
				"definition.go": `var Key = &cm.CertificatePrivateKey{Algorithm:"ECDSA",Size:256,RotationPolicy:"EXCLUDED_ORIGIN_SENTINEL"}`,
				"getter.go":     helper,
			} {
				content := `package policy; import cm "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"; ` + code
				if test.private {
					content = strings.ReplaceAll(content, " Key", " key")
					content = strings.ReplaceAll(content, "*Key", "*key")
				}
				if err := os.WriteFile(filepath.Join(policy, name), []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			result, err := (Source{Path: directory, Exclude: test.exclude}).Collect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			components := map[string]inventory.Entry{}
			for _, entry := range result.Entries {
				components[entry.Component.BOMRef] = entry
			}
			found := false
			for _, entry := range result.Entries {
				if entry.Component.Name != "cert-manager Certificate configuration" || entry.Evidence.Location != "main.go" {
					continue
				}
				found = true
				ref := (*entry.Component.CryptoProperties.CertificateProperties.RelatedCryptographicAssets)[0].Ref
				key := components[ref]
				if key.Component.CryptoProperties.RelatedCryptoMaterialProperties.Size != nil ||
					key.Component.CryptoProperties.RelatedCryptoMaterialProperties.RelatedCryptographicAssets != nil ||
					len(key.Evidence.Parameters) != 0 {
					t.Fatalf("unsafe or excluded policy resolved at use site: %+v", key)
				}
			}
			if !found {
				t.Fatal("unknown certificate configuration was lost")
			}
			if strings.HasSuffix(test.name, "initializer") {
				data, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
				if err != nil || strings.Contains(string(data), "EXCLUDED_ORIGIN_SENTINEL") {
					t.Fatalf("excluded initializer leaked into report: %v", err)
				}
			}
		})
	}
}

func TestSSHSessionChannelAndAuthenticationAPIs(t *testing.T) {
	directory := fixture(t, `package example
import ("crypto"; "crypto/rsa"; "golang.org/x/crypto/ssh")
func Run(client *ssh.Client, session *ssh.Session, channel ssh.Channel, key *rsa.PublicKey, other crypto.PublicKey, signers ...ssh.Signer) {
 _ = channel.Close()
 _, _ = channel.Read(nil)
 _, _ = channel.Write(nil)
 _ = key.Equal(other)
 _ = session.Wait()
 _ = ssh.PublicKeys(signers...)
 _ = ssh.InsecureIgnoreHostKey()
 _, _ = client.NewSession()
 _, _ = session.StdinPipe()
 _, _ = session.StdoutPipe()
 _, _ = session.StderrPipe()
 _ = session.Shell()
}`)
	result, err := (Source{Path: directory}).Collect(context.Background())
	if err != nil || len(result.Diagnostics) != 0 {
		t.Fatalf("SSH/RSA APIs remain unclassified: %v %+v", err, result.Diagnostics)
	}
	count, auth, hostKeys := 0, false, false
	for _, entry := range result.Entries {
		p := entry.Component.CryptoProperties
		if p == nil {
			continue
		}
		count++
		if p.AssetType != cdx.CryptoAssetTypeProtocol || p.ProtocolProperties.Type != cdx.CryptoProtocolTypeSSH ||
			p.ProtocolProperties.Version != "" || p.ProtocolProperties.CipherSuites != nil || entry.Evidence.Kind != "configured" {
			t.Fatalf("source SSH use was mistaken for runtime evidence: %+v", entry)
		}
		if entry.Component.Properties != nil {
			for _, property := range *entry.Component.Properties {
				auth = auth || property.Name == "ciphertrail:ssh.auth-method" && property.Value == "public-key"
				hostKeys = hostKeys || property.Name == "ciphertrail:ssh.host-key-verification" && property.Value == "disabled"
				if property.Name == "ciphertrail:scope" && strings.HasPrefix(property.Value, "source API use;") {
					t.Fatal("generic source-analysis caveat was duplicated on the SSH finding")
				}
			}
		}
	}
	if count != 6 || !auth || !hostKeys {
		t.Fatalf("incorrect SSH configuration inventory: count=%d auth=%v hostKeys=%v", count, auth, hostKeys)
	}
	if _, err := cyclonedx.Encode([]inventory.Collection{{Result: result}}); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownCryptoOperationsStillProduceDiagnostics(t *testing.T) {
	directory := fixture(t, `package example
import ("crypto"; "crypto/x509"; "crypto/tls"; "golang.org/x/crypto/ssh")
func Run(signer crypto.Signer, certificate *x509.Certificate, key ssh.PublicKey, scheme tls.SignatureScheme) {
 _, _ = signer.Sign(nil, nil, crypto.SHA256)
 _ = certificate.CheckSignature(x509.SHA256WithRSA, nil, nil)
 _ = key.Verify(nil, nil)
 _ = scheme.String()
}`)
	result, err := (Source{Path: directory}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, symbol := range []string{"crypto.Signer).Sign", "x509.Certificate).CheckSignature", "ssh.PublicKey).Verify", "tls.SignatureScheme).String"} {
		found := false
		for _, diagnostic := range result.Diagnostics {
			if strings.Contains(diagnostic.Message, symbol) {
				found = diagnostic.Location == "main.go" && diagnostic.Line > 0
			}
		}
		if !found {
			t.Errorf("unknown API %s was masked or lost its location", symbol)
		}
	}
}

func TestExplicitExclusionsSkipHelpersFilesAndNestedModules(t *testing.T) {
	directory := fixture(t, `package example
import "crypto/sha256"
func Run() { _ = sha256.Sum256(nil) }
`)
	files := map[string]string{
		".ciphertrailignore":             "# Deliberate source scope\ninternal/testutil/\nfixtures/nested/\n",
		"internal/testutil/crypto.go":    "package testutil\nfunc Broken() { undefined() }\n",
		"fixtures/nested/go.mod":         "not a valid module\n",
		"fixtures/nested/main.go":        "not valid Go\n",
		"fixtures.go":                    "package example\nimport (\"crypto/tls\"; \"crypto/x509\")\nfunc Fixtures() { _, _ = x509.ParseCertificate(nil); _ = &tls.Config{} }\n",
		"production/testutil/hash.go":    "package testutil\nimport \"crypto/sha512\"\nfunc Run() { _ = sha512.Sum512(nil) }\n",
		"internal/testutilities/hash.go": "package testutilities\nimport \"crypto/sha1\"\nfunc Run() { _ = sha1.Sum(nil) }\n",
	}
	for name, content := range files {
		path := filepath.Join(directory, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	result, err := (Source{Path: directory, Exclude: []string{"fixtures.go"}}).Collect(context.Background())
	if err != nil || len(result.Diagnostics) != 0 {
		t.Fatalf("excluded sources were analyzed: %v %+v", err, result.Diagnostics)
	}
	names := map[string]bool{}
	for _, entry := range result.Entries {
		if entry.Component.CryptoProperties == nil {
			continue
		}
		location := entry.Evidence.Location
		if strings.HasPrefix(location, "internal/testutil/") || strings.HasPrefix(location, "fixtures/") || location == "fixtures.go" {
			t.Fatalf("excluded finding leaked: %+v", entry.Evidence)
		}
		names[entry.Component.Name] = true
	}
	if !names["SHA-256"] || !names["SHA-512"] || !names["SHA-1"] || len(names) != 3 {
		t.Fatalf("production evidence lost or fixture retained: %v", names)
	}
	recorded := false
	for _, detail := range result.Details {
		recorded = recorded || detail.Name == "source-exclusion-paths"
	}
	if !recorded {
		t.Fatal("missing exclusion provenance in run details")
	}
}

func TestExcludingRequiredHelperDoesNotHideCompilationErrors(t *testing.T) {
	directory := fixture(t, `package example
import "example.test/fixture/internal/testutil"
func Run() { testutil.Broken() }
`)
	path := filepath.Join(directory, "internal", "testutil")
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "helper.go"), []byte("package testutil\nfunc Broken() { undefined() }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := (Source{Path: directory, Exclude: []string{"internal/testutil"}}).Collect(context.Background())
	if err == nil {
		t.Fatal("required code's compilation failure was hidden by source exclusion")
	}
}

func TestTestutilNameAloneDoesNotExcludeProductionCode(t *testing.T) {
	directory := fixture(t, `package example
import "example.test/fixture/internal/testutil"
func Run() { testutil.Hash() }
`)
	path := filepath.Join(directory, "internal", "testutil")
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "hash.go"), []byte("package testutil\nimport \"crypto/sha512\"\nfunc Hash() { _ = sha512.Sum512(nil) }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := (Source{Path: directory}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range result.Entries {
		found = found || entry.Component.Name == "SHA-512" && entry.Evidence.Location == "internal/testutil/hash.go"
	}
	if !found {
		t.Fatal("a production-used helper was hidden based on its directory name")
	}
}

func TestKeySerializationValidationAndCertificateEquality(t *testing.T) {
	directory := fixture(t, `package example
import ("crypto/rsa"; "crypto/x509"; "golang.org/x/crypto/ssh")
func Run(private *rsa.PrivateKey, public ssh.PublicKey, a,b *x509.Certificate) {
 _ = private.Validate()
 _ = ssh.MarshalAuthorizedKey(public)
 _ = a.Equal(b)
}`)
	result, err := (Source{Path: directory}).Collect(context.Background())
	if err != nil || len(result.Diagnostics) != 0 {
		t.Fatalf("new API cases remain gaps: %v %+v", err, result.Diagnostics)
	}
	var private, public int
	for _, entry := range result.Entries {
		properties := entry.Component.CryptoProperties
		if properties == nil {
			continue
		}
		if properties.AssetType != cdx.CryptoAssetTypeRelatedCryptoMaterial || properties.RelatedCryptoMaterialProperties == nil {
			t.Fatalf("key operation was misclassified: %+v", entry)
		}
		key := properties.RelatedCryptoMaterialProperties
		if key.Type == cdx.RelatedCryptoMaterialTypePrivateKey {
			private++
		}
		if key.Type == cdx.RelatedCryptoMaterialTypePublicKey {
			public++
		}
		if key.Value != "" || key.Size != nil || entry.Evidence.Kind != "configured" {
			t.Fatal("key operation invented material or runtime evidence")
		}
	}
	if private != 1 || public != 1 {
		t.Fatalf("incorrect key inventory or spurious equality finding: private=%d public=%d", private, public)
	}
	if nonAssetAPI(apiIdentity{"crypto/rsa", "PrivateKey", "Validate"}) ||
		nonAssetAPI(apiIdentity{"crypto/x509", "Certificate", "Verify"}) {
		t.Fatal("validation or signature verification was suppressed as metadata")
	}
	if _, err := cyclonedx.Encode([]inventory.Collection{{Result: result}}); err != nil {
		t.Fatal(err)
	}
}

func TestCurveConstructorsAndMethodExpressions(t *testing.T) {
	directory := fixture(t, `package example
import ("context"; "crypto"; "crypto/ecdh"; "crypto/elliptic"; "crypto/tls")
type Private = ecdh.PrivateKey
type TLSConn = tls.Conn
func Run(private *Private, connection *TLSConn, decrypter crypto.Decrypter) {
 _ = elliptic.P224()
 _ = elliptic.P384()
 _ = elliptic.P521()
 _ = (*Private).PublicKey(private)
 _ = (*TLSConn).HandshakeContext(connection, context.Background())
 _ = connection.Handshake()
 _ = decrypter.Public()
}`)
	result, err := (Source{Path: directory}).Collect(context.Background())
	if err != nil || len(result.Diagnostics) != 0 {
		t.Fatalf("scan failed or misclassified methods: %v %+v", err, result.Diagnostics)
	}
	curves, keys, handshakes := map[string]bool{}, 0, 0
	for _, entry := range result.Entries {
		p := entry.Component.CryptoProperties
		if p == nil {
			continue
		}
		if p.AlgorithmProperties != nil {
			curves[p.AlgorithmProperties.EllipticCurve] = true
		}
		if p.RelatedCryptoMaterialProperties != nil && p.RelatedCryptoMaterialProperties.Type == cdx.RelatedCryptoMaterialTypePublicKey {
			keys++
		}
		if p.ProtocolProperties != nil && p.ProtocolProperties.Type == cdx.CryptoProtocolTypeTLS {
			handshakes++
		}
	}
	if !curves["nist/P-224"] || !curves["nist/P-384"] || !curves["nist/P-521"] || len(curves) != 3 || keys != 2 || handshakes != 2 {
		t.Fatalf("wrong curve/key/protocol evidence: %v keys=%d handshakes=%d", curves, keys, handshakes)
	}
}

func TestNonAssetClassificationRequiresExactIdentity(t *testing.T) {
	for _, api := range []apiIdentity{
		{"example.test/fixture", "Curve", "Params"},
		{"example.test/fixture", "Conn", "Close"},
		{"crypto/tls", "SignatureScheme", "String"},
		{"golang.org/x/crypto/ssh", "Channel", "SendRequest"},
		{"crypto/x509", "CertPool", "AppendCertsFromPEM"},
		{"crypto/tls", "Conn", "HandshakeContext"},
		{"crypto", "Signer", "Sign"},
	} {
		if nonAssetAPI(api) {
			t.Errorf("overbroad non-asset classification: %+v", api)
		}
	}
}
