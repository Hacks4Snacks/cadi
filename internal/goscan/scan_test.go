package goscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	data, err := inventory.Encode([]inventory.Collection{{Result: result}})
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
	if _, encodeErr := inventory.Encode([]inventory.Collection{{Result: result, Err: err}}); encodeErr != nil {
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
	count, scope := 0, false
	for _, entry := range result.Entries {
		if entry.Component.CryptoProperties != nil {
			count++
		}
		if entry.Component.Properties != nil {
			for _, property := range *entry.Component.Properties {
				scope = scope || property.Name == "ciphertrail:analysis-scope" && strings.Contains(property.Value, "not runtime execution")
			}
		}
	}
	if count != len(tests) {
		t.Fatalf("non-asset helpers created cryptographic assets: got %d, want %d", count, len(tests))
	}
	if !scope {
		t.Fatal("static analysis scope was discarded rather than retained as metadata")
	}
	data, err := inventory.Encode([]inventory.Collection{{Collector: "go", Result: result}})
	if err != nil || inventory.Validate(data) != nil {
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
		if properties["ciphertrail:cert-manager.duration"] != "720h0m0s" ||
			properties["ciphertrail:cert-manager.renew-before"] != "240h0m0s" ||
			properties["ciphertrail:cert-manager.issuer.name"] != "unknown" ||
			properties["ciphertrail:cert-manager.issuer.kind"] != "Issuer" ||
			!strings.Contains(properties["ciphertrail:cert-manager.usages"], "server auth") {
			t.Fatalf("incorrect or guessed declaration settings: %v", properties)
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
	if _, err := inventory.Encode([]inventory.Collection{{Result: result}}); err != nil {
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
	data, err := inventory.Encode([]inventory.Collection{{Result: result}})
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
	if _, err := inventory.Encode([]inventory.Collection{{Result: result}}); err != nil {
		t.Fatal(err)
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
			}
		}
	}
	if count != 6 || !auth || !hostKeys {
		t.Fatalf("incorrect SSH configuration inventory: count=%d auth=%v hostKeys=%v", count, auth, hostKeys)
	}
	if _, err := inventory.Encode([]inventory.Collection{{Result: result}}); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownCryptoOperationsStillProduceDiagnostics(t *testing.T) {
	directory := fixture(t, `package example
import ("crypto"; "crypto/x509"; "crypto/tls"; "golang.org/x/crypto/ssh")
func Run(signer crypto.Signer, certificate *x509.Certificate, key ssh.PublicKey, group tls.CurveID) {
 _, _ = signer.Sign(nil, nil, crypto.SHA256)
 _, _ = certificate.Verify(x509.VerifyOptions{})
 _ = key.Verify(nil, nil)
 _ = group.String()
}`)
	result, err := (Source{Path: directory}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, symbol := range []string{"crypto.Signer).Sign", "x509.Certificate).Verify", "ssh.PublicKey).Verify", "tls.CurveID).String"} {
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
	data, err := inventory.Encode([]inventory.Collection{{Result: result}})
	if err != nil || !strings.Contains(string(data), "ciphertrail:source-exclusion-paths") {
		t.Fatalf("missing exclusion provenance: %v", err)
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
	if _, err := inventory.Encode([]inventory.Collection{{Result: result}}); err != nil {
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
		{"crypto/tls", "CurveID", "String"},
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
