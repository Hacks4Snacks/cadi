package pyscan

import (
	"context"
	"slices"
	"strings"
	"testing"

	"ciphertrail/internal/export/cyclonedx"
	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestPythonModelFamiliesAndPublicParameters(t *testing.T) {
	selection := fixture(t, map[string]string{"app.py": `
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, x25519, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Cryptodome.PublicKey import RSA, ECC
from Cryptodome.Hash import SHA256

hashlib.pbkdf2_hmac("sha256", b"PRIVATE_PASSWORD", b"PRIVATE_SALT", 600000, dklen=32)
hashlib.new("shake_128", b"PRIVATE_PAYLOAD")
hashes.Hash(hashes.SHAKE128(16))
key = rsa.generate_private_key(65537, 2048 + 2048)
signature = key.sign(b"PRIVATE_PAYLOAD", padding.PKCS1v15(), hashes.SHA256())
key.public_key().verify(signature, b"PRIVATE_PAYLOAD", padding.PKCS1v15(), hashes.SHA256())
ec.generate_private_key(ec.SECP256R1())
edkey = ed25519.Ed25519PrivateKey.generate()
edkey.sign(b"PRIVATE_PAYLOAD")
x25519.X25519PrivateKey.generate()
Cipher(algorithms.AES(b"x" * 32), modes.CBC(b"y" * 16)).encryptor()
AESGCM(AESGCM.generate_key(bit_length=256)).encrypt(b"z" * 12, b"PRIVATE_PAYLOAD", None)
PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b"PRIVATE_SALT", iterations=100000)
RSA.generate(bits=3072)
ECC.generate(curve="P-384")
SHA256.new(b"PRIVATE_PAYLOAD")
`})
	result, err := (Source{Selection: selection}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]bool{
		"hashlib.pbkdf2_hmac":                                    false,
		primitives + "asymmetric.rsa.RSAPublicKey.verify":        false,
		primitives + "asymmetric.ed25519.Ed25519PrivateKey.sign": false,
		primitives + "ciphers.Cipher.encryptor":                  false,
		primitives + "ciphers.aead.AESGCM.encrypt":               false,
		primitives + "kdf.pbkdf2.PBKDF2HMAC":                     false,
		"Cryptodome.PublicKey.RSA.generate":                      false,
		"Cryptodome.PublicKey.ECC.generate":                      false,
	}
	for _, entry := range result.Entries {
		if strings.HasPrefix(entry.Component.Name, "SHAKE") &&
			entry.Component.CryptoProperties.AlgorithmProperties.Primitive != cdx.CryptoPrimitiveXOF {
			t.Fatal("SHAKE was classified as a fixed-output hash")
		}
		if _, exists := expected[entry.Evidence.Symbol]; !exists || entry.Component.Type != cdx.ComponentTypeCryptographicAsset {
			continue
		}
		expected[entry.Evidence.Symbol] = true
		switch entry.Evidence.Symbol {
		case "hashlib.pbkdf2_hmac", primitives + "kdf.pbkdf2.PBKDF2HMAC":
			if property(entry, "derived-key-size-bits") != "256" {
				t.Fatalf("derived length is not in bits: %+v", entry)
			}
		case primitives + "ciphers.Cipher.encryptor":
			a := entry.Component.CryptoProperties.AlgorithmProperties
			if entry.Component.Name != "AES-CBC" || a.ParameterSetIdentifier != "256" ||
				a.CryptoFunctions == nil || !slices.Contains(*a.CryptoFunctions, cdx.CryptoFunctionEncrypt) {
				t.Fatalf("cipher receiver configuration was lost: %+v", entry)
			}
		case primitives + "asymmetric.rsa.RSAPublicKey.verify":
			if property(entry, "signature.hash") != "SHA-256" {
				t.Fatal("signature digest was not resolved")
			}
		}
	}
	for symbol, found := range expected {
		if !found {
			t.Errorf("missing model: %s", symbol)
		}
	}
	data, err := cyclonedx.Encode([]inventory.Collection{{Collector: "python", Result: result}})
	if err != nil || strings.Contains(string(data), "PRIVATE_") {
		t.Fatalf("model output failed schema or exposed private data: %v", err)
	}
}

func TestPythonTLSIsConfigurationNotNegotiation(t *testing.T) {
	selection := fixture(t, map[string]string{"tls_config.py": `
import ssl
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.check_hostname = False
context.verify_mode = ssl.CERT_REQUIRED
context.set_ciphers("ECDHE+AESGCM:!aNULL")
context.load_cert_chain("/nonexistent/cert.pem", "/nonexistent/key.pem", password="PRIVATE_PASSWORD")
context.load_verify_locations(cadata="PRIVATE_CERT_DATA")
context.wrap_socket(unknown_socket)
`})
	result, err := (Source{Selection: selection}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, entry := range result.Entries {
		if entry.Component.CryptoProperties == nil {
			if entry.Component.Version != "" {
				t.Fatal("parser version was assigned to an unverified provider")
			}
			continue
		}
		protocol := entry.Component.CryptoProperties.ProtocolProperties
		if protocol == nil || protocol.Version != "" || protocol.CipherSuites != nil {
			t.Fatal("configured settings became negotiated protocol facts")
		}
		if entry.Component.Properties != nil {
			for _, property := range *entry.Component.Properties {
				values[strings.TrimPrefix(property.Name, "ciphertrail:")] = property.Value
			}
		}
	}
	for key, want := range map[string]string{
		"tls.min-version": "1.2", "tls.max-version": "1.3", "tls.check-hostname": "false",
		"tls.verify-mode": "CERT_REQUIRED", "tls.openssl-cipher-selector": "ECDHE+AESGCM:!aNULL",
		"tls.certificate-file": "/nonexistent/cert.pem", "tls.private-key-file": "/nonexistent/key.pem",
	} {
		if values[key] != want {
			t.Errorf("%s = %q; want %q", key, values[key], want)
		}
	}
	data, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
	if err != nil || strings.Contains(string(data), "PRIVATE_") {
		t.Fatalf("TLS configuration exposed inline data or failed schema: %v", err)
	}
}

func TestPythonCertificateEncodingHelpersAreNotAlgorithms(t *testing.T) {
	selection := fixture(t, map[string]string{"encoding.py": `
import ssl
ssl.PEM_cert_to_DER_cert("PRIVATE_CERTIFICATE")
ssl.DER_cert_to_PEM_cert(b"PRIVATE_CERTIFICATE")
`})
	result, err := (Source{Selection: selection}).Collect(context.Background())
	if err != nil || len(result.Diagnostics) != 0 {
		t.Fatalf("format-only helpers were reported as missing crypto models: %v %v", result.Diagnostics, err)
	}
	for _, entry := range result.Entries {
		if entry.Component.CryptoProperties != nil {
			t.Fatal("certificate re-encoding was treated as a cryptographic operation")
		}
	}
}

func TestPythonCertificateBuilderAndKeyImports(t *testing.T) {
	selection := fixture(t, map[string]string{"certificates.py": `
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
certificate = (x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(public)
    .serial_number(1234)
    .not_valid_before(start)
    .not_valid_after(end)
    .add_extension(extension, critical=True)
    .sign(private_key, hashes.SHA256()))
x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, None)
serialization.load_pem_private_key(b"PRIVATE_KEY", password=b"PRIVATE_PASSWORD")
x509.load_pem_x509_certificate(b"PRIVATE_CERTIFICATE")
`})
	result, err := (Source{Selection: selection}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, entry := range result.Entries {
		names[entry.Component.Name] = true
		if entry.Component.Name == "X.509 certificate signing" && property(entry, "signature.hash") != "SHA-256" {
			t.Fatal("certificate signing hash was lost through the builder chain")
		}
	}
	for _, name := range []string{"X.509 certificate signing", "X.509 certificate request signing", "Key import", "X.509 certificate import"} {
		if !names[name] {
			t.Errorf("missing %s", name)
		}
	}
	data, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
	if err != nil || strings.Contains(string(data), "PRIVATE_") {
		t.Fatalf("certificate/key handling exposed material or failed schema: %v", err)
	}
}
