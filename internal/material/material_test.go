package material

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"testing"

	"ciphertrail/internal/export/cyclonedx"
	"ciphertrail/internal/inventory"
	"ciphertrail/internal/testutil"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"golang.org/x/crypto/ssh"
)

func TestParseCertificateAndPrivateKeyWithoutSecrets(t *testing.T) {
	_, _, cert, key := testutil.Identity(t)
	input := append(bytes.Clone(cert), key...)
	result, recognized, err := Parse(input, inventory.Evidence{Kind: "present", Location: "identity.pem"}, "")
	if err != nil || !recognized {
		t.Fatalf("recognized=%v, err=%v", recognized, err)
	}
	data, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("BEGIN PRIVATE KEY")) || bytes.Contains(data, key[35:75]) {
		t.Fatal("private key bytes leaked")
	}
	if bytes.Contains(data, []byte("ciphertrail:certificate-serial-number")) {
		t.Fatal("legacy serial-number workaround still emitted")
	}
	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatal(err)
	}
	var certificateFound, privateKeyFound bool
	for _, component := range *bom.Components {
		if p := component.CryptoProperties; p != nil {
			if certificate := p.CertificateProperties; certificate != nil {
				certificateFound = certificate.SerialNumber == "42" && certificate.SubjectPublicKeyRef == "" &&
					certificate.SignatureAlgorithmRef == "" && certificate.RelatedCryptographicAssets != nil &&
					len(*certificate.RelatedCryptographicAssets) == 2
			}
			if algorithm := p.AlgorithmProperties; algorithm != nil && component.Name == "ECDSA" {
				if algorithm.Curve != "" || algorithm.EllipticCurve != "nist/P-256" {
					t.Fatal("canonical 1.7 curve metadata was not emitted")
				}
			}
			if key := p.RelatedCryptoMaterialProperties; key != nil && key.Type == "private-key" {
				privateKeyFound = key.Size != nil && *key.Size == 256 && key.Value == "" && key.AlgorithmRef == "" &&
					key.RelatedCryptographicAssets != nil && len(*key.RelatedCryptographicAssets) == 1
			}
		}
	}
	if !certificateFound || !privateKeyFound {
		t.Fatal("missing certificate or key parameters")
	}
}

func TestSkippedMalformedPEMPrefixIsReported(t *testing.T) {
	_, _, certificate, _ := testutil.Identity(t)
	input := append([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n"), certificate...)
	if _, _, err := Parse(input, inventory.Evidence{}, ""); err == nil {
		t.Fatal("decoder skipped a malformed PEM prefix")
	}
}

func TestEncryptedKeysRetainDistinctLocations(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("PRIVATE_SENTINEL")})
	result, recognized, err := Parse(append(bytes.Clone(block), block...), inventory.Evidence{Kind: "present", Location: "keys.pem"}, "")
	if err != nil || !recognized || len(result.Entries) != 2 {
		t.Fatalf("encrypted keys were not recorded: %v", err)
	}
	if result.Entries[0].Component.BOMRef == result.Entries[1].Component.BOMRef {
		t.Fatal("distinct unknown keys were collapsed")
	}
	for _, entry := range result.Entries {
		if len(entry.Evidence.Unresolved) != 2 {
			t.Fatal("unavailable encrypted-key parameters lost their unresolved summary")
		}
	}
	if len(result.Diagnostics) != 2 {
		t.Fatal("no-decryption limitations were dropped")
	}
	data, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
	if err != nil || bytes.Contains(data, []byte("PRIVATE_SENTINEL")) {
		t.Fatalf("invalid or unsafe encrypted-key output: %v", err)
	}
}

func TestSSHAuthorizedKeysWithComments(t *testing.T) {
	identity, _, _, _ := testutil.Identity(t)
	signer, err := ssh.NewSignerFromKey(identity.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	input := append([]byte("# PRIVATE_SENTINEL\n\n"), ssh.MarshalAuthorizedKey(signer.PublicKey())...)
	result, recognized, err := Parse(input, inventory.Evidence{Kind: "present", Location: "authorized_keys"}, "")
	if err != nil || !recognized || len(result.Entries) == 0 {
		t.Fatalf("SSH key was missed after comments: %v", err)
	}
	data, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
	if err != nil || bytes.Contains(data, []byte("PRIVATE_SENTINEL")) {
		t.Fatal("SSH comment leaked")
	}
}

func TestMalformedPEMIsAnError(t *testing.T) {
	_, recognized, err := Parse([]byte("-----BEGIN CERTIFICATE-----\ninvalid"), inventory.Evidence{}, "")
	if !recognized || err == nil {
		t.Fatal("malformed PEM must not be silently ignored")
	}
}
