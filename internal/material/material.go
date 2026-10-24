// Package material extracts public cryptographic metadata without exporting key values.
package material

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"

	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"golang.org/x/crypto/ssh"
)

// AddKey records public parameters and a fingerprint derived only from the public key.
func AddKey(result *inventory.Result, key any, evidence inventory.Evidence, parent string) (string, error) {
	kind := cdx.RelatedCryptoMaterialTypePublicKey
	switch private := key.(type) {
	case crypto.Signer:
		kind, key = cdx.RelatedCryptoMaterialTypePrivateKey, private.Public()
	case *ecdh.PrivateKey:
		kind, key = cdx.RelatedCryptoMaterialTypePrivateKey, private.PublicKey()
	case *dsa.PrivateKey:
		kind, key = cdx.RelatedCryptoMaterialTypePrivateKey, &private.PublicKey
	}
	var name, curve string
	var bits int
	primitive := cdx.CryptoPrimitiveSignature
	switch public := key.(type) {
	case *rsa.PublicKey:
		name, bits, primitive = "RSA", public.N.BitLen(), cdx.CryptoPrimitivePKE
	case *ecdsa.PublicKey:
		name, curve, bits = "ECDSA", public.Curve.Params().Name, public.Curve.Params().BitSize
	case ed25519.PublicKey:
		name, curve, bits = "Ed25519", "Ed25519", 256
	case *dsa.PublicKey:
		name, bits = "DSA", public.P.BitLen()
	case *ecdh.PublicKey:
		name, primitive = "ECDH", cdx.CryptoPrimitiveKeyAgree
		switch public.Curve() {
		case ecdh.P256():
			curve, bits = "P-256", 256
		case ecdh.P384():
			curve, bits = "P-384", 384
		case ecdh.P521():
			curve, bits = "P-521", 521
		case ecdh.X25519():
			curve, bits = "X25519", 256
		default:
			return "", fmt.Errorf("unsupported ECDH curve")
		}
	default:
		return "", fmt.Errorf("unsupported public key type %T", key)
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("encode public-key identity: %w", err)
	}
	fingerprint := digest(der)
	algorithm := inventory.Algorithm(name, primitive)
	algorithm.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = fmt.Sprint(bits)
	algorithm.CryptoProperties.AlgorithmProperties.EllipticCurve = inventory.CurveID(curve)
	algorithm.BOMRef = inventory.Ref("algorithm", name, fmt.Sprint(bits), curve)
	algorithmRef := result.Add(algorithm, evidence, parent)
	component := cdx.Component{
		BOMRef: inventory.Ref("key", string(kind), fingerprint), Type: "cryptographic-asset",
		Name: name + " " + string(kind),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type: kind, ID: "sha256:" + fingerprint, Size: &bits,
				RelatedCryptographicAssets: &[]cdx.RelatedCryptographicAsset{{Type: "algorithm", Ref: algorithmRef}},
			},
		},
	}
	inventory.Property(&component, "fingerprint-basis", "public-key-SPKI-SHA256")
	return result.Add(component, evidence, parent), nil
}

// AddCertificate records certificate identity, validity dates, and public-key relationships.
func AddCertificate(result *inventory.Result, certificate *x509.Certificate, evidence inventory.Evidence, parent string) (string, error) {
	keyRef, err := AddKey(result, certificate.PublicKey, evidence, parent)
	if err != nil {
		return "", err
	}
	signature := inventory.Algorithm(certificate.SignatureAlgorithm.String(), cdx.CryptoPrimitiveSignature)
	signature.BOMRef = inventory.Ref("certificate-signature", signature.Name)
	signatureRef := result.Add(signature, evidence, parent)
	fingerprint := digest(certificate.Raw)
	component := cdx.Component{
		BOMRef: inventory.Ref("certificate", fingerprint), Type: "cryptographic-asset",
		Name:   "X.509 certificate " + fingerprint[:16],
		Hashes: &[]cdx.Hash{{Algorithm: "SHA-256", Value: fingerprint}},
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeCertificate,
			CertificateProperties: &cdx.CertificateProperties{
				SerialNumber: certificate.SerialNumber.String(),
				SubjectName:  certificate.Subject.String(), IssuerName: certificate.Issuer.String(),
				NotValidBefore:    certificate.NotBefore.UTC().Format(time.RFC3339),
				NotValidAfter:     certificate.NotAfter.UTC().Format(time.RFC3339),
				CertificateFormat: "X.509",
				RelatedCryptographicAssets: &[]cdx.RelatedCryptographicAsset{
					{Type: "publicKey", Ref: keyRef},
					{Type: "signatureAlgorithm", Ref: signatureRef},
				},
			},
		},
	}
	return result.Add(component, evidence, parent), nil
}

// AddSSHKey records host/authorized-key metadata without treating key format as a signature algorithm.
func AddSSHKey(result *inventory.Result, key ssh.PublicKey, evidence inventory.Evidence, parent string) (string, error) {
	wireType := key.Type()
	if certificate, ok := key.(*ssh.Certificate); ok {
		key = certificate.Key
		result.Diagnostics = append(result.Diagnostics, inventory.Diagnostic{
			Location: evidence.Location, Message: "SSH certificate subject key inventoried; certificate extensions and signer are not analyzed",
		})
	}
	public, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		return "", fmt.Errorf("unsupported SSH public key format %s", wireType)
	}
	ref, err := AddKey(result, public.CryptoPublicKey(), evidence, parent)
	if err != nil {
		return "", err
	}
	inventory.Property(&result.Entries[len(result.Entries)-1].Component, "ssh-key-format", wireType)
	inventory.Property(&result.Entries[len(result.Entries)-1].Component, "ssh-fingerprint", ssh.FingerprintSHA256(key))
	return ref, nil
}

func digest(data []byte) string {
	value := sha256.Sum256(data)
	return hex.EncodeToString(value[:])
}
