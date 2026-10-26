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

	"cadi/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"golang.org/x/crypto/ssh"
)

// AddKey records public parameters, the known source format (empty when unknown),
// and a fingerprint derived only from the public key.
func AddKey(result *inventory.Result, key any, evidence inventory.Evidence, parent, format string) (string, error) {
	kind := cdx.RelatedCryptoMaterialTypePublicKey
	switch private := key.(type) {
	case crypto.Signer:
		kind, key = cdx.RelatedCryptoMaterialTypePrivateKey, private.Public()
	case *ecdh.PrivateKey:
		kind, key = cdx.RelatedCryptoMaterialTypePrivateKey, private.PublicKey()
	case *dsa.PrivateKey:
		kind, key = cdx.RelatedCryptoMaterialTypePrivateKey, &private.PublicKey
	}
	var name, curve, family, oid string
	var bits int
	primitive := cdx.CryptoPrimitiveSignature
	switch public := key.(type) {
	case *rsa.PublicKey:
		name, bits, primitive = "RSA", public.N.BitLen(), cdx.CryptoPrimitivePKE
	case *ecdsa.PublicKey:
		name, curve, bits = "ECDSA", public.Curve.Params().Name, public.Curve.Params().BitSize
		family = "ECDSA"
	case ed25519.PublicKey:
		name, curve, bits = "Ed25519", "Ed25519", 256
		family, oid = "EdDSA", inventory.OIDEd25519
	case *dsa.PublicKey:
		name, bits = "DSA", public.P.BitLen()
		family = "DSA"
	case *ecdh.PublicKey:
		name, primitive = "ECDH", cdx.CryptoPrimitiveKeyAgree
		family = "ECDH"
		switch public.Curve() {
		case ecdh.P256():
			curve, bits = "P-256", 256
		case ecdh.P384():
			curve, bits = "P-384", 384
		case ecdh.P521():
			curve, bits = "P-521", 521
		case ecdh.X25519():
			curve, bits = "X25519", 256
			oid = inventory.OIDX25519
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
	algorithm.CryptoProperties.AlgorithmProperties.AlgorithmFamily = family
	algorithm.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = fmt.Sprint(bits)
	algorithm.CryptoProperties.AlgorithmProperties.EllipticCurve = inventory.CurveID(curve)
	algorithm.CryptoProperties.OID = oid
	algorithm.BOMRef = inventory.Ref("algorithm", name, fmt.Sprint(bits), curve)
	algorithmRef := result.Add(algorithm, evidence, parent)
	component := cdx.Component{
		BOMRef: inventory.Ref("key", string(kind), fingerprint), Type: "cryptographic-asset",
		Name: name + " " + string(kind),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type: kind, ID: "sha256:" + fingerprint, Size: &bits, Format: format,
				RelatedCryptographicAssets: &[]cdx.RelatedCryptographicAsset{{Type: "algorithm", Ref: algorithmRef}},
			},
		},
	}
	inventory.Property(&component, "fingerprint-basis", "public-key-SPKI-SHA256")
	return result.Add(component, evidence, parent), nil
}

// AddCertificate records certificate identity, validity dates, and public-key relationships.
func AddCertificate(result *inventory.Result, certificate *x509.Certificate, evidence inventory.Evidence, parent string) (string, error) {
	keyFormat := ""
	if len(certificate.RawSubjectPublicKeyInfo) > 0 {
		keyFormat = "DER"
	}
	keyRef, err := AddKey(result, certificate.PublicKey, evidence, parent, keyFormat)
	if err != nil {
		return "", err
	}
	signature := signatureAlgorithm(certificate.SignatureAlgorithm)
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

var signatureAlgorithms = map[x509.SignatureAlgorithm]struct {
	family, oid string
	padding     cdx.CryptoPadding
}{
	x509.MD5WithRSA:       {"RSASSA-PKCS1", "1.2.840.113549.1.1.4", cdx.CryptoPaddingPKCS1v15},
	x509.SHA1WithRSA:      {"RSASSA-PKCS1", "1.2.840.113549.1.1.5", cdx.CryptoPaddingPKCS1v15},
	x509.SHA256WithRSA:    {"RSASSA-PKCS1", "1.2.840.113549.1.1.11", cdx.CryptoPaddingPKCS1v15},
	x509.SHA384WithRSA:    {"RSASSA-PKCS1", "1.2.840.113549.1.1.12", cdx.CryptoPaddingPKCS1v15},
	x509.SHA512WithRSA:    {"RSASSA-PKCS1", "1.2.840.113549.1.1.13", cdx.CryptoPaddingPKCS1v15},
	x509.SHA256WithRSAPSS: {"RSASSA-PSS", inventory.OIDRSASSAPSS, ""},
	x509.SHA384WithRSAPSS: {"RSASSA-PSS", inventory.OIDRSASSAPSS, ""},
	x509.SHA512WithRSAPSS: {"RSASSA-PSS", inventory.OIDRSASSAPSS, ""},
	x509.DSAWithSHA1:      {"DSA", "1.2.840.10040.4.3", ""},
	x509.DSAWithSHA256:    {"DSA", "2.16.840.1.101.3.4.3.2", ""},
	x509.ECDSAWithSHA1:    {"ECDSA", "1.2.840.10045.4.1", ""},
	x509.ECDSAWithSHA256:  {"ECDSA", "1.2.840.10045.4.3.2", ""},
	x509.ECDSAWithSHA384:  {"ECDSA", "1.2.840.10045.4.3.3", ""},
	x509.ECDSAWithSHA512:  {"ECDSA", "1.2.840.10045.4.3.4", ""},
	x509.PureEd25519:      {"EdDSA", inventory.OIDEd25519, ""},
}

func signatureAlgorithm(identity x509.SignatureAlgorithm) cdx.Component {
	component := inventory.Algorithm(identity.String(), cdx.CryptoPrimitiveSignature)
	if facts, known := signatureAlgorithms[identity]; known {
		a := component.CryptoProperties.AlgorithmProperties
		a.AlgorithmFamily, a.Padding = facts.family, facts.padding
		a.CryptoFunctions = &[]cdx.CryptoFunction{cdx.CryptoFunctionSign}
		component.CryptoProperties.OID = facts.oid
		if identity == x509.PureEd25519 {
			a.EllipticCurve = inventory.CurveID("Ed25519")
		}
	}
	return component
}

// AddSSHKey records host/authorized-key metadata without treating key format as a signature algorithm.
func AddSSHKey(result *inventory.Result, key ssh.PublicKey, evidence inventory.Evidence, parent, format string) (string, error) {
	wireType := key.Type()
	if certificate, ok := key.(*ssh.Certificate); ok {
		key = certificate.Key
		format = "SSH"
		result.Diagnostics = append(result.Diagnostics, inventory.Diagnostic{
			Location: evidence.Location, Message: "SSH certificate subject key inventoried; certificate extensions and signer are not analyzed",
		})
	}
	public, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		return "", fmt.Errorf("unsupported SSH public key format %s", wireType)
	}
	ref, err := AddKey(result, public.CryptoPublicKey(), evidence, parent, format)
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
