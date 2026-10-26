package inventory

import (
	"strconv"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Attribute is an explicitly resolved public configuration value.
type Attribute struct {
	Name, Value string
}

func attributes(component *cdx.Component, values []Attribute) {
	for _, value := range values {
		Property(component, value.Name, value.Value)
	}
}

// ConfigurationResource creates non-cryptographic ownership context for a resource.
func ConfigurationResource(resource ResourceIdentity) cdx.Component {
	name := resource.Name
	if resource.Namespace != "" {
		name = resource.Namespace + "/" + name
	}
	label := resource.Kind
	if name != "" {
		label += " " + name
	}
	return cdx.Component{Type: cdx.ComponentTypeData, Name: label}
}

// ConfiguredCertificate records an X.509 declaration or reference, not issued material.
func ConfiguredCertificate(name, keyRef string, values []Attribute) cdx.Component {
	component := cdx.Component{Type: cdx.ComponentTypeCryptographicAsset, Name: name,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:             cdx.CryptoAssetTypeCertificate,
			CertificateProperties: &cdx.CertificateProperties{CertificateFormat: "X.509"},
		}}
	if keyRef != "" {
		component.CryptoProperties.CertificateProperties.RelatedCryptographicAssets =
			&[]cdx.RelatedCryptographicAsset{{Type: "privateKey", Ref: keyRef}}
	}
	attributes(&component, values)
	return component
}

// ConfiguredKeyAlgorithm maps explicit certificate key settings without assuming defaults.
func ConfiguredKeyAlgorithm(name string, size int) (cdx.Component, bool) {
	var algorithm cdx.Component
	switch name {
	case "RSA":
		algorithm = Algorithm(name, cdx.CryptoPrimitivePKE)
	case "ECDSA":
		algorithm = Algorithm(name, cdx.CryptoPrimitiveSignature)
		algorithm.CryptoProperties.AlgorithmProperties.AlgorithmFamily = "ECDSA"
		if size == 256 || size == 384 || size == 521 {
			algorithm.CryptoProperties.AlgorithmProperties.EllipticCurve = CurveID("P-" + strconv.Itoa(size))
		}
	case "Ed25519":
		algorithm = Algorithm(name, cdx.CryptoPrimitiveSignature)
		algorithm.CryptoProperties.AlgorithmProperties.AlgorithmFamily = "EdDSA"
		algorithm.CryptoProperties.AlgorithmProperties.EllipticCurve = CurveID("Ed25519")
		algorithm.CryptoProperties.OID = OIDEd25519
		size = 0
	default:
		return cdx.Component{}, false
	}
	if size > 0 {
		algorithm.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = strconv.Itoa(size)
	}
	return algorithm, true
}

// AddConfiguredPrivateKey records requested key parameters without generating a key.
func (r *Result) AddConfiguredPrivateKey(name, algorithmName string, size int, values []Attribute, evidence Evidence, parent string) string {
	key := cdx.Component{Type: cdx.ComponentTypeCryptographicAsset, Name: name,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:                       cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{Type: cdx.RelatedCryptoMaterialTypePrivateKey},
		}}
	properties := key.CryptoProperties.RelatedCryptoMaterialProperties
	for _, value := range values {
		if value.Name == "cert-manager.key-encoding" {
			properties.Format = CertManagerKeyFormat(value.Value)
		}
	}
	if size > 0 && algorithmName != "Ed25519" {
		properties.Size = &size
	}
	if algorithm, known := ConfiguredKeyAlgorithm(algorithmName, size); known {
		algorithmRef := r.Add(algorithm, evidence, parent)
		properties.RelatedCryptographicAssets = &[]cdx.RelatedCryptographicAsset{{Type: "algorithm", Ref: algorithmRef}}
	}
	attributes(&key, values)
	return r.Add(key, evidence, parent)
}

// CertManagerKeyFormat records the PEM envelope promised by explicit supported
// encodings; the original PKCS1/PKCS8 container selection remains a separate fact.
func CertManagerKeyFormat(encoding string) string {
	switch encoding {
	case "PKCS1", "PKCS8":
		return "PEM"
	default:
		return ""
	}
}

// TLSConfiguration contains explicitly configured TLS references and cipher-suite names.
type TLSConfiguration struct {
	CertificateRefs []string
	CipherSuites    []string
}

// ConfiguredTLS records declared TLS use without negotiation claims or implicit versions.
func ConfiguredTLS(name string, configuration TLSConfiguration, values []Attribute) cdx.Component {
	component := cdx.Component{Type: cdx.ComponentTypeCryptographicAsset, Name: name,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:          cdx.CryptoAssetTypeProtocol,
			ProtocolProperties: &cdx.CryptoProtocolProperties{Type: cdx.CryptoProtocolTypeTLS},
		}}
	if len(configuration.CertificateRefs) != 0 {
		related := make([]cdx.RelatedCryptographicAsset, 0, len(configuration.CertificateRefs))
		for _, ref := range configuration.CertificateRefs {
			related = append(related, cdx.RelatedCryptographicAsset{Type: "certificate", Ref: ref})
		}
		component.CryptoProperties.ProtocolProperties.RelatedCryptographicAssets = &related
	}
	if len(configuration.CipherSuites) != 0 {
		suites := make([]cdx.CipherSuite, 0, len(configuration.CipherSuites))
		for _, name := range configuration.CipherSuites {
			suites = append(suites, cdx.CipherSuite{Name: name})
		}
		component.CryptoProperties.ProtocolProperties.CipherSuites = &suites
	}
	attributes(&component, values)
	return component
}

// ConfiguredEncryptionAlgorithm identifies an apiserver provider without inspecting key values.
func ConfiguredEncryptionAlgorithm(provider string, writes bool, values []Attribute) (cdx.Component, bool) {
	var algorithm cdx.Component
	switch provider {
	case "secretbox":
		algorithm = Algorithm("XSalsa20-Poly1305", cdx.CryptoPrimitiveAE)
		algorithm.CryptoProperties.AlgorithmProperties.AlgorithmFamily = "Salsa20"
	case "aesgcm":
		algorithm = Algorithm("AES-GCM", cdx.CryptoPrimitiveAE)
		algorithm.CryptoProperties.AlgorithmProperties.AlgorithmFamily = "AES"
		algorithm.CryptoProperties.AlgorithmProperties.Mode = cdx.CryptoAlgorithmModeGCM
	case "aescbc":
		algorithm = Algorithm("AES-CBC", cdx.CryptoPrimitiveBlockCipher)
		algorithm.CryptoProperties.AlgorithmProperties.AlgorithmFamily = "AES"
		algorithm.CryptoProperties.AlgorithmProperties.Mode = cdx.CryptoAlgorithmModeCBC
		algorithm.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS7
	default:
		return cdx.Component{}, false
	}
	functions := []cdx.CryptoFunction{cdx.CryptoFunctionDecrypt}
	if writes {
		functions = []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt}
	}
	algorithm.CryptoProperties.AlgorithmProperties.CryptoFunctions = &functions
	attributes(&algorithm, values)
	return algorithm, true
}

// EncryptionKeyReference records a declared symmetric key name without material or a private digest.
func EncryptionKeyReference(algorithmRef string, values []Attribute) cdx.Component {
	key := cdx.Component{Type: cdx.ComponentTypeCryptographicAsset, Name: "Kubernetes encryption key reference",
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type:                       cdx.RelatedCryptoMaterialTypeSecretKey,
				RelatedCryptographicAssets: &[]cdx.RelatedCryptographicAsset{{Type: "algorithm", Ref: algorithmRef}},
			},
		}}
	attributes(&key, values)
	return key
}
