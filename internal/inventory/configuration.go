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
	component := cdx.Component{Type: cdx.ComponentTypeData, Name: resource.Kind + " " + name}
	Property(&component, "resource.api-version", resource.APIVersion)
	Property(&component, "resource.kind", resource.Kind)
	if resource.Namespace != "" {
		Property(&component, "resource.namespace", resource.Namespace)
	}
	return component
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
		if size == 256 || size == 384 || size == 521 {
			algorithm.CryptoProperties.AlgorithmProperties.EllipticCurve = CurveID("P-" + strconv.Itoa(size))
		}
	case "Ed25519":
		algorithm = Algorithm(name, cdx.CryptoPrimitiveSignature)
		algorithm.CryptoProperties.AlgorithmProperties.EllipticCurve = CurveID("Ed25519")
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

// ConfiguredTLS records declared TLS use and certificate references without negotiation claims.
func ConfiguredTLS(name string, certificateRefs []string, values []Attribute) cdx.Component {
	component := cdx.Component{Type: cdx.ComponentTypeCryptographicAsset, Name: name,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:          cdx.CryptoAssetTypeProtocol,
			ProtocolProperties: &cdx.CryptoProtocolProperties{Type: cdx.CryptoProtocolTypeTLS},
		}}
	if len(certificateRefs) != 0 {
		related := make([]cdx.RelatedCryptographicAsset, 0, len(certificateRefs))
		for _, ref := range certificateRefs {
			related = append(related, cdx.RelatedCryptographicAsset{Type: "certificate", Ref: ref})
		}
		component.CryptoProperties.ProtocolProperties.RelatedCryptographicAssets = &related
	}
	attributes(&component, values)
	return component
}
