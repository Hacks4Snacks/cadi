package pyscan

import (
	"strings"

	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func asymmetricCall(name string, call value, evidence *inventory.Evidence) (cdx.Component, bool) {
	short := strings.TrimPrefix(name, "asymmetric.")
	switch short {
	case "rsa.generate_private_key":
		component := algorithm("RSA", cdx.CryptoPrimitivePKE, cdx.CryptoFunctionKeygen)
		parameter(&component, evidence, "key-size-bits", argument(call, 1, "key_size"), false)
		parameter(&component, evidence, "public-exponent", argument(call, 0, "public_exponent"), false)
		return component, true
	case "ec.generate_private_key", "ec.derive_private_key":
		index := 0
		function := cdx.CryptoFunctionKeygen
		if short == "ec.derive_private_key" {
			index, function = 1, cdx.CryptoFunctionKeyderive
		}
		component := algorithm("Elliptic-curve key", cdx.CryptoPrimitiveOther, function)
		setCurve(&component, evidence, argument(call, index, "curve"))
		return component, true
	}
	if strings.HasPrefix(short, "ec.") {
		if curve, known := curves[strings.TrimPrefix(short, "ec.")]; known {
			component := algorithm("Elliptic curve "+curve, cdx.CryptoPrimitiveOther, "")
			component.CryptoProperties.AlgorithmProperties.EllipticCurve = inventory.CurveID(curve)
			return component, true
		}
	}
	for _, key := range []struct {
		module, class, name string
		primitive           cdx.CryptoPrimitive
		curve               string
	}{
		{"ed25519", "Ed25519PrivateKey", "Ed25519", cdx.CryptoPrimitiveSignature, inventory.CurveID("Ed25519")},
		{"ed448", "Ed448PrivateKey", "Ed448", cdx.CryptoPrimitiveSignature, ""},
		{"x25519", "X25519PrivateKey", "X25519", cdx.CryptoPrimitiveKeyAgree, inventory.CurveID("X25519")},
		{"x448", "X448PrivateKey", "X448", cdx.CryptoPrimitiveKeyAgree, ""},
	} {
		if short == key.module+"."+key.class+".generate" {
			component := algorithm(key.name, key.primitive, cdx.CryptoFunctionKeygen)
			component.CryptoProperties.AlgorithmProperties.EllipticCurve = key.curve
			return component, true
		}
	}
	for _, key := range []struct {
		class, label string
	}{
		{"rsa.RSAPrivateKey", "RSA"}, {"rsa.RSAPublicKey", "RSA"},
		{"ec.EllipticCurvePrivateKey", "ECDSA"}, {"ec.EllipticCurvePublicKey", "ECDSA"},
		{"ed25519.Ed25519PrivateKey", "Ed25519"}, {"ed25519.Ed25519PublicKey", "Ed25519"},
		{"ed448.Ed448PrivateKey", "Ed448"}, {"ed448.Ed448PublicKey", "Ed448"},
	} {
		for _, method := range []string{"sign", "verify", "encrypt", "decrypt"} {
			if short != key.class+"."+method {
				continue
			}
			private := strings.HasSuffix(key.class, "PrivateKey")
			if private && (method == "verify" || method == "encrypt") || !private && (method == "sign" || method == "decrypt") {
				continue
			}
			primitive := cdx.CryptoPrimitiveSignature
			if method == "encrypt" || method == "decrypt" {
				if key.label != "RSA" {
					return cdx.Component{}, false
				}
				primitive = cdx.CryptoPrimitivePKE
			}
			component := algorithm(key.label, primitive, operation(method))
			if key.label == "RSA" && (method == "sign" || method == "verify") {
				index := 2
				if method == "verify" {
					index = 3
				}
				if hash := digest(argument(call, index, "algorithm")); hash != "" {
					inventory.Property(&component, "signature.hash", hash)
				} else {
					evidence.Unresolved = append(evidence.Unresolved, "signature.hash")
				}
			}
			return component, true
		}
	}
	return cdx.Component{}, false
}

func setCurve(component *cdx.Component, evidence *inventory.Evidence, v value) {
	name := symbol(v.Base)
	if v.Kind == "call" && strings.HasPrefix(name, primitives+"asymmetric.ec.") {
		if curve, known := curves[strings.TrimPrefix(name, primitives+"asymmetric.ec.")]; known {
			component.CryptoProperties.AlgorithmProperties.EllipticCurve = inventory.CurveID(curve)
			return
		}
	}
	evidence.Unresolved = append(evidence.Unresolved, "curve")
}
