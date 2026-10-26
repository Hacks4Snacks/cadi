package pyscan

import (
	"strings"

	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func asymmetricCall(name string, call value, evidence *inventory.Evidence) (cdx.Component, bool) {
	short := strings.TrimPrefix(name, "asymmetric.")
	switch short {
	case "ec.ECDH":
		component := algorithm("ECDH", cdx.CryptoPrimitiveKeyAgree, "")
		component.CryptoProperties.AlgorithmProperties.AlgorithmFamily = "ECDH"
		return component, true
	case "x25519.X25519PrivateKey.exchange", "x448.X448PrivateKey.exchange":
		if len(receiver(call).Modified) != 0 {
			return cdx.Component{}, false
		}
		label, oid := "X25519", inventory.OIDX25519
		if short == "x448.X448PrivateKey.exchange" {
			label, oid = "X448", inventory.OIDX448
		}
		component := algorithm(label, cdx.CryptoPrimitiveKeyAgree, cdx.CryptoFunctionKeyderive)
		a := component.CryptoProperties.AlgorithmProperties
		a.AlgorithmFamily, a.EllipticCurve = "ECDH", inventory.CurveID(label)
		component.CryptoProperties.OID = oid
		return component, true
	case "ec.EllipticCurvePrivateKey.exchange":
		constructor := receiver(call)
		if len(constructor.Modified) != 0 {
			return cdx.Component{}, false
		}
		component := algorithm("Elliptic-curve key agreement", cdx.CryptoPrimitiveKeyAgree, cdx.CryptoFunctionKeyderive)
		selected := argument(call, 0, "algorithm")
		if selected.Kind == "call" && len(selected.Modified) == 0 &&
			symbol(selected.Base) == primitives+"asymmetric.ec.ECDH" {
			component.Name = "ECDH"
			component.CryptoProperties.AlgorithmProperties.AlgorithmFamily = "ECDH"
		} else {
			evidence.Unresolved = append(evidence.Unresolved, "algorithm")
		}
		var curve value
		switch symbol(constructor.Base) {
		case primitives + "asymmetric.ec.generate_private_key":
			curve = argument(constructor, 0, "curve")
		case primitives + "asymmetric.ec.derive_private_key":
			curve = argument(constructor, 1, "curve")
		}
		setCurve(&component, evidence, curve)
		return component, true
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
		family, curve, oid  string
	}{
		{"ed25519", "Ed25519PrivateKey", "Ed25519", cdx.CryptoPrimitiveSignature, "EdDSA", inventory.CurveID("Ed25519"), inventory.OIDEd25519},
		{"ed448", "Ed448PrivateKey", "Ed448", cdx.CryptoPrimitiveSignature, "EdDSA", inventory.CurveID("Ed448"), inventory.OIDEd448},
		{"x25519", "X25519PrivateKey", "X25519", cdx.CryptoPrimitiveKeyAgree, "ECDH", inventory.CurveID("X25519"), inventory.OIDX25519},
		{"x448", "X448PrivateKey", "X448", cdx.CryptoPrimitiveKeyAgree, "ECDH", inventory.CurveID("X448"), inventory.OIDX448},
	} {
		if short == key.module+"."+key.class+".generate" {
			component := algorithm(key.name, key.primitive, cdx.CryptoFunctionKeygen)
			component.CryptoProperties.AlgorithmProperties.EllipticCurve = key.curve
			component.CryptoProperties.AlgorithmProperties.AlgorithmFamily = key.family
			component.CryptoProperties.OID = key.oid
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
			switch key.label {
			case "RSA":
				rsaScheme(&component, call, method)
			case "ECDSA":
				component.CryptoProperties.AlgorithmProperties.AlgorithmFamily = "ECDSA"
			case "Ed25519", "Ed448":
				component.CryptoProperties.AlgorithmProperties.AlgorithmFamily = "EdDSA"
				component.CryptoProperties.AlgorithmProperties.EllipticCurve = inventory.CurveID(key.label)
				component.CryptoProperties.OID = inventory.OIDEd25519
				if key.label == "Ed448" {
					component.CryptoProperties.OID = inventory.OIDEd448
				}
			}
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

func rsaScheme(component *cdx.Component, call value, method string) {
	index := 1
	if method == "verify" {
		index = 2
	}
	padding := argument(call, index, "padding")
	if padding.Kind != "call" {
		return
	}
	a := component.CryptoProperties.AlgorithmProperties
	switch symbol(padding.Base) {
	case primitives + "asymmetric.padding.PKCS1v15":
		a.AlgorithmFamily, a.Padding = "RSASSA-PKCS1", cdx.CryptoPaddingPKCS1v15
		if a.Primitive == cdx.CryptoPrimitivePKE {
			a.AlgorithmFamily = "RSAES-PKCS1"
		}
	case primitives + "asymmetric.padding.PSS":
		if a.Primitive == cdx.CryptoPrimitiveSignature {
			a.AlgorithmFamily, component.CryptoProperties.OID = "RSASSA-PSS", inventory.OIDRSASSAPSS
		}
	case primitives + "asymmetric.padding.OAEP":
		if a.Primitive == cdx.CryptoPrimitivePKE {
			a.AlgorithmFamily, a.Padding = "RSAES-OAEP", cdx.CryptoPaddingOAEP
			component.CryptoProperties.OID = inventory.OIDRSAESOAEP
		}
	}
}

func setCurve(component *cdx.Component, evidence *inventory.Evidence, v value) {
	name := symbol(v.Base)
	if v.Kind == "call" && len(v.Modified) == 0 && strings.HasPrefix(name, primitives+"asymmetric.ec.") {
		if curve, known := curves[strings.TrimPrefix(name, primitives+"asymmetric.ec.")]; known {
			component.CryptoProperties.AlgorithmProperties.EllipticCurve = inventory.CurveID(curve)
			return
		}
	}
	evidence.Unresolved = append(evidence.Unresolved, "curve")
}
