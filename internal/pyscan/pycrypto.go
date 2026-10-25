package pyscan

import (
	"strings"

	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func pyCryptoCall(name string, call value, evidence *inventory.Evidence) (cdx.Component, bool) {
	root, short, _ := strings.Cut(name, ".")
	if strings.HasPrefix(short, "Hash.") && strings.HasSuffix(short, ".new") {
		class := strings.TrimSuffix(strings.TrimPrefix(short, "Hash."), ".new")
		if hash := hashName(class); hash != "" {
			primitive := cdx.CryptoPrimitiveHash
			if strings.HasPrefix(hash, "SHAKE") {
				primitive = cdx.CryptoPrimitiveXOF
			}
			return algorithm(hash, primitive, ""), true
		}
		if class == "HMAC" {
			label := "HMAC"
			if hash := digest(argument(call, 2, "digestmod")); hash != "" {
				label += "-" + hash
			} else {
				evidence.Unresolved = append(evidence.Unresolved, "hash")
			}
			component := algorithm(label, cdx.CryptoPrimitiveMAC, "")
			parameter(&component, evidence, "key-size-bits", argument(call, 0, "key"), true)
			return component, true
		}
	}
	switch short {
	case "Cipher.AES.new":
		modeValue := argument(call, 1, "mode")
		mode := strings.TrimPrefix(symbol(&modeValue), root+".Cipher.AES.MODE_")
		component, known := blockMode("AES", mode)
		if !known {
			component = algorithm("AES", cdx.CryptoPrimitiveBlockCipher, "")
			evidence.Unresolved = append(evidence.Unresolved, "mode")
		}
		parameter(&component, evidence, "key-size-bits", argument(call, 0, "key"), true)
		if supplied(call, -1, "nonce") {
			parameter(&component, evidence, "nonce-size-bits", argument(call, -1, "nonce"), true)
		}
		if supplied(call, -1, "iv") {
			parameter(&component, evidence, "iv-size-bits", argument(call, -1, "iv"), true)
		}
		return component, true
	case "Cipher.AES.encrypt", "Cipher.AES.encrypt_and_digest", "Cipher.AES.decrypt", "Cipher.AES.decrypt_and_verify":
		constructor := receiver(call)
		component, _ := pyCryptoCall(root+".Cipher.AES.new", constructor, evidence)
		function := cdx.CryptoFunctionEncrypt
		if strings.HasPrefix(strings.TrimPrefix(short, "Cipher.AES."), "decrypt") {
			function = cdx.CryptoFunctionDecrypt
		}
		component.CryptoProperties.AlgorithmProperties.CryptoFunctions = &[]cdx.CryptoFunction{function}
		return component, true
	case "PublicKey.RSA.generate":
		component := algorithm("RSA", cdx.CryptoPrimitivePKE, cdx.CryptoFunctionKeygen)
		parameter(&component, evidence, "key-size-bits", argument(call, 0, "bits"), false)
		if supplied(call, 2, "e") {
			parameter(&component, evidence, "public-exponent", argument(call, 2, "e"), false)
		}
		return component, true
	case "PublicKey.ECC.generate":
		component := algorithm("Elliptic-curve key", cdx.CryptoPrimitiveOther, cdx.CryptoFunctionKeygen)
		curve, known := literalText(argument(call, -1, "curve"))
		resolved := map[string]string{"P-224": "P-224", "P-256": "P-256", "P-384": "P-384", "P-521": "P-521",
			"Ed25519": "Ed25519", "Curve25519": "X25519"}[curve]
		if known && resolved != "" {
			component.CryptoProperties.AlgorithmProperties.EllipticCurve = inventory.CurveID(resolved)
		} else {
			evidence.Unresolved = append(evidence.Unresolved, "curve")
		}
		return component, true
	}
	return cdx.Component{}, false
}
