package pyscan

import (
	"strings"

	"cadi/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func pyCryptoCall(name string, call value, evidence *inventory.Evidence) (cdx.Component, bool) {
	root, short, _ := strings.Cut(name, ".")
	if strings.HasPrefix(short, "Hash.") && strings.HasSuffix(short, ".new") {
		class := strings.TrimSuffix(strings.TrimPrefix(short, "Hash."), ".new")
		if hash := hashName(class); hash != "" {
			component, known := inventory.HashAlgorithm(hash)
			if known && component.CryptoProperties.AlgorithmProperties.AlgorithmFamily == "BLAKE2" {
				bytes, bits := supplied(call, -1, "digest_bytes"), supplied(call, -1, "digest_bits")
				switch {
				case bytes && bits:
					evidence.Unresolved = append(evidence.Unresolved, "digest-size-bits")
				case bytes:
					byteCountParameter(&component, evidence, "digest-size-bits", argument(call, -1, "digest_bytes"))
				case bits:
					parameter(&component, evidence, "digest-size-bits", argument(call, -1, "digest_bits"), false)
				}
			}
			return component, known
		}
		if class == "HMAC" {
			hash := digest(argument(call, 2, "digestmod"))
			if hash == "" {
				evidence.Unresolved = append(evidence.Unresolved, "hash")
			}
			component := inventory.HMACAlgorithm(hash)
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
		a := component.CryptoProperties.AlgorithmProperties
		a.AlgorithmFamily = "AES"
		parameter(&component, evidence, "key-size-bits", argument(call, 0, "key"), true)
		component.CryptoProperties.OID = inventory.AESOID(a.Mode, a.ParameterSetIdentifier)
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
