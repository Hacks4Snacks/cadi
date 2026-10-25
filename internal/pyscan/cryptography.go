package pyscan

import (
	"strings"

	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

const primitives = "cryptography.hazmat.primitives."

var curves = map[string]string{
	"SECP224R1": "P-224", "SECP256R1": "P-256", "SECP384R1": "P-384", "SECP521R1": "P-521",
}

var aeadNames = map[string]string{
	"AESGCM": "AES-GCM", "AESCCM": "AES-CCM", "AESOCB3": "AES-OCB",
	"AESSIV": "AES-SIV", "AESGCMSIV": "AES-GCM-SIV", "ChaCha20Poly1305": "ChaCha20-Poly1305",
}

func cryptographyCall(name string, call value, evidence *inventory.Evidence) (cdx.Component, bool) {
	short := strings.TrimPrefix(name, primitives)
	if strings.HasPrefix(short, "hashes.") {
		hash := hashName(strings.TrimPrefix(short, "hashes."))
		if hash != "" {
			primitive := cdx.CryptoPrimitiveHash
			if strings.HasPrefix(hash, "SHAKE") {
				primitive = cdx.CryptoPrimitiveXOF
			}
			component := algorithm(hash, primitive, "")
			if supplied(call, 0, "digest_size") {
				byteCountParameter(&component, evidence, "digest-size-bits", argument(call, 0, "digest_size"))
			}
			return component, true
		}
		if short == "hashes.Hash" {
			hash = digest(argument(call, 0, "algorithm"))
			if hash == "" {
				hash = "Hash configuration"
				evidence.Unresolved = append(evidence.Unresolved, "algorithm")
			}
			primitive := cdx.CryptoPrimitiveHash
			if strings.HasPrefix(hash, "SHAKE") {
				primitive = cdx.CryptoPrimitiveXOF
			}
			return algorithm(hash, primitive, ""), true
		}
	}
	if strings.HasPrefix(short, "asymmetric.") {
		return asymmetricCall(short, call, evidence)
	}
	if strings.HasPrefix(short, "kdf.") {
		return kdfCall(short, call, evidence)
	}
	if strings.HasPrefix(short, "ciphers.aead.") {
		class, method, _ := strings.Cut(strings.TrimPrefix(short, "ciphers.aead."), ".")
		label, known := aeadNames[class]
		if !known || method != "" && method != "generate_key" && method != "encrypt" && method != "decrypt" {
			return cdx.Component{}, false
		}
		component := algorithm(label, cdx.CryptoPrimitiveAE, operation(method))
		switch class {
		case "AESGCM":
			component.CryptoProperties.AlgorithmProperties.Mode = cdx.CryptoAlgorithmModeGCM
		case "AESCCM":
			component.CryptoProperties.AlgorithmProperties.Mode = cdx.CryptoAlgorithmModeCCM
		}
		switch method {
		case "generate_key":
			if class == "ChaCha20Poly1305" {
				parameter(&component, evidence, "key-size-bits", value{Kind: "int", Integer: 256}, false)
			} else {
				parameter(&component, evidence, "key-size-bits", argument(call, 0, "bit_length"), false)
			}
		case "":
			parameter(&component, evidence, "key-size-bits", argument(call, 0, "key"), true)
		default:
			parameter(&component, evidence, "key-size-bits", argument(receiver(call), 0, "key"), true)
		}
		return component, true
	}
	if strings.HasPrefix(short, "ciphers.algorithms.") {
		class := strings.TrimPrefix(short, "ciphers.algorithms.")
		primitive := cdx.CryptoPrimitiveBlockCipher
		label := class
		switch class {
		case "AES", "AES128", "AES256":
			label = "AES"
		case "TripleDES":
			label = "3DES"
		case "ChaCha20", "ARC4":
			primitive = cdx.CryptoPrimitiveStreamCipher
		case "Camellia", "Blowfish", "CAST5", "IDEA", "SEED", "SM4":
		default:
			return cdx.Component{}, false
		}
		component := algorithm(label, primitive, "")
		parameter(&component, evidence, "key-size-bits", argument(call, 0, "key"), true)
		return component, true
	}
	if strings.HasPrefix(short, "ciphers.modes.") {
		mode := strings.TrimPrefix(short, "ciphers.modes.")
		component, known := blockMode("Block cipher", mode)
		if known && mode != "ECB" {
			parameter(&component, evidence, "iv-size-bits", argument(call, 0, "initialization_vector"), true)
		}
		return component, known
	}
	if short == "ciphers.Cipher.encryptor" || short == "ciphers.Cipher.decryptor" {
		component := algorithm("Cipher operation", cdx.CryptoPrimitiveOther, operation(strings.TrimSuffix(strings.TrimPrefix(short, "ciphers.Cipher."), "or")))
		constructor := receiver(call)
		alg := argument(constructor, 0, "algorithm")
		if alg.Kind == "call" {
			if inner, known := cryptographyCall(symbol(alg.Base), alg, evidence); known {
				component = inner
				component.CryptoProperties.AlgorithmProperties.CryptoFunctions = &[]cdx.CryptoFunction{operation(strings.TrimSuffix(strings.TrimPrefix(short, "ciphers.Cipher."), "or"))}
			}
		}
		mode := argument(constructor, 1, "mode")
		if mode.Kind == "call" {
			class := strings.TrimPrefix(symbol(mode.Base), primitives+"ciphers.modes.")
			if merged, known := blockMode(component.Name, class); known {
				component.Name = merged.Name
				component.CryptoProperties.AlgorithmProperties.Mode = merged.CryptoProperties.AlgorithmProperties.Mode
				component.CryptoProperties.AlgorithmProperties.Primitive = merged.CryptoProperties.AlgorithmProperties.Primitive
			}
		}
		return component, true
	}
	if short == "hmac.HMAC" || short == "hmac.HMAC.verify" {
		constructor := call
		function := cdx.CryptoFunction("")
		if short == "hmac.HMAC.verify" {
			constructor, function = receiver(call), cdx.CryptoFunctionVerify
		}
		label := "HMAC"
		if hash := digest(argument(constructor, 1, "algorithm")); hash != "" {
			label += "-" + hash
		} else {
			evidence.Unresolved = append(evidence.Unresolved, "hash")
		}
		component := algorithm(label, cdx.CryptoPrimitiveMAC, function)
		parameter(&component, evidence, "key-size-bits", argument(constructor, 0, "key"), true)
		return component, true
	}
	if strings.HasPrefix(short, "serialization.") {
		method := strings.TrimPrefix(short, "serialization.")
		kind := cdx.RelatedCryptoMaterialTypePrivateKey
		switch method {
		case "load_pem_private_key", "load_der_private_key", "load_ssh_private_key":
		case "load_pem_public_key", "load_der_public_key", "load_ssh_public_key":
			kind = cdx.RelatedCryptoMaterialTypePublicKey
		default:
			return cdx.Component{}, false
		}
		return cdx.Component{Type: cdx.ComponentTypeCryptographicAsset, Name: "Key import",
			CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
				RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{Type: kind}}}, true
	}
	switch name {
	case "cryptography.x509.load_pem_x509_certificate", "cryptography.x509.load_der_x509_certificate",
		"cryptography.x509.load_pem_x509_csr", "cryptography.x509.load_der_x509_csr":
		label := "X.509 certificate import"
		if strings.HasSuffix(name, "_csr") {
			label = "X.509 certificate request import"
		}
		return inventory.ConfiguredCertificate(label, "", nil), true
	case "cryptography.x509.CertificateBuilder.sign", "cryptography.x509.CertificateSigningRequestBuilder.sign":
		label := "X.509 certificate signing"
		if strings.Contains(name, "CertificateSigningRequestBuilder") {
			label = "X.509 certificate request signing"
		}
		component := inventory.ConfiguredCertificate(label, "", nil)
		hash := argument(call, 1, "algorithm")
		if name := digest(hash); name != "" {
			inventory.Property(&component, "signature.hash", name)
		} else if hash.Kind != "none" {
			evidence.Unresolved = append(evidence.Unresolved, "signature.hash")
		}
		return component, true
	case "cryptography.fernet.Fernet", "cryptography.fernet.Fernet.generate_key",
		"cryptography.fernet.Fernet.encrypt", "cryptography.fernet.Fernet.decrypt":
		return algorithm("Fernet", cdx.CryptoPrimitiveCombiner, operation(strings.TrimPrefix(name, "cryptography.fernet.Fernet."))), true
	}
	return cdx.Component{}, false
}

func operation(method string) cdx.CryptoFunction {
	switch method {
	case "generate", "generate_key", "generate_private_key":
		return cdx.CryptoFunctionKeygen
	case "encrypt":
		return cdx.CryptoFunctionEncrypt
	case "decrypt":
		return cdx.CryptoFunctionDecrypt
	case "sign":
		return cdx.CryptoFunctionSign
	case "verify":
		return cdx.CryptoFunctionVerify
	}
	return ""
}

func receiver(call value) value {
	if call.Base != nil && call.Base.Kind == "attribute" && call.Base.Base != nil {
		return *call.Base.Base
	}
	return value{}
}

func blockMode(name, mode string) (cdx.Component, bool) {
	modes := map[string]cdx.CryptoAlgorithmMode{
		"ECB": cdx.CryptoAlgorithmModeECB, "CBC": cdx.CryptoAlgorithmModeCBC,
		"CFB": cdx.CryptoAlgorithmModeCFB, "OFB": cdx.CryptoAlgorithmModeOFB,
		"CTR": cdx.CryptoAlgorithmModeCTR, "GCM": cdx.CryptoAlgorithmModeGCM, "CCM": cdx.CryptoAlgorithmModeCCM,
	}
	resolved, known := modes[mode]
	if !known {
		return cdx.Component{}, false
	}
	primitive := cdx.CryptoPrimitiveBlockCipher
	if mode == "GCM" || mode == "CCM" {
		primitive = cdx.CryptoPrimitiveAE
	}
	component := algorithm(name+"-"+mode, primitive, "")
	component.CryptoProperties.AlgorithmProperties.Mode = resolved
	return component, true
}
