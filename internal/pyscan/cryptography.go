package pyscan

import (
	"strings"

	"cadi/internal/inventory"

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
			component, known := inventory.HashAlgorithm(hash)
			if !known {
				return component, false
			}
			if supplied(call, 0, "digest_size") {
				byteCountParameter(&component, evidence, "digest-size-bits", argument(call, 0, "digest_size"))
			}
			return component, true
		}
		if short == "hashes.Hash" {
			hash = digest(argument(call, 0, "algorithm"))
			if hash == "" {
				evidence.Unresolved = append(evidence.Unresolved, "algorithm")
				return algorithm("Hash configuration", cdx.CryptoPrimitiveHash, cdx.CryptoFunctionDigest), true
			}
			return inventory.HashAlgorithm(hash)
		}
	}
	if strings.HasPrefix(short, "asymmetric.") {
		return asymmetricCall(short, call, evidence)
	}
	if strings.HasPrefix(short, "kdf.") {
		return kdfCall(short, call, evidence)
	}
	if strings.HasPrefix(short, "keywrap.") {
		return keyWrapCall(short, call, evidence)
	}
	if short == "cmac.CMAC" || short == "cmac.CMAC.finalize" || short == "cmac.CMAC.verify" {
		return cmacCall(short, call, evidence)
	}
	if strings.HasPrefix(short, "ciphers.aead.") {
		class, method, _ := strings.Cut(strings.TrimPrefix(short, "ciphers.aead."), ".")
		label, known := aeadNames[class]
		if !known || method != "" && method != "generate_key" && method != "encrypt" && method != "decrypt" {
			return cdx.Component{}, false
		}
		component := algorithm(label, cdx.CryptoPrimitiveAE, operation(method))
		a := component.CryptoProperties.AlgorithmProperties
		a.AlgorithmFamily = "AES"
		if class == "ChaCha20Poly1305" {
			a.AlgorithmFamily = "ChaCha20"
		}
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
		if a.AlgorithmFamily == "AES" {
			component.CryptoProperties.OID = inventory.AESOID(a.Mode, a.ParameterSetIdentifier)
		}
		return component, true
	}
	if strings.HasPrefix(short, "ciphers.algorithms.") {
		class := strings.TrimPrefix(short, "ciphers.algorithms.")
		primitive := cdx.CryptoPrimitiveBlockCipher
		label, family := class, class
		switch class {
		case "AES", "AES128", "AES256":
			label, family = "AES", "AES"
		case "TripleDES":
			label, family = "3DES", "3DES"
		case "ChaCha20":
			primitive = cdx.CryptoPrimitiveStreamCipher
		case "ARC4":
			primitive, family = cdx.CryptoPrimitiveStreamCipher, "RC4"
		case "Camellia":
			family = "CAMELLIA"
		case "Blowfish", "CAST5", "IDEA", "SEED":
		case "SM4":
			family = ""
		default:
			return cdx.Component{}, false
		}
		component := algorithm(label, primitive, "")
		component.CryptoProperties.AlgorithmProperties.AlgorithmFamily = family
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
		if alg.Kind == "call" && strings.HasPrefix(symbol(alg.Base), primitives+"ciphers.algorithms.") {
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
		a := component.CryptoProperties.AlgorithmProperties
		if a.AlgorithmFamily == "AES" {
			component.CryptoProperties.OID = inventory.AESOID(a.Mode, a.ParameterSetIdentifier)
		}
		return component, true
	}
	if short == "hmac.HMAC" || short == "hmac.HMAC.verify" {
		constructor := call
		function := cdx.CryptoFunction("")
		if short == "hmac.HMAC.verify" {
			constructor, function = receiver(call), cdx.CryptoFunctionVerify
		}
		hash := digest(argument(constructor, 1, "algorithm"))
		if hash == "" {
			evidence.Unresolved = append(evidence.Unresolved, "hash")
		}
		component := inventory.HMACAlgorithm(hash)
		if function != "" {
			component.CryptoProperties.AlgorithmProperties.CryptoFunctions = &[]cdx.CryptoFunction{function}
		}
		parameter(&component, evidence, "key-size-bits", argument(constructor, 0, "key"), true)
		return component, true
	}
	if strings.HasPrefix(short, "serialization.") {
		method := strings.TrimPrefix(short, "serialization.")
		kind := cdx.RelatedCryptoMaterialTypePrivateKey
		format := ""
		switch method {
		case "load_pem_private_key", "load_ssh_private_key":
			format = "PEM"
		case "load_der_private_key":
			format = "DER"
		case "load_pem_public_key":
			kind, format = cdx.RelatedCryptoMaterialTypePublicKey, "PEM"
		case "load_der_public_key":
			kind, format = cdx.RelatedCryptoMaterialTypePublicKey, "DER"
		case "load_ssh_public_key":
			kind, format = cdx.RelatedCryptoMaterialTypePublicKey, "OpenSSH"
		default:
			return cdx.Component{}, false
		}
		return cdx.Component{Type: cdx.ComponentTypeCryptographicAsset, Name: "Key import",
			CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
				RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{Type: kind, Format: format}}}, true
	}
	switch name {
	case "cryptography.x509.load_pem_x509_certificate", "cryptography.x509.load_der_x509_certificate":
		return inventory.ConfiguredCertificate("X.509 certificate import", "", nil), true
	case "cryptography.x509.load_pem_x509_csr", "cryptography.x509.load_der_x509_csr":
		format := "PEM"
		if name == "cryptography.x509.load_der_x509_csr" {
			format = "DER"
		}
		return certificateRequest("X.509 certificate request import", format), true
	case "cryptography.x509.CertificateBuilder.sign", "cryptography.x509.CertificateSigningRequestBuilder.sign":
		component := inventory.ConfiguredCertificate("X.509 certificate signing", "", nil)
		if name == "cryptography.x509.CertificateSigningRequestBuilder.sign" {
			component = certificateRequest("X.509 certificate request signing", "")
		}
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

func keyWrapCall(name string, call value, evidence *inventory.Evidence) (cdx.Component, bool) {
	padded := false
	function := cdx.CryptoFunctionEncrypt
	switch name {
	case "keywrap.aes_key_wrap":
	case "keywrap.aes_key_unwrap":
		function = cdx.CryptoFunctionDecrypt
	case "keywrap.aes_key_wrap_with_padding":
		padded = true
	case "keywrap.aes_key_unwrap_with_padding":
		padded, function = true, cdx.CryptoFunctionDecrypt
	default:
		return cdx.Component{}, false
	}
	label := "AES-KW"
	if padded {
		label = "AES-KWP"
	}
	component := algorithm(label, cdx.CryptoPrimitiveKeyWrap, function)
	a := component.CryptoProperties.AlgorithmProperties
	a.AlgorithmFamily = "AES"
	parameter(&component, evidence, "key-size-bits", argument(call, 0, "wrapping_key"), true)
	// RFC 5649 section 5 assigns distinct identifiers to KW and KWP.
	oids := map[bool]map[string]string{
		false: {"128": "2.16.840.1.101.3.4.1.5", "192": "2.16.840.1.101.3.4.1.25", "256": "2.16.840.1.101.3.4.1.45"},
		true:  {"128": "2.16.840.1.101.3.4.1.8", "192": "2.16.840.1.101.3.4.1.28", "256": "2.16.840.1.101.3.4.1.48"},
	}
	component.CryptoProperties.OID = oids[padded][a.ParameterSetIdentifier]
	return component, true
}

func cmacCall(name string, call value, evidence *inventory.Evidence) (cdx.Component, bool) {
	constructor := call
	function := cdx.CryptoFunctionTag
	if name != "cmac.CMAC" {
		constructor = receiver(call)
	}
	if name == "cmac.CMAC.verify" {
		function = cdx.CryptoFunctionVerify
	}
	for depth := 0; depth < 16 && symbol(constructor.Base) == primitives+"cmac.CMAC.copy"; depth++ {
		if len(constructor.Modified) != 0 {
			return cdx.Component{}, false
		}
		constructor = receiver(constructor)
	}
	if len(constructor.Modified) != 0 {
		return cdx.Component{}, false
	}
	component := algorithm("CMAC", cdx.CryptoPrimitiveMAC, function)
	a := component.CryptoProperties.AlgorithmProperties
	a.AlgorithmFamily = "CMAC"
	cipher := argument(constructor, 0, "algorithm")
	if cipher.Kind == "call" && len(cipher.Modified) == 0 &&
		strings.HasPrefix(symbol(cipher.Base), primitives+"ciphers.algorithms.") {
		if inner, known := cryptographyCall(symbol(cipher.Base), cipher, evidence); known &&
			inner.CryptoProperties.AlgorithmProperties.Primitive == cdx.CryptoPrimitiveBlockCipher {
			component.Name = inner.Name + "-CMAC"
			a.ParameterSetIdentifier = inner.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier
			return component, true
		}
	}
	evidence.Unresolved = append(evidence.Unresolved, "underlying-algorithm", "key-size-bits")
	return component, true
}

func certificateRequest(name, format string) cdx.Component {
	return cdx.Component{Type: cdx.ComponentTypeCryptographicAsset, Name: name,
		CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{Type: cdx.RelatedCryptoMaterialTypeOther, Format: format}}}
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
