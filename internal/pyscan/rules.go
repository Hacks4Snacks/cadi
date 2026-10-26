package pyscan

import (
	"fmt"
	"strings"

	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

var hashes = map[string]string{
	"md5": "MD5", "sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256",
	"sha384": "SHA-384", "sha512": "SHA-512", "sha512_224": "SHA-512/224", "sha512_256": "SHA-512/256",
	"sha3_224": "SHA3-224", "sha3_256": "SHA3-256", "sha3_384": "SHA3-384", "sha3_512": "SHA3-512",
	"shake_128": "SHAKE128", "shake_256": "SHAKE256", "blake2b": "BLAKE2b", "blake2s": "BLAKE2s",
}

func hashName(name string) string {
	name = strings.ToLower(strings.ReplaceAll(name, "-", ""))
	switch name {
	case "shake128":
		name = "shake_128"
	case "shake256":
		name = "shake_256"
	}
	return hashes[name]
}

var cryptoNamespaces = []string{
	"hashlib", "hmac", "ssl", "secrets", "cryptography", "Crypto", "Cryptodome",
	"OpenSSL", "jwt", "paramiko", "bcrypt", "argon2",
}

func cryptoNamespace(name string) bool {
	if name == "os.urandom" {
		return true
	}
	for _, root := range cryptoNamespaces {
		if name == root || strings.HasPrefix(name, root+".") {
			return true
		}
	}
	return false
}

func nonAsset(name string) bool {
	for _, class := range []string{"hashlib.Hash", "hmac.HMAC", "cryptography.hazmat.primitives.hashes.Hash",
		primitives + "hmac.HMAC", "cryptography.hazmat.primitives.ciphers.CipherContext"} {
		for _, method := range []string{"update", "digest", "hexdigest", "copy", "finalize"} {
			if name == class+"."+method {
				return true
			}
		}
	}
	for _, builder := range []string{"cryptography.x509.CertificateBuilder", "cryptography.x509.CertificateSigningRequestBuilder"} {
		if name == builder {
			return true
		}
		if strings.HasPrefix(name, builder+".") && builderMethod(builder, strings.TrimPrefix(name, builder+".")) {
			return true
		}
	}
	for private := range publicKeyTypes {
		if name == primitives+private+".public_key" {
			return true
		}
	}
	for _, root := range []string{"Crypto.Hash.", "Cryptodome.Hash."} {
		if strings.HasPrefix(name, root) {
			class, method, _ := strings.Cut(strings.TrimPrefix(name, root), ".")
			if hashName(class) != "" || class == "HMAC" {
				switch method {
				case "update", "digest", "hexdigest", "copy":
					return true
				}
			}
		}
	}
	switch name {
	case "hmac.compare_digest", "secrets.compare_digest", "cryptography.hazmat.primitives.constant_time.bytes_eq",
		"cryptography.hazmat.primitives.ciphers.Cipher", "ssl.SSLContext.load_default_certs",
		"ssl.SSLContext.get_ciphers", "ssl.PEM_cert_to_DER_cert", "ssl.DER_cert_to_PEM_cert",
		primitives + "cmac.CMAC.update", primitives + "cmac.CMAC.copy",
		"bcrypt.gensalt", "argon2.PasswordHasher.check_needs_rehash":
		return true
	}
	return false
}

func parameter(component *cdx.Component, evidence *inventory.Evidence, name string, argument value, bytes bool) {
	number, known := integer(argument)
	if bytes {
		number, known = length(argument)
		known = known && argument.Kind != "sequence" && number <= maxSourceBytes
		number *= 8
	}
	if !known {
		evidence.Unresolved = append(evidence.Unresolved, name)
		return
	}
	if a := component.CryptoProperties.AlgorithmProperties; a != nil && number > 0 {
		if name == "key-size-bits" || name == "digest-size-bits" && a.AlgorithmFamily == "BLAKE2" {
			a.ParameterSetIdentifier = fmt.Sprint(number)
			return
		}
	}
	inventory.Property(component, name, fmt.Sprint(number))
}

func byteCountParameter(component *cdx.Component, evidence *inventory.Evidence, name string, argument value) {
	count, known := integer(argument)
	converted := value{}
	if known && count >= 0 && count <= maxSourceBytes {
		converted = value{Kind: "int", Integer: count * 8}
	}
	parameter(component, evidence, name, converted, false)
}

func algorithm(name string, primitive cdx.CryptoPrimitive, function cdx.CryptoFunction) cdx.Component {
	component := inventory.Algorithm(name, primitive)
	if function != "" {
		component.CryptoProperties.AlgorithmProperties.CryptoFunctions = &[]cdx.CryptoFunction{function}
	}
	return component
}

func digest(v value) string {
	if text, known := literalText(v); known {
		return hashName(text)
	}
	name := symbol(&v)
	if v.Kind == "call" {
		name = symbol(v.Base)
	}
	if strings.HasPrefix(name, "hashlib.") {
		return hashName(strings.TrimPrefix(name, "hashlib."))
	}
	if strings.HasPrefix(name, "cryptography.hazmat.primitives.hashes.") {
		return hashName(strings.TrimPrefix(name, "cryptography.hazmat.primitives.hashes."))
	}
	for _, root := range []string{"Crypto.Hash.", "Cryptodome.Hash."} {
		if strings.HasPrefix(name, root) {
			return hashName(strings.TrimSuffix(strings.TrimPrefix(name, root), ".new"))
		}
	}
	return ""
}

func recognize(name string, call value, evidence *inventory.Evidence) (cdx.Component, bool) {
	if strings.HasPrefix(name, "hashlib.") {
		method := strings.TrimPrefix(name, "hashlib.")
		if hash := hashName(method); hash != "" {
			component, known := inventory.HashAlgorithm(hash)
			if known && component.CryptoProperties.AlgorithmProperties.AlgorithmFamily == "BLAKE2" && supplied(call, -1, "digest_size") {
				byteCountParameter(&component, evidence, "digest-size-bits", argument(call, -1, "digest_size"))
			}
			return component, known
		}
		switch method {
		case "new":
			hash := digest(argument(call, 0, "name"))
			if hash == "" {
				evidence.Unresolved = append(evidence.Unresolved, "algorithm")
				return algorithm("Hash configuration", cdx.CryptoPrimitiveHash, cdx.CryptoFunctionDigest), true
			}
			component, known := inventory.HashAlgorithm(hash)
			if known && component.CryptoProperties.AlgorithmProperties.AlgorithmFamily == "BLAKE2" && supplied(call, -1, "digest_size") {
				byteCountParameter(&component, evidence, "digest-size-bits", argument(call, -1, "digest_size"))
			}
			return component, known
		case "pbkdf2_hmac":
			component := algorithm("PBKDF2", cdx.CryptoPrimitiveKDF, cdx.CryptoFunctionKeyderive)
			component.CryptoProperties.AlgorithmProperties.AlgorithmFamily = "PBKDF2"
			if hash := digest(argument(call, 0, "hash_name")); hash != "" {
				inventory.Property(&component, "hash", hash)
			} else {
				evidence.Unresolved = append(evidence.Unresolved, "hash")
			}
			parameter(&component, evidence, "iterations", argument(call, 3, "iterations"), false)
			byteCountParameter(&component, evidence, "derived-key-size-bits", argument(call, 4, "dklen"))
			return component, true
		case "scrypt":
			component := algorithm("scrypt", cdx.CryptoPrimitiveKDF, cdx.CryptoFunctionKeyderive)
			for _, field := range []string{"n", "r", "p"} {
				parameter(&component, evidence, field, argument(call, -1, field), false)
			}
			return component, true
		}
	}
	switch name {
	case "hmac.new", "hmac.HMAC", "hmac.digest":
		digestParameter := "digestmod"
		if name == "hmac.digest" {
			digestParameter = "digest"
		}
		hash := digest(argument(call, 2, digestParameter))
		if hash == "" {
			evidence.Unresolved = append(evidence.Unresolved, "hash")
		}
		component := inventory.HMACAlgorithm(hash)
		parameter(&component, evidence, "key-size-bits", argument(call, 0, "key"), true)
		return component, true
	case "os.urandom", "secrets.token_bytes", "secrets.token_hex", "secrets.token_urlsafe", "ssl.RAND_bytes",
		"Crypto.Random.get_random_bytes", "Cryptodome.Random.get_random_bytes":
		component := algorithm("Cryptographic random generation", cdx.CryptoPrimitiveOther, cdx.CryptoFunctionGenerate)
		parameter(&component, evidence, "random-bytes", argument(call, 0, "nbytes"), false)
		return component, true
	case "secrets.randbelow", "secrets.randbits", "secrets.choice":
		return algorithm("Cryptographic random generation", cdx.CryptoPrimitiveOther, cdx.CryptoFunctionGenerate), true
	}
	if strings.HasPrefix(name, "ssl.") {
		return sslCall(name, call, evidence)
	}
	if strings.HasPrefix(name, "bcrypt.") || strings.HasPrefix(name, "argon2.") {
		return passwordCall(name, call, evidence)
	}
	if strings.HasPrefix(name, "cryptography.") {
		return cryptographyCall(name, call, evidence)
	}
	if strings.HasPrefix(name, "Crypto.") || strings.HasPrefix(name, "Cryptodome.") {
		return pyCryptoCall(name, call, evidence)
	}
	return cdx.Component{}, false
}
