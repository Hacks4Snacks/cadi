package pyscan

import (
	"math"
	"strings"
)

var publicKeyTypes = map[string]string{
	"asymmetric.rsa.RSAPrivateKey":          "asymmetric.rsa.RSAPublicKey",
	"asymmetric.ec.EllipticCurvePrivateKey": "asymmetric.ec.EllipticCurvePublicKey",
	"asymmetric.ed25519.Ed25519PrivateKey":  "asymmetric.ed25519.Ed25519PublicKey",
	"asymmetric.ed448.Ed448PrivateKey":      "asymmetric.ed448.Ed448PublicKey",
	"asymmetric.x25519.X25519PrivateKey":    "asymmetric.x25519.X25519PublicKey",
	"asymmetric.x448.X448PrivateKey":        "asymmetric.x448.X448PublicKey",
}

func builderMethod(class, method string) bool {
	if class == "cryptography.x509.CertificateBuilder" {
		switch method {
		case "subject_name", "issuer_name", "not_valid_before", "not_valid_after", "serial_number", "public_key", "add_extension":
			return true
		}
	}
	return class == "cryptography.x509.CertificateSigningRequestBuilder" &&
		(method == "subject_name" || method == "add_extension" || method == "add_attribute")
}

func symbol(v *value) string {
	if v == nil {
		return ""
	}
	switch v.Kind {
	case "symbol":
		return v.Text
	case "attribute":
		base := symbol(v.Base)
		if base == "" {
			base = instance(v.Base)
		}
		if base != "" {
			return base + "." + v.Text
		}
	}
	return ""
}

func instance(v *value) string {
	if v == nil || v.Kind != "call" {
		return ""
	}
	name := symbol(v.Base)
	if class := httpInstance(*v); class != "" {
		return class
	}
	switch name {
	case "ssl.SSLContext", "ssl.create_default_context", "ssl._create_unverified_context":
		return "ssl.SSLContext"
	case "hmac.new", "hmac.HMAC":
		return "hmac.HMAC"
	case "cryptography.hazmat.primitives.hashes.Hash":
		return name
	case primitives + "hmac.HMAC":
		return name
	case primitives + "cmac.CMAC", primitives + "cmac.CMAC.copy":
		return primitives + "cmac.CMAC"
	case "argon2.PasswordHasher":
		return name
	case "cryptography.hazmat.primitives.ciphers.Cipher":
		return name
	case "cryptography.hazmat.primitives.ciphers.Cipher.encryptor", "cryptography.hazmat.primitives.ciphers.Cipher.decryptor":
		return "cryptography.hazmat.primitives.ciphers.CipherContext"
	case "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key":
		return "cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey"
	case "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key", "cryptography.hazmat.primitives.asymmetric.ec.derive_private_key":
		return "cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey"
	case primitives + "asymmetric.ed25519.Ed25519PrivateKey.generate", primitives + "asymmetric.ed448.Ed448PrivateKey.generate",
		primitives + "asymmetric.x25519.X25519PrivateKey.generate", primitives + "asymmetric.x448.X448PrivateKey.generate":
		return strings.TrimSuffix(name, ".generate")
	}
	for private, public := range publicKeyTypes {
		if name == primitives+private+".public_key" {
			return primitives + public
		}
	}
	if _, known := kdfModels[strings.TrimPrefix(name, primitives)]; known {
		return name
	}
	for _, builder := range []string{"cryptography.x509.CertificateBuilder", "cryptography.x509.CertificateSigningRequestBuilder"} {
		if name == builder {
			return builder
		}
		if strings.HasPrefix(name, builder+".") && builderMethod(builder, strings.TrimPrefix(name, builder+".")) {
			return builder
		}
	}
	if strings.HasPrefix(name, "hashlib.") && (hashName(strings.TrimPrefix(name, "hashlib.")) != "" || name == "hashlib.new") {
		return "hashlib.Hash"
	}
	if _, known := aeadNames[strings.TrimPrefix(name, primitives+"ciphers.aead.")]; known {
		return name
	}
	if name == "cryptography.fernet.Fernet" {
		return name
	}
	for _, prefix := range []string{"Crypto.", "Cryptodome."} {
		if strings.HasPrefix(name, prefix+"Cipher.") && strings.HasSuffix(name, ".new") {
			return strings.TrimSuffix(name, ".new")
		}
		if strings.HasPrefix(name, prefix+"Hash.") && strings.HasSuffix(name, ".new") {
			return strings.TrimSuffix(name, ".new")
		}
	}
	return ""
}

func argumentsExpanded(v value) bool {
	if _, expanded := v.Keywords["**"]; expanded {
		return true
	}
	for _, argument := range v.Args {
		if argument.Kind == "unpack" {
			return true
		}
	}
	return false
}

func argument(v value, index int, name string) value {
	if argumentsExpanded(v) {
		return value{}
	}
	if arg, ok := v.Keywords[name]; ok {
		if index >= 0 && index < len(v.Args) {
			return value{}
		}
		return arg
	}
	if index >= 0 && index < len(v.Args) {
		return v.Args[index]
	}
	return value{}
}

func integer(v value) (int64, bool) {
	switch v.Kind {
	case "int":
		return v.Integer, true
	case "unary":
		if len(v.Args) != 1 {
			return 0, false
		}
		number, known := integer(v.Args[0])
		if !known {
			return 0, false
		}
		switch v.Text {
		case "UAdd":
			return number, true
		case "USub":
			return -number, number != math.MinInt64
		}
	case "binary":
		if len(v.Args) != 2 {
			return 0, false
		}
		left, a := integer(v.Args[0])
		right, b := integer(v.Args[1])
		if !a || !b {
			return 0, false
		}
		switch v.Text {
		case "Add":
			result := left + right
			return result, !(right > 0 && result < left || right < 0 && result > left)
		case "Sub":
			result := left - right
			return result, !(right > 0 && result > left || right < 0 && result < left)
		case "Mult":
			if left == 0 || right == 0 {
				return 0, true
			}
			if left == math.MinInt64 && right == -1 || right == math.MinInt64 && left == -1 {
				return 0, false
			}
			result := left * right
			return result, result/right == left
		}
	case "call":
		if symbol(v.Base) == "builtins.len" && len(v.Args) == 1 && len(v.Keywords) == 0 {
			return length(v.Args[0])
		}
	}
	return 0, false
}

func length(v value) (int64, bool) {
	switch v.Kind {
	case "bytes":
		return v.Length, v.Length >= 0 && v.Length <= maxSourceBytes
	case "binary":
		if v.Text == "Mult" && len(v.Args) == 2 {
			bytesValue, countValue := v.Args[0], v.Args[1]
			if bytesValue.Kind != "bytes" {
				bytesValue, countValue = countValue, bytesValue
			}
			size, a := length(bytesValue)
			count, b := integer(countValue)
			if bytesValue.Kind == "bytes" && a && b && size >= 0 && count >= 0 && count <= maxSourceBytes && size <= maxSourceBytes/max(1, count) {
				return size * count, true
			}
		}
	case "call":
		name := symbol(v.Base)
		switch name {
		case "builtins.bytes", "os.urandom", "secrets.token_bytes",
			"Crypto.Random.get_random_bytes", "Cryptodome.Random.get_random_bytes":
			size, known := integer(argument(v, 0, "nbytes"))
			return size, known && size >= 0 && size <= maxSourceBytes
		case "cryptography.hazmat.primitives.ciphers.aead.AESGCM.generate_key", "cryptography.hazmat.primitives.ciphers.aead.AESCCM.generate_key":
			bits, known := integer(argument(v, 0, "bit_length"))
			return bits / 8, known && bits > 0 && bits%8 == 0 && bits <= maxSourceBytes*8
		case "cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305.generate_key":
			return 32, true
		case "bcrypt.kdf":
			size, known := integer(argument(v, 2, "desired_key_bytes"))
			return size, known && len(v.Modified) == 0 && size >= 0 && size <= maxSourceBytes
		}
		if strings.HasSuffix(name, ".derive") {
			class := strings.TrimSuffix(strings.TrimPrefix(name, primitives), ".derive")
			if model, known := kdfModels[class]; known {
				constructor := receiver(v)
				if len(constructor.Modified) != 0 || len(v.Modified) != 0 {
					return 0, false
				}
				size, known := integer(argument(constructor, model.lengthIndex, "length"))
				return size, known && size >= 0 && size <= maxSourceBytes
			}
		}
	}
	return 0, false
}

func literalText(v value) (string, bool) {
	return v.Text, v.Kind == "string" && v.Length == int64(len([]rune(v.Text)))
}

func canonicalCryptoName(name string) string {
	if name == "argon2.Type" {
		return "argon2.low_level.Type"
	}
	if suffix, found := strings.CutPrefix(name, "argon2.Type."); found {
		return "argon2.low_level.Type." + suffix
	}
	return name
}

func invalidate(v value, shadowed map[string]bool, mutations []string) value {
	name := symbol(&v)
	if name != "" && (shadowed[strings.Split(name, ".")[0]] || mutated(name, mutations)) {
		return value{Kind: "unknown", Hint: name}
	}
	if v.Base != nil {
		base := invalidate(*v.Base, shadowed, mutations)
		v.Base = &base
	}
	for index, arg := range v.Args {
		v.Args[index] = invalidate(arg, shadowed, mutations)
	}
	for name, arg := range v.Keywords {
		v.Keywords[name] = invalidate(arg, shadowed, mutations)
	}
	return v
}
