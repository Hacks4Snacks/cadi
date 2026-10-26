package goscan

import (
	"fmt"
	"strings"

	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"golang.org/x/tools/go/ssa"
)

var hashNames = map[string]map[string]string{
	"md5":     {"New": "MD5", "Sum": "MD5"},
	"sha1":    {"New": "SHA-1", "Sum": "SHA-1"},
	"sha256":  {"New": "SHA-256", "Sum256": "SHA-256", "New224": "SHA-224", "Sum224": "SHA-224"},
	"sha512":  {"New": "SHA-512", "Sum512": "SHA-512", "New384": "SHA-384", "Sum384": "SHA-384", "New512_224": "SHA-512/224", "Sum512_224": "SHA-512/224", "New512_256": "SHA-512/256", "Sum512_256": "SHA-512/256"},
	"sha3":    {"New224": "SHA3-224", "Sum224": "SHA3-224", "New256": "SHA3-256", "Sum256": "SHA3-256", "New384": "SHA3-384", "Sum384": "SHA3-384", "New512": "SHA3-512", "Sum512": "SHA3-512", "NewSHAKE128": "SHAKE128", "NewSHAKE256": "SHAKE256", "NewShake128": "SHAKE128", "NewShake256": "SHAKE256"},
	"blake2b": {"New256": "BLAKE2b-256", "Sum256": "BLAKE2b-256", "New384": "BLAKE2b-384", "Sum384": "BLAKE2b-384", "New512": "BLAKE2b-512", "Sum512": "BLAKE2b-512"},
	"blake2s": {"New256": "BLAKE2s-256", "Sum256": "BLAKE2s-256", "New128": "BLAKE2s-128"},
}

// These exact APIs read metadata or manage containers/connections without selecting
// or executing cryptography. Other methods, even with the same name, remain gaps.
func nonAssetAPI(api apiIdentity) bool {
	switch api {
	case apiIdentity{"crypto/elliptic", "Curve", "Params"},
		apiIdentity{"crypto/elliptic", "CurveParams", "Params"},
		apiIdentity{"crypto/ecdh", "PublicKey", "Curve"},
		apiIdentity{"crypto/x509", "SignatureAlgorithm", "String"},
		apiIdentity{"crypto/x509", "Certificate", "Equal"},
		apiIdentity{"crypto/rsa", "PublicKey", "Equal"},
		apiIdentity{"crypto/x509/pkix", "Name", "String"},
		apiIdentity{"golang.org/x/crypto/ssh", "PublicKey", "Type"},
		apiIdentity{"crypto/x509", "", "NewCertPool"},
		apiIdentity{"crypto/x509", "CertPool", "Clone"},
		apiIdentity{"crypto/tls", "Conn", "ConnectionState"},
		apiIdentity{"crypto/tls", "", "CipherSuiteName"},
		apiIdentity{"golang.org/x/crypto/ssh", "Conn", "Close"},
		apiIdentity{"golang.org/x/crypto/ssh", "Channel", "Close"},
		apiIdentity{"golang.org/x/crypto/ssh", "Session", "Wait"},
		apiIdentity{"golang.org/x/crypto/ssh", "Session", "StdinPipe"},
		apiIdentity{"golang.org/x/crypto/ssh", "Session", "StdoutPipe"},
		apiIdentity{"golang.org/x/crypto/ssh", "Session", "StderrPipe"},
		apiIdentity{"crypto/tls", "ClientAuthType", "String"}:
		return true
	}
	return false
}

func recognize(path, name string, call *ssa.CallCommon, values *values, evidence *inventory.Evidence) (cdx.Component, bool) {
	api := calledAPI(call)
	switch api {
	case apiIdentity{"crypto", "Signer", "Public"},
		apiIdentity{"crypto", "Decrypter", "Public"},
		apiIdentity{"crypto/ecdh", "PrivateKey", "PublicKey"},
		apiIdentity{"golang.org/x/crypto/ssh", "CryptoPublicKey", "CryptoPublicKey"}:
		c := keyOperation("Public key access")
		if api.path == "crypto/ecdh" {
			inventory.Property(&c, "key-algorithm", "ECDH")
		}
		return c, true
	case apiIdentity{"crypto/x509", "CertPool", "AppendCertsFromPEM"}:
		return operation("X.509 certificate import", cdx.CryptoAssetTypeCertificate), true
	case apiIdentity{"crypto/rsa", "PrivateKey", "Validate"}:
		c := keyOperation("Private key validation")
		inventory.Property(&c, "key-algorithm", "RSA")
		inventory.Property(&c, "scope", "structural key check; success, signing, and encryption are not inferred")
		return c, true
	case apiIdentity{"crypto/x509", "CertificateRequest", "CheckSignature"}:
		c := inventory.Algorithm("CSR signature verification", cdx.CryptoPrimitiveSignature)
		c.CryptoProperties.AlgorithmProperties.CryptoFunctions = &[]cdx.CryptoFunction{cdx.CryptoFunctionVerify}
		evidence.Unresolved = append(evidence.Unresolved, "algorithm")
		inventory.Property(&c, "scope", "PKCS#10 self-signature check; validity, approval, and certificate issuance are not established")
		return c, true
	case apiIdentity{"golang.org/x/crypto/ssh", "", "MarshalAuthorizedKey"}:
		return keyOperation("Public key serialization"), true
	case apiIdentity{"golang.org/x/crypto/ssh", "Channel", "Read"},
		apiIdentity{"golang.org/x/crypto/ssh", "Channel", "Write"},
		apiIdentity{"golang.org/x/crypto/ssh", "Client", "NewSession"},
		apiIdentity{"golang.org/x/crypto/ssh", "Session", "Shell"}:
		c := protocol("SSH channel/session use", cdx.CryptoProtocolTypeSSH)
		inventory.Property(&c, "ssh.operation", api.receiver+"."+api.name)
		return c, true
	case apiIdentity{"golang.org/x/crypto/ssh", "", "PublicKeys"}:
		c := protocol("SSH authentication configuration", cdx.CryptoProtocolTypeSSH)
		inventory.Property(&c, "ssh.auth-method", "public-key")
		evidence.Unresolved = append(evidence.Unresolved, "ssh.signer-algorithm", "key-size-bits")
		return c, true
	case apiIdentity{"golang.org/x/crypto/ssh", "", "InsecureIgnoreHostKey"}:
		c := protocol("SSH host-key configuration", cdx.CryptoProtocolTypeSSH)
		inventory.Property(&c, "ssh.host-key-verification", "disabled")
		inventory.Property(&c, "scope", "callback factory only; application to a connection is not established")
		return c, true
	case apiIdentity{"crypto/tls", "Conn", "Handshake"},
		apiIdentity{"crypto/tls", "Conn", "HandshakeContext"}:
		c := protocol("TLS handshake", cdx.CryptoProtocolTypeTLS)
		evidence.Unresolved = append(evidence.Unresolved, "tls.version", "tls.cipher-suite")
		return c, true
	}
	family := path[strings.LastIndex(path, "/")+1:]
	if path != "crypto/"+family && path != "golang.org/x/crypto/"+family {
		return cdx.Component{}, false
	}
	arg := func(index int) ssa.Value {
		if index >= 0 && index < len(call.Args) {
			return call.Args[index]
		}
		return nil
	}
	parameter := func(c *cdx.Component, label string, index int, byteLength bool) {
		value, known := values.integer(arg(index))
		if byteLength {
			value, known = values.length(arg(index))
			if value > 1<<30 {
				known = false
			}
			value *= 8
		}
		if known {
			if label == "key-size-bits" && c.CryptoProperties.AlgorithmProperties != nil {
				c.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = fmt.Sprint(value)
			} else {
				inventory.Property(c, label, fmt.Sprint(value))
			}
		} else {
			evidence.Unresolved = append(evidence.Unresolved, label)
		}
	}
	if hash := hashNames[family][name]; hash != "" {
		return inventory.HashAlgorithm(hash)
	}
	switch family {
	case "elliptic":
		if api.receiver == "" && (name == "P224" || name == "P256" || name == "P384" || name == "P521") {
			curve := "P-" + strings.TrimPrefix(name, "P")
			c := inventory.Algorithm("Elliptic curve "+curve, cdx.CryptoPrimitiveOther)
			c.CryptoProperties.AlgorithmProperties.EllipticCurve = inventory.CurveID(curve)
			return c, true
		}
	case "rsa":
		switch name {
		case "GenerateKey", "GenerateMultiPrimeKey", "EncryptOAEP", "DecryptOAEP", "EncryptPKCS1v15", "DecryptPKCS1v15", "DecryptPKCS1v15SessionKey", "SignPKCS1v15", "VerifyPKCS1v15", "SignPSS", "VerifyPSS", "Sign", "Decrypt":
			c := inventory.Algorithm("RSA", cdx.CryptoPrimitivePKE)
			function := cdx.CryptoFunctionKeygen
			switch {
			case strings.HasPrefix(name, "Sign"), strings.HasPrefix(name, "Verify"):
				c.CryptoProperties.AlgorithmProperties.Primitive = cdx.CryptoPrimitiveSignature
				function = cdx.CryptoFunctionSign
				if strings.HasPrefix(name, "Verify") {
					function = cdx.CryptoFunctionVerify
				}
			case strings.HasPrefix(name, "Encrypt"):
				function = cdx.CryptoFunctionEncrypt
			case strings.HasPrefix(name, "Decrypt"):
				function = cdx.CryptoFunctionDecrypt
			}
			c.CryptoProperties.AlgorithmProperties.CryptoFunctions = &[]cdx.CryptoFunction{function}
			a := c.CryptoProperties.AlgorithmProperties
			switch name {
			case "EncryptOAEP", "DecryptOAEP":
				a.AlgorithmFamily, a.Padding = "RSAES-OAEP", cdx.CryptoPaddingOAEP
				c.CryptoProperties.OID = inventory.OIDRSAESOAEP
			case "EncryptPKCS1v15", "DecryptPKCS1v15", "DecryptPKCS1v15SessionKey":
				a.AlgorithmFamily, a.Padding = "RSAES-PKCS1", cdx.CryptoPaddingPKCS1v15
			case "SignPKCS1v15", "VerifyPKCS1v15":
				a.AlgorithmFamily, a.Padding = "RSASSA-PKCS1", cdx.CryptoPaddingPKCS1v15
			case "SignPSS", "VerifyPSS":
				a.AlgorithmFamily = "RSASSA-PSS"
				c.CryptoProperties.OID = inventory.OIDRSASSAPSS
			}
			if name == "GenerateKey" {
				parameter(&c, "key-size-bits", 1, false)
			} else if name == "GenerateMultiPrimeKey" {
				parameter(&c, "key-size-bits", 2, false)
			} else {
				evidence.Unresolved = append(evidence.Unresolved, "key-size-bits")
			}
			return c, true
		}
	case "aes", "des", "chacha20", "chacha20poly1305":
		if name == "NewCipher" || name == "NewTripleDESCipher" || name == "NewUnauthenticatedCipher" || name == "New" || name == "NewX" {
			label, primitive := strings.ToUpper(family), cdx.CryptoPrimitiveBlockCipher
			switch family {
			case "des":
				label = "DES"
				if name == "NewTripleDESCipher" {
					label = "3DES"
				}
			case "chacha20":
				label, primitive = "ChaCha20", cdx.CryptoPrimitiveStreamCipher
			case "chacha20poly1305":
				label, primitive = "ChaCha20-Poly1305", cdx.CryptoPrimitiveAE
				if name == "NewX" {
					label = "XChaCha20-Poly1305"
				}
			}
			c := inventory.Algorithm(label, primitive)
			algorithmFamily := label
			if family == "chacha20poly1305" {
				algorithmFamily = "ChaCha20"
			}
			c.CryptoProperties.AlgorithmProperties.AlgorithmFamily = algorithmFamily
			parameter(&c, "key-size-bits", 0, true)
			return c, true
		}
	case "ecdsa", "ed25519":
		if strings.HasPrefix(name, "GenerateKey") || strings.HasPrefix(name, "NewKeyFromSeed") || strings.HasPrefix(name, "Sign") || strings.HasPrefix(name, "Verify") {
			label := "ECDSA"
			if family == "ed25519" {
				label = "Ed25519"
			}
			c := inventory.Algorithm(label, cdx.CryptoPrimitiveSignature)
			a := c.CryptoProperties.AlgorithmProperties
			a.AlgorithmFamily = "ECDSA"
			switch {
			case strings.HasPrefix(name, "GenerateKey"):
				a.CryptoFunctions = &[]cdx.CryptoFunction{cdx.CryptoFunctionKeygen}
			case name == "NewKeyFromSeed":
				a.CryptoFunctions = &[]cdx.CryptoFunction{cdx.CryptoFunctionKeyderive}
			case strings.HasPrefix(name, "Sign"):
				a.CryptoFunctions = &[]cdx.CryptoFunction{cdx.CryptoFunctionSign}
			case strings.HasPrefix(name, "Verify"):
				a.CryptoFunctions = &[]cdx.CryptoFunction{cdx.CryptoFunctionVerify}
			}
			if label == "Ed25519" {
				a.AlgorithmFamily, a.EllipticCurve = "EdDSA", inventory.CurveID("Ed25519")
				if api.receiver == "" {
					switch name {
					case "GenerateKey", "NewKeyFromSeed", "Sign", "Verify":
						c.CryptoProperties.OID = inventory.OIDEd25519
					}
				}
			} else if name == "GenerateKey" {
				if constructor, ok := arg(0).(*ssa.Call); ok {
					pkg, curve, _ := callSymbol(&constructor.Call)
					if pkg == "crypto/elliptic" && (curve == "P224" || curve == "P256" || curve == "P384" || curve == "P521") {
						c.CryptoProperties.AlgorithmProperties.EllipticCurve = inventory.CurveID("P-" + strings.TrimPrefix(curve, "P"))
					}
				}
				if c.CryptoProperties.AlgorithmProperties.EllipticCurve == "" {
					evidence.Unresolved = append(evidence.Unresolved, "curve")
				}
			}
			return c, true
		}
	case "ecdh", "curve25519":
		if name == "X25519" || name == "P256" || name == "P384" || name == "P521" || name == "ECDH" || name == "GenerateKey" || name == "NewPrivateKey" || name == "NewPublicKey" {
			c := inventory.Algorithm("ECDH", cdx.CryptoPrimitiveKeyAgree)
			a := c.CryptoProperties.AlgorithmProperties
			a.AlgorithmFamily = "ECDH"
			switch {
			case name == "GenerateKey":
				a.CryptoFunctions = &[]cdx.CryptoFunction{cdx.CryptoFunctionKeygen}
			case name == "ECDH" || path == "golang.org/x/crypto/curve25519" && name == "X25519":
				a.CryptoFunctions = &[]cdx.CryptoFunction{cdx.CryptoFunctionKeyderive}
			}
			if name == "X25519" || strings.HasPrefix(name, "P") && len(name) == 4 {
				curve := name
				if strings.HasPrefix(curve, "P") {
					curve = "P-" + strings.TrimPrefix(curve, "P")
				}
				c.CryptoProperties.AlgorithmProperties.EllipticCurve = inventory.CurveID(curve)
				if name == "X25519" {
					c.CryptoProperties.OID = inventory.OIDX25519
				}
			} else {
				evidence.Unresolved = append(evidence.Unresolved, "curve")
			}
			return c, true
		}
	case "hmac":
		if name == "New" {
			hash := ""
			if function, ok := arg(0).(*ssa.Function); ok && function.Pkg != nil {
				hashFamily := function.Pkg.Pkg.Name()
				hashPath := function.Pkg.Pkg.Path()
				if hashPath == "crypto/"+hashFamily || hashPath == "golang.org/x/crypto/"+hashFamily {
					hash = hashNames[hashFamily][function.Name()]
				}
			}
			c := inventory.HMACAlgorithm(hash)
			parameter(&c, "key-size-bits", 1, true)
			return c, true
		}
	case "bcrypt", "scrypt", "argon2", "pbkdf2", "hkdf":
		switch name {
		case "GenerateFromPassword", "CompareHashAndPassword", "Key", "IDKey", "New", "Extract", "Expand":
			c := inventory.Algorithm(family, cdx.CryptoPrimitiveKDF)
			c.CryptoProperties.AlgorithmProperties.CryptoFunctions = &[]cdx.CryptoFunction{cdx.CryptoFunctionKeyderive}
			switch family {
			case "bcrypt":
				c.CryptoProperties.AlgorithmProperties.AlgorithmFamily = "bcrypt"
				if name == "GenerateFromPassword" {
					parameter(&c, "cost", 1, false)
				} else {
					c.CryptoProperties.AlgorithmProperties.CryptoFunctions = &[]cdx.CryptoFunction{cdx.CryptoFunctionVerify}
				}
			case "scrypt":
				parameter(&c, "N", 2, false)
				parameter(&c, "r", 3, false)
				parameter(&c, "p", 4, false)
			case "argon2":
				if name == "IDKey" {
					c.Name = "Argon2id"
				} else {
					c.Name = "Argon2i"
				}
				parameter(&c, "iterations", 2, false)
				parameter(&c, "memory-kib", 3, false)
			case "pbkdf2":
				c.CryptoProperties.AlgorithmProperties.AlgorithmFamily = "PBKDF2"
				index := 2
				if path == "crypto/pbkdf2" {
					index = 3
				}
				parameter(&c, "iterations", index, false)
			case "hkdf":
				c.CryptoProperties.AlgorithmProperties.AlgorithmFamily = "HKDF"
			}
			return c, true
		}
	case "x509":
		if name == "ParseCertificate" || name == "ParseCertificates" || name == "CreateCertificate" {
			return operation("X.509 "+name, cdx.CryptoAssetTypeCertificate), true
		}
		if name == "CreateCertificateRequest" || name == "ParseCertificateRequest" {
			c := operation("PKCS#10 certificate request", cdx.CryptoAssetTypeRelatedCryptoMaterial)
			c.CryptoProperties.RelatedCryptoMaterialProperties = &cdx.RelatedCryptoMaterialProperties{Type: cdx.RelatedCryptoMaterialTypeOther}
			return c, true
		}
		if strings.HasPrefix(name, "Parse") || strings.HasPrefix(name, "Marshal") {
			if strings.Contains(name, "Key") {
				return keyOperation(name), true
			}
		}
	case "tls":
		if name == "LoadX509KeyPair" || name == "X509KeyPair" {
			return operation("TLS X.509 key pair", cdx.CryptoAssetTypeCertificate), true
		}
		switch name {
		case "Client", "Server", "Dial", "DialWithDialer", "DialContext", "Listen":
			return protocol("TLS", cdx.CryptoProtocolTypeTLS), true
		}
	case "ssh":
		if name == "FingerprintSHA256" && api.receiver == "" {
			c, known := inventory.HashAlgorithm("SHA-256")
			inventory.Property(&c, "purpose", "SSH public-key fingerprint")
			return c, known
		}
		switch name {
		case "ParseAuthorizedKey", "ParsePublicKey", "NewPublicKey", "ParsePrivateKey", "ParseRawPrivateKey", "ParsePrivateKeyWithPassphrase", "ParseRawPrivateKeyWithPassphrase", "NewSignerFromKey":
			return keyOperation(name), true
		case "Dial", "NewClientConn", "NewServerConn":
			return protocol("SSH", cdx.CryptoProtocolTypeSSH), true
		}
	case "rand":
		if name == "Read" || name == "Text" || name == "Int" || name == "Prime" {
			c := inventory.Algorithm("Go CSPRNG", cdx.CryptoPrimitiveOther)
			c.CryptoProperties.AlgorithmProperties.CryptoFunctions = &[]cdx.CryptoFunction{cdx.CryptoFunctionGenerate}
			return c, true
		}
	case "mlkem":
		if strings.HasPrefix(name, "GenerateKey") || strings.HasPrefix(name, "NewDecapsulationKey") || name == "Encapsulate" || name == "Decapsulate" {
			c := inventory.Algorithm("ML-KEM", cdx.CryptoPrimitiveKEM)
			a := c.CryptoProperties.AlgorithmProperties
			a.AlgorithmFamily = "ML-KEM"
			function := cdx.CryptoFunctionKeygen
			switch name {
			case "Encapsulate":
				function = cdx.CryptoFunctionEncapsulate
			case "Decapsulate":
				function = cdx.CryptoFunctionDecapsulate
			}
			a.CryptoFunctions = &[]cdx.CryptoFunction{function}
			identity := name
			if api.receiver != "" {
				identity = api.receiver
			}
			switch identity {
			case "GenerateKey512", "NewDecapsulationKey512", "DecapsulationKey512", "EncapsulationKey512":
				a.ParameterSetIdentifier, c.CryptoProperties.OID = "512", "2.16.840.1.101.3.4.4.1"
			case "GenerateKey768", "NewDecapsulationKey768", "DecapsulationKey768", "EncapsulationKey768":
				a.ParameterSetIdentifier, c.CryptoProperties.OID = "768", "2.16.840.1.101.3.4.4.2"
			case "GenerateKey1024", "NewDecapsulationKey1024", "DecapsulationKey1024", "EncapsulationKey1024":
				a.ParameterSetIdentifier, c.CryptoProperties.OID = "1024", "2.16.840.1.101.3.4.4.3"
			}
			return c, true
		}
	case "cipher":
		modes := map[string]cdx.CryptoAlgorithmMode{
			"NewGCM": "gcm", "NewGCMWithNonceSize": "gcm", "NewGCMWithTagSize": "gcm", "NewGCMWithRandomNonce": "gcm",
			"NewCBCEncrypter": "cbc", "NewCBCDecrypter": "cbc", "NewCTR": "ctr", "NewOFB": "ofb",
			"NewCFBEncrypter": "cfb", "NewCFBDecrypter": "cfb",
		}
		if mode := modes[name]; mode != "" {
			c := inventory.Algorithm("Block cipher ("+strings.ToUpper(string(mode))+")", cdx.CryptoPrimitiveBlockCipher)
			c.CryptoProperties.AlgorithmProperties.Mode = mode
			if mode == cdx.CryptoAlgorithmModeGCM {
				c.CryptoProperties.AlgorithmProperties.Primitive = cdx.CryptoPrimitiveAE
			}
			switch name {
			case "NewCBCEncrypter", "NewCFBEncrypter":
				c.CryptoProperties.AlgorithmProperties.CryptoFunctions = &[]cdx.CryptoFunction{cdx.CryptoFunctionEncrypt}
			case "NewCBCDecrypter", "NewCFBDecrypter":
				c.CryptoProperties.AlgorithmProperties.CryptoFunctions = &[]cdx.CryptoFunction{cdx.CryptoFunctionDecrypt}
			}
			evidence.Unresolved = append(evidence.Unresolved, "underlying-algorithm")
			return c, true
		}
	}
	return cdx.Component{}, false
}

func addConfiguredParameters(component *cdx.Component, evidence *inventory.Evidence, call *ssa.CallCommon, values *values) {
	api := calledAPI(call)
	index := -1
	switch api {
	case apiIdentity{"crypto/rsa", "", "GenerateKey"}:
		index = 1
	case apiIdentity{"crypto/rsa", "", "GenerateMultiPrimeKey"}:
		index = 2
	}
	if index < 0 || index >= len(call.Args) {
		return
	}
	if _, exact := values.integer(call.Args[index]); exact {
		return
	}
	for _, fact := range values.declaredIntegers(call.Args[index]) {
		fact.Name = "key-size-bits"
		evidence.Parameters = append(evidence.Parameters, fact)
		inventory.Property(component, "key-size-bits:declared", fact.Value)
	}
}

func operation(name string, kind cdx.CryptoAssetType) cdx.Component {
	return cdx.Component{Type: "cryptographic-asset", Name: name, CryptoProperties: &cdx.CryptoProperties{AssetType: kind}}
}

func keyOperation(name string) cdx.Component {
	c := operation(name, cdx.CryptoAssetTypeRelatedCryptoMaterial)
	kind := cdx.RelatedCryptoMaterialTypeKey
	if strings.Contains(name, "Private") {
		kind = cdx.RelatedCryptoMaterialTypePrivateKey
	} else if strings.Contains(name, "Public") || name == "ParseAuthorizedKey" {
		kind = cdx.RelatedCryptoMaterialTypePublicKey
	}
	c.CryptoProperties.RelatedCryptoMaterialProperties = &cdx.RelatedCryptoMaterialProperties{Type: kind}
	return c
}

func protocol(name string, kind cdx.CryptoProtocolType) cdx.Component {
	return cdx.Component{Type: "cryptographic-asset", Name: name,
		CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeProtocol,
			ProtocolProperties: &cdx.CryptoProtocolProperties{Type: kind}}}
}
