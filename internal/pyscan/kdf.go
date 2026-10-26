package pyscan

import (
	"strings"

	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

var kdfModels = map[string]struct {
	name        string
	lengthIndex int
	argon2      bool
}{
	"kdf.pbkdf2.PBKDF2HMAC": {"PBKDF2", 1, false},
	"kdf.hkdf.HKDF":         {"HKDF", 1, false},
	"kdf.hkdf.HKDFExpand":   {"HKDF-Expand", 1, false},
	"kdf.scrypt.Scrypt":     {"scrypt", 1, false},
	"kdf.argon2.Argon2id":   {"Argon2id", -1, true},
	"kdf.argon2.Argon2i":    {"Argon2i", -1, true},
	"kdf.argon2.Argon2d":    {"Argon2d", -1, true},
}

func kdfCall(name string, call value, evidence *inventory.Evidence) (cdx.Component, bool) {
	constructor := call
	function := cdx.CryptoFunction("")
	class := name
	for _, method := range []string{"derive", "verify"} {
		if strings.HasSuffix(name, "."+method) {
			class = strings.TrimSuffix(name, "."+method)
			constructor = receiver(call)
			function = cdx.CryptoFunctionKeyderive
			if method == "verify" {
				function = cdx.CryptoFunctionVerify
			}
		}
	}
	model, known := kdfModels[class]
	if !known || len(constructor.Modified) != 0 {
		return cdx.Component{}, false
	}
	component := algorithm(model.name, cdx.CryptoPrimitiveKDF, function)
	switch class {
	case "kdf.pbkdf2.PBKDF2HMAC":
		component.CryptoProperties.AlgorithmProperties.AlgorithmFamily = "PBKDF2"
	case "kdf.hkdf.HKDF", "kdf.hkdf.HKDFExpand":
		component.CryptoProperties.AlgorithmProperties.AlgorithmFamily = "HKDF"
	}
	byteCountParameter(&component, evidence, "derived-key-size-bits", argument(constructor, model.lengthIndex, "length"))
	if model.argon2 {
		for _, field := range []struct{ name, parameter string }{
			{"iterations", "iterations"}, {"memory_cost", "memory-kib"}, {"lanes", "parallelism"},
		} {
			parameter(&component, evidence, field.parameter, argument(constructor, -1, field.name), false)
		}
		return component, true
	}
	if class == "kdf.scrypt.Scrypt" {
		for index, parameterName := range []string{"n", "r", "p"} {
			parameter(&component, evidence, parameterName, argument(constructor, index+2, parameterName), false)
		}
	} else {
		if hash := digest(argument(constructor, 0, "algorithm")); hash != "" {
			inventory.Property(&component, "hash", hash)
		} else {
			evidence.Unresolved = append(evidence.Unresolved, "hash")
		}
		if class == "kdf.pbkdf2.PBKDF2HMAC" {
			parameter(&component, evidence, "iterations", argument(constructor, 3, "iterations"), false)
		}
	}
	return component, true
}

func passwordCall(name string, call value, evidence *inventory.Evidence) (cdx.Component, bool) {
	switch name {
	case "bcrypt.hashpw", "bcrypt.checkpw", "bcrypt.kdf":
		function := cdx.CryptoFunctionKeyderive
		label := "bcrypt"
		if name == "bcrypt.checkpw" {
			function = cdx.CryptoFunctionVerify
		} else if name == "bcrypt.kdf" {
			label = "bcrypt-PBKDF"
		}
		component := algorithm(label, cdx.CryptoPrimitiveKDF, function)
		component.CryptoProperties.AlgorithmProperties.AlgorithmFamily = "bcrypt"
		if name == "bcrypt.hashpw" {
			salt := argument(call, 1, "salt")
			if salt.Kind == "call" && len(salt.Modified) == 0 && symbol(salt.Base) == "bcrypt.gensalt" {
				parameter(&component, evidence, "cost", argument(salt, 0, "rounds"), false)
			} else {
				evidence.Unresolved = append(evidence.Unresolved, "cost")
			}
		} else if name == "bcrypt.kdf" {
			parameter(&component, evidence, "rounds", argument(call, 3, "rounds"), false)
			byteCountParameter(&component, evidence, "derived-key-size-bits", argument(call, 2, "desired_key_bytes"))
		}
		return component, true
	case "argon2.PasswordHasher", "argon2.PasswordHasher.hash", "argon2.PasswordHasher.verify":
		constructor := call
		function := cdx.CryptoFunction("")
		if name != "argon2.PasswordHasher" {
			constructor = receiver(call)
			if len(constructor.Modified) != 0 {
				return cdx.Component{}, false
			}
			function = cdx.CryptoFunctionKeyderive
		}
		if name == "argon2.PasswordHasher.verify" {
			// Verification uses the encoded hash's parameters, not the hasher configuration.
			return algorithm("Argon2", cdx.CryptoPrimitiveKDF, cdx.CryptoFunctionVerify), true
		}
		variant := argument(constructor, 6, "type")
		label := map[string]string{
			"argon2.low_level.Type.ID": "Argon2id",
			"argon2.low_level.Type.I":  "Argon2i",
			"argon2.low_level.Type.D":  "Argon2d",
		}[canonicalCryptoName(symbol(&variant))]
		if label == "" {
			label = "Argon2"
			evidence.Unresolved = append(evidence.Unresolved, "variant")
		}
		component := algorithm(label, cdx.CryptoPrimitiveKDF, function)
		for index, field := range []struct{ name, parameter string }{
			{"time_cost", "iterations"}, {"memory_cost", "memory-kib"}, {"parallelism", "parallelism"},
		} {
			parameter(&component, evidence, field.parameter, argument(constructor, index, field.name), false)
		}
		byteCountParameter(&component, evidence, "derived-key-size-bits", argument(constructor, 3, "hash_len"))
		salt := argument(call, -1, "salt")
		if name == "argon2.PasswordHasher.hash" &&
			(argumentsExpanded(call) || supplied(call, -1, "salt") && salt.Kind != "none") {
			parameter(&component, evidence, "salt-size-bits", salt, true)
		} else {
			byteCountParameter(&component, evidence, "salt-size-bits", argument(constructor, 4, "salt_len"))
		}
		return component, true
	}
	return cdx.Component{}, false
}
