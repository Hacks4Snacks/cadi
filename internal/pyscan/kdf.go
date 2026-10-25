package pyscan

import (
	"strings"

	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

var kdfNames = map[string]string{
	"kdf.pbkdf2.PBKDF2HMAC": "PBKDF2",
	"kdf.hkdf.HKDF":         "HKDF",
	"kdf.hkdf.HKDFExpand":   "HKDF-Expand",
	"kdf.scrypt.Scrypt":     "scrypt",
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
	label, known := kdfNames[class]
	if !known {
		return cdx.Component{}, false
	}
	component := algorithm(label, cdx.CryptoPrimitiveKDF, function)
	byteCountParameter(&component, evidence, "derived-key-size-bits", argument(constructor, 1, "length"))
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
