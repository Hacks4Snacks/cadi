package material

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"cadi/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"golang.org/x/crypto/ssh"
)

// Parse inventories recognized PEM, DER, and SSH authorized-key encodings.
func Parse(data []byte, evidence inventory.Evidence, parent string) (inventory.Result, bool, error) {
	var result inventory.Result
	if bytes.Contains(data, []byte("-----BEGIN ")) {
		rest := data
		for bytes.Contains(rest, []byte("-----BEGIN ")) {
			start := bytes.Index(rest, []byte("-----BEGIN "))
			block, remaining := pem.Decode(rest)
			if block == nil {
				return result, true, fmt.Errorf("malformed PEM in %s", evidence.Location)
			}
			consumed := len(rest) - len(remaining)
			if bytes.Count(rest[:consumed], []byte("-----BEGIN ")) != 1 {
				return result, true, fmt.Errorf("malformed PEM prefix in %s", evidence.Location)
			}
			blockEvidence := evidence
			line := bytes.Count(data[:len(data)-len(rest)+start], []byte{'\n'}) + 1
			if evidence.Context == nil {
				blockEvidence.Line = line
			} else {
				context := *evidence.Context
				context.ContentLine = line
				blockEvidence.Context = &context
			}
			rest = remaining
			if err := parseBlock(&result, block, blockEvidence, parent); err != nil {
				return result, true, fmt.Errorf("%s: %w", evidence.Location, err)
			}
		}
		return result, true, nil
	}
	var trimmed []byte
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) != 0 && line[0] != '#' {
			trimmed = line
			break
		}
	}
	if len(trimmed) == 0 && filepath.Base(evidence.Location) == "authorized_keys" {
		result.Diagnostics = append(result.Diagnostics, inventory.Diagnostic{Location: evidence.Location, Message: "authorized-key file has no key entries"})
		return result, true, nil
	}
	if bytes.HasPrefix(trimmed, []byte("ssh-")) || bytes.HasPrefix(trimmed, []byte("ecdsa-")) ||
		bytes.HasPrefix(trimmed, []byte("sk-")) || bytes.Contains(trimmed, []byte(" ssh-")) ||
		bytes.Contains(trimmed, []byte(" ecdsa-")) {
		for _, line := range bytes.Split(data, []byte{'\n'}) {
			line = bytes.TrimSuffix(line, []byte{'\r'})
			line = bytes.TrimSpace(line)
			if len(line) == 0 || line[0] == '#' {
				continue
			}
			if bytes.ContainsRune(line, '\r') {
				return result, true, fmt.Errorf("embedded carriage return in SSH key entry")
			}
			key, _, _, rest, err := ssh.ParseAuthorizedKey(line)
			if err != nil || len(bytes.TrimSpace(rest)) != 0 {
				return result, true, fmt.Errorf("malformed SSH public key entry")
			}
			if _, err := AddSSHKey(&result, key, evidence, parent, "OpenSSH"); err != nil {
				return result, true, err
			}
		}
		return result, true, nil
	}
	if certificate, err := x509.ParseCertificate(data); err == nil {
		_, err := AddCertificate(&result, certificate, evidence, parent)
		return result, true, err
	}
	parsers := []func([]byte) (any, error){
		x509.ParsePKCS8PrivateKey, x509.ParsePKIXPublicKey,
		func(data []byte) (any, error) { return x509.ParsePKCS1PrivateKey(data) },
		func(data []byte) (any, error) { return x509.ParsePKCS1PublicKey(data) },
		func(data []byte) (any, error) { return x509.ParseECPrivateKey(data) },
	}
	for _, parse := range parsers {
		if key, err := parse(data); err == nil {
			_, err := AddKey(&result, key, evidence, parent, "DER")
			return result, true, err
		}
	}
	return result, false, nil
}

func parseBlock(result *inventory.Result, block *pem.Block, evidence inventory.Evidence, parent string) error {
	if block.Type == "ENCRYPTED PRIVATE KEY" || strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
		encryptedKey(result, evidence, parent)
		return nil
	}
	var key any
	var err error
	switch block.Type {
	case "CERTIFICATE":
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse X.509 certificate: %w", err)
		}
		_, err = AddCertificate(result, certificate, evidence, parent)
		return err
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "PUBLIC KEY":
		key, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
	case "OPENSSH PRIVATE KEY":
		key, err = ssh.ParseRawPrivateKey(pem.EncodeToMemory(block))
		var encrypted *ssh.PassphraseMissingError
		if errors.As(err, &encrypted) {
			encryptedKey(result, evidence, parent)
			return nil
		}
	default:
		return errors.New("unsupported PEM block type")
	}
	if err != nil {
		return fmt.Errorf("parse %s: %w", block.Type, err)
	}
	_, err = AddKey(result, key, evidence, parent, "PEM")
	return err
}

func encryptedKey(result *inventory.Result, evidence inventory.Evidence, parent string) {
	component := cdx.Component{
		Type: "cryptographic-asset", Name: "Encrypted private key",
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:                       cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{Type: cdx.RelatedCryptoMaterialTypePrivateKey, Format: "PEM"},
		},
	}
	evidence.Unresolved = append([]string{"key-algorithm", "key-size-bits"}, evidence.Unresolved...)
	result.Add(component, evidence, parent)
	result.Diagnostics = append(result.Diagnostics, inventory.Diagnostic{Location: evidence.Location, Message: "encrypted private-key parameters are unavailable; no decryption attempted"})
}
