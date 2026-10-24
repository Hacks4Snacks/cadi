package artifact

import (
	"bufio"
	"bytes"
	"path/filepath"
	"regexp"
	"strings"

	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

var publicSelector = regexp.MustCompile(`^[A-Za-z0-9_:@!+,.=?/-]+$`)

func opensslCandidate(path string) bool {
	return strings.Contains(strings.ToLower(filepath.Base(path)), "openssl") && strings.HasSuffix(strings.ToLower(path), ".cnf")
}

func parseOpenSSL(result *inventory.Result, data []byte, evidence inventory.Evidence, parent string) (bool, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	section, line, found := "", 0, false
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(text, ".include") {
			result.Diagnostics = append(result.Diagnostics, inventory.Diagnostic{Location: evidence.Location, Message: "OpenSSL include is not expanded"})
		}
		if strings.HasPrefix(text, "[") && strings.HasSuffix(text, "]") {
			section = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(text, "["), "]"))
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		switch key {
		case "MinProtocol", "MaxProtocol", "CipherString", "Ciphersuites", "Groups", "SignatureAlgorithms":
		default:
			continue
		}
		value, _, _ = strings.Cut(value, "#")
		value = strings.TrimSpace(value)
		if !publicSelector.MatchString(value) {
			value = "unknown: expression is not resolved"
		}
		component := cdx.Component{Type: "cryptographic-asset", Name: "OpenSSL TLS configuration",
			CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeProtocol,
				ProtocolProperties: &cdx.CryptoProtocolProperties{Type: cdx.CryptoProtocolTypeTLS}}}
		inventory.Property(&component, "openssl."+key, value)
		inventory.Property(&component, "openssl.section", section)
		inventory.Property(&component, "scope", "configuration declaration; section activation and selectors are not evaluated")
		e := evidence
		e.Kind, e.Line = "configured", line
		result.Add(component, e, parent)
		found = true
	}
	return found, scanner.Err()
}
