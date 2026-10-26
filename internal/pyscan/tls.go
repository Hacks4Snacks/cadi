package pyscan

import (
	"strings"

	"cadi/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func configuredTLS() cdx.Component {
	return inventory.ConfiguredTLS("Python TLS configuration", inventory.TLSConfiguration{}, nil)
}

func enumProperty(component *cdx.Component, evidence *inventory.Evidence, name string, v value, choices map[string]string) {
	if resolved, ok := choices[symbol(&v)]; ok {
		inventory.Property(component, name, resolved)
	} else {
		evidence.Unresolved = append(evidence.Unresolved, name)
	}
}

func textProperty(component *cdx.Component, evidence *inventory.Evidence, name string, v value) {
	text, known := literalText(v)
	if known && !strings.ContainsAny(text, "\x00\r\n") {
		inventory.Property(component, name, text)
	} else {
		evidence.Unresolved = append(evidence.Unresolved, name)
	}
}

func supplied(call value, index int, name string) bool {
	_, keyword := call.Keywords[name]
	return keyword || index >= 0 && index < len(call.Args)
}

func sslCall(name string, call value, evidence *inventory.Evidence) (cdx.Component, bool) {
	component := configuredTLS()
	switch name {
	case "ssl.SSLContext":
		enumProperty(&component, evidence, "tls.protocol-selector", argument(call, 0, "protocol"), map[string]string{
			"ssl.PROTOCOL_TLS": "PROTOCOL_TLS", "ssl.PROTOCOL_TLS_CLIENT": "PROTOCOL_TLS_CLIENT",
			"ssl.PROTOCOL_TLS_SERVER": "PROTOCOL_TLS_SERVER", "ssl.PROTOCOL_SSLv23": "PROTOCOL_SSLv23",
			"ssl.PROTOCOL_TLSv1": "PROTOCOL_TLSv1", "ssl.PROTOCOL_TLSv1_1": "PROTOCOL_TLSv1_1",
			"ssl.PROTOCOL_TLSv1_2": "PROTOCOL_TLSv1_2",
		})
	case "ssl.create_default_context", "ssl._create_unverified_context":
	case "ssl.SSLContext.wrap_socket", "ssl.SSLContext.wrap_bio":
	case "ssl.SSLContext.set_ciphers":
		textProperty(&component, evidence, "tls.openssl-cipher-selector", argument(call, 0, "ciphers"))
	case "ssl.SSLContext.load_cert_chain":
		textProperty(&component, evidence, "tls.certificate-file", argument(call, 0, "certfile"))
		if supplied(call, 1, "keyfile") {
			textProperty(&component, evidence, "tls.private-key-file", argument(call, 1, "keyfile"))
		}
	case "ssl.SSLContext.load_verify_locations":
		for index, field := range []string{"cafile", "capath"} {
			if supplied(call, index, field) {
				property := "tls.ca-file"
				if index == 1 {
					property = "tls.ca-directory"
				}
				textProperty(&component, evidence, property, argument(call, index, field))
			}
		}
		if supplied(call, 2, "cadata") {
			inventory.Property(&component, "tls.ca-data", "supplied inline; contents are not inspected")
		}
	default:
		return cdx.Component{}, false
	}
	return component, true
}

func sslSetting(assignment setting, evidence *inventory.Evidence) (cdx.Component, bool) {
	component := configuredTLS()
	switch assignment.Attribute {
	case "minimum_version", "maximum_version":
		name := "tls.min-version"
		if assignment.Attribute == "maximum_version" {
			name = "tls.max-version"
		}
		enumProperty(&component, evidence, name, assignment.Value, map[string]string{
			"ssl.TLSVersion.SSLv3": "SSLv3", "ssl.TLSVersion.TLSv1": "1.0",
			"ssl.TLSVersion.TLSv1_1": "1.1", "ssl.TLSVersion.TLSv1_2": "1.2",
			"ssl.TLSVersion.TLSv1_3":           "1.3",
			"ssl.TLSVersion.MINIMUM_SUPPORTED": "MINIMUM_SUPPORTED",
			"ssl.TLSVersion.MAXIMUM_SUPPORTED": "MAXIMUM_SUPPORTED",
		})
	case "verify_mode":
		enumProperty(&component, evidence, "tls.verify-mode", assignment.Value, map[string]string{
			"ssl.CERT_NONE": "CERT_NONE", "ssl.CERT_OPTIONAL": "CERT_OPTIONAL", "ssl.CERT_REQUIRED": "CERT_REQUIRED",
		})
	case "check_hostname":
		if assignment.Value.Kind == "bool" {
			inventory.Property(&component, "tls.check-hostname", assignment.Value.Text)
		} else {
			evidence.Unresolved = append(evidence.Unresolved, "tls.check-hostname")
		}
	default:
		return cdx.Component{}, false
	}
	return component, true
}
