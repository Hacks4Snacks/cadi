package kubernetes

import (
	"strings"

	"cadi/internal/inventory"

	"go.yaml.in/yaml/v3"
)

var cryptoArguments = map[string]string{
	"tls-min-version":            "tls.min-version",
	"tls-cipher-suites":          "tls.cipher-suites",
	"cipher-suites":              "tls.cipher-suites",
	"tls-cert-file":              "tls.certificate-file",
	"tls-private-key-file":       "tls.private-key-file",
	"client-ca-file":             "tls.ca-file",
	"cert-file":                  "tls.certificate-file",
	"key-file":                   "tls.private-key-file",
	"trusted-ca-file":            "tls.ca-file",
	"peer-cert-file":             "tls.peer-certificate-file",
	"peer-key-file":              "tls.peer-private-key-file",
	"peer-trusted-ca-file":       "tls.peer-ca-file",
	"encryption-provider-config": "encryption.config-file",
}

func configuredText(node *yaml.Node) (string, bool, error) {
	value, known, err := textValue(node)
	if known && runtimeVariable.MatchString(value) {
		return "", false, nil
	}
	return value, known, err
}

func (r resource) bootstrapTLS(node *yaml.Node, field, label string) error {
	if node == nil {
		return nil
	}
	arguments := map[string][]*yaml.Node{}
	switch node.Kind {
	case yaml.MappingNode:
		for name, value := range fields(node) {
			if parameter := cryptoArguments[name]; parameter != "" {
				arguments[parameter] = append(arguments[parameter], value)
			}
		}
	case yaml.SequenceNode:
		for _, argument := range node.Content {
			if argument.Kind != yaml.MappingNode {
				return r.failure(argument, "bootstrap argument must be a name/value object")
			}
			object := fields(argument)
			name, known, err := configuredText(object["name"])
			if err != nil {
				return r.failure(argument, "bootstrap argument name must be a string")
			}
			if !known {
				r.note(argument, "bootstrap argument name is unresolved")
				continue
			}
			if parameter := cryptoArguments[name]; parameter != "" {
				arguments[parameter] = append(arguments[parameter], object["value"])
			}
		}
	default:
		return r.failure(node, "bootstrap arguments must be a map or name/value list")
	}
	if len(arguments) == 0 {
		return nil
	}
	evidence := r.at(node, field)
	var values []inventory.Attribute
	var suites []string
	tls := false
	for _, parameter := range []string{
		"tls.min-version", "tls.cipher-suites", "tls.certificate-file", "tls.private-key-file",
		"tls.ca-file", "tls.peer-certificate-file", "tls.peer-private-key-file", "tls.peer-ca-file", "encryption.config-file",
	} {
		nodes := arguments[parameter]
		if len(nodes) == 0 {
			continue
		}
		tls = tls || strings.HasPrefix(parameter, "tls.")
		if len(nodes) != 1 {
			evidence.Unresolved = append(evidence.Unresolved, parameter)
			r.note(node, "duplicate cryptographic argument; configured value is ambiguous")
			continue
		}
		value, known, err := configuredText(nodes[0])
		if err != nil {
			return r.failure(nodes[0], "cryptographic argument value must be a string")
		}
		if !known || value == "" {
			evidence.Unresolved = append(evidence.Unresolved, parameter)
			continue
		}
		if strings.HasSuffix(parameter, "-file") || parameter == "encryption.config-file" {
			if strings.Contains(value, "://") || strings.ContainsAny(value, "\x00\r\n") {
				evidence.Unresolved = append(evidence.Unresolved, parameter)
				r.note(nodes[0], "file reference is not a local path; it was not evaluated")
				continue
			}
		}
		switch parameter {
		case "tls.min-version":
			switch value {
			case "VersionTLS10", "1.0":
				value = "1.0"
			case "VersionTLS11", "1.1":
				value = "1.1"
			case "VersionTLS12", "1.2":
				value = "1.2"
			case "VersionTLS13", "1.3":
				value = "1.3"
			default:
				evidence.Unresolved = append(evidence.Unresolved, parameter)
				r.note(nodes[0], "TLS minimum-version token is not modeled")
				continue
			}
		case "tls.cipher-suites":
			valid := true
			for _, name := range strings.Split(value, ",") {
				name = strings.TrimSpace(name)
				if !strings.HasPrefix(name, "TLS_") || !resourceToken.MatchString(name) {
					valid = false
					break
				}
				suites = append(suites, name)
			}
			if !valid {
				suites = nil
				evidence.Unresolved = append(evidence.Unresolved, parameter)
				r.note(nodes[0], "TLS cipher-suite expression is not resolved")
			}
			continue
		case "encryption.config-file":
			component := inventory.ConfigurationResource(*r.identity())
			component.BOMRef = r.parent
			inventory.Property(&component, parameter, value)
			r.result.Add(component, r.at(nodes[0], field), "")
			continue
		}
		values = append(values, inventory.Attribute{Name: parameter, Value: value})
	}
	if tls {
		r.result.Add(inventory.ConfiguredTLS("Kubeadm "+label+" TLS configuration",
			inventory.TLSConfiguration{CipherSuites: suites}, values), evidence, r.parent)
	}
	return nil
}
