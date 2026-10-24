package kubernetes

import (
	"strconv"

	"ciphertrail/internal/inventory"

	"go.yaml.in/yaml/v3"
)

func (r resource) certificate(spec *yaml.Node) error {
	if err := r.mapping(spec, "Certificate spec"); err != nil {
		return err
	}
	attributes, unresolved, err := r.parameters(spec, []parameter{
		{"secretName", "cert-manager.secret-name", textValue},
		{"commonName", "cert-manager.common-name", textValue},
		{"isCA", "cert-manager.is-ca", boolValue},
		{"duration", "cert-manager.duration", durationValue},
		{"renewBefore", "cert-manager.renew-before", durationValue},
		{"usages", "cert-manager.usages", stringsValue},
		{"dnsNames", "cert-manager.dns-names", stringsValue},
	})
	if err != nil {
		return err
	}
	object := fields(spec)
	issuer := object["issuerRef"]
	if err := r.mapping(issuer, "Certificate issuerRef"); err != nil {
		return err
	}
	issuerValues, issuerUnknown, err := r.parameters(issuer, []parameter{
		{"name", "cert-manager.issuer.name", textValue},
		{"kind", "cert-manager.issuer.kind", textValue},
		{"group", "cert-manager.issuer.group", textValue},
	})
	if err != nil {
		return err
	}
	attributes = append(attributes, issuerValues...)
	unresolved = append(unresolved, issuerUnknown...)
	if issuer != nil && issuer.Tag == "!!null" {
		unresolved = append(unresolved, "cert-manager.issuer")
	}
	keyRef := ""
	key := object["privateKey"]
	if key != nil {
		if err := r.mapping(key, "Certificate privateKey"); err != nil {
			return err
		}
		keyValues, keyUnknown, err := r.parameters(key, []parameter{
			{"algorithm", "cert-manager.key-algorithm", textValue},
			{"size", "cert-manager.key-size", intValue},
			{"encoding", "cert-manager.key-encoding", textValue},
			{"rotationPolicy", "cert-manager.rotation-policy", textValue},
		})
		if err != nil {
			return err
		}
		keyEvidence := r.at(key, "/spec/privateKey")
		keyEvidence.Unresolved = keyUnknown
		if key.Tag == "!!null" {
			keyEvidence.Unresolved = append(keyEvidence.Unresolved, "cert-manager.private-key")
		}
		var algorithm string
		var size int
		for _, parameter := range keyValues {
			switch parameter.Name {
			case "cert-manager.key-algorithm":
				algorithm = parameter.Value
			case "cert-manager.key-size":
				// intValue has already checked the host integer range.
				size, err = strconv.Atoi(parameter.Value)
				if err != nil {
					return r.failure(key, "invalid key size")
				}
			}
		}
		keyRef = r.result.AddConfiguredPrivateKey("cert-manager Private key configuration", algorithm, size, keyValues, keyEvidence, r.parent)
	}
	evidence := r.at(spec, "/spec")
	evidence.Unresolved = unresolved
	r.result.Add(inventory.ConfiguredCertificate("cert-manager Certificate configuration", keyRef, attributes), evidence, r.parent)
	return nil
}
