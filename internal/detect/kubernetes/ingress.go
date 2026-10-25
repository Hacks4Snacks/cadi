package kubernetes

import (
	"strconv"

	"ciphertrail/internal/inventory"

	"go.yaml.in/yaml/v3"
)

func (r resource) ingress(spec *yaml.Node) error {
	if err := r.mapping(spec, "Ingress spec"); err != nil {
		return err
	}
	tls := fields(spec)["tls"]
	if tls == nil {
		return nil
	}
	if tls.Kind != yaml.SequenceNode {
		return r.failure(tls, "Ingress spec.tls must be a list")
	}
	for i, declaration := range tls.Content {
		if declaration.Kind != yaml.MappingNode {
			return r.failure(declaration, "Ingress TLS entry must be an object")
		}
		attributes, unknown, err := r.parameters(declaration, []parameter{
			{"secretName", "kubernetes.secret-name", textValue},
			{"hosts", "kubernetes.hosts", stringsValue},
		})
		if err != nil {
			return err
		}
		field := "/spec/tls/" + strconv.Itoa(i)
		evidence := r.at(declaration, field)
		evidence.Unresolved = unknown
		var certificateRefs []string
		secret := fields(declaration)["secretName"]
		secretName, known, err := textValue(secret)
		if err != nil {
			return r.failure(secret, "Ingress TLS secretName must be a string")
		}
		if known && secretName != "" {
			parameters := []inventory.Attribute{
				{Name: "kubernetes.secret-name", Value: secretName},
				{Name: "scope", Value: "declared Secret reference only; target existence and certificate material are not established"},
			}
			if namespace := r.evidence.Context.Resource.Namespace; namespace != "" {
				parameters = append(parameters, inventory.Attribute{Name: "kubernetes.namespace", Value: namespace})
			}
			ref := r.result.Add(inventory.ConfiguredCertificate("Kubernetes certificate reference", "", parameters),
				r.at(secret, field+"/secretName"), r.parent)
			certificateRefs = append(certificateRefs, ref)
		} else {
			evidence.Unresolved = append(evidence.Unresolved, "kubernetes.secret-name")
		}
		r.result.Add(inventory.ConfiguredTLS("Kubernetes Ingress TLS configuration",
			inventory.TLSConfiguration{CertificateRefs: certificateRefs}, attributes), evidence, r.parent)
	}
	return nil
}
