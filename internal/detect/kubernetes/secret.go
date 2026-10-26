package kubernetes

import (
	"context"
	"encoding/base64"
	"errors"

	"cadi/internal/inventory"
	"cadi/internal/material"

	"go.yaml.in/yaml/v3"
)

func (r resource) secret(ctx context.Context, node *yaml.Node) error {
	object := fields(node)
	secretType, _, err := textValue(object["type"])
	if err != nil {
		return r.failure(object["type"], "Secret type must be a string")
	}
	if secretType != "kubernetes.io/tls" {
		if templateValue(object["type"]) {
			r.note(node, "unrendered Secret type; contents were not inspected")
			return nil
		}
		r.note(node, "Secret is not kubernetes.io/tls; contents were not inspected")
		return nil
	}
	for _, name := range []string{"data", "stringData"} {
		if err := r.mapping(object[name], "Secret "+name); err != nil {
			return err
		}
	}
	data, stringData := fields(object["data"]), fields(object["stringData"])
	var failures error
	var missing []string
	for _, name := range []string{"tls.crt", "tls.key"} {
		if err := ctx.Err(); err != nil {
			return errors.Join(failures, err)
		}
		field, section := data[name], "data"
		if override := stringData[name]; override != nil {
			field, section = override, "stringData"
		}
		if field == nil {
			missing = append(missing, "kubernetes."+name)
			continue
		}
		value, known, err := textValue(field)
		if templateValue(field) {
			missing = append(missing, "kubernetes."+name)
			r.note(field, "unrendered TLS Secret field; material was not inspected")
			continue
		}
		if err != nil || !known {
			failures = errors.Join(failures, r.failure(field, "TLS Secret field must be a string"))
			continue
		}
		contents := []byte(value)
		if section == "data" {
			contents, err = base64.StdEncoding.DecodeString(value)
			if err != nil {
				failures = errors.Join(failures, r.failure(field, "invalid base64 in TLS Secret field"))
				continue
			}
		}
		evidence := r.at(field, "/"+section+"/"+name)
		evidence.Kind = "present"
		partial, recognized, err := material.Parse(contents, evidence, r.parent)
		r.result.Merge(partial)
		if err != nil || !recognized {
			failures = errors.Join(failures, r.failure(field, "invalid or unsupported cryptographic material in TLS Secret field"))
		}
	}
	if len(missing) > 0 {
		evidence := r.at(node, "")
		evidence.Unresolved = missing
		r.result.Add(inventory.ConfiguredCertificate("Kubernetes TLS Secret configuration", "", nil), evidence, r.parent)
	}
	return failures
}
