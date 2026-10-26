package kubernetes

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"

	"ciphertrail/internal/inventory"
	"ciphertrail/internal/material"

	"go.yaml.in/yaml/v3"
)

func (r resource) configMap(ctx context.Context, node *yaml.Node) error {
	object := fields(node)
	var failures error
	dataFields := fields(object["data"])
	for _, section := range []string{"data", "binaryData"} {
		mapping := object[section]
		if err := r.mapping(mapping, "ConfigMap "+section); err != nil {
			failures = errors.Join(failures, err)
			continue
		}
		if mapping == nil || mapping.Tag == "!!null" {
			continue
		}
		for i := 0; i+1 < len(mapping.Content); i += 2 {
			key, value := mapping.Content[i].Value, mapping.Content[i+1]
			if err := ctx.Err(); err != nil {
				return errors.Join(failures, err)
			}
			if section == "binaryData" && dataFields[key] != nil {
				failures = errors.Join(failures, r.failure(value, "ConfigMap key appears in both data and binaryData"))
				continue
			}
			if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
				failures = errors.Join(failures, r.failure(value, "ConfigMap values must be strings"))
				continue
			}
			content := []byte(value.Value)
			if section == "binaryData" {
				var err error
				content, err = base64.StdEncoding.DecodeString(value.Value)
				if err != nil {
					failures = errors.Join(failures, r.failure(value, "invalid base64 in ConfigMap binaryData"))
					continue
				}
			}
			field := "/" + section + "/" + pointerSegment(key)
			failures = errors.Join(failures, r.embedded(ctx, content, r.at(value, field), inventory.EmbeddedContext{}))
		}
	}
	return failures
}

func (r resource) embedded(ctx context.Context, data []byte, evidence inventory.Evidence, origin inventory.EmbeddedContext) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("#!")) {
		return nil
	}
	pem := bytes.HasPrefix(trimmed, []byte("-----BEGIN "))
	if pem && len(evidence.Context.Embedded) >= MaxEmbeddedDepth {
		return fmt.Errorf("embedded configuration exceeds %d decoded levels", MaxEmbeddedDepth)
	}
	context := *evidence.Context
	context.Embedded = slices.Clone(context.Embedded)
	if !pem || origin.File != "" || len(origin.Unresolved) != 0 {
		context.Embedded = append(context.Embedded, origin)
	}
	evidence.Context = &context
	if pem {
		r.budget.bytes += int64(len(data))
		if int64(len(data)) > MaxManifestBytes || r.budget.bytes > MaxDecodedBytes {
			return fmt.Errorf("embedded material exceeds decoded byte limits")
		}
		evidence.Kind = "present"
		partial, recognized, err := material.Parse(data, evidence, r.parent)
		r.result.Merge(partial)
		if err != nil || !recognized {
			return fmt.Errorf("invalid or unsupported embedded cryptographic material")
		}
		return nil
	}
	child := r
	child.evidence = evidence
	_, err := child.documents(ctx, data, false)
	return err
}

func pointerSegment(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}
