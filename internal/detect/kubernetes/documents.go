package kubernetes

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"

	"cadi/internal/inventory"

	"go.yaml.in/yaml/v3"
)

// MaxEmbeddedDepth limits decoded configuration nesting independently of YAML node depth.
const MaxEmbeddedDepth = 8

// MaxDecodedBytes bounds cumulative root and embedded document bytes per input file.
const MaxDecodedBytes int64 = 32 << 20

type decodeBudget struct {
	bytes int64
	nodes int
}

func (r resource) documents(ctx context.Context, data []byte, strict bool) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if int64(len(data)) > MaxManifestBytes {
		return false, fmt.Errorf("embedded document exceeds the %d-byte limit", MaxManifestBytes)
	}
	r.budget.bytes += int64(len(data))
	if r.budget.bytes > MaxDecodedBytes {
		return false, fmt.Errorf("cumulative decoded content exceeds the %d-byte limit", MaxDecodedBytes)
	}
	found, documentNumber := false, 0
	var failures error
	for _, chunk := range splitDocuments(data) {
		decoder := yaml.NewDecoder(bytes.NewReader(chunk.data))
		for {
			if err := ctx.Err(); err != nil {
				return found, errors.Join(failures, err)
			}
			var document yaml.Node
			decodeErr := decoder.Decode(&document)
			if errors.Is(decodeErr, io.EOF) {
				break
			}
			documentNumber++
			scanner := r
			scanner.prefix, scanner.offset = "", chunk.line-1
			scanner.evidence.Kind, scanner.evidence.Collector = "configured", "kubernetes"
			if r.evidence.Context != nil && len(r.evidence.Context.Embedded) > 0 {
				context := *r.evidence.Context
				context.Embedded = slices.Clone(context.Embedded)
				last := &context.Embedded[len(context.Embedded)-1]
				last.Document = documentNumber
				scanner.evidence.Context = &context
			} else {
				scanner.evidence.Context = &inventory.SourceContext{Document: documentNumber, RenderedFrom: renderedSource(&document)}
				scanner.evidence.Line = chunk.line
			}
			if decodeErr != nil {
				if bytes.Contains(chunk.data, []byte("{{")) {
					scanner.note(nil, "unrendered template not analyzed; supply rendered Helm YAML/JSON")
					found = true
					break
				}
				if strict || malformedResourceHint(chunk.data) {
					found = true
					failures = errors.Join(failures, scanner.failure(nil, "invalid YAML/JSON"))
				}
				break
			}
			if len(document.Content) == 0 {
				continue
			}
			root := document.Content[0]
			header := fields(root)
			if header["apiVersion"] == nil || header["kind"] == nil {
				continue
			}
			found = true
			if len(scanner.evidence.Context.Embedded) > MaxEmbeddedDepth {
				return found, errors.Join(failures, fmt.Errorf("embedded configuration exceeds %d decoded levels", MaxEmbeddedDepth))
			}
			if err := validateNodes(ctx, root, 0, &r.budget.nodes); err != nil {
				if ctx.Err() != nil {
					return found, errors.Join(failures, ctx.Err())
				}
				if errors.Is(err, errComplexMappingKey) && bytes.Contains(chunk.data, []byte("{{")) {
					scanner.note(root, "unrendered template not analyzed; supply rendered Helm YAML/JSON")
					continue
				}
				failures = errors.Join(failures, scanner.failure(root, err.Error()))
				continue
			}
			failures = errors.Join(failures, scanner.inspect(ctx, root, "", inventory.ResourceIdentity{}))
		}
	}
	return found, failures
}
