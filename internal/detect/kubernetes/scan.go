// Package kubernetes inventories local Kubernetes configuration without rendering or cluster access.
package kubernetes

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"ciphertrail/internal/input"
	"ciphertrail/internal/inventory"

	"go.yaml.in/yaml/v3"
)

// MaxManifestBytes bounds YAML/JSON parsing independently of binary/material limits.
const MaxManifestBytes int64 = 16 << 20

// Detector reads supported Kubernetes resources; Strict selects explicitly requested manifests.
type Detector struct{ Strict bool }

// Name identifies the built-in configuration detector.
func (Detector) Name() string { return "kubernetes" }

// Match selects YAML/JSON files, or an explicitly selected manifest with another suffix.
func (d Detector) Match(file *input.File, _ []byte) bool {
	switch strings.ToLower(filepath.Ext(file.Name)) {
	case ".yaml", ".yml", ".json":
		return true
	case ".tpl":
		return d.Strict
	default:
		return d.Strict && file.Explicit
	}
}

// Detect inventories declarations and embedded TLS material without executing input.
func (d Detector) Detect(ctx context.Context, file *input.File) (inventory.Result, bool, error) {
	var result inventory.Result
	data, err := file.ReadAll(ctx, MaxManifestBytes)
	if err != nil {
		return result, false, err
	}
	found, count, documentNumber := false, 0, 0
	var failures error
	for _, chunk := range splitDocuments(data) {
		if err := ctx.Err(); err != nil {
			return result, found, errors.Join(failures, err)
		}
		var document yaml.Node
		decoder := yaml.NewDecoder(bytes.NewReader(chunk.data))
		decodeErr := decoder.Decode(&document)
		if errors.Is(decodeErr, io.EOF) {
			continue
		}
		documentNumber++
		if decodeErr == nil {
			var extra yaml.Node
			if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
				decodeErr = fmt.Errorf("expected a single document")
			}
		}
		if decodeErr != nil {
			if bytes.Contains(chunk.data, []byte("{{")) {
				templateNote(&result, file, documentNumber, chunk.line)
				found = true
				continue
			}
			if d.Strict || looksLikeResource(chunk.data) {
				found = true
				failures = errors.Join(failures, fmt.Errorf("document %d: invalid YAML/JSON", documentNumber))
			}
			continue
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
		if err := validateNodes(ctx, root, 0, &count); err != nil {
			if errors.Is(err, errComplexMappingKey) && bytes.Contains(chunk.data, []byte("{{")) {
				templateNote(&result, file, documentNumber, chunk.line)
				continue
			}
			failures = errors.Join(failures, fmt.Errorf("document %d: %w", documentNumber, err))
			continue
		}
		evidence := file.Evidence
		evidence.Kind, evidence.Collector = "configured", "kubernetes"
		evidence.Context = &inventory.SourceContext{Document: documentNumber, RenderedFrom: renderedSource(&document)}
		scanner := resource{result: &result, evidence: evidence, parent: file.Parent, offset: chunk.line - 1}
		failures = errors.Join(failures, scanner.inspect(ctx, root, "", inventory.ResourceIdentity{}))
	}
	if found {
		result.Metadata("analysis-scope", "local Kubernetes declarations and embedded material only; no Helm rendering, cluster access, issuance, deployment, key-pair validation, trust, or protocol negotiation is established")
	}
	return result, found, failures
}

type resource struct {
	result   *inventory.Result
	evidence inventory.Evidence
	parent   string
	prefix   string
	offset   int
}

var resourceToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)
var objectName = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)

func (r resource) inspect(ctx context.Context, node *yaml.Node, prefix string, implied inventory.ResourceIdentity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.prefix = prefix
	if node.Kind != yaml.MappingNode {
		return r.failure(node, "resource must be an object")
	}
	object := fields(node)
	if templateValue(object["apiVersion"]) || templateValue(object["kind"]) {
		r.note(node, "unrendered resource identity; supply rendered Helm YAML/JSON")
		return nil
	}
	apiVersion, _, apiErr := textValue(object["apiVersion"])
	kind, _, kindErr := textValue(object["kind"])
	if apiVersion == "" {
		apiVersion = implied.APIVersion
	}
	if kind == "" {
		kind = implied.Kind
	}
	if apiErr != nil || kindErr != nil || len(apiVersion) > 317 || len(kind) > 128 ||
		!resourceToken.MatchString(apiVersion) || !resourceToken.MatchString(kind) {
		return r.failure(node, "resource apiVersion and kind must be valid strings")
	}
	if implied.Kind != "" && (kind != implied.Kind || apiVersion != implied.APIVersion) {
		return r.failure(node, "resource identity does not match its typed List")
	}
	if apiVersion == "v1" && kind == "List" ||
		apiVersion == "v1" && kind == "SecretList" ||
		apiVersion == "cert-manager.io/v1" && kind == "CertificateList" ||
		apiVersion == "networking.k8s.io/v1" && kind == "IngressList" {
		items := object["items"]
		if items == nil || items.Kind != yaml.SequenceNode {
			return r.failure(node, "resource List requires an items array")
		}
		var itemType inventory.ResourceIdentity
		if kind != "List" {
			itemType = inventory.ResourceIdentity{APIVersion: apiVersion, Kind: strings.TrimSuffix(kind, "List")}
		}
		var failures error
		for i, item := range items.Content {
			failures = errors.Join(failures, r.inspect(ctx, item, prefix+"/items/"+strconv.Itoa(i), itemType))
		}
		return failures
	}
	if !(apiVersion == "cert-manager.io/v1" && kind == "Certificate") &&
		!(apiVersion == "v1" && kind == "Secret") &&
		!(apiVersion == "networking.k8s.io/v1" && kind == "Ingress") {
		r.note(node, "unsupported Kubernetes resource kind: "+apiVersion+" "+kind)
		return nil
	}
	metadata := fields(object["metadata"])
	if templateValue(metadata["name"]) || templateValue(metadata["namespace"]) {
		r.note(node, "unrendered resource identity; supply rendered Helm YAML/JSON")
		return nil
	}
	name, known, nameErr := textValue(metadata["name"])
	namespace, _, namespaceErr := textValue(metadata["namespace"])
	if nameErr != nil || namespaceErr != nil || !known || len(name) > 253 || !objectName.MatchString(name) ||
		namespace != "" && (len(namespace) > 63 || !objectName.MatchString(namespace) || strings.Contains(namespace, ".")) {
		return r.failure(node, "supported resource requires a valid metadata.name and optional namespace")
	}
	identity := inventory.ResourceIdentity{APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name}
	context := *r.evidence.Context
	context.Resource = &identity
	r.evidence.Context = &context
	r.evidence.Symbol = apiVersion + "." + kind
	r.evidence.Line = r.offset + node.Line
	r.parent = r.result.Add(inventory.ConfigurationResource(identity), r.at(node, ""), r.parent)
	switch kind {
	case "Certificate":
		return r.certificate(object["spec"])
	case "Secret":
		return r.secret(ctx, node)
	case "Ingress":
		return r.ingress(object["spec"])
	}
	return nil
}

func (r resource) at(node *yaml.Node, field string) inventory.Evidence {
	evidence := r.evidence
	context := *evidence.Context
	context.Field = r.prefix + field
	evidence.Context = &context
	if node != nil {
		evidence.Line = r.offset + node.Line
	}
	evidence.Unresolved, evidence.Parameters = nil, nil
	return evidence
}

func (r resource) failure(node *yaml.Node, message string) error {
	return fmt.Errorf("document %d, line %d: %s", r.evidence.Context.Document, r.at(node, "").Line, message)
}

func (r resource) note(node *yaml.Node, message string) {
	r.result.Diagnostics = append(r.result.Diagnostics, inventory.Diagnostic{Location: r.evidence.Location,
		Line: r.at(node, "").Line, Message: fmt.Sprintf("document %d: %s", r.evidence.Context.Document, message)})
}

type documentChunk struct {
	data []byte
	line int
}

func templateNote(result *inventory.Result, file *input.File, document, line int) {
	result.Diagnostics = append(result.Diagnostics, inventory.Diagnostic{Location: file.Evidence.Location,
		Line: line, Message: fmt.Sprintf("document %d: unrendered template not analyzed; supply rendered Helm YAML/JSON", document)})
}

func splitDocuments(data []byte) []documentChunk {
	var documents []documentChunk
	start, offset, line, firstLine := 0, 0, 1, 1
	for _, row := range bytes.SplitAfter(data, []byte{'\n'}) {
		text := strings.TrimRight(string(row), "\r\n")
		if strings.HasPrefix(text, "---") {
			tail := strings.TrimSpace(text[3:])
			if tail == "" || strings.HasPrefix(tail, "#") {
				if offset > start {
					documents = append(documents, documentChunk{data[start:offset], firstLine})
				}
				start, firstLine = offset, line
			}
		}
		offset += len(row)
		line++
	}
	if start < len(data) {
		documents = append(documents, documentChunk{data[start:], firstLine})
	}
	return documents
}

func looksLikeResource(data []byte) bool {
	return (bytes.Contains(data, []byte("apiVersion:")) || bytes.Contains(data, []byte(`"apiVersion"`))) &&
		(bytes.Contains(data, []byte("kind:")) || bytes.Contains(data, []byte(`"kind"`)))
}

func renderedSource(document *yaml.Node) string {
	comments := document.HeadComment
	if len(document.Content) > 0 {
		root := document.Content[0]
		comments += "\n" + root.HeadComment
		if len(root.Content) > 0 {
			comments += "\n" + root.Content[0].HeadComment
		}
	}
	for _, comment := range strings.Split(comments, "\n") {
		text := strings.TrimSpace(strings.TrimPrefix(comment, "#"))
		if value, ok := strings.CutPrefix(text, "Source: "); ok && resourceToken.MatchString(value) &&
			!path.IsAbs(value) && path.Clean(value) == value && !strings.HasPrefix(value, "../") {
			return value
		}
	}
	return ""
}
