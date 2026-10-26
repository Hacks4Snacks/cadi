// Package kubernetes inventories local Kubernetes configuration without rendering or cluster access.
package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"ciphertrail/internal/detect"
	"ciphertrail/internal/input"
	"ciphertrail/internal/inventory"

	"go.yaml.in/yaml/v3"
)

// MaxManifestBytes bounds YAML/JSON parsing independently of binary/material limits.
const MaxManifestBytes int64 = 16 << 20

const maxRecognitionBytes int64 = 32 << 20

// Detector reads supported Kubernetes resources; Strict selects explicitly requested manifests.
type Detector struct{ Strict bool }

// Name identifies the built-in configuration detector.
func (Detector) Name() string { return "kubernetes" }

// Match selects YAML/JSON files, or an explicitly selected manifest with another suffix.
func (d Detector) Match(file *input.File, _ []byte) detect.Match {
	if file.HelmTemplate && !file.Explicit {
		return detect.Match{Deferred: "Helm templates require rendered YAML/JSON"}
	}
	switch strings.ToLower(filepath.Ext(file.Name)) {
	case ".yaml", ".yml", ".json":
		return detect.Match{Applicable: true}
	case ".tpl":
		return detect.Match{Applicable: d.Strict}
	default:
		return detect.Match{Applicable: d.Strict && file.Explicit}
	}
}

// Detect inventories declarations and embedded TLS material without executing input.
func (d Detector) Detect(ctx context.Context, file *input.File) (inventory.Result, bool, error) {
	var result inventory.Result
	limit := MaxManifestBytes
	if !d.Strict && !file.Explicit {
		limit = maxRecognitionBytes
	}
	data, err := file.ReadAll(ctx, limit)
	if err != nil {
		if limit > MaxManifestBytes {
			return result, false, fmt.Errorf("Kubernetes applicability undetermined (recognition limit %d bytes): %w", limit, err)
		}
		return result, false, err
	}
	if int64(len(data)) > MaxManifestBytes {
		found, err := oversizedJSONResource(ctx, data)
		if err != nil || !found {
			return result, false, err
		}
		return result, true, fmt.Errorf("Kubernetes resource exceeds the %d-byte manifest parsing limit", MaxManifestBytes)
	}
	scanner := resource{result: &result, evidence: file.Evidence, parent: file.Parent, budget: &decodeBudget{}}
	found, err := scanner.documents(ctx, data, d.Strict)
	return result, found, err
}

func oversizedJSONResource(ctx context.Context, data []byte) (bool, error) {
	if !json.Valid(data) {
		return false, fmt.Errorf("Kubernetes applicability undetermined: oversized input is not valid JSON; manifest parsing limit remains %d bytes", MaxManifestBytes)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if bytes.TrimSpace(data)[0] != '{' {
		return false, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return false, errors.New("Kubernetes JSON resource recognition failed")
	}
	if token != json.Delim('{') {
		return false, nil
	}
	apiVersion, kind := false, false
	var value json.RawMessage
	for decoder.More() {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		key, err := decoder.Token()
		if err != nil {
			return false, errors.New("Kubernetes JSON resource recognition failed")
		}
		apiVersion = apiVersion || key == "apiVersion"
		kind = kind || key == "kind"
		if apiVersion && kind {
			return true, nil
		}
		if err := decoder.Decode(&value); err != nil {
			return false, errors.New("Kubernetes JSON resource recognition failed")
		}
	}
	return false, nil
}

type resource struct {
	result   *inventory.Result
	evidence inventory.Evidence
	parent   string
	prefix   string
	offset   int
	budget   *decodeBudget
}

func (r resource) identity() *inventory.ResourceIdentity {
	context := r.evidence.Context
	if len(context.Embedded) > 0 {
		return context.Embedded[len(context.Embedded)-1].Resource
	}
	return context.Resource
}

var resourceToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)
var objectName = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)
var runtimeVariable = regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*\}`)

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
		apiVersion == "v1" && kind == "ConfigMapList" ||
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
	bootstrap := bootstrapResource(apiVersion, kind)
	pure := pureConfiguration(apiVersion, kind)
	if !(apiVersion == "cert-manager.io/v1" && kind == "Certificate") &&
		!(apiVersion == "v1" && kind == "Secret") &&
		!(apiVersion == "v1" && kind == "ConfigMap") &&
		!(apiVersion == "networking.k8s.io/v1" && kind == "Ingress") && !bootstrap && !pure {
		if len(r.evidence.Context.Embedded) > 0 {
			r.result.Metadata("unsupported-embedded-kind", apiVersion+" "+kind)
		} else {
			r.note(node, "unsupported Kubernetes resource kind: "+apiVersion+" "+kind)
		}
		return nil
	}
	metadata := map[string]*yaml.Node{}
	if !pure {
		metadata = fields(object["metadata"])
	}
	if templateValue(metadata["name"]) || templateValue(metadata["namespace"]) {
		r.note(node, "unrendered resource identity; supply rendered Helm YAML/JSON")
		return nil
	}
	name, known, nameErr := textValue(metadata["name"])
	namespace, _, namespaceErr := textValue(metadata["namespace"])
	var unresolved []string
	if bootstrap || len(r.evidence.Context.Embedded) > 0 {
		if runtimeVariable.MatchString(name) && objectName.MatchString(runtimeVariable.ReplaceAllString(name, "value")) {
			name, known = "", true
			unresolved = append(unresolved, "resource.name")
		}
		if runtimeVariable.MatchString(namespace) && objectName.MatchString(runtimeVariable.ReplaceAllString(namespace, "value")) {
			namespace = ""
			unresolved = append(unresolved, "resource.namespace")
		}
	}
	if !pure && (nameErr != nil || namespaceErr != nil || !known || len(name) > 253 ||
		(name == "" && !slices.Contains(unresolved, "resource.name")) ||
		(name != "" && !objectName.MatchString(name)) ||
		namespace != "" && (len(namespace) > 63 || !objectName.MatchString(namespace) || strings.Contains(namespace, "."))) {
		return r.failure(node, "supported resource requires a valid metadata.name and optional namespace")
	}
	identity := inventory.ResourceIdentity{APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name}
	context := *r.evidence.Context
	context.Embedded = slices.Clone(context.Embedded)
	if len(context.Embedded) == 0 {
		context.Resource, context.Unresolved = &identity, unresolved
		r.evidence.Line = r.offset + node.Line
	} else {
		last := &context.Embedded[len(context.Embedded)-1]
		last.Resource = &identity
		last.Unresolved = append(slices.Clone(last.Unresolved), unresolved...)
	}
	r.evidence.Context = &context
	r.evidence.Symbol = apiVersion + "." + kind
	r.parent = r.result.Add(inventory.ConfigurationResource(identity), r.at(node, ""), r.parent)
	if bootstrap || pure && kind != "EncryptionConfiguration" {
		return r.bootstrap(ctx, node, kind)
	}
	switch kind {
	case "Certificate":
		return r.certificate(object["spec"])
	case "Secret":
		return r.secret(ctx, node)
	case "Ingress":
		return r.ingress(object["spec"])
	case "ConfigMap":
		return r.configMap(ctx, node)
	case "EncryptionConfiguration":
		return r.encryption(node)
	}
	return nil
}

func (r resource) at(node *yaml.Node, field string) inventory.Evidence {
	evidence := r.evidence
	context := *evidence.Context
	context.Embedded = slices.Clone(context.Embedded)
	if len(context.Embedded) == 0 {
		context.Field = r.prefix + field
		if node != nil {
			evidence.Line = r.offset + node.Line
		}
	} else {
		last := &context.Embedded[len(context.Embedded)-1]
		last.Field = r.prefix + field
		if node != nil {
			last.Line = r.offset + node.Line
		}
	}
	evidence.Context = &context
	evidence.Unresolved, evidence.Parameters = nil, nil
	return evidence
}

func (r resource) failure(node *yaml.Node, message string) error {
	if len(r.evidence.Context.Embedded) > 0 {
		return fmt.Errorf("document %d, line %d, embedded line %d: %s",
			r.evidence.Context.Document, r.evidence.Line, r.offset+nodeLine(node), message)
	}
	return fmt.Errorf("document %d, line %d: %s", r.evidence.Context.Document, r.at(node, "").Line, message)
}

func nodeLine(node *yaml.Node) int {
	if node == nil {
		return 0
	}
	return node.Line
}

func (r resource) note(node *yaml.Node, message string) {
	r.result.Diagnostics = append(r.result.Diagnostics, inventory.Diagnostic{Location: r.evidence.Location,
		Line: r.at(node, "").Line, Message: fmt.Sprintf("document %d: %s", r.evidence.Context.Document, message)})
}

type documentChunk struct {
	data []byte
	line int
}

func splitDocuments(data []byte) []documentChunk {
	if bytes.HasPrefix(data, []byte{0xff, 0xfe}) || bytes.HasPrefix(data, []byte{0xfe, 0xff}) {
		// UTF-8 byte boundaries cannot frame UTF-16; use the decoder's stream support.
		return []documentChunk{{data, 1}}
	}
	var documents []documentChunk
	start, offset, line, firstLine := 0, 0, 1, 1
	body := false
	for offset < len(data) {
		end, next := len(data), len(data)
		if index := bytes.IndexAny(data[offset:], "\r\n\u0085\u2028\u2029"); index >= 0 {
			end = offset + index
			_, size := utf8.DecodeRune(data[end:])
			next = end + size
			if data[end] == '\r' && next < len(data) && data[next] == '\n' {
				next++
			}
		}
		row := data[offset:end]
		if offset == 0 {
			row = bytes.TrimPrefix(row, []byte("\xef\xbb\xbf"))
		}
		switch {
		case documentIndicator(row, "---"):
			if body && offset > start {
				documents = append(documents, documentChunk{data[start:offset], firstLine})
				start, firstLine = offset, line
			}
			body = true
		case documentIndicator(row, "..."):
			documents = append(documents, documentChunk{data[start:next], firstLine})
			start, firstLine, body = next, line+1, false
		default:
			text := bytes.TrimSpace(row)
			if len(text) > 0 && text[0] != '#' && row[0] != '%' {
				body = true
			}
		}
		offset = next
		line++
	}
	if start < len(data) {
		documents = append(documents, documentChunk{data[start:], firstLine})
	}
	return documents
}

func documentIndicator(row []byte, marker string) bool {
	return bytes.HasPrefix(row, []byte(marker)) && (len(row) == 3 || row[3] == ' ' || row[3] == '\t')
}

// malformedResourceHint is used only after decoding fails, never to exclude a valid document.
func malformedResourceHint(data []byte) bool {
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
