package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Evidence describes how a component was identified, not its trustworthiness.
type Evidence struct {
	Kind       string              `json:"kind"`
	Collector  string              `json:"collector"`
	Location   string              `json:"location,omitempty"`
	Line       int                 `json:"line,omitempty"`
	Symbol     string              `json:"symbol,omitempty"`
	Time       string              `json:"time,omitempty"`
	Context    *SourceContext      `json:"context,omitempty"`
	Unresolved []string            `json:"unresolved,omitempty"`
	Parameters []ParameterEvidence `json:"parameters,omitempty"`
}

// ResourceIdentity identifies a configuration resource without assuming a deployment namespace.
type ResourceIdentity struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
}

// SourceContext locates a resource field within a structured input or embedded payload.
type SourceContext struct {
	Document     int               `json:"document,omitempty"`
	Resource     *ResourceIdentity `json:"resource,omitempty"`
	Field        string            `json:"field,omitempty"`
	RenderedFrom string            `json:"renderedFrom,omitempty"`
	ContentLine  int               `json:"contentLine,omitempty"`
}

// ParameterEvidence records a scoped declaration without asserting a runtime value.
type ParameterEvidence struct {
	Name       string `json:"name"`
	Value      string `json:"value"`
	Basis      string `json:"basis"`
	Location   string `json:"location"`
	Line       int    `json:"line,omitempty"`
	Symbol     string `json:"symbol,omitempty"`
	Limitation string `json:"limitation"`
}

// Diagnostic records an analysis limitation without evaluating cryptographic policy.
type Diagnostic struct {
	Location string `json:"location,omitempty"`
	Line     int    `json:"line,omitempty"`
	Message  string `json:"message"`
}

// Entry associates a typed component with evidence and its owning component.
type Entry struct {
	Component cdx.Component
	Evidence  Evidence
	Parent    string
}

// Dependency records a use relationship, distinct from component ownership.
type Dependency struct {
	Source string
	Target string
}

// Result is the language-independent collector output contract.
type Result struct {
	Entries      []Entry
	Dependencies []Dependency
	Properties   []cdx.Property
	Diagnostics  []Diagnostic
	err          error
}

// Collector inventories explicit inputs without making policy decisions.
type Collector interface {
	Collect(context.Context) (Result, error)
}

// Collection records a requested collector run, including partial results on failure.
type Collection struct {
	Collector string
	Target    string
	Result    Result
	Err       error
}

// Ref creates a stable, namespaced identifier from non-secret identity attributes.
func Ref(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		hash.Write([]byte(part))
		hash.Write([]byte{0})
	}
	return "urn:ciphertrail:" + hex.EncodeToString(hash.Sum(nil))
}

// Add attaches evidence and returns the component reference.
func (r *Result) Add(component cdx.Component, evidence Evidence, parent string) string {
	if component.BOMRef == "" {
		// Only public, typed component metadata is serialized here.
		identity, err := json.Marshal(component)
		if err != nil {
			r.err = errors.Join(r.err, fmt.Errorf("identify component %q: %w", component.Name, err))
			return ""
		}
		parts := []string{string(identity), parent, evidence.Kind, evidence.Location, evidence.Symbol, strconv.Itoa(evidence.Line)}
		if evidence.Context != nil {
			context, err := json.Marshal(evidence.Context)
			if err != nil {
				r.err = errors.Join(r.err, fmt.Errorf("identify structured evidence: %w", err))
				return ""
			}
			parts = append(parts, string(context))
		}
		component.BOMRef = Ref(parts...)
	}
	r.Entries = append(r.Entries, Entry{Component: component, Evidence: evidence, Parent: parent})
	return component.BOMRef
}

// Err returns failures recorded while constructing inventory entries.
func (r *Result) Err() error {
	return r.err
}

// Metadata records collection-level public context or an analysis limitation.
func (r *Result) Metadata(name, value string) {
	r.Properties = append(r.Properties, cdx.Property{Name: "ciphertrail:" + name, Value: value})
}

// DependOn associates a component with a required component without claiming ownership.
func (r *Result) DependOn(source, target string) {
	r.Dependencies = append(r.Dependencies, Dependency{Source: source, Target: target})
}

// Merge incorporates another collector's entries, relationships, context, and limitations.
func (r *Result) Merge(other Result) {
	r.Entries = append(r.Entries, other.Entries...)
	r.Dependencies = append(r.Dependencies, other.Dependencies...)
	r.Properties = append(r.Properties, other.Properties...)
	r.Diagnostics = append(r.Diagnostics, other.Diagnostics...)
	r.err = errors.Join(r.err, other.err)
}

// Algorithm constructs an algorithm asset without security or compliance judgments.
func Algorithm(name string, primitive cdx.CryptoPrimitive) cdx.Component {
	return cdx.Component{
		Type: "cryptographic-asset", Name: name,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
				Primitive: primitive,
			},
		},
	}
}

// CurveID maps Go curve names to CycloneDX identifiers, preserving other values for schema validation.
func CurveID(name string) string {
	switch name {
	case "P-224", "P-256", "P-384", "P-521":
		return "nist/" + name
	case "Ed25519":
		return "other/Ed25519"
	case "X25519":
		return "other/Curve25519"
	default:
		return name
	}
}

// GoPURL identifies a Go module without inventing a version for local code.
func GoPURL(path, version string) string {
	parts := strings.Split(path, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	result := "pkg:golang/" + strings.Join(parts, "/")
	if version != "" && version != "(devel)" {
		result += "@" + url.PathEscape(version)
	}
	return result
}

// Property appends a namespaced public-metadata property.
func Property(component *cdx.Component, name, value string) {
	if component.Properties == nil {
		component.Properties = &[]cdx.Property{}
	}
	*component.Properties = append(*component.Properties, cdx.Property{Name: "ciphertrail:" + name, Value: value})
}
