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
	Name       string `json:"name,omitempty"`
}

// SourceContext locates a resource field within a structured input or embedded payload.
type SourceContext struct {
	Document     int               `json:"document,omitempty"`
	Resource     *ResourceIdentity `json:"resource,omitempty"`
	Field        string            `json:"field,omitempty"`
	RenderedFrom string            `json:"renderedFrom,omitempty"`
	ContentLine  int               `json:"contentLine,omitempty"`
	Unresolved   []string          `json:"unresolved,omitempty"`
	Embedded     []EmbeddedContext `json:"embedded,omitempty"`
}

// EmbeddedContext identifies a decoded document without replacing its containing source location.
type EmbeddedContext struct {
	Document   int               `json:"document,omitempty"`
	Resource   *ResourceIdentity `json:"resource,omitempty"`
	Field      string            `json:"field,omitempty"`
	File       string            `json:"file,omitempty"`
	Line       int               `json:"line,omitempty"`
	Unresolved []string          `json:"unresolved,omitempty"`
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
	Entries []Entry
	// Subjects identifies collected primary components, not ordinary dependencies.
	Subjects     []string
	Dependencies []Dependency
	Details      []RunMetadata
	Diagnostics  []Diagnostic
	Coverage     []Coverage
	err          error
}

// RunMetadata holds a public execution detail as a structured JSON value.
type RunMetadata struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
}

// ScanReportFormat identifies CipherTrail's execution report, not a CBOM.
const ScanReportFormat = "CipherTrailScanReport"

// Coverage describes analyzer execution and preparation gaps, not cryptographic policy.
type Coverage struct {
	Analyzer string `json:"analyzer"`
	Status   string `json:"status"`
	Files    int    `json:"files,omitempty"`
	Modules  int    `json:"modules,omitempty"`
	Findings int    `json:"findings,omitempty"`
	Skipped  int    `json:"skipped,omitempty"`
	Reason   string `json:"reason,omitempty"`
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

// Metadata records structured public details for the optional execution report.
func (r *Result) Metadata(name string, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		r.err = errors.Join(r.err, fmt.Errorf("encode run metadata %q: %w", name, err))
		return
	}
	r.Details = append(r.Details, RunMetadata{Name: name, Value: data})
}

// DependOn associates a component with a required component without claiming ownership.
func (r *Result) DependOn(source, target string) {
	r.Dependencies = append(r.Dependencies, Dependency{Source: source, Target: target})
}

// Merge incorporates another collector's entries, relationships, context, and limitations.
func (r *Result) Merge(other Result) {
	r.Entries = append(r.Entries, other.Entries...)
	r.Subjects = append(r.Subjects, other.Subjects...)
	r.Dependencies = append(r.Dependencies, other.Dependencies...)
	r.Details = append(r.Details, other.Details...)
	r.Diagnostics = append(r.Diagnostics, other.Diagnostics...)
	r.Coverage = append(r.Coverage, other.Coverage...)
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

const (
	OIDRSAESOAEP = "1.2.840.113549.1.1.7"
	OIDRSASSAPSS = "1.2.840.113549.1.1.10"
	OIDX25519    = "1.3.101.110"
	OIDX448      = "1.3.101.111"
	OIDEd25519   = "1.3.101.112"
	OIDEd448     = "1.3.101.113"
)

var hashAlgorithms = map[string]struct {
	primitive                       cdx.CryptoPrimitive
	family, parameter, oid, hmacOID string
}{
	"MD4":         {cdx.CryptoPrimitiveHash, "MD4", "128", "", ""},
	"MD5":         {cdx.CryptoPrimitiveHash, "MD5", "128", "1.2.840.113549.2.5", ""},
	"RIPEMD-160":  {cdx.CryptoPrimitiveHash, "RIPEMD", "160", "", ""},
	"SHA-1":       {cdx.CryptoPrimitiveHash, "SHA-1", "160", "1.3.14.3.2.26", ""},
	"SHA-224":     {cdx.CryptoPrimitiveHash, "SHA-2", "224", "2.16.840.1.101.3.4.2.4", "1.2.840.113549.2.8"},
	"SHA-256":     {cdx.CryptoPrimitiveHash, "SHA-2", "256", "2.16.840.1.101.3.4.2.1", "1.2.840.113549.2.9"},
	"SHA-384":     {cdx.CryptoPrimitiveHash, "SHA-2", "384", "2.16.840.1.101.3.4.2.2", "1.2.840.113549.2.10"},
	"SHA-512":     {cdx.CryptoPrimitiveHash, "SHA-2", "512", "2.16.840.1.101.3.4.2.3", "1.2.840.113549.2.11"},
	"SHA-512/224": {cdx.CryptoPrimitiveHash, "SHA-2", "224", "2.16.840.1.101.3.4.2.5", ""},
	"SHA-512/256": {cdx.CryptoPrimitiveHash, "SHA-2", "256", "2.16.840.1.101.3.4.2.6", ""},
	"SHA3-224":    {cdx.CryptoPrimitiveHash, "SHA-3", "224", "2.16.840.1.101.3.4.2.7", "2.16.840.1.101.3.4.2.13"},
	"SHA3-256":    {cdx.CryptoPrimitiveHash, "SHA-3", "256", "2.16.840.1.101.3.4.2.8", "2.16.840.1.101.3.4.2.14"},
	"SHA3-384":    {cdx.CryptoPrimitiveHash, "SHA-3", "384", "2.16.840.1.101.3.4.2.9", "2.16.840.1.101.3.4.2.15"},
	"SHA3-512":    {cdx.CryptoPrimitiveHash, "SHA-3", "512", "2.16.840.1.101.3.4.2.10", "2.16.840.1.101.3.4.2.16"},
	"SHAKE128":    {cdx.CryptoPrimitiveXOF, "SHA-3", "128", "2.16.840.1.101.3.4.2.11", ""},
	"SHAKE256":    {cdx.CryptoPrimitiveXOF, "SHA-3", "256", "2.16.840.1.101.3.4.2.12", ""},
	"BLAKE2b":     {cdx.CryptoPrimitiveHash, "BLAKE2", "", "", ""},
	"BLAKE2s":     {cdx.CryptoPrimitiveHash, "BLAKE2", "", "", ""},
	"BLAKE2b-256": {cdx.CryptoPrimitiveHash, "BLAKE2", "256", "", ""},
	"BLAKE2b-384": {cdx.CryptoPrimitiveHash, "BLAKE2", "384", "", ""},
	"BLAKE2b-512": {cdx.CryptoPrimitiveHash, "BLAKE2", "512", "", ""},
	"BLAKE2s-128": {cdx.CryptoPrimitiveHash, "BLAKE2", "128", "", ""},
	"BLAKE2s-256": {cdx.CryptoPrimitiveHash, "BLAKE2", "256", "", ""},
}

// HashAlgorithm constructs a modeled hash identity, not a name-based export heuristic.
func HashAlgorithm(name string) (cdx.Component, bool) {
	facts, known := hashAlgorithms[name]
	if !known {
		return cdx.Component{}, false
	}
	component := Algorithm(name, facts.primitive)
	properties := component.CryptoProperties
	properties.OID = facts.oid
	properties.AlgorithmProperties.AlgorithmFamily = facts.family
	properties.AlgorithmProperties.ParameterSetIdentifier = facts.parameter
	properties.AlgorithmProperties.CryptoFunctions = &[]cdx.CryptoFunction{cdx.CryptoFunctionDigest}
	return component, true
}

// HMACAlgorithm keeps digest identity separate from the independently resolved key length.
func HMACAlgorithm(hash string) cdx.Component {
	name := "HMAC"
	if hash != "" {
		name += "-" + hash
	}
	component := Algorithm(name, cdx.CryptoPrimitiveMAC)
	component.CryptoProperties.AlgorithmProperties.AlgorithmFamily = "HMAC"
	component.CryptoProperties.AlgorithmProperties.CryptoFunctions = &[]cdx.CryptoFunction{cdx.CryptoFunctionTag}
	component.CryptoProperties.OID = hashAlgorithms[hash].hmacOID
	return component
}

var aesOIDs = map[cdx.CryptoAlgorithmMode]map[string]string{
	cdx.CryptoAlgorithmModeECB: {"128": "2.16.840.1.101.3.4.1.1", "192": "2.16.840.1.101.3.4.1.21", "256": "2.16.840.1.101.3.4.1.41"},
	cdx.CryptoAlgorithmModeCBC: {"128": "2.16.840.1.101.3.4.1.2", "192": "2.16.840.1.101.3.4.1.22", "256": "2.16.840.1.101.3.4.1.42"},
	cdx.CryptoAlgorithmModeOFB: {"128": "2.16.840.1.101.3.4.1.3", "192": "2.16.840.1.101.3.4.1.23", "256": "2.16.840.1.101.3.4.1.43"},
	cdx.CryptoAlgorithmModeCFB: {"128": "2.16.840.1.101.3.4.1.4", "192": "2.16.840.1.101.3.4.1.24", "256": "2.16.840.1.101.3.4.1.44"},
	cdx.CryptoAlgorithmModeGCM: {"128": "2.16.840.1.101.3.4.1.6", "192": "2.16.840.1.101.3.4.1.26", "256": "2.16.840.1.101.3.4.1.46"},
	cdx.CryptoAlgorithmModeCCM: {"128": "2.16.840.1.101.3.4.1.7", "192": "2.16.840.1.101.3.4.1.27", "256": "2.16.840.1.101.3.4.1.47"},
}

// AESOID returns a CSOR identifier only for an explicitly resolved mode and key size.
func AESOID(mode cdx.CryptoAlgorithmMode, parameter string) string {
	return aesOIDs[mode][parameter]
}

// CurveID maps Go curve names to CycloneDX identifiers, preserving other values for schema validation.
func CurveID(name string) string {
	switch name {
	case "P-224", "P-256", "P-384", "P-521":
		return "nist/" + name
	case "Ed25519":
		return "other/Ed25519"
	case "Ed448":
		return "other/Ed448"
	case "X25519":
		return "other/Curve25519"
	case "X448":
		return "other/Curve448"
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
