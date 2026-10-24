package inventory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func decimal(value int) string { return strconv.Itoa(value) }

// EncodeOptions controls inventory scope, not cryptographic policy.
type EncodeOptions struct {
	IncludeDependencies bool
}

// Encode constructs a validated, crypto-focused CycloneDX 1.7 document.
func Encode(collections []Collection) ([]byte, error) {
	return EncodeWithOptions(collections, EncodeOptions{})
}

// EncodeWithOptions optionally includes the complete collected dependency inventory.
func EncodeWithOptions(collections []Collection, options EncodeOptions) ([]byte, error) {
	components := make(map[string]*cdx.Component)
	edges := make(map[string]map[string]bool)
	owners := make(map[string]map[string]bool)
	var metadata []cdx.Property
	incomplete := false
	for _, collection := range collections {
		if collection.Result.err != nil {
			return nil, collection.Result.err
		}
		status := "succeeded"
		if collection.Err != nil {
			incomplete = true
			status = "incomplete"
		}
		outcome := struct {
			Collector   string         `json:"collector"`
			Target      string         `json:"target"`
			Status      string         `json:"status"`
			Error       string         `json:"error,omitempty"`
			Properties  []cdx.Property `json:"properties,omitempty"`
			Diagnostics []Diagnostic   `json:"diagnostics,omitempty"`
		}{Collector: collection.Collector, Target: collection.Target, Status: status,
			Properties: slices.Clone(collection.Result.Properties), Diagnostics: collection.Result.Diagnostics}
		slices.SortFunc(outcome.Properties, compareProperty)
		outcome.Properties = slices.Compact(outcome.Properties)
		if collection.Err != nil {
			outcome.Error = collection.Err.Error()
		}
		encoded, err := json.Marshal(outcome)
		if err != nil {
			return nil, fmt.Errorf("encode collection outcome: %w", err)
		}
		metadata = append(metadata, cdx.Property{Name: "ciphertrail:collection", Value: string(encoded)})
		for _, entry := range collection.Result.Entries {
			ref := entry.Component.BOMRef
			if ref == "" {
				return nil, fmt.Errorf("component %q has no reference", entry.Component.Name)
			}
			component, exists := components[ref]
			if !exists {
				copy := entry.Component
				if copy.Properties != nil {
					properties := slices.Clone(*copy.Properties)
					copy.Properties = &properties
				}
				copy.Evidence = &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{}}
				components[ref] = &copy
				component = &copy
			} else if entry.Component.Properties != nil {
				if component.Properties == nil {
					component.Properties = &[]cdx.Property{}
				}
				*component.Properties = append(*component.Properties, *entry.Component.Properties...)
			}
			evidence, err := json.Marshal(entry.Evidence)
			if err != nil {
				return nil, fmt.Errorf("encode evidence: %w", err)
			}
			Property(component, "evidence", string(evidence))
			if entry.Evidence.Location != "" {
				occurrence := cdx.EvidenceOccurrence{Location: entry.Evidence.Location, Symbol: entry.Evidence.Symbol}
				if entry.Evidence.Line > 0 {
					line := entry.Evidence.Line
					occurrence.Line = &line
				}
				*component.Evidence.Occurrences = append(*component.Evidence.Occurrences, occurrence)
			}
			if edges[ref] == nil {
				edges[ref] = make(map[string]bool)
			}
			if entry.Parent != "" && entry.Parent != ref {
				addEdge(edges, entry.Parent, ref)
				addEdge(owners, ref, entry.Parent)
			}
		}
		for _, dependency := range collection.Result.Dependencies {
			addEdge(edges, dependency.Source, dependency.Target)
		}
	}
	for ref, component := range components {
		if component.CryptoProperties != nil && component.Type != cdx.ComponentTypeCryptographicAsset {
			return nil, fmt.Errorf("component %q has crypto properties but is not a cryptographic asset", component.Name)
		}
		if component.Properties != nil {
			slices.SortFunc(*component.Properties, compareProperty)
			*component.Properties = slices.Compact(*component.Properties)
		}
		occurrences := *component.Evidence.Occurrences
		slices.SortFunc(occurrences, func(a, b cdx.EvidenceOccurrence) int {
			return compareText(occurrenceKey(a), occurrenceKey(b))
		})
		occurrences = slices.CompactFunc(occurrences, func(a, b cdx.EvidenceOccurrence) bool {
			return occurrenceKey(a) == occurrenceKey(b)
		})
		if len(occurrences) == 0 {
			component.Evidence = nil
		} else {
			component.Evidence.Occurrences = &occurrences
		}
		for _, target := range cryptoReferences(component) {
			if _, ok := components[target]; !ok {
				return nil, fmt.Errorf("component %q references missing crypto asset %q", component.Name, target)
			}
			if target != ref {
				edges[ref][target] = true
			}
		}
	}
	for ref, targets := range edges {
		if components[ref] == nil {
			return nil, fmt.Errorf("missing dependency parent %q", ref)
		}
		for target := range targets {
			if components[target] == nil {
				return nil, fmt.Errorf("component %q has missing dependency %q", ref, target)
			}
		}
	}
	before := len(components)
	scope := "full-dependencies"
	if !options.IncludeDependencies {
		scope = "crypto-focused"
		focusGraph(components, edges, owners)
	}
	metadata = append(metadata,
		cdx.Property{Name: "ciphertrail:output-scope", Value: scope},
		cdx.Property{Name: "ciphertrail:omitted-components", Value: decimal(before - len(components))},
	)
	ordered := make([]cdx.Component, 0, len(components))
	for _, component := range components {
		ordered = append(ordered, *component)
	}
	dependencies := make([]cdx.Dependency, 0, len(edges))
	for ref, targets := range edges {
		children := make([]string, 0, len(targets))
		for child := range targets {
			children = append(children, child)
		}
		slices.Sort(children)
		dependencies = append(dependencies, cdx.Dependency{Ref: ref, Dependencies: &children})
	}
	slices.SortFunc(ordered, func(a, b cdx.Component) int { return compareText(a.BOMRef, b.BOMRef) })
	slices.SortFunc(dependencies, func(a, b cdx.Dependency) int { return compareText(a.Ref, b.Ref) })
	slices.SortFunc(metadata, compareProperty)
	status := "succeeded"
	if incomplete {
		status = "incomplete"
	}
	metadata = append(metadata, cdx.Property{Name: "ciphertrail:collection-status", Value: status})
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_7
	bom.JSONSchema = schemaURL
	bom.Components = &ordered
	bom.Dependencies = &dependencies
	bom.Metadata = &cdx.Metadata{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Properties: &metadata,
		Tools: &cdx.ToolsChoice{Components: &[]cdx.Component{
			{Type: "application", Name: "ciphertrail", Version: "dev"},
		}},
	}
	var buffer bytes.Buffer
	// Version conversion can silently coerce component types; validate rather than down-convert.
	encoder := json.NewEncoder(&buffer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(bom); err != nil {
		return nil, fmt.Errorf("encode CycloneDX: %w", err)
	}
	if err := Validate(buffer.Bytes()); err != nil {
		return nil, fmt.Errorf("validate generated CycloneDX: %w", err)
	}
	return buffer.Bytes(), nil
}

func addEdge(graph map[string]map[string]bool, source, target string) {
	if graph[source] == nil {
		graph[source] = make(map[string]bool)
	}
	graph[source][target] = true
}

func focusGraph(components map[string]*cdx.Component, edges, owners map[string]map[string]bool) {
	var pending []string
	for ref, component := range components {
		if component.Type == cdx.ComponentTypeCryptographicAsset {
			pending = append(pending, ref)
		}
	}
	retained := make(map[string]bool)
	for len(pending) > 0 {
		ref := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if retained[ref] {
			continue
		}
		retained[ref] = true
		for owner := range owners[ref] {
			pending = append(pending, owner)
		}
		// Crypto dependencies include implementation providers and native crypto
		// references. Do not expand providers' ordinary software dependencies.
		if components[ref].Type == cdx.ComponentTypeCryptographicAsset {
			for dependency := range edges[ref] {
				pending = append(pending, dependency)
			}
		}
	}
	for ref := range components {
		if !retained[ref] {
			delete(components, ref)
			delete(edges, ref)
			continue
		}
		for dependency := range edges[ref] {
			if !retained[dependency] {
				delete(edges[ref], dependency)
			}
		}
	}
}

func cryptoReferences(component *cdx.Component) []string {
	var refs []string
	add := func(ref cdx.BOMReference) {
		if ref != "" {
			refs = append(refs, string(ref))
		}
	}
	related := func(assets *[]cdx.RelatedCryptographicAsset) {
		if assets != nil {
			for _, asset := range *assets {
				add(cdx.BOMReference(asset.Ref))
			}
		}
	}
	if properties := component.CryptoProperties; properties != nil {
		if certificate := properties.CertificateProperties; certificate != nil {
			add(certificate.SignatureAlgorithmRef)
			add(certificate.SubjectPublicKeyRef)
			related(certificate.RelatedCryptographicAssets)
		}
		if key := properties.RelatedCryptoMaterialProperties; key != nil {
			add(key.AlgorithmRef)
			related(key.RelatedCryptographicAssets)
			if key.SecuredBy != nil {
				add(key.SecuredBy.AlgorithmRef)
			}
		}
		if protocol := properties.ProtocolProperties; protocol != nil {
			related(protocol.RelatedCryptographicAssets)
			if protocol.CryptoRefArray != nil {
				for _, ref := range *protocol.CryptoRefArray {
					add(ref)
				}
			}
			if protocol.CipherSuites != nil {
				for _, suite := range *protocol.CipherSuites {
					if suite.Algorithms != nil {
						for _, ref := range *suite.Algorithms {
							add(ref)
						}
					}
				}
			}
		}
	}
	return refs
}

func occurrenceKey(value cdx.EvidenceOccurrence) string {
	line := 0
	if value.Line != nil {
		line = *value.Line
	}
	return value.Location + "\x00" + decimal(line) + "\x00" + value.Symbol
}

func compareText(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func compareProperty(a, b cdx.Property) int {
	if result := compareText(a.Name, b.Name); result != 0 {
		return result
	}
	return compareText(a.Value, b.Value)
}
