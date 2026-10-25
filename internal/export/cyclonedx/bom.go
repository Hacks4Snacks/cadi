package cyclonedx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"time"

	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func decimal(value int) string { return strconv.Itoa(value) }

type provenance struct {
	Occurrence string                   `json:"occurrence,omitempty"`
	Kind       string                   `json:"kind,omitempty"`
	Collector  string                   `json:"collector,omitempty"`
	Time       string                   `json:"time,omitempty"`
	Symbol     string                   `json:"symbol,omitempty"`
	Context    *inventory.SourceContext `json:"context,omitempty"`
	Parameters []parameterGroup         `json:"parameters,omitempty"`
}

type parameterGroup struct {
	Basis      string           `json:"basis"`
	Limitation string           `json:"limitation"`
	Values     []parameterValue `json:"values"`
}

type parameterValue struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Location string `json:"location"`
	Line     int    `json:"line,omitempty"`
	Symbol   string `json:"symbol,omitempty"`
}

// EncodeOptions controls inventory scope, not cryptographic policy.
type EncodeOptions struct {
	IncludeDependencies bool
}

// Encode constructs a validated, crypto-focused CycloneDX 1.7 document.
func Encode(collections []inventory.Collection) ([]byte, error) {
	return EncodeWithOptions(collections, EncodeOptions{})
}

// EncodeWithOptions optionally includes the complete collected dependency inventory.
func EncodeWithOptions(collections []inventory.Collection, options EncodeOptions) ([]byte, error) {
	components := make(map[string]*cdx.Component)
	edges := make(map[string]map[string]bool)
	owners := make(map[string]map[string]bool)
	provenances := make(map[string][]provenance)
	var metadata []cdx.Property
	incomplete := false
	for _, collection := range collections {
		if err := collection.Result.Err(); err != nil {
			return nil, err
		}
		status := "succeeded"
		if collection.Err != nil {
			incomplete = true
			status = "incomplete"
		}
		outcome := struct {
			Collector   string                 `json:"collector"`
			Target      string                 `json:"target"`
			Status      string                 `json:"status"`
			Error       string                 `json:"error,omitempty"`
			Properties  []cdx.Property         `json:"properties,omitempty"`
			Diagnostics []inventory.Diagnostic `json:"diagnostics,omitempty"`
			Coverage    []inventory.Coverage   `json:"coverage,omitempty"`
		}{Collector: collection.Collector, Target: collection.Target, Status: status,
			Properties: slices.Clone(collection.Result.Properties), Diagnostics: collection.Result.Diagnostics,
			Coverage: collection.Result.Coverage}
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
			record, err := appendProvenance(component, entry.Evidence)
			if err != nil {
				return nil, err
			}
			provenances[ref] = append(provenances[ref], record)
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
		if err := appendEvidenceProperties(component, provenances[ref]); err != nil {
			return nil, err
		}
		occurrences := *component.Evidence.Occurrences
		slices.SortFunc(occurrences, func(a, b cdx.EvidenceOccurrence) int {
			return compareText(occurrenceKey(a)+"\x00"+a.BOMRef, occurrenceKey(b)+"\x00"+b.BOMRef)
		})
		occurrences = slices.CompactFunc(occurrences, func(a, b cdx.EvidenceOccurrence) bool {
			return a.BOMRef == b.BOMRef
		})
		if len(occurrences) == 0 {
			component.Evidence = nil
		} else {
			component.Evidence.Occurrences = &occurrences
		}
		if component.Properties != nil {
			slices.SortFunc(*component.Properties, compareProperty)
			*component.Properties = slices.Compact(*component.Properties)
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

func appendProvenance(component *cdx.Component, evidence inventory.Evidence) (provenance, error) {
	record := provenance{Kind: evidence.Kind, Collector: evidence.Collector, Time: evidence.Time, Context: sourceLocatorContext(evidence.Context)}
	if evidence.Location != "" {
		occurrence := cdx.EvidenceOccurrence{Location: evidence.Location, Symbol: evidence.Symbol}
		if evidence.Line > 0 {
			line := evidence.Line
			occurrence.Line = &line
		}
		parts := []string{"occurrence", component.BOMRef, occurrenceKey(occurrence)}
		if record.Context != nil {
			context, err := json.Marshal(record.Context)
			if err != nil {
				return record, fmt.Errorf("encode occurrence context: %w", err)
			}
			parts = append(parts, string(context))
		}
		occurrence.BOMRef = inventory.Ref(parts...)
		record.Occurrence = occurrence.BOMRef
		*component.Evidence.Occurrences = append(*component.Evidence.Occurrences, occurrence)
	} else {
		record.Symbol = evidence.Symbol
	}
	for _, fact := range evidence.Parameters {
		index := slices.IndexFunc(record.Parameters, func(group parameterGroup) bool {
			return group.Basis == fact.Basis && group.Limitation == fact.Limitation
		})
		if index < 0 {
			index = len(record.Parameters)
			record.Parameters = append(record.Parameters, parameterGroup{Basis: fact.Basis, Limitation: fact.Limitation})
		}
		group := &record.Parameters[index]
		group.Values = append(group.Values, parameterValue{
			Name: fact.Name, Value: fact.Value, Location: fact.Location, Line: fact.Line, Symbol: fact.Symbol,
		})
	}
	slices.SortFunc(record.Parameters, func(a, b parameterGroup) int {
		return compareText(a.Basis+"\x00"+a.Limitation, b.Basis+"\x00"+b.Limitation)
	})
	for i := range record.Parameters {
		values := record.Parameters[i].Values
		slices.SortFunc(values, func(a, b parameterValue) int {
			return compareText(parameterKey(a), parameterKey(b))
		})
		record.Parameters[i].Values = slices.Compact(values)
	}
	return record, nil
}

func (p provenance) detailed() bool {
	return p.Time != "" || p.Symbol != "" || p.Context != nil || len(p.Parameters) != 0
}

func sourceLocatorContext(source *inventory.SourceContext) *inventory.SourceContext {
	if source == nil {
		return nil
	}
	context := &inventory.SourceContext{
		Document: source.Document, Field: source.Field,
		RenderedFrom: source.RenderedFrom, ContentLine: source.ContentLine,
	}
	for _, frame := range source.Embedded {
		if frame.Document == 0 && frame.Field == "" && frame.File == "" && frame.Line == 0 {
			continue
		}
		context.Embedded = append(context.Embedded, inventory.EmbeddedContext{
			Document: frame.Document, Field: frame.Field, File: frame.File, Line: frame.Line,
		})
	}
	if context.Document == 0 && context.Field == "" && context.RenderedFrom == "" &&
		context.ContentLine == 0 && len(context.Embedded) == 0 {
		return nil
	}
	return context
}

func appendEvidenceProperties(component *cdx.Component, records []provenance) error {
	if len(records) == 0 {
		return nil
	}
	first := records[0]
	simple := !first.detailed()
	for _, record := range records[1:] {
		simple = simple && !record.detailed() && record.Kind == first.Kind && record.Collector == first.Collector
	}
	if simple {
		if first.Kind != "" {
			inventory.Property(component, "evidence-kind", first.Kind)
		}
		if first.Collector != "" {
			inventory.Property(component, "collector", first.Collector)
		}
		return nil
	}
	for _, record := range records {
		if record.Kind == "" && record.Collector == "" && !record.detailed() {
			continue
		}
		data, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("encode provenance: %w", err)
		}
		inventory.Property(component, "provenance", string(data))
	}
	return nil
}

func parameterKey(value parameterValue) string {
	return value.Name + "\x00" + value.Value + "\x00" + value.Location + "\x00" + decimal(value.Line) + "\x00" + value.Symbol
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
