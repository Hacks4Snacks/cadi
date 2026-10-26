package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"cadi/internal/inventory"

	"go.yaml.in/yaml/v3"
)

var errComplexMappingKey = errors.New("mapping keys must be strings; YAML merge keys are not supported")

func fields(node *yaml.Node) map[string]*yaml.Node {
	result := map[string]*yaml.Node{}
	if node != nil && node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			result[node.Content[i].Value] = node.Content[i+1]
		}
	}
	return result
}

func validateNodes(ctx context.Context, node *yaml.Node, depth int, count *int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	*count += 1
	if depth > 64 || *count > 100000 {
		return fmt.Errorf("YAML structure exceeds depth or node limits")
	}
	if node.Kind == yaml.AliasNode {
		return fmt.Errorf("YAML aliases are not supported")
	}
	if node.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "<<" {
				return errComplexMappingKey
			}
			if seen[key.Value] {
				return fmt.Errorf("duplicate mapping key")
			}
			seen[key.Value] = true
		}
	}
	for _, child := range node.Content {
		if err := validateNodes(ctx, child, depth+1, count); err != nil {
			return err
		}
	}
	return nil
}

type formatter func(*yaml.Node) (string, bool, error)

func textValue(node *yaml.Node) (string, bool, error) {
	if node == nil || node.Tag == "!!null" || templateValue(node) {
		return "", false, nil
	}
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return "", false, fmt.Errorf("expected a string")
	}
	return node.Value, true, nil
}

func boolValue(node *yaml.Node) (string, bool, error) {
	if node == nil || node.Tag == "!!null" || templateValue(node) {
		return "", false, nil
	}
	var value bool
	if node.Kind != yaml.ScalarNode || node.Tag != "!!bool" || node.Decode(&value) != nil {
		return "", false, fmt.Errorf("expected a boolean")
	}
	return strconv.FormatBool(value), true, nil
}

func intValue(node *yaml.Node) (string, bool, error) {
	if node == nil || node.Tag == "!!null" || templateValue(node) {
		return "", false, nil
	}
	var value int
	if node.Kind != yaml.ScalarNode || node.Tag != "!!int" || node.Decode(&value) != nil {
		return "", false, fmt.Errorf("expected an integer within the supported range")
	}
	return strconv.Itoa(value), true, nil
}

func durationValue(node *yaml.Node) (string, bool, error) {
	value, known, err := textValue(node)
	if err != nil || !known {
		return "", known, err
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return "", false, fmt.Errorf("expected a duration")
	}
	return duration.String(), true, nil
}

func stringsValue(node *yaml.Node) (string, bool, error) {
	if node == nil || node.Tag == "!!null" {
		return "", false, nil
	}
	if node.Kind != yaml.SequenceNode {
		return "", false, fmt.Errorf("expected a list of strings")
	}
	var values []string
	for _, child := range node.Content {
		if templateValue(child) {
			return "", false, nil
		}
		value, known, err := textValue(child)
		if err != nil || !known {
			return "", false, fmt.Errorf("expected a list of strings")
		}
		values = append(values, value)
	}
	return strings.Join(values, ", "), true, nil
}

type parameter struct {
	field, name string
	format      formatter
}

func (r resource) parameters(node *yaml.Node, definitions []parameter) ([]inventory.Attribute, []string, error) {
	mapping := fields(node)
	var attributes []inventory.Attribute
	var unresolved []string
	for _, definition := range definitions {
		field := mapping[definition.field]
		if field == nil {
			continue
		}
		if field.Kind == yaml.ScalarNode && runtimeVariable.MatchString(field.Value) {
			unresolved = append(unresolved, definition.name)
			continue
		}
		value, known, err := definition.format(field)
		if err != nil {
			return nil, nil, r.failure(field, definition.name+": "+err.Error())
		}
		if known {
			attributes = append(attributes, inventory.Attribute{Name: definition.name, Value: value})
		} else {
			unresolved = append(unresolved, definition.name)
			if hasTemplate(field) {
				r.note(field, "unrendered configuration field: "+definition.name+"; supply rendered Helm YAML/JSON")
			}
		}
	}
	return attributes, unresolved, nil
}

func templateValue(node *yaml.Node) bool {
	return node != nil && node.Kind == yaml.ScalarNode && strings.Contains(node.Value, "{{")
}

func hasTemplate(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if templateValue(node) {
		return true
	}
	for _, child := range node.Content {
		if hasTemplate(child) {
			return true
		}
	}
	return false
}

func (r resource) mapping(node *yaml.Node, name string) error {
	if node != nil && node.Tag != "!!null" && node.Kind != yaml.MappingNode {
		return r.failure(node, name+" must be an object")
	}
	return nil
}
