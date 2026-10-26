package kubernetes

import (
	"errors"
	"strconv"
	"strings"

	"cadi/internal/inventory"

	"go.yaml.in/yaml/v3"
)

func (r resource) encryption(node *yaml.Node) error {
	groups := fields(node)["resources"]
	if groups == nil || groups.Kind != yaml.SequenceNode {
		return r.failure(node, "EncryptionConfiguration resources must be a list")
	}
	var failures error
	for groupIndex, group := range groups.Content {
		if group.Kind != yaml.MappingNode {
			failures = errors.Join(failures, r.failure(group, "encryption resource entry must be an object"))
			continue
		}
		object := fields(group)
		targets, known, err := stringsValue(object["resources"])
		if err != nil || !known {
			failures = errors.Join(failures, r.failure(group, "encrypted resources must be a list of strings"))
			continue
		}
		providers := object["providers"]
		if providers == nil || providers.Kind != yaml.SequenceNode || len(providers.Content) == 0 {
			failures = errors.Join(failures, r.failure(group, "encryption providers must be a nonempty list"))
			continue
		}
		var order []string
		valid := true
		for _, provider := range providers.Content {
			if provider.Kind != yaml.MappingNode || len(provider.Content) != 2 ||
				!resourceToken.MatchString(provider.Content[0].Value) || len(provider.Content[0].Value) > 64 {
				failures = errors.Join(failures, r.failure(provider, "each provider must specify exactly one type"))
				valid = false
				break
			}
			order = append(order, provider.Content[0].Value)
		}
		if !valid {
			continue
		}
		for index, provider := range providers.Content {
			name, configuration := order[index], provider.Content[1]
			field := "/resources/" + strconv.Itoa(groupIndex) + "/providers/" + strconv.Itoa(index)
			if err := r.mapping(configuration, "encryption provider configuration"); err != nil {
				failures = errors.Join(failures, err)
				continue
			}
			if name == "identity" {
				r.result.Metadata("encryption.identity", "identity is a passthrough provider, not a cryptographic algorithm; provider ordering remains in configured provider evidence")
				continue
			}
			values := []inventory.Attribute{
				{Name: "encryption.provider", Value: name},
				{Name: "encryption.provider-index", Value: strconv.Itoa(index)},
				{Name: "encryption.provider-order", Value: strings.Join(order, ", ")},
				{Name: "encryption.write-provider", Value: order[0]},
			}
			evidence := r.at(provider, field)
			if runtimeVariable.MatchString(targets) {
				evidence.Unresolved = append(evidence.Unresolved, "encryption.resources")
			} else {
				values = append(values, inventory.Attribute{Name: "encryption.resources", Value: targets})
			}
			algorithm, supported := inventory.ConfiguredEncryptionAlgorithm(name, index == 0, values)
			if !supported {
				r.note(provider, "encryption provider is not modeled: "+name+"; no algorithm is inferred")
				continue
			}
			evidence.Unresolved = append(evidence.Unresolved, "key-size-bits")
			algorithmRef := r.result.Add(algorithm, evidence, r.parent)
			failures = errors.Join(failures, r.encryptionKeys(configuration, field+"/"+name, algorithmRef, index == 0))
		}
	}
	return failures
}

func (r resource) encryptionKeys(configuration *yaml.Node, field, algorithmRef string, writes bool) error {
	keys := fields(configuration)["keys"]
	if keys == nil || keys.Tag == "!!null" {
		r.note(configuration, "encryption provider key references are unresolved")
		return nil
	}
	if keys.Kind != yaml.SequenceNode {
		return r.failure(keys, "encryption keys must be a list")
	}
	for index, key := range keys.Content {
		if key.Kind != yaml.MappingNode {
			return r.failure(key, "encryption key reference must be an object")
		}
		object := fields(key)
		if secret := object["secret"]; secret != nil && (secret.Kind != yaml.ScalarNode || secret.Tag != "!!str") {
			return r.failure(secret, "encryption key secret must be a string")
		}
		name, known, err := configuredText(object["name"])
		if err != nil {
			return r.failure(key, "encryption key name must be a string")
		}
		evidence := r.at(key, field+"/keys/"+strconv.Itoa(index))
		evidence.Unresolved = []string{"key-size-bits"}
		role := "decrypt"
		if writes && index == 0 {
			role = "encrypt, decrypt"
		}
		values := []inventory.Attribute{{Name: "encryption.key-index", Value: strconv.Itoa(index)}, {Name: "encryption.key-role", Value: role}}
		if known {
			values = append(values, inventory.Attribute{Name: "encryption.key-name", Value: name})
		} else {
			evidence.Unresolved = append(evidence.Unresolved, "encryption.key-name")
		}
		r.result.Add(inventory.EncryptionKeyReference(algorithmRef, values), evidence, r.parent)
	}
	return nil
}
