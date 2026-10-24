package cyclonedx

import (
	"embed"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schema/*.json
var schemaFiles embed.FS

const documentVersion = "1.7"
const schemaName = "bom-1.7.schema.json"
const schemaURL = "http://cyclonedx.org/schema/" + schemaName

type offlineLoader struct{}

func (offlineLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("schema resource is not bundled: %s", url)
}

var compiledSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	compiler.UseLoader(offlineLoader{})
	for _, name := range []string{schemaName, "cryptography-defs.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"} {
		data, err := schemaFiles.ReadFile("schema/" + name)
		if err != nil {
			return nil, err
		}
		var document any
		if err := json.Unmarshal(data, &document); err != nil {
			return nil, err
		}
		if err := compiler.AddResource("http://cyclonedx.org/schema/"+name, document); err != nil {
			return nil, err
		}
	}
	return compiler.Compile(schemaURL)
})

// Validate checks a document against bundled official schemas without network access.
func Validate(data []byte) error {
	schema, err := compiledSchema()
	if err != nil {
		return fmt.Errorf("compile bundled schema: %w", err)
	}
	var document any
	if err := json.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("decode CBOM: %w", err)
	}
	object, ok := document.(map[string]any)
	if !ok || object["specVersion"] != documentVersion {
		return fmt.Errorf("expected a CycloneDX %s document", documentVersion)
	}
	return schema.Validate(document)
}
