package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ciphertrail/internal/export/cyclonedx"
	"ciphertrail/internal/inventory"
	"ciphertrail/internal/testutil"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestCLIFileOutputAndOperationalFailure(t *testing.T) {
	_, _, certificate, _ := testutil.Identity(t)
	directory := t.TempDir()
	input, output := filepath.Join(directory, "cert.pem"), filepath.Join(directory, "cbom.json")
	if err := os.WriteFile(input, certificate, 0600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		var stdout, stderr bytes.Buffer
		if code := Run(context.Background(), []string{"scan", "--file", input, "--output", output}, &stdout, &stderr); code != 0 {
			t.Fatalf("exit=%d: %s", code, stderr.String())
		}
		if stdout.Len() != 0 {
			t.Fatal("file output polluted stdout")
		}
		data, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if err := cyclonedx.Validate(data); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"scan", "--file", input, "--file", filepath.Join(directory, "missing.pem")}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stdout.String(), "incomplete") || stderr.Len() == 0 {
		t.Fatalf("missing partial/error behavior: exit=%d stderr=%s", code, stderr.String())
	}
	if err := cyclonedx.Validate(stdout.Bytes()); err != nil {
		t.Fatal(err)
	}
}

func TestExisting16ReportCanBeRegeneratedAs17(t *testing.T) {
	_, _, certificate, _ := testutil.Identity(t)
	directory := t.TempDir()
	input, output := filepath.Join(directory, "certificate.pem"), filepath.Join(directory, "cbom.json")
	if err := os.WriteFile(input, certificate, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"tools":{"components":[{"type":"application","name":"ciphertrail"}]}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"scan", "--file", input, "--output", output}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatal(err)
	}
	if bom.SpecVersion != cdx.SpecVersion1_7 || bom.JSONSchema != "http://cyclonedx.org/schema/bom-1.7.schema.json" {
		t.Fatal("report did not migrate to 1.7")
	}
}

func TestOutputCannotOverwriteInputOrUnrelatedFiles(t *testing.T) {
	_, _, certificate, _ := testutil.Identity(t)
	directory := t.TempDir()
	input := filepath.Join(directory, "cert.pem")
	unrelated := filepath.Join(directory, "important.txt")
	for path, data := range map[string][]byte{input: certificate, unrelated: []byte("keep this")} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, output := range []string{input, unrelated} {
		before, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if code := Run(context.Background(), []string{"scan", "--file", input, "--output", output}, &stdout, &stderr); code == 0 {
			t.Fatal("destructive output accepted")
		}
		after, err := os.ReadFile(output)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("input was modified")
		}
	}
}

func TestOutputSymlinkIsRejected(t *testing.T) {
	_, _, certificate, _ := testutil.Identity(t)
	directory := t.TempDir()
	input, output := filepath.Join(directory, "cert.pem"), filepath.Join(directory, "out.json")
	if err := os.WriteFile(input, certificate, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(input, output); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"scan", "--file", input, "--output", output}, &stdout, &stderr); code == 0 {
		t.Fatal("output symlink accepted")
	}
}

func TestGoScanThroughCLI(t *testing.T) {
	directory := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":  "module example.test/cli\n\ngo 1.27.0\n",
		"main.go": "package cli; import \"crypto/sha256\"; func Hash() { _ = sha256.Sum256(nil) }\n",
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"scan", directory}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "SHA-256") {
		t.Fatalf("exit=%d: %s", code, stderr.String())
	}
	if err := cyclonedx.Validate(stdout.Bytes()); err != nil {
		t.Fatal(err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("fully modeled source should not emit boilerplate notes: %s", stderr.String())
	}
}

func TestOfflineCLISelectsDependencyMode(t *testing.T) {
	directory := t.TempDir()
	for name, data := range map[string]string{
		"go.mod":  "module example.test/offlinecli\n\ngo 1.27.0\n",
		"main.go": "package example\nimport \"crypto/sha256\"\nfunc Run() { _ = sha256.Sum256(nil) }\n",
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"scan", "--source", directory, "--offline"}, &stdout, &stderr); code != 0 {
		t.Fatalf("offline CLI failed: %d %s", code, stderr.String())
	}
	var bom cdx.BOM
	if err := json.Unmarshal(stdout.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, property := range *bom.Metadata.Properties {
		if property.Name != "ciphertrail:collection" {
			continue
		}
		var collection struct{ Properties []cdx.Property }
		if err := json.Unmarshal([]byte(property.Value), &collection); err != nil {
			t.Fatal(err)
		}
		for _, item := range collection.Properties {
			found = found || item.Name == "ciphertrail:dependency-mode" && item.Value == "offline"
		}
	}
	if !found {
		t.Fatal("CLI did not record strict offline source behavior")
	}
}

func TestGoScanRetainsActionableUnknownAPINotes(t *testing.T) {
	directory := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":  "module example.test/unknown\n\ngo 1.27.0\n",
		"main.go": "package unknown\nimport \"crypto\"\nfunc Run(s crypto.Signer) { _, _ = s.Sign(nil, nil, crypto.SHA256) }\n",
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"scan", "--source", directory}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stderr.String(), "NOTE: main.go:3: cryptographic API not modeled: (crypto.Signer).Sign") {
		t.Fatalf("unknown API was hidden: exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "cryptographic API not modeled") {
		t.Fatal("unknown API was not persisted in the CBOM")
	}
}

func TestDependencyInventoryIsOptIn(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "formatting"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"go.mod":               "module example.test/cli\n\ngo 1.27.0\nrequire example.test/formatting v0.0.0\nreplace example.test/formatting => ./formatting\n",
		"main.go":              "package cli\nimport (\"crypto/sha256\"; _ \"example.test/formatting\")\nfunc Hash() { _ = sha256.Sum256(nil) }\n",
		"formatting/go.mod":    "module example.test/formatting\n\ngo 1.27.0\n",
		"formatting/format.go": "package formatting\nimport \"fmt\"\nfunc Format() string { return fmt.Sprint(1) }\n",
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var cryptoRef string
	for _, include := range []bool{false, true} {
		args := []string{"scan", "--source", directory}
		if include {
			args = append(args, "--include-dependencies")
		}
		var stdout, stderr bytes.Buffer
		if code := Run(context.Background(), args, &stdout, &stderr); code != 0 {
			t.Fatalf("include=%v: exit=%d %s", include, code, stderr.String())
		}
		var bom cdx.BOM
		if err := json.Unmarshal(stdout.Bytes(), &bom); err != nil {
			t.Fatal(err)
		}
		var owner, provider, unrelated bool
		for _, component := range *bom.Components {
			owner = owner || component.Name == "example.test/cli"
			provider = provider || component.Name == "Go standard library"
			unrelated = unrelated || component.Name == "example.test/formatting"
			if component.Type == cdx.ComponentTypeCryptographicAsset && component.Name == "SHA-256" {
				if cryptoRef != "" && cryptoRef != component.BOMRef {
					t.Fatal("output scope changed the crypto reference")
				}
				cryptoRef = component.BOMRef
			}
		}
		if !owner || !provider || unrelated != include || cryptoRef == "" {
			t.Fatalf("include=%v owner=%v provider=%v unrelated=%v crypto=%s", include, owner, provider, unrelated, cryptoRef)
		}
	}
}

func TestCLIExclusionsCombineWithSourceRootConfiguration(t *testing.T) {
	directory := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":             "module example.test/exclusions\n\ngo 1.27.0\n",
		"main.go":            "package example\nimport \"crypto/sha256\"\nfunc Production() { _ = sha256.Sum256(nil) }\n",
		"fixture.go":         "package example\nimport \"crypto/tls\"\nfunc Fixture() { _, _ = tls.X509KeyPair(nil, nil) }\n",
		"other_fixture.go":   "package example\nimport \"crypto/sha512\"\nfunc OtherFixture() { _ = sha512.Sum512(nil) }\n",
		".ciphertrailignore": "fixture.go\n",
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"scan", "--source", directory, "--exclude", "other_fixture.go", "--exclude", "unused_helpers"}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	var bom cdx.BOM
	if err := json.Unmarshal(stdout.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	for _, component := range *bom.Components {
		if component.Type == cdx.ComponentTypeCryptographicAsset && component.Name != "SHA-256" {
			t.Errorf("fixture leaked into CLI output: %s", component.Name)
		}
	}
	if !strings.Contains(stdout.String(), "ciphertrail:source-exclusion-paths") || !strings.Contains(stdout.String(), "unused_helpers") {
		t.Fatal("effective exclusion scope was not recorded")
	}
}

func TestOutputCannotCreateOrOverwriteSourceIgnoreFile(t *testing.T) {
	directory := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"scan", "--source", directory, "--output", filepath.Join(directory, ".ciphertrailignore")}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "overwrite a scan input") {
		t.Fatalf("ignore file was not protected: exit=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(directory, ".ciphertrailignore")); !os.IsNotExist(err) {
		t.Fatal("output created a source configuration file")
	}
}

func TestNestedRepositoryCLIInclusionIsExplicit(t *testing.T) {
	directory := t.TempDir()
	if err := os.MkdirAll(filepath.Join(directory, "checkout", ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"go.mod":           "module example.test/root\n\ngo 1.27.0\n",
		"main.go":          "package root\nimport \"crypto/sha256\"\nfunc Run() { _ = sha256.Sum256(nil) }\n",
		"checkout/go.mod":  "module example.test/checkout\n\ngo 1.27.0\n",
		"checkout/main.go": "package checkout\nimport \"crypto/sha512\"\nfunc Run() { _ = sha512.Sum512(nil) }\n",
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, include := range []bool{false, true} {
		args := []string{"scan", "--source", directory}
		if include {
			args = append(args, "--include-nested-repos")
		}
		var stdout, stderr bytes.Buffer
		if code := Run(context.Background(), args, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
			t.Fatalf("include=%v exit=%d stderr=%s", include, code, stderr.String())
		}
		if strings.Contains(stdout.String(), `"name": "SHA-512"`) != include {
			t.Fatal("CLI did not honor nested repository scope")
		}
	}
}

func TestInvalidOptionsAndCredentialURLs(t *testing.T) {
	for _, args := range [][]string{
		{"scan"}, {"scan", "--policy", "anything"},
		{"scan", "--tls", "https://user:SECRET@example.test:443"},
		{"scan", "--ssh", "example.test:0"},
		{"scan", "--tls", "localhost:443", "--timeout", "0"},
		{"scan", "--file", ".", "--client-key", "key.pem"},
		{"scan", "--file", ".", "--exclude", "internal/testutil"},
		{"scan", "--file", ".", "--include-nested-repos"},
		{"scan", "--source", ".", "--offline", "--tls", "localhost:443"},
		{"scan", "--offline", "--ssh", "localhost:22"},
	} {
		var stdout, stderr bytes.Buffer
		code := Run(context.Background(), args, &stdout, &stderr)
		if code != 2 || stdout.Len() != 0 {
			t.Fatalf("%v: exit=%d stderr=%s", args, code, stderr.String())
		}
		if strings.Contains(stderr.String(), "SECRET") {
			t.Fatal("credential URL leaked")
		}
	}

}

func TestDiagnosticPresentation(t *testing.T) {
	for _, tt := range []struct {
		diagnostic inventory.Diagnostic
		want       string
	}{
		{inventory.Diagnostic{Message: "limitation"}, "NOTE: limitation\n"},
		{inventory.Diagnostic{Location: "main.go", Message: "limitation"}, "NOTE: main.go: limitation\n"},
		{inventory.Diagnostic{Location: "main.go", Line: 42, Message: "limitation"}, "NOTE: main.go:42: limitation\n"},
	} {
		var output bytes.Buffer
		writeDiagnostic(&output, tt.diagnostic)
		if output.String() != tt.want {
			t.Errorf("got %q, want %q", output.String(), tt.want)
		}
	}
}

func TestSelfScanIsQuietAndRetainsCryptoEvidence(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"scan", "--source", "../.."}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	var bom cdx.BOM
	if err := json.Unmarshal(stdout.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, component := range *bom.Components {
		if component.Type == cdx.ComponentTypeCryptographicAsset {
			names[component.Name] = true
		}
	}
	for _, name := range []string{"SHA-256", "Public key access", "X.509 certificate import", "TLS handshake", "TLS X.509 key pair"} {
		if !names[name] {
			t.Errorf("self-scan lost %s evidence", name)
		}
	}
	for _, component := range *bom.Components {
		if component.Evidence == nil || component.Evidence.Occurrences == nil {
			continue
		}
		for _, occurrence := range *component.Evidence.Occurrences {
			if strings.HasPrefix(occurrence.Location, "internal/testutil/") {
				t.Fatal("test helper leaked into the default self-scan")
			}
		}
	}
}
