package artifact

import (
	"context"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"ciphertrail/internal/inventory"
)

func TestBuildSettingsDoNotExportLinkerSecrets(t *testing.T) {
	var result inventory.Result
	addBuildInfo(&result, &debug.BuildInfo{
		Path: "example.test/tool", GoVersion: "go1.27.0",
		Settings: []debug.BuildSetting{
			{Key: "-ldflags", Value: "-X main.token=PRIVATE_SENTINEL"},
			{Key: "GOOS", Value: "linux"},
		},
	}, inventory.Evidence{Kind: "present", Location: "tool"}, "")
	data, err := inventory.EncodeWithOptions([]inventory.Collection{{Result: result}}, inventory.EncodeOptions{IncludeDependencies: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "PRIVATE_SENTINEL") || !strings.Contains(string(data), "linux") {
		t.Fatal("incorrect build metadata filtering")
	}
	focused, err := inventory.Encode([]inventory.Collection{{Result: result}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(focused), "example.test/tool") || strings.Contains(string(focused), "cryptographic-asset") {
		t.Fatal("build metadata alone was treated as evidence of cryptographic use")
	}
}

func TestOpenSSLConfigurationIsNotClaimedAsNegotiated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openssl.cnf")
	if err := os.WriteFile(path, []byte("[system_default]\nMinProtocol=TLSv1.2\nCipherString=DEFAULT:@SECLEVEL=2\nPassword=PRIVATE_SENTINEL\n.include other.cnf\n"), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := (Files{Path: path}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 2 || len(result.Diagnostics) == 0 {
		t.Fatal("missing configuration declarations or include limitation")
	}
	for _, entry := range result.Entries {
		if entry.Evidence.Kind != "configured" || entry.Component.CryptoProperties.ProtocolProperties.CipherSuites != nil {
			t.Fatal("configuration was misrepresented as negotiation")
		}
	}
	data, err := inventory.Encode([]inventory.Collection{{Result: result}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "PRIVATE_SENTINEL") {
		t.Fatal("unrelated configuration exported")
	}
}

func TestOpenSSLUnresolvedExpressionsHaveNoValuePlaceholder(t *testing.T) {
	var result inventory.Result
	found, err := parseOpenSSL(&result, []byte("[default]\nCipherString=$ENV::PRIVATE_SENTINEL\nMinProtocol=unknown\n"),
		inventory.Evidence{Kind: "present", Collector: "file", Location: "openssl.cnf"}, "")
	if err != nil || !found || len(result.Entries) != 2 {
		t.Fatalf("OpenSSL declarations not collected: %v", err)
	}
	if len(result.Entries[0].Evidence.Unresolved) != 1 ||
		result.Entries[0].Evidence.Unresolved[0] != "openssl.CipherString" ||
		len(result.Entries[1].Evidence.Unresolved) != 0 {
		t.Fatal("unresolved expression was lost or leaked into another declaration")
	}
	data, err := inventory.Encode([]inventory.Collection{{Result: result}})
	if err != nil || strings.Contains(string(data), "PRIVATE_SENTINEL") ||
		strings.Contains(string(data), "unknown: expression") {
		t.Fatalf("unresolved source or value placeholder leaked: %v", err)
	}
	if !strings.Contains(string(data), `"value": "unknown"`) {
		t.Fatal("a literal selector equal to unknown was discarded")
	}
}
