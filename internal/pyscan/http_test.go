package pyscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ciphertrail/internal/export/cyclonedx"
	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func httpsEntries(result inventory.Result) []inventory.Entry {
	var entries []inventory.Entry
	for _, entry := range result.Entries {
		if entry.Component.Name == "Python HTTPS request configuration" {
			entries = append(entries, entry)
		}
	}
	return entries
}

func TestPythonHTTPClientModels(t *testing.T) {
	for _, test := range []struct {
		name, source string
		findings     int
	}{
		{"requests-get", "import requests\nrequests.get('https://example.invalid')", 1},
		{"requests-alias", "from requests.api import request as send\nsend('GET', url='https://example.invalid')", 1},
		{"requests-session", "import requests\ns = requests.Session()\ns.get('https://example.invalid')", 1},
		{"requests-session-factory", "import requests\ns = requests.session()\ns.request('POST', 'https://example.invalid')", 1},
		{"requests-context", "import requests\nwith requests.Session() as s:\n s.get('https://example.invalid')", 1},
		{"httpx-get", "import httpx\nhttpx.get('https://example.invalid')", 1},
		{"httpx-client", "import httpx\nc = httpx.Client()\nc.post('https://example.invalid')", 1},
		{"httpx-context-base", "import httpx\nwith httpx.Client(base_url='https://example.invalid') as c:\n c.get('/path')", 1},
		{"httpx-async", "import httpx\nasync def fetch():\n async with httpx.AsyncClient(base_url='https://example.invalid') as c:\n  await c.get(f'/items/{item}')", 1},
		{"httpx-url", "import httpx\nhttpx.request('GET', httpx.URL('https://example.invalid'))", 1},
		{"urllib3-request", "import urllib3\nurllib3.request('GET', 'https://example.invalid')", 1},
		{"urllib3-pool", "import urllib3\np = urllib3.PoolManager()\np.request('GET', 'https://example.invalid')", 1},
		{"urllib3-proxy", "import urllib3\np = urllib3.ProxyManager('http://proxy.invalid')\np.request('GET', 'https://example.invalid')", 1},
		{"urllib-open", "from urllib.request import urlopen\nurlopen('https://example.invalid')", 1},
		{"urllib-request", "from urllib.request import Request, urlopen\nr = Request('https://example.invalid')\nurlopen(r)", 1},
		{"urllib-opener", "import urllib.request\nopener = urllib.request.build_opener()\nopener.open('https://example.invalid')", 1},
		{"https-connection", "import http.client\nc = http.client.HTTPSConnection('example.invalid')\nc.request('GET', '/')", 2},
		{"https-pool", "from urllib3 import HTTPSConnectionPool\np = HTTPSConnectionPool('example.invalid')\np.request('GET', '/')", 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := (Source{Selection: fixture(t, map[string]string{"app.py": test.source})}).Collect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			entries := httpsEntries(result)
			if len(entries) != test.findings || len(result.Diagnostics) != 0 {
				t.Fatalf("HTTPS findings=%d, want %d; diagnostics=%v", len(entries), test.findings, result.Diagnostics)
			}
			for _, entry := range entries {
				protocol := entry.Component.CryptoProperties.ProtocolProperties
				if entry.Evidence.Kind != "configured" || entry.Evidence.Collector != "python" ||
					entry.Evidence.Location != "app.py" || entry.Evidence.Line == 0 ||
					protocol.Type != cdx.CryptoProtocolTypeTLS || protocol.Version != "" ||
					protocol.CipherSuites != nil || protocol.RelatedCryptographicAssets != nil {
					t.Fatalf("incorrect protocol or evidence: %+v", entry)
				}
			}
			if _, err := cyclonedx.Encode([]inventory.Collection{{Collector: "python", Result: result}}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPythonHTTPSchemeResolution(t *testing.T) {
	for _, test := range []struct {
		name, expression string
		https, note      bool
	}{
		{"literal", "'https://example.invalid/path'", true, false},
		{"case", "'HTTPS://example.invalid'", true, false},
		{"f-string-path", "f'https://example.invalid/{subscription}/items'", true, false},
		{"f-string-host", "f'https://{host}/path'", true, false},
		{"f-string-format", "f'https://example.invalid/{item!r:>20}'", true, false},
		{"literal-concat", "'https:' + '//example.invalid'", true, false},
		{"typed-concat", "'https://' + f'{host}/path'", true, false},
		{"long-url", "'https://example.invalid/" + strings.Repeat("PRIVATE_", 100) + "'", true, false},
		{"http", "'http://example.invalid'", false, false},
		{"http-f-string", "f'http://{host}/path'", false, false},
		{"opaque", "url_from_environment()", false, true},
		{"dynamic-scheme", "f'{scheme}://example.invalid'", false, true},
		{"scheme-suffix", "f'https{suffix}://example.invalid'", false, true},
		{"opaque-concat", "'https://' + opaque_object", false, true},
		{"relative", "'/path'", false, true},
		{"conditional", "'https://example.invalid' if flag else 'http://example.invalid'", false, true},
		{"other-scheme", "'ftp://example.invalid'", false, true},
		{"bytes", "b'https://example.invalid'", false, true},
		{"format-method", "'https://{host}'.format(host=host)", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := "import requests\nurl = " + test.expression + "\nrequests.get(url)\n"
			result, err := (Source{Selection: fixture(t, map[string]string{"app.py": source})}).Collect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if (len(httpsEntries(result)) == 1) != test.https || (len(result.Diagnostics) != 0) != test.note {
				t.Fatalf("findings=%d diagnostics=%v", len(httpsEntries(result)), result.Diagnostics)
			}
			for _, diagnostic := range result.Diagnostics {
				if diagnostic.Line != 3 || !strings.Contains(diagnostic.Message, "URL scheme") || strings.Contains(diagnostic.Message, "PRIVATE_") {
					t.Fatalf("missing or unsafe scheme diagnostic: %+v", diagnostic)
				}
			}
		})
	}
}

func TestPythonHTTPPrivacyAndStableIdentity(t *testing.T) {
	selection := fixture(t, map[string]string{"app.py": `import requests
url = f"https://PRIVATE_USER:PRIVATE_PASSWORD@example.invalid/PRIVATE_PATH/{value}?token=PRIVATE_TOKEN"
requests.get(url, headers={"Authorization": "PRIVATE_AUTH"}, cookies={"c": "PRIVATE_COOKIE"}, auth=("PRIVATE_LOGIN", "PRIVATE_PASSWORD"), data=b"PRIVATE_BODY", cert="PRIVATE_CERT", verify="PRIVATE_CA")
`})
	collect := func() (inventory.Result, []inventory.Entry) {
		t.Helper()
		result, err := (Source{Selection: selection}).Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		entries := httpsEntries(result)
		if len(entries) != 1 {
			t.Fatalf("HTTPS request was not found: %v", result.Diagnostics)
		}
		data, err := cyclonedx.Encode([]inventory.Collection{{Result: result}})
		if err != nil || strings.Contains(string(data), "PRIVATE_") || strings.Contains(string(data), "example.invalid") {
			t.Fatalf("request details leaked or schema failed: %v", err)
		}
		return result, entries
	}
	_, before := collect()
	path := filepath.Join(selection.Root, "app.py")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.ReplaceAll(string(data), "PRIVATE_", "PRIVATE_CHANGED_")), 0600); err != nil {
		t.Fatal(err)
	}
	_, after := collect()
	if before[0].Component.BOMRef != after[0].Component.BOMRef {
		t.Fatal("private request data affected asset identity")
	}
}
