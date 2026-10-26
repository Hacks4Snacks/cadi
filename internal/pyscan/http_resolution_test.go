package pyscan

import (
	"context"
	"testing"
)

func TestPythonHTTPReceiverAndMutationBoundaries(t *testing.T) {
	for _, test := range []struct {
		name, source string
		findings     int
		note         bool
	}{
		{"httpx-relative", "import httpx\nc = httpx.Client(base_url='https://example.invalid')\nc.get('items')", 1, false},
		{"httpx-http-base", "import httpx\nc = httpx.Client(base_url='http://example.invalid')\nc.get('/items')", 0, false},
		{"httpx-absolute-overrides-base", "import httpx\nc = httpx.Client(base_url='https://example.invalid')\nc.get('http://example.invalid')", 0, false},
		{"httpx-dynamic-can-override-base", "import httpx\nc = httpx.Client(base_url='https://example.invalid')\nc.get(unknown_url)", 0, true},
		{"httpx-base-reassigned", "import httpx\nc = httpx.Client(base_url='https://example.invalid')\nc.base_url = 'http://example.invalid'\nc.get('/items')", 0, true},
		{"httpx-base-alias", "import httpx\nc = httpx.Client(base_url='https://example.invalid')\nalias = c\nalias.base_url = unknown\nc.get('/items')", 0, true},
		{"httpx-context-base-reassigned", "import httpx\nwith httpx.Client(base_url='https://example.invalid') as c:\n c.base_url = unknown\n c.get('/items')", 0, true},
		{"urllib-url-reassigned", "import urllib.request\nr = urllib.request.Request('https://example.invalid')\nr.full_url = 'http://example.invalid'\nurllib.request.urlopen(r)", 0, true},
		{"urllib-type-reassigned", "import urllib.request\nr = urllib.request.Request('https://example.invalid')\nr.type = 'http'\nurllib.request.urlopen(r)", 0, true},
		{"plain-connection", "import http.client\nc = http.client.HTTPConnection('example.invalid')\nc.request('GET', '/')", 0, false},
		{"connection-class-mutated", "import http.client\nc = http.client.HTTPSConnection('example.invalid')\nc.__class__ = http.client.HTTPConnection\nc.request('GET', '/')", 1, true},
		{"constructor-mutated", "import http.client\nhttp.client.HTTPSConnection.__new__ = custom\nhttp.client.HTTPSConnection('example.invalid')", 0, true},
		{"parameter-shadow", "import requests\ndef f(requests):\n requests.get('https://example.invalid')", 0, false},
		{"local-client-method", "class Client:\n def get(self, url): pass\nc = Client()\nc.get('https://example.invalid')", 0, false},
		{"custom-context", "import requests\nclass C:\n def __enter__(self): return requests.Session()\nwith C() as client:\n client.get('https://example.invalid')", 0, false},
		{"class-is-not-context-instance", "import requests\nwith requests.Session as client:\n client.get('https://example.invalid')", 0, false},
		{"enter-mutated", "import requests\nrequests.Session.__enter__ = custom\nwith requests.Session() as c:\n c.get('https://example.invalid')", 0, false},
		{"method-mutated", "import requests\nc = requests.Session()\nc.get = custom\nc.get('https://example.invalid')", 0, true},
		{"namespace-alias-mutated", "import requests\nfrom requests.sessions import Session\nSession.get = custom\nrequests.Session().get('https://example.invalid')", 0, true},
		{"expanded-keywords", "import requests\nrequests.get('https://example.invalid', **options)", 0, true},
		{"expanded-positional", "import requests\nrequests.request(*parameters, 'https://example.invalid')", 0, true},
		{"opaque-prepared-request", "import requests\nc = requests.Session()\nc.send(prepared_request)", 0, true},
		{"unbound-method", "import requests\nrequests.Session.get(instance, 'https://example.invalid')", 1, false},
		{"unbound-self-is-not-url", "import requests\nrequests.Session.get('https://not-a-session.invalid', 'http://example.invalid')", 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := (Source{Selection: fixture(t, map[string]string{"app.py": test.source})}).Collect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(httpsEntries(result)) != test.findings || (len(result.Diagnostics) > 0) != test.note {
				t.Fatalf("HTTPS findings=%d, want %d; diagnostics=%v", len(httpsEntries(result)), test.findings, result.Diagnostics)
			}
		})
	}
}

func TestPythonHTTPShadowedProviders(t *testing.T) {
	for _, provider := range []string{"requests", "httpx", "urllib3", "urllib", "http"} {
		t.Run(provider, func(t *testing.T) {
			call := provider + ".get('https://example.invalid')"
			switch provider {
			case "urllib3":
				call = "urllib3.request('GET', 'https://example.invalid')"
			case "urllib":
				call = "urllib.request.urlopen('https://example.invalid')"
			case "http":
				call = "http.client.HTTPSConnection('example.invalid')"
			}
			selection := fixture(t, map[string]string{
				provider + ".py": "PRIVATE_SHADOW not valid Python",
				".cadiignore":    provider + ".py\n",
				"app.py":         "import " + provider + "\n" + call,
			})
			result, err := (Source{Selection: selection}).Collect(context.Background())
			if err != nil || len(httpsEntries(result)) != 0 || len(result.Diagnostics) == 0 {
				t.Fatalf("shadowed HTTP provider was trusted: findings=%d, notes=%v, err=%v", len(httpsEntries(result)), result.Diagnostics, err)
			}
		})
	}
}

func TestPythonHTTPMutationAcrossSelectedFiles(t *testing.T) {
	selection := fixture(t, map[string]string{
		"patch.py": "import requests.sessions\nrequests.sessions.Session.get = replacement\n",
		"app.py":   "import requests\nrequests.Session().get('https://example.invalid')\n",
	})
	result, err := (Source{Selection: selection}).Collect(context.Background())
	if err != nil || len(httpsEntries(result)) != 0 {
		t.Fatalf("selected-source mutation was not honored: %v", err)
	}
}
