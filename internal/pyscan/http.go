package pyscan

import (
	"slices"
	"strings"

	"ciphertrail/internal/inventory"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

var httpConstructors = map[string]string{
	"requests.Session":              "requests.Session",
	"requests.session":              "requests.Session",
	"httpx.Client":                  "httpx.Client",
	"httpx.AsyncClient":             "httpx.AsyncClient",
	"urllib3.PoolManager":           "urllib3.PoolManager",
	"urllib3.ProxyManager":          "urllib3.ProxyManager",
	"urllib3.HTTPConnectionPool":    "urllib3.HTTPConnectionPool",
	"urllib3.HTTPSConnectionPool":   "urllib3.HTTPSConnectionPool",
	"urllib.request.build_opener":   "urllib.request.OpenerDirector",
	"urllib.request.OpenerDirector": "urllib.request.OpenerDirector",
	"http.client.HTTPConnection":    "http.client.HTTPConnection",
	"http.client.HTTPSConnection":   "http.client.HTTPSConnection",
}

type httpModel struct {
	client     string
	urlIndex   int
	urlName    string
	fixed      scheme
	baseURL    bool
	opaqueSend bool
}

func canonicalHTTPName(name string) string {
	for _, alias := range [][2]string{
		{"requests.api", "requests"},
		{"requests.sessions.Session", "requests.Session"},
		{"requests.sessions.session", "requests.session"},
		{"urllib3.poolmanager.PoolManager", "urllib3.PoolManager"},
		{"urllib3.poolmanager.ProxyManager", "urllib3.ProxyManager"},
		{"urllib3.connectionpool.HTTPSConnectionPool", "urllib3.HTTPSConnectionPool"},
		{"urllib3.connectionpool.HTTPConnectionPool", "urllib3.HTTPConnectionPool"},
	} {
		if name == alias[0] || strings.HasPrefix(name, alias[0]+".") {
			return alias[1] + strings.TrimPrefix(name, alias[0])
		}
	}
	return name
}

func httpNamespace(name string) bool {
	for _, root := range []string{"requests", "httpx", "urllib3", "urllib", "http"} {
		if name == root || strings.HasPrefix(name, root+".") {
			return true
		}
	}
	return false
}

func httpInstance(call value) string {
	name := canonicalHTTPName(symbol(call.Base))
	if class := httpConstructors[name]; class != "" {
		return class
	}
	class := ""
	switch name {
	case "requests.Session.__enter__":
		class = "requests.Session"
	case "httpx.Client.__enter__":
		class = "httpx.Client"
	case "httpx.AsyncClient.__aenter__":
		class = "httpx.AsyncClient"
	case "urllib3.PoolManager.__enter__":
		class = "urllib3.PoolManager"
	case "urllib3.ProxyManager.__enter__":
		class = "urllib3.ProxyManager"
	}
	context := receiver(call)
	if class != "" && instance(&context) == class {
		return class
	}
	return ""
}

func httpCallModel(name string) (httpModel, bool) {
	name = canonicalHTTPName(name)
	model := httpModel{urlName: "url"}
	switch name {
	case "http.client.HTTPSConnection", "urllib3.HTTPSConnectionPool":
		model.fixed = schemeHTTPS
		return model, true
	case "urllib.request.urlopen":
		return model, true
	case "urllib3.request":
		model.urlIndex = 1
		return model, true
	}
	index := strings.LastIndex(name, ".")
	if index < 0 {
		return model, false
	}
	class, method := name[:index], name[index+1:]
	switch class {
	case "requests", "httpx", "requests.Session", "httpx.Client", "httpx.AsyncClient":
		switch method {
		case "get", "post", "put", "patch", "delete", "head", "options":
		case "request":
			model.urlIndex = 1
		case "stream":
			if !strings.HasPrefix(class, "httpx") {
				return model, false
			}
			model.urlIndex = 1
		case "send":
			if class == "requests" || class == "httpx" {
				return model, false
			}
			model.opaqueSend = true
		default:
			return model, false
		}
		if class != "requests" && class != "httpx" {
			model.client = class
		}
		model.baseURL = class == "httpx.Client" || class == "httpx.AsyncClient"
	case "urllib3.PoolManager", "urllib3.ProxyManager":
		if method != "request" && method != "urlopen" {
			return model, false
		}
		model.client, model.urlIndex = class, 1
	case "urllib3.HTTPConnectionPool", "urllib3.HTTPSConnectionPool", "http.client.HTTPConnection", "http.client.HTTPSConnection":
		if method != "request" && (method != "urlopen" || !strings.HasPrefix(class, "urllib3.")) {
			return model, false
		}
		model.client, model.fixed = class, schemeHTTP
		if strings.Contains(class, "HTTPSConnection") {
			model.fixed = schemeHTTPS
		}
	case "urllib.request.OpenerDirector":
		if method != "open" {
			return model, false
		}
		model.client, model.urlName = class, "fullurl"
	default:
		return model, false
	}
	return model, true
}

func (m httpModel) scheme(call value) scheme {
	if m.opaqueSend {
		return schemeUnknown
	}
	position := m.urlIndex
	client := receiver(call)
	if m.client != "" && canonicalHTTPName(symbol(&client)) == m.client {
		position++
		if len(call.Args) > 0 {
			client = call.Args[0]
		}
	}
	if m.client != "" && (slices.Contains(client.Modified, "__class__") ||
		slices.Contains(client.Modified, "__dict__") || slices.Contains(client.Modified, "*")) {
		return schemeUnknown
	}
	if m.fixed != schemeUnknown {
		return m.fixed
	}
	resolved := urlScheme(argument(call, position, m.urlName))
	if resolved != schemeRelative || !m.baseURL {
		return resolved
	}
	for client.Kind == "call" && (strings.HasSuffix(symbol(client.Base), ".__enter__") ||
		strings.HasSuffix(symbol(client.Base), ".__aenter__")) {
		if urlModified(client) {
			return schemeUnknown
		}
		client = receiver(client)
	}
	if urlModified(client) || instance(&client) != m.client {
		return schemeUnknown
	}
	return urlScheme(argument(client, -1, "base_url"))
}

func httpsConfiguration() cdx.Component {
	component := inventory.ConfiguredTLS("Python HTTPS request configuration", inventory.TLSConfiguration{}, nil)
	inventory.Property(&component, "http.url-scheme", "https")
	return component
}
