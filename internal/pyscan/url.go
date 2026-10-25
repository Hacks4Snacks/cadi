package pyscan

import (
	"slices"
	"strings"
)

type scheme uint8

const (
	schemeUnknown scheme = iota
	schemeHTTP
	schemeHTTPS
	schemeRelative
)

const maxURLPrefix = 64

func urlScheme(v value) scheme {
	if urlModified(v) {
		return schemeUnknown
	}
	if v.Kind == "call" {
		switch canonicalHTTPName(symbol(v.Base)) {
		case "urllib.request.Request", "httpx.URL":
			if len(v.Modified) > 0 {
				return schemeUnknown
			}
			return urlScheme(argument(v, 0, "url"))
		}
	}
	prefix, complete, known := stringPrefix(v)
	if !known {
		return schemeUnknown
	}
	lower := strings.ToLower(prefix)
	switch {
	case strings.HasPrefix(lower, "https://"):
		return schemeHTTPS
	case strings.HasPrefix(lower, "http://"):
		return schemeHTTP
	case strings.HasPrefix(prefix, "/"), strings.HasPrefix(prefix, "?"), strings.HasPrefix(prefix, "#"):
		return schemeRelative
	case complete && !strings.ContainsAny(prefix, ":\\\x00\r\n"):
		return schemeRelative
	default:
		return schemeUnknown
	}
}

func stringPrefix(v value) (string, bool, bool) {
	switch v.Kind {
	case "string":
		if text, known := literalText(v); known {
			return boundedPrefix(text)
		}
		return v.Prefix, false, v.Prefix != ""
	case "string-prefix":
		return v.Text, false, true
	case "binary":
		if v.Text != "Add" || len(v.Args) != 2 {
			return "", false, false
		}
		left, leftComplete, leftKnown := stringPrefix(v.Args[0])
		right, rightComplete, rightKnown := stringPrefix(v.Args[1])
		// An opaque operand may replace concatenation through __radd__.
		if !leftKnown || !rightKnown {
			return "", false, false
		}
		if !leftComplete {
			return left, false, true
		}
		prefix, complete, known := boundedPrefix(left + right)
		return prefix, complete && rightComplete, known
	}
	return "", false, false
}

func boundedPrefix(text string) (string, bool, bool) {
	runes := []rune(text)
	if len(runes) > maxURLPrefix {
		return string(runes[:maxURLPrefix]), false, true
	}
	return text, true, true
}

func urlModified(v value) bool {
	for _, field := range []string{"*", "__dict__", "__class__", "base_url", "_base_url", "url", "_url", "full_url", "scheme"} {
		if slices.Contains(v.Modified, field) {
			return true
		}
	}
	return false
}
