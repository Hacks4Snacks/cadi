package scan

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"ciphertrail/internal/detect"
	"ciphertrail/internal/detect/artifact"
	"ciphertrail/internal/detect/kubernetes"
	"ciphertrail/internal/probe"
	"ciphertrail/internal/scope"
)

// Options separates input locations from passive analyzer selection.
type Options struct {
	Paths, Images, TLS, SSH                   []string
	Analyzers, Exclude                        []string
	GOOS, GOARCH, Tags                        string
	ServerName, CAFile, ClientCert, ClientKey string
	Timeout                                   time.Duration
	Insecure, IncludeNestedRepos, Offline     bool
}

type analyzer struct {
	name string
	file func() detect.Detector
}

var analyzers = []analyzer{
	{name: "go"},
	{name: "python"},
	{name: "kubernetes", file: func() detect.Detector { return kubernetes.Detector{} }},
	{name: "artifact", file: func() detect.Detector { return artifact.Detector{} }},
}

// AnalyzerNames returns the supported passive analyzers in their execution order.
func AnalyzerNames() []string {
	var names []string
	for _, analyzer := range analyzers {
		names = append(names, analyzer.name)
	}
	return names
}

func (o Options) selectedAnalyzers() ([]string, error) {
	if o.Analyzers == nil {
		return AnalyzerNames(), nil
	}
	if len(o.Analyzers) == 0 {
		return nil, errors.New("--analyzers must select at least one analyzer")
	}
	selected := map[string]bool{}
	for _, name := range o.Analyzers {
		name = strings.TrimSpace(name)
		if !slices.Contains(AnalyzerNames(), name) {
			return nil, fmt.Errorf("unknown analyzer %q; choose from %s", name, strings.Join(AnalyzerNames(), ", "))
		}
		selected[name] = true
	}
	var names []string
	for _, name := range AnalyzerNames() {
		if selected[name] {
			names = append(names, name)
		}
	}
	return names, nil
}

func fileDetectors(selected []string) ([]detect.Detector, detect.Detector) {
	var detectors []detect.Detector
	var fallback detect.Detector
	for _, analyzer := range analyzers {
		if analyzer.file != nil && slices.Contains(selected, analyzer.name) {
			detector := analyzer.file()
			detectors = append(detectors, detector)
			if analyzer.name == "artifact" {
				fallback = detector
			}
		}
	}
	return detectors, fallback
}

func (o Options) validate() error {
	for _, inputs := range [][]string{o.Paths, o.Images, o.TLS, o.SSH} {
		for _, value := range inputs {
			if value == "" {
				return errors.New("input must not be empty")
			}
		}
	}
	if len(o.Paths)+len(o.Images)+len(o.TLS)+len(o.SSH) == 0 {
		return errors.New("provide at least one PATH, --image, --tls, or --ssh input")
	}
	if o.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if (o.ClientCert == "") != (o.ClientKey == "") {
		return errors.New("client certificate and key must be supplied together")
	}
	if len(o.TLS) == 0 && (o.Insecure || o.ServerName != "" || o.CAFile != "" || o.ClientCert != "" || o.ClientKey != "") {
		return errors.New("TLS options require a TLS target")
	}
	if len(o.Paths) == 0 && (len(o.Exclude) != 0 || o.IncludeNestedRepos || o.GOOS != "" || o.GOARCH != "" || o.Tags != "") {
		return errors.New("repository and Go options require a PATH input")
	}
	if o.Offline && (len(o.TLS) != 0 || len(o.SSH) != 0) {
		return errors.New("--offline cannot be combined with TLS or SSH network probes")
	}
	for _, addresses := range [][]string{o.TLS, o.SSH} {
		for _, address := range addresses {
			if _, err := probe.EndpointHost(address); err != nil {
				return err
			}
		}
	}
	return scope.ValidateExclusions(o.Exclude)
}

func canonical(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err == nil {
		return filepath.Join(parent, filepath.Base(absolute))
	}
	return absolute
}

func (o Options) additionalRequests(selected []string) []Request {
	var requests []Request
	seen := map[string]bool{}
	for _, path := range o.Images {
		path = canonical(path)
		if seen["image:"+path] {
			continue
		}
		seen["image:"+path] = true
		detectors, _ := fileDetectors(selected)
		requests = append(requests, imageRequest(path, detectors, selected))
	}
	for _, address := range o.TLS {
		if seen["tls:"+address] {
			continue
		}
		seen["tls:"+address] = true
		requests = append(requests, Request{"tls", address, probe.TLS{
			Address: address, ServerName: o.ServerName, Timeout: o.Timeout,
			ClientCert: o.ClientCert, ClientKey: o.ClientKey, CAFile: o.CAFile, Insecure: o.Insecure,
		}})
	}
	for _, address := range o.SSH {
		if seen["ssh:"+address] {
			continue
		}
		seen["ssh:"+address] = true
		requests = append(requests, Request{"ssh", address, probe.SSH{Address: address, Timeout: o.Timeout}})
	}
	return requests
}

// Prepare validates and discovers all passive input work without running analyzers or probes.
func (o Options) Prepare(ctx context.Context, outputs ...string) (Plan, error) {
	if err := o.validate(); err != nil {
		return Plan{}, err
	}
	selected, err := o.selectedAnalyzers()
	if err != nil {
		return Plan{}, err
	}
	if !slices.Contains(selected, "go") && (o.GOOS != "" || o.GOARCH != "" || o.Tags != "") {
		return Plan{}, errors.New("Go build options require the go analyzer")
	}
	return o.prepare(ctx, outputs, selected)
}
