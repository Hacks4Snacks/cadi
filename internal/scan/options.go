package scan

import (
	"errors"
	"path/filepath"
	"time"

	"ciphertrail/internal/detect"
	"ciphertrail/internal/detect/artifact"
	"ciphertrail/internal/detect/kubernetes"
	"ciphertrail/internal/goscan"
	"ciphertrail/internal/input"
	"ciphertrail/internal/probe"
)

// Options describes explicit targets and their source/runtime collection settings.
type Options struct {
	Sources, Files, Images, Manifests, TLS, SSH []string
	Exclude                                     []string
	GOOS, GOARCH, Tags                          string
	ServerName, CAFile, ClientCert, ClientKey   string
	Timeout                                     time.Duration
	Insecure, IncludeNestedRepos, Offline       bool
}

// Requests validates options and composes built-in collectors without performing I/O.
func (o Options) Requests() ([]Request, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	var requests []Request
	for _, path := range o.Sources {
		requests = append(requests, Request{"go", path, goscan.Source{
			Path: path, GOOS: o.GOOS, GOARCH: o.GOARCH, Tags: o.Tags, Exclude: o.Exclude,
			IncludeNestedRepos: o.IncludeNestedRepos, Offline: o.Offline,
		}})
	}
	for _, path := range o.Files {
		requests = append(requests, Request{"file", path, detect.Collector{
			Source: input.Local{Path: path}, Detectors: fileDetectors(), Fallback: artifact.Detector{},
		}})
	}
	for _, path := range o.Images {
		requests = append(requests, Request{"image", path, detect.Collector{Source: input.Image{Path: path}, Detectors: fileDetectors()}})
	}
	for _, path := range o.Manifests {
		requests = append(requests, Request{"kubernetes", path, detect.Collector{
			Source: input.Local{Path: path}, Detectors: []detect.Detector{kubernetes.Detector{Strict: true}},
		}})
	}
	for _, address := range o.TLS {
		requests = append(requests, Request{"tls", address, probe.TLS{
			Address: address, ServerName: o.ServerName, Timeout: o.Timeout,
			ClientCert: o.ClientCert, ClientKey: o.ClientKey, CAFile: o.CAFile, Insecure: o.Insecure,
		}})
	}
	for _, address := range o.SSH {
		requests = append(requests, Request{"ssh", address, probe.SSH{Address: address, Timeout: o.Timeout}})
	}
	return requests, nil
}

func fileDetectors() []detect.Detector {
	return []detect.Detector{artifact.Detector{}, kubernetes.Detector{}}
}

func (o Options) validate() error {
	if len(o.Sources)+len(o.Files)+len(o.Images)+len(o.Manifests)+len(o.TLS)+len(o.SSH) == 0 {
		return errors.New("provide at least one explicit input; use ciphertrail help")
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
	if len(o.Sources) == 0 && (o.GOOS != "" || o.GOARCH != "" || o.Tags != "") {
		return errors.New("Go build options require a source directory")
	}
	if len(o.Sources) == 0 && len(o.Exclude) > 0 {
		return errors.New("Go source exclusions require a source directory")
	}
	if len(o.Sources) == 0 && o.IncludeNestedRepos {
		return errors.New("nested repository inclusion requires a source directory")
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
	return nil
}

// LocalInputs lists inputs that the output writer must not overwrite.
func (o Options) LocalInputs() []string {
	var paths []string
	paths = append(paths, o.Sources...)
	for _, source := range o.Sources {
		paths = append(paths, filepath.Join(source, ".ciphertrailignore"))
	}
	paths = append(paths, o.Files...)
	paths = append(paths, o.Images...)
	paths = append(paths, o.Manifests...)
	for _, credential := range []string{o.CAFile, o.ClientCert, o.ClientKey} {
		if credential != "" {
			paths = append(paths, credential)
		}
	}
	return paths
}
