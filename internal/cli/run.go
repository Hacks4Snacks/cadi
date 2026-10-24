// Package cli provides CipherTrail's command-line interface.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"ciphertrail/internal/artifact"
	"ciphertrail/internal/goscan"
	"ciphertrail/internal/inventory"
	"ciphertrail/internal/probe"
)

// Version is overridden by release builds.
var Version = "dev"

const usage = `CipherTrail: evidence-driven cryptographic inventory

Usage:
  ciphertrail scan [options] [Go source directory]
  ciphertrail version

Collectors (repeat to combine inputs):
  --source DIR       Go modules and cryptographic call sites
  --file PATH        Certificate/key files, directories, or Go binaries
  --image PATH       Single-image Docker save TAR or OCI layout directory
  --tls HOST:PORT    One TLS handshake, with public certificate metadata
  --ssh HOST:PORT    SSH host key, stopping before authentication

Output:
  --output PATH      CycloneDX 1.7 JSON (default: stdout)
  --include-dependencies
                    Include all collected software; default is crypto-focused

Runtime options:
  --timeout 5s       Deadline per endpoint
  --server-name NAME Override TLS SNI and hostname verification
  --ca-file PATH    PEM trust roots for TLS verification
  --client-cert PATH --client-key PATH
                    Optional mTLS client identity
  --tls-insecure    Explicitly observe TLS without verifying the peer

Go options:
  --goos OS --goarch ARCH --tags TAGS
  --offline         Disable dependency downloads; incompatible with TLS/SSH probes
  --exclude PATH    Exclude a Go source-relative file/directory (repeatable)
  --include-nested-repos
                    Descend into nested Git repositories (default: separate roots)

Go source scans prepare missing dependencies using existing Go settings, then
analyze offline. They also read .ciphertrailignore at each source root.

Place flags before the optional positional directory.
No network discovery, source uploads, policy verdicts, or target execution.
`

type repeated []string

func (r *repeated) String() string { return fmt.Sprint([]string(*r)) }
func (r *repeated) Set(value string) error {
	if value == "" {
		return errors.New("input must not be empty")
	}
	*r = append(*r, value)
	return nil
}

type options struct {
	sources, files, images, tls, ssh repeated
	excludes                         repeated
	output, goos, goarch, tags       string
	serverName, ca, cert, key        string
	timeout                          time.Duration
	insecure                         bool
	includeDependencies              bool
	includeNestedRepos               bool
	offline                          bool
}

type request struct {
	name, target string
	collector    inventory.Collector
}

// Run returns 0 on successful collection, 1 on operational failure, and 2 on invalid usage.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintln(stdout, "ciphertrail "+Version)
		return 0
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return 0
	case "scan":
	default:
		fmt.Fprintln(stderr, "ERROR: unknown command; use ciphertrail help")
		return 2
	}
	var opts options
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { fmt.Fprint(stderr, usage) }
	flags.Var(&opts.sources, "source", "Go source directory")
	flags.Var(&opts.files, "file", "local cryptographic file, directory, or Go binary")
	flags.Var(&opts.images, "image", "Docker archive or OCI layout directory")
	flags.Var(&opts.tls, "tls", "TLS host:port")
	flags.Var(&opts.ssh, "ssh", "SSH host:port")
	flags.StringVar(&opts.output, "output", "-", "output file or - for stdout")
	flags.BoolVar(&opts.includeDependencies, "include-dependencies", false, "include the full collected dependency inventory")
	flags.StringVar(&opts.goos, "goos", "", "target GOOS")
	flags.StringVar(&opts.goarch, "goarch", "", "target GOARCH")
	flags.StringVar(&opts.tags, "tags", "", "Go build tags")
	flags.BoolVar(&opts.offline, "offline", false, "use cached Go dependencies only; do not allow downloads")
	flags.Var(&opts.excludes, "exclude", "Go source-relative file or directory to exclude (repeatable)")
	flags.BoolVar(&opts.includeNestedRepos, "include-nested-repos", false, "include nested Git repositories in source discovery")
	flags.DurationVar(&opts.timeout, "timeout", 5*time.Second, "runtime probe timeout")
	flags.StringVar(&opts.serverName, "server-name", "", "TLS server name")
	flags.StringVar(&opts.ca, "ca-file", "", "TLS CA PEM file")
	flags.StringVar(&opts.cert, "client-cert", "", "mTLS client certificate PEM file")
	flags.StringVar(&opts.key, "client-key", "", "mTLS private key PEM file")
	flags.BoolVar(&opts.insecure, "tls-insecure", false, "observe TLS without peer verification")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() > 1 {
		fmt.Fprintln(stderr, "ERROR: provide at most one positional source directory; place options before it")
		return 2
	}
	if flags.NArg() == 1 {
		opts.sources = append(opts.sources, flags.Arg(0))
	}
	if err := opts.validate(); err != nil {
		fmt.Fprintln(stderr, "ERROR:", err)
		return 2
	}
	target, err := prepareOutput(opts.output, opts.localInputs())
	if err != nil {
		fmt.Fprintln(stderr, "ERROR:", err)
		return 1
	}
	var collections []inventory.Collection
	failed := false
	for _, request := range opts.requests() {
		result, err := request.collector.Collect(ctx)
		collections = append(collections, inventory.Collection{
			Collector: request.name, Target: request.target, Result: result, Err: err,
		})
		if err != nil {
			failed = true
			fmt.Fprintf(stderr, "ERROR: %s collection: %v\n", request.name, err)
		}
		for _, diagnostic := range result.Diagnostics {
			writeDiagnostic(stderr, diagnostic)
		}
	}
	data, err := inventory.EncodeWithOptions(collections, inventory.EncodeOptions{IncludeDependencies: opts.includeDependencies})
	if err != nil {
		fmt.Fprintln(stderr, "ERROR:", err)
		return 1
	}
	if target == nil {
		n, err := stdout.Write(data)
		if err != nil || n != len(data) {
			if err == nil {
				err = io.ErrShortWrite
			}
			fmt.Fprintln(stderr, "ERROR: write CBOM:", err)
			return 1
		}
	} else if err := target.write(data); err != nil {
		fmt.Fprintln(stderr, "ERROR:", err)
		return 1
	}
	if failed {
		return 1
	}
	return 0
}

func writeDiagnostic(writer io.Writer, diagnostic inventory.Diagnostic) {
	if diagnostic.Location == "" {
		fmt.Fprintf(writer, "NOTE: %s\n", diagnostic.Message)
	} else if diagnostic.Line > 0 {
		fmt.Fprintf(writer, "NOTE: %s:%d: %s\n", diagnostic.Location, diagnostic.Line, diagnostic.Message)
	} else {
		fmt.Fprintf(writer, "NOTE: %s: %s\n", diagnostic.Location, diagnostic.Message)
	}
}

func (o options) validate() error {
	if len(o.sources)+len(o.files)+len(o.images)+len(o.tls)+len(o.ssh) == 0 {
		return errors.New("provide at least one explicit input; use ciphertrail help")
	}
	if o.timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if o.output == "" {
		return errors.New("output must be a path or -")
	}
	if (o.cert == "") != (o.key == "") {
		return errors.New("client certificate and key must be supplied together")
	}
	if len(o.tls) == 0 && (o.insecure || o.serverName != "" || o.ca != "" || o.cert != "" || o.key != "") {
		return errors.New("TLS options require a TLS target")
	}
	if len(o.sources) == 0 && (o.goos != "" || o.goarch != "" || o.tags != "") {
		return errors.New("Go build options require a source directory")
	}
	if len(o.sources) == 0 && len(o.excludes) > 0 {
		return errors.New("Go source exclusions require a source directory")
	}
	if len(o.sources) == 0 && o.includeNestedRepos {
		return errors.New("nested repository inclusion requires a source directory")
	}
	if o.offline && (len(o.tls) != 0 || len(o.ssh) != 0) {
		return errors.New("--offline cannot be combined with TLS or SSH network probes")
	}
	for _, addresses := range []repeated{o.tls, o.ssh} {
		for _, address := range addresses {
			if _, err := probe.EndpointHost(address); err != nil {
				return err
			}
		}
	}
	return nil
}

func (o options) localInputs() []string {
	var paths []string
	paths = append(paths, o.sources...)
	for _, source := range o.sources {
		paths = append(paths, filepath.Join(source, ".ciphertrailignore"))
	}
	paths = append(paths, o.files...)
	paths = append(paths, o.images...)
	for _, credential := range []string{o.ca, o.cert, o.key} {
		if credential != "" {
			paths = append(paths, credential)
		}
	}
	return paths
}

func (o options) requests() []request {
	var requests []request
	for _, path := range o.sources {
		requests = append(requests, request{"go", path, goscan.Source{
			Path: path, GOOS: o.goos, GOARCH: o.goarch, Tags: o.tags, Exclude: o.excludes,
			IncludeNestedRepos: o.includeNestedRepos,
			Offline:            o.offline,
		}})
	}
	for _, path := range o.files {
		requests = append(requests, request{"file", path, artifact.Files{Path: path}})
	}
	for _, path := range o.images {
		requests = append(requests, request{"image", path, artifact.Image{Path: path}})
	}
	for _, address := range o.tls {
		requests = append(requests, request{"tls", address, probe.TLS{
			Address: address, ServerName: o.serverName, Timeout: o.timeout,
			ClientCert: o.cert, ClientKey: o.key, CAFile: o.ca, Insecure: o.insecure,
		}})
	}
	for _, address := range o.ssh {
		requests = append(requests, request{"ssh", address, probe.SSH{Address: address, Timeout: o.timeout}})
	}
	return requests
}
