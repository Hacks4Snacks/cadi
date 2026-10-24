// Package cli provides CipherTrail's command-line interface.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"ciphertrail/internal/export/cyclonedx"
	"ciphertrail/internal/inventory"
	"ciphertrail/internal/scan"
)

// Version is overridden by release builds.
var Version = "dev"

const usage = `CipherTrail: evidence-driven cryptographic inventory

Usage:
  ciphertrail scan [options] [Go source directory]
  ciphertrail version

Collectors (repeat to combine inputs):
  --source DIR       Go modules and cryptographic call sites
  --file PATH        Supported material, configuration files, directories, or Go binaries
  --image PATH       Single-image Docker save TAR or OCI layout directory
  --manifest PATH    Kubernetes YAML/JSON file or directory (including rendered Helm output)
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
Manifest detection does not run Helm or contact Kubernetes clusters.
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
	scan.Options
	output              string
	includeDependencies bool
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
	flags.Var((*repeated)(&opts.Sources), "source", "Go source directory")
	flags.Var((*repeated)(&opts.Files), "file", "local material/configuration file, directory, or Go binary")
	flags.Var((*repeated)(&opts.Images), "image", "Docker archive or OCI layout directory")
	flags.Var((*repeated)(&opts.Manifests), "manifest", "local Kubernetes YAML/JSON file or directory")
	flags.Var((*repeated)(&opts.TLS), "tls", "TLS host:port")
	flags.Var((*repeated)(&opts.SSH), "ssh", "SSH host:port")
	flags.StringVar(&opts.output, "output", "-", "output file or - for stdout")
	flags.BoolVar(&opts.includeDependencies, "include-dependencies", false, "include the full collected dependency inventory")
	flags.StringVar(&opts.GOOS, "goos", "", "target GOOS")
	flags.StringVar(&opts.GOARCH, "goarch", "", "target GOARCH")
	flags.StringVar(&opts.Tags, "tags", "", "Go build tags")
	flags.BoolVar(&opts.Offline, "offline", false, "use cached Go dependencies only; do not allow downloads")
	flags.Var((*repeated)(&opts.Exclude), "exclude", "Go source-relative file or directory to exclude (repeatable)")
	flags.BoolVar(&opts.IncludeNestedRepos, "include-nested-repos", false, "include nested Git repositories in source discovery")
	flags.DurationVar(&opts.Timeout, "timeout", 5*time.Second, "runtime probe timeout")
	flags.StringVar(&opts.ServerName, "server-name", "", "TLS server name")
	flags.StringVar(&opts.CAFile, "ca-file", "", "TLS CA PEM file")
	flags.StringVar(&opts.ClientCert, "client-cert", "", "mTLS client certificate PEM file")
	flags.StringVar(&opts.ClientKey, "client-key", "", "mTLS private key PEM file")
	flags.BoolVar(&opts.Insecure, "tls-insecure", false, "observe TLS without peer verification")
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
		opts.Sources = append(opts.Sources, flags.Arg(0))
	}
	requests, err := opts.Options.Requests()
	if err != nil {
		fmt.Fprintln(stderr, "ERROR:", err)
		return 2
	}
	if opts.output == "" {
		fmt.Fprintln(stderr, "ERROR: output must be a path or -")
		return 2
	}
	target, err := prepareOutput(opts.output, opts.LocalInputs())
	if err != nil {
		fmt.Fprintln(stderr, "ERROR:", err)
		return 1
	}
	collections := scan.Run(ctx, requests)
	failed := false
	for _, collection := range collections {
		if collection.Err != nil {
			failed = true
			fmt.Fprintf(stderr, "ERROR: %s collection: %v\n", collection.Collector, collection.Err)
		}
		for _, diagnostic := range collection.Result.Diagnostics {
			writeDiagnostic(stderr, diagnostic)
		}
	}
	data, err := cyclonedx.EncodeWithOptions(collections, cyclonedx.EncodeOptions{IncludeDependencies: opts.includeDependencies})
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
