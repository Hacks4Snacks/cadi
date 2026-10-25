// Package cli provides CipherTrail's command-line interface.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"ciphertrail/internal/export/cyclonedx"
	"ciphertrail/internal/inventory"
	"ciphertrail/internal/scan"

	"github.com/spf13/pflag"
)

// Version is overridden by release builds.
var Version = "dev"

const usage = `CipherTrail: evidence-driven cryptographic inventory

Usage:
  ciphertrail scan PATH... [options]
  ciphertrail scan --image PATH | --tls HOST:PORT | --ssh HOST:PORT [options]
  ciphertrail version

PATH inputs:
  Directories are mixed repositories; files are explicit passive inputs.
  Repeat paths to combine repositories, rendered manifests, and material files.
  Flags may appear before or after paths. Use -- before a path beginning with -.

Analysis:
  --analyzers go,python,kubernetes,artifact
                    Select passive analyzers (default: all supported analyzers)
  --exclude PATH    Exclude a literal root-relative file/directory for all analyzers
  --include-nested-repos
                    Include nested Git repositories (default: separate roots)
  --goos OS --goarch ARCH --tags TAGS
                    Build context for Go source analysis
  --offline         Disable dependency downloads and disallow TLS/SSH probes

Additional explicit inputs:
  --image PATH      Single-image Docker save TAR or OCI layout directory
  --tls HOST:PORT   One TLS handshake, with public certificate metadata
  --ssh HOST:PORT   SSH host key, stopping before authentication

Output:
  --output PATH     CycloneDX 1.7 JSON (default: stdout)
  --include-dependencies
                    Include all collected software; default is crypto-focused

Runtime options:
  --timeout 5s      Deadline per endpoint
  --server-name NAME --ca-file PATH
                    TLS server identity and trust roots
  --client-cert PATH --client-key PATH
                    Optional mTLS identity
  --tls-insecure    Explicitly observe TLS without peer verification

Repository scope reads .ciphertrailignore and excludes generated output, known
test/dependency directories, and nested Git repositories by default. Explicit
file inputs can select material inside default-excluded directories.
Helm templates require separately rendered YAML/JSON; charts are not executed.
Python source analysis requires a trusted Python 3.10+ interpreter on PATH.
No network discovery, source uploads, policy verdicts, or target execution.
`

// Run returns 0 on completed collection, 1 on operational failure, and 2 on invalid usage.
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
	var options scan.Options
	var output string
	var includeDependencies bool
	flags := pflag.NewFlagSet("scan", pflag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { fmt.Fprint(stdout, usage) }
	flags.StringSliceVar(&options.Analyzers, "analyzers", nil, "passive analyzers: "+strings.Join(scan.AnalyzerNames(), ","))
	flags.StringArrayVar(&options.Exclude, "exclude", nil, "literal root-relative exclusion")
	flags.StringArrayVar(&options.Images, "image", nil, "Docker archive or OCI layout directory")
	flags.StringArrayVar(&options.TLS, "tls", nil, "explicit TLS host:port")
	flags.StringArrayVar(&options.SSH, "ssh", nil, "explicit SSH host:port")
	flags.StringVar(&output, "output", "-", "output file or - for stdout")
	flags.BoolVar(&includeDependencies, "include-dependencies", false, "include the full collected dependency inventory")
	flags.StringVar(&options.GOOS, "goos", "", "target GOOS")
	flags.StringVar(&options.GOARCH, "goarch", "", "target GOARCH")
	flags.StringVar(&options.Tags, "tags", "", "Go build tags")
	flags.BoolVar(&options.Offline, "offline", false, "use cached Go dependencies only; no runtime probes")
	flags.BoolVar(&options.IncludeNestedRepos, "include-nested-repos", false, "include nested Git repositories")
	flags.DurationVar(&options.Timeout, "timeout", 5*time.Second, "runtime probe timeout")
	flags.StringVar(&options.ServerName, "server-name", "", "TLS server name")
	flags.StringVar(&options.CAFile, "ca-file", "", "TLS CA PEM file")
	flags.StringVar(&options.ClientCert, "client-cert", "", "mTLS client certificate PEM file")
	flags.StringVar(&options.ClientKey, "client-key", "", "mTLS private key PEM file")
	flags.BoolVar(&options.Insecure, "tls-insecure", false, "observe TLS without peer verification")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "ERROR:", err)
		return 2
	}
	options.Paths = flags.Args()
	if output == "" {
		fmt.Fprintln(stderr, "ERROR: output must be a path or -")
		return 2
	}
	plan, err := options.Prepare(ctx, output)
	if err != nil {
		fmt.Fprintln(stderr, "ERROR:", err)
		return 2
	}
	target, err := prepareOutput(output, plan.Inputs)
	if err != nil {
		fmt.Fprintln(stderr, "ERROR:", err)
		return 1
	}
	collections := scan.Run(ctx, plan.Requests)
	failed := false
	for _, collection := range collections {
		if collection.Err != nil {
			failed = true
			fmt.Fprintf(stderr, "ERROR: %s collection: %v\n", collection.Collector, collection.Err)
		}
		writeCoverage(stderr, collection)
		writeDiagnostics(stderr, collection.Result.Diagnostics)
	}
	data, err := cyclonedx.EncodeWithOptions(collections, cyclonedx.EncodeOptions{IncludeDependencies: includeDependencies})
	if err != nil {
		fmt.Fprintln(stderr, "ERROR:", err)
		return 1
	}
	if target == nil {
		n, err := stdout.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		if err != nil {
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

func writeCoverage(writer io.Writer, collection inventory.Collection) {
	var parts []string
	for _, coverage := range collection.Result.Coverage {
		part := coverage.Analyzer + "=" + coverage.Status
		if coverage.Modules > 0 {
			part += fmt.Sprintf(" modules=%d", coverage.Modules)
		}
		if coverage.Files > 0 {
			part += fmt.Sprintf(" files=%d", coverage.Files)
		}
		if coverage.Findings > 0 {
			part += fmt.Sprintf(" crypto=%d", coverage.Findings)
		}
		if coverage.Skipped > 0 {
			part += fmt.Sprintf(" skipped=%d", coverage.Skipped)
		}
		if coverage.Reason != "" {
			part += " (" + coverage.Reason + ")"
		}
		parts = append(parts, part)
	}
	if len(parts) > 0 {
		fmt.Fprintf(writer, "INFO: %s: %s\n", collection.Target, strings.Join(parts, "; "))
	}
}

func writeDiagnostics(writer io.Writer, diagnostics []inventory.Diagnostic) {
	counts := map[string]int{}
	for _, diagnostic := range diagnostics {
		counts[diagnostic.Message]++
	}
	for _, diagnostic := range diagnostics {
		count := counts[diagnostic.Message]
		if count == 0 {
			continue
		}
		delete(counts, diagnostic.Message)
		if count > 1 {
			diagnostic.Message = fmt.Sprintf("%s (%d occurrences; details retained in CBOM)", diagnostic.Message, count)
		}
		writeDiagnostic(writer, diagnostic)
	}
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
