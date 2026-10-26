// Package cli provides CADI's command-line interface.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"cadi/internal/export/cyclonedx"
	"cadi/internal/inventory"
	"cadi/internal/scan"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/pflag"
)

// Version is overridden by release builds.
var Version = "dev"

const usage = inventory.ProjectName + ` (cadi): evidence-driven cryptographic inventory

Usage:
  cadi scan PATH... [options]
  cadi scan --image PATH | --tls HOST:PORT | --ssh HOST:PORT [options]
  cadi version

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
  --scan-report PATH
                    Write detailed execution metadata to a separate JSON file
  --summary         Show crypto findings with API/library context on stderr
  --include-dependencies
                    Include all collected software; default is crypto-focused

Runtime options:
  --timeout 5s      Deadline per endpoint
  --server-name NAME --ca-file PATH
                    TLS server identity and trust roots
  --client-cert PATH --client-key PATH
                    Optional mTLS identity
  --tls-insecure    Explicitly observe TLS without peer verification

Repository scope reads .cadiignore (and legacy .ciphertrailignore) and excludes generated output, known
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
		fmt.Fprintln(stdout, inventory.ToolName+" "+toolVersion())
		return 0
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return 0
	case "scan":
	default:
		fmt.Fprintln(stderr, "ERROR: unknown command; use cadi help")
		return 2
	}
	var options scan.Options
	var output string
	var reportPath string
	var includeDependencies bool
	var summary bool
	flags := pflag.NewFlagSet("scan", pflag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { fmt.Fprint(stdout, usage) }
	flags.StringSliceVar(&options.Analyzers, "analyzers", nil, "passive analyzers: "+strings.Join(scan.AnalyzerNames(), ","))
	flags.StringArrayVar(&options.Exclude, "exclude", nil, "literal root-relative exclusion")
	flags.StringArrayVar(&options.Images, "image", nil, "Docker archive or OCI layout directory")
	flags.StringArrayVar(&options.TLS, "tls", nil, "explicit TLS host:port")
	flags.StringArrayVar(&options.SSH, "ssh", nil, "explicit SSH host:port")
	flags.StringVar(&output, "output", "-", "output file or - for stdout")
	flags.StringVar(&reportPath, "scan-report", "", "separate JSON scan report file")
	flags.BoolVar(&includeDependencies, "include-dependencies", false, "include the full collected dependency inventory")
	flags.BoolVar(&summary, "summary", false, "show a crypto-focused findings table on stderr")
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
	if flags.Changed("scan-report") && (reportPath == "" || reportPath == "-") {
		fmt.Fprintln(stderr, "ERROR: --scan-report must be a file path, not stdout or an empty value")
		return 2
	}
	plan, err := options.Prepare(ctx, output, reportPath)
	if err != nil {
		fmt.Fprintln(stderr, "ERROR:", err)
		return 2
	}
	protectedInputs := slices.Clone(plan.Inputs)
	if reportPath != "" {
		protectedInputs = append(protectedInputs, reportPath)
	}
	target, err := prepareOutput(output, protectedInputs, outputCBOM)
	if err != nil {
		fmt.Fprintln(stderr, "ERROR:", err)
		return 1
	}
	var reportTarget *outputTarget
	if reportPath != "" {
		protectedInputs = slices.Clone(plan.Inputs)
		if output != "-" {
			protectedInputs = append(protectedInputs, output)
		}
		reportTarget, err = prepareOutput(reportPath, protectedInputs, outputScanReport)
		if err != nil {
			fmt.Fprintln(stderr, "ERROR:", err)
			return 1
		}
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
	version := toolVersion()
	data, outputErr := cyclonedx.EncodeWithOptions(collections, cyclonedx.EncodeOptions{IncludeDependencies: includeDependencies, ToolVersion: version})
	if outputErr == nil {
		if target == nil {
			n, err := stdout.Write(data)
			if err == nil && n != len(data) {
				err = io.ErrShortWrite
			}
			if err != nil {
				outputErr = fmt.Errorf("write CBOM: %w", err)
			}
		} else {
			outputErr = target.write(data)
		}
	}
	if outputErr != nil {
		fmt.Fprintln(stderr, "ERROR:", outputErr)
	}
	if summary && outputErr == nil {
		if err := writeSummary(stderr, data, failed); err != nil {
			fmt.Fprintln(stderr, "ERROR: write findings summary:", err)
			outputErr = fmt.Errorf("write findings summary: %w", err)
		}
	}
	reportFailed := false
	if reportTarget != nil {
		report, err := scan.EncodeReport(collections, scan.ReportOptions{
			ToolVersion: version, IncludeDependencies: includeDependencies, CBOM: data, OutputError: outputErr,
		})
		if err == nil {
			err = reportTarget.write(report)
		}
		if err != nil {
			fmt.Fprintln(stderr, "ERROR: write scan report:", err)
			reportFailed = true
		}
	}
	if failed || outputErr != nil || reportFailed {
		return 1
	}
	return 0
}

func toolVersion() string {
	info, _ := debug.ReadBuildInfo()
	return versionFromBuildInfo(Version, info)
}

func versionFromBuildInfo(version string, info *debug.BuildInfo) string {
	if version != "" && version != "dev" {
		return version
	}
	if info != nil {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			return info.Main.Version
		}
		var revision string
		modified := false
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				revision = setting.Value
			case "vcs.modified":
				modified = setting.Value == "true"
			}
		}
		if revision != "" {
			value := "dev+" + revision[:min(len(revision), 12)]
			if modified {
				value += ".dirty"
			}
			return value
		}
	}
	return "dev"
}

func writeSummary(writer io.Writer, data []byte, incomplete bool) error {
	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return fmt.Errorf("decode validated CBOM: %w", err)
	}
	components := map[string]cdx.Component{}
	var assets []cdx.Component
	addComponent := func(component cdx.Component) {
		components[component.BOMRef] = component
		if component.Type == cdx.ComponentTypeCryptographicAsset {
			assets = append(assets, component)
		}
	}
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		addComponent(*bom.Metadata.Component)
	}
	if bom.Components != nil {
		for _, component := range *bom.Components {
			addComponent(component)
		}
	}
	providers := map[string][]string{}
	if bom.Dependencies != nil {
		for _, dependency := range *bom.Dependencies {
			if dependency.Dependencies == nil {
				continue
			}
			for _, ref := range *dependency.Dependencies {
				component, exists := components[ref]
				if !exists {
					return fmt.Errorf("summary dependency %q is missing", ref)
				}
				if component.Type == cdx.ComponentTypeLibrary {
					providers[dependency.Ref] = append(providers[dependency.Ref], component.Name)
				}
			}
		}
	}
	slices.SortFunc(assets, func(a, b cdx.Component) int {
		if order := strings.Compare(a.Name, b.Name); order != 0 {
			return order
		}
		return strings.Compare(a.BOMRef, b.BOMRef)
	})
	var output strings.Builder
	fmt.Fprintf(&output, "\nCryptographic findings: %d", len(assets))
	if incomplete {
		output.WriteString(" (INCOMPLETE)")
	}
	output.WriteByte('\n')
	if len(assets) == 0 {
		output.WriteString("None collected; see coverage and diagnostics. This does not establish absence of cryptography.\n")
	} else {
		table := tabwriter.NewWriter(&output, 0, 4, 2, ' ', 0)
		fmt.Fprintln(table, "ASSET\tKIND\tEVIDENCE\tSOURCE\tAPI / LIBRARY")
		for _, asset := range assets {
			var kinds, locations []string
			if asset.Properties != nil {
				for _, property := range *asset.Properties {
					if property.Name == "cadi:evidence-kind" {
						if property.Value != "" {
							kinds = append(kinds, property.Value)
						}
						continue
					}
					if property.Name != "cadi:provenance" {
						continue
					}
					var evidence struct{ Kind string }
					if err := json.Unmarshal([]byte(property.Value), &evidence); err != nil {
						return fmt.Errorf("decode summary evidence for %q: %w", asset.Name, err)
					}
					if evidence.Kind != "" {
						kinds = append(kinds, evidence.Kind)
					}
				}
			}
			if asset.Evidence != nil && asset.Evidence.Occurrences != nil {
				for _, occurrence := range *asset.Evidence.Occurrences {
					location := occurrence.Location
					if occurrence.Line != nil && *occurrence.Line > 0 {
						location += ":" + strconv.Itoa(*occurrence.Line)
					}
					if location != "" {
						locations = append(locations, location)
					}
				}
			}
			kind := "unspecified"
			if asset.CryptoProperties != nil && asset.CryptoProperties.AssetType != "" {
				kind = string(asset.CryptoProperties.AssetType)
			}
			fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\n",
				summaryCell(asset.Name), summaryCell(kind), summaryCell(summaryValues(kinds)),
				summaryCell(summaryValues(locations)), summaryCell(summaryValues(providers[asset.BOMRef])))
		}
		if err := table.Flush(); err != nil {
			return fmt.Errorf("format findings summary: %w", err)
		}
	}
	text := output.String()
	n, err := io.WriteString(writer, text)
	if err == nil && n != len(text) {
		err = io.ErrShortWrite
	}
	return err
}

func summaryValues(values []string) string {
	slices.Sort(values)
	values = slices.Compact(values)
	if len(values) == 0 {
		return "-"
	}
	return strings.Join(values, "; ")
}

func summaryCell(value string) string {
	quoted := strconv.Quote(value)
	return quoted[1 : len(quoted)-1]
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
