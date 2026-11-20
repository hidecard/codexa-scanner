package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

type cliAuditOptions struct {
	URLs         []string
	FailOn       string
	JSONPath     string
	SARIFPath    string
	AllowPrivate bool
	Timeout      int
	RulesPath    string
}

type stringListFlag []string

func (s *stringListFlag) String() string { return strings.Join(*s, ",") }
func (s *stringListFlag) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("--url must not be empty")
	}
	*s = append(*s, strings.TrimSpace(value))
	return nil
}

func parseAuditArgs(args []string, stderr io.Writer) (cliAuditOptions, error) {
	options := cliAuditOptions{FailOn: "high", Timeout: 10}
	set := flag.NewFlagSet("audit", flag.ContinueOnError)
	set.SetOutput(stderr)
	set.Var((*stringListFlag)(&options.URLs), "url", "URL to audit (may be repeated; max 100)")
	set.StringVar(&options.FailOn, "fail-on", options.FailOn, "minimum finding severity for exit code 1: critical, high, medium, low, info")
	set.StringVar(&options.JSONPath, "json", "", "write a redacted, versioned JSON report to this path (use - for stdout)")
	set.StringVar(&options.SARIFPath, "sarif", "", "write a SARIF 2.1.0 report to this path (use - for stdout)")
	set.BoolVar(&options.AllowPrivate, "allow-private", false, "allow private/loopback lab targets for this run")
	set.IntVar(&options.Timeout, "timeout", options.Timeout, "per-request timeout in seconds (3–60)")
	set.StringVar(&options.RulesPath, "rules", "", "path to custom rules file (YAML or JSON) for secret patterns, header rules, and path wordlists")
	if err := set.Parse(args); err != nil {
		return options, err
	}
	if len(set.Args()) != 0 {
		return options, fmt.Errorf("unexpected positional arguments: %s", strings.Join(set.Args(), " "))
	}
	if len(options.URLs) == 0 {
		return options, errors.New("at least one --url is required")
	}
	if len(options.URLs) > 100 {
		return options, errors.New("at most 100 --url values are accepted")
	}
	if _, ok := severityRank(options.FailOn); !ok {
		return options, fmt.Errorf("invalid --fail-on value %q (choose critical, high, medium, low, or info)", options.FailOn)
	}
	if options.Timeout < 3 || options.Timeout > 60 {
		return options, errors.New("--timeout must be between 3 and 60 seconds")
	}
	if options.JSONPath == "-" && options.SARIFPath == "-" {
		return options, errors.New("--json and --sarif cannot both write to stdout")
	}
	return options, nil
}

func severityRank(severity string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 5, true
	case "high":
		return 4, true
	case "medium":
		return 3, true
	case "low":
		return 2, true
	case "info":
		return 1, true
	default:
		return 0, false
	}
}

func resultsMeetFailureThreshold(results []BulkHeaderResult, threshold string) bool {
	thresholdRank, ok := severityRank(threshold)
	if !ok {
		return false
	}
	for _, result := range results {
		for _, finding := range result.Findings {
			if rank, valid := severityRank(finding.Severity); valid && rank >= thresholdRank {
				return true
			}
		}
	}
	return false
}

func writeCLIAuditReport(path string, results []BulkHeaderResult) ([]byte, error) {
	data, err := json.Marshal(results)
	if err != nil {
		return nil, err
	}
	_, report, err := prepareScanReportEnvelope("http_security_audit.json", string(data), nil)
	if err != nil {
		return nil, err
	}
	if path == "-" {
		return report, nil
	}
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("report path is empty")
	}
	if err := os.WriteFile(path, report, 0600); err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	return report, nil
}

func writeCLISARIFReport(path string, results []BulkHeaderResult) ([]byte, error) {
	report, err := marshalSARIFReport(results)
	if err != nil {
		return nil, err
	}
	if path == "-" {
		return report, nil
	}
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("SARIF report path is empty")
	}
	if err := os.WriteFile(path, report, 0600); err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	return report, nil
}

func runAudit(args []string, stdout, stderr io.Writer) int {
	options, err := parseAuditArgs(args, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "codexa-scanner audit: %v\n", err)
		return 2
	}
	app := NewApp()

	// Load custom rules if specified
	var customRules *CustomRulesFile
	if options.RulesPath != "" {
		customRules, err = loadCustomRules(options.RulesPath)
		if err != nil {
			fmt.Fprintf(stderr, "codexa-scanner audit: loading custom rules: %v\n", err)
			return 2
		}
	}

	results := app.AnalyzeBulkURLs(strings.Join(options.URLs, "\n"), 10, options.AllowPrivate, 0, 0, 0, "", options.Timeout, nil, "", "", "", customRules)
	if len(results) == 0 {
		fmt.Fprintln(stderr, "codexa-scanner audit: no valid targets were accepted")
		return 2
	}
	var report []byte
	if options.JSONPath != "" {
		report, err = writeCLIAuditReport(options.JSONPath, results)
		if err != nil {
			fmt.Fprintf(stderr, "codexa-scanner audit: writing JSON report: %v\n", err)
			return 2
		}
	}
	var sarif []byte
	if options.SARIFPath != "" {
		sarif, err = writeCLISARIFReport(options.SARIFPath, results)
		if err != nil {
			fmt.Fprintf(stderr, "codexa-scanner audit: writing SARIF report: %v\n", err)
			return 2
		}
	}
	stdoutReport := ""
	if options.JSONPath == "-" {
		stdoutReport = "JSON"
	} else if options.SARIFPath == "-" {
		stdoutReport = "SARIF"
		report = sarif
	}
	if stdoutReport != "" {
		if _, err := io.Copy(stdout, bytes.NewReader(report)); err != nil {
			fmt.Fprintf(stderr, "codexa-scanner audit: writing %s to stdout: %v\n", stdoutReport, err)
			return 2
		}
	} else {
		for _, result := range results {
			if result.Error != "" {
				fmt.Fprintf(stdout, "ERROR %s: %s\n", result.URL, result.Error)
				continue
			}
			fmt.Fprintf(stdout, "Grade %s | risk %d/100 | %s\n", result.Grade, result.RiskScore, result.URL)
			for _, finding := range result.Findings {
				fmt.Fprintf(stdout, "  [%s] %s\n", strings.ToUpper(finding.Severity), finding.Title)
			}
		}
		if options.JSONPath != "" {
			fmt.Fprintf(stdout, "JSON report: %s\n", options.JSONPath)
		}
		if options.SARIFPath != "" {
			fmt.Fprintf(stdout, "SARIF report: %s\n", options.SARIFPath)
		}
	}
	for _, result := range results {
		if result.Error != "" {
			return 2
		}
	}
	if resultsMeetFailureThreshold(results, options.FailOn) {
		return 1
	}
	return 0
}

func runCLI(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return 0
	}
	command := args[0]
	if command == "--cli" {
		args = args[1:]
		if len(args) == 0 {
			fmt.Fprintln(stderr, "usage: codexa-scanner --cli audit --url <http(s)://target>")
			return 2
		}
		command = args[0]
		args = args[1:]
	} else {
		args = args[1:]
	}
	if command == "help" || command == "--help" || command == "-h" {
		fmt.Fprintln(stdout, "Codexa Scanner headless mode\n\nUsage:\n  codexa-scanner audit --url <http(s)://target> [--url <target> ...] [--fail-on high] [--json report.json] [--sarif report.sarif] [--rules rules.yaml]\n  codexa-scanner import nmap-xml <file.xml> [--json report.json]\n  codexa-scanner import subdomains <file.txt> [--json report.json]\n  codexa-scanner inspect <url> [--method GET|HEAD|OPTIONS] [--header 'Key: Value'] [--allow-private] [--timeout 10] [--json -]\n  codexa-scanner audit --help\n  codexa-scanner import --help\n  codexa-scanner inspect --help\n\nExit codes: 0 no finding at/above threshold; 1 threshold reached; 2 usage, target, network, or report error.\nPrivate/loopback targets require the explicit --allow-private flag. Commands are bounded Web Audits; only use targets you are authorized to assess.")
		return 0
	}
	if command == "import" {
		if len(args) == 0 {
			fmt.Fprintln(stderr, "usage: codexa-scanner import nmap-xml|subdomains <file> [--json report.json]")
			return 2
		}
		subCommand := args[0]
		args = args[1:]
		if subCommand == "help" || subCommand == "--help" || subCommand == "-h" {
			fmt.Fprintln(stdout, "Usage: codexa-scanner import nmap-xml <file.xml> [--json report.json|-]\n       codexa-scanner import subdomains <file.txt> [--json report.json|-]\n\nImports external tool output into local history.\n  nmap-xml: Parses nmap -oX XML output, stores port scans, and identifies HTTP/HTTPS endpoints.\n  subdomains: Imports newline-delimited subdomain lists from subfinder, amass, etc.\n\nExit codes: 0 success; 2 usage, file, or parse error.")
			return 0
		}
		if subCommand == "nmap-xml" {
			return runImportNmapXML(args, stdout, stderr)
		}
		if subCommand == "subdomains" {
			return runImportSubdomains(args, stdout, stderr)
		}
		fmt.Fprintf(stderr, "unknown import command %q (use 'codexa-scanner import --help')\n", subCommand)
		return 2
	}
	if command == "inspect" {
		return runHTTPInspect(args, stdout, stderr)
	}
	if command != "audit" {
		fmt.Fprintf(stderr, "unknown command %q (use 'codexa-scanner help')\n", command)
		return 2
	}
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(stdout, "Usage: codexa-scanner audit --url <http(s)://target> [--url <target> ...] [--fail-on critical|high|medium|low|info] [--json report.json|-] [--sarif report.sarif|-] [--allow-private] [--timeout 3..60] [--rules rules.yaml]\n\nExit codes: 0 below threshold; 1 threshold reached; 2 invalid input or execution/report error.")
		return 0
	}
	return runAudit(args, stdout, stderr)
}

func runHTTPInspect(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: codexa-scanner inspect <url> [--method GET|HEAD|OPTIONS] [--header 'Key: Value'] [--allow-private] [--timeout 10] [--json -]")
		return 2
	}
	if args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, "Usage: codexa-scanner inspect <url> [--method GET|HEAD|OPTIONS] [--header 'Key: Value'] [--allow-private] [--timeout 10] [--json -]\n\nInspects a URL and displays raw request/response headers and body (truncated to 64 KiB).\nOnly safe methods (GET, HEAD, OPTIONS) are allowed.\n\nExit codes: 0 success; 2 usage, network, or parse error.")
		return 0
	}

	url := ""
	method := "GET"
	headers := make(map[string]string)
	allowPrivate := false
	timeout := 10
	jsonPath := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--method":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "--method requires a value")
				return 2
			}
			method = args[i+1]
			i++
		case "--header":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "--header requires a 'Key: Value' value")
				return 2
			}
			parts := strings.SplitN(args[i+1], ":", 2)
			if len(parts) != 2 {
				fmt.Fprintln(stderr, "--header format must be 'Key: Value'")
				return 2
			}
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			i++
		case "--allow-private":
			allowPrivate = true
		case "--timeout":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "--timeout requires a value")
				return 2
			}
			var err error
			timeout, err = strconv.Atoi(args[i+1])
			if err != nil || timeout < 3 || timeout > 60 {
				fmt.Fprintln(stderr, "--timeout must be between 3 and 60")
				return 2
			}
			i++
		case "--json":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "--json requires a path")
				return 2
			}
			jsonPath = args[i+1]
			i++
		default:
			if url == "" {
				url = args[i]
			} else {
				fmt.Fprintf(stderr, "unexpected argument: %s\n", args[i])
				return 2
			}
		}
	}

	if url == "" {
		fmt.Fprintln(stderr, "missing URL")
		return 2
	}

	app := NewApp()
	req := HTTPInspectorRequest{
		URL:            url,
		Method:         method,
		Headers:        headers,
		AllowPrivate:   allowPrivate,
		TimeoutSeconds: timeout,
	}
	result := app.InspectHTTP(req)

	if jsonPath != "" {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "codexa-scanner inspect: encoding JSON: %v\n", err)
			return 2
		}
		if jsonPath == "-" {
			fmt.Fprintln(stdout, string(data))
		} else {
			if err := os.WriteFile(jsonPath, data, 0600); err != nil {
				fmt.Fprintf(stderr, "codexa-scanner inspect: writing JSON: %v\n", err)
				return 2
			}
			fmt.Fprintf(stdout, "Inspection result written to %s\n", jsonPath)
		}
	} else {
		if result.Error != "" {
			fmt.Fprintf(stderr, "Error: %s\n", result.Error)
			return 2
		}
		if result.Request != nil {
			fmt.Fprintf(stdout, "REQUEST %s %s\n", result.Request.Method, result.Request.URL)
			for k, v := range result.Request.Headers {
				fmt.Fprintf(stdout, "%s: %s\n", k, v)
			}
			if result.Request.Body != "" {
				fmt.Fprintln(stdout)
				fmt.Fprintln(stdout, result.Request.Body)
			}
			fmt.Fprintln(stdout)
		}
		if result.Response != nil {
			fmt.Fprintf(stdout, "RESPONSE HTTP/1.1 %d\n", result.Response.StatusCode)
			for k, v := range result.Response.Headers {
				fmt.Fprintf(stdout, "%s: %s\n", k, v)
			}
			fmt.Fprintln(stdout)
			if result.Response.Body != "" {
				fmt.Fprintln(stdout, result.Response.Body)
			}
			if result.Response.BodyTruncated {
				fmt.Fprintln(stdout, "... (body truncated to 64 KiB)")
			}
		}
	}
	return 0
}

func runImportNmapXML(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: codexa-scanner import nmap-xml <file.xml> [--json report.json|-]")
		return 2
	}
	jsonPath := ""
	filePath := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--json" {
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "--json requires a path")
				return 2
			}
			jsonPath = args[i+1]
			i++
		} else if filePath == "" {
			filePath = args[i]
		} else {
			fmt.Fprintf(stderr, "unexpected argument: %s\n", args[i])
			return 2
		}
	}
	if filePath == "" {
		fmt.Fprintln(stderr, "missing input file")
		return 2
	}
	app := NewApp()
	result, err := app.ImportNmapXMLFile(filePath)
	if err != nil {
		fmt.Fprintf(stderr, "codexa-scanner import nmap-xml: %v\n", err)
		return 2
	}
	if jsonPath != "" {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "codexa-scanner import nmap-xml: encoding JSON: %v\n", err)
			return 2
		}
		if jsonPath == "-" {
			fmt.Fprintln(stdout, string(data))
		} else {
			if err := os.WriteFile(jsonPath, data, 0600); err != nil {
				fmt.Fprintf(stderr, "codexa-scanner import nmap-xml: writing JSON: %v\n", err)
				return 2
			}
			fmt.Fprintf(stdout, "Import result written to %s\n", jsonPath)
		}
	} else {
		fmt.Fprintf(stdout, "Hosts processed: %d\n", result.HostsProcessed)
		fmt.Fprintf(stdout, "Hosts up: %d\n", result.HostsUp)
		fmt.Fprintf(stdout, "Open ports found: %d\n", result.PortsFound)
		fmt.Fprintf(stdout, "HTTP/HTTPS endpoints: %d\n", result.WebEndpointsFound)
		if len(result.Errors) > 0 {
			fmt.Fprintln(stdout, "Errors:")
			for _, e := range result.Errors {
				fmt.Fprintf(stdout, "  %s\n", e)
			}
		}
	}
	return 0
}

func runImportSubdomains(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: codexa-scanner import subdomains <file.txt> [--json report.json|-]")
		return 2
	}
	jsonPath := ""
	filePath := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--json" {
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "--json requires a path")
				return 2
			}
			jsonPath = args[i+1]
			i++
		} else if filePath == "" {
			filePath = args[i]
		} else {
			fmt.Fprintf(stderr, "unexpected argument: %s\n", args[i])
			return 2
		}
	}
	if filePath == "" {
		fmt.Fprintln(stderr, "missing input file")
		return 2
	}
	app := NewApp()
	result, err := app.ImportSubdomainsFile(filePath)
	if err != nil {
		fmt.Fprintf(stderr, "codexa-scanner import subdomains: %v\n", err)
		return 2
	}
	if jsonPath != "" {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "codexa-scanner import subdomains: encoding JSON: %v\n", err)
			return 2
		}
		if jsonPath == "-" {
			fmt.Fprintln(stdout, string(data))
		} else {
			if err := os.WriteFile(jsonPath, data, 0600); err != nil {
				fmt.Fprintf(stderr, "codexa-scanner import subdomains: writing JSON: %v\n", err)
				return 2
			}
			fmt.Fprintf(stdout, "Import result written to %s\n", jsonPath)
		}
	} else {
		fmt.Fprintf(stdout, "Subdomains loaded: %d\n", result.SubdomainsLoaded)
		fmt.Fprintf(stdout, "Duplicates removed: %d\n", result.DuplicatesRemoved)
		fmt.Fprintf(stdout, "Invalid entries: %d\n", result.InvalidEntries)
		if len(result.Errors) > 0 {
			fmt.Fprintln(stdout, "Errors:")
			for _, e := range result.Errors {
				fmt.Fprintf(stdout, "  %s\n", e)
			}
		}
	}
	return 0
}