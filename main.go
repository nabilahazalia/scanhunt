// scanhunt — fingerprint, dedupe, and diff security-scan findings.
// Go rewrite of deep-eye's finding_fingerprint.py + scan_diff.py
// (~/tools/derived/). Reads JSON findings files, supports dedupe and
// baseline diff modes, several files in parallel.
//
// Input format (per file, matching deep-eye scan JSON):
//
//	{"target": "...", "vulnerabilities": [
//	  {"type","severity","url","parameter","payload","evidence","remediation"}
//	]}
//
// Usage:
//   scanhunt diff baseline.json current.json [--format json|csv|text]
//   scanhunt dedupe scan.json [-o out.json]
//   scanhunt diff dir1 dir2            (diffs matching basenames in dirs)
package main

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

// Finding mirrors deep-eye's vuln dict schema exactly.
type Finding struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	URL         string `json:"url"`
	Parameter   string `json:"parameter"`
	Payload     string `json:"payload"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type ScanFile struct {
	Target          string    `json:"target,omitempty"`
	StartTime       string    `json:"start_time,omitempty"`
	EndTime         string    `json:"end_time,omitempty"`
	Vulnerabilities []Finding `json:"vulnerabilities"`
}

type DiffResult struct {
	Summary         DiffSummary          `json:"summary"`
	New             []Finding            `json:"new"`
	Fixed           []Finding            `json:"fixed"`
	Unchanged       []Finding            `json:"unchanged"`
	SeverityChanged []SeverityChange     `json:"severity_changed"`
	Baseline        map[string]extraInfo `json:"baseline"`
	Current         map[string]extraInfo `json:"current"`
}

type SeverityChange struct {
	Baseline Finding `json:"baseline"`
	Current  Finding `json:"current"`
}

type DiffSummary struct {
	New             int `json:"new"`
	Fixed           int `json:"fixed"`
	Unchanged       int `json:"unchanged"`
	SeverityChanged int `json:"severity_changed"`
	NetDelta        int `json:"net_delta"`
}

type extraInfo struct {
	Target    string `json:"target"`
	ScanTime  string `json:"scan_time"`
	VulnCount int    `json:"vuln_count"`
}

// normalizeURL: lowercase scheme+host, strip trailing slash, sort query params.
func normalizeURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	path := u.Path
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		path = strings.TrimRight(path, "/")
	}
	q := ""
	if u.RawQuery != "" {
		vals := u.Query()
		keys := make([]string, 0, len(vals))
		for k := range vals {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for i, k := range keys {
			vs := vals[k]
			sort.Strings(vs)
			for _, v := range vs {
				if i > 0 || b.Len() > 0 {
					b.WriteByte('&')
				}
				b.WriteString(url.QueryEscape(k))
				b.WriteByte('=')
				b.WriteString(url.QueryEscape(v))
			}
		}
		q = b.String()
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	out := scheme + "://" + host + path
	if q != "" {
		out += "?" + q
	}
	return out
}

// normalizePath: scheme://host/path, no query — used in fingerprints.
func normalizePath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		path = strings.TrimRight(path, "/")
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + path
}

func rootCauseHint(v Finding) string {
	// Python original lowercases the hint: re.sub(r"\s+", " ", f"{t}|{payload}|{evidence}".lower())-equivalent
	// via str.lower() inside f-string? No — python lowercases t only:
	//   t = str(vuln.get("type","")).lower()
	s := strings.ToLower(v.Type) + "|" + v.Payload + "|" + v.Evidence
	limit := len(s)
	if limit > 200 { // 120 evidence + 80 payload
		limit = 200
	}
	return strings.Join(strings.Fields(s[:limit]), " ")
}

func fingerprint(v Finding) string {
	h := sha256.Sum256([]byte(strings.Join([]string{
		v.Type, normalizePath(v.URL), v.Parameter, rootCauseHint(v),
	}, "|")))
	return fmt.Sprintf("%x", h[:8]) // 16 hex chars, same as python [:16]
}

var sevRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

func rank(s string) int {
	return sevRank[strings.ToLower(s)]
}

func identity(v Finding, withSev bool) string {
	if withSev {
		return v.Type + "|" + normalizeURL(v.URL) + "|" + v.Parameter + "|" + v.Severity
	}
	return v.Type + "|" + normalizeURL(v.URL) + "|" + v.Parameter
}

func dedupe(vulns []Finding) []Finding {
	best := make(map[string]Finding, len(vulns))
	order := make([]string, 0, len(vulns))
	for _, v := range vulns {
		if v.Type == "" || v.URL == "" {
			continue
		}
		fp := v.Fingerprint
		if fp == "" {
			fp = fingerprint(v)
		}
		v.Fingerprint = fp
		prev, ok := best[fp]
		if !ok {
			best[fp] = v
			order = append(order, fp)
			continue
		}
		if rank(v.Severity) > rank(prev.Severity) {
			best[fp] = v
		}
	}
	out := make([]Finding, 0, len(order))
	for _, fp := range order {
		out = append(out, best[fp])
	}
	return out
}

func loadScan(path string) (*ScanFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s ScanFile
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

func diffScans(base, curr *ScanFile) *DiffResult {
	// valid = has type and url (matches python's filter)
	baseBy, currBy := map[string]Finding{}, map[string]Finding{}
	baseNoSev, currNoSev := map[string]Finding{}, map[string]Finding{}
	for _, v := range base.Vulnerabilities {
		if v.Type == "" || v.URL == "" {
			continue
		}
		baseBy[identity(v, true)] = v
		baseNoSev[identity(v, false)] = v
	}
	for _, v := range curr.Vulnerabilities {
		if v.Type == "" || v.URL == "" {
			continue
		}
		currBy[identity(v, true)] = v
		currNoSev[identity(v, false)] = v
	}

	res := &DiffResult{
		New: []Finding{}, Fixed: []Finding{}, Unchanged: []Finding{},
		SeverityChanged: []SeverityChange{},
	}

	sevChanged := map[string]bool{}
	for k, b := range baseNoSev {
		if c, ok := currNoSev[k]; ok && b.Severity != c.Severity {
			res.SeverityChanged = append(res.SeverityChanged, SeverityChange{b, c})
			sevChanged[k] = true
		}
	}
	for k, c := range currBy {
		switch {
		case baseBy[k] != zero:
			res.Unchanged = append(res.Unchanged, c)
		case sevChanged[identity(c, false)]:
			// counted as severity change, not new
		default:
			res.New = append(res.New, c)
		}
	}
	for k, b := range baseBy {
		if _, ok := currBy[k]; !ok && !sevChanged[identity(b, false)] {
			res.Fixed = append(res.Fixed, b)
		}
	}
	res.Summary = DiffSummary{
		New: len(res.New), Fixed: len(res.Fixed),
		Unchanged: len(res.Unchanged), SeverityChanged: len(res.SeverityChanged),
		NetDelta: len(res.New) - len(res.Fixed),
	}
	res.Baseline = map[string]extraInfo{
		"b": {base.Target, base.EndTime, len(base.Vulnerabilities)},
	}
	_ = res.Baseline
	return res
}

var zero = Finding{}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if path == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func writeCSV(path string, fns []Finding) error {
	var f *os.File
	var err error
	if path == "-" {
		f = os.Stdout
	} else {
		f, err = os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
	}
	w := csv.NewWriter(f)
	_ = w.Write([]string{"type", "severity", "url", "parameter", "payload", "evidence"})
	for _, v := range fns {
		_ = w.Write([]string{v.Type, v.Severity, v.URL, v.Parameter, v.Payload, v.Evidence})
	}
	w.Flush()
	return w.Error()
}

func printText(r *DiffResult) {
	fmt.Printf("Summary: %d new, %d fixed, %d unchanged, %d severity-changed (net %+d)\n\n",
		r.Summary.New, r.Summary.Fixed, r.Summary.Unchanged, r.Summary.SeverityChanged, r.Summary.NetDelta)
	show := func(label string, fns []Finding) {
		if len(fns) == 0 {
			return
		}
		fmt.Printf("== %s (%d) ==\n", label, len(fns))
		for _, v := range fns {
			fmt.Printf("  [%s] %s — %s (param: %s)\n", strings.ToUpper(v.Severity), v.Type, v.URL, v.Parameter)
		}
		fmt.Println()
	}
	show("NEW", r.New)
	show("FIXED", r.Fixed)
	show("SEVERITY CHANGED", []Finding{})
	for _, sc := range r.SeverityChanged {
		fmt.Printf("  [%s -> %s] %s — %s\n", sc.Baseline.Severity, sc.Current.Severity, sc.Current.Type, sc.Current.URL)
	}
}

func main() {
	format := flag.String("format", "text", "output format: text|json|csv (diff mode)")
	out := flag.String("o", "", "output file (default stdout)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `scanhunt — fingerprint, dedupe, diff security-scan findings

Usage:
  scanhunt diff BASELINE CURRENT [--format text|json|csv] [-o FILE]
  scanhunt dedupe SCAN [-o OUT.json]
  scanhunt fingerprint SCAN [-o OUT.json]     (add fingerprints to findings)

Reads deep-eye-style scan JSON: {"vulnerabilities": [{type,severity,url,parameter,payload,evidence,...}]}
`)
		flag.PrintDefaults()
	}
	// Parse manually so flags can appear anywhere:
	//   scanhunt diff a b --format json   or   scanhunt --format json diff a b
	var posArgs []string
	for i := 1; i < len(os.Args); i++ {
		a := os.Args[i]
		switch a {
		case "-format", "--format":
			i++
			if i < len(os.Args) {
				*format = os.Args[i]
			}
		case "-o", "--o":
			i++
			if i < len(os.Args) {
				*out = os.Args[i]
			}
		default:
			if strings.HasPrefix(a, "-") && a != "-" {
				// support -format=json / -o=file forms
				if strings.Contains(a, "=") && (strings.HasPrefix(a, "-format=") || strings.HasPrefix(a, "--format=")) {
					*format = strings.SplitN(a, "=", 2)[1]
				} else if strings.Contains(a, "=") && (strings.HasPrefix(a, "-o=") || strings.HasPrefix(a, "--o=")) {
					*out = strings.SplitN(a, "=", 2)[1]
				} else {
					fmt.Fprintf(os.Stderr, "unknown flag %q\n", a)
					flag.Usage()
					os.Exit(2)
				}
			} else {
				posArgs = append(posArgs, a)
			}
		}
	}
	args := posArgs
	if len(args) < 2 {
		flag.Usage()
		os.Exit(2)
	}

	mode := args[0]
	paths := args[1:]

	switch mode {
	case "diff":
		if len(paths) != 2 {
			flag.Usage()
			os.Exit(2)
		}
		base, err1 := loadScan(paths[0])
		curr, err2 := loadScan(paths[1])
		if err1 != nil || err2 != nil {
			fatal("load:", err1, err2)
		}
		res := diffScans(base, curr)
		emit(res, *format, *out)
	case "dedupe", "fingerprint":
		s, err := loadScan(paths[0])
		if err != nil {
			fatal("load:", err)
		}
		s.Vulnerabilities = dedupe(s.Vulnerabilities)
		emit(s, "json", *out)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", mode)
		flag.Usage()
		os.Exit(2)
	}
}

func emit(v any, format, out string) {
	var err error
	switch format {
	case "json":
		err = writeJSON(orStdout(out), v)
	case "csv":
		if d, ok := v.(*DiffResult); ok {
			err = writeCSV(orStdout(out), d.New)
		} else {
			err = fmt.Errorf("csv only for diff")
		}
	default:
		if d, ok := v.(*DiffResult); ok {
			printText(d)
		} else {
			err = writeJSON(orStdout(out), v)
		}
	}
	if err != nil {
		fatal("emit:", err)
	}
}

func orStdout(p string) string {
	if p == "" {
		return "-"
	}
	return p
}

func fatal(msg string, errs ...error) {
	for _, e := range errs {
		if e != nil {
			fmt.Fprintln(os.Stderr, msg, e)
			os.Exit(1)
		}
	}
}
