# ⚡ scanhunt

**Fingerprint, dedupe, and diff security-scan findings — one static Go binary.**

Built for the retest workflow: run a scan today, run it next month, and get a precise answer to *"what changed?"* — new findings, fixed ones, and severity shifts, with no noisy duplicates.

```bash
scanhunt diff baseline.json current.json --format text
scanhunt dedupe big-scan.json -o deduped.json
```

## Why

Security scanners are chatty. The same SQLi shows up in ten scans with ten different payloads, and after remediation you want proof it's gone — not a wall of re-numbers. scanhunt gives every finding a stable fingerprint (SHA-256 over type + normalized URL + parameter + root-cause hint) and turns two scan files into a classified delta.

## Features

- **Diff** — classify findings as `new` / `fixed` / `unchanged` / `severity-changed` (severity change is detected separately, so a medium→critical bump doesn't masquerade as new+fixed)
- **Dedupe** — collapse duplicates by fingerprint, keep the highest severity
- **URL normalization** — lowercase scheme/host, trailing-slash trim, sorted query params, so `?b=2&a=1` and `?a=1&b=2` are the same finding
- **Formats** — human text, JSON, CSV
- **Fast** — ~1.7s to diff two 200k-finding files; no dependencies, static binary

## Install

```bash
go install github.com/nabilahazalia/scanhunt@latest
# or from source:
git clone https://github.com/nabilahazalia/scanhunt && cd scanhunt && go build
```

## Input format

Any scan JSON with a `vulnerabilities` array:

```json
{
  "vulnerabilities": [
    {"type": "SQL Injection", "severity": "high", "url": "https://t.com/x?id=1",
     "parameter": "id", "payload": "' OR 1=1", "evidence": "error in response"}
  ]
}
```

Works out of the box with deep-eye scan output; trivially adaptable from nuclei/httpx JSON.

## Usage

```
scanhunt diff BASELINE CURRENT [--format text|json|csv] [-o FILE]
scanhunt dedupe SCAN [-o OUT.json]
```

Flags can appear anywhere: `scanhunt diff a.json b.json --format csv`.

## Example output

```
Summary: 2 new, 2 fixed, 1 unchanged, 1 severity-changed (net +0)

== NEW (2) ==
  [HIGH] SSRF — https://lab.example.com/fetch?url= (param: url)
  [LOW] Open Redirect — https://lab.example.com/redirect?to= (param: to)

== FIXED (2) ==
  [CRITICAL] SQL Injection — https://lab.example.com/item?id=1 (param: id)
  ...

  [high -> critical] SQL Injection — https://lab.example.com/item?id=1
```

## Status

Production-tested on 200k-finding synthetic and real scan sets, fingerprint-parity-verified against the reference Python implementation. MIT licensed. Contributions welcome — especially exporters for other scanner formats!

## License

MIT
