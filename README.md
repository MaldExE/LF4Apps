# LF4Apps

# LF4apps 🔍

> **Active Directory DNS → Web Attack Surface Mapper**  
> Enumerate all exposed web applications from an AD domain in one command.

LF4apps automates the full pipeline from AD DNS enumeration to web application discovery and screenshotting — designed to run inside [Exegol](https://github.com/ThePorgs/Exegol) or any pentest environment with the required tools installed.

---

## Pipeline

```
adidnsdump          Extract A / AAAA / CNAME records from AD DNS
    │
    ▼
Dangling DNS check  Detect potential subdomain takeovers (28 cloud patterns)
    │
    ▼
URL generation      Build http/https + extra ports for every live host
    │
    ▼
httpx               Probe all URLs, detect status codes & technologies
    │
    ▼
gowitness           Screenshot every responding application
    │
    ▼
HTML report         Consolidated report with DNS table, dangling findings & app list
```

---

## Features

- **Full AD DNS coverage** — extracts A, AAAA and CNAME records (configurable)
- **Smart noise filtering** — automatically discards AD technical records (`@`, `ForestDnsZones`, `DomainDnsZones`, `_msdcs`, etc.)
- **Dangling DNS detection** — checks 28 cloud/SaaS patterns (AWS, Azure, GitHub Pages, Heroku, Netlify, Vercel, Shopify…) for subdomain takeover risk
- **Multi-port scanning** — tests `80`, `443`, `8080`, `8443`, `8888`, `8000`, `9443` automatically
- **Dual scheme** — generates both `http://` and `https://` for every host
- **Clean httpx output** — uses `-o` flag to capture only real HTTP responses, no `[FAILED]` noise
- **gowitness screenshots** — skipped automatically if no live targets found
- **HTML report** — dark-themed, self-contained report with stats dashboard, DNS table, dangling alerts and app inventory
- **Resume mode** — skip adidnsdump and reuse an existing CSV (`--resume`)
- **Graceful Ctrl+C** — partial results saved to `recon-partial.json` on interruption
- **Colorized output** — green (2xx), cyan (3xx), yellow (401/403), red (errors)
- **Password prompt** — password never required in CLI arguments (interactive prompt available)

---

## Requirements

### Tools (must be in `$PATH`)

| Tool | Install |
|------|---------|
| [adidnsdump](https://github.com/dirkjanm/adidnsdump) | `pip install adidnsdump` |
| [httpx](https://github.com/projectdiscovery/httpx) | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| [gowitness](https://github.com/sensepost/gowitness) | `go install github.com/sensepost/gowitness@latest` |

### Python dependencies

```bash
pip install dnspython
```

> `dnspython` is optional — if missing, the dangling DNS check is silently skipped.

---

## Installation

```bash
git clone https://github.com/youruser/LF4apps
cd LF4apps
pip install dnspython
```

---

## Usage

```bash
python3 LF4apps.py -d <DOMAIN> -u <USER> --dc <DC_IP>
```

Password is prompted interactively if `-p` is omitted (recommended to avoid shell history exposure).

### Basic examples

```bash
# Minimal — password prompted
python3 LF4apps.py -d corp.local -u jdoe --dc 10.0.0.1

# With password inline
python3 LF4apps.py -d corp.local -u jdoe -p 'S3cr3t!' --dc 10.0.0.1

# Enumerate zones first (adidnsdump --print-zones)
python3 LF4apps.py -d corp.local -u jdoe --dc 10.0.0.1 --print-zones

# Resume from existing CSV (skip adidnsdump re-run)
python3 LF4apps.py -d corp.local -u jdoe --dc 10.0.0.1 --resume

# Skip extra ports (only 80/443)
python3 LF4apps.py -d corp.local -u jdoe --dc 10.0.0.1 --skip-extra-ports

# Skip dangling check, httpx and gowitness (DNS only)
python3 LF4apps.py -d corp.local -u jdoe --dc 10.0.0.1 --skip-dangling --skip-httpx --skip-gowitness
```

---

## Options

### Authentication
| Flag | Required | Description |
|------|----------|-------------|
| `-d`, `--domain` | ✅ | AD domain (e.g. `corp.local`) |
| `-u`, `--username` | ✅ | Username without domain |
| `-p`, `--password` | ❌ | Password (prompted if omitted) |
| `--dc` | ✅ | Domain Controller IP or hostname |

### adidnsdump / DNS
| Flag | Default | Description |
|------|---------|-------------|
| `--print-zones` | off | Pass `--print-zones` to adidnsdump |
| `--csv` | `out-LF4apps/records.csv` | Path to adidnsdump CSV output |
| `--record-types` | `A,AAAA,CNAME` | DNS record types to include |
| `--skip-dangling` | off | Skip dangling DNS check |
| `--resume` | off | Reuse existing CSV, skip adidnsdump |

### httpx
| Flag | Default | Description |
|------|---------|-------------|
| `--url-file` | `out-LF4apps/urls-all.txt` | Generated URL list |
| `--httpx-out` | `out-LF4apps/httpx-output.txt` | httpx raw output |
| `--httpx-ok` | `out-LF4apps/httpx-urls-ok.txt` | Live URLs for gowitness |
| `--skip-extra-ports` | off | Only scan ports 80 and 443 |
| `--skip-httpx` | off | Skip httpx entirely |

### gowitness
| Flag | Default | Description |
|------|---------|-------------|
| `--gowitness-out` | `out-LF4apps/gowitness-output.txt` | gowitness log |
| `--threads` | `20` | Concurrent screenshot threads |
| `--timeout` | `5` | Per-target timeout (seconds) |
| `--skip-gowitness` | off | Skip gowitness entirely |

### Output
| Flag | Default | Description |
|------|---------|-------------|
| `--report` | `out-LF4apps/recon-report.html` | HTML report path |
| `--no-report` | off | Disable HTML report generation |

---

## Output files

All files are written to `out-LF4apps/` automatically (created if missing).

```
out-LF4apps/
├── records.csv              # Raw adidnsdump output
├── urls-all.txt             # All generated URLs (pre-httpx)
├── httpx-output.txt         # httpx results (live hosts only)
├── httpx-urls-ok.txt        # Clean URL list for gowitness
├── gowitness-output.txt     # gowitness scan log
├── recon-report.html        # Consolidated HTML report
└── recon-partial.json       # Saved on Ctrl+C interruption
```

---

## HTML Report

The self-contained dark-themed report includes:

- **Stats dashboard** — total hosts, record breakdown, dangling count, live app count
- **DNS table** — all A / AAAA / CNAME records with color-coded type badges
- **Dangling DNS table** — FQDN, CNAME target, affected service, with red alert banner
- **Applications table** — URL (clickable), HTTP status, page title, server header, detected technologies

---

## Dangling DNS patterns

LF4apps checks CNAMEs against 28 known cloud/SaaS providers:

`AWS` · `Azure` (Web Apps, Blob, Traffic Manager, HDInsight) · `GitHub Pages` · `Heroku` · `Fastly` · `Netlify` · `Vercel` · `Webflow` · `Shopify` · `Zendesk` · `Freshdesk` · `Ghost` · `WordPress.com` · `WPEngine` · `Squarespace` · `Strikingly` · `Pantheon` · `Bitbucket Pages` · `SmugMug` · `HelpScout` · `Readme.io` · `Surge.sh`

---

## Disclaimer

> This tool is intended for **authorized penetration testing and red team assessments only**.  
> Use against systems you do not own or have explicit written permission to test is illegal.  
> The authors assume no liability for misuse.

---

## Credits

Built on top of:
- [adidnsdump](https://github.com/dirkjanm/adidnsdump) by [@dirkjanm](https://github.com/dirkjanm)
- [httpx](https://github.com/projectdiscovery/httpx) by [ProjectDiscovery](https://github.com/projectdiscovery)
- [gowitness](https://github.com/sensepost/gowitness) by [SensePost](https://github.com/sensepost)
