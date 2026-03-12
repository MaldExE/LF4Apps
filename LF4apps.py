#!/usr/bin/env python3
"""
ADIDNSdump + A/AAAA/CNAME + Dangling DNS + HTTPX (multi-port) + gowitness
Usage : python3 LF4apps.py -d corp.local -u jdoe --dc 10.0.0.1
"""

import argparse
import csv
import datetime
import getpass
import json
import shlex
import signal
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Patterns de dangling DNS (services cloud/SaaS connus)
# ---------------------------------------------------------------------------

DANGLING_PATTERNS = {
    "amazonaws.com":         "AWS S3 / Elastic Beanstalk",
    "azurewebsites.net":     "Azure Web Apps",
    "cloudapp.azure.com":    "Azure Cloud App",
    "azurehdinsight.net":    "Azure HDInsight",
    "trafficmanager.net":    "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Blob Storage",
    "github.io":             "GitHub Pages",
    "herokuapp.com":         "Heroku",
    "fastly.net":            "Fastly CDN",
    "pantheonsite.io":       "Pantheon",
    "ghost.io":              "Ghost CMS",
    "myshopify.com":         "Shopify",
    "zendesk.com":           "Zendesk",
    "freshdesk.com":         "Freshdesk",
    "helpscoutdocs.com":     "HelpScout",
    "readme.io":             "Readme.io",
    "surge.sh":              "Surge.sh",
    "netlify.app":           "Netlify",
    "netlify.com":           "Netlify",
    "vercel.app":            "Vercel",
    "now.sh":                "Vercel (legacy)",
    "webflow.io":            "Webflow",
    "bitbucket.io":          "Bitbucket Pages",
    "smugmug.com":           "SmugMug",
    "wordpress.com":         "WordPress.com",
    "wpengine.com":          "WPEngine",
    "strikingly.com":        "Strikingly",
    "squarespace.com":       "Squarespace",
}

# Ports additionnels à tester en plus de 80/443
EXTRA_PORTS = [8080, 8443, 8888, 9443, 8000]

# ---------------------------------------------------------------------------
# Couleurs terminal
# ---------------------------------------------------------------------------

C = {
    "ok":    "\033[92m",
    "warn":  "\033[93m",
    "err":   "\033[91m",
    "info":  "\033[96m",
    "bold":  "\033[1m",
    "reset": "\033[0m",
}

def cprint(level, msg):
    icons = {"ok": "[+]", "warn": "[~]", "err": "[!]", "info": "[*]"}
    print(f"{C.get(level,'')}{icons.get(level,'[?]')} {msg}{C['reset']}")

def banner(title):
    print(f"\n{C['bold']}{'═'*60}\n  {title}\n{'═'*60}{C['reset']}\n")

# ---------------------------------------------------------------------------
# Gestion SIGINT — sauvegarde résultats partiels
# ---------------------------------------------------------------------------

_partial_results = {}

def _sigint_handler(sig, frame):
    cprint("warn", "Interruption — sauvegarde des résultats partiels…")
    if _partial_results:
        out = Path("recon-partial.json")
        out.write_text(json.dumps(_partial_results, indent=2, ensure_ascii=False))
        cprint("warn", f"Résultats partiels → {out.resolve()}")
    sys.exit(130)

signal.signal(signal.SIGINT, _sigint_handler)

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        prog="LF4apps.py",
        description="ADIDNSdump → A/AAAA/CNAME → Dangling → HTTPX (multi-port) → gowitness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  %(prog)s -d corp.local -u jdoe --dc 10.0.0.1
  %(prog)s -d corp.local -u jdoe -p 'S3cr3t' --dc 10.0.0.1
  %(prog)s -d corp.local -u jdoe --dc 10.0.0.1 --print-zones
  %(prog)s -d corp.local -u jdoe --dc 10.0.0.1 --skip-dangling --skip-extra-ports
  %(prog)s -d corp.local -u jdoe --dc 10.0.0.1 --resume
  %(prog)s -d corp.local -u jdoe --dc 10.0.0.1 --skip-httpx --skip-gowitness
        """,
    )

    auth = parser.add_argument_group("Authentification")
    auth.add_argument("-d", "--domain",   required=True, metavar="DOMAIN")
    auth.add_argument("-u", "--username", required=True, metavar="USER")
    auth.add_argument("-p", "--password", default=None,  metavar="PASS",
                      help="Si omis, demandé interactivement")
    auth.add_argument("--dc", required=True, metavar="DC",
                      help="IP ou hostname du DC / DNS")

    dns_grp = parser.add_argument_group("adidnsdump / DNS")
    dns_grp.add_argument("--print-zones", action="store_true")
    dns_grp.add_argument("--csv", default=None, metavar="FILE",
                         help="CSV généré par adidnsdump (défaut: out-LF4apps/records.csv)")
    dns_grp.add_argument("--record-types", default="A,AAAA,CNAME", metavar="TYPES",
                         help="Types DNS à inclure (défaut: A,AAAA,CNAME)")
    dns_grp.add_argument("--skip-dangling", action="store_true",
                         help="Ne pas effectuer le check dangling DNS")
    dns_grp.add_argument("--resume", action="store_true",
                         help="Reprendre depuis le CSV existant sans relancer adidnsdump")

    http_grp = parser.add_argument_group("httpx")
    http_grp.add_argument("--url-file",  default=None, metavar="FILE",
                          help="defaut: out-LF4apps/urls-all.txt")
    http_grp.add_argument("--httpx-out", default=None, metavar="FILE",
                          help="defaut: out-LF4apps/httpx-output.txt")
    http_grp.add_argument("--httpx-ok",  default=None, metavar="FILE",
                          help="defaut: out-LF4apps/httpx-urls-ok.txt")
    http_grp.add_argument("--skip-extra-ports", action="store_true",
                          help=f"Ne pas tester les ports {','.join(map(str,EXTRA_PORTS))}")
    http_grp.add_argument("--skip-httpx", action="store_true")

    gw_grp = parser.add_argument_group("gowitness")
    gw_grp.add_argument("--gowitness-out", default=None, metavar="FILE",
                        help="defaut: out-LF4apps/gowitness-output.txt")
    gw_grp.add_argument("--threads", type=int, default=20)
    gw_grp.add_argument("--timeout", type=int, default=5)
    gw_grp.add_argument("--skip-gowitness", action="store_true")

    out_grp = parser.add_argument_group("Output")
    out_grp.add_argument("--report", default=None, metavar="FILE",
                         help="Rapport HTML consolidé (defaut: out-LF4apps/recon-report.html)")
    out_grp.add_argument("--no-report", action="store_true")

    return parser.parse_args()

# ---------------------------------------------------------------------------
# adidnsdump
# ---------------------------------------------------------------------------

def run_adidnsdump(domain, username, password, dc, out_csv: Path, print_zones=False):
    """
    Lance adidnsdump. L'outil écrit toujours records.csv dans le CWD ;
    on le déplace ensuite vers out_csv si nécessaire.
    """
    cmd = ["adidnsdump", "-u", f"{domain}\\{username}", "-p", password, dc]
    if print_zones:
        cmd.append("--print-zones")

    safe = cmd.copy()
    safe[cmd.index(password)] = "***"
    cprint("info", f"Exécution : {' '.join(shlex.quote(c) for c in safe)}")

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout: cprint("ok",   result.stdout.strip())
    if result.stderr: cprint("warn", result.stderr.strip())
    cprint("info", f"Code retour : {result.returncode}")

    # adidnsdump génère toujours ./records.csv — on le déplace dans OUT_DIR
    default_csv = Path("records.csv")
    if result.returncode == 0 and default_csv.exists() and default_csv.resolve() != out_csv.resolve():
        import shutil
        shutil.move(str(default_csv), str(out_csv))
        cprint("ok", f"records.csv déplacé → {out_csv.resolve()}")

    return result.returncode

# ---------------------------------------------------------------------------
# Extraction DNS records (A, AAAA, CNAME)
# ---------------------------------------------------------------------------

def extract_dns_records(csv_path: str, wanted_types: list) -> dict:
    csv_file = Path(csv_path)
    if not csv_file.exists():
        cprint("err", f"Fichier introuvable : {csv_file}")
        return {}

    records = defaultdict(list)
    wanted_upper = [t.upper() for t in wanted_types]

    with csv_file.open("r", newline="", encoding="utf-8") as f:
        for row in csv.reader(f):
            if not row or len(row) < 3:
                continue
            rtype = row[0].strip().upper()
            if rtype in wanted_upper:
                records[rtype].append((rtype, row[1].strip(), row[2].strip()))

    for rtype, rows in records.items():
        cprint("ok", f"{len(rows):>4} enregistrements {rtype}")

    return dict(records)

# ---------------------------------------------------------------------------
# Dangling DNS check
# ---------------------------------------------------------------------------

def check_dangling(records: dict, domain: str) -> list:
    if not DNS_AVAILABLE:
        cprint("warn", "dnspython non installé — dangling check ignoré (pip install dnspython)")
        return []

    cnames = records.get("CNAME", [])
    if not cnames:
        cprint("warn", "Aucun CNAME à vérifier")
        return []

    cprint("info", f"Vérification de {len(cnames)} CNAMEs…")
    findings = []

    import dns.resolver, dns.exception
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0

    for _, name, target in cnames:
        matched_service = next(
            (svc for pat, svc in DANGLING_PATTERNS.items() if target.lower().endswith(pat)),
            None
        )
        if not matched_service:
            continue

        try:
            resolver.resolve(target, "A")
            resolves = True
        except Exception:
            resolves = False

        if not resolves:
            fqdn = f"{name}.{domain}" if not name.endswith(domain) else name
            findings.append({"fqdn": fqdn, "cname": target, "service": matched_service})
            cprint("err", f"DANGLING ⚠  {fqdn} → {target} ({matched_service})")

    if not findings:
        cprint("ok", "Aucun dangling DNS détecté")

    return findings

# Noms DNS techniques AD à exclure du scan (faux positifs garantis)
AD_NOISE = {
    "@",
    "forestdnszones",
    "domaindnszones",
    "_msdcs",
    "_sites",
    "_tcp",
    "_udp",
    "gc._msdcs",
}

def _is_noise(name: str, domain: str) -> bool:
    """Retourne True si le nom DNS est un enregistrement technique AD sans intérêt."""
    # Retire le suffixe domaine pour travailler sur le label court
    label = name.lower()
    if label.endswith(f".{domain.lower()}"):
        label = label[: -(len(domain) + 1)]
    # Nom vide ou @ (apex de zone)
    if not label or label == "@":
        return True
    # Comparaison exacte contre la liste de bruit
    if label in AD_NOISE:
        return True
    # Préfixes courants d'enregistrements de service
    if label.startswith("_"):
        return True
    return False

# ---------------------------------------------------------------------------
# Construction fichier URLs (http + https + ports extra)
# ---------------------------------------------------------------------------

def build_url_file(records: dict, domain: str, url_file: str,
                   skip_extra_ports: bool = False) -> int:
    hosts = set()
    skipped = []
    for rtype in ("A", "AAAA", "CNAME"):
        for _, name, _ in records.get(rtype, []):
            if _is_noise(name, domain):
                skipped.append(name)
                continue
            fqdn = name if (name.endswith(f".{domain}") or name == domain) else f"{name}.{domain}"
            hosts.add(fqdn)

    if skipped:
        cprint("warn", f"{len(skipped)} entrées AD exclues (bruit) : {', '.join(skipped)}")

    urls = []
    for host in sorted(hosts):
        for scheme in ("http", "https"):
            urls.append(f"{scheme}://{host}/")
        if not skip_extra_ports:
            for port in EXTRA_PORTS:
                scheme = "https" if port in (8443, 9443) else "http"
                urls.append(f"{scheme}://{host}:{port}/")

    Path(url_file).write_text("\n".join(urls) + "\n", encoding="utf-8")
    cprint("ok", f"{len(urls)} URLs générées ({len(hosts)} hosts uniques) → {Path(url_file).resolve()}")
    return len(urls)

# ---------------------------------------------------------------------------
# httpx
# ---------------------------------------------------------------------------

def run_httpx(url_list_file: str, httpx_out: str):
    cmd = [
        "httpx", "-probe",
        "-l", url_list_file,
        "-tech-detect",
        "-status-code",
        "-title",
        "-server",
        "-fr",
        "-include-response-header", "Content-Security-Policy",
        "-include-response-header", "Strict-Transport-Security",
        "-include-response-header", "X-Frame-Options",
        "-mc", "200,301,302,401,403",
        "-nc",          # no color — sortie fichier propre, sans escape ANSI
        "-o", httpx_out,  # httpx écrit lui-même le fichier, sans [FAILED]
    ]
    cprint("info", f"Exécution httpx : {' '.join(shlex.quote(c) for c in cmd)}")

    # Capture stdout ligne par ligne (affichage temps réel) pour pallier le bug
    # httpx v1.7.x avec -probe + -mc qui n'écrit pas toujours le fichier -o
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None, text=True, bufsize=1)
    captured = []
    try:
        for line in proc.stdout:
            line = line.rstrip("\n")
            print(line)
            captured.append(line)
        proc.stdout.close()
    except KeyboardInterrupt:
        proc.terminate()
        raise
    rc = proc.wait()

    # Fallback : si httpx n'a pas créé le fichier -o, on écrit le stdout capturé
    # (extract_httpx_urls_ok filtre déjà les lignes [FAILED])
    out_path = Path(httpx_out)
    if not out_path.exists() and captured:
        out_path.write_text("\n".join(captured) + "\n", encoding="utf-8")

    cprint("info", f"Code retour httpx : {rc}")
    cprint("ok",   f"Sortie httpx → {out_path.resolve()}")
    return rc


def _print_httpx_colored(line: str):
    code = next((t[1:-1] for t in line.split() if t.startswith("[") and t.endswith("]") and t[1:-1].isdigit()), "")
    if   code.startswith("2"): print(f"{C['ok']}{line}{C['reset']}")
    elif code.startswith("3"): print(f"{C['info']}{line}{C['reset']}")
    elif code in ("401","403"): print(f"{C['warn']}{line}{C['reset']}")
    else: print(line)

# ---------------------------------------------------------------------------
# Extraction URLs valides
# ---------------------------------------------------------------------------

def extract_httpx_urls_ok(httpx_out: str, ok_file: str) -> list:
    src = Path(httpx_out)
    if not src.exists():
        cprint("err", f"Introuvable : {src}")
        return []

    entries, urls_only = [], []
    with src.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Garder uniquement les lignes de résultat httpx :
            # - commencent par http:// ou https://
            # - ne sont pas [FAILED]
            if not (line.startswith("http://") or line.startswith("https://")):
                continue
            if "[FAILED]" in line:
                continue
            parts = line.split()
            if not parts:
                continue
            entry = {"url": parts[0], "status": "", "title": "", "server": "", "techs": []}
            for tok in parts[1:]:
                if tok.startswith("[") and tok.endswith("]"):
                    inner = tok[1:-1]
                    if inner.isdigit():
                        entry["status"] = inner
                    else:
                        entry["techs"].append(inner)
            entries.append(entry)
            urls_only.append(entry["url"])

    # Écrit le fichier même s'il est vide (gowitness le lira)
    Path(ok_file).write_text("\n".join(urls_only) + "\n" if urls_only else "", encoding="utf-8")

    if entries:
        cprint("ok", f"{len(entries)} URLs actives (hors FAILED) → {Path(ok_file).resolve()}")
    else:
        cprint("warn", "Aucune URL active trouvée — toutes les cibles sont injoignables")

    return entries

# ---------------------------------------------------------------------------
# gowitness
# ---------------------------------------------------------------------------

def run_gowitness(url_list_file: str, gowitness_out: str, threads: int, timeout: int):
    cmd = [
        "gowitness", "scan", "file",
        "-f", url_list_file,
        "--threads", str(threads),
        "--timeout", str(timeout),
        "--write-db",
    ]
    cprint("info", f"Exécution gowitness : {' '.join(shlex.quote(c) for c in cmd)}")

    out = Path(gowitness_out)
    with out.open("w", encoding="utf-8") as f:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, bufsize=1)
        try:
            for line in proc.stdout:
                line = line.rstrip("\n")
                print(line)
                f.write(line + "\n")
            proc.stdout.close()
        except KeyboardInterrupt:
            proc.terminate()
            raise
        proc.wait()

    cprint("ok", f"Log gowitness → {out.resolve()}")

# ---------------------------------------------------------------------------
# Rapport HTML
# ---------------------------------------------------------------------------

def generate_html_report(domain, records, dangling, httpx_entries, report_path):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_hosts = sum(len(v) for v in records.values())

    # DNS rows
    dns_rows = ""
    badge_colors = {"A": "#3b82f6", "AAAA": "#8b5cf6", "CNAME": "#10b981"}
    for rtype, rows in records.items():
        color = badge_colors.get(rtype, "#6b7280")
        for _, name, value in rows:
            dns_rows += (f"<tr><td><span class='badge' style='background:{color}'>{rtype}</span></td>"
                         f"<td>{name}</td><td>{value}</td></tr>\n")

    # Dangling rows
    if dangling:
        dangling_rows = "".join(
            f"<tr class='danger'><td>⚠ {d['fqdn']}</td><td>{d['cname']}</td><td>{d['service']}</td></tr>\n"
            for d in dangling
        )
    else:
        dangling_rows = "<tr><td colspan='3' class='ok-cell'>✓ Aucun dangling DNS détecté</td></tr>"

    # httpx rows
    if httpx_entries:
        httpx_rows = ""
        for e in httpx_entries:
            sc = e.get("status", "")
            color = "#16a34a" if sc.startswith("2") else "#ea580c" if sc in ("401","403") else "#2563eb"
            httpx_rows += (
                f"<tr><td><a href='{e['url']}' target='_blank'>{e['url']}</a></td>"
                f"<td><span class='badge' style='background:{color}'>{sc}</span></td>"
                f"<td>{e.get('title','')}</td><td>{e.get('server','')}</td>"
                f"<td>{', '.join(e.get('techs',[]))}</td></tr>\n"
            )
    else:
        httpx_rows = "<tr><td colspan='5' class='ok-cell'>Aucun résultat httpx</td></tr>"

    danger_banner = (
        f"<div class='danger-banner'>⚠ {len(dangling)} enregistrement(s) DANGLING — risque de subdomain takeover !</div>"
        if dangling else ""
    )

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Recon Report — {domain}</title>
<style>
  :root {{
    --bg:#0f172a; --surface:#1e293b; --border:#334155;
    --text:#e2e8f0; --muted:#94a3b8; --accent:#38bdf8;
    --danger:#ef4444; --ok:#22c55e;
  }}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;padding:2rem}}
  h1{{font-size:1.8rem;color:var(--accent);margin-bottom:.25rem}}
  .meta{{color:var(--muted);font-size:.85rem;margin-bottom:2rem}}
  .stats{{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}}
  .stat{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:.75rem 1.25rem;min-width:130px}}
  .stat .val{{font-size:1.6rem;font-weight:700;color:var(--accent)}}
  .stat .lbl{{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}}
  section{{margin-bottom:2.5rem}}
  h2{{font-size:1.1rem;color:var(--accent);border-bottom:1px solid var(--border);padding-bottom:.5rem;margin-bottom:1rem}}
  table{{width:100%;border-collapse:collapse;font-size:.85rem}}
  th{{background:var(--surface);color:var(--muted);text-align:left;padding:.5rem .75rem;font-weight:600;border-bottom:2px solid var(--border)}}
  td{{padding:.45rem .75rem;border-bottom:1px solid var(--border);vertical-align:top;word-break:break-all}}
  tr:hover td{{background:var(--surface)}}
  tr.danger td{{background:rgba(239,68,68,.08)}}
  .ok-cell{{color:var(--ok);text-align:center;padding:1rem}}
  .badge{{display:inline-block;padding:.15rem .5rem;border-radius:4px;color:#fff;font-size:.75rem;font-weight:600}}
  a{{color:var(--accent);text-decoration:none}}
  a:hover{{text-decoration:underline}}
  .danger-banner{{background:rgba(239,68,68,.15);border:1px solid var(--danger);border-radius:8px;
    padding:.75rem 1rem;margin-bottom:1.5rem;color:var(--danger);font-weight:600}}
</style>
</head>
<body>
<h1>🔍 Recon Report — {domain}</h1>
<p class="meta">Généré le {ts}</p>
<div class="stats">
  <div class="stat"><div class="val">{total_hosts}</div><div class="lbl">Hosts DNS</div></div>
  <div class="stat"><div class="val">{len(records.get('A',[]))}</div><div class="lbl">A records</div></div>
  <div class="stat"><div class="val">{len(records.get('AAAA',[]))}</div><div class="lbl">AAAA records</div></div>
  <div class="stat"><div class="val">{len(records.get('CNAME',[]))}</div><div class="lbl">CNAME records</div></div>
  <div class="stat"><div class="val" style="color:{'#ef4444' if dangling else '#22c55e'}">{len(dangling)}</div><div class="lbl">Dangling DNS</div></div>
  <div class="stat"><div class="val">{len(httpx_entries)}</div><div class="lbl">Applis actives</div></div>
</div>
{danger_banner}
<section>
  <h2>Enregistrements DNS ({total_hosts})</h2>
  <table><tr><th>Type</th><th>Nom</th><th>Valeur</th></tr>{dns_rows}</table>
</section>
<section>
  <h2>Dangling DNS — Subdomain Takeover ({len(dangling)})</h2>
  <table><tr><th>FQDN</th><th>CNAME cible</th><th>Service</th></tr>{dangling_rows}</table>
</section>
<section>
  <h2>Applications actives — httpx ({len(httpx_entries)})</h2>
  <table><tr><th>URL</th><th>Status</th><th>Titre</th><th>Serveur</th><th>Technologies</th></tr>{httpx_rows}</table>
</section>
</body>
</html>"""

    Path(report_path).write_text(html, encoding="utf-8")
    cprint("ok", f"Rapport HTML → {Path(report_path).resolve()}")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args   = parse_args()
    password = args.password or getpass.getpass("Mot de passe : ")
    wanted_types = [t.strip() for t in args.record_types.split(",")]

    # ── Dossier de sortie ──────────────────────────────────────────────────
    OUT_DIR = Path("out-LF4apps")
    OUT_DIR.mkdir(exist_ok=True)
    cprint("info", f"Dossier de sortie : {OUT_DIR.resolve()}")

    # Résolution des chemins (valeur CLI ou défaut dans OUT_DIR)
    csv_path      = Path(args.csv)          if args.csv          else OUT_DIR / "records.csv"
    url_file      = Path(args.url_file)     if args.url_file     else OUT_DIR / "urls-all.txt"
    httpx_out     = Path(args.httpx_out)    if args.httpx_out    else OUT_DIR / "httpx-output.txt"
    httpx_ok      = Path(args.httpx_ok)     if args.httpx_ok     else OUT_DIR / "httpx-urls-ok.txt"
    gowitness_out = Path(args.gowitness_out)if args.gowitness_out else OUT_DIR / "gowitness-output.txt"
    report_path   = Path(args.report)       if args.report       else OUT_DIR / "recon-report.html"
    partial_path  = OUT_DIR / "recon-partial.json"

    # Mise à jour du handler SIGINT pour utiliser le bon chemin
    def _sigint_out(sig, frame):
        cprint("warn", "Interruption — sauvegarde des résultats partiels…")
        if _partial_results:
            partial_path.write_text(json.dumps(_partial_results, indent=2, ensure_ascii=False))
            cprint("warn", f"Résultats partiels → {partial_path.resolve()}")
        sys.exit(130)
    signal.signal(signal.SIGINT, _sigint_out)

    banner(f"Recon pipeline — {args.domain}")

    # 1. adidnsdump
    if args.resume and csv_path.exists():
        cprint("warn", f"--resume : adidnsdump ignoré, CSV existant utilisé ({csv_path})")
    else:
        rc = run_adidnsdump(args.domain, args.username, password, args.dc,
                            out_csv=csv_path, print_zones=args.print_zones)
        if rc != 0:
            cprint("err", "adidnsdump a échoué, arrêt.")
            sys.exit(rc)

    # 2. Extraction DNS
    banner("Extraction DNS (A / AAAA / CNAME)")
    records = extract_dns_records(str(csv_path), wanted_types)
    _partial_results["records"] = {k: [list(r) for r in v] for k, v in records.items()}

    if not any(records.values()):
        cprint("err", "Aucun enregistrement trouvé, arrêt.")
        sys.exit(0)

    # 3. Dangling DNS
    dangling = []
    if not args.skip_dangling:
        banner("Dangling DNS check")
        dangling = check_dangling(records, args.domain)
        _partial_results["dangling"] = dangling
    else:
        cprint("warn", "Dangling DNS check ignoré (--skip-dangling)")

    # 4. Génération URLs
    banner("Génération des URLs")
    build_url_file(records, args.domain, str(url_file),
                   skip_extra_ports=args.skip_extra_ports)

    # 5. httpx
    httpx_entries = []
    if not args.skip_httpx:
        banner("httpx")
        run_httpx(str(url_file), str(httpx_out))
        httpx_entries = extract_httpx_urls_ok(str(httpx_out), str(httpx_ok))
        _partial_results["httpx"] = httpx_entries
    else:
        cprint("warn", "httpx ignoré (--skip-httpx)")

    # 6. gowitness
    if not args.skip_gowitness:
        if httpx_entries:
            banner("gowitness")
            run_gowitness(str(httpx_ok), str(gowitness_out), args.threads, args.timeout)
        else:
            cprint("warn", "gowitness ignoré — aucune URL active à screenshotter")
    else:
        cprint("warn", "gowitness ignoré (--skip-gowitness)")

    # 7. Rapport HTML
    if not args.no_report:
        banner("Rapport HTML")
        generate_html_report(args.domain, records, dangling, httpx_entries, str(report_path))

    # Résumé
    banner("Résumé")
    cprint("ok",  f"A        : {len(records.get('A',[]))}")
    cprint("ok",  f"AAAA     : {len(records.get('AAAA',[]))}")
    cprint("ok",  f"CNAME    : {len(records.get('CNAME',[]))}")
    if dangling:
        cprint("err", f"Dangling : {len(dangling)}  ← ⚠ vérifier manuellement !")
    else:
        cprint("ok", "Dangling : 0")
    cprint("ok",  f"Applis   : {len(httpx_entries)}")
    cprint("ok",  "Pipeline terminé.")


if __name__ == "__main__":
    main()