"""
modules/report.py
=================
MOKSH — Phase 5: Merge + Report Generation

This module does ONE job: read every JSON result file written by the
previous phases, merge them into per-domain records, and write the
final hybrid report file.

Report rules (from 08_rules_and_decisions):
  - report.py NEVER runs a tool. It only reads files and writes the report.
  - No raw tool output in Sections 1-4. English only. Human-readable.
  - Section 5 is JSON only. All structured data lives here.
  - id field starts at 1 — sequential integer, processing order.
  - scan_profile present in EVERY record (deep / stealth / null for dead).
  - MITRE in JSON only — not in English sections.
  - Dead domain records: complete schema, all fields null/empty.
  - Stealth result records: annotated in comments (the JSON comment block).
  - One record per DOMAIN — not per IP. IP is a field inside the record.

Data sources (all loaded from temp/ JSON files — never raw text):
  temp/httpx_raw.txt         → re-parsed for status + title per URL
  temp/subdomains_dedup.txt  → Section 2 subdomain list
  temp/live_urls.txt         → live domain list (ordering for Section 3)
  temp/dead_domains.txt      → dead domain list (Section 4)
  temp/dns_resolved.txt      → NXDOMAIN detection for dead domains
  temp/waf_profile_map.json  → {url: {waf, scan_profile}}  (wafw00f.py)
  temp/ip_map.json           → {domain: ip}                 (dnsx.py)
  temp/nmap_results.json     → {ip: [ports]}                (nmap.py)
  temp/nuclei_results.json   → {url: [findings]}            (nuclei.py)
  temp/katana_results.json   → {domain: [endpoints]}        (katana.py)

MITRE ATT&CK rule-based mapping (~12 conditions, no external library):
  T1595.001  Subfinder ran (input was domain/url)
  T1595.002  Subfinder found subdomains (count > 1)
  T1590      httpx got any HTTP response (domain is live)
  T1592.002  dnsx resolved domain to IP
  T1046      Nmap found any open port
  T1190      Nuclei found any vulnerability
  T1083      Katana found any endpoints
  T1584.001  Dead domain with NXDOMAIN (high-value takeover signal)
  T1592.002  WAF detected (also triggers this — defensive infra info)
  (deduped — T1592.002 appears once even if both IP and WAF trigger it)

Output:
  Single .txt file containing Sections 1-4 (English) + Section 5 (JSON).
  File path determined by main.py (flags["output_path"]).
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import utils.flags as flags
from utils.parser import (
    read_lines,
    parse_httpx_line,
    parse_dnsx_line,
    extract_domain_from_url,
)

# Loader helpers from each module — report.py never re-parses raw tool output
from modules.wafw00f import load_profile_map
from modules.dnsx    import load_ip_map
from modules.nmap    import load_nmap_results
from modules.nuclei  import load_nuclei_results
from modules.katana  import load_katana_results


# ===========================================================================
# MITRE ATT&CK rule-based mapper
# ~12 conditions, Python dict, zero external libraries
# ===========================================================================

def _apply_mitre(
    is_live:          bool,
    is_dead:          bool,
    is_nxdomain:      bool,
    subfinder_ran:    bool,
    subfinder_found:  bool,
    has_ip:           bool,
    has_ports:        bool,
    has_vulns:        bool,
    has_endpoints:    bool,
    has_waf:          bool,
) -> list[str]:
    """
    Apply the MITRE ATT&CK rule table from the phase reference spec.
    Returns a deduplicated list of technique IDs in spec order.

    All conditions are boolean — computed by the record builder before
    calling this function. No tool output is parsed here.
    """
    techniques: list[str] = []

    # T1595.001 — Active Scanning: Port Scan
    # Trigger: subfinder ran (means domain/url input — full pipeline)
    if subfinder_ran:
        techniques.append("T1595.001")

    # T1595.002 — Active Scanning: Vulnerability Scanning
    # Trigger: subfinder found subdomains
    if subfinder_found:
        techniques.append("T1595.002")

    # T1590 — Gather Victim Network Info
    # Trigger: httpx got any HTTP response (domain is live)
    if is_live:
        techniques.append("T1590")

    # T1592.002 — Gather Victim Host Info: Software
    # Trigger: dnsx resolved domain to IP  OR  WAF detected
    # Added once even if both conditions are true (dedup at end)
    if has_ip:
        techniques.append("T1592.002")
    if has_waf and "T1592.002" not in techniques:
        techniques.append("T1592.002")

    # T1046 — Network Service Discovery
    # Trigger: nmap found any open port
    if has_ports:
        techniques.append("T1046")

    # T1190 — Exploit Public-Facing Application
    # Trigger: nuclei found any vulnerability
    if has_vulns:
        techniques.append("T1190")

    # T1083 — File and Directory Discovery
    # Trigger: katana found any endpoints
    if has_endpoints:
        techniques.append("T1083")

    # T1584.001 — Compromise Infrastructure: Domains
    # Trigger: dead domain with NXDOMAIN (high-value subdomain takeover signal)
    if is_dead and is_nxdomain:
        techniques.append("T1584.001")

    # Final dedup preserving order (a technique can't be added twice)
    seen:   set[str]  = set()
    unique: list[str] = []
    for t in techniques:
        if t not in seen:
            seen.add(t)
            unique.append(t)

    return unique


# ===========================================================================
# Per-domain record builder
# ===========================================================================

def _build_record(
    domain_id:    int,
    domain:       str,
    status:       str,           # "live" | "dead"
    http_status:  Optional[int],
    title:        Optional[str],
    waf:          Optional[str],
    scan_profile: Optional[str],
    ip:           Optional[str],
    ports:        list[str],
    vulnerabilities: Any,        # list[dict] for live, "skipped - dead domain" for dead
    endpoints:    list[str],
    # MITRE condition inputs
    subfinder_ran:   bool,
    subfinder_found: bool,
    is_nxdomain:     bool,
) -> dict:
    """
    Build one complete JSON record matching the schema from the sample report.

    Schema:
      id · domain · ip · status · http_status · title · waf · scan_profile
      · ports · vulnerabilities · endpoints · mitre
    """
    mitre = _apply_mitre(
        is_live         = (status == "live"),
        is_dead         = (status == "dead"),
        is_nxdomain     = is_nxdomain,
        subfinder_ran   = subfinder_ran,
        subfinder_found = subfinder_found,
        has_ip          = ip is not None,
        has_ports       = bool(ports),
        has_vulns       = isinstance(vulnerabilities, list) and len(vulnerabilities) > 0,
        has_endpoints   = bool(endpoints),
        has_waf         = waf is not None,
    )

    return {
        "id":              domain_id,
        "domain":          domain,
        "ip":              ip,
        "status":          status,
        "http_status":     http_status,
        "title":           title,
        "waf":             waf,
        "scan_profile":    scan_profile,
        "ports":           ports,
        "vulnerabilities": vulnerabilities,
        "endpoints":       endpoints,
        "mitre":           mitre,
    }


# ===========================================================================
# NXDOMAIN detection
# ===========================================================================

def _build_resolved_set(temp_dir: Path) -> set[str]:
    """
    Build a set of bare domains that dnsx successfully resolved.
    A dead domain NOT in this set → NXDOMAIN.
    """
    resolved: set[str] = set()
    for line in read_lines(temp_dir / "dns_resolved.txt"):
        parsed = parse_dnsx_line(line)
        if parsed:
            resolved.add(parsed["domain"].lower())
    return resolved


def _is_nxdomain(domain: str, resolved_set: set[str]) -> bool:
    """
    Return True if the domain is absent from DNS resolution results.
    Bare domain comparison — strip protocol if needed.
    """
    bare = extract_domain_from_url(domain) if domain.startswith("http") \
           else domain.lower()
    return bare not in resolved_set


# ===========================================================================
# httpx metadata loader
# ===========================================================================

def _load_httpx_meta(temp_dir: Path) -> dict[str, dict]:
    """
    Re-parse temp/httpx_raw.txt into {url: {status, title}} dict.
    This is the source for http_status and title in every live record.

    We re-parse from disk (not from in-memory url_meta) so report.py
    is fully self-contained and doesn't depend on main.py passing data through.
    """
    meta: dict[str, dict] = {}
    for line in read_lines(temp_dir / "httpx_raw.txt"):
        parsed = parse_httpx_line(line)
        if parsed:
            meta[parsed["url"]] = {
                "status": parsed["status"],
                "title":  parsed["title"],
            }
    return meta


# ===========================================================================
# Report section builders (English, Sections 1–4)
# Rules: no raw tool output, human-readable, quick reference only
# ===========================================================================

def _section1(f: dict, output_filename: str) -> str:
    """Section 1 — Target Information."""
    target     = f.get("target", "unknown")
    mode       = f.get("mode", "soft")
    input_type = f.get("input_type", "domain")
    ts         = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Mode description line
    if mode == "soft":
        mode_desc = "non-recursive subfinder · top-1000 nmap · katana depth 3"
    else:
        mode_desc = "recursive subfinder · full port 0-65535 · katana depth 5"

    # Nmap port description
    nmap_ports = f.get("nmap_ports_flag", "--top-ports 1000")
    if "--top-ports" in nmap_ports:
        nmap_deep_ports = "top-1000"
    else:
        nmap_deep_ports = nmap_ports.replace("-p ", "")

    lines = [
        "=" * 72,
        "  MOKSH — RECON REPORT",
        "  Liberation by Recon",
        "=" * 72,
        "",
        "1. TARGET INFORMATION",
        "-" * 40,
        f"  Root domain    : {target}",
        f"  Input type     : {input_type.capitalize()}",
        f"  Scan mode      : {mode} ({mode_desc})",
        f"  Timestamp      : {ts}",
        f"  Tools          : subfinder · httpx · wafw00f · dnsx · nmap · nuclei · katana",
        f"  Nuclei deep    : all templates · rl={f.get('nuclei_rl', 15)} · "
        f"timeout={f.get('nuclei_timeout', 30)}s",
        f"  Nuclei stealth : info+tech-detect · rl={f.get('nuclei_stealth_rl', 5)} · "
        f"timeout={f.get('nuclei_stealth_timeout', 60)}s",
        f"  Katana deep    : depth={f.get('katana_depth', 3)} · "
        f"rl={f.get('katana_rl', 15)} · no delay",
        f"  Katana stealth : depth={f.get('katana_stealth_depth', 2)} · "
        f"rl={f.get('katana_stealth_rl', 5)} · "
        f"delay={f.get('katana_stealth_delay', 2)}s",
        f"  Nmap deep      : {nmap_deep_ports} · -Pn · --open · -sV · -O",
        f"  Nmap stealth   : {nmap_deep_ports} · -Pn · --open · no -sV · no -O",
        f"  Output file    : {output_filename}",
        "",
    ]
    return "\n".join(lines) + "\n"


def _section2(subdomains: list[str]) -> str:
    """Section 2 — Subdomains (deduplicated list)."""
    count = len(subdomains)
    lines = [
        "2. SUBDOMAINS",
        "-" * 40,
        f"  Deduplicated — {count} found",
        "",
    ]
    # Display in rows of 3, matching sample report format
    for i in range(0, len(subdomains), 3):
        row = subdomains[i:i + 3]
        lines.append("  " + "   ".join(f"{s:<35}" for s in row).rstrip())
    lines.append("")
    return "\n".join(lines) + "\n"


def _section3(live_records: list[dict]) -> str:
    """Section 3 — Live Domains table."""
    count = len(live_records)
    col_url     = 45
    col_status  = 8
    col_title   = 30
    col_waf     = 20

    header = [
        "3. LIVE DOMAINS",
        "-" * 40,
        f"  {count} live · httpx probe",
        "",
        f"  {'URL':<{col_url}} {'STATUS':<{col_status}} {'TITLE':<{col_title}} "
        f"{'WAF':<{col_waf}} PROFILE",
        "  " + "-" * 110,
    ]

    rows = []
    for rec in live_records:
        url     = str(rec.get("domain", ""))[:col_url - 1]
        status  = str(rec.get("http_status") or "")
        title   = str(rec.get("title") or "")[:col_title - 1]
        waf     = str(rec.get("waf") or "None")[:col_waf - 1]
        profile = str(rec.get("scan_profile") or "")
        rows.append(
            f"  {url:<{col_url}} {status:<{col_status}} "
            f"{title:<{col_title}} {waf:<{col_waf}} {profile}"
        )

    return "\n".join(header + rows) + "\n\n"


def _section4(dead_records: list[dict]) -> str:
    """Section 4 — Dead Domains table."""
    count = len(dead_records)
    col_domain = 40
    col_reason = 25

    header = [
        "4. DEAD DOMAINS",
        "-" * 40,
        f"  {count} dead — check for subdomain takeover",
        "",
        f"  {'DOMAIN':<{col_domain}} {'REASON':<{col_reason}} NOTE",
        "  " + "-" * 90,
    ]

    rows = []
    for rec in dead_records:
        domain = str(rec.get("domain", ""))[:col_domain - 1]
        reason = str(rec.get("_dead_reason", "No response"))[:col_reason - 1]
        note   = str(rec.get("_dead_note", ""))
        rows.append(f"  {domain:<{col_domain}} {reason:<{col_reason}} {note}")

    return "\n".join(header + rows) + "\n\n"


# ===========================================================================
# Section 5 — JSON block builder
# ===========================================================================

def _section5_header() -> str:
    return (
        "5. STRUCTURED OUTPUT\n"
        "  JSON — one record per domain/IP\n"
        "  Fields: id · domain · ip · status · http_status · title · waf\n"
        "          scan_profile · ports · vulnerabilities · endpoints · mitre\n\n"
    )


def _record_comment(rec: dict) -> str:
    """
    Build the comment line that appears before each JSON record,
    matching the format from the sample report:
    /* Record #1 — api.example.com — LIVE — deep scan — no WAF */
    """
    rid     = rec.get("id", "?")
    domain  = rec.get("domain", "")
    status  = rec.get("status", "").upper()
    profile = rec.get("scan_profile") or "n/a"
    waf     = rec.get("waf")
    waf_str = f"WAF: {waf}" if waf else "no WAF"

    if status == "DEAD":
        return f"/* Record #{rid} — {domain} — DEAD */"
    else:
        return f"/* Record #{rid} — {domain} — {status} — {profile} scan — {waf_str} */"


def _build_section5(records: list[dict]) -> str:
    """
    Build the full Section 5 JSON block.
    Each record gets a comment line (as in sample report) then its JSON.
    Internal _dead_reason/_dead_note keys are stripped before serialisation.
    """
    lines = [_section5_header()]

    clean_keys = {"_dead_reason", "_dead_note"}

    for i, rec in enumerate(records):
        # Strip internal display-only keys
        clean_rec = {k: v for k, v in rec.items() if k not in clean_keys}

        comment = _record_comment(clean_rec)
        # Indent JSON 2 spaces, add trailing comma except last record
        json_str = json.dumps(clean_rec, indent=2, ensure_ascii=False)
        separator = "," if i < len(records) - 1 else ""

        lines.append(comment)
        lines.append(json_str + separator)
        lines.append("")

    return "\n".join(lines)


# ===========================================================================
# Public API
# ===========================================================================

def run_report(flags_dict: dict, temp_dir: Path) -> dict:
    """
    Execute Phase 5 — merge all results and write the final report.

    This function:
      1. Loads all JSON result files from temp/.
      2. Builds per-domain records for every live and dead domain.
      3. Assigns sequential ids starting at 1.
      4. Applies MITRE ATT&CK mapping per record.
      5. Writes the hybrid report (Sections 1-4 English + Section 5 JSON).

    Parameters
    ----------
    flags_dict : dict  — resolved config from flags.load_flags()
    temp_dir   : Path  — path to the temp/ directory

    Returns
    -------
    dict:
        vuln_count  : int   — total vulnerabilities found
        crit_count  : int   — critical severity findings
        live_count  : int
        dead_count  : int
        waf_count   : int   — domains behind a WAF
        unique_ips  : int
        output_path : str   — final report file path

    Raises
    ------
    RuntimeError
        If the report file cannot be written.
        main.py catches this and exits with code 1.
    """
    f       = flags_dict
    verbose = f.get("verbose", False)

    output_path = Path(f.get("output_path", "recon_report.txt"))

    # ── Load all data sources from temp/ ─────────────────────────────────
    if verbose:
        print("[report] Loading data from temp/...")

    profile_map  : dict[str, dict]         = load_profile_map(temp_dir)
    ip_map       : dict[str, str]          = load_ip_map(temp_dir)
    nmap_results : dict[str, list[str]]    = load_nmap_results(temp_dir)
    nuclei_results: dict[str, list[dict]]  = load_nuclei_results(temp_dir)
    katana_results: dict[str, list[str]]   = load_katana_results(temp_dir)
    httpx_meta   : dict[str, dict]         = _load_httpx_meta(temp_dir)
    resolved_set : set[str]                = _build_resolved_set(temp_dir)

    # Raw lists from temp/
    live_urls    : list[str] = read_lines(temp_dir / "live_urls.txt")
    dead_domains : list[str] = read_lines(temp_dir / "dead_domains.txt")
    all_subs     : list[str] = read_lines(temp_dir / "subdomains_dedup.txt")

    input_type = f.get("input_type", "domain")

    # MITRE global conditions (same for all records in this scan)
    subfinder_ran   = (input_type != "ip")
    # subfinder_found = more than just the root domain itself
    subfinder_found = len(all_subs) > 1

    if verbose:
        print(f"[report] Live: {len(live_urls)} | Dead: {len(dead_domains)} | "
              f"Subdomains: {len(all_subs)}")

    # ── Build records ─────────────────────────────────────────────────────
    all_records:  list[dict] = []
    live_records: list[dict] = []
    dead_records: list[dict] = []
    domain_id = 1

    # ── LIVE records ──────────────────────────────────────────────────────
    for url in live_urls:
        bare = extract_domain_from_url(url) if url.startswith("http") \
               else url.lower()

        # httpx data — status + title
        meta        = httpx_meta.get(url, {})
        http_status = meta.get("status")
        title       = meta.get("title") or None  # empty string → None

        # WAF gate data — waf name + scan profile
        prof_entry  = profile_map.get(url, {})
        waf         = prof_entry.get("waf")         # None or "Cloudflare" etc
        scan_profile = prof_entry.get("scan_profile", "deep")

        # dnsx data — IP
        ip = ip_map.get(bare)

        # nmap data — ports (looked up by IP)
        ports: list[str] = nmap_results.get(ip, []) if ip else []

        # nuclei data — vulnerabilities (try full URL first, then bare domain)
        raw_vulns: list[dict] = (
            nuclei_results.get(url, []) or
            nuclei_results.get(bare, []) or
            []
        )

        # katana data — endpoints (keyed by bare domain)
        raw_endpoints: list[str] = katana_results.get(bare, [])
        # Strip protocol from endpoints for JSON — keep only path
        endpoints = _strip_to_paths(raw_endpoints)

        rec = _build_record(
            domain_id    = domain_id,
            domain       = url,
            status       = "live",
            http_status  = http_status,
            title        = title,
            waf          = waf,
            scan_profile = scan_profile,
            ip           = ip,
            ports        = ports,
            vulnerabilities = raw_vulns if raw_vulns else [],
            endpoints    = endpoints,
            subfinder_ran   = subfinder_ran,
            subfinder_found = subfinder_found,
            is_nxdomain     = False,
        )

        all_records.append(rec)
        live_records.append(rec)
        domain_id += 1

    # ── IP input: no live_urls.txt — build single record from target IP ───
    if input_type == "ip" and not live_urls:
        target_ip = f.get("target", "")
        ports     = nmap_results.get(target_ip, [])
        raw_vulns = (
            nuclei_results.get(target_ip, []) or
            nuclei_results.get(f"http://{target_ip}", []) or
            nuclei_results.get(f"https://{target_ip}", []) or
            []
        )

        rec = _build_record(
            domain_id    = domain_id,
            domain       = target_ip,
            status       = "live",
            http_status  = None,
            title        = None,
            waf          = None,
            scan_profile = "deep",
            ip           = target_ip,
            ports        = ports,
            vulnerabilities = raw_vulns if raw_vulns else [],
            endpoints    = [],
            subfinder_ran   = False,
            subfinder_found = False,
            is_nxdomain     = False,
        )
        all_records.append(rec)
        live_records.append(rec)
        domain_id += 1

    # ── DEAD records ──────────────────────────────────────────────────────
    for domain in dead_domains:
        bare        = extract_domain_from_url(domain) if domain.startswith("http") \
                      else domain.lower()
        nxdomain    = _is_nxdomain(bare, resolved_set)
        dead_reason = "NXDOMAIN"   if nxdomain else "No response"
        dead_note   = "Potential subdomain takeover or Name Server" if nxdomain else ""

        rec = _build_record(
            domain_id    = domain_id,
            domain       = domain,
            status       = "dead",
            http_status  = None,
            title        = None,
            waf          = None,
            scan_profile = None,
            ip           = None,
            ports        = [],
            vulnerabilities = "skipped - dead domain",
            endpoints    = [],
            subfinder_ran   = subfinder_ran,
            subfinder_found = subfinder_found,
            is_nxdomain     = nxdomain,
        )
        # Attach display-only keys for Section 4 table (stripped before JSON)
        rec["_dead_reason"] = dead_reason
        rec["_dead_note"]   = dead_note

        all_records.append(rec)
        dead_records.append(rec)
        domain_id += 1

    # ── Summary counters ──────────────────────────────────────────────────
    all_vulns  = [
        v for rec in all_records
        for v in (rec.get("vulnerabilities") or [])
        if isinstance(v, dict)
    ]
    vuln_count  = len(all_vulns)
    crit_count  = sum(1 for v in all_vulns if v.get("severity") == "critical")
    waf_count   = sum(1 for r in live_records if r.get("waf") is not None)
    unique_ips  = len({r.get("ip") for r in all_records if r.get("ip")})

    if verbose:
        print(
            f"[report] Records built: {len(live_records)} live + "
            f"{len(dead_records)} dead | "
            f"Vulns: {vuln_count} ({crit_count} critical) | "
            f"WAF: {waf_count} | IPs: {unique_ips}"
        )

    # ── Assemble full report ──────────────────────────────────────────────
    report_text = (
        _section1(f, output_path.name) +
        _section2(all_subs) +
        _section3(live_records) +
        _section4(dead_records) +
        _build_section5(all_records)
    )

    # ── Write to disk ─────────────────────────────────────────────────────
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report_text, encoding="utf-8")
    except Exception as exc:
        raise RuntimeError(
            f"Could not write report to {output_path}: {exc}"
        )

    if verbose:
        print(f"[report] Written: {output_path}")

    return {
        "vuln_count":  vuln_count,
        "crit_count":  crit_count,
        "live_count":  len(live_records),
        "dead_count":  len(dead_records),
        "waf_count":   waf_count,
        "unique_ips":  unique_ips,
        "output_path": str(output_path),
    }


# ===========================================================================
# Internal helpers
# ===========================================================================

def _strip_to_paths(endpoints: list[str]) -> list[str]:
    """
    Convert full endpoint URLs to path-only strings for the JSON output.

    The sample report shows endpoints as paths:
      ["/api/v1/users", "/api/v1/admin", "/upload", "/config.json"]

    katana_results.json stores full URLs like:
      ["https://api.example.com/api/v1/users", ...]

    We strip the protocol + domain, keeping only /path?query.
    If the endpoint is already a path (starts with /), keep as-is.
    """
    paths: list[str] = []
    for ep in endpoints:
        if not ep.startswith("http"):
            paths.append(ep)
            continue
        # Extract path from URL
        try:
            # Remove protocol + host: "https://api.example.com/path" → "/path"
            no_proto = ep.split("://", 1)[1] if "://" in ep else ep
            slash_pos = no_proto.find("/")
            if slash_pos == -1:
                paths.append("/")
            else:
                paths.append(no_proto[slash_pos:])
        except Exception:
            paths.append(ep)
    return paths
