"""
modules/dnsx.py
MOKSH — Phase 4C (Part 1): DNS Resolution

Resolves live domains to IPs using dnsx.
However: dnsx output format has changed across versions. We now handle
ALL known formats via a multi-pattern parser in utils/parser.py.

What it does:
  1. Strips protocol + path from live_urls.txt → bare domains only
  2. Deduplicates bare domains before resolving
  3. Runs dnsx -a -resp -silent -threads N
  4. Parses output with multi-format parser → {domain: ip} mapping
  5. Socket fallback for any domains dnsx missed
  6. Deduplicates IPs (two domains on same CDN IP = one nmap scan)
  7. Writes all output files for nmap.py and report.py

Extra flags:
  --dnsx-extra passes raw flags to dnsx subprocess.
  Known flags are overwritten, new flags inserted before -o.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Optional

import utils.flags as flags
from utils.parser import (
    read_lines,
    write_lines,
    dedup_lines,
    parse_dnsx_line,
    apply_extra_flags,
    extract_domain_from_url,
)

# ---------------------------------------------------------------------------
# Socket fallback
# ---------------------------------------------------------------------------
def _socket_resolve(domain: str) -> Optional[str]:
    """
    Resolve a single domain to its first IPv4 address using socket.
    Returns IP string or None on failure.

    Used only as a fallback when dnsx returns no result for a domain.
    Not a replacement for dnsx — just fills the gaps.
    """
    try:
        # getaddrinfo returns list of (family, type, proto, canonname, sockaddr)
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        if results:
            return results[0][4][0]   # first IPv4 address
    except Exception:
        pass
    return None

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def run_dnsx(flags_dict: dict, temp_dir: Path) -> dict:
    """
    Execute DNS resolution phase.

    Reads  : temp/live_urls.txt  (and temp/waf_domains.txt for WAF IP list)
    Writes :
        temp/domains_stripped.txt  — bare hostnames sent to dnsx
        temp/dns_resolved.txt      — raw dnsx output lines
        temp/unique_ips.txt        — deduplicated IPs for nmap deep scan
        temp/waf_ips.txt           — IPs behind WAF (for nmap stealth scan)
        temp/ip_map.json           — {domain: ip} consumed by report.py

    Returns
    -------
    dict:
        domain_ip_map : dict[str, str]
        unique_ips    : list[str]
        waf_ips       : list[str]
        ip_map_file   : str
    """
    f       = flags_dict
    verbose = f.get("verbose", False)

    input_type = f.get("input_type", "domain")

    # IP input: skip dnsx entirely, write direct mapping
    if input_type == "ip":
        return _handle_ip_input(f, temp_dir, verbose)

    binary = shutil.which("dnsx")
    if binary is None:
        print("[dnsx] WARNING: dnsx not found in PATH — trying socket fallback.",
              file=sys.stderr)
        # No dnsx at all — go straight to socket resolution
        return _full_socket_fallback(f, temp_dir, verbose)

    live_file       = temp_dir / "live_urls.txt"
    waf_file        = temp_dir / "waf_domains.txt"
    stripped_file   = temp_dir / "domains_stripped.txt"
    resolved_file   = temp_dir / "dns_resolved.txt"
    unique_ips_file = temp_dir / "unique_ips.txt"
    waf_ips_file    = temp_dir / "waf_ips.txt"
    ip_map_file     = temp_dir / "ip_map.json"

    if not live_file.exists() or not read_lines(live_file):
        print("[dnsx] WARNING: live_urls.txt empty — skipping.", file=sys.stderr)
        return _write_empty_outputs(temp_dir)

    live_urls = read_lines(live_file)

    # ── Step 1: Strip protocol + path → bare hostnames ───────────────────
    bare_domains: list[str] = []
    for url in live_urls:
        bare = extract_domain_from_url(url) if url.startswith("http") else url.lower()
        bare_domains.append(bare)

    bare_domains = dedup_lines(bare_domains)
    write_lines(stripped_file, bare_domains)

    if verbose:
        print(f"[dnsx] Resolving {len(bare_domains)} unique domain(s)...")

    # ── Step 2: Build dnsx command ────────────────────────────────────────
    base_cmd = [
        binary,
        "-l",       str(stripped_file),
        "-a",                               # query A records only
        "-resp",                            # include IP in output
        "-silent",
        "-threads", str(f.get("dnsx_threads", 50)),
        "-o",       str(resolved_file),
    ]

    cmd = apply_extra_flags(
        base_cmd,
        f.get("dnsx_extra"),
        protected    = [],
        output_flags = ["-o"],
    )

    if verbose:
        print(f"[dnsx] Command: {' '.join(cmd)}")

    # ── Step 3: Run dnsx ──────────────────────────────────────────────────
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
            text=True,
        )
        if verbose and proc.stderr.strip():
            print(f"[dnsx] stderr: {proc.stderr.strip()}", file=sys.stderr)
    except subprocess.TimeoutExpired:
        print("[dnsx] WARNING: timed out — using socket fallback.", file=sys.stderr)
        return _full_socket_fallback(f, temp_dir, verbose)
    except Exception as exc:
        print(f"[dnsx] WARNING: execution failed ({exc}) — using socket fallback.",
              file=sys.stderr)
        return _full_socket_fallback(f, temp_dir, verbose)

    # ── Step 4: Parse dnsx output with multi-format parser ────────────────
    # Some dnsx versions write to stdout instead of -o file when -silent is set.
    # Read from -o file first; if empty fall back to capturing stdout lines.
    resolved_lines = read_lines(resolved_file)
    if not resolved_lines and proc.stdout.strip():
        if verbose:
            print("[dnsx] -o file empty — reading from stdout instead")
        stdout_lines = [
            ln.strip() for ln in proc.stdout.splitlines() if ln.strip()
        ]
        # Write captured stdout to resolved_file so downstream tools can read it
        write_lines(resolved_file, stdout_lines)
        resolved_lines = stdout_lines
    domain_ip_map: dict[str, str] = {}

    for line in resolved_lines:
        parsed = parse_dnsx_line(line)
        if parsed:
            domain_ip_map[parsed["domain"]] = parsed["ip"]

    if verbose:
        print(f"[dnsx] Parsed {len(domain_ip_map)}/{len(bare_domains)} domains from output")

    # ── Step 5: Socket fallback for any domain dnsx missed ────────────────
    # dnsx may silently skip some domains (timeout, wildcard, NXDOMAIN).
    # For any domain with no IP yet, try socket as a silent backup.
    fallback_count = 0
    for domain in bare_domains:
        if domain not in domain_ip_map:
            ip = _socket_resolve(domain)
            if ip:
                domain_ip_map[domain] = ip
                fallback_count += 1
                if verbose:
                    print(f"[dnsx/fallback] {domain} → {ip}")

    if fallback_count and verbose:
        print(f"[dnsx] Socket fallback resolved {fallback_count} additional domain(s)")

    if verbose:
        print(f"[dnsx] Total resolved: {len(domain_ip_map)} domain(s)")

    # ── Step 6: Build unique IP list (deduped) for nmap deep scan ─────────
    all_ips    = list(domain_ip_map.values())
    unique_ips = dedup_lines(sorted(set(all_ips)))
    write_lines(unique_ips_file, unique_ips)

    # ── Step 7: Build WAF IP list for nmap stealth scan ───────────────────
    waf_urls = read_lines(waf_file)
    waf_ips: list[str] = []
    for url in waf_urls:
        bare = extract_domain_from_url(url) if url.startswith("http") else url.lower()
        ip   = domain_ip_map.get(bare)
        if ip:
            waf_ips.append(ip)
    waf_ips = dedup_lines(waf_ips)
    write_lines(waf_ips_file, waf_ips)

    # ── Step 8: Write ip_map.json for report.py ───────────────────────────
    ip_map_file.write_text(
        json.dumps(domain_ip_map, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    if verbose:
        print(f"[dnsx] unique_ips: {unique_ips[:5]}{'...' if len(unique_ips) > 5 else ''}")
        print(f"[dnsx] waf_ips:    {waf_ips[:5]}{'...' if len(waf_ips) > 5 else ''}")

    return {
        "domain_ip_map": domain_ip_map,
        "unique_ips":    unique_ips,
        "waf_ips":       waf_ips,
        "ip_map_file":   str(ip_map_file),
    }

# ---------------------------------------------------------------------------
# Full socket fallback (when dnsx binary is missing entirely)
# ---------------------------------------------------------------------------
def _full_socket_fallback(
    flags_dict: dict,
    temp_dir:   Path,
    verbose:    bool,
) -> dict:
    """
    Resolve all bare domains using socket when dnsx is unavailable.
    Reads bare_domains from live_urls.txt directly.
    """
    live_file       = temp_dir / "live_urls.txt"
    waf_file        = temp_dir / "waf_domains.txt"
    stripped_file   = temp_dir / "domains_stripped.txt"
    resolved_file   = temp_dir / "dns_resolved.txt"
    unique_ips_file = temp_dir / "unique_ips.txt"
    waf_ips_file    = temp_dir / "waf_ips.txt"
    ip_map_file     = temp_dir / "ip_map.json"

    live_urls = read_lines(live_file)
    bare_domains: list[str] = []
    for url in live_urls:
        bare = extract_domain_from_url(url) if url.startswith("http") else url.lower()
        bare_domains.append(bare)
    bare_domains = dedup_lines(bare_domains)
    write_lines(stripped_file, bare_domains)

    domain_ip_map: dict[str, str] = {}
    resolved_lines: list[str]     = []

    for domain in bare_domains:
        ip = _socket_resolve(domain)
        if ip:
            domain_ip_map[domain] = ip
            resolved_lines.append(f"{domain} [{ip}]")
            if verbose:
                print(f"[dnsx/socket] {domain} → {ip}")

    write_lines(resolved_file, resolved_lines)

    all_ips    = list(domain_ip_map.values())
    unique_ips = dedup_lines(sorted(set(all_ips)))
    write_lines(unique_ips_file, unique_ips)

    waf_urls = read_lines(waf_file)
    waf_ips: list[str] = []
    for url in waf_urls:
        bare = extract_domain_from_url(url) if url.startswith("http") else url.lower()
        ip   = domain_ip_map.get(bare)
        if ip:
            waf_ips.append(ip)
    waf_ips = dedup_lines(waf_ips)
    write_lines(waf_ips_file, waf_ips)

    ip_map_file.write_text(
        json.dumps(domain_ip_map, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    if verbose:
        print(f"[dnsx/socket] Resolved {len(domain_ip_map)} domain(s) via socket")

    return {
        "domain_ip_map": domain_ip_map,
        "unique_ips":    unique_ips,
        "waf_ips":       waf_ips,
        "ip_map_file":   str(ip_map_file),
    }

# ---------------------------------------------------------------------------
# IP input handler
# ---------------------------------------------------------------------------
def _handle_ip_input(
    flags_dict: dict,
    temp_dir:   Path,
    verbose:    bool,
) -> dict:
    """
    For IP input: dnsx resolution is skipped (IP is already resolved).

    BUT: we still need httpx and wafw00f to run so we know which protocol
    is live and whether there is a WAF on the IP. To do this without
    changing any downstream module, we write the IP as full URLs into
    live_urls.txt and subdomains_dedup.txt — the same files httpx and
    wafw00f expect. main.py will then NOT skip those phases for IP input.

    We also write the IP→IP mapping into ip_map.json and unique_ips.txt
    so nmap always has a target regardless of what httpx/wafw00f produce.
    """
    target_ip       = flags_dict.get("target", "")
    unique_ips_file = temp_dir / "unique_ips.txt"
    waf_ips_file    = temp_dir / "waf_ips.txt"
    ip_map_file     = temp_dir / "ip_map.json"
    stripped_file   = temp_dir / "domains_stripped.txt"
    resolved_file   = temp_dir / "dns_resolved.txt"
    live_file       = temp_dir / "live_urls.txt"
    dedup_file      = temp_dir / "subdomains_dedup.txt"

    # Write both protocols so httpx can probe which one is actually live
    ip_urls = [f"http://{target_ip}", f"https://{target_ip}"]

    # subdomains_dedup.txt — input to httpx probe
    write_lines(dedup_file,   ip_urls)

    # live_urls.txt — pre-populate so wafw00f and downstream have a fallback
    # if httpx is skipped or returns nothing. httpx will overwrite this.
    write_lines(live_file,    ip_urls)

    # DNS files — IP resolves to itself
    domain_ip_map = {target_ip: target_ip}
    write_lines(stripped_file,   [target_ip])
    write_lines(resolved_file,   [f"{target_ip} [{target_ip}]"])

    # unique_ips.txt — nmap always gets the target IP regardless of httpx outcome
    write_lines(unique_ips_file, [target_ip])
    write_lines(waf_ips_file,    [])

    ip_map_file.write_text(
        json.dumps(domain_ip_map, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    if verbose:
        print(f"[dnsx] IP input — wrote {ip_urls} for httpx/wafw00f pipeline")

    return {
        "domain_ip_map": domain_ip_map,
        "unique_ips":    [target_ip],
        "waf_ips":       [],
        "ip_map_file":   str(ip_map_file),
    }

# ---------------------------------------------------------------------------
# Empty output writer
# ---------------------------------------------------------------------------
def _write_empty_outputs(temp_dir: Path) -> dict:
    """Write empty stub files so downstream modules don't crash."""
    for fname in ["unique_ips.txt", "waf_ips.txt", "domains_stripped.txt"]:
        write_lines(temp_dir / fname, [])
    ip_map_file = temp_dir / "ip_map.json"
    ip_map_file.parent.mkdir(parents=True, exist_ok=True)
    ip_map_file.write_text("{}", encoding="utf-8")
    return {
        "domain_ip_map": {},
        "unique_ips":    [],
        "waf_ips":       [],
        "ip_map_file":   str(ip_map_file),
    }
  
# ---------------------------------------------------------------------------
# Loader helper — used by report.py
# ---------------------------------------------------------------------------
def load_ip_map(temp_dir: Path) -> dict[str, str]:
    """
    Load ip_map.json written by run_dnsx().
    Returns {domain: ip} dict. Returns {} on error.
    """
    ip_map_file = temp_dir / "ip_map.json"
    if not ip_map_file.exists():
        return {}
    try:
        return json.loads(
            ip_map_file.read_text(encoding="utf-8", errors="replace")
        )
    except Exception as exc:
        print(f"[dnsx] Warning: could not load ip_map.json: {exc}", file=sys.stderr)
        return {}
