"""
modules/nmap.py
===============
MOKSH — Phase 4C (Part 2): Nmap Port Scanner

Runs port scans after dnsx.py has resolved domains to IPs.
Runs in parallel with nuclei.py (4A) and katana.py (4B), but WITHIN
the dnsx_nmap thread it always runs after dnsx — nmap needs the IPs
that dnsx writes. The sequencing is: run_dnsx() → run_nmap() in the
same thread inside main.py's parallel task_dnsx_nmap().

Absolute rules enforced here:
  R1  — -Pn ALWAYS ON. Cannot be disabled. Ever.
         Hardcoded in both command builders AND in the protected list
         passed to apply_extra_flags — so --nmap-extra cannot remove it.
  --open ALWAYS ON.
         Only open ports. Filtered/closed = noise. Also protected.

Extra flags via --nmap-extra:
  Applied to BOTH deep and stealth profile commands.
  Rules (enforced by apply_extra_flags in parser.py):
    Known flag already in cmd → overwrite its value
    New flag                  → insert before -oN (output boundary)
    -Pn, --open               → protected, ignored if user tries to touch them

  Examples:
    --nmap-extra "-T4"               → adds timing template to both profiles
    --nmap-extra "-sS"               → adds SYN scan to both profiles
    --nmap-extra "--top-ports 500"   → overwrites default top-ports value
    --nmap-extra "-T4 -sS --top-ports 500" → all three at once

Two profiles (set by WAF gate in Phase 3):
  Deep    (clean domains, no WAF):
    Soft: nmap -iL unique_ips.txt  -Pn --open -sV -O --top-ports 1000 -oN nmap_deep.txt
    Hard: nmap -iL unique_ips.txt  -Pn --open -sV -O -p 0-65535       -oN nmap_deep.txt
    → Full service detection (-sV) + OS detection (-O)

  Stealth (WAF-protected domains):
    Soft: nmap -iL waf_ips.txt     -Pn --open        --top-ports 1000 -oN nmap_stealth.txt
    Hard: nmap -iL waf_ips.txt     -Pn --open        -p 0-65535       -oN nmap_stealth.txt
    → NO -sV, NO -O (version/OS probing triggers WAF blocks)
    → R5: stealth never skips — port list only beats no data

Blank retry:
  If a single IP returns zero open ports → retry with -Pn -p 80,443,8080,8443
  Retry is internal — --nmap-extra does NOT apply here.

Output files:
  temp/nmap_deep.txt         — deep scan results
  temp/nmap_stealth.txt      — stealth scan results
  temp/nmap_results.json     — parsed {ip: [ports]} for report.py

NON-CRITICAL: exceptions caught by main.py parallel runner.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

import utils.flags as flags
from utils.parser import (
    read_lines,
    write_lines,
    parse_nmap_output,
    apply_extra_flags,
)

# ---------------------------------------------------------------------------
# Protected flags — hardcoded AND enforced via apply_extra_flags protected list
# R1: -Pn absolute rule — cannot be removed by user under any circumstance
# --open: data quality rule — same protection level
# ---------------------------------------------------------------------------
_NMAP_PROTECTED = ["-Pn", "--open"]


# ---------------------------------------------------------------------------
# Command builders
# ---------------------------------------------------------------------------

def _build_deep_cmd(
    binary:       str,
    ip_list_file: Path,
    out_file:     Path,
    ports_flag:   str,
    extra:        Optional[str],
) -> list[str]:
    """
    Deep profile: -sV -O always included.
    -Pn --open hardcoded AND protected.
    apply_extra_flags layered on top — new flags inserted before -oN.
    """
    base = [
        binary,
        "-iL",   str(ip_list_file),
        "-Pn",                       # R1: hardcoded — not a variable
        "--open",                    # open ports only — always
        "-sV",                       # service + version detection
        "-O",                        # OS detection
    ]
    base += ports_flag.split()
    base += ["-oN", str(out_file)]

    return apply_extra_flags(
        base,
        extra,
        protected    = _NMAP_PROTECTED,
        output_flags = ["-oN", "-o"],
    )


def _build_stealth_cmd(
    binary:       str,
    ip_list_file: Path,
    out_file:     Path,
    ports_flag:   str,
    extra:        Optional[str],
) -> list[str]:
    """
    Stealth profile: NO -sV, NO -O.
    -Pn --open hardcoded AND protected.
    apply_extra_flags layered on top — same rules as deep.
    """
    base = [
        binary,
        "-iL",   str(ip_list_file),
        "-Pn",                       # R1: hardcoded — not a variable
        "--open",                    # open ports only — always
        # deliberately NO -sV, NO -O for stealth
    ]
    base += ports_flag.split()
    base += ["-oN", str(out_file)]

    return apply_extra_flags(
        base,
        extra,
        protected    = _NMAP_PROTECTED,
        output_flags = ["-oN", "-o"],
    )


def _build_retry_cmd(binary: str, ip: str) -> list[str]:
    """
    Internal blank retry — --nmap-extra does NOT apply.
    Probes common web ports when full scan returns nothing.
    -Pn hardcoded (R1).
    """
    return [
        binary,
        "-Pn",                       # R1
        "--open",
        "-p", "80,443,8080,8443",
        ip,
    ]


# ---------------------------------------------------------------------------
# Subprocess runner
# ---------------------------------------------------------------------------

def _run_nmap(
    cmd:     list[str],
    label:   str,
    verbose: bool,
    timeout: int = 7200,
) -> str:
    """
    Execute nmap. Returns stdout text.
    nmap -oN writes to file — read from file after.
    Never raises — logs warning on failure.
    """
    if verbose:
        print(f"[nmap/{label}] Command: {' '.join(cmd)}")

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
        )
        if verbose and proc.stderr.strip():
            print(f"[nmap/{label}] stderr: {proc.stderr.strip()}", file=sys.stderr)
        return proc.stdout
    except subprocess.TimeoutExpired:
        print(f"[nmap/{label}] WARNING: timed out after {timeout}s.", file=sys.stderr)
        return ""
    except FileNotFoundError:
        print(f"[nmap/{label}] WARNING: binary not found.", file=sys.stderr)
        return ""
    except Exception as exc:
        print(f"[nmap/{label}] WARNING: {exc}", file=sys.stderr)
        return ""


# ---------------------------------------------------------------------------
# Blank retry
# ---------------------------------------------------------------------------

def _blank_retry(binary: str, ip: str, verbose: bool) -> list[str]:
    """
    Single IP returned zero open ports — retry on common web ports.
    Returns port strings or [].
    """
    if verbose:
        print(f"[nmap/retry] {ip} — retrying on 80,443,8080,8443")

    try:
        proc = subprocess.run(
            _build_retry_cmd(binary, ip),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            text=True,
        )
        for rec in parse_nmap_output(proc.stdout):
            if rec["ip"] == ip and rec["ports"]:
                if verbose:
                    print(f"[nmap/retry] {ip} → {rec['ports']}")
                return rec["ports"]
    except Exception as exc:
        if verbose:
            print(f"[nmap/retry] WARNING: {ip}: {exc}", file=sys.stderr)
    return []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_nmap(flags_dict: dict, temp_dir: Path) -> dict:
    """
    Execute Phase 4C part 2 — nmap port scanning (deep + stealth).

    Reads  :
        temp/unique_ips.txt   — clean IPs  (written by dnsx.py)
        temp/waf_ips.txt      — WAF IPs    (written by dnsx.py)

    Writes :
        temp/nmap_deep.txt        — raw deep scan output
        temp/nmap_stealth.txt     — raw stealth scan output
        temp/nmap_results.json    — {ip: [ports]} for report.py

    Returns
    -------
    dict:
        ports_by_ip  : dict[str, list[str]]
        deep_ips     : list[str]
        stealth_ips  : list[str]
        results_file : str
    """
    f       = flags_dict
    verbose = f.get("verbose", False)

    binary = shutil.which("nmap")
    if binary is None:
        print("[nmap] WARNING: nmap not found in PATH — skipping.",
              file=sys.stderr)
        return _write_empty_outputs(temp_dir)

    ports_flag = f.get("nmap_ports_flag", "--top-ports 1000")
    extra      = f.get("nmap_extra")

    unique_ips_file = temp_dir / "unique_ips.txt"
    waf_ips_file    = temp_dir / "waf_ips.txt"
    deep_out        = temp_dir / "nmap_deep.txt"
    stealth_out     = temp_dir / "nmap_stealth.txt"
    results_json    = temp_dir / "nmap_results.json"

    ports_by_ip: dict[str, list[str]] = {}

    unique_ips = read_lines(unique_ips_file)
    waf_ips    = read_lines(waf_ips_file)

    # For IP input: target IP is always in unique_ips.txt written by dnsx.py.
    # If somehow both lists are empty, recover the target IP from flags
    # so nmap never skips the explicit scan target under any circumstance.
    if not unique_ips and not waf_ips:
        input_type = f.get("input_type", "domain")
        target_ip  = f.get("target", "")
        if input_type == "ip" and target_ip:
            if verbose:
                print(f"[nmap] Recovering target IP from flags: {target_ip}")
            unique_ips = [target_ip]
            write_lines(unique_ips_file, unique_ips)
        else:
            if verbose:
                print("[nmap] No IPs to scan — skipping.")
            return _write_empty_outputs(temp_dir)

    waf_ip_set = set(waf_ips)
    clean_ips  = [ip for ip in unique_ips if ip not in waf_ip_set]

    # Safety net: if the target IP ended up in waf_ips only (stealth profile),
    # clean_ips will be empty but waf_ips has it — that is correct and handled
    # below. But if BOTH are empty after subtraction (shouldn't happen), recover.
    if not clean_ips and not waf_ips:
        input_type = f.get("input_type", "domain")
        target_ip  = f.get("target", "")
        if input_type == "ip" and target_ip:
            clean_ips = [target_ip]

    if verbose:
        print(f"[nmap] Deep scan targets   : {len(clean_ips)} IP(s)")
        print(f"[nmap] Stealth scan targets : {len(waf_ips)} IP(s)")
        print(f"[nmap] Port flag            : {ports_flag}")
        if extra:
            print(f"[nmap] Extra flags          : {extra}")
            print(f"[nmap] Protected (locked)   : {_NMAP_PROTECTED}")

    # ══════════════════════════════════════════════════════════════════════
    # DEEP SCAN — clean IPs
    # ══════════════════════════════════════════════════════════════════════
    if clean_ips:
        clean_ips_file = temp_dir / "clean_ips.txt"
        write_lines(clean_ips_file, clean_ips)

        cmd = _build_deep_cmd(binary, clean_ips_file, deep_out, ports_flag, extra)
        _run_nmap(cmd, "deep", verbose, timeout=7200)

        deep_raw = deep_out.read_text(encoding="utf-8", errors="replace") \
                   if deep_out.exists() else ""

        for rec in parse_nmap_output(deep_raw):
            ports_by_ip[rec["ip"]] = rec["ports"]
            if verbose:
                print(f"[nmap/deep] {rec['ip']} → {len(rec['ports'])} port(s)")

        # Blank retry for any clean IP that got zero results
        for ip in clean_ips:
            if ip not in ports_by_ip or not ports_by_ip[ip]:
                ports_by_ip[ip] = _blank_retry(binary, ip, verbose) or []

    # ══════════════════════════════════════════════════════════════════════
    # STEALTH SCAN — WAF IPs
    # R5: never skip — port list without version still has value
    # ══════════════════════════════════════════════════════════════════════
    if waf_ips:
        cmd = _build_stealth_cmd(binary, waf_ips_file, stealth_out, ports_flag, extra)
        _run_nmap(cmd, "stealth", verbose, timeout=7200)

        stealth_raw = stealth_out.read_text(encoding="utf-8", errors="replace") \
                      if stealth_out.exists() else ""

        for rec in parse_nmap_output(stealth_raw):
            if rec["ip"] not in ports_by_ip:
                ports_by_ip[rec["ip"]] = rec["ports"]
            if verbose:
                print(f"[nmap/stealth] {rec['ip']} → {len(rec['ports'])} port(s)")

        # Blank retry for WAF IPs that returned nothing
        for ip in waf_ips:
            if ip not in ports_by_ip or not ports_by_ip[ip]:
                ports_by_ip[ip] = _blank_retry(binary, ip, verbose) or []

    # ── Write nmap_results.json ───────────────────────────────────────────
    results_json.write_text(
        json.dumps(ports_by_ip, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    if verbose:
        total = sum(len(v) for v in ports_by_ip.values())
        print(f"[nmap] Done — {len(ports_by_ip)} IPs · {total} open ports")

    return {
        "ports_by_ip":  ports_by_ip,
        "deep_ips":     clean_ips,
        "stealth_ips":  waf_ips,
        "results_file": str(results_json),
    }


# ---------------------------------------------------------------------------
# Empty output writer
# ---------------------------------------------------------------------------

def _write_empty_outputs(temp_dir: Path) -> dict:
    """Write empty nmap_results.json so report.py never hits FileNotFoundError."""
    results_json = temp_dir / "nmap_results.json"
    results_json.parent.mkdir(parents=True, exist_ok=True)
    results_json.write_text("{}", encoding="utf-8")
    return {
        "ports_by_ip":  {},
        "deep_ips":     [],
        "stealth_ips":  [],
        "results_file": str(results_json),
    }


# ---------------------------------------------------------------------------
# Loader helper — used by report.py
# ---------------------------------------------------------------------------

def load_nmap_results(temp_dir: Path) -> dict[str, list[str]]:
    """
    Load nmap_results.json written by run_nmap().
    Returns {ip: [ports]} dict. Returns {} on error.
    report.py calls this — never re-parses raw nmap text.
    """
    results_file = temp_dir / "nmap_results.json"
    if not results_file.exists():
        return {}
    try:
        return json.loads(
            results_file.read_text(encoding="utf-8", errors="replace")
        )
    except Exception as exc:
        print(f"[nmap] Warning: could not load nmap_results.json: {exc}",
              file=sys.stderr)
        return {}
