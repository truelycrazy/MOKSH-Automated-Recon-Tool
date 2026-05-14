"""
modules/katana.py
=================
MOKSH — Phase 4B: Katana Web Crawler

Runs in parallel with nuclei.py (4A) and dnsx+nmap (4C).
Completely independent — a crash here does not affect nuclei or nmap.

Two profiles, both always run (R5 — stealth never skips):

  DEEP profile   → clean_domains.txt (no WAF detected)
  ─────────────────────────────────────────────────────
  Soft mode:
    katana -list temp/clean_domains.txt -depth 3 -rate-limit 15 -silent
           -o temp/katana_deep.txt
  Hard mode:
    katana -list temp/clean_domains.txt -depth 5 -rate-limit 25 -silent
           -o temp/katana_deep.txt

  Extra flags via --katana-extra (deep profile ONLY):
    Known flag already in cmd → overwrite its value
    New flag                  → inserted before -o (output boundary)
    Example: --katana-extra "-jc"          → adds JS crawling flag
    Example: --katana-extra "-depth 8"     → overwrites default depth
    Example: --katana-extra "-jc -depth 8 -xhr-extraction"
  No protected flags for katana deep — everything is overridable.

  STEALTH profile → waf_domains.txt (WAF detected)
  ─────────────────────────────────────────────────
    katana -list temp/waf_domains.txt -depth 2 -rate-limit 5 -delay 2
           -silent -o temp/katana_stealth.txt

Endpoint filter (data quality rule):
  After both crawls, ALL endpoints are pooled and filtered:
    grep -Ei "admin|api|login|upload|backup|config|token|secret|key|password"
  → temp/katana_filtered.txt
  Signal only — /static/logo.png is worthless, /admin/login is not.

Output files:
  temp/katana_deep.txt         — raw deep crawl output
  temp/katana_stealth.txt      — raw stealth crawl output
  temp/katana_filtered.txt     — filtered interesting endpoints (both profiles)
  temp/katana_results.json     — {domain: [endpoints]} for report.py

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
    dedup_lines,
    filter_katana_endpoints,
    extract_domain_from_url,
    apply_extra_flags,
)

# ---------------------------------------------------------------------------
# Internal: single profile runner
# Takes a fully-built command list — caller is responsible for assembly
# ---------------------------------------------------------------------------
def _run_profile(
    cmd:        list[str],
    label:      str,
    input_file: Path,
    out_file:   Path,
    verbose:    bool,
    timeout:    int,
) -> list[str]:
    """
    Run katana with the given fully-built command.

    Returns list of crawled endpoint URLs, or [] on any failure.
    Never raises — error isolation rule.
    Parameters
    ----------
    cmd        : list[str] — complete command including all flags
    label      : str       — "deep" or "stealth" for log messages
    input_file : Path      — targets file (used for guard check only)
    out_file   : Path      — where katana writes its -o output
    verbose    : bool
    timeout    : int       — subprocess hard ceiling in seconds
    """
    if not input_file.exists():
        if verbose:
            print(f"[katana/{label}] Input not found: {input_file} — skipping")
        return []

    targets = read_lines(input_file)
    if not targets:
        if verbose:
            print(f"[katana/{label}] No targets — skipping")
        return []

    if verbose:
        print(f"[katana/{label}] {len(targets)} target(s) | cmd: {' '.join(cmd)}")

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
        )
        if verbose and proc.stderr.strip():
            print(f"[katana/{label}] stderr: {proc.stderr.strip()}", file=sys.stderr)

    except subprocess.TimeoutExpired:
        print(f"[katana/{label}] WARNING: timed out after {timeout}s",
              file=sys.stderr)
        return []
    except FileNotFoundError:
        print(f"[katana/{label}] WARNING: katana binary not executable",
              file=sys.stderr)
        return []
    except Exception as exc:
        print(f"[katana/{label}] WARNING: {exc}", file=sys.stderr)
        return []

    if not out_file.exists():
        if verbose:
            print(f"[katana/{label}] No output file produced — zero endpoints")
        return []

    endpoints = read_lines(out_file)

    if verbose:
        print(f"[katana/{label}] {len(endpoints)} raw endpoint(s) crawled")

    return endpoints

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def run_katana(flags_dict: dict, temp_dir: Path) -> dict:
    """
    Execute Phase 4B — katana web crawling (deep + stealth).

    Reads  :
        temp/clean_domains.txt   — deep profile targets  (from wafw00f.py)
        temp/waf_domains.txt     — stealth profile targets (from wafw00f.py)

    Writes :
        temp/katana_deep.txt         — raw deep crawl output
        temp/katana_stealth.txt      — raw stealth crawl output
        temp/katana_filtered.txt     — filtered interesting endpoints
        temp/katana_results.json     — {domain: [endpoints]} for report.py

    Parameters
    ----------
    flags_dict : dict
    temp_dir   : Path

    Returns
    -------
    dict:
        endpoints_by_domain : dict[str, list[str]]
        all_filtered        : list[str]
        deep_raw_count      : int
        stealth_raw_count   : int
        filtered_count      : int
        results_file        : str
    """
    f       = flags_dict
    verbose = f.get("verbose", False)

    binary = shutil.which("katana")
    if binary is None:
        print("[katana] WARNING: katana not found in PATH — web crawl skipped.",
              file=sys.stderr)
        return _write_empty_outputs(temp_dir)

    clean_file   = temp_dir / "clean_domains.txt"
    waf_file     = temp_dir / "waf_domains.txt"
    deep_out     = temp_dir / "katana_deep.txt"
    stealth_out  = temp_dir / "katana_stealth.txt"
    filtered_out = temp_dir / "katana_filtered.txt"
    results_json = temp_dir / "katana_results.json"

    extra = f.get("katana_extra")   # --katana-extra passthrough (deep only)

    # ══════════════════════════════════════════════════════════════════════
    # DEEP PROFILE
    # ══════════════════════════════════════════════════════════════════════
    deep_base = [
        binary,
        "-list",       str(clean_file),
        "-depth",      str(f.get("katana_depth", 3)),
        "-rate-limit", str(f.get("katana_rl",    15)),
        "-silent",
        "-o",          str(deep_out),
    ]

    deep_cmd = apply_extra_flags(
        deep_base,
        extra,
        protected    = [],       
        output_flags = ["-o"],
    )

    if verbose and extra:
        print(f"[katana/deep] Extra flags: {extra}")

    deep_endpoints = _run_profile(
        cmd        = deep_cmd,
        label      = "deep",
        input_file = clean_file,
        out_file   = deep_out,
        verbose    = verbose,
        timeout    = 3600,
    )

    # ══════════════════════════════════════════════════════════════════════
    # STEALTH PROFILE
    # ══════════════════════════════════════════════════════════════════════
    stealth_cmd = [
        binary,
        "-list",       str(waf_file),
        "-depth",      str(f.get("katana_stealth_depth", 2)),   
       "-rate-limit", str(f.get("katana_stealth_rl",    5)),  
        "-delay",      str(f.get("katana_stealth_delay", 2)), 
        "-silent",
        "-o",          str(stealth_out),
    ]
   

    stealth_endpoints = _run_profile(
        cmd        = stealth_cmd,
        label      = "stealth",
        input_file = waf_file,
        out_file   = stealth_out,
        verbose    = verbose,
        timeout    = 3600,
    )

    # ══════════════════════════════════════════════════════════════════════
    # Pool → dedup → keyword filter
    # ══════════════════════════════════════════════════════════════════════
    all_raw      = dedup_lines(deep_endpoints + stealth_endpoints)
    all_filtered = filter_katana_endpoints(all_raw)
    all_filtered = dedup_lines(all_filtered)

    write_lines(filtered_out, all_filtered)

    if verbose:
        print(
            f"[katana] Raw: {len(deep_endpoints)} deep + "
            f"{len(stealth_endpoints)} stealth = {len(all_raw)} | "
            f"After filter: {len(all_filtered)}"
        )

    # ══════════════════════════════════════════════════════════════════════
    # Build endpoints_by_domain
    # Key  : bare domain e.g. "api.example.com"
    # Value: filtered endpoints under that domain
    # report.py does: endpoints_by_domain.get(bare_domain, [])
    # ══════════════════════════════════════════════════════════════════════
    endpoints_by_domain: dict[str, list[str]] = {}

    for endpoint in all_filtered:
        if not endpoint.startswith("http"):
            continue   # relative URL — cannot map to domain
        domain = extract_domain_from_url(endpoint)
        endpoints_by_domain.setdefault(domain, []).append(endpoint)

    # ══════════════════════════════════════════════════════════════════════
    # Write katana_results.json — report.py loads this, never raw text
    # ══════════════════════════════════════════════════════════════════════
    results_json.write_text(
        json.dumps(endpoints_by_domain, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    if verbose:
        print(
            f"[katana] {len(all_filtered)} filtered endpoints "
            f"across {len(endpoints_by_domain)} domain(s)"
        )

    return {
        "endpoints_by_domain": endpoints_by_domain,
        "all_filtered":        all_filtered,
        "deep_raw_count":      len(deep_endpoints),
        "stealth_raw_count":   len(stealth_endpoints),
        "filtered_count":      len(all_filtered),
        "results_file":        str(results_json),
    }

# ---------------------------------------------------------------------------
# Empty output writer
# ---------------------------------------------------------------------------
def _write_empty_outputs(temp_dir: Path) -> dict:
    """Write empty outputs so report.py never hits FileNotFoundError."""
    results_json = temp_dir / "katana_results.json"
    filtered_out = temp_dir / "katana_filtered.txt"
    results_json.parent.mkdir(parents=True, exist_ok=True)
    results_json.write_text("{}", encoding="utf-8")
    write_lines(filtered_out, [])
    return {
        "endpoints_by_domain": {},
        "all_filtered":        [],
        "deep_raw_count":      0,
        "stealth_raw_count":   0,
        "filtered_count":      0,
        "results_file":        str(results_json),
    }

# ---------------------------------------------------------------------------
# Loader helper — called by report.py only
# ---------------------------------------------------------------------------
def load_katana_results(temp_dir: Path) -> dict[str, list[str]]:
    """
    Load katana_results.json written by run_katana().
    Returns {domain: [endpoints]} dict.
    Returns {} on missing file or parse error.
    report.py uses this — never reads raw crawl files directly.
    """
    results_file = temp_dir / "katana_results.json"
    if not results_file.exists():
        return {}
    try:
        return json.loads(
            results_file.read_text(encoding="utf-8", errors="replace")
        )
    except Exception as exc:
        print(f"[katana] Warning: could not load katana_results.json: {exc}",
              file=sys.stderr)
        return {}
