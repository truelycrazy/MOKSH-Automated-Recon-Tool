"""
modules/nuclei.py
=================
MOKSH — Phase 4A: Nuclei Vulnerability Scanner

Runs in parallel with katana.py (4B) and dnsx+nmap (4C).
Each runs independently — a crash here does not touch katana or nmap.

Two profiles, both always run (R5 — stealth never skips):

  DEEP profile   → clean_domains.txt (no WAF detected)
  ─────────────────────────────────────────────────────
  nuclei -l temp/clean_domains.txt
         -s critical,high,medium   ← default severity (overridable)
         -rl 20                    ← rate limit (overridable)
         --timeout 7               ← 7s per request — fast, not 30s
         -retries 2                ← retry failed requests before giving up
         -mhe 5                    ← skip host after 5 consecutive errors
         -o temp/nuclei_deep.txt

  Why these defaults:
    --timeout 7  — 30s default makes nuclei hang for hours on large lists.
                   7s is enough for real responses, kills stuck templates fast.
    -retries 2   — transient failures get retried instead of false-negatives.
    -mhe 5       — stops hammering hosts that are clearly blocking us.
    -rl 20       — slightly higher than old default of 15, still safe.

  Extra flags via --nuclei-extra (deep profile only):
    Known flag already in cmd  → value overwritten
    New flag                   → inserted before -o
    Example: --nuclei-extra "-tags cve,exposure"
    Example: --nuclei-extra "--timeout 15 -rl 10"

  STEALTH profile → waf_domains.txt (WAF detected)
  ─────────────────────────────────────────────────
  nuclei -l temp/waf_domains.txt
         -tags info,tech-detect   ← safe fingerprint templates only
         -rl 5                    ← slow — WAF rate limits are strict
         --timeout 10             ← more lenient, WAFs add latency
         -retries 1               ← one retry only — don't hammer
         -mhe 3                   ← give up on blocked hosts sooner
         -o temp/nuclei_stealth.txt

  Stealth is no longer completely locked.
  --nuclei-stealth-extra allows tuning (rate, timeout, etc.)
  Tags (info,tech-detect) remain the default but are also overridable.
  Rationale: WAF tolerates fingerprint requests. Exploit templates = blocked.
             But users may legitimately want to adjust rate/timeout for their
             specific WAF target without throwing the tool away entirely.

IP input flow:
  main.py writes constructed URLs (http://IP, https://IP) into clean_domains.txt.
  This module reads it as normal. waf_domains.txt empty for IP input.

Output files:
  temp/nuclei_deep.txt        — raw nuclei output (deep scan)
  temp/nuclei_stealth.txt     — raw nuclei output (stealth scan)
  temp/nuclei_results.json    — {url: [findings]} for report.py

NON-CRITICAL: each profile run is independently try/excepted.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import utils.flags as flags
from utils.parser import (
    read_lines,
    parse_nuclei_output,
    apply_extra_flags,
)


# ---------------------------------------------------------------------------
# Internal: single profile runner
# ---------------------------------------------------------------------------

def _run_profile(
    binary:     str,
    label:      str,
    input_file: Path,
    out_file:   Path,
    cmd_args:   list[str],
    verbose:    bool,
    timeout:    int,
) -> list[dict]:
    """
    Run nuclei for one profile (deep or stealth).
    Returns list of parsed finding dicts, or [] on any failure.
    Never raises — error isolation rule.
    """
    if not input_file.exists():
        if verbose:
            print(f"[nuclei/{label}] Input not found: {input_file} — skipping")
        return []

    targets = read_lines(input_file)
    if not targets:
        if verbose:
            print(f"[nuclei/{label}] No targets — skipping")
        return []

    if verbose:
        print(f"[nuclei/{label}] {len(targets)} target(s) | cmd: {' '.join(cmd_args)}")

    try:
        proc = subprocess.run(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
        )
        if verbose and proc.stderr.strip():
            print(f"[nuclei/{label}] stderr: {proc.stderr.strip()}", file=sys.stderr)

    except subprocess.TimeoutExpired:
        print(f"[nuclei/{label}] WARNING: timed out after {timeout}s", file=sys.stderr)
        return []
    except FileNotFoundError:
        print(f"[nuclei/{label}] WARNING: nuclei binary not executable", file=sys.stderr)
        return []
    except Exception as exc:
        print(f"[nuclei/{label}] WARNING: {exc}", file=sys.stderr)
        return []

    if not out_file.exists():
        if verbose:
            print(f"[nuclei/{label}] No output file produced — zero findings")
        return []

    raw      = out_file.read_text(encoding="utf-8", errors="replace")
    findings = parse_nuclei_output(raw)

    if verbose:
        print(f"[nuclei/{label}] {len(findings)} finding(s)")

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_nuclei(flags_dict: dict, temp_dir: Path) -> dict:
    """
    Execute Phase 4A — nuclei vulnerability scanning (deep + stealth).

    Reads  :
        temp/clean_domains.txt   — deep profile targets  (from wafw00f.py)
        temp/waf_domains.txt     — stealth profile targets (from wafw00f.py)

    Writes :
        temp/nuclei_deep.txt         — raw deep scan output
        temp/nuclei_stealth.txt      — raw stealth scan output
        temp/nuclei_results.json     — {url: [findings]} for report.py

    Returns
    -------
    dict:
        findings_by_target : dict[str, list[dict]]
        all_findings       : list[dict]
        deep_count         : int
        stealth_count      : int
        results_file       : str
    """
    f       = flags_dict
    verbose = f.get("verbose", False)

    binary = shutil.which("nuclei")
    if binary is None:
        print("[nuclei] WARNING: nuclei not found in PATH — skipping.", file=sys.stderr)
        return _write_empty_outputs(temp_dir)

    clean_file   = temp_dir / "clean_domains.txt"
    waf_file     = temp_dir / "waf_domains.txt"
    deep_out     = temp_dir / "nuclei_deep.txt"
    stealth_out  = temp_dir / "nuclei_stealth.txt"
    results_json = temp_dir / "nuclei_results.json"

    # ══════════════════════════════════════════════════════════════════════
    # DEEP PROFILE
    # Smarter defaults: fast timeout, retries, host-error limit
    # All flags are overridable via --nuclei-extra
    # ══════════════════════════════════════════════════════════════════════
    severity = f.get("nuclei_severity", "critical,high,medium")

    deep_base_cmd = [
        binary,
        "-l",            str(clean_file),
        "-s",            severity,                            # severity filter
        "-rl",           str(f.get("nuclei_rl", 20)),         # rate limit
        "-c",            str(f.get("nuclei_c", 30)),          # concurrency ready workers to go as soon as 20 comes, 20 gone 10 ready always
        "--timeout",     str(f.get("nuclei_timeout", 7)),     # 7s per request
        "-retries",      str(f.get("nuclei_retries", 1)),     # retry on failure
        "-mhe",          str(f.get("nuclei_mhe", 40)),        # max host errors
        "-bs",           str(f.get("nuclei_bs", 25)),         # bulk size 
        "-o",            str(deep_out),
    ]

    # Apply --nuclei-extra passthrough
    # Known flags overwritten, new flags inserted before -o
    # Nothing is protected for deep profile — everything is overridable
    deep_cmd = apply_extra_flags(
        deep_base_cmd,
        f.get("nuclei_extra"),
        protected    = [],
        output_flags = ["-o"],
    )

    deep_findings = _run_profile(
        binary     = binary,
        label      = "deep",
        input_file = clean_file,
        out_file   = deep_out,
        cmd_args   = deep_cmd,
        verbose    = verbose,
        timeout    = 3600,
    )

    # ══════════════════════════════════════════════════════════════════════
    # STEALTH PROFILE
    # Smarter defaults for WAF domains: slow rate, low mhe.
    # --nuclei-stealth-extra now allows tuning — profile is no longer frozen.
    # Tags default to info,tech-detect (safe) but are also overridable.
    # R5: stealth never skips — fingerprinting still gives stack info.
    # ══════════════════════════════════════════════════════════════════════
    stealth_base_cmd = [
        binary,
        "-l",            str(waf_file),
        "-tags",         str(f.get("nuclei_stealth_templates", "info,tech-detect")),
        "-rl",           str(f.get("nuclei_stealth_rl", 5)),          # slow
        "-c",            str(f.get("nuclei_stealth_c", 10)),          # because header response is long so we keep cycle going
        "-bs",           str(f.get("nuclei_stealth_bs", 5)),          # low because modern waf also check concurrent connection
        "--timeout",     str(f.get("nuclei_stealth_timeout", 10)),    # WAFs add latency
        "-retries",      str(f.get("nuclei_stealth_retries", 1)),     # one retry only
        "-mhe",          str(f.get("nuclei_stealth_mhe", 10)),        # give up sooner as waf might be configured to drop suspicious outgoing packets 
        "-o",            str(stealth_out),
    ]

    # Apply --nuclei-stealth-extra passthrough
    # Stealth is no longer completely frozen — users can tune rate/timeout
    # Tags remain the default but can be overridden if user knows what they're doing
    stealth_cmd = apply_extra_flags(
        stealth_base_cmd,
        f.get("nuclei_stealth_extra"),
        protected    = [],
        output_flags = ["-o"],
    )

    stealth_findings = _run_profile(
        binary     = binary,
        label      = "stealth",
        input_file = waf_file,
        out_file   = stealth_out,
        cmd_args   = stealth_cmd,
        verbose    = verbose,
        timeout    = 3600,
    )

    # ══════════════════════════════════════════════════════════════════════
    # Build findings_by_target for report.py
    # ══════════════════════════════════════════════════════════════════════
    findings_by_target: dict[str, list[dict]] = {}
    all_findings:       list[dict]             = []

    for finding in deep_findings + stealth_findings:
        target = finding.get("target", "unknown")
        clean  = {
            "severity": finding.get("severity", "info"),
            "id":       finding.get("id",       "unknown"),
            "template": finding.get("template", "unknown"),
        }
        findings_by_target.setdefault(target, []).append(clean)
        all_findings.append({**clean, "target": target})

    # ══════════════════════════════════════════════════════════════════════
    # Write nuclei_results.json
    # ══════════════════════════════════════════════════════════════════════
    results_json.write_text(
        json.dumps(findings_by_target, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    if verbose:
        print(
            f"[nuclei] Done — "
            f"{len(deep_findings)} deep + {len(stealth_findings)} stealth "
            f"= {len(all_findings)} total finding(s) across "
            f"{len(findings_by_target)} target(s)"
        )

    return {
        "findings_by_target": findings_by_target,
        "all_findings":       all_findings,
        "deep_count":         len(deep_findings),
        "stealth_count":      len(stealth_findings),
        "results_file":       str(results_json),
    }


# ---------------------------------------------------------------------------
# Empty output writer
# ---------------------------------------------------------------------------

def _write_empty_outputs(temp_dir: Path) -> dict:
    """Write empty nuclei_results.json so report.py never hits FileNotFoundError."""
    results_json = temp_dir / "nuclei_results.json"
    results_json.parent.mkdir(parents=True, exist_ok=True)
    results_json.write_text("{}", encoding="utf-8")
    return {
        "findings_by_target": {},
        "all_findings":       [],
        "deep_count":         0,
        "stealth_count":      0,
        "results_file":       str(results_json),
    }


# ---------------------------------------------------------------------------
# Loader helper — called by report.py only
# ---------------------------------------------------------------------------

def load_nuclei_results(temp_dir: Path) -> dict[str, list[dict]]:
    """
    Load nuclei_results.json written by run_nuclei().
    Returns {target_url: [findings]} dict.
    Returns {} on missing file or parse error.
    """
    results_file = temp_dir / "nuclei_results.json"
    if not results_file.exists():
        return {}
    try:
        return json.loads(
            results_file.read_text(encoding="utf-8", errors="replace")
        )
    except Exception as exc:
        print(f"[nuclei] Warning: could not load nuclei_results.json: {exc}",
              file=sys.stderr)
        return {}
