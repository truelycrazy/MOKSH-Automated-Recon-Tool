"""
modules/subfinder.py
====================
MOKSH — Phase 1: Surface Discovery

Runs subdomain enumeration via subfinder.

Rules enforced here:
  R2 — Root domain ALWAYS appended after subfinder output.
        Subfinder may miss the apex domain — add it manually, every time.
  R3 — For URL input: original URL re-added after subfinder + root append.
        The specific path/endpoint must not be lost.
  R7 — Deduplicate the full list before writing to file.
        Never probe duplicates — wastes time and may trigger rate limits.

Exact commands (from phase reference spec):
  Soft: subfinder -d <target> -timeout 10 -rl 10 -silent -o subdomains_raw.txt
  Hard: subfinder -d <target> -timeout 20 -rl 10 -recursive -silent -o subdomains_raw.txt

Extra flags via --subfinder-extra:
  Known flag already in cmd  → value overwritten
  New flag                   → inserted before -o
  Example: --subfinder-extra "-all -recursive"
           -all is new     → added before -o
           -recursive is new → added before -o

  After run: append root domain → append original URL (if URL input) → dedup
  Output: temp/subdomains_dedup.txt

CRITICAL module — raises RuntimeError on failure.
main.py exits the pipeline if this raises (nothing to scan without subdomains).
SKIPPED for IP input — main.py checks input_type before calling this.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import utils.flags as flags
from utils.parser import (
    read_lines,
    write_lines,
    dedup_lines,
    apply_extra_flags,
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_base_command(
    binary:    str,
    target:    str,
    timeout:   int,
    rl:        int,
    recursive: bool,
    out_file:  Path,
) -> list[str]:
    """
    Build the base subfinder command per the phase reference spec.

    Soft:  subfinder -d <target> -timeout 10 -rl 10 -silent -o <file>
    Hard:  subfinder -d <target> -timeout 20 -rl 10 -recursive -silent -o <file>

    apply_extra_flags() is called on the result of this function —
    any --subfinder-extra flags are merged in after.
    """
    cmd = [
        binary,
        "-d",       target,
        "-timeout", str(timeout),
        "-rl",      str(rl),
        "-silent",
        "-o",       str(out_file),
    ]
    if recursive:
        cmd.append("-recursive")
    return cmd


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_subfinder(flags_dict: dict, temp_dir: Path) -> dict:
    """
    Execute Phase 1 — subfinder subdomain enumeration.

    Parameters
    ----------
    flags_dict : dict  — resolved config from flags.load_flags()
    temp_dir   : Path  — path to the temp/ directory

    Returns
    -------
    dict:
        count    : int        — unique subdomains after R2 + R3 + dedup
        outfile  : str        — absolute path to temp/subdomains_dedup.txt
        domains  : list[str]  — the deduped list

    Raises
    ------
    RuntimeError
        On any subprocess failure, timeout, or missing binary.
        main.py catches this and exits with code 1.
    """
    f = flags_dict

    binary = shutil.which("subfinder")
    if binary is None:
        raise RuntimeError(
            "subfinder not found in PATH. "
            "Pre-flight should have caught this — check MOKSH installation."
        )

    target    = f["target"]
    timeout   = f.get("subfinder_timeout",   10)
    rl        = f.get("subfinder_rl",        10)
    recursive = f.get("subfinder_recursive", False)
    verbose   = f.get("verbose",             False)

    raw_out   = temp_dir / "subdomains_raw.txt"
    dedup_out = temp_dir / "subdomains_dedup.txt"

    # ── Build base command ────────────────────────────────────────────────
    base_cmd = _build_base_command(binary, target, timeout, rl, recursive, raw_out)

    # ── Apply --subfinder-extra passthrough ───────────────────────────────
    # Known flags (e.g. -timeout, -rl) get overwritten if user supplies them.
    # New flags (e.g. -all, -nW) are inserted before -o so subfinder sees them.
    # No protected flags for subfinder — everything is overridable.
    cmd = apply_extra_flags(
        base_cmd,
        f.get("subfinder_extra"),
        protected    = [],
        output_flags = ["-o"],
    )

    if verbose:
        print(f"[subfinder] Command: {' '.join(cmd)}")

    # ── Run subfinder ─────────────────────────────────────────────────────
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=600,
            text=True,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("subfinder timed out after 600 seconds.")
    except FileNotFoundError:
        raise RuntimeError(f"subfinder binary not executable: {binary}")
    except Exception as exc:
        raise RuntimeError(f"subfinder execution failed: {exc}")

    if verbose and proc.stderr.strip():
        print(f"[subfinder] stderr: {proc.stderr.strip()}", file=sys.stderr)

    # ── Read raw output ───────────────────────────────────────────────────
    raw_domains: list[str] = read_lines(raw_out)

    if verbose:
        print(f"[subfinder] Raw results: {len(raw_domains)} subdomains found")

    # ── R2: ALWAYS append root domain ────────────────────────────────────
    raw_domains.append(target)

    # ── R3: URL input — re-add original URL ──────────────────────────────
    original_url = f.get("original_url")
    if original_url:
        raw_domains.append(original_url)

    # ── R7: Deduplicate before writing ───────────────────────────────────
    cleaned = [d.strip() for d in raw_domains if d.strip()]
    deduped = dedup_lines(cleaned)

    write_lines(dedup_out, deduped)

    if verbose:
        print(f"[subfinder] After R2+R3+dedup: {len(deduped)} unique entries")
        print(f"[subfinder] Output: {dedup_out}")

    return {
        "count":   len(deduped),
        "outfile": str(dedup_out),
        "domains": deduped,
    }
