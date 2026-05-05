"""
modules/httpx_probe.py
======================
MOKSH — Phase 2: httpx Probe (Live / Dead Split)

Probes every subdomain from Phase 1 to determine which are live.

Rules enforced here:
  R4 — 403 = LIVE. A 403 response means something answered. WAF returns 403.
        Never classify a 403 as dead — it will be missed entirely otherwise.
  R7 — Input is already deduped (from subfinder) — no re-dedup needed here.

Exact base command (from phase reference spec):
  httpx -l temp/subdomains_dedup.txt -silent -status-code -title
        -threads 50 -o temp/httpx_raw.txt

Extra flags via --httpx-extra:
  Known flag already in cmd  → value overwritten
  New flag                   → inserted before -o
  Example: --httpx-extra "-follow-redirects -timeout 10"
           -follow-redirects is new → added before -o
           -timeout 10 is new       → added before -o
  Example: --httpx-extra "-threads 100"
           -threads already in cmd  → 50 overwritten with 100
  No protected flags for httpx — everything is overridable.

Output files:
  temp/httpx_raw.txt    — raw httpx output (url + status + title lines)
  temp/live_urls.txt    — URLs that responded (any status code, including 403)
  temp/dead_domains.txt — input domains that produced NO httpx output

Return value includes per-URL metadata dict (status + title) so
wafw00f and report.py can use it without re-parsing httpx_raw.txt.

CRITICAL module — raises RuntimeError on failure.
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
    parse_httpx_line,
    extract_domain_from_url,
    apply_extra_flags,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_httpx_probe(flags_dict: dict, temp_dir: Path) -> dict:
    """
    Execute Phase 2 — httpx live/dead probe.

    Parameters
    ----------
    flags_dict : dict  — resolved config from flags.load_flags()
    temp_dir   : Path  — path to the temp/ directory

    Returns
    -------
    dict:
        live_count   : int
        dead_count   : int
        live_urls    : list[str]         — ordered list of live URLs
        dead_domains : list[str]         — domains with no response
        url_meta     : dict[str, dict]   — {url: {"status": int, "title": str}}
        outfile_live : str
        outfile_dead : str

    Raises
    ------
    RuntimeError
        On binary missing, subprocess failure, or missing input file.
    """
    f = flags_dict

    binary = shutil.which("httpx")
    if binary is None:
        raise RuntimeError(
            "httpx not found in PATH. "
            "Pre-flight should have caught this — check MOKSH installation."
        )

    verbose    = f.get("verbose",       False)
    threads    = f.get("httpx_threads", 50)
    input_file = temp_dir / "subdomains_dedup.txt"
    raw_out    = temp_dir / "httpx_raw.txt"
    live_out   = temp_dir / "live_urls.txt"
    dead_out   = temp_dir / "dead_domains.txt"

    # Input file must exist — subfinder should have written it
    if not input_file.exists():
        raise RuntimeError(
            f"httpx input file not found: {input_file}\n"
            "subfinder must run before httpx_probe."
        )

    input_domains = read_lines(input_file)
    if not input_domains:
        raise RuntimeError(
            f"httpx input file is empty: {input_file}\n"
            "No subdomains to probe."
        )

    # ── Build base command per phase reference spec ────────────────────────
    base_cmd = [
        binary,
        "-l",       str(input_file),
        "-silent",
        "-status-code",
        "-title",
        "-threads", str(threads),
        "-o",       str(raw_out),
    ]

    # ── Apply --httpx-extra passthrough ───────────────────────────────────
    # Known flags (e.g. -threads) get overwritten if user supplies them.
    # New flags (e.g. -follow-redirects, -timeout) inserted before -o.
    # No protected flags for httpx — nothing is safety-critical here.
    cmd = apply_extra_flags(
        base_cmd,
        f.get("httpx_extra"),
        protected    = [],
        output_flags = ["-o"],
    )

    if verbose:
        print(f"[httpx] Command: {' '.join(cmd)}")
        print(f"[httpx] Probing {len(input_domains)} domain(s)...")

    # ── Run httpx ─────────────────────────────────────────────────────────
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=900,          # 15-minute ceiling
            text=True,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("httpx timed out after 900 seconds.")
    except FileNotFoundError:
        raise RuntimeError(f"httpx binary not executable: {binary}")
    except Exception as exc:
        raise RuntimeError(f"httpx execution failed: {exc}")

    if verbose and proc.stderr.strip():
        print(f"[httpx] stderr: {proc.stderr.strip()}", file=sys.stderr)

    # ── Parse httpx output ────────────────────────────────────────────────
    raw_lines = read_lines(raw_out)
    url_meta:  dict[str, dict] = {}
    live_urls: list[str]       = []

    for line in raw_lines:
        parsed = parse_httpx_line(line)
        if parsed is None:
            continue

        url    = parsed["url"]
        status = parsed["status"]
        title  = parsed["title"]

        # R4: ANY response (including 403) = LIVE
        # If httpx reported it, something answered — it is live.
        live_urls.append(url)
        url_meta[url] = {"status": status, "title": title}

    # Deduplicate live_urls (httpx should not produce dupes, but be safe)
    live_urls = dedup_lines(live_urls)

    # ── Compute dead domains ──────────────────────────────────────────────
    # Domains that produced NO line in httpx output are dead.
    # Compare bare domain/host — strip protocol and path before matching.
    live_bare: set[str] = set()
    for url in live_urls:
        live_bare.add(extract_domain_from_url(url))

    dead_domains: list[str] = []
    for entry in input_domains:
        # Input entries can be bare domains OR full URLs (R3 original URL)
        bare = extract_domain_from_url(entry) \
               if entry.startswith("http") else entry.lower()
        if bare not in live_bare:
            dead_domains.append(entry)

    dead_domains = dedup_lines(dead_domains)

    # ── Write output files ────────────────────────────────────────────────
    write_lines(live_out, live_urls)
    write_lines(dead_out, dead_domains)

    if verbose:
        print(f"[httpx] Live: {len(live_urls)}  Dead: {len(dead_domains)}")

    return {
        "live_count":   len(live_urls),
        "dead_count":   len(dead_domains),
        "live_urls":    live_urls,
        "dead_domains": dead_domains,
        "url_meta":     url_meta,
        "outfile_live": str(live_out),
        "outfile_dead": str(dead_out),
    }
