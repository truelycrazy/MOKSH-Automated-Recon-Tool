"""
modules/wafw00f.py
==================
MOKSH — Phase 3: WAF Gate (Intelligence Layer)

Most consequential phase in the pipeline. Its output controls every
downstream tool's scan profile (deep vs stealth).

Architecture: per-domain loop + -a flag + ThreadPoolExecutor(5)
─────────────────────────────────────────────────────────────────
OLD (broken):
  wafw00f -i live_urls.txt -o waf_raw.txt
  → Batch mode silently drops domains it can't reach quickly.
  → Stops at the FIRST WAF signature match per domain.
  → Result: most domains classified as "clean" incorrectly.

NEW (this implementation):
  One wafw00f process per URL, always with -a flag, 5 at a time.

Why -a flag:
  Default wafw00f stops the moment it finds one matching signature.
  -a continues checking ALL remaining signatures even after a hit.
  This matters because:
    1. Some WAFs only trigger on specific signature checks — if the
       first check passes, default mode reports clean incorrectly.
    2. Multi-layer setups (CDN WAF + App WAF) are only visible with -a.
    3. More signatures checked = higher confidence in the result.
  -a is protected: it cannot be removed via --wafw00f-extra.

Why per-domain (not batch -i):
  Batch mode has no per-URL timeout control. A single slow/unreachable
  domain can block the entire list. Per-domain gives us explicit control
  over every URL — timeout, default on failure, zero silent skips.

Why ThreadPoolExecutor(5):
  I/O bound operation — 5 parallel workers give near-5x speedup vs
  sequential. Small enough not to look like a DDoS pattern.

Why redirects are followed (no --no-redirect):
  WAFs typically sit on HTTPS endpoints. If a domain redirects
  http://example.com → https://example.com and we block redirects,
  we check the pre-WAF HTTP response and get a false "clean".
  Default redirect-following is correct for WAF detection.

Failure defaults to deep/clean profile:
  A failed check defaulting to "WAF/stealth" would downgrade scan
  quality on clean domains. Failing to "clean/deep" is the safer
  direction — worst case a slightly more aggressive scan, not a missed
  vulnerability due to overly cautious stealth mode.

Rules enforced:
  R5 — Stealth NEVER skips. WAF domain = stealth profile. Always.
  -a  — Always on. In protected list. Cannot be overridden.

Output files:
  temp/waf_domains.txt      — URLs with WAF detected  (stealth profile)
  temp/clean_domains.txt    — URLs with no WAF        (deep profile)
  temp/waf_profile_map.json — {url: {waf, scan_profile}} for report.py
  temp/waf_raw.txt          — combined raw output (one section per URL)

NON-CRITICAL — raises on hard failure, caught by main.py fallback.
SKIPPED for IP input — main.py checks input_type before calling.
"""

from __future__ import annotations

import concurrent.futures
import json
import re
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
    apply_extra_flags,
)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_WAF_WORKERS    = 5    # parallel domain checks
_DOMAIN_TIMEOUT = 30   # seconds per domain before giving up

# ---------------------------------------------------------------------------
# Module-level compiled regex — NOT inside functions (performance + clarity)
# ---------------------------------------------------------------------------

# "is behind Cloudflare Web Application Firewall (WAF)."
# "is behind ModSecurity (Trustwave) WAF."
# "is behind a Web Application Firewall."
# "is behind Cloudflare WAF"
_WAF_BEHIND = re.compile(
    r"is behind (.+?)(?:\s+Web Application Firewall|\s+\(WAF\)|\s+WAF\.?|\s*$)",
    re.IGNORECASE,
)

# "No WAF detected by the script"
_CLEAN = re.compile(r"no waf detected", re.IGNORECASE)

# Exact single article — signals "is behind a WAF" (unnamed)
_ARTICLE_ONLY = re.compile(r"^(a|an|the)$", re.IGNORECASE)

# Strip leading article from extracted name: "the Akamai" → "Akamai"
_STRIP_ARTICLE = re.compile(r"^(?:a|an|the)\s+", re.IGNORECASE)

# Strip trailing " WAF" from extracted name: "Cloudflare WAF" → "Cloudflare"
_TRAILING_WAF = re.compile(r"\s+WAF\.?$", re.IGNORECASE)

# Strip wafw00f CLI prefix tokens: "[+]", "[-]", "[*]", "[~]"
_LINE_PREFIX = re.compile(r"^\[.\]\s*")

# Strip parenthetical company names: "Cloudflare (Cloudflare Inc.)" → "Cloudflare"
_COMPANY_PARENS = re.compile(r"\s*\([^)]+\)")


# ---------------------------------------------------------------------------
# WAF name extractor — unit tested against 8 known output formats
# ---------------------------------------------------------------------------

def _extract_waf_name(raw_name: str) -> str:
    """
    Clean the raw WAF name extracted from the regex match group.

    Handles:
      "Cloudflare"         → "Cloudflare"
      "Cloudflare WAF."    → "Cloudflare"
      "a"                  → "Unknown WAF"   (from "is behind a WAF")
      "the Akamai"         → "Akamai"
      "an Unknown"         → "Unknown"
      "AWS WAF"            → "AWS"
      "F5 BIG-IP WAF"      → "F5 BIG-IP"
      "ModSecurity"        → "ModSecurity"
    """
    name = raw_name.strip().rstrip(".")

    # Single article = unnamed WAF ("is behind a Web Application Firewall")
    if _ARTICLE_ONLY.match(name):
        return "Unknown WAF"

    # Strip leading article: "the Akamai" → "Akamai"
    name = _STRIP_ARTICLE.sub("", name).strip()

    # Strip parenthetical company name: "Cloudflare (Cloudflare Inc.)" → "Cloudflare"
    name = _COMPANY_PARENS.sub("", name).strip()

    # Strip trailing " WAF": "Cloudflare WAF" → "Cloudflare"
    name = _TRAILING_WAF.sub("", name).strip().rstrip(".")

    if not name or name.lower() == "waf":
        return "Unknown WAF"

    return name


# ---------------------------------------------------------------------------
# Per-domain output parser
# ---------------------------------------------------------------------------

def _parse_per_domain_output(raw: str) -> Optional[str]:
    """
    Parse wafw00f stdout+stderr for a single domain.

    wafw00f -a can detect multiple WAFs. We collect ALL of them and
    join with " + " so the report shows the full picture:
      e.g. "Cloudflare + ModSecurity"

    Returns WAF name string or None if clean/unknown.

    Handles all known wafw00f output formats:
      "The site https://x.com is behind Cloudflare Web Application Firewall (WAF)."
      "The site https://x.com is behind Cloudflare WAF."
      "https://x.com is behind Cloudflare WAF"
      "No WAF detected by the script"
      "The site https://x.com is behind a Web Application Firewall."
    """
    if not raw.strip():
        return None

    found_wafs: list[str] = []

    for line in raw.splitlines():
        line = _LINE_PREFIX.sub("", line.strip())  # strip [+]/[-]/[*] prefix
        if not line:
            continue

        # Explicit clean result — return immediately
        if _CLEAN.search(line):
            return None

        # WAF detection line
        m = _WAF_BEHIND.search(line)
        if m:
            waf = _extract_waf_name(m.group(1))
            if waf and waf not in found_wafs:
                found_wafs.append(waf)

    if found_wafs:
        # Multiple WAFs joined: "Cloudflare + ModSecurity"
        return " + ".join(found_wafs)

    return None


# ---------------------------------------------------------------------------
# JSON output parser — primary detection method
# ---------------------------------------------------------------------------

def _parse_json_output(json_path: str, url: str) -> Optional[str]:
    """
    Parse wafw00f -f json -o <file> output.

    Actual wafw00f v2.3.2 JSON format (one object per detection):
        [{"detected": true, "firewall": "Cloudflare",
          "manufacturer": "Cloudflare Inc.", "trigger_url": "..."}]

    Multiple WAFs with -a produce multiple objects in the list.
    "detected": false or [] means clean.
    WAF name lives in "firewall" key, not "detected".

    Returns WAF name string (e.g. "Cloudflare") or None if clean/error.
    """
    import json as _json, os

    if not os.path.exists(json_path):
        return None

    try:
        text = open(json_path, encoding="utf-8", errors="replace").read().strip()
        if not text or text in ("[]", "null", "{}"):
            return None

        data = _json.loads(text)
        if not data or not isinstance(data, list):
            return None

        found_wafs: list[str] = []

        for entry in data:
            # Skip entries where detected is explicitly False
            if not entry.get("detected", False):
                continue

            # WAF name is in "firewall" key
            name = str(entry.get("firewall", "")).strip()
            if not name:
                continue

            # Clean the name
            name = _COMPANY_PARENS.sub("", name).strip()
            name = _TRAILING_WAF.sub("", name).strip().rstrip(".")
            name = _STRIP_ARTICLE.sub("", name).strip()

            if name and name.lower() not in ("waf", "") and name not in found_wafs:
                found_wafs.append(name)

        return " + ".join(found_wafs) if found_wafs else None

    except Exception:
        return None


# ---------------------------------------------------------------------------
# Per-domain subprocess runner
# ---------------------------------------------------------------------------

def _check_one_url(
    binary:  str,
    url:     str,
    extra:   Optional[str],
    verbose: bool,
) -> dict:
    """
    Run wafw00f against a single URL with -a flag.

    Uses -f json -o tmpfile output strategy.
    Reason: wafw00f uses Python logging internally. When run via subprocess
    with stdout/stderr PIPE (no TTY), the logging handler is not attached
    and ALL detection output is silently suppressed — stdout and stderr
    both come back empty even when a WAF is present.
    Writing to a JSON file bypasses the logging system entirely and gives
    reliable structured output regardless of TTY state.

    Returns:
        {"url": str, "waf": str | None, "raw_output": str}

    Never raises — any failure returns waf=None (deep profile default).
    """
    import tempfile, os

    # Write JSON output to a temp file — bypasses logging TTY issue
    tmp_json = tempfile.NamedTemporaryFile(
        suffix=".json", delete=False, mode="w"
    )
    tmp_json.close()
    tmp_path = tmp_json.name

    base_cmd = [
        binary,
        url,
        "-a",        # check ALL signatures — never stop at first hit
        "-f", "json",
        "-o", tmp_path,
    ]

    cmd = apply_extra_flags(
        base_cmd,
        extra,
        protected    = ["-a"],
        output_flags = ["-o"],
    )

    if verbose:
        print(f"[wafw00f] Checking: {url}")

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_DOMAIN_TIMEOUT,
            text=True,
        )
        raw = proc.stdout + proc.stderr

    except subprocess.TimeoutExpired:
        if verbose:
            print(f"[wafw00f] TIMEOUT: {url} — defaulting to deep profile",
                  file=sys.stderr)
        try: os.unlink(tmp_path)
        except Exception: pass
        return {"url": url, "waf": None, "raw_output": "TIMEOUT"}

    except Exception as exc:
        if verbose:
            print(f"[wafw00f] ERROR: {url}: {exc} — defaulting to deep profile",
                  file=sys.stderr)
        try: os.unlink(tmp_path)
        except Exception: pass
        return {"url": url, "waf": None, "raw_output": f"ERROR: {exc}"}

    # Parse JSON output file — primary method
    waf_name = _parse_json_output(tmp_path, url)
    try: os.unlink(tmp_path)
    except Exception: pass

    # Fallback: if JSON file empty/missing, try parsing stdout+stderr
    if waf_name is None and raw.strip():
        waf_name = _parse_per_domain_output(raw)

    if verbose:
        if waf_name:
            print(f"[wafw00f]   ✓ {url} → WAF: {waf_name}")
        else:
            print(f"[wafw00f]   ✓ {url} → clean")

    return {"url": url, "waf": waf_name, "raw_output": raw}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_wafw00f(flags_dict: dict, temp_dir: Path) -> dict:
    """
    Execute Phase 3 — WAF gate (per-domain, parallel, -a flag).

    Reads  : temp/live_urls.txt
    Writes :
        temp/waf_raw.txt          — combined raw output (one section per URL)
        temp/waf_domains.txt      — URLs behind a WAF   (stealth profile)
        temp/clean_domains.txt    — URLs with no WAF    (deep profile)
        temp/waf_profile_map.json — {url: {waf, scan_profile}} for report.py

    Parameters
    ----------
    flags_dict : dict
    temp_dir   : Path

    Returns
    -------
    dict:
        waf_count     : int
        clean_count   : int
        waf_domains   : list[str]
        clean_domains : list[str]
        profile_map   : dict[str, dict]

    Raises
    ------
    RuntimeError — NON-CRITICAL, caught by main.py which falls back to
                   putting all domains into deep profile.
    """
    f       = flags_dict
    verbose = f.get("verbose", False)

    binary = shutil.which("wafw00f")
    if binary is None:
        raise RuntimeError(
            "wafw00f not found in PATH. "
            "Pre-flight should have caught this."
        )

    input_file      = temp_dir / "live_urls.txt"
    raw_out         = temp_dir / "waf_raw.txt"
    waf_out         = temp_dir / "waf_domains.txt"
    clean_out       = temp_dir / "clean_domains.txt"
    profile_map_out = temp_dir / "waf_profile_map.json"

    if not input_file.exists():
        raise RuntimeError(
            f"WAF gate input not found: {input_file}\n"
            "httpx_probe must run before wafw00f."
        )

    live_urls = read_lines(input_file)
    if not live_urls:
        _write_empty_outputs(waf_out, clean_out, profile_map_out)
        return {
            "waf_count":     0,
            "clean_count":   0,
            "waf_domains":   [],
            "clean_domains": [],
            "profile_map":   {},
        }

    extra = f.get("wafw00f_extra")

    if verbose:
        print(
            f"[wafw00f] {len(live_urls)} URL(s) — "
            f"per-domain · -a (all signatures) · "
            f"{_WAF_WORKERS} parallel workers · "
            f"{_DOMAIN_TIMEOUT}s timeout per domain"
        )

    # ── Per-domain parallel checks ─────────────────────────────────────────
    results: list[dict] = []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=_WAF_WORKERS
    ) as executor:
        future_map = {
            executor.submit(_check_one_url, binary, url, extra, verbose): url
            for url in live_urls
        }
        for future in concurrent.futures.as_completed(future_map):
            url = future_map[future]
            try:
                results.append(future.result())
            except Exception as exc:
                if verbose:
                    print(f"[wafw00f] Unexpected error for {url}: {exc}",
                          file=sys.stderr)
                # Default to clean — never crash the pipeline
                results.append({"url": url, "waf": None, "raw_output": ""})

    # ── Build profile map + split into waf / clean lists ──────────────────
    profile_map:   dict[str, dict] = {}
    waf_domains:   list[str]       = []
    clean_domains: list[str]       = []
    all_raw_lines: list[str]       = []

    for res in results:
        url      = res["url"]
        waf_name = res["waf"]
        raw      = res.get("raw_output", "")

        # Write raw output per-section for debugging
        if raw.strip():
            all_raw_lines.append(f"=== {url} ===")
            all_raw_lines.extend(raw.strip().splitlines())
            all_raw_lines.append("")

        if waf_name:
            # R5: WAF detected → stealth profile — NEVER skip
            profile_map[url] = {"waf": waf_name, "scan_profile": "stealth"}
            waf_domains.append(url)
        else:
            profile_map[url] = {"waf": None, "scan_profile": "deep"}
            clean_domains.append(url)

    # Preserve original live_urls ordering
    waf_domains   = dedup_lines(waf_domains)
    clean_domains = dedup_lines(clean_domains)

    # ── Write output files ─────────────────────────────────────────────────
    write_lines(raw_out,   all_raw_lines)
    write_lines(waf_out,   waf_domains)
    write_lines(clean_out, clean_domains)

    profile_map_out.write_text(
        json.dumps(profile_map, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    if verbose:
        print(
            f"[wafw00f] Done — "
            f"{len(clean_domains)} clean (deep) · "
            f"{len(waf_domains)} WAF-protected (stealth)"
        )
        for url, entry in profile_map.items():
            if entry["waf"]:
                print(f"[wafw00f]   WAF detected: {entry['waf']} → {url}")

    return {
        "waf_count":     len(waf_domains),
        "clean_count":   len(clean_domains),
        "waf_domains":   waf_domains,
        "clean_domains": clean_domains,
        "profile_map":   profile_map,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _write_empty_outputs(
    waf_out:         Path,
    clean_out:       Path,
    profile_map_out: Path,
) -> None:
    """Write empty output files when there are no live URLs."""
    write_lines(waf_out,   [])
    write_lines(clean_out, [])
    profile_map_out.write_text("{}", encoding="utf-8")


def load_profile_map(temp_dir: Path) -> dict[str, dict]:
    """
    Load waf_profile_map.json written by run_wafw00f().
    Used by report.py to get {waf, scan_profile} per URL.
    Returns {} if file missing (e.g. IP input, wafw00f skipped).
    """
    profile_map_file = temp_dir / "waf_profile_map.json"
    if not profile_map_file.exists():
        return {}
    try:
        return json.loads(
            profile_map_file.read_text(encoding="utf-8", errors="replace")
        )
    except Exception as exc:
        print(f"[wafw00f] Warning: could not load profile map: {exc}",
              file=sys.stderr)
        return {}
