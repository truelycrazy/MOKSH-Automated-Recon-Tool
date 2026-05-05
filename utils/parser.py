"""
utils/parser.py
===============
MOKSH — Shared Parsing Helpers
--------------------------------
All output-parsing logic and common file I/O helpers live here.
No module should duplicate parsing logic — import from here instead.

Covers:
  - Input type detection (domain / url / ip)
  - Target normalisation and sanitisation
  - httpx output line parser
  - wafw00f output line parser
  - dnsx output line parser  ← handles ALL known dnsx output formats
  - nmap -oN output parser
  - nuclei output parser
  - katana endpoint filter
  - apply_extra_flags()      ← passthrough flag helper for all modules
  - Common file helpers: read_lines, write_lines, dedup_lines
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Optional


# ===========================================================================
# Input type detection and normalisation
# ===========================================================================

_IP_RE  = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def detect_input_type(target: str) -> str:
    """
    Classify the raw target string.

    Detection order:
      1. Matches IPv4 pattern             → "ip"
      2. Starts with http:// or https://  → "url"
      3. Anything else                    → "domain"
    """
    t = target.strip()
    if _IP_RE.match(t):
        return "ip"
    if _URL_RE.match(t):
        return "url"
    return "domain"


def normalise_target(target: str) -> str:
    """Lowercase, strip trailing slash and whitespace."""
    return target.strip().lower().rstrip("/")


def extract_domain_from_url(url: str) -> str:
    """
    Pull the bare domain from a full URL.
    "https://api.example.com/login"  → "api.example.com"
    "http://example.com:8080/path"   → "example.com"
    """
    bare = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    bare = bare.split("/")[0].split("?")[0].split("#")[0]
    bare = re.sub(r":\d+$", "", bare)
    return bare.lower()


def sanitize_target_name(target: str) -> str:
    """
    Convert any target into a filesystem-safe string for the report filename.
    Works on both Windows and Linux.
    """
    name = re.sub(r"^https?://", "", target, flags=re.IGNORECASE)
    name = name.split("/")[0].split("?")[0].split("#")[0]
    name = re.sub(r":\d+$", "", name)
    name = re.sub(r'[\\/:*?"<>|]', "_", name)
    name = name.lower().strip("._")
    return name if name else "target"


# ===========================================================================
# httpx output parser
# ===========================================================================

def parse_httpx_line(line: str) -> Optional[dict]:
    """
    Parse one line of httpx -status-code -title -silent output.

    Formats:
        https://example.com [200] [Page Title]
        https://example.com [403]

    Returns dict { "url": str, "status": int, "title": str } or None.
    """
    line = line.strip()
    if not line:
        return None

    m = re.match(
        r"^(https?://\S+)\s+\[(\d{3})\](?:\s+\[(.+?)\])?",
        line,
        re.IGNORECASE,
    )
    if not m:
        return None

    return {
        "url":    m.group(1).rstrip("/"),
        "status": int(m.group(2)),
        "title":  m.group(3).strip() if m.group(3) else "",
    }


# ===========================================================================
# wafw00f output parser
# ===========================================================================

def parse_wafw00f_line(line: str) -> Optional[dict]:
    """
    Parse one line from wafw00f text output.

    Handles:
        https://admin.example.com is behind Cloudflare Web Application Firewall (WAF)
        https://api.example.com   is behind a WAF
        https://dev.example.com   No WAF detected

    Returns dict { "url": str, "waf": str | None } or None.
    """
    line = line.strip()
    if not line:
        return None

    url_m = re.match(r"^(https?://\S+)", line, re.IGNORECASE)
    if not url_m:
        return None

    url  = url_m.group(1).rstrip("/")
    rest = line[len(url_m.group(0)):].strip()

    if re.search(r"no\s+waf\s+detected", rest, re.IGNORECASE):
        return {"url": url, "waf": None}

    named = re.search(
        r"is\s+behind\s+(.+?)(?:\s+Web\s+Application|\s+WAF|\s*$)",
        rest,
        re.IGNORECASE,
    )
    if named:
        name = named.group(1).strip()
        if name.lower() in ("a", "an", "the"):
            return {"url": url, "waf": "Unknown WAF"}
        return {"url": url, "waf": name}

    if re.search(r"is\s+behind", rest, re.IGNORECASE):
        return {"url": url, "waf": "Unknown WAF"}

    return {"url": url, "waf": None}


# ===========================================================================
# dnsx output parser — handles ALL known output formats
# ===========================================================================

# IPv4 pattern reused across both parsers
_IPV4 = r"(\d{1,3}(?:\.\d{1,3}){3})"

# Pattern list — tried in order, first match wins
# Each pattern: (compiled_regex, domain_group, ip_group)
_DNSX_PATTERNS: list[tuple] = [
    # Format 1 (most common): domain [IP]  or  domain [IP] [extra...]
    # Also handles: [domain] [IP]
    (re.compile(r"^\[?(\S+?)\]?\s+.*\[" + _IPV4 + r"\]"),          1, 2),

    # Format 2: domain A 1.2.3.4  (no brackets, record type present)
    (re.compile(r"^(\S+)\s+[A-Z]{1,5}\s+" + _IPV4 + r"\s*$"),      1, 2),

    # Format 3: domain 1.2.3.4  (bare, no brackets, no record type)
    (re.compile(r"^(\S+)\s+" + _IPV4 + r"\s*$"),                    1, 2),
]


def parse_dnsx_line(line: str) -> Optional[dict]:
    """
    Parse one line from dnsx output — handles ALL known output formats:

      api.example.com [1.2.3.4]                ← standard with brackets
      api.example.com [1.2.3.4] [A]            ← with record type in brackets
      api.example.com [1.2.3.4] [CNAME]        ← with CNAME note
      api.example.com A 1.2.3.4               ← space-separated, record type
      api.example.com 1.2.3.4                 ← bare, no brackets
      [api.example.com] [1.2.3.4]             ← both bracketed

    Returns dict { "domain": str, "ip": str } or None.
    Lines with no IPv4 address (e.g. pure CNAME records) return None.
    """
    line = line.strip()
    if not line:
        return None

    for pattern, d_grp, ip_grp in _DNSX_PATTERNS:
        m = pattern.match(line)
        if m:
            domain = m.group(d_grp).lower().strip("[]")
            ip     = m.group(ip_grp)
            # Sanity check: skip if domain looks like an IP itself
            if _IP_RE.match(domain):
                continue
            return {"domain": domain, "ip": ip}

    return None


# ===========================================================================
# nmap -oN output parser
# ===========================================================================

def parse_nmap_output(raw: str) -> list[dict]:
    """
    Parse the full text of an nmap -oN output file.

    Returns list of host records:
        [{"ip": "1.2.3.4", "ports": ["22/ssh/OpenSSH 8.9p1", "443/https/nginx 1.24"]}]

    Only open ports are included (--open is always passed to nmap).
    """
    results:       list[dict] = []
    current_ip:    Optional[str] = None
    current_ports: list[str]     = []

    for line in raw.splitlines():
        line = line.strip()

        host_m = re.match(
            r"Nmap scan report for (?:\S+\s+\()?(\d{1,3}(?:\.\d{1,3}){3})\)?",
            line,
        )
        if host_m:
            if current_ip is not None:
                results.append({"ip": current_ip, "ports": current_ports})
            current_ip    = host_m.group(1)
            current_ports = []
            continue

        port_m = re.match(
            r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?$",
            line,
            re.IGNORECASE,
        )
        if port_m and current_ip is not None:
            port_num = port_m.group(1)
            service  = port_m.group(3)
            version  = (port_m.group(4) or "").strip()
            entry    = f"{port_num}/{service}/{version}" if version \
                       else f"{port_num}/{service}"
            current_ports.append(entry)
            continue

    if current_ip is not None:
        results.append({"ip": current_ip, "ports": current_ports})

    return results


# ===========================================================================
# nuclei output parser
# ===========================================================================

def parse_nuclei_output(raw: str) -> list[str]:
    """
    Returns raw finding lines only — no parsing, no dicts.
    Discards [INF]/[WRN]/[ERR]/[DBG] log lines and banner lines.
    """
    findings: list[str] = []
    noise_prefixes = ("[INF]", "[WRN]", "[ERR]", "[DBG]", "[*]", "[~]")
    banner_words   = (
        "projectdiscovery", "__   _", "/ /", "/_/",
        "Current nuclei", "Templates loaded", "Targets loaded",
        "Using Interactsh", "Templates clustered", "Executing",
        "New templates added", "Skipped ", "Scan completed",
    )
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if any(line.startswith(p) for p in noise_prefixes):
            continue
        if any(w in line for w in banner_words):
            continue
        findings.append(line)
    return findings


# ===========================================================================
# Katana endpoint filter
# ===========================================================================

_INTERESTING_RE = re.compile(
    r"admin|api|login|upload|backup|config|token|secret|key|password",
    re.IGNORECASE,
)


def filter_katana_endpoints(endpoints: list[str]) -> list[str]:
    """
    Filter katana crawled endpoints to interesting paths only.
    Mirrors: grep -Ei "admin|api|login|upload|backup|config|token|secret|key|password"
    """
    return [ep for ep in endpoints if _INTERESTING_RE.search(ep)]


# ===========================================================================
# Passthrough flag helper
# ===========================================================================

def apply_extra_flags(cmd: list[str], extra: Optional[str],
                      protected: Optional[list[str]] = None,
                      output_flags: Optional[list[str]] = None) -> list[str]:
    """
    Apply user-supplied extra flags to an existing command list.

    Rules:
      1. If a flag in extra already exists in cmd → OVERWRITE the existing value.
      2. If a flag in extra is new → INSERT it before the output flag.
      3. Protected flags (e.g. ["-Pn", "--open"]) can NEVER be removed
         or overwritten regardless of what extra contains.
      4. Output flags (e.g. ["-o", "-oN"]) always stay at the end —
         new flags are inserted before them so tools don't ignore them.

    Parameters
    ----------
    cmd          : list[str]  — base command already built by the module
    extra        : str | None — raw string from user e.g. "-sS -T4 --top-ports 500"
    protected    : list[str]  — flags that must always stay (default: [])
    output_flags : list[str]  — flags that mark the output section (default: ["-o","-oN"])

    Returns
    -------
    list[str] — modified command with extra flags applied
    """
    if not extra or not extra.strip():
        return cmd

    protected    = protected    or []
    output_flags = output_flags or ["-o", "-oN", "-output"]

    # Parse extra string into (flag, value_or_None) pairs
    extra_tokens = extra.split()
    extra_pairs: list[tuple[str, Optional[str]]] = []
    i = 0
    while i < len(extra_tokens):
        tok = extra_tokens[i]
        if tok.startswith("-"):
            # Check if next token is a value (not a flag)
            if i + 1 < len(extra_tokens) and not extra_tokens[i + 1].startswith("-"):
                extra_pairs.append((tok, extra_tokens[i + 1]))
                i += 2
            else:
                extra_pairs.append((tok, None))
                i += 1
        else:
            i += 1

    # Work on a mutable copy
    result = list(cmd)

    for flag, value in extra_pairs:
        # Never allow overwriting protected flags
        if flag in protected:
            continue

        # Check if flag already exists in result
        if flag in result:
            idx = result.index(flag)
            if value is not None:
                # Flag has a value — overwrite the next element if it exists
                # and isn't itself a flag
                if idx + 1 < len(result) and not result[idx + 1].startswith("-"):
                    result[idx + 1] = value
                else:
                    result.insert(idx + 1, value)
            # If no value, flag is boolean — already present, nothing to do
        else:
            # New flag — find insertion point (before output flag)
            insert_at = len(result)
            for out_flag in output_flags:
                if out_flag in result:
                    insert_at = result.index(out_flag)
                    break

            if value is not None:
                result.insert(insert_at, value)
                result.insert(insert_at, flag)
            else:
                result.insert(insert_at, flag)

    return result


# ===========================================================================
# File I/O helpers (cross-platform via pathlib)
# ===========================================================================

def read_lines(path: Path) -> list[str]:
    """
    Read a file and return non-empty stripped lines.
    Returns [] if the file does not exist — callers handle this gracefully.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        return [ln.strip() for ln in text.splitlines() if ln.strip()]
    except FileNotFoundError:
        return []
    except Exception as exc:
        print(f"[parser] Warning: could not read {path}: {exc}", file=sys.stderr)
        return []


def write_lines(path: Path, lines: list[str]) -> None:
    """Write a list of strings to a file, one per line (UTF-8)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def dedup_lines(lines: list[str]) -> list[str]:
    """
    Remove duplicates preserving insertion order.
    Case-insensitive comparison, original casing preserved.
    """
    seen: set[str] = set()
    out:  list[str] = []
    for ln in lines:
        key = ln.lower()
        if key not in seen:
            seen.add(key)
            out.append(ln)
    return out
