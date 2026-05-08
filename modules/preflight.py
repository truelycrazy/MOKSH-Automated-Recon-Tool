"""
modules/preflight.py
====================
MOKSH — Phase 0: Pre-Flight

Runs before everything else on every invocation.

Responsibilities:
  1. Check every required external tool is present via shutil.which()
     — NO hardcoded paths, NO auto-install, NO blocking on old versions.
  2. Print per-tool status: [OK] tool vX.Y  /  [WARN] tool outdated  /
     [ERROR] tool not found — install required.
  3. EXIT only if a tool is completely MISSING (not found in PATH at all).
     A stale version is a warning — the scan continues. (DO NOT list rule:
     "No Blocking: Do not use exit() just because a version is older.")
  4. Detect input type: ip / url / domain via regex.
  5. Normalise target string (lowercase, strip trailing slash).
  6. For URL input: preserve original URL in flags (Rule R3) and extract
     bare domain as the working target for subfinder.
  7. Write detected input_type, target_normalised, original_url back into
     the flags CONFIG so every subsequent module can read them.
  8. Version info is CLI-only — it NEVER appears in the report file.

CRITICAL module — main.py exits the pipeline if run_preflight() raises
a RuntimeError (missing tool). It does NOT call sys.exit() for old versions.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

# utils imported directly — not passed as arguments (module contract rule)
import utils.flags as flags
from utils.parser import detect_input_type, normalise_target, extract_domain_from_url


# ---------------------------------------------------------------------------
# Tool manifest
# Each entry: (binary_name, version_flag, display_name)
# version_flag is the argument that makes the tool print its version
# ---------------------------------------------------------------------------
TOOL_MANIFEST: list[tuple[str, str, str]] = [
    ("subfinder", "-version",  "subfinder"),
    ("httpx",     "-version",  "httpx    "),
    ("wafw00f",   "--version", "wafw00f  "),
    ("dnsx",      "-version",  "dnsx     "),
    ("nmap",      "-version",  "nmap     "),
    ("nuclei",    "-version",  "nuclei   "),
    ("katana",    "-version",  "katana   "),
]


# ---------------------------------------------------------------------------
# Colour helpers
# Self-contained here so preflight.py has zero dependency on main.py
# ---------------------------------------------------------------------------

def _use_color() -> bool:
    if sys.platform == "win32":
        import os
        return (
            "WT_SESSION"    in os.environ
            or "ANSICON"    in os.environ
            or os.environ.get("TERM_PROGRAM") is not None
        )
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


_C = _use_color()


def _ok(s: str)   -> str: return f"\033[32m{s}\033[0m"   if _C else s  # green
def _warn(s: str) -> str: return f"\033[33m{s}\033[0m"   if _C else s  # yellow
def _err(s: str)  -> str: return f"\033[31;1m{s}\033[0m" if _C else s  # bold red
def _dim(s: str)  -> str: return f"\033[2m{s}\033[0m"    if _C else s  # dim


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _find_binary(name: str) -> Optional[str]:
    """
    Locate a binary using shutil.which().
    Returns the resolved path string, or None if not found.
    No hardcoded paths — cross-platform by design.
    """
    return shutil.which(name)


def _get_version_string(binary_path: str, version_flag: str) -> str:
    """
    Run `binary version_flag` and return the first non-empty output line.
    Returns an empty string on any failure — version check is best-effort.
    """
    try:
        result = subprocess.run(
            [binary_path, version_flag],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            text=True,
        )
        # Most tools print version to stdout; wafw00f and some others use stderr
        combined = (result.stdout + result.stderr).strip()
        for line in combined.splitlines():
            if line.strip():
                return line.strip()
        return ""
    except Exception:
        return ""


def _extract_version_token(version_line: str) -> str:
    """
    Extract a short human-readable version token from a version string.

    "subfinder version v2.6.3" → "v2.6.3"
    "Nmap version 7.94"        → "7.94"
    "wafw00f v0.9.7"           → "v0.9.7"
    """
    m = re.search(r"v?\d+[\d.]+(?:[-_]\w+)?", version_line, re.IGNORECASE)
    if m:
        token = m.group(0)
        # Ensure "v" prefix for display consistency
        return token if token.startswith("v") else f"v{token}"
    # Fallback: return first 30 chars of version line
    return version_line[:30] if version_line else "?"


def _check_all_tools() -> tuple[bool, list[str]]:
    """
    Iterate through TOOL_MANIFEST and check each binary.

    Returns
    -------
    (all_present: bool, missing: list[str])
      all_present — True only if every tool was found via shutil.which()
      missing     — list of tool names that could not be located
    """
    missing: list[str] = []

    print()
    print(_dim("  ┌─────────────────────────────────────────────────┐"))
    print(_dim("  │") + "  Tool Version Check                             " + _dim("│"))
    print(_dim("  └─────────────────────────────────────────────────┘"))
    print()

    for binary_name, ver_flag, display_name in TOOL_MANIFEST:
        path = _find_binary(binary_name)

        if path is None:
            # MISSING — this is the only case that will block the scan
            print(f"  {_err('[ERROR]')} {display_name}  not found in PATH"
                  f"  {_dim('← install required')}")
            missing.append(binary_name)
            continue

        # Found — get version string
        version_line  = _get_version_string(path, ver_flag)
        version_token = _extract_version_token(version_line)

        # We do NOT block on version numbers (DO NOT list rule).
        # If we can't parse a version it's still a [OK] — tool exists.
        print(f"  {_ok('[OK]')}    {display_name}  {version_token}")

    print()

    # Python version check (informational only — not a blocking condition)
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 8):
        print(f"  {_ok('[OK]')}    python      v{py_ver}")
    else:
        # Python < 3.8 is a hard requirement — warn loudly but still let
        # the caller decide whether to abort (main.py raises, not sys.exit)
        print(f"  {_warn('[WARN]')}  python      v{py_ver}"
              f"  {_dim('← Python 3.8+ recommended')}")

    print()
    return (len(missing) == 0), missing


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_preflight(flags_dict: dict) -> dict:
    """
    Execute Phase 0 — pre-flight checks.

    Parameters
    ----------
    flags_dict : dict
        The CONFIG dict from flags.load_flags().
        Updated in-place with: input_type, target_normalised, original_url.

    Returns
    -------
    dict:
        input_type : "domain" | "url" | "ip"
        target     : normalised working target for all subsequent phases

    Raises
    ------
    RuntimeError
        If one or more required tools are completely missing from PATH.
        main.py catches this and exits with code 1.
        Does NOT raise for old/outdated versions.
    """
    raw_target = flags_dict.get("target", "").strip()

    # Divider line — visual separation in CLI output
    print("  " + "─" * 51)
    print("  MOKSH — Pre-Flight")
    print("  " + "─" * 51)

    # ── 1. Tool checks ────────────────────────────────────────────────────
    all_present, missing = _check_all_tools()

    if not all_present:
        missing_str = ", ".join(missing)
        raise RuntimeError(
            f"Required tool(s) not found in PATH: {missing_str}\n"
            f"Install them and ensure they are accessible before running MOKSH."
        )

    # ── 2. Input type detection ───────────────────────────────────────────
    input_type = detect_input_type(raw_target)
    normalised = normalise_target(raw_target)

    # For URL input: the working target sent to subfinder is the bare domain.
    # The full URL is preserved as original_url (Rule R3).
    original_url:    Optional[str] = None
    working_target:  str

    if input_type == "url":
        original_url   = normalised                      # e.g. "https://api.example.com/login"
        working_target = extract_domain_from_url(normalised)  # e.g. "api.example.com"
    else:
        working_target = normalised                      # domain or IP as-is

    # ── 3. Display detected input ─────────────────────────────────────────
    print(f"  Input detected  :  {_ok(input_type.upper())}")
    print(f"  Working target  :  {working_target}")
    if original_url:
        print(f"  Original URL    :  {_dim(original_url)}")
        print(f"  {_dim('(URL preserved — will be re-added after subfinder, Rule R3)')}")
    if input_type == "ip":
        print(f"  {_dim('(IP input — subfinder skipped)')}")
    print()

    # ── 4. Write back into flags CONFIG ──────────────────────────────────
    # Every subsequent module reads these from flags.CONFIG directly.
    flags.set_runtime("input_type",        input_type)
    flags.set_runtime("target",            working_target)
    flags.set_runtime("target_normalised", working_target)
    flags.set_runtime("original_url",      original_url)

    # Also update the caller's local dict reference (same object, but explicit)
    flags_dict["input_type"]        = input_type
    flags_dict["target"]            = working_target
    flags_dict["target_normalised"] = working_target
    flags_dict["original_url"]      = original_url

    return {
        "input_type": input_type,
        "target":     working_target,
    }
