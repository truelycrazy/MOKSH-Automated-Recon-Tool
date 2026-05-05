"""
utils/flags.py
==============
MOKSH — Flag & Configuration Management
----------------------------------------
Single source of truth for all runtime configuration.

Rules enforced here:
  - Loaded ONCE at startup by main.py via load_flags(args).
  - Every module imports this file directly — flags are never passed as
    function arguments through the chain.
  - All defaults live here. CLI overrides win when provided.
  - Each tool has an --<tool>-extra passthrough: raw flags appended to that
    tool's subprocess call via apply_extra_flags() in parser.py.
    Rules for extra flags:
      • Known flag already in command → OVERWRITE its value
      • New flag → INSERT before output flag (-o / -oN)
      • Protected flags (-Pn, --open) → NEVER touched even if user tries
"""

from __future__ import annotations
import argparse
from typing import Any

# ---------------------------------------------------------------------------
# Global CONFIG dict
# ---------------------------------------------------------------------------
CONFIG: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Fixed constants — NOT overridable
# ---------------------------------------------------------------------------

# Katana stealth — depth and rl are fixed (increasing triggers WAF bot detection)
KATANA_STEALTH_DEPTH = 2
KATANA_STEALTH_RL    = 5

# R1: -Pn and --open are ALWAYS in nmap commands — hardcoded, never a variable
NMAP_PROTECTED_FLAGS = ["-Pn", "--open"]

# R4: httpx 403 = LIVE
HTTP_403_IS_LIVE = True


# ---------------------------------------------------------------------------
# load_flags
# ---------------------------------------------------------------------------

def load_flags(args: argparse.Namespace) -> dict[str, Any]:
    """
    Merge parsed CLI args with built-in defaults.
    Populates and returns the global CONFIG dict.
    Called exactly once from main.py after argparse.parse_args().
    """
    global CONFIG

    mode: str = args.mode  # "soft" | "hard"

    # ── Subfinder ─────────────────────────────────────────────────────────
    subfinder_timeout_default = 10 if mode == "soft" else 20
    subfinder_timeout = (
        args.subfinder_timeout
        if args.subfinder_timeout is not None
        else subfinder_timeout_default
    )
    subfinder_rl        = args.subfinder_rl if args.subfinder_rl is not None else 10
    subfinder_recursive = (mode == "hard")

    # ── httpx ─────────────────────────────────────────────────────────────
    httpx_threads = args.httpx_threads if args.httpx_threads is not None else 50

    # ── Nuclei deep ───────────────────────────────────────────────────────
    # Smarter defaults: fast timeout, retries, host-error limit, random-agent.
    # Old default of 30s timeout made nuclei hang for hours on large lists.
    # 7s per request is enough for real responses and kills stuck templates fast.
    nuclei_rl_default = 20 if mode == "soft" else 25
    nuclei_rl       = args.nuclei_rl      if args.nuclei_rl      is not None else nuclei_rl_default
    nuclei_timeout  = args.nuclei_timeout if args.nuclei_timeout is not None else 7
    nuclei_severity = args.nuclei_severity if args.nuclei_severity is not None \
                      else "critical,high,medium"
    nuclei_retries  = getattr(args, "nuclei_retries", None)
    nuclei_retries  = nuclei_retries if nuclei_retries is not None else 2
    nuclei_mhe      = getattr(args, "nuclei_mhe", None)
    nuclei_mhe      = nuclei_mhe if nuclei_mhe is not None else 5
    nuclei_c        = getattr(args, "nuclei_c",  None)
    nuclei_c        = nuclei_c if nuclei_c is not None else 30
    nuclei_bs       = getattr(args, "nuclei_bs", None)
    nuclei_bs       = nuclei_bs if nuclei_bs is not None else 25
    
    # ── Nuclei stealth ────────────────────────────────────────────────────
    # No longer completely frozen — stealth_extra passthrough added.
    # Tags default to info,tech-detect (safe fingerprinting only).
    # Rate, timeout, retries, mhe have sensible WAF-aware defaults.
    nuclei_stealth_rl       = getattr(args, "nuclei_stealth_rl",      None) or 5
    nuclei_stealth_timeout  = getattr(args, "nuclei_stealth_timeout",  None) or 10
    nuclei_stealth_templates= getattr(args, "nuclei_stealth_templates",None) or "info,tech-detect"
    nuclei_stealth_retries  = getattr(args, "nuclei_stealth_retries",  None) or 1
    nuclei_stealth_mhe      = getattr(args, "nuclei_stealth_mhe",      None) or 3
    nuclei_stealth_c        = getattr(args, "nuclei_stealth_c",  None) or 10
    nuclei_stealth_bs       = getattr(args, "nuclei_stealth_bs", None) or 5

    # ── Katana deep ───────────────────────────────────────────────────────
    katana_depth_default = 3 if mode == "soft" else 5
    katana_depth = args.katana_depth if args.katana_depth is not None else katana_depth_default

    katana_rl_default = 15 if mode == "soft" else 25
    katana_rl    = args.katana_rl    if args.katana_rl    is not None else katana_rl_default

    katana_stealth_delay = args.katana_delay if args.katana_delay is not None else 2

    # ── dnsx ──────────────────────────────────────────────────────────────
    dnsx_threads = args.dnsx_threads if args.dnsx_threads is not None else 50

    # ── Nmap port range ───────────────────────────────────────────────────
    if args.nmap_ports is not None:
        nmap_ports_flag = f"-p {args.nmap_ports}"
    else:
        nmap_ports_flag = "--top-ports 1000" if mode == "soft" else "-p 0-65535"

    # ── Extra passthrough flags ───────────────────────────────────────────
    subfinder_extra      = getattr(args, "subfinder_extra",      None)
    httpx_extra          = getattr(args, "httpx_extra",          None)
    wafw00f_extra        = getattr(args, "wafw00f_extra",        None)
    dnsx_extra           = getattr(args, "dnsx_extra",           None)
    nmap_extra           = getattr(args, "nmap_extra",           None)
    nuclei_extra         = getattr(args, "nuclei_extra",         None)
    nuclei_stealth_extra = getattr(args, "nuclei_stealth_extra", None)
    katana_extra         = getattr(args, "katana_extra",         None)

    # ── Assemble CONFIG ───────────────────────────────────────────────────
    CONFIG = {
        # Identity
        "target": args.target,
        "mode":   mode,

        # I/O
        "output":    args.output,
        "keep_temp": args.keep_temp,
        "verbose":   args.verbose,

        # Subfinder
        "subfinder_timeout":   subfinder_timeout,
        "subfinder_rl":        subfinder_rl,
        "subfinder_recursive": subfinder_recursive,
        "subfinder_extra":     subfinder_extra,

        # httpx
        "httpx_threads": httpx_threads,
        "httpx_extra":   httpx_extra,

        # wafw00f
        "wafw00f_extra": wafw00f_extra,

        # Nuclei deep
        "nuclei_rl":       nuclei_rl,
        "nuclei_timeout":  nuclei_timeout,
        "nuclei_severity": nuclei_severity,
        "nuclei_retries":  nuclei_retries,
        "nuclei_mhe":      nuclei_mhe,
        "nuclei_c":        nuclei_c,
        "nuclei_bs":       nuclei_bs,
        "nuclei_extra":    nuclei_extra,

        # Nuclei stealth
        "nuclei_stealth_rl":        nuclei_stealth_rl,
        "nuclei_stealth_templates": nuclei_stealth_templates,
        "nuclei_stealth_timeout":   nuclei_stealth_timeout,
        "nuclei_stealth_retries":   nuclei_stealth_retries,
        "nuclei_stealth_mhe":       nuclei_stealth_mhe,
        "nuclei_stealth_c":         nuclei_stealth_c,
        "nuclei_stealth_bs":        nuclei_stealth_bs,
        "nuclei_stealth_extra":     nuclei_stealth_extra,

        # Katana deep
        "katana_depth": katana_depth,
        "katana_rl":    katana_rl,
        "katana_extra": katana_extra,

        # Katana stealth (depth + rl fixed, delay semi-overridable)
        "katana_stealth_depth": KATANA_STEALTH_DEPTH,
        "katana_stealth_rl":    KATANA_STEALTH_RL,
        "katana_stealth_delay": katana_stealth_delay,

        # dnsx
        "dnsx_threads": dnsx_threads,
        "dnsx_extra":   dnsx_extra,

        # Nmap
        "nmap_ports_flag": nmap_ports_flag,
        "nmap_extra":      nmap_extra,

        # Runtime state (populated by preflight / main.py)
        "input_type":        None,
        "target_normalised": None,
        "original_url":      None,
        "temp_dir":          None,
        "output_path":       None,
    }

    return CONFIG


# ---------------------------------------------------------------------------
# Convenience accessors
# ---------------------------------------------------------------------------

def get(key: str, default: Any = None) -> Any:
    """Read a value from the global CONFIG dict."""
    return CONFIG.get(key, default)


def set_runtime(key: str, value: Any) -> None:
    """
    Set a runtime key after initial load.
    Used by preflight and main.py to write input_type, target, temp_dir, etc.
    """
    CONFIG[key] = value
