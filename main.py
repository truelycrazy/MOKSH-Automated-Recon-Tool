#!/usr/bin/env python3
"""
main.py
=======
MOKSH — Liberation by Recon
Main orchestrator. Entry point for the tool.

Pipeline:
  Phase 0  — Preflight      [CRITICAL]
  Phase 1  — Subfinder      [CRITICAL]
  Phase 2  — httpx          [CRITICAL]
  Phase 3  — dnsx + wafw00f [CRITICAL]
  Phase 4  — Nmap + Katana  [PARALLEL, non-critical]
  Phase 5  — Nuclei         [non-critical]
  Phase 6  — Report + Cleanup
"""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import shutil
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Path bootstrap ─────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# ── Local imports ──────────────────────────────────────────────────────────
from utils.flags  import load_flags
from utils.parser import sanitize_target_name, write_lines, read_lines

from modules.preflight   import run_preflight
from modules.subfinder   import run_subfinder
from modules.httpx_probe import run_httpx_probe
from modules.wafw00f     import run_wafw00f
from modules.dnsx        import run_dnsx
from modules.nmap        import run_nmap
from modules.nuclei      import run_nuclei
from modules.katana      import run_katana
from modules.report      import run_report


# ===========================================================================
# Colour helpers — pure stdlib, no Rich
# ===========================================================================

def _supports_color() -> bool:
    if os.name == "nt":
        return (
            "WT_SESSION" in os.environ
            or "ANSICON"  in os.environ
            or os.environ.get("TERM_PROGRAM") is not None
        )
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

_COLOR = _supports_color()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text

def _info(msg: str)  -> None: print(_c("36",   f"  [~] {msg}"))
def _ok(msg: str)    -> None: print(_c("32",   f"  [✓] {msg}"))
def _warn(msg: str)  -> None: print(_c("33",   f"  [!] {msg}"))
def _err(msg: str)   -> None: print(_c("31;1", f"  [✗] {msg}"), file=sys.stderr)
def _phase(msg: str) -> None: print(_c("35",   f"\n  ── {msg}"))
def _dim(msg: str)   -> None: print(_c("2",    f"     {msg}"))


# ===========================================================================
# Banner
# ===========================================================================

BANNER = r"""
  ███╗   ███╗ ██████╗ ██╗  ██╗███████╗██╗  ██╗
  ████╗ ████║██╔═══██╗██║ ██╔╝██╔════╝██║  ██║
  ██╔████╔██║██║   ██║█████╔╝ ███████╗███████║
  ██║╚██╔╝██║██║   ██║██╔═██╗ ╚════██║██╔══██║
  ██║ ╚═╝ ██║╚██████╔╝██║  ██╗███████║██║  ██║
  ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
"""
TAGLINE = "  Liberation by Recon"

def print_banner() -> None:
    print(_c("35;1", BANNER))
    print(_c("36;1", TAGLINE))
    print(_c("2", "  " + "─" * 46))
    print()


# ===========================================================================
# Argument parser
# ===========================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="moksh",
        description=(
            "MOKSH — Liberation by Recon\n"
            "─────────────────────────────────────────────────\n"
            "BASIC USAGE:\n"
            "  python3 main.py example.com\n"
            "  python3 main.py example.com --mode hard\n"
            "  python3 main.py 1.2.3.4 --output /reports/\n"
            "  python3 main.py https://api.example.com/login -v\n\n"
            "PASSTHROUGH — pass any native tool flag directly:\n"
            "  --subfinder-extra \"-all -nW\"\n"
            "  --nmap-extra      \"-T4 -sS\"\n"
            "  --nuclei-extra    \"-tags cve -stats\"\n"
            "  --katana-extra    \"-jc -xhr-extraction\"\n"
            "  --httpx-extra     \"-follow-redirects\"\n"
            "  --wafw00f-extra   \"-t 10\"\n"
            "  --dnsx-extra      \"-aaaa\"\n\n"
            "  Known flags → overwritten. New flags → inserted before -o.\n"
            "  Protected: nmap -Pn --open | wafw00f -a  (cannot be removed)\n\n"
            "AUTHORISATION: Only scan systems you own or have written permission."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Positional
    p.add_argument(
        "target",
        help=(
            "Domain  →  example.com\n"
            "URL     →  https://api.example.com/login\n"
            "IP      →  1.2.3.4"
        ),
    )

    # Core
    p.add_argument("--mode", choices=["soft","hard"], default="soft",
        help="soft (default) — top-1000 nmap, depth 3 katana, non-recursive subfinder\n"
             "hard           — full 0-65535 nmap, depth 5 katana, recursive subfinder")
    p.add_argument("--output","-o", default=None, metavar="PATH",
        help="Output directory or full filepath. Default: current directory.")
    p.add_argument("--keep-temp", action="store_true", default=False,
        help="Keep temp/ after report is written (debug).")
    p.add_argument("--verbose","-v", action="store_true", default=False,
        help="Show raw tool output during scan.")

    # ── Subfinder ──────────────────────────────────────────────────────────
    g = p.add_argument_group("Subfinder  [Phase 1 — skipped for IP input]")
    g.add_argument("--subfinder-timeout", type=int, default=None, metavar="SEC",
        help="Override -timeout  (soft: 10s | hard: 20s)")
    g.add_argument("--subfinder-rl", type=int, default=None, metavar="N",
        help="Override -rl req/sec  (default: 10)")
    g.add_argument("--subfinder-extra", type=str, default=None, metavar="FLAGS",
        help="Any native subfinder flag(s).  e.g. \"-all -nW\"")

    # ── httpx ──────────────────────────────────────────────────────────────
    g = p.add_argument_group("httpx  [Phase 2 — R4: 403=LIVE]")
    g.add_argument("--httpx-threads", type=int, default=None, metavar="N",
        help="Override -threads  (default: 50)")
    g.add_argument("--httpx-extra", type=str, default=None, metavar="FLAGS",
        help="Any native httpx flag(s).  e.g. \"-follow-redirects -timeout 10\"")

    # ── wafw00f ────────────────────────────────────────────────────────────
    g = p.add_argument_group("wafw00f  [Phase 3 — per-domain, -a always on]")
    g.add_argument("--wafw00f-extra", type=str, default=None, metavar="FLAGS",
        help="Any native wafw00f flag(s).  -a is protected.  e.g. \"-t 10\"")

    # ── dnsx ───────────────────────────────────────────────────────────────
    g = p.add_argument_group("dnsx  [Phase 3 — socket fallback if dnsx misses]")
    g.add_argument("--dnsx-threads", type=int, default=None, metavar="N",
        help="Override -threads  (default: 50)")
    g.add_argument("--dnsx-extra", type=str, default=None, metavar="FLAGS",
        help="Any native dnsx flag(s).  e.g. \"-aaaa -resp-only\"")

    # ── Nmap ───────────────────────────────────────────────────────────────
    g = p.add_argument_group("Nmap  [Phase 4 — -Pn and --open always on, cannot be removed]")
    g.add_argument("--nmap-ports", type=str, default=None, metavar="RANGE",
        help="Override port range.  e.g. '80,443' | '0-65535'\n"
             "soft default: --top-ports 1000 | hard: -p 0-65535")
    g.add_argument("--nmap-extra", type=str, default=None, metavar="FLAGS",
        help="Any native nmap flag(s). Applied to both deep and stealth.\n"
             "-Pn and --open are protected.  e.g. \"-T4 -sS\"")

    # ── Nuclei ─────────────────────────────────────────────────────────────
    g = p.add_argument_group(
        "Nuclei  [Phase 5 — deep profile overridable | stealth rl=5,tags=info,tech-detect FIXED]")
    g.add_argument("--nuclei-rl", type=int, default=None, metavar="N",
        help="Override deep -rate-limit  (soft: 15 | hard: 25)")
    g.add_argument("--nuclei-timeout", type=int, default=None, metavar="SEC",
        help="Override deep -timeout  (default: 30s)")
    g.add_argument("--nuclei-severity", type=str, default=None, metavar="LIST",
        help="Override deep severity filter.\n"
             "Default: critical,high,medium\n"
             "Example: --nuclei-severity critical,high,medium,low,info")
    g.add_argument("--nuclei-extra", type=str, default=None, metavar="FLAGS",
        help="Any native nuclei flag(s) — deep profile only.\n"
             "Stealth profile is fixed, extra does not apply there.\n"
             "e.g. \"-tags cve,exposure -stats\"")
    g.add_argument("--nuclei-stealth-extra", type=str, default=None, metavar="FLAGS",
        help="Any native nuclei flag(s) — stealth profile only.\n"
             "e.g. \"-tags cve,tech-detect\"")

    # ── Katana ─────────────────────────────────────────────────────────────
    g = p.add_argument_group(
        "Katana  [Phase 4 — deep profile overridable | stealth depth=2,rl=5 FIXED]")
    g.add_argument("--katana-depth", type=int, default=None, metavar="N",
        help="Override deep -depth  (soft: 3 | hard: 5)")
    g.add_argument("--katana-rl", type=int, default=None, metavar="N",
        help="Override deep -rate-limit  (soft: 15 | hard: 25)")
    g.add_argument("--katana-delay", type=int, default=None, metavar="SEC",
        help="Override stealth -delay  (default: 2s)")
    g.add_argument("--katana-extra", type=str, default=None, metavar="FLAGS",
        help="Any native katana flag(s) — deep profile only.\n"
             "Stealth profile is fixed, extra does not apply there.\n"
             "e.g. \"-jc -xhr-extraction\"")

    return p


# ===========================================================================
# Helpers
# ===========================================================================

def setup_temp_dir() -> Path:
    temp_dir = PROJECT_ROOT / "temp"
    temp_dir.mkdir(parents=True, exist_ok=True)
    return temp_dir

def cleanup_temp_dir(temp_dir: Path, verbose: bool) -> None:
    try:
        shutil.rmtree(temp_dir)
        if verbose:
            _dim(f"Temp directory removed: {temp_dir}")
    except Exception as exc:
        _warn(f"Could not remove temp/: {exc}")

def build_output_path(target: str, output_arg: Optional[str]) -> Path:
    ts       = datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"recon_{sanitize_target_name(target)}_{ts}.txt"
    if output_arg is None:
        return Path.cwd() / filename
    out = Path(output_arg)
    if out.is_dir() or not out.suffix:
        out.mkdir(parents=True, exist_ok=True)
        return out / filename
    out.parent.mkdir(parents=True, exist_ok=True)
    return out


# ===========================================================================
# Phase 4 parallel runner
# ===========================================================================

_active_futures: list[concurrent.futures.Future] = []

def _run_parallel_nmap_katana(flags: dict, temp_dir: Path) -> tuple[dict, dict]:
    nmap_result = {}
    katana_result = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        fn = executor.submit(run_nmap,   flags, temp_dir)
        fk = executor.submit(run_katana, flags, temp_dir)
        _active_futures.extend([fn, fk])

        for future in concurrent.futures.as_completed([fn, fk], timeout=9000):
            try:
                result = future.result()
                if future is fn:
                    nmap_result = result
                else:
                    katana_result = result
            except Exception as exc:
                label = "nmap" if future is fn else "katana"
                _warn(f"Parallel task [{label}] raised: {exc}")

    _active_futures.clear()
    return nmap_result, katana_result


# ===========================================================================
# Ctrl+C handler
# ===========================================================================

_temp_dir_ref: Optional[Path] = None

def _handle_interrupt(signum, frame) -> None:
    print()
    _warn("Ctrl+C detected — Exiting MOKSH...")
    for future in _active_futures:
        future.cancel()
    if _temp_dir_ref is not None and _temp_dir_ref.exists():
        try:
            shutil.rmtree(_temp_dir_ref)
            _dim("Temp files cleaned up.")
        except Exception:
            pass
    print()
    sys.exit(130)

signal.signal(signal.SIGINT, _handle_interrupt)


# ===========================================================================
# IP input stub writer
# ===========================================================================

def _setup_ip_input_files(target_ip: str, temp_dir: Path) -> None:
    urls = [f"http://{target_ip}", f"https://{target_ip}"]
    write_lines(temp_dir / "clean_domains.txt",    urls)
    write_lines(temp_dir / "waf_domains.txt",      [])
    write_lines(temp_dir / "live_urls.txt",        [])
    write_lines(temp_dir / "dead_domains.txt",     [])
    write_lines(temp_dir / "subdomains_dedup.txt", [target_ip])


# ===========================================================================
# main()
# ===========================================================================

def main() -> int:
    global _temp_dir_ref

    print_banner()

    parser = build_parser()
    args   = parser.parse_args()
    flags  = load_flags(args)

    temp_dir      = setup_temp_dir()
    _temp_dir_ref = temp_dir
    flags["temp_dir"] = str(temp_dir)

    output_path = build_output_path(args.target, args.output)
    flags["output_path"] = str(output_path)

    start_time = time.time()

    print(_c("36", f"  Target  : {_c('36;1', args.target)}"))
    print(_c("36", f"  Mode    : {_c('36;1', flags['mode'].upper())}"))
    print(_c("36", f"  Output  : {output_path}"))

    # Show any active extra passthrough flags
    extras = {k: v for k, v in {
        "subfinder": flags.get("subfinder_extra"),
        "httpx":     flags.get("httpx_extra"),
        "wafw00f":   flags.get("wafw00f_extra"),
        "dnsx":      flags.get("dnsx_extra"),
        "nmap":      flags.get("nmap_extra"),
        "nuclei":    flags.get("nuclei_extra"),
        "katana":    flags.get("katana_extra"),
    }.items() if v}
    if extras:
        print(_c("2", "  Extras  : " + " | ".join(
            f"{t}={v!r}" for t, v in extras.items()
        )))
    print()

    try:
        # ══════════════════════════════════════════════════════════════════
        # PHASE 0 — PRE-FLIGHT  [CRITICAL]
        # ══════════════════════════════════════════════════════════════════
        _phase("Phase 0 — Pre-Flight")
        _info("Checking tool versions...")
        try:
            pre = run_preflight(flags)
        except RuntimeError as exc:
            _err(str(exc))
            cleanup_temp_dir(temp_dir, args.verbose)
            return 1

        input_type = pre["input_type"]
        target     = pre["target"]
        flags["input_type"] = input_type
        flags["target"]     = target

        output_path = build_output_path(target, args.output)
        flags["output_path"] = str(output_path)

        _ok(f"All tools present — {_c('36;1', input_type.upper())} — {_c('36;1', target)}")
        if input_type == "ip":
           _setup_ip_input_files(target, temp_dir)

        # ══════════════════════════════════════════════════════════════════
        # PHASE 1 — SUBFINDER  [CRITICAL, domain/URL only]
        # ══════════════════════════════════════════════════════════════════
        _phase("Phase 1 — Surface Discovery")
        if input_type != "ip":
            _info(f"Seeking subdomains on {target} "
                  f"({flags['mode']}, timeout={flags['subfinder_timeout']}s, "
                  f"rl={flags['subfinder_rl']})...")
            try:
                sf = run_subfinder(flags, temp_dir)
            except RuntimeError as exc:
                _err(f"Subfinder failed: {exc}")
                cleanup_temp_dir(temp_dir, args.verbose)
                return 1
            _ok(f"{sf['count']} targets liberated (root appended, deduped)")
        else:
            _dim("Skipped for IP input")
            sf = {"count": 0}

        # ══════════════════════════════════════════════════════════════════
        # PHASE 2 — HTTPX  [CRITICAL]
        # ══════════════════════════════════════════════════════════════════
        _phase("Phase 2 — HTTP Probe")

        _info(f"Probing {sf['count']} subdomains "
              f"({flags['httpx_threads']} threads)...")
        try:
            hx = run_httpx_probe(flags, temp_dir)
        except RuntimeError as exc:
            _err(f"httpx probe failed: {exc}")
            cleanup_temp_dir(temp_dir, args.verbose)
            return 1
            _ok(f"{hx['live_count']} live · {hx['dead_count']} dead")
        live_count = hx["live_count"]


        # ══════════════════════════════════════════════════════════════════
        # PHASE 3 — DNSX + WAFW00F  [domain/URL only]
        # ══════════════════════════════════════════════════════════════════
        _phase("Phase 3 — DNS Resolution + WAF Gate")
        # dnsx
        _info(f"Resolving {live_count} domain(s) to IPs "
             f"(dnsx + socket fallback)...")
        try:
            dns = run_dnsx(flags, temp_dir)
            _ok(f"{len(dns['unique_ips'])} unique IP(s) resolved")
        except Exception as exc:
            _warn(f"dnsx failed ({exc}) — IPs will be null in report")
            dns = {"unique_ips": [], "waf_ips": [], "domain_ip_map": {}}

        # wafw00f
        _info(f"WAF detection on {live_count} domain(s) "
              f"(per-domain · -a · 5 parallel workers)...")
        try:
            waf     = run_wafw00f(flags, temp_dir)
            clean_c = waf["clean_count"]
            waf_c   = waf["waf_count"]
            _ok(f"WAF gate — "
                f"{_c('32', str(clean_c))} clean (deep) · "
                f"{_c('33', str(waf_c))} WAF-protected (stealth)")
        except Exception as exc:
            _warn(f"wafw00f failed ({exc}) — defaulting all to deep profile")
            live_lines = read_lines(temp_dir / "live_urls.txt")
            write_lines(temp_dir / "clean_domains.txt", live_lines)
            write_lines(temp_dir / "waf_domains.txt",   [])
            (temp_dir / "waf_profile_map.json").write_text("{}", encoding="utf-8")
            clean_c = live_count
            waf_c   = 0


        # ══════════════════════════════════════════════════════════════════
        # PHASE 4 — PARALLEL: NMAP + KATANA  [non-critical]
        # ══════════════════════════════════════════════════════════════════
        _phase("Phase 4 — Discovery Push (Parallel)")
        _info(f"Nmap on {len(dns.get('unique_ips', []))} IP(s) · "
              f"Katana deep ({clean_c}) · stealth ({waf_c}) — parallel...")

        nmap_result, katana_result = _run_parallel_nmap_katana(flags, temp_dir)

        ports_found     = sum(len(v) for v in nmap_result.get("ports_by_ip", {}).values())
        endpoints_found = katana_result.get("filtered_count", 0)
        _ok(f"Nmap — {ports_found} open port(s) · "
            f"Katana — {endpoints_found} interesting endpoint(s)")

        # ══════════════════════════════════════════════════════════════════
        # PHASE 5 — NUCLEI  [non-critical, runs AFTER parallel]
        # ══════════════════════════════════════════════════════════════════
        _phase("Phase 5 — Exploit Push (Nuclei)")
        severity = flags.get("nuclei_severity", "critical,high,medium")
        _info(f"Nuclei deep ({clean_c} target(s), severity={severity}, "
              f"rl={flags['nuclei_rl']}) · "
              f"stealth ({waf_c} target(s), rl=5, tags=info,tech-detect)...")

        nuclei_result = run_nuclei(flags, temp_dir)
        deep_n    = nuclei_result.get("deep_count",    0)
        stealth_n = nuclei_result.get("stealth_count", 0)
        total_n   = deep_n + stealth_n

        if total_n > 0:
            _ok(f"{total_n} finding(s) — {deep_n} deep · {stealth_n} stealth")
        else:
            _ok("No vulnerabilities found")

        # ══════════════════════════════════════════════════════════════════
        # PHASE 6 — REPORT  [CRITICAL]
        # ══════════════════════════════════════════════════════════════════
        _phase("Phase 6 — Wrap-Up")
        _info("Merging all results and generating report...")
        try:
            rpt = run_report(flags, temp_dir)
        except RuntimeError as exc:
            _err(f"Report generation failed: {exc}")
            return 1

        # Cleanup
        if not args.keep_temp:
            cleanup_temp_dir(temp_dir, args.verbose)
            _temp_dir_ref = None
        else:
            _dim(f"Temp files kept at: {temp_dir}  (--keep-temp)")

        # Final summary
        elapsed    = time.time() - start_time
        mins, secs = divmod(int(elapsed), 60)

        vuln_count = rpt.get("vuln_count", 0)
        crit_count = rpt.get("crit_count", 0)
        live_total = rpt.get("live_count", 0)
        dead_total = rpt.get("dead_count", 0)
        waf_total  = rpt.get("waf_count",  0)
        ip_total   = rpt.get("unique_ips", 0)

        print()
        print("  " + _c("2", "─" * 60))
        print()
        print(_c("32;1", f"  [✓] Done — {_c('36;1', str(Path(flags['output_path'])))}"))
        print()
        print(_c("36",
            f"  Summary: "
            f"{_c('31;1' if crit_count else '33', str(vuln_count))} vuln(s) "
            f"({_c('31;1', str(crit_count))} critical) · "
            f"{_c('32', str(live_total))} live · "
            f"{dead_total} dead · "
            f"{_c('33', str(waf_total))} WAF · "
            f"{ip_total} unique IP(s) · "
            f"{_c('2', f'{mins}m {secs}s')}"
        ))
        print()
        return 0

    except KeyboardInterrupt:
        _handle_interrupt(None, None)
        return 130

    except Exception as exc:
        _err(f"Unexpected error: {exc}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        if _temp_dir_ref is not None and _temp_dir_ref.exists() \
                and not args.keep_temp:
            cleanup_temp_dir(_temp_dir_ref, False)
        return 1


# ===========================================================================
if __name__ == "__main__":
    sys.exit(main())
