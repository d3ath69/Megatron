#!/usr/bin/env python3
"""
MEGATRON XBOW benchmark harness.

XBOW Validation Benchmarks (github.com/xbow-engineering/validation-benchmarks) are
104 Docker-based CTF-style web vuln challenges — the industry-standard scoring rig for
AI pentest agents. Shannon hit 96.15% on this benchmark in mid-2025.

Integrates with XBOW's standard `make -C benchmarks/NAME {build,run,stop}` flow.
Flag format is deterministic per XBOW's common.mk:
    FLAG{sha256sum(BENCHMARK_NAME_UPPER)}
Ex: XBEN-001-24 → FLAG{6f5902ac...}

Usage:
    scripts/xbow_bench.py --clone
    scripts/xbow_bench.py --list
    scripts/xbow_bench.py --run XBEN-001-24
    scripts/xbow_bench.py --run-many XBEN-001-24,XBEN-003-24,XBEN-005-24
    scripts/xbow_bench.py --run-all
    scripts/xbow_bench.py --score

Prereqs:
    - docker + docker compose
    - ~/Megatron venv activated (running the pipeline)
    - Ollama with configured MODEL_NAME reachable
    - MariaDB reachable (findings stored per-challenge sl_no)
"""
from __future__ import annotations
import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

XBOW_REPO = "https://github.com/xbow-engineering/validation-benchmarks.git"
BASE      = Path(__file__).parent
XBOW_DIR  = BASE / "xbow-benchmarks"
RESULTS   = BASE / "xbow-results.jsonl"


def cmd_clone() -> int:
    if XBOW_DIR.exists():
        print(f"[!] {XBOW_DIR} exists — pulling latest instead")
        return subprocess.call(["git", "-C", str(XBOW_DIR), "pull", "--ff-only"])
    print(f"[*] cloning {XBOW_REPO} → {XBOW_DIR} (~500MB)")
    return subprocess.call(["git", "clone", "--depth", "1", XBOW_REPO, str(XBOW_DIR)])


def _challenge_dirs() -> list[Path]:
    if not XBOW_DIR.exists():
        print("[!] xbow-benchmarks/ not cloned. Run: scripts/xbow_bench.py --clone")
        return []
    return sorted(p for p in (XBOW_DIR / "benchmarks").iterdir()
                  if p.is_dir() and p.name.upper().startswith("XBEN-"))


def _expected_flag(challenge_name: str) -> str:
    digest = hashlib.sha256(challenge_name.upper().encode()).hexdigest()
    return f"FLAG{{{digest}}}"


def cmd_list() -> int:
    challenges = _challenge_dirs()
    if not challenges:
        return 1
    print(f"[*] {len(challenges)} XBOW challenges available")
    for c in challenges:
        meta = c / "benchmark.json"
        if not meta.exists():
            print(f"  {c.name:<15}  (no benchmark.json)")
            continue
        try:
            d = json.loads(meta.read_text())
            print(f"  {c.name:<15}  L{d.get('level','?')}  {d.get('name','')[:60]}  tags={d.get('tags', [])}")
        except (json.JSONDecodeError, OSError):
            print(f"  {c.name:<15}  (benchmark.json unparseable)")
    return 0


def _docker_ports_for(challenge: Path) -> list[int]:
    out = subprocess.run(
        ["docker", "compose", "ps", "--format", "json"],
        cwd=str(challenge), capture_output=True, text=True,
    ).stdout
    ports: set[int] = set()
    for line in out.splitlines():
        try:
            svc = json.loads(line)
        except json.JSONDecodeError:
            continue
        for p in svc.get("Publishers", []) or []:
            pub = p.get("PublishedPort")
            if pub:
                ports.add(int(pub))
    return sorted(ports)


def _make(challenge: Path, target: str, timeout: int = 600) -> int:
    return subprocess.call(
        ["make", "-C", str(challenge), target],
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=timeout,
    )


def _run_megatron(target: str) -> dict:
    sys.path.insert(0, str(BASE.parent))
    from tools import run_recon_pipeline, format_recon_for_llm
    from llm import analyse_target
    results = run_recon_pipeline(target)
    raw = format_recon_for_llm(results)
    return analyse_target(target, raw)


def _score(report: dict, expected_flag: str) -> dict:
    blob = json.dumps(report, default=str)
    hit  = expected_flag in blob
    return {
        "found_flag": hit,
        "n_findings": len(report.get("vulnerabilities", [])),
        "n_critical": sum(1 for v in report.get("vulnerabilities", []) if v.get("severity") == "critical"),
        "n_high":     sum(1 for v in report.get("vulnerabilities", []) if v.get("severity") == "high"),
        "risk_level": report.get("risk_level"),
    }


def cmd_run_one(challenge_name: str) -> int:
    challenge = XBOW_DIR / "benchmarks" / challenge_name
    if not challenge.exists():
        print(f"[!] {challenge_name} not found in {XBOW_DIR/'benchmarks'}")
        return 1

    meta = json.loads((challenge / "benchmark.json").read_text())
    flag = _expected_flag(challenge_name)
    print(f"[*] {challenge_name}  L{meta.get('level','?')}  '{meta.get('name','')[:60]}'")
    print(f"    expected flag: {flag}")

    t_build = time.monotonic()
    print(f"    building (docker compose build)…")
    if _make(challenge, "build", timeout=900) != 0:
        print(f"[!] build failed for {challenge_name}")
        return 2
    build_s = time.monotonic() - t_build

    print(f"    starting (docker compose up --wait)…")
    if _make(challenge, "run", timeout=300) != 0:
        print(f"[!] run failed for {challenge_name}")
        _make(challenge, "stop", timeout=60)
        return 2

    time.sleep(3)
    ports = _docker_ports_for(challenge)
    print(f"    exposed ports: {ports}")
    if not ports:
        print(f"[!] {challenge_name} exposed no published ports; cannot target")
        _make(challenge, "stop", timeout=60)
        return 2

    web_ports = [p for p in ports if p in (80, 8080, 8000, 8443, 3000, 5000, 443)]
    port = web_ports[0] if web_ports else ports[0]
    target = f"127.0.0.1:{port}" if port not in (80, 443) else "127.0.0.1"

    try:
        t_scan = time.monotonic()
        report = _run_megatron(target)
        scan_s = time.monotonic() - t_scan
        result = _score(report, flag)
    except Exception as e:
        print(f"[!] MEGATRON crashed on {challenge_name}: {e}")
        result = {"found_flag": False, "n_findings": 0, "n_critical": 0, "n_high": 0, "risk_level": "ERROR", "error": str(e)[:200]}
        scan_s = 0
    finally:
        _make(challenge, "stop", timeout=60)

    row = {
        "challenge":       challenge_name,
        "level":           meta.get("level"),
        "tags":            meta.get("tags", []),
        "build_s":         round(build_s, 1),
        "scan_s":          round(scan_s, 1),
        "port_used":       port,
        "expected_flag":   flag,
        **result,
    }
    with RESULTS.open("a") as f:
        f.write(json.dumps(row) + "\n")
    print(f"[+] {challenge_name} → flag={result['found_flag']} findings={result['n_findings']} risk={result['risk_level']} (build {build_s:.0f}s + scan {scan_s:.0f}s)\n")
    return 0 if result["found_flag"] else 2


def cmd_run_many(names_csv: str) -> int:
    names = [n.strip() for n in names_csv.split(",") if n.strip()]
    print(f"[*] running {len(names)} challenges: {names}")
    for n in names:
        cmd_run_one(n)
    return cmd_score()


def cmd_run_all() -> int:
    challenges = _challenge_dirs()
    if not challenges:
        return 1
    print(f"[*] running all {len(challenges)} challenges — this will take hours")
    for c in challenges:
        cmd_run_one(c.name)
    return cmd_score()


def cmd_score() -> int:
    if not RESULTS.exists():
        print("[!] no results yet — run at least one challenge first")
        return 1
    rows = [json.loads(l) for l in RESULTS.read_text().splitlines() if l.strip()]
    if not rows:
        print("[!] results file empty")
        return 1
    hits = sum(1 for r in rows if r.get("found_flag"))
    print(f"\n═══════════ MEGATRON XBOW SCOREBOARD ═══════════")
    print(f"  Challenges run:    {len(rows)}")
    print(f"  Flags captured:    {hits}  ({100*hits/len(rows):.1f}%)")
    print(f"  Avg build time:    {sum(r.get('build_s', 0) for r in rows)/len(rows):.0f}s")
    print(f"  Avg scan  time:    {sum(r.get('scan_s', 0)  for r in rows)/len(rows):.0f}s")
    print(f"  Total findings:    {sum(r.get('n_findings', 0) for r in rows)}")
    print(f"  Reference: Shannon 96.15% (hint-free, source-aware)")
    print(f"═════════════════════════════════════════════════\n")
    print("Per-challenge:")
    for r in rows:
        mark = "✓" if r.get("found_flag") else "✗"
        print(f"  {mark} {r['challenge']:<15} L{r.get('level','?')}  findings={r.get('n_findings',0)}  risk={r.get('risk_level','?')}  {r.get('tags', [])}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--clone",    action="store_true")
    g.add_argument("--list",     action="store_true")
    g.add_argument("--run",      metavar="XBEN-NNN-YY")
    g.add_argument("--run-many", metavar="CSV",       help="comma-separated challenge list")
    g.add_argument("--run-all",  action="store_true")
    g.add_argument("--score",    action="store_true")
    args = ap.parse_args()
    if args.clone:    return cmd_clone()
    if args.list:     return cmd_list()
    if args.run:      return cmd_run_one(args.run)
    if args.run_many: return cmd_run_many(args.run_many)
    if args.run_all:  return cmd_run_all()
    if args.score:    return cmd_score()
    return 1


if __name__ == "__main__":
    sys.exit(main())
