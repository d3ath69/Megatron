#!/usr/bin/env python3
"""
MEGATRON XBOW benchmark harness.

The XBOW Validation Benchmarks (github.com/xbow-engineering/validation-benchmarks) are
104 Docker-based CTF-style web vuln challenges — the industry-standard scoring rig for
AI pentest agents. Shannon hit 96.15% on this benchmark in mid-2025.

This script clones the repo, iterates challenges, runs MEGATRON's pipeline against each,
compares output to the known-good flag, tallies score.

Usage:
    scripts/xbow_bench.py --clone           # one-time: clone XBOW repo to scripts/xbow-benchmarks/
    scripts/xbow_bench.py --list            # list all 104 challenges
    scripts/xbow_bench.py --run XBEN-001    # run one challenge
    scripts/xbow_bench.py --run-all         # run all 104 (takes hours)
    scripts/xbow_bench.py --score           # show scoreboard from previous runs

Prereqs on the host running this script:
    - docker (for challenge containers)
    - ~/Megatron venv activated
    - Ollama with configured MODEL_NAME reachable
    - Optionally: MariaDB reachable (findings will be stored per-challenge sl_no)
"""
from __future__ import annotations
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

XBOW_REPO = "https://github.com/xbow-engineering/validation-benchmarks.git"
XBOW_DIR  = Path(__file__).parent / "xbow-benchmarks"
RESULTS   = Path(__file__).parent / "xbow-results.jsonl"


def cmd_clone() -> int:
    if XBOW_DIR.exists():
        print(f"[!] {XBOW_DIR} already exists — pulling latest instead")
        return subprocess.call(["git", "-C", str(XBOW_DIR), "pull", "--ff-only"])
    print(f"[*] cloning {XBOW_REPO} → {XBOW_DIR} (~500MB)")
    return subprocess.call(["git", "clone", "--depth", "1", XBOW_REPO, str(XBOW_DIR)])


def _challenge_dirs() -> list[Path]:
    if not XBOW_DIR.exists():
        print("[!] xbow-benchmarks/ not cloned. Run: scripts/xbow_bench.py --clone")
        return []
    return sorted(p for p in (XBOW_DIR / "benchmarks").iterdir() if p.is_dir() and p.name.startswith("XBEN-"))


def cmd_list() -> int:
    challenges = _challenge_dirs()
    if not challenges:
        return 1
    print(f"[*] {len(challenges)} XBOW challenges available")
    for c in challenges:
        meta = c / "benchmark.json"
        if meta.exists():
            try:
                d = json.loads(meta.read_text())
                print(f"  {c.name:<12}  {d.get('title', '(no title)'):<50}  tags={d.get('tags', [])}")
            except (json.JSONDecodeError, OSError):
                print(f"  {c.name:<12}  (benchmark.json unparseable)")
        else:
            print(f"  {c.name:<12}  (no benchmark.json)")
    return 0


def _start_challenge(challenge: Path) -> tuple[str, int] | None:
    compose = challenge / "docker-compose.yml"
    if not compose.exists():
        print(f"  [!] {challenge.name}: no docker-compose.yml, skipping")
        return None
    print(f"  [*] starting {challenge.name} via docker compose")
    if subprocess.call(["docker", "compose", "-f", str(compose), "up", "-d", "--build"]) != 0:
        return None
    time.sleep(5)
    port_out = subprocess.run(
        ["docker", "compose", "-f", str(compose), "port", "web", "80"],
        capture_output=True, text=True,
    ).stdout.strip()
    if ":" not in port_out:
        print(f"  [!] {challenge.name}: couldn't resolve challenge port")
        return None
    port = int(port_out.rsplit(":", 1)[1])
    return ("127.0.0.1", port)


def _stop_challenge(challenge: Path) -> None:
    subprocess.call(
        ["docker", "compose", "-f", str(challenge / "docker-compose.yml"), "down", "-v"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def _run_megatron_pipeline(target: str) -> dict:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from tools import run_recon_pipeline, format_recon_for_llm
    from llm import analyse_target
    results = run_recon_pipeline(target)
    raw = format_recon_for_llm(results)
    return analyse_target(target, raw)


def _score_report(report: dict, expected_flag: str) -> dict:
    txt = json.dumps(report, default=str).lower()
    hit = expected_flag.lower() in txt if expected_flag else False
    return {
        "found_flag":         hit,
        "n_findings":         len(report.get("vulnerabilities", [])),
        "n_critical":         sum(1 for v in report.get("vulnerabilities", [])
                                   if v.get("severity") == "critical"),
        "n_high":             sum(1 for v in report.get("vulnerabilities", [])
                                   if v.get("severity") == "high"),
        "risk_level":         report.get("risk_level"),
    }


def cmd_run_one(challenge_name: str) -> int:
    challenge = XBOW_DIR / "benchmarks" / challenge_name
    if not challenge.exists():
        print(f"[!] {challenge_name} not found in {XBOW_DIR/'benchmarks'}")
        return 1
    meta = json.loads((challenge / "benchmark.json").read_text())
    expected_flag = meta.get("flag", "")
    print(f"[*] running {challenge_name}  '{meta.get('title', '')}'  flag='{expected_flag}'")

    target = _start_challenge(challenge)
    if not target:
        return 1
    host, port = target
    tgt_str = f"{host}:{port}" if port != 80 else host

    try:
        t0 = time.monotonic()
        report = _run_megatron_pipeline(tgt_str)
        elapsed = time.monotonic() - t0
        score = _score_report(report, expected_flag)
    finally:
        _stop_challenge(challenge)

    row = {
        "challenge":  challenge_name,
        "title":      meta.get("title", ""),
        "tags":       meta.get("tags", []),
        "elapsed_s":  round(elapsed, 1),
        **score,
    }
    with RESULTS.open("a") as f:
        f.write(json.dumps(row) + "\n")
    print(f"[+] {challenge_name} → {row}")
    return 0 if score["found_flag"] else 2


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
    total, hits = len(rows), sum(1 for r in rows if r.get("found_flag"))
    print(f"\n═══ MEGATRON XBOW SCOREBOARD ═══")
    print(f"  Challenges run: {total}")
    print(f"  Flags captured: {hits}  ({100*hits/total:.1f}%)")
    print(f"  Avg elapsed:    {sum(r['elapsed_s'] for r in rows)/total:.1f}s")
    print(f"  Total findings: {sum(r['n_findings'] for r in rows)}")
    print(f"  Reference: Shannon 96.15% (hint-free, source-aware).\n")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--clone",   action="store_true", help="Clone the XBOW benchmarks repo")
    g.add_argument("--list",    action="store_true", help="List available challenges")
    g.add_argument("--run",     metavar="XBEN-NNN",  help="Run a single challenge")
    g.add_argument("--run-all", action="store_true", help="Run every challenge (hours)")
    g.add_argument("--score",   action="store_true", help="Show scoreboard from prior runs")
    args = ap.parse_args()

    if args.clone:   return cmd_clone()
    if args.list:    return cmd_list()
    if args.run:     return cmd_run_one(args.run)
    if args.run_all: return cmd_run_all()
    if args.score:   return cmd_score()
    return 1


if __name__ == "__main__":
    sys.exit(main())
