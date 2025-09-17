#!/usr/bin/env python3

import argparse, os, re, subprocess, sys, time, csv
from pathlib import Path
from typing import List, Dict, Tuple, Optional

# -----------------------------------------------------------------------------
# Paths & defaults (mirror run_loop_docker.py)
# -----------------------------------------------------------------------------
DB_PATH = "DB/funsearch.db"  # not used here, kept for consistency
LIB_PATH = "ChampSim_CRC2/lib/config1.a"
INCLUDE_DIR = "ChampSim_CRC2/inc"
DOCKER_IMAGE = "champsim-runner"

# Host ↔ container path translation. The workspace root is mounted at /app.
_HOST_ROOT = Path(os.getcwd()).resolve()
_CONTAINER_ROOT = Path("/app")


def _to_container_path(path: Path) -> str:
    """Map a host path into the container's /app mount if possible."""
    try:
        relative = path.resolve().relative_to(_HOST_ROOT)
    except ValueError:
        return str(path)
    return str(_CONTAINER_ROOT / relative)

WARMUP_INST_DEFAULT = "1000000"
SIM_INST_DEFAULT    = "10000000"

# Standard 5 workloads with fixed trace paths (same as your run_loop_docker.py)
WORKLOADS = [
    {"name": "astar",   "trace_path": "ChampSim_CRC2/traces/astar_313B.trace.gz"},
    {"name": "lbm",     "trace_path": "ChampSim_CRC2/traces/lbm_564B.trace.gz"},
    {"name": "mcf",     "trace_path": "ChampSim_CRC2/traces/mcf_250B.trace.gz"},
    {"name": "milc",    "trace_path": "ChampSim_CRC2/traces/milc_409B.trace.gz"},
    {"name": "omnetpp", "trace_path": "ChampSim_CRC2/traces/omnetpp_17B.trace.gz"}
]

# -----------------------------------------------------------------------------
# Docker helpers (identical behavior to run_loop_docker.py)
# -----------------------------------------------------------------------------
def run_in_docker(command: List[str], workdir: str = "/app") -> subprocess.CompletedProcess:
    docker_cmd = [
        "docker", "run", "--platform", "linux/amd64", "--rm",
        "-v", f"{os.getcwd()}:/app",
        "-w", workdir,
        DOCKER_IMAGE, "bash", "-c", " ".join(command),
    ]
    return subprocess.run(docker_cmd, check=True, capture_output=True, text=True)

def compile_policy(cc: Path) -> Path:
    """
    Compile the provided C++ policy file into an executable inside Docker,
    linking against the ChampSim static library (config1.a).
    """
    exe = cc.with_suffix(".out")
    cc_in_container = _to_container_path(cc)
    exe_in_container = _to_container_path(exe)
    compile_cmd = [
        "g++", "-Wall", "--std=c++11",
        "-I", INCLUDE_DIR,
        cc_in_container, LIB_PATH,
        "-o", exe_in_container,
    ]
    try:
        print(f"🔨 Compiling {cc} → {exe.name}")
        run_in_docker(compile_cmd)
        return exe
    except subprocess.CalledProcessError as e:
        print(f"❌ Docker compilation failed (exit {e.returncode}).")
        if e.stderr:
            print("----- stderr -----")
            print(e.stderr)
        if e.stdout:
            print("----- stdout -----")
            print(e.stdout)
        raise

def run_executable(exe: Path, trace_path: Path, warmup: str, sim: str) -> str:
    trace_in_container = _to_container_path(trace_path)
    exe_in_container = _to_container_path(exe)
    run_cmd = [
        exe_in_container,
        "-warmup_instructions", warmup,
        "-simulation_instructions", sim,
        "-traces", trace_in_container,
    ]
    start = time.time()
    print(f"⏳ Running {exe.name} on {trace_path} ...")
    try:
        result = run_in_docker(run_cmd)
        print(f"🏁 Finished in {time.time()-start:.2f}s")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"❌ Docker simulation failed (exit {e.returncode}).")
        if e.stderr:
            print("----- stderr -----")
            print(e.stderr)
        if e.stdout:
            print("----- stdout -----")
            print(e.stdout)
        raise

# -----------------------------------------------------------------------------
# Parsers
# -----------------------------------------------------------------------------
_IPC_PATTERNS = [
    r"CPU\s*\d+\s+cumulative\s+IPC:\s*([0-9]*\.?[0-9]+)",  # "CPU 0 cumulative IPC: 1.2345"
    r"Overall\s+IPC:\s*([0-9]*\.?[0-9]+)",                 # "Overall IPC: 1.23"
]

def parse_ipc(output: str) -> float:
    for pat in _IPC_PATTERNS:
        m = re.search(pat, output, flags=re.IGNORECASE)
        if m:
            return float(m.group(1))
    # Heartbeats and summaries sometimes include "cumulative" or "cummulative" IPC.
    cum_matches = re.findall(r"c[u]?mmulative\s+IPC:\s*([0-9]*\.?[0-9]+)", output, flags=re.IGNORECASE)
    if cum_matches:
        return float(cum_matches[-1])
    # Fallback: compute from totals if present
    m_instr = re.search(r"Total\s+Instructions:\s*([0-9]+)", output, flags=re.IGNORECASE)
    m_cycles = re.search(r"Total\s+Cycles:\s*([0-9]+)", output, flags=re.IGNORECASE)
    if m_instr and m_cycles:
        instr = float(m_instr.group(1))
        cycles = float(m_cycles.group(1))
        if cycles > 0:
            return instr / cycles
    # Debug dump tail if not found
    print("⚠️  IPC not found; last 500 chars of output:")
    print("="*60)
    print(output[-500:])
    print("="*60)
    raise RuntimeError("IPC not found in simulator output.")

def parse_cache_hit_rate(output: str) -> Optional[float]:
    m = re.search(r"LLC TOTAL\s+ACCESS:\s+(\d+)\s+HIT:\s+(\d+)", output)
    if not m: 
        return None
    access, hit = int(m.group(1)), int(m.group(2))
    return (hit / access) if access > 0 else 0.0

# -----------------------------------------------------------------------------
# Evaluation
# -----------------------------------------------------------------------------
def pick_workloads(names: List[str]) -> List[Dict[str, str]]:
    if not names:
        return WORKLOADS
    name_set = set(n.strip().lower() for n in names)
    selected = [w for w in WORKLOADS if w["name"].lower() in name_set]
    missing = name_set - set(w["name"].lower() for w in selected)
    if missing:
        raise ValueError(f"Unknown workload(s): {', '.join(sorted(missing))}")
    return selected

def evaluate_policy(cc_path: Path, workloads: List[Dict[str,str]], warmup: str, sim: str) -> Tuple[float, list]:
    exe = compile_policy(cc_path)
    results = []
    for w in workloads:
        out = run_executable(exe, Path(w["trace_path"]), warmup, sim)
        ipc = parse_ipc(out)
        hit = parse_cache_hit_rate(out)
        results.append({
            "workload": w["name"],
            "policy": cc_path.stem,
            "cpp_file_path": str(cc_path),
            "ipc": ipc,
            "cache_hit_rate": hit if hit is not None else "",
        })
        print(f"   • {w['name']}: IPC={ipc:.4f}" + (f", HitRate={hit:.4f}" if hit is not None else ""))
    mean_ipc = sum(r["ipc"] for r in results) / len(results) if results else 0.0
    return mean_ipc, results

def write_csv(rows: list, out_path: Path):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["workload","policy","cpp_file_path","ipc","cache_hit_rate"]
    import csv
    with out_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)

# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(description="Evaluate a cache replacement policy for IPC (Docker).")
    p.add_argument("--policy", required=True, help="Path to the C++ policy file (e.g., ChampSim_CRC2/new_policies/047_...cc)")
    p.add_argument("--workloads", nargs="*", default=["astar","lbm","mcf","milc","omnetpp"], help="Subset of workloads to run")
    p.add_argument("--warmup", default=WARMUP_INST_DEFAULT, help="Warmup instructions")
    p.add_argument("--sim", default=SIM_INST_DEFAULT, help="Simulation instructions")
    p.add_argument("--out", default="results/ipc_results.csv", help="CSV output path")
    args = p.parse_args()

    # Sanity: Docker available?
    try:
        subprocess.run(["docker","--version"], check=True, capture_output=True)
        print("✅ Docker detected")
    except Exception:
        print("❌ Docker is not available. Install Docker and try again.")
        sys.exit(1)

    cc_path = Path(args.policy)
    if not cc_path.exists():
        print(f"❌ Policy file not found: {cc_path}")
        sys.exit(1)

    selected = pick_workloads(args.workloads)
    print(f"🎯 Running workloads: {[w['name'] for w in selected]}")
    mean_ipc, rows = evaluate_policy(cc_path, selected, str(args.warmup), str(args.sim))

    out_path = Path(args.out)
    write_csv(rows, out_path)
    print(f"\n📄 Wrote per-workload results → {out_path}")
    print(f"📈 Mean IPC (across {len(selected)} workloads): {mean_ipc:.4f}")

if __name__ == "__main__":
    main()
