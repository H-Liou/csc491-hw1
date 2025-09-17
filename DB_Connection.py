import sys, os
sys.path.append(os.path.abspath(".."))

import sqlite3
import subprocess
import re
from pathlib import Path
from collections import defaultdict
from typing import Tuple

# Try to import RAG and PromptGenerator, skip if not available
try:
    from RAG import *
    from PromptGenerator import *
except ImportError:
    print("Warning: RAG and PromptGenerator modules not found, continuing without them")

DB_PATH       = "DB/funsearch.db"
TRACE_PATH    = Path("ChampSim_CRC2/traces/mcf_250B.trace.gz")
LIB_PATH      = "ChampSim_CRC2/lib/config1.a"
INCLUDE_DIR   = "ChampSim_CRC2/inc"
WARMUP_INST   = "1000000"
SIM_INST      = "10000000"
OUT_DIR   = Path("ChampSim_CRC2/new_policies")

OUT_DIR.mkdir(exist_ok=True, parents=True)

CSV_PATH = "policy_stats_mcf.csv"

def compile_policy(src: Path) -> Path:
    """g++ <src> -> <src>.out  (always recompiles)"""
    exe = OUT_DIR / (src.stem + ".out")
    try:
        subprocess.run(
            [
                "g++",
                "-Wall",
                "--std=c++11",
                str(src),
                LIB_PATH,
                "-o",
                str(exe)
            ],
            check=True,
        )
        return exe
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Compilation failed: {e}")
        raise


def run_policy(exe: Path) -> str:
    """Execute ChampSim binary and capture stdout."""
    res = subprocess.run(
        [
            str(exe),
            "-warmup_instructions", WARMUP_INST,
            "-simulation_instructions", SIM_INST,
            "-traces", str(TRACE_PATH),
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    return res.stdout


def parse_llc_stats(text: str) -> Tuple[int, int]:
    """
    Extract 'LLC TOTAL ACCESS: <A> HIT: <H>' and return (A, H).
    Raises if pattern not found.
    """
    m = re.search(r"LLC TOTAL\s+ACCESS:\s+(\d+)\s+HIT:\s+(\d+)", text)
    if not m:
        raise RuntimeError("LLC TOTAL line not found in ChampSim output")
    access, hits = map(int, m.groups())
    return access, hits


workloads = {
    "astar": {
        "description": (
            "The A* workload models a pathfinding algorithm commonly used in game AI and robotics. "
            "It is characterized by deeply nested control-flow, frequent branching, and high rates of speculative execution due to unpredictable decisions in the search space. "
            "Memory access patterns are moderately sparse with irregular access strides and limited reuse, making it a stress test for branch predictors and instruction-level parallelism. "
            "Cache-wise, it has a moderate trace size and shows limited temporal locality, challenging replacement policies to avoid pollution from control-dominated paths."
        ),
        "trace": "ChampSim_CRC2/traces/astar_313B.trace.gz"
    },
    "lbm": {
        "description": (
            "LBM (Lattice-Boltzmann Method) simulates fluid dynamics by performing stencil-based updates across 3D grids. "
            "It exhibits dense, regular memory access patterns with high spatial locality but limited temporal reuse. "
            "Cache pressure is significant due to large working sets and repetitive accesses across neighboring cells, making it ideal for evaluating how well a policy handles spatial locality and prefetching alignment. "
            "LBM's deterministic access stride also exposes weaknesses in replacement strategies that fail to retain blocks until their reuse window arrives."
        ),
        "trace": "ChampSim_CRC2/traces/lbm_564B.trace.gz"
    },
    "mcf": {
        "description": (
            "The MCF workload solves the Minimum Cost Flow problem using network simplex algorithms. "
            "It is known for pointer-chasing behavior, deep data dependencies, and highly irregular, sparse memory accesses. "
            "This leads to poor cache locality and low IPC due to frequent pipeline stalls from memory latency. "
            "MCF is a classical example of memory-bound workloads and is particularly harsh on cache replacement policies that rely on recency or frequency heuristics. "
            "Its access patterns are difficult to predict, making it valuable for testing adaptive and learned policies."
        ),
        "trace": "ChampSim_CRC2/traces/mcf_250B.trace.gz"
    },
    "milc": {
        "description": (
            "MILC simulates Quantum Chromodynamics (QCD) calculations on 4D space-time lattices, often used in particle physics research. "
            "The workload includes extensive use of floating-point arithmetic within nested loops, coupled with both regular and irregular memory accesses. "
            "MILC combines phases of high spatial reuse with intermittent pointer dereferencing and indirect indexing, leading to inconsistent locality characteristics. "
            "This makes it a strong candidate for evaluating how well a replacement policy can respond to phase changes in workload behavior."
        ),
        "trace": "ChampSim_CRC2/traces/milc_409B.trace.gz"
    },
    "omnetpp": {
        "description": (
            "Omnet++ models a discrete-event network simulator, simulating communication protocols with complex object-oriented structures. "
            "It features heavy dynamic memory allocation, small object usage, and highly unpredictable control flow. "
            "Its access pattern is dominated by pointer dereferencing and virtual function calls, resulting in low spatial and temporal locality. "
            "Frequent branching and irregular memory usage make it a demanding workload for branch predictors and cache systems, especially those relying on stable reuse signals."
        ),
        "trace": "ChampSim_CRC2/traces/omnetpp_17B.trace.gz"
    }
}

policies = {
    "LRU": {
        "description": (
            "Least Recently Used (LRU) replacement policy evicts the cache line that has not been accessed for the longest time. "
            "It assumes temporal locality—recently used data is more likely to be used again. "
            "This simple stack-based heuristic is hardware-friendly but can perform poorly under non-recurring access patterns or streaming workloads."
        ),
        "file_path": "ChampSim_CRC2/champ_repl_pol/lru.cc"
    },
    "Hawkeye": {
        "description": (
            "Hawkeye is a predictive replacement policy that leverages Belady's MIN algorithm as an oracle during training phases. "
            "It classifies memory accesses as cache-friendly or cache-averse using past reuse behavior. "
            "Hawkeye tracks the hit/miss patterns of PCs and predicts future reuse, evicting lines unlikely to be reused. "
            "This learned policy often outperforms heuristics in workloads with high variance in reuse patterns."
        ),
        "file_path": "ChampSim_CRC2/champ_repl_pol/hawkeye_final.cc"
    },
    "Less is More": {
        "description": (
            "The Less is More (LIME) policy maintains a smaller but more predictable working set in cache by selectively caching only highly reusable data. "
            "It introduces filters or confidence thresholds to reduce cache pollution, especially effective in workloads with sparse reuse or high noise. "
            "By avoiding over-commitment, it reduces thrashing and improves effective cache utilization in irregular access patterns."
        ),
        "file_path": "ChampSim_CRC2/champ_repl_pol/lime.cc"
    },
    "Multiperspective": {
        "description": (
            "Multiperspective replacement integrates multiple heuristics—temporal (recency), spatial (block adjacency), and frequency (access counts)—"
            "to make informed eviction decisions. "
            "It balances short-term reuse with longer-term utility predictions, offering adaptability across diverse workloads. "
            "This hybrid strategy is especially useful in mixed compute and memory-intensive applications."
        ),
        "file_path": "ChampSim_CRC2/champ_repl_pol/dancrc2.cc"
    },
    "Reordering-based Cache Replacement": {
        "description": (
            "This policy reorders memory accesses to increase temporal locality before they reach the cache. "
            "By dynamically reshaping the access stream (e.g., via scheduling queues or address clustering), it reduces conflict misses and enhances reuse. "
            "The effectiveness is tied to how well reordering aligns with the underlying data reuse patterns of the workload."
        ),
        "file_path": "ChampSim_CRC2/champ_repl_pol/red.cc"
    },
    "Ship++": {
        "description": (
            "SHiP++ (Signature-based Hit Predictor) is an enhancement over the SHiP policy, which uses PC-based signatures and outcome history to track line usefulness. "
            "SHiP++ incorporates refined predictors, decay mechanisms, and hybrid reuse classification to better handle pathological cases (e.g., thrashing). "
            "It provides strong performance across workloads with dynamic and complex reuse patterns."
        ),
        "file_path": "ChampSim_CRC2/champ_repl_pol/ship++.cc"
    }
}

# --- Step 1: Initialize ---
performance_data = defaultdict(list)

# Use pre-computed results since we're on macOS and binaries are Linux-specific
print("[INFO] Using pre-computed performance data (binaries are Linux-specific)")
perf_data={
    'astar': [0.45454223305787467, 0.3573547794394494, 0.38901773944350737, 0.03709567109384967, 0.4110201774653078, 0.33821173935846005], 
    'lbm': [0.43985783443540666, 0.27289983516244354, 0.32972240516582263, 0.011593643367720617, 0.19358477211349756, 0.2615846099982021], 
    'mcf': [0.4074020886631043, 0.5087725688923012, 0.5230175409101099, 0.515161598323247, 0.5200312710592792, 0.524743749964974], 
    'milc': [0.3219114100958022, 0.06456693483565899, 0.23460321368313578, 0.00026430697263517673, 0.14627399581453615, 0.054986712238499026],
    'omnetpp': [0.4606533811310401, 0.6753672808393627, 0.6900525496418154, 0.008547620325799737, 0.4621028207407054, 0.698462878241108]
}

# Step 1: Compute the average hit rate (score) per policy
policy_hit_rates = defaultdict(list)  # key = policy_name, value = list of hit rates

# Populate policy_hit_rates from performance_data
for workload_name in workloads:
    for i, policy_name in enumerate(policies):
        hit_rate = perf_data[workload_name][i]
        policy_hit_rates[policy_name].append(hit_rate)

# Calculate average score for each policy
policy_scores = {
    policy_name: sum(hit_rates) / len(hit_rates) if hit_rates else 0.0
    for policy_name, hit_rates in policy_hit_rates.items()
}

print("Policy Scores:")
for policy, score in policy_scores.items():
    print(f"  {policy}: {score:.4f}")

# Create DB directory if it doesn't exist
Path("DB").mkdir(exist_ok=True)

# Create a database connection (creates file if it doesn't exist)
conn = sqlite3.connect(DB_PATH)

# Create a cursor
c = conn.cursor()

# Create the table
c.execute('''
    CREATE TABLE IF NOT EXISTS experiments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        workload TEXT NOT NULL,
        policy TEXT NOT NULL,
        policy_description TEXT NOT NULL,
        workload_description TEXT NOT NULL,
        cpp_file_path TEXT NOT NULL,
        cache_hit_rate REAL NOT NULL,
        score REAL NOT NULL
    )
''')

# Clear existing data
c.execute('DELETE FROM experiments')

# Commit and close
conn.commit()
conn.close()

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

for workload_name, wdata in workloads.items():
    workload_desc = wdata["description"]
    
    for i, (policy_name, pdata) in enumerate(policies.items()):
        policy_desc = pdata["description"]
        cpp_path = pdata["file_path"]

        hit_rate = perf_data[workload_name][i]
        score = policy_scores[policy_name]  # use the precomputed average score

        c.execute('''
            INSERT INTO experiments (
                workload,
                policy,
                policy_description,
                workload_description,
                cpp_file_path,
                cache_hit_rate,
                score
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            workload_name,
            policy_name,
            policy_desc,
            workload_desc,
            cpp_path,
            hit_rate,
            score
        ))

conn.commit()
conn.close()

print("Data has been successfully inserted into the funsearch.db database!")

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

for i, (policy_name, pdata) in enumerate(policies.items()):
        policy_desc = pdata["description"]
        cpp_path = pdata["file_path"]
        score = policy_scores[policy_name]

        c.execute('''
            INSERT INTO experiments (
                workload,
                policy,
                policy_description,
                workload_description,
                cpp_file_path,
                cache_hit_rate,
                score
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            "all",
            policy_name,
            policy_desc,
            "",
            cpp_path,
            score,
            score
        ))

conn.commit()
conn.close()

print("Database setup complete!")

# Test the RAG functionality if available
try:
    from RAG import ExperimentRAG
    
    WORKLOAD="all"
    rag = ExperimentRAG(DB_PATH)
    top5 = rag.get_top_policies_by_score(WORKLOAD, top_n=5)

    if not top5:
        raise RuntimeError("No RAG data for workload")

    print("\nTop 5 policies by score:")
    for i, policy in enumerate(top5):
        print(f"{i+1}. {policy['policy']} --- {policy['score']:.4f}")
        
except ImportError:
    print("\nRAG module not available, skipping RAG test")
except Exception as e:
    print(f"\nRAG test failed: {e}")

print("\nScript completed successfully!")