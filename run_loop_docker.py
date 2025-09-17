#!/usr/bin/env python3
import sys, os
sys.path.append(os.path.abspath(".."))

from dotenv import load_dotenv
import re
import time
import sqlite3
import subprocess
from pathlib import Path
from typing import Optional, Tuple
from openai import AzureOpenAI
from RAG import ExperimentRAG
from PromptGenerator import PolicyPromptGenerator


# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────
DB_PATH = "DB/funsearch.db"
LIB_PATH = "ChampSim_CRC2/lib/config1.a"
INCLUDE_DIR = "ChampSim_CRC2/inc"
EXAMPLE_DIR = Path("ChampSim_CRC2/new_policies")

WARMUP_INST = "1000000"
SIM_INST = "10000000"

MODEL_FAST   = "o4-mini"
MODEL_BASE   = "o3-mini"
MODEL_STRONG = "gpt-4.1"
MODEL        = MODEL_STRONG
ITERATIONS = 50

EXAMPLE_DIR.mkdir(parents=True, exist_ok=True)

# Multi-candidate exploration per iteration

CANDIDATES = 3
TEMP = 0.2

# o-series models do not support temperature; see Azure OpenAI docs.
def _is_o_series(model_name: str) -> bool:
    return str(model_name).lower().startswith("o")

workloads = [
    {"name": "astar", "trace_path": "ChampSim_CRC2/traces/astar_313B.trace.gz"},
    {"name": "lbm", "trace_path": "ChampSim_CRC2/traces/lbm_564B.trace.gz"},
    {"name": "mcf", "trace_path": "ChampSim_CRC2/traces/mcf_250B.trace.gz"},
    {"name": "milc", "trace_path": "ChampSim_CRC2/traces/milc_409B.trace.gz"},
    {"name": "omnetpp", "trace_path": "ChampSim_CRC2/traces/omnetpp_17B.trace.gz"}
]

# ──────────────────────────────────────────────────────────────────────────────
# Docker-based execution helpers
# ──────────────────────────────────────────────────────────────────────────────
def run_in_docker(command: list, workdir: str = "/app") -> subprocess.CompletedProcess:
    """Run a command inside a Docker container"""
    docker_cmd = [
        "docker", "run", "--platform", "linux/amd64", "--rm",
        "-v", f"{os.getcwd()}:/app",
        "-w", workdir,
        "champsim-runner",
        "bash", "-c",
        " ".join(command)
    ]
    return subprocess.run(docker_cmd, check=True, capture_output=True, text=True)

def sanitize(name: str) -> str:
    print("     3. 🔧 [Sanitize] Cleaning policy name")
    return "".join(c if c.isalnum() else "_" for c in name).strip("_").lower()

def parse_policy_content(text: str,) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    def _extract(pattern: str):
        m = re.search(pattern, text, flags=re.DOTALL | re.IGNORECASE)
        return m.group(1).strip() if m else None

    name = _extract(r"##\s*Policy\s*Name\s*\n(.*?)\n")
    desc = _extract(r"##\s*Policy\s*Description\s*\n(.*?)\n")
    code = _extract(r"```cpp\s*(.*?)\s*```")

    # print(f"📦 [Parse] Extracted policy: {name}")
    return name, desc, code

def compile_policy(cc: Path) -> Path:
    print(f"     4. 🔨 [Compile] Compiling: {cc.name} using Docker\n")

    exe = cc.with_suffix(".out")
    
    # Use Docker to compile
    compile_cmd = [
        "g++", "-Wall", "--std=c++11",
        "-I", INCLUDE_DIR,
        str(cc), LIB_PATH,
        "-o", str(exe)
    ]
    
    try:
        run_in_docker(compile_cmd)
        return exe
    except subprocess.CalledProcessError as e:
        print(f"Docker compilation failed (exit {e.returncode}).")
        if e.stderr:
            print("----- stderr -----")
            print(e.stderr)
        if e.stdout:
            print("----- stdout -----")
            print(e.stdout)
        raise

def run_policy(exe: Path, trace_path: Path) -> str:
    
    print(f"     5. ⏳ [Simulation] Starting simulation for: {exe.name} and {str(trace_path)}")
    start_time = time.time()

    # Use Docker to run the simulation
    run_cmd = [
        str(exe),
        "-warmup_instructions", WARMUP_INST,
        "-simulation_instructions", SIM_INST,
        "-traces", str(trace_path)
    ]
    
    try:
        result = run_in_docker(run_cmd)
        duration = time.time() - start_time
        print(f"     6. 🏁 [Simulation] Finished in {duration:.2f} seconds for: {exe.name} and {trace_path}")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Docker simulation failed: {e}")
        raise

def parse_hit_rate(output: str) -> float:
    print("     7. 📊 [Metric] Parsing cache hit rate from output")

    # Try the standard format first
    m = re.search(r"LLC TOTAL\s+ACCESS:\s+(\d+)\s+HIT:\s+(\d+)", output)
    if m:
        access_count = int(m.group(1))
        hit_count = int(m.group(2))
        if access_count > 0:
            hit_rate = hit_count / access_count
            print(f"     📊 [Metric] Found LLC stats: {hit_count}/{access_count} = {hit_rate:.4f}")
            return hit_rate
        else:
            print("     ⚠️  [Warning] Zero LLC accesses found")
            return 0.0
    
    # If not found, show debug info
    print("❌ [Debug] LLC TOTAL not found in output. Here's the last 500 chars:")
    print("=" * 50)
    print(output[-500:])
    print("=" * 50)
    raise RuntimeError("LLC TOTAL not found")

def record(workload, name, desc, cc: Path, rate, workload_desc):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """
      INSERT INTO experiments
        (workload, policy, policy_description, workload_description,
         cpp_file_path, cache_hit_rate, score)
      VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (workload, name, desc, workload_desc, str(cc), rate, rate),
    )
    conn.commit()
    conn.close()

# ──────────────────────────────────────────────────────────────────────────────
# Main Feedback Loop with Reward/Penalty
# ──────────────────────────────────────────────────────────────────────────────
def main():
    
    WORKLOAD = "all"

    # Check if Docker is available
    try:
        subprocess.run(["docker", "--version"], check=True, capture_output=True)
        print("✅ Docker is available")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ Docker is not available. Please install Docker to run this script.")
        return

    # 1) Setup RAG and PromptGenerator
    rag = ExperimentRAG(DB_PATH)
    prompt_gen = PolicyPromptGenerator(DB_PATH)
    load_dotenv(dotenv_path=Path(".env"), override=False)

    endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
    api_key = os.getenv("AZURE_OPENAI_API_KEY")
    api_version = os.getenv("AZURE_OPENAI_API_VERSION", "2024-06-01")
    if not endpoint or not api_key:
        raise RuntimeError("Missing AZURE_OPENAI_ENDPOINT or AZURE_OPENAI_API_KEY in environment.")

    client = AzureOpenAI(
        azure_endpoint=endpoint,
        api_key=api_key,
        api_version=api_version,
    )

    top_policies = rag.get_top_policies_by_score(WORKLOAD, top_n=5)
    workload_desc, traces = rag.get_all_workloads_with_description_and_traces()

    best_hit = top_policies[0]["score"]
    policy_summary = "\n".join(
            f"Policy: {p['policy']}\nHit Rate: {float(p['score']):.2%}\nDescription:\n{p['policy_description']}\n"
            for p in top_policies
        )

    print(f"     📈 [Init] Starting best cache hit rate: {best_hit:.2%}")

    prev_name = prev_desc = prev_code = None
    current_hit = best_hit

    # Iterative search with multi-candidate temperature sweep
    for i in range(ITERATIONS):

        SEED_KNOWLEDGE = (
            "You can compose policies from these compact mechanisms that fit <=64 KiB metadata:\\n"
            "- RRIP/DRRIP: 2-bit RRPV; SRRIP vs BRRIP with set-dueling and a 10-bit PSEL selector.\\n"
            "- DIP-style insertion depth control: choose between LIP/BIP using 32–64 leader sets.\\n"
            "- SHiP-lite: 4–6 bit PC signatures with 2-bit outcome counters to bias insertion depth.\\n"
            "- Streaming detector: detect near-monotonic address deltas; bypass or insert at distant RRPV.\\n"
            "- Dead-block approximation: tiny per-line reuse counters, periodic decay.\\n"
            "Keep the total metadata <= 64 KiB across all structures. Prefer small saturating counters."
        )

        if i == 0:
            prompt = (
                f"The following workloads are under consideration:\\n"
                f"{workload_desc}\\n\\n"
                "The top-performing cache replacement policies from past experiments are:\\n"
                f"{policy_summary}\\n\\n"
                "Design goal: Propose a new cache replacement policy that outperforms the above across these workloads.\\n"
                "Constraints: Implementation must compile inside the provided template and keep total metadata \\&lt;= 64 KiB.\\n\\n"
                "Diversity requirements (generate distinct ideas):\\n"
                "• Vary reuse prediction source (recency vs PC/signature vs address bits).\\n"
                "• Vary insertion depth (e.g., DIP/DRRIP-like) and protection strategy.\\n"
                "• Consider a streaming/scan detector to avoid polluting working sets.\\n\\n"
                "Seed mechanisms you may combine:\\n"
                f"{SEED_KNOWLEDGE}\\n\\n"
                "Think briefly before coding (2–3 bullets), then commit to ONE design:\\n"
                "1) List three candidate mechanisms and the specific workloads they help (astar, lbm, mcf, milc, omnetpp).\\n"
                "2) Choose the best one, explaining why it dominates on average.\\n"
                "3) Provide a complete C++ implementation that compiles with the given template.\\n\\n"
                "Use the exact output format below:\\n\\n"
                "## Policy Name\\n&lt;name&gt;\\n\\n"
                "## Policy Description\\n&lt;one paragraph describing the approach and why it helps&gt;\\n\\n"
                "## C++ Implementation\\n"
                f"{prompt_gen._get_code_template()}\\n"
            )
        else:
            if current_hit > best_hit:
                feedback = (
                    f"Great! Policy improved from {best_hit:.2%} to {current_hit:.2%}. Please refine further, preserving the winning mechanism."
                )
                best_hit = current_hit
            else:
                feedback = (
                    f"Policy hit rate was {current_hit:.2%}, not better than {best_hit:.2%}. Try a materially different mechanism."
                )
            prompt = (
                f"The following workloads are under consideration:\\n"
                f"{workload_desc}\\n\\n"
                f"Your previous design was **{prev_name}**:\\n\\n"
                f"Description:\\n{prev_desc}\\n\\n"
                f"Implementation:\\n```cpp\\n{prev_code}\\n```\\n\\n"
                f"Feedback from the last run:\\n{feedback}\\n\\n"
                "Task: Refine or redesign the policy to achieve better performance across all workloads.\\n"
                "Diversity requirements: change at least ONE of (prediction source, insertion depth policy, streaming/bypass logic, metadata layout).\\n\\n"
                "Seed mechanisms you may combine:\\n"
                f"{SEED_KNOWLEDGE}\\n\\n"
                "Think briefly before coding (2–3 bullets), then commit to ONE design.\\n"
                "Produce the output in the exact format:\\n\\n"
                "## Policy Name\\n&lt;name&gt;\\n\\n"
                "## Policy Description\\n&lt;one paragraph explaining the approach and why it improves performance&gt;\\n\\n"
                "## C++ Implementation\\n"
                f"{prompt_gen._get_code_template()}\\n"
            )

        print(f"     1. 📤 [LLM] Iteration {i+1}/{ITERATIONS}: Generating {CANDIDATES} candidates with temp {TEMP}")
        candidate_results = []
        for j in range(CANDIDATES):
            temp = TEMP
            try:
                # o‑series models do not support temperature; omit it (defaults to 1)
                params = {
                    "model": MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                }
                if not _is_o_series(MODEL):
                    params["temperature"] = temp
                    temp_str = str(temp)
                else:
                    temp_str = "1 (fixed for o‑series)"
                resp = client.chat.completions.create(**params)
                text = resp.choices[0].message.content
                print(f"     2.{j+1} 📥 [LLM] Candidate {j+1} received (temp={temp_str})")
            except Exception as e:
                print(f"     ❌ [LLM] Candidate {j+1} failed at temp={temp}: {e}")
                continue

            # Parse
            name, desc, code = parse_policy_content(text)
            if not (name and desc and code):
                print(f"     ❌ [Parse] Candidate {j+1} parse failed")
                continue

            # Write C++ file
            base = sanitize(name) + f"_t{str(temp).replace('.', '')}"
            cc = EXAMPLE_DIR / f"{i:03}_{j:02}_{base}.cc"
            cc.write_text(code, encoding="utf-8")

            # Compile
            try:
                exe = compile_policy(cc)
            except subprocess.CalledProcessError as e:
                print(f"     ❌ [Compile Error] Candidate {j+1}: {e}")
                continue

            # Evaluate on all workloads
            total_hit = 0.0
            per_wl = []
            for trace_info in workloads:
                WORKLOAD = trace_info["name"]
                trace_path = trace_info["trace_path"]
                out = run_policy(exe, trace_path)
                hit = parse_hit_rate(out)
                total_hit += hit
                per_wl.append((WORKLOAD, hit))
                record(WORKLOAD, name, desc, cc, hit, "")

            avg_hit = total_hit / len(workloads)
            print(f"     ✅ [Result] Candidate {j+1}: {name} → avg hit {avg_hit:.2%}")
            candidate_results.append({
                "avg_hit": avg_hit,
                "name": name,
                "desc": desc,
                "code": code,
                "cc": cc,
                "per_wl": per_wl,
            })

        if not candidate_results:
            print("No successful candidates this iteration; continuing.")
            prev_name, prev_desc, prev_code = prev_name, prev_desc, prev_code
            continue

        # Select the best candidate by average hit rate
        best_cand = max(candidate_results, key=lambda x: x["avg_hit"])
        name, desc, code = best_cand["name"], best_cand["desc"], best_cand["code"]
        cc = best_cand["cc"]
        current_hit = best_cand["avg_hit"]
        for WORKLOAD, hit in best_cand["per_wl"]:
            print(f"      [+] BEST {name} → workload: {WORKLOAD} → hit rate: {hit:.4f}")
        print(f"🎯 [Chosen] Iteration {i+1}/{ITERATIONS}: {name} → average hit rate {current_hit:.2%}\n")

        # Record the chosen one under 'all'
        record("all", name, desc, cc, current_hit, "")
        prev_name, prev_desc, prev_code = name, desc, code

        # Optional: keep the early exit condition if you achieve exceptional performance
        if best_hit > 0 and (current_hit / best_hit) > 1.3:
            print(f"🎉 Early exit: Achieved {current_hit/best_hit:.1%} improvement over baseline!")
            break

    print(f"🏁 Completed {i+1} iterations")
    prompt_gen.close()
    rag.close()


if __name__ == "__main__":
    main()