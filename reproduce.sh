#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
MODE=${1:-}

usage() {
  cat <<'USAGE'
Usage: ./reproduce.sh <target>

Targets:
  best    Run the best-performing policy and baseline policies across the five workloads.
  all     Rebuild + evaluate LRU/LIME/Ours on five workloads and refresh results/ artifacts.
USAGE
}

if [[ -z "$MODE" ]]; then
  usage
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required but was not found on PATH." >&2
  exit 1
fi

IMAGE_NAME="champsim-runner"
DOCKERFILE="$ROOT_DIR/Dockerfile.champsim"

if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
  echo "[setup] Building Docker image '$IMAGE_NAME' (once)..."
  docker build --platform linux/amd64 -f "$DOCKERFILE" -t "$IMAGE_NAME" "$ROOT_DIR"
fi

RESULT_ROOT="$ROOT_DIR/results"
WORKLOADS=(astar lbm mcf milc omnetpp)

case "$MODE" in
  best)
    RESULT_DIR="$RESULT_ROOT/best"
    POLICIES=(
      "best:best-performing-policy.cc"
      "hawkeye:ChampSim_CRC2/champ_repl_pol/hawkeye_final.cc"
      "lime:ChampSim_CRC2/champ_repl_pol/lime.cc"
      "lru:ChampSim_CRC2/champ_repl_pol/lru.cc"
      "ship_pp:ChampSim_CRC2/champ_repl_pol/ship++.cc"
    )
    ;;
  all)
    RESULT_DIR="$RESULT_ROOT/all"
    POLICIES=(
      "Ours:best-performing-policy.cc"
      "LIME:ChampSim_CRC2/champ_repl_pol/lime.cc"
      "LRU:ChampSim_CRC2/champ_repl_pol/lru.cc"
    )
    ;;
  *)
    echo "Unsupported target: $MODE" >&2
    usage
    exit 1
    ;;
esac

rm -rf "$RESULT_DIR"
mkdir -p "$RESULT_DIR"

# Warmup/simulation knobs (default to ChampSim CRC2 single-core config).
WARMUP_INST=${WARMUP_INST:-1000000}
SIM_INST=${SIM_INST:-10000000}

run_policy() {
  local label=$1
  local policy_path=$2
  local out_csv=$3

  if [[ ! -f "$ROOT_DIR/$policy_path" ]]; then
    echo "Missing policy file: $ROOT_DIR/$policy_path" >&2
    exit 1
  fi

  echo "[run] $label → $policy_path (host: $ROOT_DIR/$policy_path)"
  python3 "$ROOT_DIR/ChampSim_CRC2/eval_ipc_docker.py" \
    --policy "$policy_path" \
    --warmup "$WARMUP_INST" \
    --sim "$SIM_INST" \
    --workloads "${WORKLOADS[@]}" \
    --out "$out_csv"
}

METADATA_FILE="$RESULT_DIR/.policy_runs"
: >"$METADATA_FILE"

for entry in "${POLICIES[@]}"; do
  IFS=":" read -r label path <<<"$entry"
  safe_label=$(echo "$label" | tr '[:upper:]' '[:lower:]' | tr ' ' '_' | tr -cd '[:alnum:]_-' )
  [[ -z "$safe_label" ]] && safe_label="policy"
  out_csv="$RESULT_DIR/${safe_label}_results.csv"
  run_policy "$label" "$path" "$out_csv"
  printf '%s,%s\n' "$label" "$out_csv" >>"$METADATA_FILE"
done

# Aggregate metrics, write summary tables, and (for 'all') produce figures.
tmp_mpl=$(mktemp -d)
export MPLCONFIGDIR="$tmp_mpl"
python3 - "$RESULT_DIR" "$METADATA_FILE" "$MODE" <<'PY'
import csv
import sys
from collections import defaultdict
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt

result_dir = Path(sys.argv[1])
metadata_path = Path(sys.argv[2])
mode = sys.argv[3]

if not metadata_path.exists():
    raise SystemExit("Missing policy metadata; nothing to summarize.")

entries = []
with metadata_path.open() as meta:
    for line in meta:
        line = line.strip()
        if not line:
            continue
        label, csv_path = line.split(',', 1)
        entries.append((label, Path(csv_path)))

if not entries:
    raise SystemExit("No policies recorded; aborting summary step.")

rows = []
for label, csv_path in entries:
    if not csv_path.exists():
        raise SystemExit(f"Expected CSV missing: {csv_path}")
    with csv_path.open(newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            workload = row.get("workload", "")
            policy = row.get("policy", "")
            cpp_path = row.get("cpp_file_path", "")
            ipc_raw = row.get("ipc", "")
            hit_raw = row.get("cache_hit_rate", "")
            try:
                ipc_val = float(ipc_raw) if ipc_raw not in ("", None) else None
            except ValueError:
                ipc_val = None
            try:
                hit_val = float(hit_raw) if hit_raw not in ("", None) else None
            except ValueError:
                hit_val = None
            rows.append({
                "policy_label": label,
                "workload": workload,
                "policy": policy,
                "cpp_file_path": cpp_path,
                "ipc_val": ipc_val,
                "ipc_raw": ipc_raw,
                "hit_val": hit_val,
                "hit_raw": hit_raw,
            })

if not rows:
    raise SystemExit("No result rows found; aborting summary step.")

def fmt(val):
    return f"{val:.6f}" if isinstance(val, float) else ("" if val in (None, "") else str(val))

combined_path = result_dir / "combined.csv"
fieldnames = ["policy_label", "workload", "policy", "cpp_file_path", "ipc", "cache_hit_rate"]
with combined_path.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({
            "policy_label": row["policy_label"],
            "workload": row["workload"],
            "policy": row["policy"],
            "cpp_file_path": row["cpp_file_path"],
            "ipc": fmt(row["ipc_val"] if row["ipc_val"] is not None else row["ipc_raw"]),
            "cache_hit_rate": fmt(row["hit_val"] if row["hit_val"] is not None else row["hit_raw"]),
        })

by_policy = defaultdict(list)
for row in rows:
    by_policy[row["policy_label"]].append(row)

summary_path = result_dir / "summary.csv"
with summary_path.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["policy_label", "mean_ipc", "mean_cache_hit_rate"])
    writer.writeheader()
    for label in sorted(by_policy):
        ipc_vals = [r["ipc_val"] for r in by_policy[label] if isinstance(r["ipc_val"], float)]
        hit_vals = [r["hit_val"] for r in by_policy[label] if isinstance(r["hit_val"], float)]
        writer.writerow({
            "policy_label": label,
            "mean_ipc": fmt(sum(ipc_vals) / len(ipc_vals)) if ipc_vals else "",
            "mean_cache_hit_rate": fmt(sum(hit_vals) / len(hit_vals)) if hit_vals else "",
        })

if mode == "all":
    workloads = ["astar", "lbm", "mcf", "milc", "omnetpp"]
    preferred_order = ["Ours", "LIME", "LRU"]

    # Build dataframe for easier manipulation.
    df = pd.DataFrame([
        {
            "workload": r["workload"],
            "policy": r["policy_label"],
            "ipc": r["ipc_val"],
        }
        for r in rows
        if r["workload"] and isinstance(r["ipc_val"], float)
    ])

    if df.empty:
        raise SystemExit("No numeric IPC results for plotting.")

    df["workload"] = pd.Categorical(df["workload"], workloads, ordered=True)
    df["policy"] = pd.Categorical(df["policy"], preferred_order, ordered=True)
    df = df.sort_values(["policy", "workload"]).reset_index(drop=True)

    ipc_all_path = result_dir / "ipc_all.csv"
    df_out = df.copy()
    df_out.columns = ["workload", "policy", "ipc"]
    df_out.to_csv(ipc_all_path, index=False)

    mean_ipc_path = result_dir / "mean_ipc.csv"
    df_mean = df.groupby("policy")["ipc"].mean().reindex(preferred_order)
    df_mean.to_csv(mean_ipc_path, header=["mean_ipc"])

    compare_path = result_dir / "compare_ipc.txt"
    label_titles = {
        "Ours": "Best policy",
        "LIME": "LIME baseline",
        "LRU": "LRU baseline",
    }
    with compare_path.open("w") as f:
        for policy in preferred_order:
            if policy not in by_policy:
                continue
            f.write(f"--- {label_titles.get(policy, policy)} ---\n")
            policy_rows = {r["workload"]: r for r in by_policy[policy] if isinstance(r["ipc_val"], float)}
            for wl in workloads:
                if wl in policy_rows:
                    f.write(f"{wl},{fmt(policy_rows[wl]['ipc_val'])}\n")
            ipc_vals = [r["ipc_val"] for r in by_policy[policy] if isinstance(r["ipc_val"], float)]
            if ipc_vals:
                f.write(f"mean,{fmt(sum(ipc_vals)/len(ipc_vals))}\n")

    # Write per-policy CSVs mirroring prior artifacts.
    for policy in preferred_order:
        if policy not in by_policy:
            continue
        policy_rows = {r["workload"]: r for r in by_policy[policy] if isinstance(r["ipc_val"], float)}
        policy_path = result_dir / f"ipc_{policy.lower()}.csv"
        with policy_path.open("w", newline="") as f:
            writer = csv.writer(f)
            vals = []
            for wl in workloads:
                if wl in policy_rows:
                    ipc_val = policy_rows[wl]["ipc_val"]
                    writer.writerow([wl, fmt(ipc_val)])
                    vals.append(ipc_val)
            if vals:
                writer.writerow(["mean", fmt(sum(vals)/len(vals))])

    # Plot IPC per workload bar chart.
    pivot = df.pivot(index="workload", columns="policy", values="ipc").reindex(workloads)
    ax = pivot.plot(kind="bar", figsize=(8, 4.5))
    ax.set_ylabel("IPC")
    ax.set_xlabel("Workload")
    ax.set_title("IPC per workload (higher is better)")
    ax.legend(title="Policy")
    plt.tight_layout()
    plt.savefig(result_dir / "fig_ipc_per_workload.png", dpi=200)

print(f"[results] Combined metrics → {combined_path}")
print(f"[results] Summary averages → {summary_path}")
if mode == "all":
    print(f"[results] IPC data → {result_dir / 'ipc_all.csv'}")
    print(f"[results] Figure → {result_dir / 'fig_ipc_per_workload.png'}")
PY
rm -rf "$tmp_mpl"

echo "Done. Results in $RESULT_DIR"
