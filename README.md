# CSC491 Cache Replacement Search

LLM-assisted search for ChampSim CRC2 cache replacement policies. Azure OpenAI proposes policies, ChampSim evaluates them, and the best one ships as `best-performing-policy.cc` alongside LRU/LIME/HawkEye/SHiP++ baselines.

## Setup
```bash
git clone <repo-url>
cd csc491-hw1
pip install python-dotenv openai pandas matplotlib
# or: conda env create -f environment.yml && conda activate new_env
```
Need Docker running for the reproducibility script. Set `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_DEPLOYMENT` before you run the CacheForge loop.

## CacheForge Loop (macOS via Docker)
1. Ensure `Dockerfile.champsim`, `DB_Connection.py`, and `run_loop_docker.py` sit in the `cacheforge/` folder alongside `run_loop.py`.
2. Build the ChampSim image using the Linux VM base:
   ```bash
   docker build --platform linux/amd64 -f Dockerfile.champsim -t champsim-runner .
   ```
3. Initialize the experiment database:
   ```bash
   python DB_Connection.py
   ```
4. Launch the main loop inside Docker:
   ```bash
   python run_loop_docker.py
   ```

## Reproduce
`reproduce.sh` runs every workload inside Docker and drops fresh CSVs/plots in `results/`.
```
./reproduce.sh best   # best policy + baselines
./reproduce.sh all    # rebuild LRU/LIME/Ours and refresh artifacts
```
Optional: shorten runs with `WARMUP_INST=... SIM_INST=... ./reproduce.sh best`.

## Handy Scripts
- `run_loop.py` – Azure OpenAI feedback loop when running directly on Linux.
- `run_champsim.py` – local helper to compile and execute all DB policies.

## License
MIT (inherits ChampSim CRC2).
