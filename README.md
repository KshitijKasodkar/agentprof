# agentprof: tracing AI agents with eBPF

agentprof traces AI coding agents from the Linux kernel with eBPF, without modifying the agents. For each run it records:

- processes and tool calls (the full process tree)
- syscalls, with counts and latency
- CPU time, split into user and kernel
- network connections and bytes, labelled as LLM, telemetry, DNS or package traffic
- memory

From these it reconstructs each LLM call (request size, response size, time to first byte) and splits the run time into LLM wait, tool execution, the agent's own work and rate-limit back-off.

**Status:** first stage. The tracer is built and validated, and there is a first comparison of two agents on the same model. Work on local models and on PARAM is next.

## Layout

| Path | What it is |
|---|---|
| `agentprof/bpf/agentprof.bpf.c` | The eBPF program: process, scheduler, syscall, socket and TCP tracepoints |
| `agentprof/` | Loader, runner and analyzer (`runner.py`, `kernel.py`, `libbpf.py`, `analyze.py`, `html_report.py`, …) |
| `tools/ref_agent.py` | Minimal reference agent, the baseline harness |
| `tasks/` | 8 small coding tasks, each with an instruction, start files and a PASS/fail checker |
| `experiments/run_matrix.py` | Runs agent × task × repetition under the tracer |
| `experiments/compare_campaigns.py` | Builds a comparison page from two campaigns |
| `experiments/results/` | Results of the first comparison (24 runs per agent) |
| `scripts/setup_wsl.sh` | One-time setup on WSL2 / Ubuntu |

## Requirements

- Linux kernel 6.3 or newer (tested on WSL2, kernel 6.18), with root access for eBPF
- python3, libbpf and clang (installed by the setup script)
- For the experiments: a Gemini API key, plus [Gemini CLI](https://github.com/google-gemini/gemini-cli) for the second agent

## Quick start

```bash
sudo bash scripts/setup_wsl.sh          # install, compile the eBPF program, check the machine
export GEMINI_API_KEY="<your key>"

# reference agent: all 8 tasks, 3 runs each
sudo -E python3 experiments/run_matrix.py --agents ref-gemini --model gemini-3.5-flash-lite \
    --tasks all --reps 3 --user $USER --campaign baseline_flashlite_wsl --cooldown 30

# Gemini CLI: the same tasks
sudo -E python3 experiments/run_matrix.py --agents gemini-cli --model gemini-3.5-flash-lite \
    --tasks all --reps 3 --user $USER --campaign gemini_cli_flashlite_wsl --cooldown 30

# comparison page
python3 experiments/compare_campaigns.py experiments/results/baseline_flashlite_wsl \
    experiments/results/gemini_cli_flashlite_wsl -o experiments/results/comparison.html
```

Each run writes a `report.html` and a `summary.json` to `experiments/results/<campaign>/<agent>__<task>__r<n>/`. Each campaign also gets a `results.md` table.

## First results

These come from a laptop (Intel Core Ultra 5 125H, WSL2) using gemini-3.5-flash-lite. All 48 runs passed.

| | Reference agent | Gemini CLI |
|---|---|---|
| Median run time | 18.3 s | 16.8 s |
| Time waiting on the LLM | 94% | 86% |
| Request size (first → last) | 1.6 → 5.7 KB | 44.5 → 58.7 KB |
| Agent CPU | 87 ms | 1,891 ms |
| Network connections | 2.2 | 8.5 |

Tracer overhead on the same laptop: +0.9% on a whole agent session, and 0.2–0.7% of one CPU during real runs.

The full comparison is in `experiments/results/comparison.html`. GitHub shows HTML as source, so download it and open it in a browser.

## Next

- Local models (Ollama), first on the laptop and then on PARAM (V100), with results both with and without profiling
- Standard benchmarks (Terminal-Bench, SWE-bench), cold runs with caches cleared, per-call distributions and token counts


