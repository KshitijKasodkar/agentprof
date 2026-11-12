"""`agentprof compare`: one table across runs, next to the published numbers.

Reference values are what the papers report for THEIR setups; they are context,
not targets. Our numbers come from our tasks, agents, models and hardware.
"""
import csv
import json
import os

REFERENCE = [
    # metric, value, source
    ("os_exec_like_pct", "56-74 %", "AgentCgroup v2 (arXiv 2602.09345): initialization + tool execution share of task time; "
     "Claude Code, SWE-rebench, Haiku 4.5 (API) and GLM-4.7-Flash (local)"),
    ("tool_exec_share_pct", "42.5 % / 36.4 %", "AgentCgroup: tool execution share of active time (Haiku / GLM)"),
    ("memory_peak_to_avg", "15.4x", "AgentCgroup: memory peak-to-average (1 s sampling)"),
    ("agent framework memory", "~185 MB", "AgentCgroup: Claude Code framework baseline memory"),
    ("llm_calls", "8.8 per request", "TraceLab (arXiv 2606.30560): LLM steps per user request (Claude Code + Codex, 43 developers)"),
    ("tool_calls", "10.8 per request", "TraceLab: tool calls per user request"),
    ("append tokens", "median 875 (prefix 119K, output 214)", "TraceLab: per LLM step"),
    ("tool_calls_per_llm_call", "~1:1", "Agentic Coding in the Wild (GitHub Copilot, arXiv 2608.00101)"),
    ("llm_calls_per_turn", "6.6", "Agentic Coding in the Wild: LLM calls per user turn; 87 % agent-initiated"),
    ("completion_to_prompt", "very low", "MCP characterization (arXiv 2511.07426): completion/prompt token ratio with Cline"),
]

COLS = ["run", "label", "run_s", "llm_calls", "llm_retries", "tool_calls", "tool_uses_logged", "tool_calls_act_phase", "tool_calls_per_llm_call",
        "llm_share_pct", "tool_share_pct", "os_exec_like_pct", "provider_backoff_pct", "neither_pct", "startup_s", "ttfb_ms_median", "req_bytes_first",
        "req_bytes_last", "memory_peak_to_avg", "agent_cpu_user_ms", "agent_cpu_sys_ms", "agent_syscalls",
        "tool_syscalls", "processes", "connections", "completion_to_prompt", "tokens_in", "tokens_out"]


def row(run_dir):
    p = os.path.join(run_dir, "summary.json")
    if not os.path.exists(p):
        from . import analyze
        analyze.main_for(run_dir, quiet=True)
    s = json.load(open(p))
    ts, c, lm, pm = s["timesplit"], s["counts"], s["llm"], s["paper_metrics"]
    ag = s["roles"].get("agent", {})
    tl = s["roles"].get("tool", {})
    al = s.get("agent_log") or {}
    tok = al.get("tokens") or {}
    return {
        "run": s["run"], "label": s.get("label"), "run_s": ts["run_s"], "llm_calls": c["llm_calls"],
        "llm_retries": c.get("llm_retries"), "tool_uses_logged": c.get("tool_uses_logged"),
        "provider_backoff_pct": ts.get("provider_backoff_pct"),
        "tool_calls": c["tool_calls"], "tool_calls_act_phase": c.get("tool_calls_act_phase"),
        "tool_calls_per_llm_call": c["tool_calls_per_llm_call"], "llm_share_pct": ts["llm_share_pct"],
        "tool_share_pct": ts["tool_share_pct"], "os_exec_like_pct": ts.get("os_exec_like_pct"),
        "neither_pct": ts["neither_pct"], "startup_s": ts["startup_s"],
        "ttfb_ms_median": lm["ttfb_ms_median"], "req_bytes_first": lm["req_bytes_first"],
        "req_bytes_last": lm["req_bytes_last"], "memory_peak_to_avg": pm["memory_peak_to_avg"],
        "agent_cpu_user_ms": round(ag.get("user_ns", 0) / 1e6, 1), "agent_cpu_sys_ms": round(ag.get("sys_ns", 0) / 1e6, 1),
        "agent_syscalls": ag.get("syscalls"), "tool_syscalls": tl.get("syscalls"), "processes": c["processes"],
        "connections": c["connections"], "completion_to_prompt": al.get("completion_to_prompt"),
        "tokens_in": (tok.get("input_tokens", 0) + tok.get("cache_read_input_tokens", 0)
                      + tok.get("cache_creation_input_tokens", 0)) or None,
        "tokens_out": tok.get("output_tokens"),
    }


def main(args):
    rows = [row(d) for d in args.run_dirs]
    lines = ["| " + " | ".join(COLS) + " |", "|" + "---|" * len(COLS)]
    for r in rows:
        lines.append("| " + " | ".join("" if r.get(k) is None else str(r.get(k)) for k in COLS) + " |")
    lines += ["", "Published reference values (their setups, for context):", "",
              "| metric | value | source |", "|---|---|---|"]
    lines += [f"| {m} | {v} | {src} |" for m, v, src in REFERENCE]
    text = "\n".join(lines)
    print(text)
    if args.md:
        with open(args.md, "w") as f:
            f.write(text + "\n")
    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=COLS)
            w.writeheader()
            w.writerows(rows)
