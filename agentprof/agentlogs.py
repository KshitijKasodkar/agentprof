"""Cross-check the kernel's view with the agent's OWN log.

agentprof never needs the agent's cooperation, but when the agent keeps a log
we use it to (a) validate the reconstruction and (b) add what encryption hides:
token counts, tool names, which tool calls the model asked for.

Supported:
  * Claude Code session transcripts: ~/.claude/projects/<cwd>/<session>.jsonl
  * tools/ref_agent.py truth logs
"""
import collections
import datetime
import glob
import json
import os
import re


def _iso_to_epoch(s):
    try:
        return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return None


def detect(path):
    with open(path) as f:
        for line in f:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if "ev" in r and r.get("ev") in ("session_start", "llm_start", "tool_start"):
                return "ref_agent"
            if r.get("type") in ("assistant", "user", "queue-operation", "attachment") or "sessionId" in r:
                return "claude_code"
    return None


def claude_code(path):
    reqs = collections.OrderedDict()
    tool_uses = collections.Counter()
    tool_errors = 0
    tool_results = 0
    for line in open(path):
        try:
            r = json.loads(line)
        except ValueError:
            continue
        m = r.get("message") or {}
        if r.get("type") == "assistant":
            rid = r.get("requestId") or m.get("id") or f"x{len(reqs)}"
            d = reqs.setdefault(rid, {"t": _iso_to_epoch(r.get("timestamp")), "blocks": [], "usage": None,
                                      "model": m.get("model")})
            for b in m.get("content") or []:
                if isinstance(b, dict):
                    d["blocks"].append(b.get("type"))
                    if b.get("type") == "tool_use":
                        tool_uses[b.get("name")] += 1
            if m.get("usage"):
                d["usage"] = m["usage"]
            d["t_last"] = _iso_to_epoch(r.get("timestamp"))
        elif r.get("type") == "user" and isinstance(m.get("content"), list):
            for b in m["content"]:
                if isinstance(b, dict) and b.get("type") == "tool_result":
                    tool_results += 1
                    if b.get("is_error"):
                        tool_errors += 1
    tok = collections.Counter()
    for d in reqs.values():
        for k, v in (d["usage"] or {}).items():
            if isinstance(v, (int, float)):
                tok[k] += v
    per_req_input = [((d["usage"] or {}).get("input_tokens", 0) + (d["usage"] or {}).get("cache_read_input_tokens", 0)
                      + (d["usage"] or {}).get("cache_creation_input_tokens", 0)) for d in reqs.values()]
    out_tok = [(d["usage"] or {}).get("output_tokens", 0) for d in reqs.values()]
    return {
        "format": "claude_code", "file": path, "api_responses": len(reqs),
        "models": sorted({d["model"] for d in reqs.values() if d["model"]}),
        "tool_uses": sum(tool_uses.values()), "tool_uses_by_name": dict(tool_uses),
        "tool_results": tool_results, "tool_errors": tool_errors,
        "tokens": dict(tok),
        "prompt_tokens_per_call": per_req_input, "output_tokens_per_call": out_tok,
        "completion_to_prompt": round(sum(out_tok) / sum(per_req_input), 4) if sum(per_req_input) else None,
        "cache_read_share": (round(tok.get("cache_read_input_tokens", 0) / sum(per_req_input), 3)
                             if sum(per_req_input) else None),
        "response_times": [d["t_last"] for d in reqs.values()],
    }


def ref_agent(path):
    recs = [json.loads(l) for l in open(path) if l.strip()]
    llm = [r for r in recs if r["ev"] == "llm_end"]
    tools = [r for r in recs if r["ev"] == "tool_start"]
    usage = collections.Counter()
    for r in llm:
        for k, v in (r.get("usage") or {}).items():
            if isinstance(v, (int, float)):
                usage[k] += v
    return {"format": "ref_agent", "file": path, "api_responses": len(llm), "tool_uses": len(tools),
            "tool_pids": [t.get("pid") for t in tools], "tokens": dict(usage)}


def find_claude_transcript(run_dir, meta):
    """Newest transcript written during the run for the run's working directory."""
    user = meta.get("user") or "root"
    home = os.path.expanduser(f"~{user}")
    cwd = meta.get("cwd") or ""
    key = re.sub(r"[^A-Za-z0-9-]", "-", cwd)      # Claude Code's folder naming
    cands = glob.glob(os.path.join(home, ".claude", "projects", key, "*.jsonl"))
    t0, t1 = meta.get("start_wall", 0), meta.get("end_wall", 1e18)
    good = [c for c in cands if t0 - 2 <= os.path.getmtime(c) <= t1 + 10]
    # the transcript is last written when the agent finishes: closest to the run's end
    return min(good, key=lambda c: abs(os.path.getmtime(c) - t1)) if good else None


def crosscheck(path, summary, run_dir):
    if path == "auto":
        with open(os.path.join(run_dir, "meta.json")) as f:
            meta = json.load(f)
        path = find_claude_transcript(run_dir, meta)
        if not path:
            return {"error": "no Claude Code transcript found for this run"}
    kind = detect(path)
    if kind == "claude_code":
        a = claude_code(path)
    elif kind == "ref_agent":
        a = ref_agent(path)
    else:
        return {"error": f"unknown log format: {path}"}
    c = summary["counts"]
    a["tracer_llm_calls"] = c["llm_calls"]
    a["tracer_tool_calls_act_phase"] = c.get("tool_calls_act_phase")
    a["tracer_tool_calls_all"] = c["tool_calls"]
    a["llm_calls_match"] = a["api_responses"] == c["llm_calls"]
    a.pop("response_times", None)
    return a
