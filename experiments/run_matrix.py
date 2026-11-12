#!/usr/bin/env python3
"""Run agents x tasks x repeats under agentprof and collect one results table.

    sudo python3 experiments/run_matrix.py --agents ref-scripted --tasks t01 t03 --reps 3
    sudo python3 experiments/run_matrix.py --agents claude-code gemini-cli --tasks all --reps 3 --user pi
    sudo python3 experiments/run_matrix.py --agents ref-gemini --tasks all --delay-ms 0,50,150   # Pi only (netem)

For every (agent, task, repeat): a fresh copy of the task in a scratch folder
owned by --user, the agent traced from its first instruction, the task's
checker, then the analysis. Output: experiments/results/<campaign>/
    <agent>__<task>__r<k>[__d<ms>]/   one agentprof run folder each
    results.csv / results.md           one row per run (success + all metrics)
"""
import argparse
import csv
import json
import os
import pwd
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
import tasks as T  # noqa: E402
from agentprof import analyze, compare  # noqa: E402


def default_iface():
    try:
        out = subprocess.run(["ip", "route", "get", "1.1.1.1"], capture_output=True, text=True).stdout.split()
        return out[out.index("dev") + 1]
    except (ValueError, IndexError, FileNotFoundError):
        return None


def set_delay(iface, ms):
    subprocess.run(["tc", "qdisc", "del", "dev", iface, "root"], capture_output=True)
    if ms:
        subprocess.run(["tc", "qdisc", "add", "dev", iface, "root", "netem", "delay", f"{ms}ms"], check=True)


def api_status(run_dir):
    """From ref_agent's own log: retries and the final API error, if any."""
    p = os.path.join(run_dir, "ref_agent_truth.jsonl")
    out = {"api_retries": 0, "api_error": None, "api_statuses": ""}
    if not os.path.exists(p):
        return out
    codes = []
    for line in open(p):
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if r.get("ev") == "llm_retry":
            out["api_retries"] += 1
            codes.append(str(r.get("status")))
        elif r.get("ev") == "llm_error":
            out["api_error"] = r.get("status") or "error"
            codes.append(str(r.get("status")))
    out["api_statuses"] = ",".join(sorted(set(codes)))
    return out


def fill(x, d):
    return x.format(**d) if isinstance(x, str) else x


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--agents", nargs="+", required=True)
    ap.add_argument("--tasks", nargs="+", default=["all"])
    ap.add_argument("--reps", type=int, default=1)
    ap.add_argument("--user", default=os.environ.get("SUDO_USER"), help="account that runs the agents")
    ap.add_argument("--model", help="override the model of the agent template")
    ap.add_argument("--campaign", help="results folder name (default: time stamp)")
    ap.add_argument("--work", default="/tmp/agentprof-work")
    ap.add_argument("--delay-ms", default="0", help="comma list of extra one-way delays to apply with netem (Pi)")
    ap.add_argument("--iface", help="interface for --delay-ms (default: route to the internet)")
    ap.add_argument("--timeout", type=int, help="override task timeouts (s)")
    ap.add_argument("--cooldown", type=float, default=2.0, help="seconds between runs (free tiers: 20-60)")
    ap.add_argument("--stop-after-api-errors", type=int, default=2,
                    help="abort the campaign after N runs in a row refused by the API (0 = never)")
    ap.add_argument("--skip-done", action="store_true",
                    help="keep runs of this --campaign that completed without API errors; redo the rest")
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("run with sudo (eBPF)")
    if not a.user or a.user == "root":
        sys.exit("give --user <normal account>: agents should not run as root")
    pw = pwd.getpwnam(a.user)
    agents = json.load(open(os.path.join(HERE, "agents.json")))
    tasks = T.load_tasks(None if a.tasks == ["all"] else a.tasks)
    delays = [int(x) for x in a.delay_ms.split(",")]
    iface = a.iface or default_iface()
    if any(delays) and not iface:
        sys.exit("cannot find the network interface for --delay-ms")
    camp = a.campaign or time.strftime("campaign_%Y%m%d-%H%M%S")
    out_root = os.path.join(HERE, "results", camp)
    os.makedirs(out_root, exist_ok=True)
    rows = []
    bad_streak = 0
    plan = [(ag, t, r, d) for d in delays for ag in a.agents for t in tasks for r in range(a.reps)]
    print(f"{len(plan)} runs -> {out_root}")
    try:
        for i, (ag, t, r, d) in enumerate(plan):
            spec = agents[ag]
            name = f"{ag}__{t['id']}__r{r}" + (f"__d{d}" if any(delays) else "")
            run_dir = os.path.join(out_root, name)
            if a.skip_done and os.path.exists(os.path.join(run_dir, "summary.json")) and \
                    not api_status(run_dir)["api_error"] and not os.path.exists(os.path.join(run_dir, ".redo")):
                print(f"[{i + 1}/{len(plan)}] {name}: already done, skipped")
                continue
            if os.path.exists(run_dir):
                shutil.rmtree(run_dir)            # an earlier API-refused attempt: start clean
            work = os.path.join(a.work, name)
            T.prepare(t, work)
            for root_, dirs, files in os.walk(work):
                for x in dirs + files:
                    os.lchown(os.path.join(root_, x), pw.pw_uid, pw.pw_gid)
            os.chown(work, pw.pw_uid, pw.pw_gid)
            os.makedirs(run_dir, exist_ok=True)
            os.chown(run_dir, pw.pw_uid, pw.pw_gid)     # agents' own logs go here
            vals = {"prompt": t["prompt"], "work": work, "run": run_dir, "root": ROOT,
                    "model": a.model or spec.get("model", "")}
            cmd = [fill(x, vals) for x in spec["cmd"]]
            env = [f"{k}={fill(v, vals)}" for k, v in (spec.get("env") or {}).items()]
            for k in spec.get("env_passthrough", []):
                if os.environ.get(k):
                    env.append(f"{k}={os.environ[k]}")
            if any(delays):
                set_delay(iface, d)
            timeout = a.timeout or t.get("timeout_s", 600)
            print(f"[{i + 1}/{len(plan)}] {name}: ", end="", flush=True)
            t_start = time.time()
            args = [sys.executable, "-m", "agentprof", "run", "--quiet", "--user", a.user, "--cwd", work,
                    "--label", name, "--out", run_dir, "--capture-output", "--no-tty"]
            for e in env:
                args += ["--env", e]
            args += ["--", *cmd]
            try:
                # SIGTERM: the tracer stops the agent and still writes its record
                subprocess.run(["timeout", "--signal=TERM", "--kill-after=30", str(timeout + 60), *args],
                               cwd=ROOT, env={**os.environ, "PYTHONPATH": ROOT})
            except KeyboardInterrupt:
                raise
            ok = T.check(t, work)
            api = api_status(run_dir)
            try:
                analyze.main_for(run_dir, quiet=True)
                row = compare.row(run_dir)
            except Exception as e:      # a broken run still gets a row
                row = {"run": name, "error": str(e)[:200]}
            row.update(agent=ag, task=t["id"], rep=r, delay_ms=d, success=ok,
                       wall_s=round(time.time() - t_start, 2), model=vals["model"], **api)
            # a run the model provider refused (quota, overload) says nothing about the agent
            row["outcome"] = "PASS" if ok else ("API-ERROR" if api["api_error"] else "fail")
            rows.append(row)
            print(f"{row['outcome']}  {row.get('run_s')} s, {row.get('llm_calls')} LLM calls, "
                  f"{row.get('tool_calls')} tool calls, LLM {row.get('llm_share_pct')} % / tools {row.get('tool_share_pct')} %"
                  + (f"  [API {api['api_error']}, {api['api_retries']} retries]" if api["api_error"] else
                     f"  [{api['api_retries']} API retr{'y' if api['api_retries'] == 1 else 'ies'} ({api['api_statuses']}), recovered]"
                     if api["api_retries"] else ""))
            bad_streak = bad_streak + 1 if api["api_error"] else 0
            if a.stop_after_api_errors and bad_streak >= a.stop_after_api_errors:
                print(f"stopping: {bad_streak} runs in a row refused by the API (quota exhausted or overloaded). "
                      f"Results so far are saved; rerun later with --campaign {camp} --skip-done")
                break
            time.sleep(a.cooldown)
    finally:
        if any(delays):
            set_delay(iface, 0)
        if rows:
            if a.skip_done and os.path.exists(os.path.join(out_root, "results.csv")):
                done = {r_["run"] for r_ in rows}
                for old_row in csv.DictReader(open(os.path.join(out_root, "results.csv"))):
                    if old_row.get("run") not in done and old_row.get("outcome") != "API-ERROR":
                        rows.append(old_row)
                rows.sort(key=lambda r_: str(r_.get("run")))
            cols = ["agent", "model", "task", "rep", "delay_ms", "outcome", "success", "api_retries", "api_statuses",
                    "wall_s"] + \
                   [c for c in compare.COLS if c not in ("run", "label")] + ["run"]
            with open(os.path.join(out_root, "results.csv"), "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
                w.writeheader()
                w.writerows(rows)
            with open(os.path.join(out_root, "results.md"), "w") as f:
                f.write("| " + " | ".join(cols) + " |\n|" + "---|" * len(cols) + "\n")
                for r_ in rows:
                    f.write("| " + " | ".join("" if r_.get(c) is None else str(r_.get(c)) for c in cols) + " |\n")
            print(f"results: {os.path.join(out_root, 'results.md')}")


if __name__ == "__main__":
    main()
