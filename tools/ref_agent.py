#!/usr/bin/env python3
"""ref_agent.py - a minimal, fully transparent coding agent (ReAct loop).

    think (LLM call)  ->  act (run a tool)  ->  observe (tool output)  ->  repeat

Two jobs:
 1. GROUND TRUTH. It logs, with CLOCK_MONOTONIC (the clock eBPF uses), the
    start/first-byte/end of every LLM call and the start/end/PID of every tool
    process. tests/proof_agent.py checks agentprof's reconstruction against it.
 2. A REAL, FREE BASELINE AGENT. It speaks the OpenAI-compatible API, so it can
    drive real models at no cost: Ollama (local), Gemini's OpenAI-compatible
    endpoint (free API key), Groq/OpenRouter free tiers, or vLLM on a server.

Standard library only. Examples:
    # against the scripted endpoint (validation)
    python3 tools/ref_agent.py --base http://127.0.0.1:8090/v1 --task "list files"
    # local model with Ollama
    python3 tools/ref_agent.py --base http://127.0.0.1:11434/v1 --model qwen2.5-coder:3b --task "..."
    # Gemini free tier (key from https://aistudio.google.com/apikey)
    GEMINI_API_KEY=... python3 tools/ref_agent.py --base https://generativelanguage.googleapis.com/v1beta/openai \
        --model gemini-3.8-flash --key-env GEMINI_API_KEY --task "..."
"""
import argparse
import http.client
import json
import os
import ssl
import subprocess
import sys
import time
from urllib.parse import urlparse

TOOLS = [
    {"type": "function", "function": {
        "name": "bash", "description": "Run a shell command in the working directory and return its output.",
        "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}}},
    {"type": "function", "function": {
        "name": "read_file", "description": "Read a text file.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "write_file", "description": "Write a text file (overwrites).",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                       "required": ["path", "content"]}}},
]

SYSTEM = ("You are a careful coding agent working in a Linux shell. Use the tools to inspect and change files "
          "and to run commands. When the task is complete, reply with a short summary and no tool call.")


def mono_ns():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)


class Log:
    def __init__(self, path):
        self.f = open(path, "a") if path else None

    def __call__(self, **rec):
        rec.setdefault("t", mono_ns())
        rec["agent_pid"] = os.getpid()
        if self.f:
            self.f.write(json.dumps(rec) + "\n")
            self.f.flush()


class Client:
    """Keeps one HTTP(S) connection open like real agents do (keep-alive)."""

    def __init__(self, base, key, timeout=600, insecure=False):
        self.insecure = insecure
        u = urlparse(base)
        self.https = u.scheme == "https"
        self.host = u.hostname
        self.port = u.port or (443 if self.https else 80)
        self.prefix = u.path.rstrip("/")
        self.key = key
        self.timeout = timeout
        self.conn = None

    def _connect(self):
        if self.https:
            ctx = ssl.create_default_context()
            if self.insecure:        # only for the local TLS test server (self-signed)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            self.conn = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=ctx)
        else:
            self.conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def chat(self, payload, on_first=None):
        """POST /chat/completions with stream=True. Returns (message, usage, nbytes)."""
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json", "Accept": "text/event-stream"}
        if self.key:
            headers["Authorization"] = f"Bearer {self.key}"
        for attempt in (1, 2):
            if self.conn is None:
                self._connect()
            try:
                self.conn.request("POST", self.prefix + "/chat/completions", body=body, headers=headers)
                resp = self.conn.getresponse()
                break
            except (http.client.HTTPException, OSError):
                self.conn.close()
                self.conn = None
                if attempt == 2:
                    raise
        if resp.status != 200:
            err = resp.read().decode(errors="replace")
            e = RuntimeError(f"HTTP {resp.status}: {err[:500]}")
            e.status = resp.status
            e.retry_after = resp.getheader("Retry-After")
            raise e
        content, calls, usage, nbytes, first = [], {}, None, 0, True
        while True:
            line = resp.readline()
            if not line:
                break
            nbytes += len(line)
            if first and on_first:
                on_first()
                first = False
            line = line.strip()
            if not line.startswith(b"data:"):
                continue
            data = line[5:].strip()
            if data == b"[DONE]":
                break
            try:
                ch = json.loads(data)
            except ValueError:
                continue
            if ch.get("usage"):
                usage = ch["usage"]
            for c in ch.get("choices", []):
                d = c.get("delta") or {}
                if d.get("content"):
                    content.append(d["content"])
                for tc in d.get("tool_calls") or []:
                    i = tc.get("index", 0)
                    slot = calls.setdefault(i, {"id": None, "name": "", "args": "", "extra": {}})
                    if tc.get("id"):
                        slot["id"] = tc["id"]
                    f = tc.get("function") or {}
                    if f.get("name"):
                        slot["name"] = f["name"]
                    if f.get("arguments"):
                        slot["args"] += f["arguments"]
                    # provider-specific fields that must be sent back unchanged, e.g. Gemini 3's
                    # extra_content.google.thought_signature (requests fail with 400 without it)
                    for k, v in tc.items():
                        if k not in ("index", "id", "type", "function"):
                            merge(slot["extra"], k, v)
        resp.read()   # drain so the connection can be reused
        msg = {"role": "assistant", "content": "".join(content) or None}
        if calls:
            msg["tool_calls"] = [{"id": c["id"] or f"call_{i}", "type": "function",
                                  "function": {"name": c["name"], "arguments": c["args"] or "{}"}, **c["extra"]}
                                 for i, c in sorted(calls.items())]
        return msg, usage, nbytes


DENY = [r"\bsudo\b", r"\brm\s+-[a-z]*r[a-z]*f?\s+/(\s|$)", r"\bmkfs", r"\bdd\s+if=.*of=/dev/", r":\(\)\s*\{",
        r"\bshutdown\b", r"\breboot\b", r"curl[^|]*\|\s*(ba)?sh", r"wget[^|]*\|\s*(ba)?sh", r"\bchmod\s+-R\s+777\s+/"]


def denied(cmd):
    import re
    return next((p for p in DENY if re.search(p, cmd)), None)


def merge(dst, k, v):
    """deep-merge streamed fragments: dicts recursively, strings concatenated"""
    if isinstance(v, dict):
        sub = dst.setdefault(k, {})
        if isinstance(sub, dict):
            for kk, vv in v.items():
                merge(sub, kk, vv)
            return
    if isinstance(v, str) and isinstance(dst.get(k), str):
        dst[k] += v
    else:
        dst[k] = v


def run_tool(name, args, cwd, log, step, timeout):
    t0 = mono_ns()
    if name == "bash":
        cmd = args.get("command", "")
        bad = denied(cmd)
        if bad:
            log(ev="tool_denied", step=step, tool=name, command=cmd, rule=bad)
            return f"refused by the agent's safety rule ({bad})"
        p = subprocess.Popen(["bash", "-c", cmd], cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        log(ev="tool_start", step=step, tool=name, pid=p.pid, command=cmd, t=t0)
        try:
            out, _ = p.communicate(timeout=timeout)
            code = p.returncode
        except subprocess.TimeoutExpired:
            p.kill()
            out, _ = p.communicate()
            code = -9
        out = out.decode(errors="replace")
        log(ev="tool_end", step=step, tool=name, pid=p.pid, exit=code, out_bytes=len(out))
        return (out[-12000:] or "(no output)") + ("" if code == 0 else f"\n[exit code {code}]")
    log(ev="tool_start", step=step, tool=name, pid=None, t=t0)
    try:
        path = os.path.join(cwd, args.get("path", ""))
        if name == "read_file":
            with open(path, errors="replace") as f:
                out = f.read()[:12000]
        elif name == "write_file":
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "w") as f:
                f.write(args.get("content", ""))
            out = f"wrote {len(args.get('content', ''))} bytes to {args.get('path')}"
        else:
            out = f"unknown tool {name}"
    except OSError as e:
        out = f"error: {e}"
    log(ev="tool_end", step=step, tool=name, pid=None, exit=0, out_bytes=len(out))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="http://127.0.0.1:8090/v1", help="OpenAI-compatible base URL")
    ap.add_argument("--model", default="scripted-model")
    ap.add_argument("--key-env", default="OPENAI_API_KEY", help="env var holding the API key")
    ap.add_argument("--task", required=True)
    ap.add_argument("--cwd", default=".")
    ap.add_argument("--max-steps", type=int, default=20)
    ap.add_argument("--tool-timeout", type=float, default=300)
    ap.add_argument("--log", default=os.environ.get("REF_AGENT_LOG", "ref_agent_truth.jsonl"))
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--insecure", action="store_true", help="do not verify TLS certificates (local tests only)")
    ap.add_argument("--allow-root", action="store_true", help="allow running as root (not recommended)")
    ap.add_argument("--retries", type=int, default=6, help="retries on HTTP 429/5xx (exponential backoff)")
    a = ap.parse_args()
    if os.geteuid() == 0 and not a.allow_root:
        sys.exit("ref_agent runs model-chosen shell commands: run it as a normal user (or pass --allow-root)")

    log = Log(a.log)
    cli = Client(a.base, os.environ.get(a.key_env, ""), insecure=a.insecure)
    messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": a.task}]
    log(ev="session_start", task=a.task, base=a.base, model=a.model)
    final = None
    for step in range(a.max_steps):
        payload = {"model": a.model, "messages": messages, "tools": TOOLS, "stream": True,
                   "temperature": a.temperature}
        t0 = mono_ns()
        first = {}
        log(ev="llm_start", step=step, t=t0, req_bytes=len(json.dumps(payload)))
        for attempt in range(a.retries + 1):
            try:
                msg, usage, nbytes = cli.chat(payload, on_first=lambda: first.setdefault("t", mono_ns()))
                break
            except RuntimeError as e:
                status = getattr(e, "status", None)
                # overloaded / rate limited / server error: back off and retry, like real agents do
                if status not in (429, 500, 502, 503, 504) or attempt == a.retries:
                    log(ev="llm_error", step=step, status=status, error=str(e)[:300])
                    raise
                try:
                    wait = float(getattr(e, "retry_after", None) or 0)
                except ValueError:
                    wait = 0
                wait = max(wait, min(60, 2 * 2 ** attempt))
                log(ev="llm_retry", step=step, attempt=attempt + 1, status=status, wait_s=wait)
                print(f"[ref_agent] HTTP {status}, retry {attempt + 1}/{a.retries} in {wait:.0f} s", file=sys.stderr)
                time.sleep(wait)
                first.clear()
        log(ev="llm_end", step=step, t_first=first.get("t"), resp_bytes=nbytes, usage=usage,
            n_tool_calls=len(msg.get("tool_calls") or []))
        messages.append(msg)
        calls = msg.get("tool_calls") or []
        if not calls:
            final = msg.get("content")
            break
        for c in calls:
            try:
                args = json.loads(c["function"]["arguments"] or "{}")
            except ValueError:
                args = {}
            out = run_tool(c["function"]["name"], args, a.cwd, log, step, a.tool_timeout)
            messages.append({"role": "tool", "tool_call_id": c["id"], "content": out})
    log(ev="session_end", final=(final or "")[:500], steps=step + 1)
    print(final or "(stopped: max steps)")


if __name__ == "__main__":
    main()
