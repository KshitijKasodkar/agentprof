"""Turn a run folder into an explanation of what the agent did.

    agentprof analyze runs/<run>      -> summary.json, report.md, report.html

Reconstruction, from kernel events only (no help from the agent):
  1. PROCESS TREE   fork/exec/exit events -> who started whom, with argv.
  2. AGENT MAIN     the process that talks to the LLM API (most LLM bytes).
  3. TOOL CALLS     each short-lived child subtree of the agent main process
                    (a `bash -c ...`, `rg`, `git`, `python -m pytest`...).
                    Long-lived children (MCP servers, persistent shells) are
                    "helpers"; their own short-lived children are tool calls.
  4. CONNECTIONS    named by TLS SNI / HTTP Host, classified (llm, telemetry,
                    package, dns, ...).
  5. EXCHANGES      on each connection, a request (burst of sends) and its
                    response (burst of receives): request bytes, time to first
                    response byte (TTFB), streaming time, response bytes.
  6. TIME SPLIT     wall clock = LLM only | tools only | both | neither.
  7. RESOURCES      CPU (user/kernel/run-queue/sleep/IO), syscalls, files,
                    memory, per role (agent / tools / helpers).
"""
import bisect
import collections
import json
import os
import statistics
import sys

from . import netparse

MIN_REQ_BYTES = 200        # smaller send bursts inside a response are control frames
HELPER_SHARE = 0.8         # a child living longer than 80 % of the run is a helper

SYSCALL_GROUPS = {
    "file": {"openat", "open", "openat2", "close", "read", "pread64", "readv", "preadv", "preadv2", "write",
             "pwrite64", "writev", "pwritev", "pwritev2", "newfstatat", "fstat", "stat", "lstat", "statx",
             "access", "faccessat", "faccessat2", "readlink", "readlinkat", "getdents64", "lseek", "fcntl",
             "ioctl", "unlink", "unlinkat", "rename", "renameat", "renameat2", "mkdir", "mkdirat", "fsync",
             "fdatasync", "ftruncate", "truncate", "chdir", "fchdir", "getcwd", "statfs", "fstatfs", "dup",
             "dup2", "dup3", "copy_file_range", "sendfile", "splice", "fchmod", "fchmodat", "chmod",
             "utimensat", "symlink", "symlinkat", "linkat", "fadvise64", "inotify_add_watch",
             "inotify_init1", "inotify_rm_watch", "flock", "umask", "pipe", "pipe2", "rmdir"},
    "network": {"socket", "connect", "accept", "accept4", "bind", "listen", "sendto", "recvfrom", "sendmsg",
                "recvmsg", "sendmmsg", "recvmmsg", "shutdown", "getsockopt", "setsockopt", "getsockname",
                "getpeername", "socketpair"},
    "wait/poll": {"epoll_wait", "epoll_pwait", "epoll_pwait2", "poll", "ppoll", "select", "pselect6",
                  "epoll_ctl", "epoll_create1", "eventfd2", "io_uring_enter", "timerfd_settime",
                  "timerfd_create"},
    "sync": {"futex", "futex_waitv", "sched_yield", "membarrier", "set_robust_list", "rseq"},
    "process": {"clone", "clone3", "fork", "vfork", "execve", "execveat", "wait4", "waitid", "exit",
                "exit_group", "kill", "tgkill", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
                "prctl", "arch_prctl", "set_tid_address", "getpid", "getppid", "gettid", "getuid",
                "geteuid", "getgid", "getegid", "setpgid", "getpgid", "setsid", "prlimit64", "pidfd_open",
                "sigaltstack", "capget", "getrlimit", "sched_getaffinity", "getrusage", "uname",
                "getrandom", "sysinfo", "getpgrp", "getgroups", "setgroups", "setuid", "setgid",
                "setresuid", "setresgid", "personality", "pidfd_send_signal", "close_range"},
    "memory": {"mmap", "munmap", "mprotect", "brk", "madvise", "mremap", "mlock", "munlock", "msync",
               "memfd_create", "mincore", "pkey_alloc", "pkey_mprotect"},
    "time": {"clock_gettime", "clock_nanosleep", "nanosleep", "gettimeofday", "clock_getres",
             "timer_settime", "setitimer", "alarm"},
}
GROUP_OF = {n: g for g, names in SYSCALL_GROUPS.items() for n in names}


def sgroup(name):
    return GROUP_OF.get(name, "other")


# --------------------------------------------------------------- loading

def load(run_dir):
    with open(os.path.join(run_dir, "meta.json")) as f:
        meta = json.load(f)
    events = []
    with open(os.path.join(run_dir, "events.jsonl")) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except ValueError:
                    pass       # truncated last line after a crash
    events.sort(key=lambda e: e["ts"])
    samples = []
    p = os.path.join(run_dir, "samples.jsonl")
    if os.path.exists(p):
        with open(p) as f:
            for line in f:
                try:
                    samples.append(json.loads(line))
                except ValueError:
                    pass
    final = {}
    p = os.path.join(run_dir, "final.json")
    if os.path.exists(p):
        with open(p) as f:
            final = json.load(f)
    pidmap = {int(k): v for k, v in (final.get("pidmap") or {}).items()}
    if pidmap:
        translate(events, final, pidmap)
    return meta, events, samples, final


def translate(events, final, pidmap):
    """Kernel events carry global PIDs; in a PID namespace (WSL2, containers)
    the user, /proc and the agent's own logs use namespace PIDs. Map every
    process ID; IDs without a mapping (threads) become negative so they can
    never collide with a namespace PID."""
    def m(x):
        if x is None or x == 0:
            return x
        return pidmap.get(x, -x)
    for e in events:
        e["tgid"] = m(e.get("tgid"))
        if "tid" in e:
            e["tid"] = m(e["tid"])
        if "child" in e:
            e["child"] = m(e["child"])
        if e.get("ev") == "connclose" and "owner" in e.get("conn", {}):
            e["conn"]["owner"] = m(e["conn"]["owner"])
    for r in final.get("sysagg", []):
        r["tgid"] = m(r["tgid"])
    final["pstats_alive"] = {str(m(int(k))): v for k, v in (final.get("pstats_alive") or {}).items()}
    for c in final.get("conns_open", []):
        c["owner"] = m(c.get("owner"))
    final["still_tracked"] = [m(x) for x in final.get("still_tracked", [])]


def union_len(intervals):
    total, cur_s, cur_e = 0, None, None
    for s, e in sorted(intervals):
        if e <= s:
            continue
        if cur_e is None or s > cur_e:
            if cur_e is not None:
                total += cur_e - cur_s
            cur_s, cur_e = s, e
        else:
            cur_e = max(cur_e, e)
    if cur_e is not None:
        total += cur_e - cur_s
    return total


def merge(intervals):
    out = []
    for s, e in sorted(intervals):
        if e <= s:
            continue
        if out and s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return out


def intersect_len(a, b):
    """total overlap of two merged interval lists"""
    i = j = 0
    tot = 0
    while i < len(a) and j < len(b):
        s = max(a[i][0], b[j][0])
        e = min(a[i][1], b[j][1])
        if e > s:
            tot += e - s
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return tot


def pct(a, b):
    return round(100.0 * a / b, 2) if b else 0.0


def med(xs):
    return statistics.median(xs) if xs else None


def ms(ns):
    return None if ns is None else round(ns / 1e6, 3)


# --------------------------------------------------------------- model

class Proc:
    def __init__(self, tgid):
        self.tgid = tgid
        self.ppid = None
        self.start = None
        self.end = None
        self.execs = []           # (ts, filename, argv, cmdline)
        self.argv_pending = None
        self.stats = None
        self.comm = None
        self.children = []
        self.alive_at_end = False
        self.role = "other"
        self.tool = None

    @property
    def argv(self):
        if self.execs:
            ts, fn, argv, cl = self.execs[-1]
            return cl or argv or [fn]
        return None

    def label(self, width=120):
        a = self.argv
        if a:
            s = " ".join(a)
        elif self.argv_pending:
            s = " ".join(self.argv_pending) + "  [exec failed]"
        else:
            s = f"(fork of {self.comm or '?'}, no exec)"
        return s if len(s) <= width else s[:width - 3] + "..."


class Conn:
    def __init__(self, e):
        self.sk = e["sk"]
        self.owner = e["tgid"]
        self.first = e["ts"]
        self.proto = "tcp" if e["proto"] == 6 else "udp" if e["proto"] == 17 else str(e["proto"])
        self.raddr = e.get("raddr")
        self.rport = e.get("rport")
        self.laddr = e.get("laddr")
        self.lport = e.get("lport")
        self.syn_ns = e.get("syn_ns") or None
        self.est_ns = e.get("est_ns") or None
        self.io = []              # (ts, dir, bytes, tid)
        self.sniffs = []          # (ts, dir, bytes)
        self.closed = None
        self.final = None
        self.retrans = 0
        self.sni = None
        self.alpn = []
        self.tls = False
        self.http = []            # parsed HTTP request heads (plain text)
        self.status = []
        self.exchanges = []

    @property
    def name(self):
        if self.sni:
            return self.sni
        for h in self.http:
            if h.get("host"):
                return h["host"]
        return f"{self.raddr}:{self.rport}" if self.raddr else f"sk{self.sk & 0xffff:x}"

    def tx(self):
        return sum(b for _, d, b, _ in self.io if d == "tx")

    def rx(self):
        return sum(b for _, d, b, _ in self.io if d == "rx")


def build(meta, events, final):
    procs = {}
    root = meta.get("root_pid")

    def P(t):
        p = procs.get(t)
        if p is None:
            p = procs[t] = Proc(t)
        return p

    fork_parent = {}
    conns_all, cur = [], {}
    connects = []
    opens = []
    for e in events:
        ev, t = e["ev"], e["tgid"]
        if ev == "fork":
            fork_parent.setdefault(e["child"], (t, e["ts"]))
            continue
        if ev in ("thread_exit",):
            continue
        if ev in ("tcpstate", "connclose", "retrans"):
            c = cur.get(e["sk"])
            if c is None:
                continue
            if ev == "tcpstate" and e["new"] == 7:
                c.closed = e["ts"]
            elif ev == "connclose":
                c.closed = c.closed or e["ts"]
                c.final = e["conn"]
                cur.pop(e["sk"], None)
            elif ev == "retrans":
                c.retrans += 1
            continue
        if t and t not in procs:
            P(t)
        if ev == "argv":
            P(t).argv_pending = e["argv"]
        elif ev == "exec":
            p = P(t)
            p.execs.append((e["ts"], e.get("filename"), p.argv_pending, e.get("cmdline")))
            p.argv_pending = None
            p.comm = e.get("comm")
        elif ev == "exit":
            p = P(t)
            p.end = e["ts"]
            p.stats = e["stats"]
            p.comm = p.comm or e.get("comm")
        elif ev == "conn":
            c = Conn(e)
            conns_all.append(c)
            cur[e["sk"]] = c
        elif ev == "io":
            c = cur.get(e["sk"])
            if c is not None:
                c.io.append((e["ts"], e["dir"], e["bytes"], e["tid"]))
        elif ev == "sniff":
            c = cur.get(e["sk"])
            if c is not None:
                c.sniffs.append((e["ts"], e["dir"], bytes.fromhex(e["hex"])))
        elif ev == "connect":
            connects.append(e)
        elif ev == "open":
            opens.append(e)

    t0 = meta["start_mono_ns"]
    t_end = final.get("end_mono_ns") or (events[-1]["ts"] if events else t0)
    if root in procs and procs[root].end:
        run_end = procs[root].end
    else:
        run_end = t_end
    alive = final.get("pstats_alive", {})
    for tg, p in procs.items():
        if tg in fork_parent:
            p.ppid, p.start = fork_parent[tg]
        if p.start is None:
            p.start = t0 if tg == root else min([x[0] for x in p.execs] + [p.end or t_end])
        if p.end is None:
            p.alive_at_end = True
            p.end = t_end
            st = alive.get(str(tg))
            if st:
                p.stats = st
        if p.stats is None:
            p.stats = {}
    for tg, p in procs.items():
        if p.ppid in procs:
            procs[p.ppid].children.append(tg)
    for p in procs.values():
        p.children.sort(key=lambda c: procs[c].start)
    return procs, conns_all, connects, opens, t0, run_end, t_end


# --------------------------------------------------------------- exchanges

def analyze_conn(c, llm_endpoints=()):
    for ts, d, data in c.sniffs:
        if d == "tx":
            ch = netparse.parse_client_hello(data)
            if ch:
                c.tls = True
                c.sni = c.sni or ch.get("sni")
                c.alpn = c.alpn or ch.get("alpn", [])
                continue
            h = netparse.parse_http_request(data)
            if h:
                h["ts"] = ts
                c.http.append(h)
        else:
            r = netparse.parse_http_response(data)
            if r:
                r["ts"] = ts
                c.status.append(r)
    # bursts: consecutive io in the same direction
    bursts = []
    for ts, d, b, tid in sorted(c.io):
        if bursts and bursts[-1]["dir"] == d:
            bb = bursts[-1]
            bb["end"] = ts
            bb["bytes"] += b
            bb["n"] += 1
        else:
            bursts.append({"dir": d, "start": ts, "end": ts, "bytes": b, "n": 1})
    exch = []
    cur = None
    rx_reads = []                       # (ts, bytes) of every receive, for TTFB refinement
    for ts, d, b, tid in sorted(c.io):
        if d == "rx":
            rx_reads.append((ts, b))
    for b in bursts:
        if b["dir"] == "tx":
            in_handshake = c.tls and len(exch) == 1 and cur is not None and cur["resp_bytes"] > 0
            if cur is not None and not in_handshake and b["bytes"] < MIN_REQ_BYTES and cur["resp_bytes"] > 0:
                cur["ctl_tx"] += b["bytes"]          # e.g. HTTP/2 WINDOW_UPDATE inside a stream
                continue
            if cur is not None and cur["resp_bytes"] == 0:
                cur["req_end"] = b["end"]            # request sent in several bursts
                cur["req_bytes"] += b["bytes"]
                continue
            cur = {"start": b["start"], "req_end": b["end"], "req_bytes": b["bytes"], "first_rx": None,
                   "last_rx": None, "resp_bytes": 0, "rx_reads": 0, "ctl_tx": 0}
            exch.append(cur)
        else:
            if cur is None:          # server spoke first (or pre-tracing request)
                cur = {"start": b["start"], "req_end": b["start"], "req_bytes": 0, "first_rx": b["start"],
                       "last_rx": b["end"], "resp_bytes": 0, "rx_reads": 0, "ctl_tx": 0}
                exch.append(cur)
            if cur["first_rx"] is None:
                cur["first_rx"] = b["start"]
            cur["last_rx"] = b["end"]
            cur["resp_bytes"] += b["bytes"]
            cur["rx_reads"] += b["n"]
    # label: TLS handshake / HTTP path
    http_q = sorted(c.http, key=lambda h: h["ts"])
    for i, x in enumerate(exch):
        x["kind"] = "data"
        if c.tls and i == 0:
            x["kind"] = "tls-handshake"
        # plain HTTP: the request line sniffed at the start of this request
        for h in http_q:
            if x["start"] - 1_000 <= h["ts"] <= x["req_end"] + 1_000:
                x["path"] = h["path"]
                x["method"] = h["method"]
                break
        x["ttfb"] = (x["first_rx"] - x["req_end"]) if x["first_rx"] is not None else None
        # TLS 1.3: the server sends session tickets as soon as it gets the client's
        # Finished, which travels together with the first request. Those few hundred
        # bytes arrive ~1 RTT later, long before the model answers. Skip them.
        if c.tls and i == 1 and x["first_rx"] is not None:
            rtt = (c.est_ns - c.syn_ns) if (c.est_ns and c.syn_ns and c.est_ns > c.syn_ns) else 0
            # +60 ms covers a ticket held back by Nagle until the peer's delayed ACK (40 ms on Linux)
            window = x["req_end"] + int(1.5 * rtt) + 60_000_000
            lo = bisect.bisect_left(rx_reads, (x["first_rx"], -1))
            skipped = 0
            j = lo
            while j < len(rx_reads) and rx_reads[j][0] <= window and skipped + rx_reads[j][1] <= 1024 \
                    and rx_reads[j][0] <= (x["last_rx"] or 0):
                skipped += rx_reads[j][1]
                j += 1
            if skipped and j < len(rx_reads) and rx_reads[j][0] <= (x["last_rx"] or 0):
                x["tls_tickets_bytes"] = skipped
                x["first_rx"] = rx_reads[j][0]
                x["ttfb"] = x["first_rx"] - x["req_end"]
        x["stream"] = (x["last_rx"] - x["first_rx"]) if x["first_rx"] is not None else None
        x["dur"] = ((x["last_rx"] or x["req_end"]) - x["start"])
    c.exchanges = exch
    paths = [h["path"] for h in c.http]
    c.category = netparse.categorize(c.sni or (c.http[0]["host"] if c.http and c.http[0].get("host") else None),
                                     c.rport, c.raddr, paths)
    for ep in llm_endpoints:          # user-declared LLM servers (self-hosted model on an IP, ...)
        host, _, port = ep.rpartition(":")
        if (host in (c.raddr, c.sni, "*")) and str(c.rport) == port or ep in (c.sni, c.name):
            c.category = "llm"
    for x in exch:
        if x["kind"] == "tls-handshake":
            continue
        if c.category == "llm":
            if x.get("path") is not None:
                x["kind"] = "llm" if netparse.is_llm_path(x["path"]) else "llm-aux"
            elif x["req_bytes"] >= MIN_REQ_BYTES and x["resp_bytes"] > 0:
                x["kind"] = "llm"
            else:
                x["kind"] = "llm-aux"


# --------------------------------------------------------------- tool calls

def subtree(procs, tg):
    out, todo = [], [tg]
    while todo:
        x = todo.pop()
        out.append(x)
        todo.extend(procs[x].children)
    return out


def find_tool_calls(procs, main, run_start, run_end):
    dur = max(1, run_end - run_start)
    tools, helpers = [], []

    def visit(parent):
        for ch in procs[parent].children:
            p = procs[ch]
            life = p.end - p.start
            long_lived = p.alive_at_end or life > HELPER_SHARE * dur
            if long_lived and p.children:
                helpers.append(ch)
                visit(ch)
            elif long_lived:
                helpers.append(ch)
            else:
                tools.append(ch)
    visit(main)
    return tools, helpers


def sum_stats(procs, tgids, keys):
    out = {k: 0 for k in keys}
    for t in tgids:
        st = procs[t].stats or {}
        for k in keys:
            out[k] += st.get(k, 0) or 0
    return out


CPU_KEYS = ["user_ns", "sys_ns", "runq_ns", "sleep_ns", "io_ns", "vcsw", "ivcsw", "syscalls", "sys_errs",
            "sys_wall_ns", "inet_tx", "inet_rx", "unix_tx", "unix_rx", "file_rd", "file_wr", "other_rd",
            "other_wr", "opens", "open_fail", "forks"]


# --------------------------------------------------------------- main analysis

def analyze(run_dir, llm_endpoints=()):
    meta, events, samples, final = load(run_dir)
    procs, conns, connects, opens, t0, run_end, t_end = build(meta, events, final)
    eps = list(llm_endpoints) + list(meta.get("llm_endpoints") or [])
    for c in conns:
        analyze_conn(c, eps)
    root = meta.get("root_pid")
    run_dur = max(1, run_end - t0)

    # ---- agent main: the process that moves the most LLM bytes
    llm_bytes = collections.Counter()
    for c in conns:
        if c.category == "llm":
            llm_bytes[c.owner] += c.tx() + c.rx()
    if llm_bytes:
        main = llm_bytes.most_common(1)[0][0]
    else:
        inet = collections.Counter()
        for c in conns:
            inet[c.owner] += c.tx() + c.rx()
        main = inet.most_common(1)[0][0] if inet else root
    if main not in procs:
        main = root
    for p in procs.values():
        p.role = "other"
    if main in procs:
        procs[main].role = "agent"
    tools, helpers = find_tool_calls(procs, main, t0, run_end) if main in procs else ([], [])
    tool_calls = []
    for i, tg in enumerate(sorted(tools, key=lambda t: procs[t].start)):
        members = subtree(procs, tg)
        for m in members:
            procs[m].role = "tool"
            procs[m].tool = i
        end = max(procs[m].end for m in members)
        tool_calls.append({"id": i, "tgid": tg, "members": members, "start": procs[tg].start, "end": end})
    for h in helpers:
        if procs[h].role == "other":
            procs[h].role = "helper"
    # processes between the root and the agent main (wrappers) stay "other"

    # ---- exchanges
    llm_x, other_x = [], []
    for ci, c in enumerate(conns):
        for x in c.exchanges:
            x["conn"] = ci
            x["owner"] = c.owner
            (llm_x if x["kind"] in ("llm", "llm-aux") else other_x).append(x)
    llm_x.sort(key=lambda x: x["start"])
    llm_main = [x for x in llm_x if x["kind"] == "llm"]

    # ---- phase of each tool call relative to the LLM calls:
    #  "startup" before the first LLM call, "act" between the end of one LLM
    #  response and the next request (where model-requested tools run),
    #  "during-llm" while a request is in flight (agent housekeeping),
    #  "after" after the last LLM call.
    llm_iv = [(x["start"], x["last_rx"] or x["req_end"]) for x in llm_x]
    for tc in tool_calls:
        st = tc["start"]
        if not llm_iv or st < llm_iv[0][0]:
            tc["phase"] = "startup"
        elif any(a <= st <= b for a, b in llm_iv):
            tc["phase"] = "during-llm"
        elif st > max(b for _, b in llm_iv):
            tc["phase"] = "after"
        else:
            tc["phase"] = "act"

    # ---- time decomposition
    L = merge([(x["start"], x["last_rx"] or x["req_end"]) for x in llm_x])
    T = merge([(tc["start"], tc["end"]) for tc in tool_calls])
    clipL = merge([(max(s, t0), min(e, run_end)) for s, e in L])
    clipT = merge([(max(s, t0), min(e, run_end)) for s, e in T])
    l_tot, t_tot = union_len(clipL), union_len(clipT)
    both = intersect_len(clipL, clipT)
    llm_only, tool_only = l_tot - both, t_tot - both
    neither = run_dur - llm_only - tool_only - both
    first_llm = llm_x[0]["start"] if llm_x else None
    last_llm = max((x["last_rx"] or x["req_end"]) for x in llm_x) if llm_x else None
    ttfbs = [x["ttfb"] for x in llm_main if x["ttfb"] is not None]
    streams = [x["stream"] for x in llm_main if x["stream"] is not None]

    # agent-side time between consecutive LLM calls (response end -> next request):
    # tool dispatch + tool execution + agent processing. Plus start-up, this is the
    # closest match to AgentCgroup's "OS-level overhead (initialization + tool execution)".
    between = 0
    for a_, b_ in zip(L, L[1:]):
        between += max(0, b_[0] - a_[1])
    startup_ns = (first_llm - t0) if first_llm else run_dur
    tail_ns = (run_end - last_llm) if last_llm else 0
    # provider back-off (rate limits / overload): the agent's own log says when it slept
    # before retrying. Kernel-side this is idle time, so it would otherwise be counted as
    # "neither" (and as OS time). Also: tool uses that run inside the agent (read/write file).
    alog = agent_log_events(run_dir)
    backoff = merge([(max(r["t"], t0), min(r["t"] + int(r.get("wait_s", 0) * 1e9), run_end))
                     for r in alog if r.get("ev") == "llm_retry"])
    busy = merge(clipL + clipT)
    backoff_only = union_len(backoff) - intersect_len(backoff, busy)
    n_retries = sum(1 for r in alog if r.get("ev") == "llm_retry")
    logged_tool_uses = sum(1 for r in alog if r.get("ev") == "tool_start")
    timesplit = {
        "run_s": round(run_dur / 1e9, 3),
        "llm_only_s": round(llm_only / 1e9, 3), "tool_only_s": round(tool_only / 1e9, 3),
        "both_s": round(both / 1e9, 3), "neither_s": round((neither - backoff_only) / 1e9, 3),
        "llm_share_pct": pct(l_tot, run_dur), "tool_share_pct": pct(t_tot, run_dur),
        "llm_only_pct": pct(llm_only, run_dur), "tool_only_pct": pct(tool_only, run_dur),
        "both_pct": pct(both, run_dur), "neither_pct": pct(neither - backoff_only, run_dur),
        "startup_s": round((first_llm - t0) / 1e9, 3) if first_llm else None,
        "after_last_llm_s": round((run_end - last_llm) / 1e9, 3) if last_llm else None,
        "between_llm_calls_s": round(between / 1e9, 3),
        "provider_backoff_s": round(backoff_only / 1e9, 3),
        "provider_backoff_pct": pct(backoff_only, run_dur),
        "os_exec_like_pct": pct(max(0, startup_ns + between + tail_ns - backoff_only), run_dur),
        "llm_wait_ttfb_s": round(sum(ttfbs) / 1e9, 3) if ttfbs else 0,
        "llm_streaming_s": round(sum(streams) / 1e9, 3) if streams else 0,
    }

    # ---- roles: CPU / syscalls / IO
    roles = collections.defaultdict(list)
    for t, p in procs.items():
        roles[p.role].append(t)
    role_stats = {r: sum_stats(procs, ts, CPU_KEYS) for r, ts in roles.items()}
    for r, st in role_stats.items():
        st["processes"] = len(roles[r])

    sys_rows = final.get("sysagg", [])
    by_role_sys = collections.defaultdict(lambda: collections.defaultdict(lambda: [0, 0, 0, 0]))
    per_tgid_sys = collections.defaultdict(lambda: collections.Counter())
    for r in sys_rows:
        p = procs.get(r["tgid"])
        role = p.role if p else "other"
        v = by_role_sys[role][r["name"]]
        v[0] += r["count"]
        v[1] += r["total_ns"]
        v[2] = max(v[2], r["max_ns"])
        v[3] += r["errs"]
        per_tgid_sys[r["tgid"]][r["name"]] += r["count"]
    syscalls = {}
    for role, d in by_role_sys.items():
        rows = [{"name": n, "group": sgroup(n), "count": v[0], "total_ms": round(v[1] / 1e6, 3),
                 "avg_us": round(v[1] / v[0] / 1e3, 2) if v[0] else 0, "max_ms": round(v[2] / 1e6, 3),
                 "errs": v[3]} for n, v in d.items()]
        rows.sort(key=lambda x: -x["count"])
        groups = collections.defaultdict(lambda: {"count": 0, "total_ms": 0.0})
        for x in rows:
            groups[x["group"]]["count"] += x["count"]
            groups[x["group"]]["total_ms"] = round(groups[x["group"]]["total_ms"] + x["total_ms"], 3)
        syscalls[role] = {"total": sum(x["count"] for x in rows), "distinct": len(rows), "top": rows[:25],
                          "groups": dict(groups)}
    hist = collections.defaultdict(dict)
    for h in final.get("syshist", []):
        hist[h["name"]][h["slot"]] = hist[h["name"]].get(h["slot"], 0) + h["count"]

    # ---- memory from samples
    peak_rss_kb = collections.Counter()
    hwm_kb = collections.Counter()
    total_rss_series = []
    agent_cpu_series = []
    prev_cpu = None
    cg_series = []
    for s in samples:
        tot = 0
        for pid_s, st in s.get("procs", {}).items():
            pid = int(pid_s)
            if pid not in procs or st.get("Tgid", pid) != pid:
                continue                 # threads report their process's memory: count it once
            tot += st.get("VmRSS", 0)
            peak_rss_kb[pid] = max(peak_rss_kb[pid], st.get("VmRSS", 0))
            hwm_kb[pid] = max(hwm_kb[pid], st.get("VmHWM", 0))
            if pid == main:
                cpu = st.get("utime", 0) + st.get("stime", 0)
                if prev_cpu is not None:
                    agent_cpu_series.append((s["ts"], cpu - prev_cpu[1], s["ts"] - prev_cpu[0]))
                prev_cpu = (s["ts"], cpu)
        total_rss_series.append((s["ts"], tot))
        if s.get("cgroup") and isinstance(s["cgroup"].get("memory.current"), int):
            cg_series.append((s["ts"], s["cgroup"]["memory.current"]))
    mem_series = cg_series or [(t, kb * 1024) for t, kb in total_rss_series]
    mem_vals = [v for _, v in mem_series if v > 0]
    memory = {
        "source": "cgroup memory.current" if cg_series else "sum of VmRSS of traced processes",
        "peak_bytes": max(mem_vals) if mem_vals else None,
        "avg_bytes": int(sum(mem_vals) / len(mem_vals)) if mem_vals else None,
        "peak_to_avg": round(max(mem_vals) / (sum(mem_vals) / len(mem_vals)), 2) if mem_vals else None,
        "agent_main_hwm_kb": hwm_kb.get(main),
        "cgroup_final": final.get("cgroup_final"),
        "note": "200 ms sampling: processes shorter than that may be missed; cgroup memory.peak is exact",
    }

    # ---- tool call details
    clk = meta.get("host", {}).get("clk_tck", 100)
    tc_out = []
    for tc in tool_calls:
        top = procs[tc["tgid"]]
        st = sum_stats(procs, tc["members"], CPU_KEYS)
        sysc = collections.Counter()
        for m in tc["members"]:
            sysc.update(per_tgid_sys.get(m, {}))
        argv = top.argv or []
        cmd = None
        if len(argv) >= 3 and os.path.basename(argv[0]) in ("bash", "sh", "zsh", "dash") and argv[1] in ("-c", "-lc", "-c -l"):
            cmd = argv[2]
        elif len(argv) >= 4 and os.path.basename(argv[0]) in ("bash", "sh", "zsh") and "-c" in argv[1:3]:
            cmd = argv[argv.index("-c") + 1] if argv.index("-c") + 1 < len(argv) else None
        tc_out.append({
            "id": tc["id"], "pid": tc["tgid"], "label": top.label(160), "command": cmd, "phase": tc["phase"],
            "start_s": round((tc["start"] - t0) / 1e9, 4), "dur_ms": ms(tc["end"] - tc["start"]),
            "processes": len(tc["members"]),
            "programs": sorted({os.path.basename((procs[m].execs[-1][1] or "")) for m in tc["members"]
                                if procs[m].execs} - {""}),
            "exit_code": (top.stats or {}).get("exit_code"),
            "cpu_user_ms": ms(st["user_ns"]), "cpu_sys_ms": ms(st["sys_ns"]), "runq_ms": ms(st["runq_ns"]),
            "sleep_ms": ms(st["sleep_ns"]), "io_wait_ms": ms(st["io_ns"]),
            "syscalls": st["syscalls"], "top_syscalls": sysc.most_common(6),
            "file_read": st["file_rd"], "file_write": st["file_wr"], "pipe_other_rd": st["other_rd"],
            "pipe_other_wr": st["other_wr"], "net_tx": st["inet_tx"], "net_rx": st["inet_rx"],
            "opens": st["opens"], "open_fail": st["open_fail"],
            "peak_rss_kb": max([hwm_kb.get(m, 0) for m in tc["members"]] or [0]) or None,
        })

    # ---- connections
    conn_out = []
    for ci, c in enumerate(conns):
        hs = None
        if c.syn_ns and c.est_ns and c.est_ns >= c.syn_ns:
            hs = ms(c.est_ns - c.syn_ns)
        tlsx = next((x for x in c.exchanges if x["kind"] == "tls-handshake"), None)
        conn_out.append({
            "id": ci, "name": c.name, "category": c.category, "proto": c.proto, "remote": f"{c.raddr}:{c.rport}",
            "local_port": c.lport, "owner": c.owner, "owner_role": procs[c.owner].role if c.owner in procs else "?",
            "owner_label": procs[c.owner].label(60) if c.owner in procs else "?",
            "tls": c.tls, "alpn": c.alpn, "tx": c.tx(), "rx": c.rx(),
            "start_s": round((c.first - t0) / 1e9, 4),
            "life_s": round(((c.closed or t_end) - c.first) / 1e9, 3),
            "tcp_handshake_ms": hs, "tls_handshake_ms": ms(tlsx["dur"]) if tlsx else None,
            "exchanges": len([x for x in c.exchanges if x["kind"] != "tls-handshake"]),
            "retrans": c.retrans, "http_paths": sorted({h["path"] for h in c.http})[:10],
            "http_status": sorted({s["status"] for s in c.status}),
        })
    cats = collections.defaultdict(lambda: {"connections": 0, "tx": 0, "rx": 0, "exchanges": 0})
    for c in conn_out:
        k = cats[c["category"]]
        k["connections"] += 1
        k["tx"] += c["tx"]
        k["rx"] += c["rx"]
        k["exchanges"] += c["exchanges"]

    # ---- LLM calls (in order) and context growth
    calls = []
    for i, x in enumerate(llm_x):
        calls.append({"n": i, "kind": x["kind"], "conn": x["conn"], "endpoint": conns[x["conn"]].name,
                      "start_s": round((x["start"] - t0) / 1e9, 4), "req_bytes": x["req_bytes"],
                      "resp_bytes": x["resp_bytes"], "ttfb_ms": ms(x["ttfb"]), "stream_ms": ms(x["stream"]),
                      "total_ms": ms(x["dur"]), "rx_reads": x["rx_reads"], "path": x.get("path")})
    req_sizes = [x["req_bytes"] for x in llm_main]
    appends = [b - a for a, b in zip(req_sizes, req_sizes[1:])]

    # ---- files
    path_count = collections.Counter()
    path_fail = collections.Counter()
    by_role_files = collections.defaultdict(lambda: collections.Counter())
    for e in opens:
        p = procs.get(e["tgid"])
        role = p.role if p else "other"
        path = e.get("path") or ""
        cls = classify_path(path)
        by_role_files[role][cls] += 1
        if e["ret"] >= 0:
            path_count[path] += 1
        else:
            path_fail[path] += 1
    files = {"opens_by_role_and_area": {r: dict(c.most_common()) for r, c in by_role_files.items()},
             "top_opened": path_count.most_common(25), "top_failed": path_fail.most_common(15),
             "distinct_paths": len(path_count), "failed_opens": sum(path_fail.values())}

    # ---- DNS
    dns = [c for c in conn_out if c["category"] == "dns"]

    # ---- tool-call / LLM-call relation
    n_tools = len(tool_calls)
    n_llm = len(llm_main)
    gaps = []
    for a, b in zip(llm_main, llm_main[1:]):
        gaps.append(b["start"] - (a["last_rx"] or a["req_end"]))

    tracer = {
        "events": final.get("n_events"), "ringbuf_dropped": final.get("ringbuf_dropped"),
        "bpf_load_s": meta.get("bpf_load_s"), "warnings": meta.get("warnings"),
        "bpf_prog_stats": final.get("bpf_prog_stats"),
    }
    ps = final.get("bpf_prog_stats") or {}
    if ps:
        tot_ns = sum(v[0] for v in ps.values())
        tot_cnt = sum(v[1] for v in ps.values())
        tracer["bpf_total_ms"] = round(tot_ns / 1e6, 3)
        tracer["bpf_runs"] = tot_cnt
        tracer["bpf_avg_ns"] = round(tot_ns / tot_cnt, 1) if tot_cnt else None
        tracer["bpf_cpu_pct_of_run"] = pct(tot_ns, run_dur)

    agent = procs.get(main)
    summary = {
        "run": os.path.basename(os.path.abspath(run_dir)),
        "label": meta.get("label"), "command": meta.get("command"), "host": meta.get("host"),
        "exit_code": meta.get("exit_code"),
        "agent_main": {"pid": main, "label": agent.label(160) if agent else None},
        "counts": {"processes": len(procs), "tool_calls": n_tools, "helpers": len(helpers),
                   "tool_calls_act_phase": sum(1 for t in tool_calls if t["phase"] == "act"),
                   "llm_retries": n_retries, "llm_calls_successful": max(0, n_llm - n_retries) if alog else None,
                   "tool_uses_logged": logged_tool_uses if alog else None,
                   "tool_calls_by_phase": dict(collections.Counter(t["phase"] for t in tool_calls)),
                   "llm_calls": n_llm, "llm_aux_calls": len(llm_x) - n_llm,
                   "connections": len(conns), "tool_calls_per_llm_call": round(n_tools / n_llm, 2) if n_llm else None},
        "timesplit": timesplit,
        "llm": {
            "endpoints": sorted({conns[x["conn"]].name for x in llm_x}),
            "ttfb_ms_median": ms(med(ttfbs)), "ttfb_ms_max": ms(max(ttfbs)) if ttfbs else None,
            "stream_ms_median": ms(med(streams)),
            "req_bytes_first": req_sizes[0] if req_sizes else None,
            "req_bytes_last": req_sizes[-1] if req_sizes else None,
            "req_bytes_median": med(req_sizes), "append_bytes_median": med(appends),
            "resp_bytes_median": med([x["resp_bytes"] for x in llm_main]),
            "gap_between_calls_ms_median": ms(med(gaps)),
            "calls": calls,
        },
        "roles": role_stats,
        "syscalls": syscalls,
        "syscall_hist": {k: v for k, v in hist.items()},
        "memory": memory,
        "network": {"by_category": dict(cats), "connections": conn_out, "dns_lookups": len(dns)},
        "files": files,
        "tool_calls": tc_out,
        "helpers": [{"pid": h, "label": procs[h].label(120), "alive_at_end": procs[h].alive_at_end,
                     "life_s": round((procs[h].end - procs[h].start) / 1e9, 3)} for h in helpers],
        "process_tree": tree_text(procs, root, t0),
        "tracer": tracer,
        "paper_metrics": paper_metrics(timesplit, n_llm, n_tools, memory, req_sizes, appends, llm_main),
    }
    timeline = {"t0": t0, "run_end": run_end,
                "llm": [(x["start"], x["req_end"], x["first_rx"], x["last_rx"], x["kind"], x["req_bytes"],
                         x["resp_bytes"]) for x in llm_x],
                "tools": [(tc["start"], tc["end"], tc_out[i]["label"], tc_out[i]["exit_code"])
                          for i, tc in enumerate(tool_calls)],
                "other_net": [(x["start"], x["last_rx"] or x["req_end"], conns[x["conn"]].category,
                               conns[x["conn"]].name) for x in other_x],
                "mem": mem_series, "agent_cpu": agent_cpu_series, "clk_tck": clk}
    return summary, timeline


def agent_log_events(run_dir):
    """ref_agent's own log, if this run has one (same clock as the kernel)."""
    p = os.path.join(run_dir, "ref_agent_truth.jsonl")
    out = []
    if os.path.exists(p):
        for line in open(p):
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


def classify_path(p):
    if not p:
        return "?"
    for pre, name in (("/proc/", "/proc"), ("/sys/", "/sys"), ("/dev/", "/dev"), ("/etc/", "/etc"),
                      ("/tmp/", "/tmp"), ("/usr/lib", "system libs"), ("/lib", "system libs"),
                      ("/usr/share", "/usr/share"), ("/usr/", "/usr")):
        if p.startswith(pre):
            return name
    if "/node_modules/" in p:
        return "node_modules"
    if "/.git/" in p or p.endswith("/.git"):
        return ".git"
    if "/site-packages/" in p or "/dist-packages/" in p or "/python3" in p:
        return "python libs"
    if "/." in p:
        return "dot-dirs (config/cache)"
    return "project/other"


def paper_metrics(ts, n_llm, n_tools, memory, req_sizes, appends, llm_main):
    """Numbers that line up with what the reference papers report."""
    return {
        "os_exec_like_pct": ts["os_exec_like_pct"],
        "tool_exec_share_pct": ts["tool_share_pct"],
        "llm_share_pct": ts["llm_share_pct"],
        "llm_calls": n_llm,
        "tool_calls": n_tools,
        "tool_calls_per_llm_call": round(n_tools / n_llm, 2) if n_llm else None,
        "provider_backoff_pct": ts["provider_backoff_pct"],
        "memory_peak_to_avg": memory.get("peak_to_avg"),
        "req_bytes_growth": (round(req_sizes[-1] / req_sizes[0], 2) if len(req_sizes) > 1 and req_sizes[0] else None),
        "append_bytes_median": med(appends),
        "resp_to_req_bytes": (round(sum(x["resp_bytes"] for x in llm_main) /
                                    max(1, sum(x["req_bytes"] for x in llm_main)), 4) if llm_main else None),
    }


def tree_text(procs, root, t0, max_lines=400):
    lines = []

    def walk(tg, depth):
        if len(lines) >= max_lines or tg not in procs:
            return
        p = procs[tg]
        st = p.stats or {}
        dur = (p.end - p.start) / 1e6 if p.end and p.start else 0
        tag = {"agent": "[AGENT] ", "tool": f"[tool {p.tool}] ", "helper": "[helper] "}.get(p.role, "")
        lines.append(f"{'  ' * depth}{tg} {tag}{p.label(100)}  "
                     f"(+{(p.start - t0) / 1e9:.3f}s, {dur:.1f} ms, cpu u/s {st.get('user_ns', 0) / 1e6:.1f}/"
                     f"{st.get('sys_ns', 0) / 1e6:.1f} ms, exit {st.get('exit_code', '?')}"
                     f"{', ALIVE' if p.alive_at_end else ''})")
        for c in p.children:
            walk(c, depth + 1)
    walk(root, 0)
    orphans = [t for t, p in procs.items() if p.ppid not in procs and t != root]
    for t in orphans:
        walk(t, 0)
    return lines


# --------------------------------------------------------------- outputs

def fmt_bytes(n):
    if n is None:
        return "-"
    n = float(n)
    for u in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024 or u == "GB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


def write_md(run_dir, s):
    L = []
    ts = s["timesplit"]
    L.append(f"# agentprof report: {s['label'] or s['run']}\n")
    L.append(f"Command: `{' '.join(s['command'] or [])}`  \nHost: {s['host'].get('hostname')} "
             f"({s['host'].get('model') or s['host'].get('machine')}, kernel {s['host'].get('kernel')}, "
             f"{s['host'].get('cpus')} CPUs)  \nAgent main process: `{s['agent_main']['label']}` "
             f"(pid {s['agent_main']['pid']}), exit code {s['exit_code']}\n")
    c = s["counts"]
    L.append("## Agent loop\n")
    L.append("| wall time | LLM calls (HTTP) | of which retries | aux LLM calls | tool processes | tool uses (agent log) | processes | connections |")
    L.append("|---|---|---|---|---|---|---|---|")
    L.append(f"| {ts['run_s']} s | {c['llm_calls']} | {c.get('llm_retries', 0)} | {c['llm_aux_calls']} | {c['tool_calls']} | "
             f"{c.get('tool_uses_logged') if c.get('tool_uses_logged') is not None else '-'} | {c['processes']} | {c['connections']} |\n")
    L.append("## Where the wall-clock time went\n")
    L.append("| LLM only | tools only | both | provider back-off (retry waits) | neither (agent CPU, start-up, idle) | startup before 1st LLM call |")
    L.append("|---|---|---|---|---|---|")
    L.append(f"| {ts['llm_only_s']} s ({ts['llm_only_pct']} %) | {ts['tool_only_s']} s ({ts['tool_only_pct']} %) | "
             f"{ts['both_s']} s ({ts['both_pct']} %) | {ts['provider_backoff_s']} s ({ts['provider_backoff_pct']} %) | "
             f"{ts['neither_s']} s ({ts['neither_pct']} %) | {ts['startup_s']} s |\n")
    L.append(f"LLM busy {ts['llm_share_pct']} % of the run (waiting for the first byte {ts['llm_wait_ttfb_s']} s, "
             f"streaming {ts['llm_streaming_s']} s); tool processes running {ts['tool_share_pct']} %. "
             f"Start-up + time between LLM calls + tail (AgentCgroup's 'OS-level overhead' definition): "
             f"{ts['os_exec_like_pct']} %.\n")
    lm = s["llm"]
    L.append("## LLM calls (from the kernel's view of the sockets)\n")
    L.append(f"Endpoints: {', '.join(lm['endpoints']) or '-'}. Median TTFB {lm['ttfb_ms_median']} ms, "
             f"median streaming {lm['stream_ms_median']} ms, request size {fmt_bytes(lm['req_bytes_first'])} → "
             f"{fmt_bytes(lm['req_bytes_last'])} (context growth), median append {fmt_bytes(lm['append_bytes_median'])}, "
             f"median gap between calls {lm['gap_between_calls_ms_median']} ms.\n")
    L.append("| # | kind | start s | request | response | TTFB ms | streaming ms | total ms | path |")
    L.append("|---|---|---|---|---|---|---|---|---|")
    for x in lm["calls"][:200]:
        L.append(f"| {x['n']} | {x['kind']} | {x['start_s']} | {fmt_bytes(x['req_bytes'])} | {fmt_bytes(x['resp_bytes'])} "
                 f"| {x['ttfb_ms']} | {x['stream_ms']} | {x['total_ms']} | {x['path'] or ''} |")
    L.append("")
    L.append("## Tool calls (child processes of the agent)\n")
    L.append(f"By phase: {c['tool_calls_by_phase']} (act = between an LLM response and the next request, "
             "where model-requested tools run; startup/during-llm = the agent's own housekeeping)\n")
    L.append("| # | phase | start s | ms | exit | procs | CPU user/sys ms | sleep ms | syscalls | file R/W | command |")
    L.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for t in s["tool_calls"][:300]:
        cmd = (t["command"] or t["label"]).replace("|", "\\|").replace("\n", " ")[:110]
        L.append(f"| {t['id']} | {t['phase']} | {t['start_s']} | {t['dur_ms']} | {t['exit_code']} | {t['processes']} | "
                 f"{t['cpu_user_ms']}/{t['cpu_sys_ms']} | {t['sleep_ms']} | {t['syscalls']} | "
                 f"{fmt_bytes(t['file_read'])}/{fmt_bytes(t['file_write'])} | `{cmd}` |")
    if s["helpers"]:
        L.append("\nHelpers (long-lived children): " + "; ".join(f"`{h['label'][:80]}`" for h in s["helpers"]))
    L.append("\n## CPU and blocking per role\n")
    L.append("Times are summed over all threads (a 10-thread runtime that sleeps 2 s shows 20 s of sleep).\n")
    L.append("| role | procs | user ms | kernel ms | run-queue ms | sleep ms | disk-wait ms | syscalls | errors | ctx sw vol/invol |")
    L.append("|---|---|---|---|---|---|---|---|---|---|")
    for r, st in sorted(s["roles"].items()):
        L.append(f"| {r} | {st['processes']} | {ms(st['user_ns'])} | {ms(st['sys_ns'])} | {ms(st['runq_ns'])} | "
                 f"{ms(st['sleep_ns'])} | {ms(st['io_ns'])} | {st['syscalls']} | {st['sys_errs']} | "
                 f"{st['vcsw']}/{st['ivcsw']} |")
    L.append("\n## System calls\n")
    for role, d in s["syscalls"].items():
        L.append(f"**{role}**: {d['total']} calls, {d['distinct']} distinct. By group: " +
                 ", ".join(f"{g} {v['count']} ({v['total_ms']:.1f} ms)" for g, v in
                           sorted(d["groups"].items(), key=lambda kv: -kv[1]["count"])) + "\n")
        L.append("| syscall | group | count | total ms | avg µs | max ms | errors |")
        L.append("|---|---|---|---|---|---|---|")
        for x in d["top"][:12]:
            L.append(f"| {x['name']} | {x['group']} | {x['count']} | {x['total_ms']} | {x['avg_us']} | {x['max_ms']} | {x['errs']} |")
        L.append("")
    L.append("## Network\n")
    L.append("| category | connections | exchanges | sent | received |")
    L.append("|---|---|---|---|---|")
    for k, v in sorted(s["network"]["by_category"].items()):
        L.append(f"| {k} | {v['connections']} | {v['exchanges']} | {fmt_bytes(v['tx'])} | {fmt_bytes(v['rx'])} |")
    L.append("")
    L.append("| endpoint | cat | owner | TCP hs ms | TLS hs ms | ALPN | life s | exch | sent | recv | retx |")
    L.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for x in s["network"]["connections"][:80]:
        L.append(f"| {x['name']} | {x['category']} | {x['owner_role']} | {x['tcp_handshake_ms']} | {x['tls_handshake_ms']} | "
                 f"{','.join(x['alpn'])} | {x['life_s']} | {x['exchanges']} | {fmt_bytes(x['tx'])} | {fmt_bytes(x['rx'])} | {x['retrans']} |")
    m = s["memory"]
    L.append(f"\n## Memory\n\nPeak {fmt_bytes(m['peak_bytes'])}, average {fmt_bytes(m['avg_bytes'])}, "
             f"peak/average {m['peak_to_avg']} ({m['source']}). Agent main high-water mark "
             f"{fmt_bytes((m['agent_main_hwm_kb'] or 0) * 1024)}.\n")
    f = s["files"]
    L.append(f"## Files\n\n{f['distinct_paths']} distinct paths opened, {f['failed_opens']} failed opens.\n")
    for role, d in f["opens_by_role_and_area"].items():
        L.append(f"- {role}: " + ", ".join(f"{k} {v}" for k, v in d.items()))
    if s.get("agent_log"):
        L.append("\n## Cross-check with the agent's own log\n")
        for k, v in s["agent_log"].items():
            if k not in ("prompt_tokens_per_call", "output_tokens_per_call"):
                L.append(f"- {k}: {v}")
    L.append("\n## Paper-comparable metrics\n")
    for k, v in s["paper_metrics"].items():
        L.append(f"- {k}: {v}")
    tr = s["tracer"]
    L.append(f"\n## Tracer\n\n{tr['events']} events, {tr['ringbuf_dropped']} dropped, load {tr['bpf_load_s']} s, "
             f"eBPF {tr.get('bpf_runs')} runs avg {tr.get('bpf_avg_ns')} ns, total {tr.get('bpf_total_ms')} ms "
             f"({tr.get('bpf_cpu_pct_of_run')} % of one CPU over the run). Warnings: {tr['warnings']}\n")
    L.append("## Process tree\n\n```")
    L.extend(s["process_tree"][:300])
    L.append("```")
    with open(os.path.join(run_dir, "report.md"), "w") as fh:
        fh.write("\n".join(L) + "\n")


def write_html(run_dir, s, tl):
    from . import html_report
    with open(os.path.join(run_dir, "report.html"), "w") as fh:
        fh.write(html_report.render(s, tl))


def main_for(run_dir, agent_log=None, quiet=False, llm_endpoints=()):
    s, tl = analyze(run_dir, llm_endpoints)
    if agent_log is None:
        cmd = " ".join(s.get("command") or [])
        if "claude" in cmd:
            agent_log = "auto"
    if agent_log:
        from . import agentlogs
        s["agent_log"] = agentlogs.crosscheck(agent_log, s, run_dir)
    with open(os.path.join(run_dir, "summary.json"), "w") as f:
        json.dump(s, f, indent=1, default=str)
    write_md(run_dir, s)
    write_html(run_dir, s, tl)
    if not quiet:
        ts = s["timesplit"]
        c = s["counts"]
        print(f"{s['label'] or s['run']}: {ts['run_s']} s, {c['llm_calls']} LLM calls, {c['tool_calls']} tool calls; "
              f"LLM {ts['llm_share_pct']} % | tools {ts['tool_share_pct']} % | neither {ts['neither_pct']} %  "
              f"-> {os.path.join(run_dir, 'report.html')}")
    return s
