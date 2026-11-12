"""`agentprof run` / `agentprof attach`: trace an agent and write a run folder.

Run folder layout (everything an analysis needs, nothing else):
    meta.json       command, host, kernel, clocks, tracer config and warnings
    events.jsonl    one JSON object per kernel event (process, socket, file...)
    samples.jsonl   every 200 ms: memory/CPU of live traced processes (+ cgroup)
    final.json      in-kernel aggregates at the end (syscall table, histograms,
                    stats of processes still alive, open connections)
    agent.log       stdout+stderr of the agent when --capture-output is used
"""
import json
import os
import platform
import pwd
import signal
import socket
import sys
import time

from . import cgroup, kernel, __version__

SAMPLE_EVERY = 0.2


def now_pair():
    return time.time(), time.clock_gettime_ns(time.CLOCK_MONOTONIC)


def read_cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            parts = f.read().split(b"\0")
        return [p.decode(errors="replace") for p in parts if p] or None
    except OSError:
        return None


def proc_status(pid):
    out = {}
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith(("VmRSS:", "VmHWM:", "Threads:", "Tgid:")):
                    k, v = line.split(":", 1)
                    out[k] = int(v.split()[0])
        if out.get("Tgid", pid) != pid:
            return None          # a thread: /proc/<tid> shows the whole process's memory
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().rsplit(")", 1)[1].split()
        out["utime"] = int(parts[11])
        out["stime"] = int(parts[12])
    except (OSError, ValueError, IndexError):
        return None
    return out


def descendants(pid):
    """Existing children/grandchildren of pid (for attach mode)."""
    kids = {}
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open(f"/proc/{d}/stat") as f:
                ppid = int(f.read().rsplit(")", 1)[1].split()[1])
            kids.setdefault(ppid, []).append(int(d))
        except (OSError, ValueError, IndexError):
            pass
    out, todo = [], [pid]
    while todo:
        p = todo.pop()
        for c in kids.get(p, []):
            out.append(c)
            todo.append(c)
    return out


def host_meta():
    m = {"hostname": socket.gethostname(), "kernel": platform.release(),
         "machine": platform.machine(), "python": platform.python_version(),
         "cpus": os.cpu_count()}
    try:
        with open("/proc/device-tree/model") as f:
            m["model"] = f.read().strip("\0\n ")
    except OSError:
        pass
    try:
        with open("/proc/meminfo") as f:
            m["mem_kb"] = int(f.readline().split()[1])
    except (OSError, ValueError):
        pass
    m["clk_tck"] = os.sysconf("SC_CLK_TCK")
    return m


class Recorder:
    def __init__(self, out_dir, args):
        self.out = out_dir
        os.makedirs(out_dir, exist_ok=True)
        self.args = args
        self.k = kernel.KernelTracer(io_events=not args.no_io_events,
                                     file_events=not args.no_file_events,
                                     sniff_max=args.sniff_max)
        self.ev_f = open(os.path.join(out_dir, "events.jsonl"), "w", buffering=1)
        self.sm_f = open(os.path.join(out_dir, "samples.jsonl"), "w", buffering=1)
        self.n_events = 0
        self.alive = set()
        self.cg = None

    def on_event(self, e):
        if e is None:
            return
        if e["ev"] == "exec":
            cl = read_cmdline(self.k.ns_of(e["tgid"]) or e["tgid"])
            if cl:
                e["cmdline"] = cl
            self.alive.add(e["tgid"])
        elif e["ev"] == "fork":
            self.alive.add(e["child"])
        elif e["ev"] == "exit":
            self.alive.discard(e["tgid"])
        self.ev_f.write(json.dumps(e, separators=(",", ":")) + "\n")
        self.n_events += 1

    def sample(self):
        wall, mono = now_pair()
        procs = {}
        for pid in self.alive_local():
            st = proc_status(pid)
            if st is None:
                continue
            procs[pid] = st
        s = {"ts": mono, "procs": procs}
        if self.cg:
            s["cgroup"] = self.cg.sample()
        self.sm_f.write(json.dumps(s, separators=(",", ":")) + "\n")

    def alive_local(self):
        """alive traced processes as PIDs of OUR namespace (for /proc)"""
        out = []
        for g in list(self.alive):
            n = self.k.ns_of(g)
            if n is not None:
                out.append(n)
        return out

    def loop_until(self, done):
        last = 0.0
        while True:
            self.k.poll(self.on_event, 100)
            t = time.monotonic()
            if t - last >= SAMPLE_EVERY:
                self.sample()
                last = t
            if done():
                break

    def finish(self, meta):
        # drain what is left in the ring buffer
        for _ in range(20):
            self.k.poll(self.on_event, 20)
        wall, mono = now_pair()
        final = {
            "end_wall": wall, "end_mono_ns": mono,
            "pstats_alive": {str(k): v for k, v in self.k.dump_pstats().items()},
            "sysagg": self.k.dump_sysagg(),
            "syshist": self.k.dump_hist(),
            "conns_open": self.k.dump_conns(),
            "pidmap": self.k.dump_pidmap(),          # global PID -> namespace PID (WSL2/containers)
            "pid_namespace": bool(self.k.ns),
            "unresolved_ns_pids": self.k.pending(),
            "still_tracked": self.k.tracked(),
            "ringbuf_dropped": self.k.dropped(),
            "bpf_prog_stats": self.k.bpf.prog_stats(),
            "n_events": self.n_events,
        }
        if self.cg:
            final["cgroup_final"] = self.cg.sample(final=True)
        with open(os.path.join(self.out, "final.json"), "w") as f:
            json.dump(final, f)
        meta["end_wall"] = wall
        meta["duration_s"] = round(wall - meta["start_wall"], 3)
        with open(os.path.join(self.out, "meta.json"), "w") as f:
            json.dump(meta, f, indent=1)
        self.ev_f.close()
        self.sm_f.close()
        self.k.close()
        if self.cg:
            self.cg.cleanup()
        return final


def _bpf_stats(on):
    try:
        with open("/proc/sys/kernel/bpf_stats_enabled", "w") as f:
            f.write("1" if on else "0")
        return True
    except OSError:
        return False


def default_out(name):
    stamp = time.strftime("%Y%m%d-%H%M%S")
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)[:40]
    return os.path.join("runs", f"{stamp}-{safe}")


def run(args):
    if os.geteuid() != 0:
        sys.exit("agentprof needs root to load eBPF programs: run it with sudo")
    cmd = args.command
    if not cmd:
        sys.exit("usage: agentprof run [options] -- <command> [args...]")
    out = args.out or default_out(args.label or os.path.basename(cmd[0]))

    # who runs the agent: the sudo user by default (agents refuse/behave
    # differently as root), or --user, or root with --as-root
    user = None if args.as_root else (args.user or os.environ.get("SUDO_USER"))
    pw = pwd.getpwnam(user) if user else None

    stats_on = _bpf_stats(True)
    t_load = time.monotonic()
    rec = Recorder(out, args)
    load_s = time.monotonic() - t_load
    if args.cgroup:
        rec.cg = cgroup.RunCgroup(os.path.basename(out.rstrip("/")))

    go_r, go_w = os.pipe()
    err_r, err_w = os.pipe()
    out_fd = None
    if args.capture_output:
        out_fd = os.open(os.path.join(out, "agent.log"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    pid = os.fork()
    if pid == 0:
        # ---------------- child: wait until the tracer tracks us, then exec
        try:
            os.close(go_w)
            os.close(err_r)
            os.read(go_r, 1)
            if args.no_tty:
                # headless benchmark runs: own session (no controlling terminal, so the
                # terminal's job-control signals can never stop the agent or the tracer)
                # and empty stdin (agents that read stdin when it is not a TTY see EOF)
                os.setsid()
                nul = os.open(os.devnull, os.O_RDONLY)
                os.dup2(nul, 0)
            if out_fd is not None:
                os.dup2(out_fd, 1)
                os.dup2(out_fd, 2)
            env = dict(os.environ)
            for kv in args.env or []:
                k, _, v = kv.partition("=")
                env[k] = v
            if pw:
                os.setgroups(os.getgrouplist(pw.pw_name, pw.pw_gid))
                os.setgid(pw.pw_gid)
                os.setuid(pw.pw_uid)
                env.update(HOME=pw.pw_dir, USER=pw.pw_name, LOGNAME=pw.pw_name)
                env.pop("SUDO_USER", None)
                env.pop("SUDO_UID", None)
                env.pop("SUDO_GID", None)
                env.pop("SUDO_COMMAND", None)
            if args.cwd:
                os.chdir(args.cwd)
            os.execvpe(cmd[0], cmd, env)
        except BaseException as e:   # report exec failure to the parent
            os.write(err_w, f"{type(e).__name__}: {e}".encode())
            os._exit(127)

    # ---------------- parent
    os.close(go_r)
    os.close(err_w)
    rec.k.track(pid)
    if rec.cg:
        rec.cg.add(pid)
    wall, mono = now_pair()
    meta = {
        "tool": "agentprof", "version": __version__, "mode": "run",
        "command": cmd, "label": args.label, "root_pid": pid,
        "user": pw.pw_name if pw else "root", "cwd": args.cwd or os.getcwd(),
        "start_wall": wall, "start_mono_ns": mono,
        "host": host_meta(), "arch": rec.k.arch,
        "tracepoints": rec.k.attached, "warnings": rec.k.warnings,
        "offsets": rec.k.offsets, "bpf_load_s": round(load_s, 3),
        "bpf_stats": stats_on, "cgroup": rec.cg.info() if rec.cg else None,
        "io_events": not args.no_io_events, "file_events": not args.no_file_events,
        "env_set": args.env or [], "llm_endpoints": args.llm_endpoint,
    }
    with open(os.path.join(out, "meta.json"), "w") as f:
        json.dump(meta, f, indent=1)
    os.write(go_w, b"g")
    os.close(go_w)

    # Ctrl-C reaches the agent (same process group); the tracer keeps going
    # until the agent has exited so the record is complete.
    old_int = signal.signal(signal.SIGINT, signal.SIG_IGN)
    # terminal job-control / hang-up signals must never stop or kill the tracer
    for sig in (signal.SIGTTOU, signal.SIGTTIN, signal.SIGTSTP, signal.SIGHUP):
        signal.signal(sig, signal.SIG_IGN)
    status = {"code": None, "t": None, "term": None}

    def on_term(signum, frame):        # timeout / kill: stop the agent, still write the record
        if status["term"] is None:
            status["term"] = time.monotonic()
            meta["terminated_by_signal"] = signum
            try:
                if args.no_tty:
                    os.killpg(pid, signal.SIGTERM)
                else:
                    os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
    signal.signal(signal.SIGTERM, on_term)

    def child_done():
        if status["term"] is not None and status["code"] is None and time.monotonic() - status["term"] > 5:
            try:                           # agent ignored SIGTERM
                if args.no_tty:
                    os.killpg(pid, signal.SIGKILL)
                else:
                    os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        if status["code"] is None:
            p, st = os.waitpid(pid, os.WNOHANG)
            if p:
                status["code"] = os.waitstatus_to_exitcode(st)
                status["t"] = time.monotonic()
        if status["code"] is None:
            return False
        # give descendants (servers, background jobs) --linger seconds to end
        others = [x for x in rec.alive_local() if x != pid]
        live = [x for x in others if os.path.exists(f"/proc/{x}")]
        return not live or time.monotonic() - status["t"] >= args.linger

    if not args.quiet:
        print(f"[agentprof] tracing pid {pid}: {' '.join(cmd)}  ->  {out}", file=sys.stderr)
    rec.loop_until(child_done)
    signal.signal(signal.SIGINT, old_int)
    err = os.read(err_r, 4096)
    if err:
        print(f"[agentprof] could not start the command: {err.decode()}", file=sys.stderr)
    meta["exit_code"] = status["code"]
    meta["exec_error"] = err.decode() if err else None
    final = rec.finish(meta)
    _bpf_stats(False) if stats_on and not args.keep_bpf_stats else None
    if not args.quiet:
        print(f"[agentprof] done: exit {status['code']}, {final['n_events']} events, "
              f"{final['ringbuf_dropped']} dropped, {meta['duration_s']} s  ->  {out}", file=sys.stderr)
    if args.analyze:
        from . import analyze
        analyze.main_for(out, quiet=args.quiet)
    return out


def attach(args):
    if os.geteuid() != 0:
        sys.exit("agentprof needs root: run it with sudo")
    pid = args.pid
    if not os.path.exists(f"/proc/{pid}"):
        sys.exit(f"no process {pid}")
    out = args.out or default_out(args.label or f"pid{pid}")
    stats_on = _bpf_stats(True)
    rec = Recorder(out, args)
    existing = [pid] + descendants(pid)
    for p in existing:
        rec.k.track(p)
        if not rec.k.ns:
            rec.alive.add(p)       # in a namespace they are added once resolved (first syscall)
    wall, mono = now_pair()
    meta = {"tool": "agentprof", "version": __version__, "mode": "attach", "command": read_cmdline(pid),
            "label": args.label, "root_pid": pid, "start_wall": wall, "start_mono_ns": mono,
            "host": host_meta(), "arch": rec.k.arch, "tracepoints": rec.k.attached,
            "warnings": rec.k.warnings + ["attach mode: connections opened before attaching are not attributed"],
            "offsets": rec.k.offsets, "bpf_stats": stats_on, "preexisting": existing,
            "preexisting_cmdlines": {str(p): read_cmdline(p) for p in existing},
            "llm_endpoints": args.llm_endpoint}
    with open(os.path.join(out, "meta.json"), "w") as f:
        json.dump(meta, f, indent=1)
    t_end = time.monotonic() + args.duration if args.duration else None
    stop = {"flag": False}
    signal.signal(signal.SIGINT, lambda *a: stop.__setitem__("flag", True))
    print(f"[agentprof] attached to {pid} (+{len(existing) - 1} children); Ctrl-C to stop", file=sys.stderr)
    rec.loop_until(lambda: stop["flag"] or not os.path.exists(f"/proc/{pid}")
                   or (t_end is not None and time.monotonic() >= t_end))
    meta["exit_code"] = None
    final = rec.finish(meta)
    print(f"[agentprof] done: {final['n_events']} events -> {out}", file=sys.stderr)
    if args.analyze:
        from . import analyze
        analyze.main_for(out)
    return out
