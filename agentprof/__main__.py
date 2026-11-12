"""agentprof command line.

    sudo ./agentprof doctor                         check kernel, tracepoints, libbpf
    sudo ./agentprof run -- claude -p "fix the bug"  trace a command (as your user)
    sudo ./agentprof attach --pid 1234              trace a running agent
    ./agentprof analyze runs/<run>                  summary.json + report.md + report.html
    ./agentprof compare runs/a runs/b ...           one table across runs
"""
import argparse
import sys

from . import __version__


def main(argv=None):
    ap = argparse.ArgumentParser(prog="agentprof", description="eBPF profiler for AI agents")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def tracer_opts(p):
        p.add_argument("--out", help="run folder (default runs/<time>-<label>)")
        p.add_argument("--label", help="short name for this run (agent/task)")
        p.add_argument("--no-io-events", action="store_true",
                       help="no per send/recv events (totals stay exact; less detail on LLM exchanges)")
        p.add_argument("--no-file-events", action="store_true", help="no per open() events")
        p.add_argument("--sniff-max", type=int, default=1000,
                       help="payload heads kept per connection (TLS SNI, HTTP request lines)")
        p.add_argument("--analyze", action="store_true", help="analyze right after the run")
        p.add_argument("--llm-endpoint", action="append", default=[], metavar="HOST:PORT",
                       help="treat this server as an LLM API (self-hosted model on an IP); repeatable")
        p.add_argument("--quiet", action="store_true")

    r = sub.add_parser("run", help="trace a command and everything it starts")
    tracer_opts(r)
    r.add_argument("--user", help="run the command as this user (default: the sudo user)")
    r.add_argument("--as-root", action="store_true", help="run the command as root")
    r.add_argument("--cwd", help="working directory for the command")
    r.add_argument("--env", action="append", metavar="K=V", help="extra environment variable (repeatable)")
    r.add_argument("--no-cgroup", dest="cgroup", action="store_false", help="do not create a cgroup")
    r.add_argument("--linger", type=float, default=3.0,
                   help="seconds to keep tracing leftover child processes after the command exits")
    r.add_argument("--capture-output", action="store_true", help="save the command's output to agent.log")
    r.add_argument("--no-tty", action="store_true",
                   help="headless: run the command in its own session with stdin from /dev/null")
    r.add_argument("--keep-bpf-stats", action="store_true", help="leave kernel.bpf_stats_enabled on")
    r.add_argument("command", nargs=argparse.REMAINDER)

    a = sub.add_parser("attach", help="trace an already running process and its children")
    tracer_opts(a)
    a.add_argument("--pid", type=int, required=True)
    a.add_argument("--duration", type=float, help="stop after N seconds (default: until it exits / Ctrl-C)")

    an = sub.add_parser("analyze", help="analyze a run folder")
    an.add_argument("run_dir")
    an.add_argument("--agent-log", help="agent's own transcript (Claude Code .jsonl) to cross-check")
    an.add_argument("--quiet", action="store_true")
    an.add_argument("--llm-endpoint", action="append", default=[], metavar="HOST:PORT")

    c = sub.add_parser("compare", help="compare analyzed runs (and the published reference numbers)")
    c.add_argument("run_dirs", nargs="+")
    c.add_argument("--md", help="write the comparison table to this Markdown file")
    c.add_argument("--csv", help="write a CSV")

    d = sub.add_parser("doctor", help="check that this machine can run agentprof")
    d.add_argument("--load", action="store_true", help="also load and attach the eBPF programs")

    args = ap.parse_args(argv)
    if args.cmd == "run":
        if args.command and args.command[0] == "--":
            args.command = args.command[1:]
        from . import runner
        runner.run(args)
    elif args.cmd == "attach":
        from . import runner
        runner.attach(args)
    elif args.cmd == "analyze":
        from . import analyze
        analyze.main_for(args.run_dir, agent_log=args.agent_log, quiet=args.quiet, llm_endpoints=args.llm_endpoint)
    elif args.cmd == "compare":
        from . import compare
        compare.main(args)
    elif args.cmd == "doctor":
        from . import doctor
        sys.exit(doctor.main(args))


if __name__ == "__main__":
    main()
