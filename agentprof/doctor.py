"""`agentprof doctor`: check the machine and print the fix for anything missing."""
import os
import platform
import shutil

from . import kernel, cgroup

OK, WARN, FAIL = "[ OK ]", "[WARN]", "[FAIL]"


def kver():
    try:
        return tuple(int(x) for x in platform.release().split("-")[0].split(".")[:2])
    except ValueError:
        return (0, 0)


def main(args):
    bad = 0

    def line(tag, what, detail=""):
        nonlocal bad
        if tag == FAIL:
            bad += 1
        print(f"{tag} {what}" + (f"  - {detail}" if detail else ""))

    print(f"agentprof doctor: {platform.node()} {platform.machine()} kernel {platform.release()}")
    line(OK if os.geteuid() == 0 else FAIL, "running as root", "" if os.geteuid() == 0 else "use sudo")
    v = kver()
    line(OK if v >= (6, 3) else WARN, f"kernel {v[0]}.{v[1]}",
         "" if v >= (6, 3) else "socket byte tracepoints need >= 6.3 (WSL2: `wsl --update`)")
    try:
        tf = kernel.tracefs()
        line(OK, "tracefs", tf)
    except RuntimeError as e:
        line(FAIL, "tracefs", str(e))
        return 1
    need = [("sched", "sched_process_fork"), ("sched", "sched_process_exec"), ("sched", "sched_process_exit"),
            ("sched", "sched_switch"), ("raw_syscalls", "sys_enter"), ("raw_syscalls", "sys_exit"),
            ("sock", "inet_sock_set_state")]
    opt = [("sock", "sock_send_length"), ("sock", "sock_recv_length"), ("tcp", "tcp_retransmit_skb")]
    for c, n in need:
        line(OK if kernel.tp_exists(c, n) else FAIL, f"tracepoint {c}:{n}")
    for c, n in opt:
        line(OK if kernel.tp_exists(c, n) else WARN, f"tracepoint {c}:{n}",
             "" if kernel.tp_exists(c, n) else "optional; socket bytes need it (Linux >= 6.3)")
    try:
        from . import libbpf
        libbpf.lib()
        line(OK, "libbpf shared library")
    except RuntimeError as e:
        line(FAIL, "libbpf shared library", "sudo apt install libbpf1")
    obj = kernel.BPF_OBJ
    line(OK if os.path.exists(obj) else FAIL, "eBPF object", obj if os.path.exists(obj) else
         "build: sudo apt install clang libbpf-dev && make -C agentprof/bpf")
    try:
        kernel.syscall_table()
        line(OK, f"syscall table for {kernel.machine_arch()}")
    except RuntimeError as e:
        line(FAIL, "syscall table", str(e))
    ns = kernel.pid_namespace()
    line(OK, "PID namespace", "own namespace (WSL2/container): PIDs are translated automatically" if ns
         else "initial namespace")
    root = cgroup.cgroup2_root()
    line(OK if root else WARN, "cgroup v2", root or "not mounted: per-run cgroup accounting disabled")
    if root:
        ctrls = open(os.path.join(root, "cgroup.controllers")).read().split()
        line(OK if "memory" in ctrls else WARN, "cgroup v2 controllers", " ".join(ctrls) or "none (hybrid setup)")
    line(OK if shutil.which("tc") else WARN, "tc (network delay experiments)",
         "" if shutil.which("tc") else "apt install iproute2")
    if getattr(args, "load", False) and not bad:
        try:
            k = kernel.KernelTracer()
            line(OK, f"eBPF programs load and attach ({len(k.attached)})", ", ".join(k.attached))
            for w in k.warnings:
                line(WARN, w)
            k.close()
        except Exception as e:
            line(FAIL, "eBPF programs load", str(e)[:2000])
    print("All checks passed." if not bad else f"{bad} problem(s).")
    return 1 if bad else 0
