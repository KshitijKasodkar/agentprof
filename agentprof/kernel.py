"""Kernel side manager: loads agentprof.bpf.o, fills its config, attaches the
tracepoints, decodes ring-buffer records and dumps the in-kernel aggregates.

Struct layouts below MUST match agentprof.bpf.c (natural alignment, little
endian; x86_64 and aarch64 are both little endian)."""
import ipaddress
import json
import os
import platform
import struct

from . import libbpf

HERE = os.path.dirname(os.path.abspath(__file__))
BPF_OBJ = os.path.join(HERE, "bpf", "agentprof.bpf.o")
TRACEFS_CANDIDATES = ("/sys/kernel/tracing", "/sys/kernel/debug/tracing")

# ---------------------------------------------------------------- layouts
HDR = struct.Struct("<IIIIQ")                       # type tgid tid pad ts
PSTATS_FIELDS = ("user_ns sys_ns runq_ns sleep_ns io_ns vcsw ivcsw syscalls sys_errs sys_wall_ns "
                 "inet_tx inet_rx inet_txc inet_rxc unix_tx unix_rx file_rd file_wr other_rd other_wr "
                 "opens open_fail forks start_ns").split()
PSTATS = struct.Struct("<%dQqII" % len(PSTATS_FIELDS))   # + exit_code ppid threads
ADDR = struct.Struct("<HHI16s")
CONN_T_FIELDS = "first_ns last_ns tx rx txc rxc retrans".split()
CONN_T = struct.Struct("<7QIHHB3xI")

EV_FORK, EV_EXEC, EV_ARGV, EV_EXIT, EV_CONN, EV_IO, EV_SNIFF, EV_TCPSTATE, \
    EV_CONNCLOSE, EV_OPEN, EV_CONNECT, EV_RETRANS, EV_THREAD_EXIT = range(1, 14)

S_FORK = struct.Struct("<II")
S_EXEC = struct.Struct("<Q16s192s")
S_ARGV_HEAD = struct.Struct("<II")
ARGV_N, ARGV_LEN = 8, 128
S_CONN = struct.Struct("<QHHi")
S_CONN_TAIL = struct.Struct("<QQBB6x")
S_IO = struct.Struct("<QIBBH")
S_SNIFF = struct.Struct("<QIB3x")
S_TCPSTATE = struct.Struct("<Qii")
S_OPEN = struct.Struct("<iI192s")
S_CONNECT = struct.Struct("<iI")
S_RETRANS = struct.Struct("<Q")

# cfg slots (enum in the .bpf.c)
CFG = dict(FORK_CHILD_OFF=0, SWITCH_PREV_PID_OFF=1, SWITCH_PREV_STATE_OFF=2, SWITCH_NEXT_PID_OFF=3,
           EXIT_GROUP_DEAD_OFF=4, EXEC_FILENAME_OFF=5, IO_EVENTS=6, FILE_EVENTS=7, SNIFF_MAX=8,
           PREV_STATE_SIZE=9, REG0=10, NS_DEV=16, NS_INO=17, BOOT_PENDING=18)

INIT_PID_NS_INO = 0xEFFFFFFC      # inode number of the initial PID namespace


def pid_namespace():
    """(dev, ino) of our PID namespace when it is NOT the initial one, else None.
    WSL2 runs each distro in its own PID namespace (so do containers): the PIDs
    user space sees differ from the global PIDs eBPF sees."""
    try:
        st = os.stat("/proc/self/ns/pid")
    except OSError:
        return None
    return None if st.st_ino == INIT_PID_NS_INO else (st.st_dev, st.st_ino)

# offsets of the syscall argument registers in the kernel's struct pt_regs
PT_REGS_ARGS = {
    "x86_64": [112, 104, 96, 56, 72, 64],     # di si dx r10 r8 r9
    "aarch64": [0, 8, 16, 24, 32, 40],        # x0..x5
}

# syscall classes (enum in the .bpf.c)
CLASSES = {
    "read": 1, "pread64": 1,
    "readv": 2, "preadv": 2, "preadv2": 2,
    "recvmsg": 3,
    "write": 4, "pwrite64": 4,
    "writev": 5, "pwritev": 5, "pwritev2": 5,
    "sendmsg": 6,
    "sendto": 7,
    "close": 8,
    "connect": 9,
    "open": 10,
    "openat": 11, "openat2": 11,
    "execve": 12,
    "execveat": 13,
    "exit_group": 14,
    "recvfrom": 15,
}

PROGRAMS = ["tp_fork", "tp_exec", "tp_exit", "tp_switch", "SYS_ENTER", "SYS_EXIT",
            "tp_send_len", "tp_recv_len", "tp_set_state", "tp_retrans"]
OPTIONAL = {"tp_send_len", "tp_recv_len", "tp_retrans"}


def machine_arch():
    m = platform.machine()
    return {"amd64": "x86_64", "arm64": "aarch64"}.get(m, m)


def syscall_table(arch=None):
    with open(os.path.join(HERE, "syscalls.json")) as f:
        t = json.load(f)
    arch = arch or machine_arch()
    if arch not in t:
        raise RuntimeError(f"no syscall table for {arch}")
    return {int(k): v for k, v in t[arch].items()}


def tracefs():
    for p in TRACEFS_CANDIDATES:
        if os.path.isdir(os.path.join(p, "events")):
            return p
    # try to mount it (needs root)
    os.makedirs("/sys/kernel/tracing", exist_ok=True)
    os.system("mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null")
    if os.path.isdir("/sys/kernel/tracing/events"):
        return "/sys/kernel/tracing"
    raise RuntimeError("tracefs not available (mount -t tracefs nodev /sys/kernel/tracing)")


def tp_format(category, name):
    """{field: (offset, size)} of a tracepoint, from tracefs."""
    path = os.path.join(tracefs(), "events", category, name, "format")
    fields = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line.startswith("field:"):
                continue
            parts = dict(p.strip().split(":", 1) for p in line.split(";") if ":" in p)
            decl = parts["field"].strip()
            fname = decl.split()[-1].split("[")[0]
            fields[fname] = (int(parts["offset"]), int(parts["size"]))
    return fields


def tp_exists(category, name):
    try:
        return os.path.exists(os.path.join(tracefs(), "events", category, name))
    except RuntimeError:
        return False


def ip_str(b16, family):
    try:
        a = ipaddress.IPv6Address(bytes(b16))
        if a.ipv4_mapped:
            return str(a.ipv4_mapped)
        if family == 2 and bytes(b16[:12]) == bytes(12):
            return str(ipaddress.IPv4Address(bytes(b16[12:])))
        return str(a)
    except ValueError:
        return "?"


def cstr(b):
    return b.split(b"\0", 1)[0].decode(errors="replace")


def decode(raw):
    """Ring buffer record -> dict (or None)."""
    if len(raw) < HDR.size:
        return None
    t, tgid, tid, _, ts = HDR.unpack_from(raw, 0)
    o = HDR.size
    e = {"t": t, "ts": ts, "tgid": tgid, "tid": tid}
    if t == EV_FORK:
        e["ev"] = "fork"
        e["child"], _ = S_FORK.unpack_from(raw, o)
    elif t == EV_EXEC:
        e["ev"] = "exec"
        cg, comm, fn = S_EXEC.unpack_from(raw, o)
        e.update(cgid=cg, comm=cstr(comm), filename=cstr(fn))
    elif t == EV_ARGV:
        e["ev"] = "argv"
        n, _ = S_ARGV_HEAD.unpack_from(raw, o)
        o2 = o + S_ARGV_HEAD.size
        e["argv"] = [cstr(raw[o2 + i * ARGV_LEN:o2 + (i + 1) * ARGV_LEN]) for i in range(min(n, ARGV_N))]
        e["argv_truncated"] = n >= ARGV_N
    elif t == EV_EXIT:
        e["ev"] = "exit"
        vals = PSTATS.unpack_from(raw, o)
        e["stats"] = dict(zip(PSTATS_FIELDS, vals[:len(PSTATS_FIELDS)]))
        e["stats"]["exit_code"], e["stats"]["ppid"], e["stats"]["threads"] = vals[len(PSTATS_FIELDS):]
        e["comm"] = cstr(raw[o + PSTATS.size:o + PSTATS.size + 16])
    elif t == EV_CONN:
        e["ev"] = "conn"
        sk, fam, proto, fd = S_CONN.unpack_from(raw, o)
        o2 = o + S_CONN.size
        lf, lp, _, la = ADDR.unpack_from(raw, o2)
        rf, rp, _, ra = ADDR.unpack_from(raw, o2 + ADDR.size)
        syn, est, have_tcp, have_fd = S_CONN_TAIL.unpack_from(raw, o2 + 2 * ADDR.size)
        e.update(sk=sk, family=fam, proto=proto, fd=fd,
                 laddr=ip_str(la, lf) if lf else None, lport=lp,
                 raddr=ip_str(ra, rf) if rf else None, rport=rp,
                 syn_ns=syn, est_ns=est, have_tcp=have_tcp, have_fdaddr=have_fd)
    elif t == EV_IO:
        e["ev"] = "io"
        sk, nbytes, d, _, proto = S_IO.unpack_from(raw, o)
        e.update(sk=sk, bytes=nbytes, dir="tx" if d == 0 else "rx", proto=proto)
    elif t == EV_SNIFF:
        e["ev"] = "sniff"
        sk, n, d = S_SNIFF.unpack_from(raw, o)
        o2 = o + S_SNIFF.size
        e.update(sk=sk, dir="tx" if d == 0 else "rx", len=n, hex=raw[o2:o2 + min(n, 256)].hex())
    elif t == EV_TCPSTATE:
        e["ev"] = "tcpstate"
        sk, old, new = S_TCPSTATE.unpack_from(raw, o)
        e.update(sk=sk, old=old, new=new)
    elif t == EV_CONNCLOSE:
        e["ev"] = "connclose"
        (sk,) = S_RETRANS.unpack_from(raw, o)
        vals = CONN_T.unpack_from(raw, o + 8)
        c = dict(zip(CONN_T_FIELDS, vals[:7]))
        c["owner"], c["proto"], c["family"], _, c["sniffs"] = vals[7:]
        e.update(sk=sk, conn=c)
    elif t == EV_OPEN:
        e["ev"] = "open"
        ret, flags, path = S_OPEN.unpack_from(raw, o)
        e.update(ret=ret, flags=flags, path=cstr(path))
    elif t == EV_CONNECT:
        e["ev"] = "connect"
        fd, _ = S_CONNECT.unpack_from(raw, o)
        af, port, _, addr = ADDR.unpack_from(raw, o + S_CONNECT.size)
        e.update(fd=fd, family=af, raddr=ip_str(addr, af), rport=port)
    elif t == EV_RETRANS:
        e["ev"] = "retrans"
        (e["sk"],) = S_RETRANS.unpack_from(raw, o)
    elif t == EV_THREAD_EXIT:
        e["ev"] = "thread_exit"
    else:
        e["ev"] = f"unknown{t}"
    return e


class KernelTracer:
    """Loads the eBPF object and exposes tracking + aggregate dumps."""

    def __init__(self, io_events=True, file_events=True, sniff_max=1000, obj_path=BPF_OBJ, raw_syscalls=True):
        self.arch = machine_arch()
        self.syscalls = syscall_table(self.arch)
        self.warnings = []
        if not os.path.exists(obj_path):
            raise RuntimeError(f"{obj_path} missing: build it with `make -C agentprof/bpf`")
        self.bpf = libbpf.BPFObject(obj_path)
        self.missing = [p for p, (c, n) in {
            "tp_send_len": ("sock", "sock_send_length"),
            "tp_recv_len": ("sock", "sock_recv_length"),
            "tp_retrans": ("tcp", "tcp_retransmit_skb"),
        }.items() if not tp_exists(c, n)]
        for p in self.missing:
            self.bpf.disable_program(p)
            self.warnings.append(f"tracepoint for {p} not in this kernel: socket byte counts unavailable "
                                 "(needs Linux >= 6.3)" if p != "tp_retrans" else "no tcp_retransmit_skb")
        self.bpf.load()
        self._configure(io_events, file_events, sniff_max)
        self.attached = []
        use_raw = raw_syscalls and self.arch in PT_REGS_ARGS
        for p in PROGRAMS:
            if p in self.missing:
                continue
            if p in ("SYS_ENTER", "SYS_EXIT"):
                raw, classic = (("raw_sys_enter", "tp_sys_enter") if p == "SYS_ENTER"
                                else ("raw_sys_exit", "tp_sys_exit"))
                if use_raw:
                    try:
                        self.bpf.attach(raw)
                        self.attached.append(raw)
                        continue
                    except libbpf.BPFError as e:
                        self.warnings.append(f"raw tracepoint {raw} failed ({e}); using the classic tracepoint")
                        use_raw = False
                self.bpf.attach(classic)
                self.attached.append(classic)
                continue
            self.bpf.attach(p)
            self.attached.append(p)
        self.m_tracked = self.bpf.map("tracked")
        self.m_counters = self.bpf.map("counters")
        self.m_nsboot = self.bpf.map("nsboot")
        self.m_nsmap = self.bpf.map("nsmap")
        self._ns_cache = {}

    def _set_cfg(self, slot, value):
        self.bpf.map("cfg").update(struct.pack("<I", slot), struct.pack("<Q", value))

    def _configure(self, io_events, file_events, sniff_max):
        fork = tp_format("sched", "sched_process_fork")
        sw = tp_format("sched", "sched_switch")
        ex = tp_format("sched", "sched_process_exit")
        exe = tp_format("sched", "sched_process_exec")
        self.offsets = {
            "FORK_CHILD_OFF": fork["child_pid"][0],
            "SWITCH_PREV_PID_OFF": sw["prev_pid"][0],
            "SWITCH_PREV_STATE_OFF": sw["prev_state"][0],
            "SWITCH_NEXT_PID_OFF": sw["next_pid"][0],
            "EXIT_GROUP_DEAD_OFF": ex["group_dead"][0] if "group_dead" in ex else 0,
            "EXEC_FILENAME_OFF": exe["filename"][0],
            "PREV_STATE_SIZE": sw["prev_state"][1],
        }
        for k, v in self.offsets.items():
            self._set_cfg(CFG[k], v)
        for i, off in enumerate(PT_REGS_ARGS.get(self.arch, [0] * 6)):
            self._set_cfg(CFG["REG0"] + i, off)
        self.ns = pid_namespace()
        if self.ns:
            self._set_cfg(CFG["NS_DEV"], self.ns[0])
            self._set_cfg(CFG["NS_INO"], self.ns[1])
            self.warnings.append("PID namespace detected (WSL2/container): PIDs are translated to this namespace")
        self._set_cfg(CFG["IO_EVENTS"], 1 if io_events else 0)
        self._set_cfg(CFG["FILE_EVENTS"], 1 if file_events else 0)
        self._set_cfg(CFG["SNIFF_MAX"], sniff_max)
        cls = self.bpf.map("cls")
        by_name = {v: k for k, v in self.syscalls.items()}
        for name, c in CLASSES.items():
            nr = by_name.get(name)
            if nr is not None and nr < 1024:
                cls.update(struct.pack("<I", nr), struct.pack("<I", c))

    # ---------------------------------------------------------- tracking
    def track(self, pid, parent=0):
        """Start tracking `pid` (a PID as seen by this process). In a PID
        namespace the kernel resolves it to the global PID at the process's
        next system call (see boot_check in the .bpf.c)."""
        if not self.ns:
            self.m_tracked.update(struct.pack("<I", pid), struct.pack("<I", parent))
            return
        self.m_nsboot.update(struct.pack("<I", pid), struct.pack("<I", parent))
        cfgm = self.bpf.map("cfg")
        key = struct.pack("<I", CFG["BOOT_PENDING"])
        cur = struct.unpack("<Q", cfgm.lookup(key, 8) or b"\0" * 8)[0]
        cfgm.update(key, struct.pack("<Q", cur + 1))

    def pending(self):
        """namespace PIDs not yet resolved"""
        if not self.ns:
            return []
        return [struct.unpack("<I", k)[0] for k, _ in self.m_nsboot.items(4, 4)]

    def ns_of(self, gpid):
        """global PID -> PID in our namespace (identity without a namespace)"""
        if not self.ns:
            return gpid
        v = self._ns_cache.get(gpid)
        if v is None:
            raw = self.m_nsmap.lookup(struct.pack("<I", gpid), 4)
            if raw is None:
                return None
            v = struct.unpack("<I", raw)[0]
            self._ns_cache[gpid] = v
        return v

    def dump_pidmap(self):
        if not self.ns:
            return {}
        return {str(struct.unpack("<I", k)[0]): struct.unpack("<I", v)[0] for k, v in self.m_nsmap.items(4, 4)}

    def untrack(self, pid):
        self.m_tracked.delete(struct.pack("<I", pid))

    def tracked(self):
        return [struct.unpack("<I", k)[0] for k, _ in self.m_tracked.items(4, 4)]

    def dropped(self):
        v = self.m_counters.lookup(struct.pack("<I", 0), 8)
        return struct.unpack("<Q", v)[0] if v else 0

    # ---------------------------------------------------------- dumps
    def dump_pstats(self):
        out = {}
        for k, v in self.bpf.map("pstats").items(4, PSTATS.size):
            tgid = struct.unpack("<I", k)[0]
            vals = PSTATS.unpack(v)
            d = dict(zip(PSTATS_FIELDS, vals[:len(PSTATS_FIELDS)]))
            d["exit_code"], d["ppid"], d["threads"] = vals[len(PSTATS_FIELDS):]
            out[tgid] = d
        return out

    def dump_sysagg(self):
        out = []
        for k, v in self.bpf.map("sysagg").items(8, 32):
            tgid, nr = struct.unpack("<II", k)
            cnt, tot, mx, errs = struct.unpack("<4Q", v)
            out.append({"tgid": tgid, "nr": nr, "name": self.syscalls.get(nr, f"sys_{nr}"),
                        "count": cnt, "total_ns": tot, "max_ns": mx, "errs": errs})
        return out

    def dump_hist(self):
        out = []
        for k, v in self.bpf.map("syshist").items(8, 8):
            nr, slot = struct.unpack("<II", k)
            out.append({"nr": nr, "name": self.syscalls.get(nr, f"sys_{nr}"), "slot": slot,
                        "count": struct.unpack("<Q", v)[0]})
        return out

    def dump_conns(self):
        out = []
        for k, v in self.bpf.map("conns").items(8, CONN_T.size):
            sk = struct.unpack("<Q", k)[0]
            vals = CONN_T.unpack(v)
            c = dict(zip(CONN_T_FIELDS, vals[:7]))
            c["owner"], c["proto"], c["family"], _, c["sniffs"] = vals[7:]
            c["sk"] = sk
            out.append(c)
        return out

    def poll(self, cb, timeout_ms=100):
        if not getattr(self, "_rb_open", False):
            self.bpf.open_ringbuf("events", lambda raw: cb(decode(raw)))
            self._rb_open = True
        return self.bpf.poll(timeout_ms)

    def drain(self):
        return self.bpf.consume()

    def close(self):
        self.bpf.close()
