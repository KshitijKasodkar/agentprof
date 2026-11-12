"""Put the traced agent into its own cgroup (v2) and sample its counters.

A cgroup ("control group") is the Linux kernel's way to group processes and
account/limit their resources (CPU, memory, I/O, number of processes). Every
container (Docker, the sandboxes coding agents run tools in) is a cgroup.
Running the agent in its own cgroup gives exact totals for the whole process
tree, including memory.peak, which per-process sampling can miss for
short-lived tool processes.

Works on pure cgroup v2 systems (Raspberry Pi OS, Ubuntu 22.04+, WSL2 with
cgroup v2). On hybrid systems the cgroup is still created (for the cgroup id)
but the controllers may be missing; the sampler then records what exists."""
import os

FILES = ("memory.current", "memory.peak", "memory.stat", "cpu.stat", "io.stat",
         "pids.current", "pids.peak", "memory.events", "cpu.pressure", "memory.pressure",
         "io.pressure")


def cgroup2_root():
    try:
        with open("/proc/mounts") as f:
            for line in f:
                p = line.split()
                if len(p) >= 3 and p[2] == "cgroup2":
                    return p[1]
    except OSError:
        pass
    return None


def _write(path, text):
    try:
        with open(path, "w") as f:
            f.write(text)
        return True
    except OSError:
        return False


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def parse_kv(text):
    out = {}
    for line in (text or "").splitlines():
        p = line.split()
        if len(p) == 2:
            try:
                out[p[0]] = int(p[1])
            except ValueError:
                pass
    return out


class RunCgroup:
    def __init__(self, name):
        self.root = cgroup2_root()
        self.path = None
        self.error = None
        if not self.root:
            self.error = "no cgroup2 mount"
            return
        parent = os.path.join(self.root, "agentprof")
        try:
            os.makedirs(parent, exist_ok=True)
            # enable controllers for children (ignore failures: hybrid systems)
            ctrls = (_read(os.path.join(self.root, "cgroup.controllers")) or "").split()
            want = " ".join(f"+{c}" for c in ("cpu", "memory", "io", "pids") if c in ctrls)
            if want:
                _write(os.path.join(self.root, "cgroup.subtree_control"), want)
                _write(os.path.join(parent, "cgroup.subtree_control"), want)
            self.path = os.path.join(parent, name)
            os.makedirs(self.path, exist_ok=True)
        except OSError as e:
            self.error = str(e)
            self.path = None

    def info(self):
        if not self.path:
            return {"path": None, "error": self.error}
        try:
            cgid = os.stat(self.path).st_ino   # cgroup id == inode number of its directory
        except OSError:
            cgid = None
        return {"path": self.path, "id": cgid,
                "controllers": (_read(os.path.join(self.path, "cgroup.controllers")) or "").split()}

    def add(self, pid):
        if self.path:
            if not _write(os.path.join(self.path, "cgroup.procs"), str(pid)):
                self.error = f"could not move {pid} into {self.path}"

    def sample(self, final=False):
        if not self.path:
            return None
        out = {}
        wanted = FILES if final else ("memory.current", "memory.peak", "cpu.stat", "pids.current")
        for name in wanted:
            t = _read(os.path.join(self.path, name))
            if t is None:
                continue
            t = t.strip()
            if name.endswith((".current", ".peak")):
                try:
                    out[name] = int(t)
                except ValueError:
                    out[name] = t
            elif name in ("cpu.stat", "memory.stat", "memory.events"):
                out[name] = parse_kv(t)
            else:
                out[name] = t
        return out

    def cleanup(self):
        """Remove the cgroup when empty (processes still inside: leave it)."""
        if self.path:
            try:
                os.rmdir(self.path)
            except OSError:
                pass
