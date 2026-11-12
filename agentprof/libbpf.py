"""Minimal ctypes binding to the system libbpf (libbpf.so.1).

Why not BCC? BCC compiles C at start-up and needs the running kernel's headers
and LLVM on the device (bwtrack: 5-9 s start, 220 MB RSS, broken on new
kernels until patched). agentprof's BPF object needs no kernel headers, so it
is compiled once with clang and only *loaded* here. The Python side uses only
the standard library plus the distro's libbpf shared library:

    Raspberry Pi OS / Debian 12+ / Ubuntu 22.04+:  apt install libbpf1   (usually already installed)
"""
import ctypes
import ctypes.util
import errno
import os

_LIB = None
_PRINT_CB = None
_LOG = []


def lib():
    global _LIB
    if _LIB is not None:
        return _LIB
    names = ["libbpf.so.1", "libbpf.so", "libbpf.so.0"]
    found = ctypes.util.find_library("bpf")
    if found:
        names.insert(0, found)
    last = None
    for n in names:
        try:
            _LIB = ctypes.CDLL(n, use_errno=True)
            break
        except OSError as e:
            last = e
    if _LIB is None:
        raise RuntimeError(f"libbpf shared library not found ({last}); install it: sudo apt install libbpf1")
    L = _LIB
    vp, cp, ci = ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int
    sig = {
        "bpf_object__open_file": (vp, [cp, vp]),
        "bpf_object__load": (ci, [vp]),
        "bpf_object__close": (None, [vp]),
        "bpf_object__find_map_by_name": (vp, [vp, cp]),
        "bpf_object__find_program_by_name": (vp, [vp, cp]),
        "bpf_map__fd": (ci, [vp]),
        "bpf_program__fd": (ci, [vp]),
        "bpf_program__attach": (vp, [vp]),
        "bpf_program__set_autoload": (ci, [vp, ctypes.c_bool]),
        "bpf_link__destroy": (ci, [vp]),
        "libbpf_get_error": (ctypes.c_long, [vp]),
        "bpf_map_lookup_elem": (ci, [ci, vp, vp]),
        "bpf_map_update_elem": (ci, [ci, vp, vp, ctypes.c_uint64]),
        "bpf_map_delete_elem": (ci, [ci, vp]),
        "bpf_map_get_next_key": (ci, [ci, vp, vp]),
        "ring_buffer__new": (vp, [ci, vp, vp, vp]),
        "ring_buffer__poll": (ci, [vp, ci]),
        "ring_buffer__consume": (ci, [vp]),
        "ring_buffer__free": (None, [vp]),
    }
    for name, (res, args) in sig.items():
        f = getattr(L, name)
        f.restype = res
        f.argtypes = args
    _install_print()
    return L


def _install_print():
    """Route libbpf's log (including verifier errors) into _LOG."""
    global _PRINT_CB
    L = _LIB
    try:
        libc = ctypes.CDLL(None)
        vsnprintf = libc.vsnprintf
        vsnprintf.restype = ctypes.c_int
        vsnprintf.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_void_p]
        PRINT = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p)

        def cb(level, fmt, args):
            buf = ctypes.create_string_buffer(1 << 20)
            try:
                vsnprintf(buf, 1 << 20, fmt, args)
                _LOG.append(buf.value.decode(errors="replace"))
            except Exception:
                _LOG.append(fmt.decode(errors="replace"))
            return 0
        _PRINT_CB = PRINT(cb)
        L.libbpf_set_print.restype = ctypes.c_void_p
        L.libbpf_set_print.argtypes = [PRINT]
        L.libbpf_set_print(_PRINT_CB)
    except Exception:
        pass


def last_log(n=40):
    return "".join(_LOG[-n:])


def _ptr_err(p):
    """libbpf 1.x returns NULL + errno; 0.x returns an error-encoded pointer."""
    if not p:
        return ctypes.get_errno() or errno.EINVAL
    e = lib().libbpf_get_error(p)
    return -e if e else 0


class BPFError(RuntimeError):
    pass


SAMPLE_FN = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)


class Map:
    def __init__(self, fd, name):
        self.fd = fd
        self.name = name

    def update(self, key: bytes, value: bytes, flags=0):
        k = ctypes.create_string_buffer(key, len(key))
        v = ctypes.create_string_buffer(value, len(value))
        if lib().bpf_map_update_elem(self.fd, k, v, flags) != 0:
            raise BPFError(f"update {self.name}: {os.strerror(ctypes.get_errno())}")

    def lookup(self, key: bytes, vsize: int):
        k = ctypes.create_string_buffer(key, len(key))
        v = ctypes.create_string_buffer(vsize)
        if lib().bpf_map_lookup_elem(self.fd, k, v) != 0:
            return None
        return v.raw

    def delete(self, key: bytes):
        k = ctypes.create_string_buffer(key, len(key))
        return lib().bpf_map_delete_elem(self.fd, k) == 0

    def items(self, ksize: int, vsize: int):
        """All (key, value) pairs. Reads key by key (works on every kernel)."""
        out = []
        cur = None
        nxt = ctypes.create_string_buffer(ksize)
        L = lib()
        guard = 0
        while True:
            if L.bpf_map_get_next_key(self.fd, cur, nxt) != 0:
                break
            key = nxt.raw
            v = ctypes.create_string_buffer(vsize)
            if L.bpf_map_lookup_elem(self.fd, nxt, v) == 0:
                out.append((key, v.raw))
            cur = ctypes.create_string_buffer(key, ksize)
            guard += 1
            if guard > 5_000_000:
                break
        return out


class BPFObject:
    def __init__(self, path):
        L = lib()
        self.path = path
        self.obj = L.bpf_object__open_file(path.encode(), None)
        err = _ptr_err(self.obj)
        if err:
            raise BPFError(f"cannot open {path}: {os.strerror(err)}\n{last_log()}")
        self.links = []
        self.progs = {}
        self._rb = None
        self._cb = None

    def disable_program(self, name):
        p = lib().bpf_object__find_program_by_name(self.obj, name.encode())
        if p:
            lib().bpf_program__set_autoload(p, False)

    def load(self):
        if lib().bpf_object__load(self.obj) != 0:
            raise BPFError("loading the eBPF object failed (verifier or permissions):\n" + last_log(80))

    def map(self, name) -> Map:
        m = lib().bpf_object__find_map_by_name(self.obj, name.encode())
        if not m:
            raise BPFError(f"map {name} not found")
        return Map(lib().bpf_map__fd(m), name)

    def attach(self, name):
        L = lib()
        p = L.bpf_object__find_program_by_name(self.obj, name.encode())
        if not p:
            raise BPFError(f"program {name} not found")
        link = L.bpf_program__attach(p)
        err = _ptr_err(link)
        if err:
            raise BPFError(f"attach {name}: {os.strerror(err)}\n{last_log(10)}")
        self.links.append(link)
        self.progs[name] = L.bpf_program__fd(p)
        return link

    def open_ringbuf(self, map_name, callback):
        """callback(bytes) for every record."""
        L = lib()

        def _cb(ctx, data, size):
            try:
                callback(ctypes.string_at(data, size))
            except Exception as e:   # never let an exception cross into C
                import traceback
                traceback.print_exc()
            return 0
        self._cb = SAMPLE_FN(_cb)
        fd = self.map(map_name).fd
        rb = L.ring_buffer__new(fd, ctypes.cast(self._cb, ctypes.c_void_p), None, None)
        if _ptr_err(rb):
            raise BPFError("ring_buffer__new failed: " + last_log(5))
        self._rb = rb

    def poll(self, timeout_ms=100):
        if self._rb:
            return lib().ring_buffer__poll(self._rb, timeout_ms)
        return 0

    def consume(self):
        if self._rb:
            return lib().ring_buffer__consume(self._rb)
        return 0

    def prog_stats(self):
        """run_time_ns / run_cnt per program (needs sysctl kernel.bpf_stats_enabled=1)."""
        out = {}
        for name, fd in self.progs.items():
            try:
                with open(f"/proc/self/fdinfo/{fd}") as f:
                    d = dict(line.split(":", 1) for line in f if ":" in line)
                out[name] = (int(d.get("run_time_ns", "0").strip() or 0), int(d.get("run_cnt", "0").strip() or 0))
            except OSError:
                pass
        return out

    def close(self):
        L = lib()
        if self._rb:
            L.ring_buffer__free(self._rb)
            self._rb = None
        for link in self.links:
            L.bpf_link__destroy(link)
        self.links = []
        if self.obj:
            L.bpf_object__close(self.obj)
            self.obj = None
