// SPDX-License-Identifier: GPL-2.0
/*
 * agentprof.bpf.c - kernel half of agentprof, the eBPF profiler for AI agents.
 *
 * DESIGN RULES (why this file looks the way it does)
 * --------------------------------------------------
 *  1. TRACEPOINTS ONLY. No kprobes, no fentry. Tracepoints are a stable kernel
 *     interface, so the same program works on Raspberry Pi OS 6.x, WSL2 6.6 and
 *     cloud kernels without kprobes (CONFIG_KPROBES=n), unlike bwtrack which
 *     hooked internal functions such as tcp_sendmsg.
 *  2. NO KERNEL HEADERS, NO BTF. We never dereference a kernel struct. Every
 *     value comes from a tracepoint's own fields or from a BPF helper. So the
 *     object can be compiled once with plain clang (no linux-headers, no
 *     vmlinux.h, no BCC/LLVM on the device) and loaded with libbpf.
 *     Tracepoint fields whose offset changed between kernel versions
 *     (e.g. sched_process_fork in 6.18) are read at an offset that user space
 *     takes from /sys/kernel/tracing/events/.../format and writes to `cfg`.
 *  3. ONLY THE AGENT. Every program first checks whether the current process
 *     belongs to the traced agent (map `tracked`: the launched command and
 *     every process forked from it). Everything else returns after one lookup.
 *  4. COUNTERS IN MAPS, RARE THINGS AS EVENTS. Syscall counts/latencies and
 *     CPU time are aggregated in the kernel; process/connection lifecycle and
 *     socket I/O timing go to user space through a ring buffer.
 *
 *  WHAT IS MEASURED                         FROM
 *  ---------------------------------------  -------------------------------------
 *  process tree, argv, exit code            sched_process_fork/exec/exit, sys_enter(execve, exit_group)
 *  every syscall: count, errors, latency    raw_syscalls:sys_enter / sys_exit
 *  CPU: user vs kernel, run-queue wait,     sched:sched_switch + syscall enter/exit
 *       sleeping (S) and blocked (D) time
 *  socket bytes per process and connection  sock:sock_send_length / sock_recv_length (Linux >= 6.3)
 *  TCP handshake time, close, retransmits   sock:inet_sock_set_state, tcp:tcp_retransmit_skb
 *  destination of TLS connections (SNI),    first bytes of a send/recv, read from the
 *  HTTP request lines of plain-text APIs    syscall's own user buffer
 *  files opened, file vs pipe vs socket I/O sys_enter/exit(open/openat/read/write/...)
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef int s32;
typedef unsigned long long u64;
typedef long long s64;

char LICENSE[] SEC("license") = "GPL";

/* ------------------------------------------------------------ config slots */
/* cfg[] is an ARRAY map written by user space before the programs attach. */
enum {
    CFG_FORK_CHILD_OFF = 0,   /* offset of child_pid in sched_process_fork   */
    CFG_SWITCH_PREV_PID_OFF,  /* sched_switch prev_pid                        */
    CFG_SWITCH_PREV_STATE_OFF,/* sched_switch prev_state                      */
    CFG_SWITCH_NEXT_PID_OFF,  /* sched_switch next_pid                        */
    CFG_EXIT_GROUP_DEAD_OFF,  /* sched_process_exit group_dead, 0 = absent    */
    CFG_EXEC_FILENAME_OFF,    /* sched_process_exec __data_loc filename       */
    CFG_IO_EVENTS,            /* 1 = one event per socket send/recv           */
    CFG_FILE_EVENTS,          /* 1 = one event per open()                     */
    CFG_SNIFF_MAX,            /* max sniffed payload heads per connection     */
    CFG_PREV_STATE_SIZE,      /* 8 (long) or 4                                */
    CFG_REG0, CFG_REG1, CFG_REG2, CFG_REG3, CFG_REG4, CFG_REG5,
                              /* offsets of the 6 syscall argument registers  */
                              /* in struct pt_regs (raw tracepoint variant)   */
    CFG_NS_DEV, CFG_NS_INO,   /* PID namespace of the tracer (0 = init ns)    */
    CFG_BOOT_PENDING,         /* processes named by namespace PID, not yet    */
                              /* resolved to the kernel's global PID          */
    CFG_MAX
};

/* syscall classes (cls[] map, nr -> class), filled per architecture */
enum {
    C_NONE = 0, C_READ, C_READV, C_RECVMSG, C_WRITE, C_WRITEV, C_SENDMSG,
    C_SENDTO, C_CLOSE, C_CONNECT, C_OPEN, C_OPENAT, C_EXECVE, C_EXECVEAT,
    C_EXIT_GROUP, C_RECVFROM,
};

#define DIR_TX 0
#define DIR_RX 1

#define EV_FORK      1
#define EV_EXEC      2
#define EV_ARGV      3
#define EV_EXIT      4
#define EV_CONN      5
#define EV_IO        6
#define EV_SNIFF     7
#define EV_TCPSTATE  8
#define EV_CONNCLOSE 9
#define EV_OPEN      10
#define EV_CONNECT   11
#define EV_RETRANS   12
#define EV_THREAD_EXIT 13

#define AF_UNIX_  1
#define AF_INET_  2
#define AF_INET6_ 10
#define TCP_ESTABLISHED_ 1
#define TCP_SYN_SENT_ 2
#define TCP_SYN_RECV_ 3
#define TCP_CLOSE_ 7
#define MSG_PEEK_ 2

#define SNIFF_LEN 256
#define ARGV_N 8
#define ARGV_LEN 128
#define PATH_LEN 192
#define FILE_LEN 192

/* ------------------------------------------------------------------ structs */

struct pstats {                 /* per process (tgid), cumulative */
    u64 user_ns;                /* on-CPU outside syscalls                     */
    u64 sys_ns;                 /* on-CPU inside syscalls                      */
    u64 runq_ns;                /* runnable but waiting for a CPU (preempted)  */
    u64 sleep_ns;               /* sleeping (S): waiting for network, timers,  */
                                /* child processes, locks...                   */
    u64 io_ns;                  /* blocked uninterruptibly (D): mostly disk    */
    u64 vcsw, ivcsw;            /* voluntary / involuntary context switches    */
    u64 syscalls, sys_errs;
    u64 sys_wall_ns;            /* sum of syscall durations (incl. blocking)   */
    u64 inet_tx, inet_rx, inet_txc, inet_rxc;   /* TCP/UDP payload bytes, calls */
    u64 unix_tx, unix_rx;                        /* AF_UNIX (local IPC)         */
    u64 file_rd, file_wr;       /* read/write on fds this process opened       */
    u64 other_rd, other_wr;     /* pipes, ttys, inherited fds                  */
    u64 opens, open_fail;
    u64 forks;                  /* fork()/clone() calls, threads included      */
    u64 start_ns;
    s64 exit_code;              /* exit_group() argument, or -1 if killed      */
    u32 ppid;
    u32 threads;
};

struct tctx {                   /* per thread */
    u64 mark_ns;                /* last CPU accounting point                   */
    u64 off_ns;                 /* when it was switched out (0 = on CPU)       */
    u64 sys_ts;                 /* syscall entry time                          */
    u64 a0, a1, a2, a4;         /* saved syscall arguments                     */
    u32 tgid;
    s32 nr;                     /* current syscall, -1 = none                  */
    u8  in_sys;
    u8  off_state;              /* 1 runq, 2 sleep, 3 io                        */
    u8  sock_hit;               /* a socket tracepoint fired in this syscall   */
    u8  cls;
};

struct sysk { u32 tgid; u32 nr; };
struct sysv { u64 count; u64 total_ns; u64 max_ns; u64 errs; };
struct histk { u32 nr; u32 slot; };
struct fdk { u32 tgid; s32 fd; };

struct addr_t {
    u16 family; u16 port;       /* port host order */
    u32 pad;
    u8  addr[16];               /* IPv4 as ::ffff:a.b.c.d */
};

struct skaddr_t {               /* last TCP state info seen for a socket */
    u16 family; u16 sport; u16 dport; u16 state;
    u8  saddr[16];
    u8  daddr[16];
    u64 syn_ns;                 /* entered SYN_SENT / SYN_RECV */
    u64 est_ns;                 /* entered ESTABLISHED          */
};

struct conn_t {                 /* one INET socket used by a traced process */
    u64 first_ns, last_ns;
    u64 tx, rx, txc, rxc;
    u64 retrans;
    u32 tgid;
    u16 proto, family;
    u8  last_dir;               /* 0 tx, 1 rx, 2 none */
    u8  pad[3];
    u32 sniffs;
};

struct ev_hdr { u32 type; u32 tgid; u32 tid; u32 pad; u64 ts; };

struct ev_fork { struct ev_hdr h; u32 child; u32 pad; };
struct ev_exec { struct ev_hdr h; u64 cgid; char comm[16]; char filename[FILE_LEN]; };
struct ev_argv { struct ev_hdr h; u32 n; u32 pad; char argv[ARGV_N][ARGV_LEN]; };
struct ev_exit { struct ev_hdr h; struct pstats s; char comm[16]; };
struct ev_conn {
    struct ev_hdr h; u64 sk; u16 family; u16 proto; s32 fd;
    struct addr_t local; struct addr_t remote;
    u64 syn_ns; u64 est_ns; u8 have_tcp; u8 have_fdaddr; u8 pad[6];
};
struct ev_io { struct ev_hdr h; u64 sk; u32 bytes; u8 dir; u8 pad; u16 proto; };
struct ev_sniff { struct ev_hdr h; u64 sk; u32 len; u8 dir; u8 pad[3]; char data[SNIFF_LEN]; };
struct ev_tcpstate { struct ev_hdr h; u64 sk; s32 oldstate; s32 newstate; };
struct ev_connclose { struct ev_hdr h; u64 sk; struct conn_t c; };
struct ev_open { struct ev_hdr h; s32 ret; u32 flags; char path[PATH_LEN]; };
struct ev_connect { struct ev_hdr h; s32 fd; u32 pad; struct addr_t a; };
struct ev_retrans { struct ev_hdr h; u64 sk; };

/* --------------------------------------------------------------------- maps */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, CFG_MAX); __type(key, u32); __type(value, u64); } cfg SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1024); __type(key, u32); __type(value, u32); } cls SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 32768); __type(key, u32); __type(value, u32); } tracked SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 32768); __type(key, u32); __type(value, struct pstats); } pstats SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, u32); __type(value, struct tctx); } tctx SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, struct sysk); __type(value, struct sysv); } sysagg SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 32768); __type(key, struct histk); __type(value, u64); } syshist SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 65536); __type(key, struct fdk); __type(value, u8); } fdkind SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 16384); __type(key, struct fdk); __type(value, struct addr_t); } fdaddr SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 65536); __type(key, u64); __type(value, struct skaddr_t); } skaddr SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 16384); __type(key, u64); __type(value, struct conn_t); } conns SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096); __type(key, u32); __type(value, struct addr_t); } sendto_addr SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, u32); __type(value, struct pstats); } zero_ps SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 4); __type(key, u32); __type(value, u64); } counters SEC(".maps");
/* PID namespaces (WSL2 distros, containers): user space only knows the PID
 * inside its namespace, eBPF sees global PIDs. nsboot holds namespace PIDs to
 * start tracking; nsmap records global tgid -> namespace tgid for reports. */
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096); __type(key, u32); __type(value, u32); } nsboot SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 65536); __type(key, u32); __type(value, u32); } nsmap SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 16 * 1024 * 1024); } events SEC(".maps");

#define CNT_DROPPED 0     /* ring buffer full: events lost */
#define CNT_TCTX_FAIL 1

/* ------------------------------------------------------------------ helpers */

static __always_inline u64 cfgv(u32 k)
{
    u64 *v = bpf_map_lookup_elem(&cfg, &k);
    return v ? *v : 0;
}

static __always_inline void bump(u32 k)
{
    u64 *v = bpf_map_lookup_elem(&counters, &k);
    if (v)
        __sync_fetch_and_add(v, 1);
}

static __always_inline void *reserve(u64 size)
{
    void *p = bpf_ringbuf_reserve(&events, size, 0);
    if (!p)
        bump(CNT_DROPPED);
    return p;
}

static __always_inline void hdr(struct ev_hdr *h, u32 type, u64 id, u64 now)
{
    h->type = type;
    h->tgid = id >> 32;
    h->tid = (u32)id;
    h->pad = 0;
    h->ts = now;
}

static __always_inline int is_tracked(u32 tgid)
{
    return bpf_map_lookup_elem(&tracked, &tgid) != 0;
}

static __always_inline struct pstats *get_ps(u32 tgid)
{
    struct pstats *p = bpf_map_lookup_elem(&pstats, &tgid);
    if (p)
        return p;
    u32 z = 0;
    struct pstats *zero = bpf_map_lookup_elem(&zero_ps, &z);
    if (!zero)
        return 0;
    bpf_map_update_elem(&pstats, &tgid, zero, BPF_NOEXIST);
    p = bpf_map_lookup_elem(&pstats, &tgid);
    if (p && p->start_ns == 0) {
        p->start_ns = bpf_ktime_get_ns();
        p->exit_code = -1;
    }
    return p;
}

/* per-thread context; created the first time a traced thread is seen */
static __always_inline struct tctx *get_tc(u32 tid, u32 tgid, u64 now)
{
    struct tctx *t = bpf_map_lookup_elem(&tctx, &tid);
    if (t)
        return t;
    struct tctx n = {};
    n.mark_ns = now;
    n.tgid = tgid;
    n.nr = -1;
    if (bpf_map_update_elem(&tctx, &tid, &n, BPF_NOEXIST) != 0) {
        t = bpf_map_lookup_elem(&tctx, &tid);
        if (!t)
            bump(CNT_TCTX_FAIL);
        return t;
    }
    struct pstats *p = get_ps(tgid);
    if (p)
        __sync_fetch_and_add(&p->threads, 1);
    return bpf_map_lookup_elem(&tctx, &tid);
}

/* add on-CPU time since the last mark to user or kernel time */
static __always_inline void account_cpu(struct tctx *t, u64 now)
{
    if (t->off_ns || t->mark_ns == 0 || now <= t->mark_ns) {
        t->mark_ns = now;
        return;
    }
    u64 d = now - t->mark_ns;
    struct pstats *p = get_ps(t->tgid);
    if (p) {
        if (t->in_sys)
            __sync_fetch_and_add(&p->sys_ns, d);
        else
            __sync_fetch_and_add(&p->user_ns, d);
    }
    t->mark_ns = now;
}

static __always_inline u32 log2_u64(u64 v)
{
    u32 r = 0;
    if (v >> 32) { v >>= 32; r += 32; }
    if (v >> 16) { v >>= 16; r += 16; }
    if (v >> 8)  { v >>= 8;  r += 8; }
    if (v >> 4)  { v >>= 4;  r += 4; }
    if (v >> 2)  { v >>= 2;  r += 2; }
    if (v >> 1)  { r += 1; }
    return r;
}

static __always_inline void set_v4mapped(u8 *dst, const u8 *v4)
{
    __builtin_memset(dst, 0, 10);
    dst[10] = 0xff;
    dst[11] = 0xff;
    dst[12] = v4[0]; dst[13] = v4[1]; dst[14] = v4[2]; dst[15] = v4[3];
}

/* read a struct sockaddr from user memory into addr_t */
static __always_inline int read_sockaddr(struct addr_t *a, const void *uaddr, u64 len)
{
    u16 fam = 0;
    if (!uaddr || len < 4)
        return -1;
    if (bpf_probe_read_user(&fam, 2, uaddr))
        return -1;
    u8 buf[28] = {};
    if (fam == AF_INET_ && len >= 16) {
        if (bpf_probe_read_user(buf, 16, uaddr))
            return -1;
        a->family = AF_INET_;
        a->port = ((u16)buf[2] << 8) | buf[3];
        set_v4mapped(a->addr, &buf[4]);
        return 0;
    }
    if (fam == AF_INET6_ && len >= 24) {
        if (bpf_probe_read_user(buf, 24, uaddr))
            return -1;
        a->family = AF_INET6_;
        a->port = ((u16)buf[2] << 8) | buf[3];
        __builtin_memcpy(a->addr, &buf[8], 16);
        return 0;
    }
    return -1;
}

/* ===================================================== process lifecycle */

SEC("tracepoint/sched/sched_process_fork")
int tp_fork(void *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    if (!is_tracked(tgid))
        return 0;
    u32 child = 0;
    u64 off = cfgv(CFG_FORK_CHILD_OFF);
    if (off == 0 || off > 64)
        return 0;
    bpf_probe_read_kernel(&child, 4, (char *)ctx + off);
    if (!child)
        return 0;
    /* Insert the child as a tracked tgid. If the child is a THREAD its id is
     * a tid that never shows up as a tgid; the entry is removed when the
     * thread exits. */
    bpf_map_update_elem(&tracked, &child, &tgid, BPF_ANY);
    struct pstats *p = get_ps(tgid);
    if (p)
        __sync_fetch_and_add(&p->forks, 1);

    u64 now = bpf_ktime_get_ns();
    struct ev_fork *e = reserve(sizeof(*e));
    if (!e)
        return 0;
    hdr(&e->h, EV_FORK, id, now);
    e->child = child;
    e->pad = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int tp_exec(void *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    if (!is_tracked(tgid))
        return 0;
    u64 now = bpf_ktime_get_ns();
    struct ev_exec *e = reserve(sizeof(*e));
    if (!e)
        return 0;
    hdr(&e->h, EV_EXEC, id, now);
    e->cgid = bpf_get_current_cgroup_id();
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    u64 off = cfgv(CFG_EXEC_FILENAME_OFF);
    u32 loc = 0;
    e->filename[0] = 0;
    if (off && off < 64) {
        bpf_probe_read_kernel(&loc, 4, (char *)ctx + off);
        bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), (char *)ctx + (loc & 0xffff));
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int tp_exit(void *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32, tid = (u32)id;
    if (!is_tracked(tgid))
        return 0;
    u64 now = bpf_ktime_get_ns();

    /* final CPU accounting for this thread, then forget it */
    struct tctx *t = bpf_map_lookup_elem(&tctx, &tid);
    if (t) {
        account_cpu(t, now);
        bpf_map_delete_elem(&tctx, &tid);
    }

    int group_dead;
    u64 off = cfgv(CFG_EXIT_GROUP_DEAD_OFF);
    if (off && off < 64) {
        u8 gd = 0;
        bpf_probe_read_kernel(&gd, 1, (char *)ctx + off);
        group_dead = gd;
    } else {
        group_dead = (tid == tgid);
    }

    if (!group_dead) {
        if (tid != tgid)
            bpf_map_delete_elem(&tracked, &tid);   /* the thread's own entry */
        struct ev_hdr *e = reserve(sizeof(*e));
        if (e) {
            hdr(e, EV_THREAD_EXIT, id, now);
            bpf_ringbuf_submit(e, 0);
        }
        return 0;
    }

    struct ev_exit *e = reserve(sizeof(*e));
    if (e) {
        hdr(&e->h, EV_EXIT, id, now);
        struct pstats *p = bpf_map_lookup_elem(&pstats, &tgid);
        if (p)
            __builtin_memcpy(&e->s, p, sizeof(e->s));
        else
            __builtin_memset(&e->s, 0, sizeof(e->s));
        bpf_get_current_comm(e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }
    bpf_map_delete_elem(&pstats, &tgid);
    if (tid != tgid)
        bpf_map_delete_elem(&tracked, &tid);
    bpf_map_delete_elem(&tracked, &tgid);
    return 0;
}

/* ========================================================== CPU / sched */

static __always_inline u8 classify_state(s64 s)
{
    if (s == 0 || s >= 0x100)
        return 1;           /* preempted / runnable: waiting in the run queue */
    if (s & 2)
        return 3;           /* D: uninterruptible (disk, some locks)         */
    return 2;               /* S and others: voluntary sleep                 */
}

SEC("tracepoint/sched/sched_switch")
int tp_switch(void *ctx)
{
    u64 now = bpf_ktime_get_ns();
    u32 prev = 0, next = 0;
    s64 pstate = 0;
    u64 o1 = cfgv(CFG_SWITCH_PREV_PID_OFF), o2 = cfgv(CFG_SWITCH_PREV_STATE_OFF),
        o3 = cfgv(CFG_SWITCH_NEXT_PID_OFF);
    if (!o1 || !o2 || !o3 || o1 > 128 || o2 > 128 || o3 > 128)
        return 0;
    bpf_probe_read_kernel(&prev, 4, (char *)ctx + o1);
    bpf_probe_read_kernel(&next, 4, (char *)ctx + o3);

    struct tctx *t = bpf_map_lookup_elem(&tctx, &prev);
    if (t) {
        if (cfgv(CFG_PREV_STATE_SIZE) == 4) {
            s32 s4 = 0;
            bpf_probe_read_kernel(&s4, 4, (char *)ctx + o2);
            pstate = s4;
        } else {
            bpf_probe_read_kernel(&pstate, 8, (char *)ctx + o2);
        }
        account_cpu(t, now);
        t->off_ns = now;
        t->off_state = classify_state(pstate);
        struct pstats *p = get_ps(t->tgid);
        if (p) {
            if (t->off_state == 1)
                __sync_fetch_and_add(&p->ivcsw, 1);
            else
                __sync_fetch_and_add(&p->vcsw, 1);
        }
    }
    struct tctx *n = bpf_map_lookup_elem(&tctx, &next);
    if (n) {
        if (n->off_ns && now > n->off_ns) {
            u64 d = now - n->off_ns;
            struct pstats *p = get_ps(n->tgid);
            if (p) {
                if (n->off_state == 1)
                    __sync_fetch_and_add(&p->runq_ns, d);
                else if (n->off_state == 3)
                    __sync_fetch_and_add(&p->io_ns, d);
                else
                    __sync_fetch_and_add(&p->sleep_ns, d);
            }
        }
        n->off_ns = 0;
        n->mark_ns = now;
    }
    return 0;
}

/* ============================================================== syscalls */

struct sys_enter_ctx { u64 common; s64 id; u64 args[6]; };
struct sys_exit_ctx { u64 common; s64 id; s64 ret; };

struct sargs { s64 id; u64 args[6]; };

/* namespace PID of the current process, or 0 when not in namespace mode */
static __always_inline u32 ns_tgid_now(void)
{
    u64 ino = cfgv(CFG_NS_INO);
    if (!ino)
        return 0;
    struct bpf_pidns_info ns = {};
    if (bpf_get_ns_current_pid_tgid(cfgv(CFG_NS_DEV), ino, &ns, sizeof(ns)))
        return 0;
    return ns.tgid;
}

/* A process named by its namespace PID makes a syscall: start tracking its
 * global PID. Costs one array lookup per syscall while nothing is pending. */
static __always_inline void boot_check(u64 id)
{
    if (!cfgv(CFG_BOOT_PENDING))
        return;
    u32 nst = ns_tgid_now();
    if (!nst)
        return;
    u32 *parent = bpf_map_lookup_elem(&nsboot, &nst);
    if (!parent)
        return;
    u32 g = id >> 32;
    bpf_map_update_elem(&tracked, &g, parent, BPF_ANY);
    bpf_map_update_elem(&nsmap, &g, &nst, BPF_ANY);
    bpf_map_delete_elem(&nsboot, &nst);
    u32 k = CFG_BOOT_PENDING;
    u64 *v = bpf_map_lookup_elem(&cfg, &k);
    if (v && *v)
        __sync_fetch_and_sub(v, 1);
}

/* remember global -> namespace PID of every traced process */
static __always_inline void ns_record(u32 tgid)
{
    if (!cfgv(CFG_NS_INO) || bpf_map_lookup_elem(&nsmap, &tgid))
        return;
    u32 nst = ns_tgid_now();
    if (nst)
        bpf_map_update_elem(&nsmap, &tgid, &nst, BPF_ANY);
}

static __always_inline int sys_enter_common(struct sargs *ctx);

/* Classic tracepoint: simple and portable, but the kernel prepares a perf
 * record for every syscall of EVERY process before calling us. */
SEC("tracepoint/raw_syscalls/sys_enter")
int tp_sys_enter(struct sys_enter_ctx *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    boot_check(id);
    if (!is_tracked(id >> 32))
        return 0;
    struct sargs a;
    a.id = ctx->id;
    a.args[0] = ctx->args[0]; a.args[1] = ctx->args[1]; a.args[2] = ctx->args[2];
    a.args[3] = ctx->args[3]; a.args[4] = ctx->args[4]; a.args[5] = ctx->args[5];
    return sys_enter_common(&a);
}

/* Raw tracepoint: called with (struct pt_regs *regs, long id) and nothing
 * prepared, so untraced processes pay much less. The argument registers are
 * read at offsets user space writes to cfg (x86_64: di si dx r10 r8 r9;
 * arm64: x0..x5), which keeps this object free of kernel headers. */
SEC("raw_tracepoint/sys_enter")
int raw_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    boot_check(id);
    if (!is_tracked(id >> 32))
        return 0;
    const char *regs = (const char *)ctx->args[0];
    struct sargs a;
    a.id = (s64)ctx->args[1];
    u64 o;
    o = cfgv(CFG_REG0); a.args[0] = 0; bpf_probe_read_kernel(&a.args[0], 8, regs + (o & 0x3ff));
    o = cfgv(CFG_REG1); a.args[1] = 0; bpf_probe_read_kernel(&a.args[1], 8, regs + (o & 0x3ff));
    o = cfgv(CFG_REG2); a.args[2] = 0; bpf_probe_read_kernel(&a.args[2], 8, regs + (o & 0x3ff));
    o = cfgv(CFG_REG3); a.args[3] = 0; bpf_probe_read_kernel(&a.args[3], 8, regs + (o & 0x3ff));
    o = cfgv(CFG_REG4); a.args[4] = 0; bpf_probe_read_kernel(&a.args[4], 8, regs + (o & 0x3ff));
    o = cfgv(CFG_REG5); a.args[5] = 0; bpf_probe_read_kernel(&a.args[5], 8, regs + (o & 0x3ff));
    return sys_enter_common(&a);
}

static __always_inline int sys_enter_common(struct sargs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32, tid = (u32)id;
    u64 now = bpf_ktime_get_ns();
    struct tctx *t = get_tc(tid, tgid, now);
    if (!t)
        return 0;
    ns_record(tgid);
    account_cpu(t, now);
    t->in_sys = 1;
    t->sys_ts = now;
    s64 nr = ctx->id;
    t->nr = (s32)nr;
    t->sock_hit = 0;
    t->cls = 0;
    if (nr < 0 || nr >= 1024)
        return 0;
    u32 k = (u32)nr;
    u32 *c = bpf_map_lookup_elem(&cls, &k);
    if (!c || *c == C_NONE)
        return 0;
    u32 cl = *c;
    t->cls = cl;
    t->a0 = ctx->args[0];
    t->a1 = ctx->args[1];
    t->a2 = ctx->args[2];
    t->a4 = ctx->args[4];

    if (cl == C_CLOSE) {
        struct fdk fk = { .tgid = tgid, .fd = (s32)ctx->args[0] };
        bpf_map_delete_elem(&fdkind, &fk);
        bpf_map_delete_elem(&fdaddr, &fk);
        return 0;
    }
    if (cl == C_EXIT_GROUP) {
        struct pstats *p = get_ps(tgid);
        if (p)
            p->exit_code = (s64)(s32)ctx->args[0];
        return 0;
    }
    if (cl == C_CONNECT) {
        struct addr_t a = {};
        if (read_sockaddr(&a, (const void *)ctx->args[1], ctx->args[2]) == 0) {
            struct fdk fk = { .tgid = tgid, .fd = (s32)ctx->args[0] };
            bpf_map_update_elem(&fdaddr, &fk, &a, BPF_ANY);
            struct ev_connect *e = reserve(sizeof(*e));
            if (e) {
                hdr(&e->h, EV_CONNECT, id, now);
                e->fd = (s32)ctx->args[0];
                e->pad = 0;
                e->a = a;
                bpf_ringbuf_submit(e, 0);
            }
        }
        return 0;
    }
    if (cl == C_SENDTO && ctx->args[4]) {
        struct addr_t a = {};
        if (read_sockaddr(&a, (const void *)ctx->args[4], ctx->args[5]) == 0)
            bpf_map_update_elem(&sendto_addr, &tid, &a, BPF_ANY);
        return 0;
    }
    if (cl == C_EXECVE || cl == C_EXECVEAT) {
        /* use the copies in the map: a computed ctx pointer is rejected by the verifier */
        const char *const *argv = (const char *const *)(cl == C_EXECVE ? t->a1 : t->a2);
        struct ev_argv *e = reserve(sizeof(*e));
        if (!e)
            return 0;
        hdr(&e->h, EV_ARGV, id, now);
        e->n = 0;
        e->pad = 0;
#pragma unroll
        for (int i = 0; i < ARGV_N; i++) {
            const char *p = 0;
            e->argv[i][0] = 0;
            if (e->n == (u32)i && argv) {
                bpf_probe_read_user(&p, sizeof(p), &argv[i]);
                if (p) {
                    bpf_probe_read_user_str(e->argv[i], ARGV_LEN, p);
                    e->n = i + 1;
                }
            }
        }
        bpf_ringbuf_submit(e, 0);
        return 0;
    }
    return 0;
}

static __always_inline void count_data(struct tctx *t, u32 tgid, s64 ret)
{
    if (ret <= 0 || t->sock_hit)
        return;
    u32 cl = t->cls;
    int rd = (cl == C_READ || cl == C_READV || cl == C_RECVMSG || cl == C_RECVFROM);
    int wr = (cl == C_WRITE || cl == C_WRITEV || cl == C_SENDMSG || cl == C_SENDTO);
    if (!rd && !wr)
        return;
    struct fdk fk = { .tgid = tgid, .fd = (s32)t->a0 };
    u8 *kind = bpf_map_lookup_elem(&fdkind, &fk);
    struct pstats *p = get_ps(tgid);
    if (!p)
        return;
    if (kind) {
        if (rd) __sync_fetch_and_add(&p->file_rd, ret);
        else    __sync_fetch_and_add(&p->file_wr, ret);
    } else {
        if (rd) __sync_fetch_and_add(&p->other_rd, ret);
        else    __sync_fetch_and_add(&p->other_wr, ret);
    }
}

static __always_inline int sys_exit_common(s64 ret, s32 nr, int nr_known);

SEC("tracepoint/raw_syscalls/sys_exit")
int tp_sys_exit(struct sys_exit_ctx *ctx)
{
    return sys_exit_common(ctx->ret, (s32)ctx->id, 1);
}

/* raw variant: (struct pt_regs *regs, long ret); the syscall number is the
 * one saved at entry */
SEC("raw_tracepoint/sys_exit")
int raw_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    return sys_exit_common((s64)ctx->args[1], 0, 0);
}

static __always_inline int sys_exit_common(s64 ret, s32 nr, int nr_known)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tid = (u32)id;
    struct tctx *t = bpf_map_lookup_elem(&tctx, &tid);
    if (!t)
        return 0;
    u32 tgid = id >> 32;
    if (t->tgid != tgid)    /* tid reused by another process */
        t->tgid = tgid;
    u64 now = bpf_ktime_get_ns();
    account_cpu(t, now);
    t->in_sys = 0;
    if (!nr_known)
        nr = t->nr;
    if (t->nr < 0 || t->nr != nr || t->sys_ts == 0 || now < t->sys_ts) {
        t->nr = -1;
        return 0;
    }
    u64 d = now - t->sys_ts;
    t->nr = -1;

    struct pstats *p = get_ps(tgid);
    if (p) {
        __sync_fetch_and_add(&p->syscalls, 1);
        __sync_fetch_and_add(&p->sys_wall_ns, d);
        if (ret < 0 && ret > -4096)
            __sync_fetch_and_add(&p->sys_errs, 1);
    }
    struct sysk k = { .tgid = tgid, .nr = (u32)nr };
    struct sysv *v = bpf_map_lookup_elem(&sysagg, &k);
    if (!v) {
        struct sysv z = {};
        bpf_map_update_elem(&sysagg, &k, &z, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&sysagg, &k);
    }
    if (v) {
        __sync_fetch_and_add(&v->count, 1);
        __sync_fetch_and_add(&v->total_ns, d);
        if (d > v->max_ns)
            v->max_ns = d;
        if (ret < 0 && ret > -4096)
            __sync_fetch_and_add(&v->errs, 1);
    }
    struct histk hk = { .nr = (u32)nr, .slot = log2_u64(d) };
    u64 *hc = bpf_map_lookup_elem(&syshist, &hk);
    if (hc) {
        __sync_fetch_and_add(hc, 1);
    } else {
        u64 one = 1;
        bpf_map_update_elem(&syshist, &hk, &one, BPF_NOEXIST);
    }

    u32 cl = t->cls;
    if (cl == C_OPEN || cl == C_OPENAT) {
        if (p) {
            __sync_fetch_and_add(&p->opens, 1);
            if (ret < 0)
                __sync_fetch_and_add(&p->open_fail, 1);
        }
        if (ret >= 0) {
            struct fdk fk = { .tgid = tgid, .fd = (s32)ret };
            u8 one = 1;
            bpf_map_update_elem(&fdkind, &fk, &one, BPF_ANY);
        }
        if (cfgv(CFG_FILE_EVENTS)) {
            struct ev_open *e = reserve(sizeof(*e));
            if (e) {
                hdr(&e->h, EV_OPEN, id, now);
                e->ret = (s32)ret;
                e->flags = (u32)(cl == C_OPEN ? t->a1 : t->a2);
                const char *path = (const char *)(cl == C_OPEN ? t->a0 : t->a1);
                e->path[0] = 0;
                bpf_probe_read_user_str(e->path, sizeof(e->path), path);
                bpf_ringbuf_submit(e, 0);
            }
        }
    } else {
        count_data(t, tgid, ret);
    }
    if (cl == C_SENDTO)
        bpf_map_delete_elem(&sendto_addr, &tid);
    t->cls = 0;
    return 0;
}

/* =============================================================== sockets */

struct sock_len_ctx { u64 common; u64 sk; u16 family; u16 protocol; s32 ret; s32 flags; };

/* user buffer of the current send/recv syscall (first iovec only) */
static __always_inline int user_buf(struct tctx *t, u64 *ptr, u64 *len)
{
    u32 cl = t->cls;
    if (cl == C_WRITE || cl == C_READ || cl == C_SENDTO || cl == C_RECVFROM) {
        *ptr = t->a1;
        *len = t->a2;
        return 0;
    }
    u64 iov = 0;
    if (cl == C_WRITEV || cl == C_READV) {
        iov = t->a1;
    } else if (cl == C_SENDMSG || cl == C_RECVMSG) {
        /* struct msghdr { void *name; int namelen; struct iovec *iov; ... } */
        if (bpf_probe_read_user(&iov, 8, (void *)(t->a1 + 16)))
            return -1;
    } else {
        return -1;
    }
    u64 v[2] = {};
    if (!iov || bpf_probe_read_user(v, 16, (void *)iov))
        return -1;
    *ptr = v[0];
    *len = v[1];
    return 0;
}

static __always_inline void sock_io(struct sock_len_ctx *ctx, u8 dir)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32, tid = (u32)id;
    if (!is_tracked(tgid))
        return;
    s32 ret = ctx->ret;
    if (dir == DIR_RX && (ctx->flags & MSG_PEEK_))
        return;
    u64 now = bpf_ktime_get_ns();
    struct tctx *t = bpf_map_lookup_elem(&tctx, &tid);
    if (t)
        t->sock_hit = 1;
    if (ret <= 0)
        return;
    u16 fam = ctx->family;
    struct pstats *p = get_ps(tgid);
    if (fam == AF_UNIX_) {
        if (p) {
            if (dir == DIR_TX) __sync_fetch_and_add(&p->unix_tx, ret);
            else               __sync_fetch_and_add(&p->unix_rx, ret);
        }
        return;
    }
    if (fam != AF_INET_ && fam != AF_INET6_)
        return;
    if (p) {
        if (dir == DIR_TX) {
            __sync_fetch_and_add(&p->inet_tx, ret);
            __sync_fetch_and_add(&p->inet_txc, 1);
        } else {
            __sync_fetch_and_add(&p->inet_rx, ret);
            __sync_fetch_and_add(&p->inet_rxc, 1);
        }
    }

    u64 sk = ctx->sk;
    struct conn_t *c = bpf_map_lookup_elem(&conns, &sk);
    if (!c) {
        struct conn_t nc = {};
        nc.first_ns = now;
        nc.tgid = tgid;
        nc.proto = ctx->protocol;
        nc.family = fam;
        nc.last_dir = 2;
        bpf_map_update_elem(&conns, &sk, &nc, BPF_NOEXIST);
        c = bpf_map_lookup_elem(&conns, &sk);
        if (!c)
            return;
        /* announce the connection with everything we know about its ends */
        struct ev_conn *e = reserve(sizeof(*e));
        if (e) {
            __builtin_memset(e, 0, sizeof(*e));
            hdr(&e->h, EV_CONN, id, now);
            e->sk = sk;
            e->family = fam;
            e->proto = ctx->protocol;
            e->fd = t ? (s32)t->a0 : -1;
            struct skaddr_t *sa = bpf_map_lookup_elem(&skaddr, &sk);
            if (sa) {
                e->have_tcp = 1;
                e->local.family = sa->family;
                e->local.port = sa->sport;
                __builtin_memcpy(e->local.addr, sa->saddr, 16);
                e->remote.family = sa->family;
                e->remote.port = sa->dport;
                __builtin_memcpy(e->remote.addr, sa->daddr, 16);
                e->syn_ns = sa->syn_ns;
                e->est_ns = sa->est_ns;
            }
            if (t) {
                struct addr_t *ua = 0;
                if (t->cls == C_SENDTO)
                    ua = bpf_map_lookup_elem(&sendto_addr, &tid);
                if (!ua) {
                    struct fdk fk = { .tgid = tgid, .fd = (s32)t->a0 };
                    ua = bpf_map_lookup_elem(&fdaddr, &fk);
                }
                if (ua) {
                    e->have_fdaddr = 1;
                    if (!e->have_tcp)
                        e->remote = *ua;
                }
            }
            bpf_ringbuf_submit(e, 0);
        }
    }
    c->last_ns = now;
    u8 turn = (c->last_dir != dir);   /* first send after a receive, etc. */
    c->last_dir = dir;
    if (dir == DIR_TX) {
        __sync_fetch_and_add(&c->tx, ret);
        __sync_fetch_and_add(&c->txc, 1);
    } else {
        __sync_fetch_and_add(&c->rx, ret);
        __sync_fetch_and_add(&c->rxc, 1);
    }

    if (cfgv(CFG_IO_EVENTS)) {
        struct ev_io *e = reserve(sizeof(*e));
        if (e) {
            hdr(&e->h, EV_IO, id, now);
            e->sk = sk;
            e->bytes = ret;
            e->dir = dir;
            e->pad = 0;
            e->proto = ctx->protocol;
            bpf_ringbuf_submit(e, 0);
        }
    }

    /* Payload head at every change of direction: TLS ClientHello (-> SNI),
     * HTTP request line / status line of plain-text APIs (local LLM servers).
     * Read from the syscall's own user buffer, which holds the data now. */
    if (turn && t && c->sniffs < cfgv(CFG_SNIFF_MAX)) {
        u64 ptr = 0, len = 0;
        if (user_buf(t, &ptr, &len) == 0 && ptr) {
            u32 n = ret;
            if (len < n)
                n = len;
            if (n > SNIFF_LEN)
                n = SNIFF_LEN;
            struct ev_sniff *e = reserve(sizeof(*e));
            if (e) {
                hdr(&e->h, EV_SNIFF, id, now);
                e->sk = sk;
                e->dir = dir;
                e->len = 0;
                /* fixed-size reads keep the verifier happy; user space keeps
                 * only the first `len` bytes (the rest may be other memory of
                 * the same process). If the buffer ends near an unmapped page
                 * the big read fails, so fall back to smaller ones. */
                if (n > 0) {
                    if (bpf_probe_read_user(e->data, SNIFF_LEN, (void *)ptr) == 0)
                        e->len = n;
                    else if (bpf_probe_read_user(e->data, 64, (void *)ptr) == 0)
                        e->len = n < 64 ? n : 64;
                    else if (bpf_probe_read_user(e->data, 8, (void *)ptr) == 0)
                        e->len = n < 8 ? n : 8;
                }
                bpf_ringbuf_submit(e, 0);
                c->sniffs++;
            }
        }
    }
}

SEC("tracepoint/sock/sock_send_length")
int tp_send_len(struct sock_len_ctx *ctx)
{
    sock_io(ctx, DIR_TX);
    return 0;
}

SEC("tracepoint/sock/sock_recv_length")
int tp_recv_len(struct sock_len_ctx *ctx)
{
    sock_io(ctx, DIR_RX);
    return 0;
}

struct set_state_ctx {
    u64 common; u64 skaddr; s32 oldstate; s32 newstate;
    u16 sport; u16 dport; u16 family; u16 protocol;
    u8 saddr[4]; u8 daddr[4]; u8 saddr_v6[16]; u8 daddr_v6[16];
};

SEC("tracepoint/sock/inet_sock_set_state")
int tp_set_state(struct set_state_ctx *ctx)
{
    if (ctx->protocol != 6)
        return 0;
    u64 sk = ctx->skaddr;
    u64 now = bpf_ktime_get_ns();
    s32 ns = ctx->newstate;

    /* remember the 4-tuple of EVERY TCP socket (cheap: state changes are rare);
     * the owner is unknown here (softirq), it is learned at the first send/recv */
    struct skaddr_t *sa = bpf_map_lookup_elem(&skaddr, &sk);
    if (!sa || ns == TCP_SYN_SENT_ || (ns == TCP_SYN_RECV_)) {
        struct skaddr_t n = {};
        bpf_map_update_elem(&skaddr, &sk, &n, BPF_ANY);
        sa = bpf_map_lookup_elem(&skaddr, &sk);
    }
    if (sa) {
        sa->family = ctx->family;
        sa->sport = ctx->sport;
        sa->dport = ctx->dport;
        sa->state = ns;
        if (ctx->family == AF_INET_) {
            set_v4mapped(sa->saddr, ctx->saddr);
            set_v4mapped(sa->daddr, ctx->daddr);
        } else {
            __builtin_memcpy(sa->saddr, ctx->saddr_v6, 16);
            __builtin_memcpy(sa->daddr, ctx->daddr_v6, 16);
        }
        if (ns == TCP_SYN_SENT_ || ns == TCP_SYN_RECV_)
            sa->syn_ns = now;
        if (ns == TCP_ESTABLISHED_)
            sa->est_ns = now;
    }

    struct conn_t *c = bpf_map_lookup_elem(&conns, &sk);
    if (!c)
        return 0;
    u64 id = ((u64)c->tgid << 32);
    struct ev_tcpstate *e = reserve(sizeof(*e));
    if (e) {
        hdr(&e->h, EV_TCPSTATE, id, now);
        e->sk = sk;
        e->oldstate = ctx->oldstate;
        e->newstate = ns;
        bpf_ringbuf_submit(e, 0);
    }
    if (ns == TCP_CLOSE_) {
        struct ev_connclose *x = reserve(sizeof(*x));
        if (x) {
            hdr(&x->h, EV_CONNCLOSE, id, now);
            x->sk = sk;
            x->c = *c;
            bpf_ringbuf_submit(x, 0);
        }
        bpf_map_delete_elem(&conns, &sk);
        bpf_map_delete_elem(&skaddr, &sk);
    }
    return 0;
}

struct retrans_ctx { u64 common; u64 skbaddr; u64 skaddr; };

SEC("tracepoint/tcp/tcp_retransmit_skb")
int tp_retrans(struct retrans_ctx *ctx)
{
    u64 sk = ctx->skaddr;
    struct conn_t *c = bpf_map_lookup_elem(&conns, &sk);
    if (!c)
        return 0;
    __sync_fetch_and_add(&c->retrans, 1);
    struct ev_retrans *e = reserve(sizeof(*e));
    if (e) {
        hdr(&e->h, EV_RETRANS, (u64)c->tgid << 32, bpf_ktime_get_ns());
        e->sk = sk;
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}
