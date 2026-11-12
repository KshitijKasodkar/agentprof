"""Self-contained HTML report (inline SVG, no JavaScript libraries, no network)."""
import html
import json

CSS = """
:root{--bg:#fbfaf7;--fg:#1d1d1b;--mut:#6b6a66;--line:#dedcd5;--llm:#3b6fd8;--wait:#9fb8ec;
--tool:#d9822b;--fail:#c2412d;--net:#7a8a99;--mem:#3f8f6b;--card:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecebe7;--mut:#a3a29c;--line:#383733;--card:#1f1f1d;
--wait:#355a9e}}
body{font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--fg);
margin:0;padding:24px;max-width:1200px;margin:auto}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 8px;border-bottom:1px solid var(--line);
padding-bottom:4px}.mut{color:var(--mut)}code{font:12px ui-monospace,monospace}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:14px 0}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.kpi b{display:block;font-size:20px;font-variant-numeric:tabular-nums}.kpi span{color:var(--mut);font-size:12px}
table{border-collapse:collapse;width:100%;font-size:12.5px;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:4px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600}td.n,th.n{text-align:right}
.bar{display:flex;height:26px;border-radius:6px;overflow:hidden;border:1px solid var(--line)}
.bar div{height:100%}.legend span{display:inline-flex;align-items:center;margin-right:14px;font-size:12px}
.legend i{width:11px;height:11px;border-radius:2px;margin-right:5px;display:inline-block}
svg text{fill:var(--fg);font:11px system-ui,sans-serif}svg .mut{fill:var(--mut)}
details{margin:8px 0}pre{font:11.5px ui-monospace,monospace;white-space:pre;overflow:auto;background:var(--card);
border:1px solid var(--line);padding:10px;border-radius:6px;max-height:420px}
"""


def e(x):
    return html.escape(str(x), quote=True)


def fmt_bytes(n):
    if n is None:
        return "–"
    n = float(n)
    for u in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024 or u == "GB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


def timeline_svg(s, tl, width=1140):
    t0, t1 = tl["t0"], max(tl["run_end"], tl["t0"] + 1)
    for x in tl["llm"]:
        if x[3]:
            t1 = max(t1, x[3])
    span = t1 - t0
    left = 150
    W = width - left - 10

    def X(t):
        return left + (t - t0) / span * W

    max_tool_rows = 40
    lanes = []                          # pack tool calls into lanes
    tools = []
    for t in sorted(tl["tools"], key=lambda x: x[0]):
        for i, end in enumerate(lanes):
            if t[0] >= end:
                lanes[i] = t[1]
                t_lane = i
                break
        else:
            lanes.append(t[1])
            t_lane = len(lanes) - 1
        tools.append(tuple(t) + (t_lane,))
    rows_tools = min(max(1, len(lanes)), max_tool_rows)
    row_h = 18
    y_llm = 30
    y_net = y_llm + 30
    y_tools = y_net + 30
    y_mem = y_tools + rows_tools * row_h + 20
    H = y_mem + 70
    o = [f'<svg viewBox="0 0 {width} {H}" width="100%" role="img" aria-label="timeline">']
    # grid
    step = nice_step(span / 1e9)
    k = 0.0
    while k <= span / 1e9 + 1e-9:
        x = X(t0 + k * 1e9)
        o.append(f'<line x1="{x:.1f}" y1="18" x2="{x:.1f}" y2="{H - 14}" stroke="var(--line)" />')
        o.append(f'<text x="{x:.1f}" y="12" text-anchor="middle" class="mut">{k:g}s</text>')
        k += step
    o.append(f'<text x="4" y="{y_llm + 13}">LLM calls</text>')
    o.append(f'<text x="4" y="{y_net + 13}">other network</text>')
    o.append(f'<text x="4" y="{y_tools + 13}">tool processes</text>')
    o.append(f'<text x="4" y="{y_mem + 30}">memory</text>')
    for st, req_end, first, last, kind, rq, rs in tl["llm"]:
        end = last or req_end
        o.append(f'<rect x="{X(st):.1f}" y="{y_llm}" width="{max(1, X(req_end) - X(st)):.1f}" height="18" fill="var(--llm)">'
                 f'<title>request {fmt_bytes(rq)}</title></rect>')
        if first:
            o.append(f'<rect x="{X(req_end):.1f}" y="{y_llm}" width="{max(1, X(first) - X(req_end)):.1f}" height="18" '
                     f'fill="var(--wait)"><title>waiting for first byte {(first - req_end) / 1e6:.0f} ms</title></rect>')
            o.append(f'<rect x="{X(first):.1f}" y="{y_llm}" width="{max(1, X(end) - X(first)):.1f}" height="18" '
                     f'fill="var(--llm)" opacity="{0.55 if kind != "llm" else 0.85}"><title>{e(kind)}: response '
                     f'{fmt_bytes(rs)} streamed in {(end - first) / 1e6:.0f} ms</title></rect>')
    for st, end, cat, name in tl["other_net"]:
        o.append(f'<rect x="{X(st):.1f}" y="{y_net + 3}" width="{max(1.5, X(end) - X(st)):.1f}" height="12" '
                 f'fill="var(--net)"><title>{e(cat)}: {e(name)}</title></rect>')
    for t in tools[: 10_000]:
        st, end, label, code, lane = t
        if lane >= max_tool_rows:
            lane = max_tool_rows - 1
        y = y_tools + lane * row_h
        col = "var(--fail)" if code not in (0, None) else "var(--tool)"
        o.append(f'<rect x="{X(st):.1f}" y="{y}" width="{max(1.5, X(end) - X(st)):.1f}" height="{row_h - 4}" '
                 f'fill="{col}" rx="2"><title>{e(label)} ({(end - st) / 1e6:.0f} ms, exit {code})</title></rect>')
    mem = tl["mem"]
    if mem:
        mx = max(v for _, v in mem) or 1
        pts = " ".join(f"{X(t):.1f},{y_mem + 50 - v / mx * 46:.1f}" for t, v in mem if t0 <= t <= t1)
        o.append(f'<polyline points="{pts}" fill="none" stroke="var(--mem)" stroke-width="1.5" />')
        o.append(f'<text x="{left + W}" y="{y_mem + 2}" text-anchor="end" class="mut">peak {fmt_bytes(mx)}</text>')
    o.append("</svg>")
    return "".join(o)


def nice_step(sec):
    for s in (0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 30, 60, 120, 300, 600, 1200, 1800, 3600):
        if sec / s <= 12:
            return s
    return 7200


def render(s, tl):
    ts = s["timesplit"]
    c = s["counts"]
    lm = s["llm"]
    o = [f"<!doctype html><html><head><meta charset='utf-8'><title>agentprof: {e(s['label'] or s['run'])}</title>"
         f"<meta name='viewport' content='width=device-width,initial-scale=1'><style>{CSS}</style></head><body>"]
    o.append(f"<h1>agentprof: {e(s['label'] or s['run'])}</h1>")
    h = s["host"] or {}
    o.append(f"<div class='mut'><code>{e(' '.join(s['command'] or []))[:300]}</code><br>{e(h.get('hostname'))} · "
             f"{e(h.get('model') or h.get('machine'))} · kernel {e(h.get('kernel'))} · agent main pid "
             f"{e(s['agent_main']['pid'])} · exit {e(s['exit_code'])}</div>")
    kp = [("wall time", f"{ts['run_s']} s"),
          ("LLM calls" + (f" ({c['llm_retries']} retries)" if c.get("llm_retries") else ""), c["llm_calls"]),
          ("tool processes" + (f" / {c['tool_uses_logged']} tool uses" if c.get("tool_uses_logged") is not None else ""),
           c["tool_calls"]),
          ("LLM busy", f"{ts['llm_share_pct']} %"), ("tools running", f"{ts['tool_share_pct']} %"),
          ("median TTFB", f"{lm['ttfb_ms_median']} ms"), ("processes", c["processes"]),
          ("peak memory", fmt_bytes(s["memory"]["peak_bytes"]))]
    o.append("<div class='kpis'>" + "".join(f"<div class='kpi'><b>{e(v)}</b><span>{e(k)}</span></div>" for k, v in kp)
             + "</div>")
    o.append("<h2>Where the time went</h2>")
    segs = [("LLM only", ts["llm_only_pct"], "var(--llm)"), ("both", ts["both_pct"], "#8a63c9"),
            ("tools only", ts["tool_only_pct"], "var(--tool)"),
            ("provider back-off", ts.get("provider_backoff_pct", 0), "var(--fail)"),
            ("neither", ts["neither_pct"], "var(--line)")]
    o.append("<div class='bar'>" + "".join(f"<div style='width:{max(0, p)}%;background:{col}' title='{e(n)} {p}%'></div>"
                                          for n, p, col in segs) + "</div>")
    o.append("<div class='legend'>" + "".join(f"<span><i style='background:{col}'></i>{e(n)} {p} %</span>"
                                             for n, p, col in segs) + "</div>")
    o.append(f"<p class='mut'>Start-up before the first LLM call {ts['startup_s']} s. Of the LLM time, "
             f"{ts['llm_wait_ttfb_s']} s was waiting for the first byte and {ts['llm_streaming_s']} s streaming. "
             "“Neither” = the agent's own processing, start-up and idle time.</p>")
    o.append("<h2>Timeline</h2>")
    o.append("<div class='legend'><span><i style='background:var(--llm)'></i>request / streamed response</span>"
             "<span><i style='background:var(--wait)'></i>waiting for first byte</span>"
             "<span><i style='background:var(--tool)'></i>tool process</span>"
             "<span><i style='background:var(--fail)'></i>tool failed</span>"
             "<span><i style='background:var(--net)'></i>other network</span>"
             "<span><i style='background:var(--mem)'></i>memory</span></div>")
    o.append(timeline_svg(s, tl))
    o.append("<h2>LLM calls</h2>")
    o.append(f"<p class='mut'>Endpoints: {e(', '.join(lm['endpoints']) or '–')}. Request size "
             f"{fmt_bytes(lm['req_bytes_first'])} → {fmt_bytes(lm['req_bytes_last'])}; median append "
             f"{fmt_bytes(lm['append_bytes_median'])}; median gap between calls {lm['gap_between_calls_ms_median']} ms.</p>")
    o.append(table(["#", "kind", "start s", "request", "response", "TTFB ms", "stream ms", "total ms", "path"],
                   [[x["n"], x["kind"], x["start_s"], fmt_bytes(x["req_bytes"]), fmt_bytes(x["resp_bytes"]),
                     x["ttfb_ms"], x["stream_ms"], x["total_ms"], x["path"] or ""] for x in lm["calls"][:300]],
                   num={0, 2, 5, 6, 7}))
    o.append("<h2>Tool calls</h2>")
    o.append(f"<p class='mut'>By phase: {e(c.get('tool_calls_by_phase'))}. “act” = between an LLM response and the "
             "next request (model-requested tools); startup / during-llm = the agent's own housekeeping.</p>")
    o.append(table(["#", "phase", "start s", "ms", "exit", "procs", "CPU u/s ms", "sleep ms", "syscalls", "file R/W", "net", "command"],
                   [[t["id"], t["phase"], t["start_s"], t["dur_ms"], t["exit_code"], t["processes"],
                     f"{t['cpu_user_ms']}/{t['cpu_sys_ms']}", t["sleep_ms"], t["syscalls"],
                     f"{fmt_bytes(t['file_read'])}/{fmt_bytes(t['file_write'])}",
                     fmt_bytes(t["net_tx"] + t["net_rx"]) if (t["net_tx"] or t["net_rx"]) else "",
                     (t["command"] or t["label"])[:140]] for t in s["tool_calls"][:400]], num={0, 2, 3, 5, 7, 8}))
    o.append("<h2>CPU and blocking by role</h2><p class='mut'>Summed over all threads of each process.</p>")
    o.append(table(["role", "procs", "user ms", "kernel ms", "run-queue ms", "sleep ms", "disk wait ms", "syscalls", "errors"],
                   [[r, st["processes"], round(st["user_ns"] / 1e6, 1), round(st["sys_ns"] / 1e6, 1),
                     round(st["runq_ns"] / 1e6, 1), round(st["sleep_ns"] / 1e6, 1), round(st["io_ns"] / 1e6, 1),
                     st["syscalls"], st["sys_errs"]] for r, st in sorted(s["roles"].items())], num={1, 2, 3, 4, 5, 6, 7, 8}))
    o.append("<h2>System calls</h2>")
    for role, d in s["syscalls"].items():
        o.append(f"<p><b>{e(role)}</b>: {d['total']} calls, {d['distinct']} distinct · " +
                 " · ".join(f"{e(g)} {v['count']}" for g, v in sorted(d["groups"].items(), key=lambda kv: -kv[1]["count"]))
                 + "</p>")
        o.append(table(["syscall", "group", "count", "total ms", "avg µs", "max ms", "errors"],
                       [[x["name"], x["group"], x["count"], x["total_ms"], x["avg_us"], x["max_ms"], x["errs"]]
                        for x in d["top"][:12]], num={2, 3, 4, 5, 6}))
    o.append("<h2>Network</h2>")
    o.append(table(["category", "connections", "exchanges", "sent", "received"],
                   [[k, v["connections"], v["exchanges"], fmt_bytes(v["tx"]), fmt_bytes(v["rx"])]
                    for k, v in sorted(s["network"]["by_category"].items())], num={1, 2}))
    o.append(table(["endpoint", "category", "owner", "TCP hs ms", "TLS hs ms", "ALPN", "life s", "exch", "sent", "recv", "retx"],
                   [[x["name"], x["category"], x["owner_role"], x["tcp_handshake_ms"], x["tls_handshake_ms"],
                     ",".join(x["alpn"]), x["life_s"], x["exchanges"], fmt_bytes(x["tx"]), fmt_bytes(x["rx"]), x["retrans"]]
                    for x in s["network"]["connections"][:120]], num={3, 4, 6, 7, 10}))
    f = s["files"]
    o.append(f"<h2>Files</h2><p>{f['distinct_paths']} distinct paths opened, {f['failed_opens']} failed opens "
             "(often module/config lookups).</p>")
    o.append(table(["role", "opens by area"], [[r, ", ".join(f"{k} {v}" for k, v in d.items())]
                                              for r, d in f["opens_by_role_and_area"].items()]))
    o.append("<h2>Paper-comparable metrics</h2>")
    o.append(table(["metric", "value"], [[k, v] for k, v in s["paper_metrics"].items()]))
    if s.get("agent_log"):
        o.append("<h2>Cross-check with the agent's own log</h2><pre>" + e(json.dumps(s["agent_log"], indent=1)) + "</pre>")
    tr = s["tracer"]
    o.append(f"<h2>Tracer</h2><p class='mut'>{tr['events']} events, {tr['ringbuf_dropped']} dropped; eBPF "
             f"{tr.get('bpf_runs')} program runs, average {tr.get('bpf_avg_ns')} ns, "
             f"{tr.get('bpf_cpu_pct_of_run')} % of one CPU. Warnings: {e(tr['warnings'])}</p>")
    o.append("<details><summary>Process tree</summary><pre>" + e("\n".join(s["process_tree"])) + "</pre></details>")
    o.append("</body></html>")
    return "".join(o)


def table(head, rows, num=()):
    o = ["<table><thead><tr>"]
    for i, h in enumerate(head):
        o.append(f"<th class='{'n' if i in num else ''}'>{e(h)}</th>")
    o.append("</tr></thead><tbody>")
    for r in rows:
        o.append("<tr>" + "".join(f"<td class='{'n' if i in num else ''}'>{e('' if v is None else v)}</td>"
                                  for i, v in enumerate(r)) + "</tr>")
    o.append("</tbody></table>")
    return "".join(o)
