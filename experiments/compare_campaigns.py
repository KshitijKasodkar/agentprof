#!/usr/bin/env python3
"""Compare campaigns (e.g. two agents on the same tasks) in one self-contained HTML page.

    python3 experiments/compare_campaigns.py \
        experiments/results/baseline_flashlite_wsl experiments/results/gemini_cli_flashlite_wsl \
        -o experiments/results/comparison.html

Reads each campaign's results.csv (written by run_matrix.py), groups runs by agent and task,
and reports means with min-max ranges. Nothing is re-measured: it only summarises.
"""
import argparse
import csv
import html
import os
import statistics as st
from collections import defaultdict

COLORS = ["#3b6fd8", "#d9822b", "#3f8f6b", "#8a63c9"]
CSS = """:root{--bg:#fbfaf7;--fg:#1d1d1b;--mut:#6b6a66;--line:#dedcd5;--card:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecebe7;--mut:#a3a29c;--line:#383733;--card:#1f1f1d}}
body{font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--fg);
padding:24px;max-width:1100px;margin:auto}h1{font-size:22px;margin:0 0 4px}
h2{font-size:16px;margin:30px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}.mut{color:var(--mut)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin:14px 0}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.kpi b{display:block;font-size:19px;font-variant-numeric:tabular-nums}.kpi span{color:var(--mut);font-size:12px}
table{border-collapse:collapse;width:100%;font-size:13px;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600}td.n,th.n{text-align:right}
.legend span{display:inline-flex;align-items:center;margin-right:16px;font-size:12px}
.legend i{width:11px;height:11px;border-radius:2px;margin-right:5px;display:inline-block}
svg text{fill:var(--fg);font:11px system-ui,sans-serif}svg .mut{fill:var(--mut)}
ul{padding-left:20px}li{margin:4px 0}"""


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def load(dirs):
    rows = []
    for d in dirs:
        p = os.path.join(d, "results.csv")
        for r in csv.DictReader(open(p)):
            r["_campaign"] = os.path.basename(os.path.normpath(d))
            rows.append(r)
    return rows


def mean(xs):
    xs = [x for x in xs if x is not None]
    return st.mean(xs) if xs else None


def fmt(x, nd=1):
    return "" if x is None else f"{x:,.{nd}f}"


def ratio(a, b):
    return "" if not a or not b else f"{b / a:.1f}×"


def chart(tasks, agents, by, w=1060):
    """Grouped horizontal bars: mean run time per task, whisker = min-max."""
    vals = [x for t in tasks for a in agents for x in by[a][t]["run_s"]]
    vmax = max(vals) * 1.05
    left, right, bh, gap = 130, 70, 13, 12
    rowh = bh * len(agents) + gap
    h = 26 + rowh * len(tasks)
    sx = lambda v: left + (w - left - right) * v / vmax
    out = [f'<svg viewBox="0 0 {w} {h}" width="100%" role="img" aria-label="run time per task">']
    step = 20 if vmax > 100 else 10 if vmax > 40 else 5
    for v in range(0, int(vmax) + 1, step):
        out.append(f'<line x1="{sx(v):.1f}" y1="16" x2="{sx(v):.1f}" y2="{h}" stroke="var(--line)"/>'
                   f'<text x="{sx(v):.1f}" y="11" text-anchor="middle" class="mut">{v}s</text>')
    for i, t in enumerate(tasks):
        y0 = 22 + i * rowh
        out.append(f'<text x="4" y="{y0 + rowh / 2:.1f}">{html.escape(t)}</text>')
        for j, a in enumerate(agents):
            xs = by[a][t]["run_s"]
            if not xs:
                continue
            m, lo, hi = st.mean(xs), min(xs), max(xs)
            y = y0 + j * bh
            c = COLORS[j % len(COLORS)]
            out.append(f'<rect x="{left}" y="{y}" width="{sx(m) - left:.1f}" height="{bh - 3}" fill="{c}" rx="2">'
                       f'<title>{a} {t}: mean {m:.1f} s, range {lo:.1f}-{hi:.1f} s, n={len(xs)}</title></rect>'
                       f'<line x1="{sx(lo):.1f}" y1="{y + (bh - 3) / 2:.1f}" x2="{sx(hi):.1f}" y2="{y + (bh - 3) / 2:.1f}" stroke="var(--fg)" stroke-width="1"/>'
                       f'<line x1="{sx(lo):.1f}" y1="{y + 2}" x2="{sx(lo):.1f}" y2="{y + bh - 5}" stroke="var(--fg)"/>'
                       f'<line x1="{sx(hi):.1f}" y1="{y + 2}" x2="{sx(hi):.1f}" y2="{y + bh - 5}" stroke="var(--fg)"/>'
                       f'<text x="{sx(hi) + 5:.1f}" y="{y + bh - 4}" class="mut">{m:.1f}</text>')
    out.append("</svg>")
    return "".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("campaigns", nargs="+", help="campaign result folders (each with results.csv)")
    ap.add_argument("-o", "--out", default="comparison.html")
    a = ap.parse_args()

    rows = load(a.campaigns)
    agents = list(dict.fromkeys(r["agent"] for r in rows))
    tasks = sorted({r["task"] for r in rows})
    models = sorted({r["model"] for r in rows})
    metrics = ["run_s", "llm_calls", "ttfb_ms_median", "req_bytes_first", "req_bytes_last", "agent_cpu_user_ms",
               "agent_cpu_sys_ms", "agent_syscalls", "tool_syscalls", "processes", "connections", "neither_pct",
               "startup_s", "llm_share_pct", "tool_share_pct"]
    by = {ag: {t: defaultdict(list) for t in tasks} for ag in agents}
    allm = {ag: defaultdict(list) for ag in agents}
    passed = defaultdict(lambda: [0, 0])
    for r in rows:
        ag, t = r["agent"], r["task"]
        passed[ag][1] += 1
        passed[ag][0] += r.get("outcome") == "PASS"
        for m in metrics:
            v = num(r.get(m))
            if v is not None:
                by[ag][t][m].append(v)
                allm[ag][m].append(v)

    A, B = agents[0], agents[-1]
    faster = defaultdict(int)
    for t in tasks:
        ma, mb = mean(by[A][t]["run_s"]), mean(by[B][t]["run_s"])
        if ma and mb:
            faster[A if ma < mb else B] += 1

    h = [f"<!doctype html><html><head><meta charset='utf-8'><title>agentprof: agent comparison</title>"
         f"<meta name='viewport' content='width=device-width,initial-scale=1'><style>{CSS}</style></head><body>",
         "<h1>agentprof: same model, different agents</h1>",
         f"<div class='mut'>Model: {html.escape(', '.join(models))} · {len(tasks)} tasks · "
         + " · ".join(f"{html.escape(ag)}: {passed[ag][0]}/{passed[ag][1]} PASS" for ag in agents)
         + "</div><div class='kpis'>"]
    kp = [("median run time", "run_s", 1, " s"), ("mean request size (first → last)", None, 0, ""),
          ("mean agent CPU (user)", "agent_cpu_user_ms", 0, " ms"), ("mean agent syscalls", "agent_syscalls", 0, ""),
          ("mean connections", "connections", 1, "")]
    for label, m, nd, unit in kp:
        parts = []
        for ag in agents:
            if m == "run_s":
                v = fmt(st.median(allm[ag][m]), nd) + unit
            elif m is None:
                v = f"{mean(allm[ag]['req_bytes_first']) / 1024:.1f} → {mean(allm[ag]['req_bytes_last']) / 1024:.1f} KB"
            else:
                v = fmt(mean(allm[ag][m]), nd) + unit
            parts.append(f"{html.escape(ag)}: {v}")
        h.append(f"<div class='kpi'><span>{label}</span>" + "".join(f"<b>{p}</b>" for p in parts) + "</div>")
    h.append(f"<div class='kpi'><span>faster on (by mean run time)</span>"
             + "".join(f"<b>{html.escape(ag)}: {faster[ag]}/{len(tasks)} tasks</b>" for ag in agents) + "</div></div>")

    h.append("<h2>Run time per task</h2><div class='legend'>"
             + "".join(f"<span><i style='background:{COLORS[j]}'></i>{html.escape(ag)}</span>" for j, ag in enumerate(agents))
             + "<span class='mut'>bar = mean, whisker = min–max over repetitions</span></div>")
    h.append(chart(tasks, agents, by))

    h.append("<h2>Per task</h2><table><thead><tr><th>task</th>")
    for ag in agents:
        h.append(f"<th class='n'>{html.escape(ag)}<br>time s (min–max)</th><th class='n'>LLM calls</th><th class='n'>TTFB ms</th>")
    h.append(f"<th class='n'>time ratio<br>{html.escape(B)} / {html.escape(A)}</th></tr></thead><tbody>")
    for t in tasks:
        h.append(f"<tr><td>{html.escape(t)}</td>")
        for ag in agents:
            xs = by[ag][t]["run_s"]
            h.append(f"<td class='n'>{fmt(mean(xs))} ({fmt(min(xs))}–{fmt(max(xs))})</td>"
                     f"<td class='n'>{fmt(mean(by[ag][t]['llm_calls']))}</td><td class='n'>{fmt(mean(by[ag][t]['ttfb_ms_median']), 0)}</td>")
        h.append(f"<td class='n'>{ratio(mean(by[A][t]['run_s']), mean(by[B][t]['run_s']))}</td></tr>")
    h.append("</tbody></table>")

    h.append(f"<h2>What the agent itself costs (mean over all runs)</h2><table><thead><tr><th>measure</th>"
             + "".join(f"<th class='n'>{html.escape(ag)}</th>" for ag in agents)
             + f"<th class='n'>{html.escape(B)} / {html.escape(A)}</th></tr></thead><tbody>")
    cost = [("first request size", "req_bytes_first", 1 / 1024, " KB", 1), ("last request size", "req_bytes_last", 1 / 1024, " KB", 1),
            ("LLM calls per task", "llm_calls", 1, "", 1), ("median TTFB per call", "ttfb_ms_median", 1, " ms", 0),
            ("agent CPU user", "agent_cpu_user_ms", 1, " ms", 0), ("agent CPU kernel", "agent_cpu_sys_ms", 1, " ms", 0),
            ("agent syscalls", "agent_syscalls", 1, "", 0), ("processes", "processes", 1, "", 1),
            ("network connections", "connections", 1, "", 1), ("start-up before first LLM call", "startup_s", 1, " s", 2),
            ("agent's own time (\"neither\")", "neither_pct", 1, " %", 1), ("LLM share of time", "llm_share_pct", 1, " %", 1),
            ("tool share of time", "tool_share_pct", 1, " %", 1)]
    for label, m, k, unit, nd in cost:
        va, vb = mean(allm[A][m]), mean(allm[B][m])
        cells = "".join(f"<td class='n'>{fmt(None if mean(allm[ag][m]) is None else mean(allm[ag][m]) * k, nd)}{unit}</td>" for ag in agents)
        h.append(f"<tr><td>{label}</td>{cells}<td class='n'>{ratio(va, vb)}</td></tr>")
    h.append("</tbody></table>")
    h.append("<p class='mut'>All values measured by agentprof (eBPF) from outside the agent; nothing in either agent was modified. "
             "Runs of different campaigns may have been made at different times, and the free API tier's latency varies.</p>"
             "</body></html>")
    with open(a.out, "w") as f:
        f.write("".join(h))
    print(f"-> {a.out}")


if __name__ == "__main__":
    main()
