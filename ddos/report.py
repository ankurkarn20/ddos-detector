"""HTML report: the traffic timeline with detections, incidents, and the evaluation."""
import base64
import io
from datetime import datetime

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from ddos.detect import incidents  # noqa: E402

COLOURS = {"surge": "#f5c451", "syn_flood": "#ff6b6b", "udp_flood": "#c77dff",
           "http_flood": "#ff9f43"}
NAMES = {"surge": "Traffic surge (not an attack signature)", "syn_flood": "SYN flood",
         "udp_flood": "UDP flood", "http_flood": "HTTP flood"}
CSS = """body{margin:0;background:#0b1020;color:#d7def0;font:14px/1.5 system-ui,Segoe UI,sans-serif}
main{max-width:1180px;margin:0 auto;padding:28px 24px}h1{font-size:24px;margin:0}
h2{font-size:16px;margin:26px 0 10px;color:#9fb0d6}.sub{color:#7d8bb0;margin:4px 0 20px}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.kpi{background:#121a33;border:1px solid #1f2a4d;border-radius:10px;padding:14px}
.kpi b{display:block;font-size:26px;color:#fff}.kpi span{color:#7d8bb0;font-size:12px}
table{width:100%;border-collapse:collapse;background:#121a33}
th,td{padding:8px 10px;border-bottom:1px solid #1f2a4d;text-align:left;font-size:13px}
th{color:#7d8bb0;background:#0f1730}img{width:100%;border-radius:10px;border:1px solid #1f2a4d}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px}"""


def _chart(w) -> str:
    fig, (a, b) = plt.subplots(2, 1, figsize=(11, 5.6), sharex=True, facecolor="#121a33",
                               gridspec_kw={"height_ratios": [2, 1.2]})
    for ax in (a, b):
        ax.set_facecolor("#121a33")
        ax.tick_params(colors="#7d8bb0")
        for side in ax.spines.values():
            side.set_color("#2a375f")
    a.plot(w["sec"], w["pkts"], color="#5b8cff", lw=1.2)
    a.set_ylabel("packets / s", color="#7d8bb0")
    for kind, colour in COLOURS.items():
        hit = w[w["verdict"] == kind]
        a.scatter(hit["sec"], hit["pkts"], s=12, color=colour, label=NAMES[kind], zorder=3)
    a.legend(facecolor="#121a33", edgecolor="#2a375f", labelcolor="#d7def0", fontsize=8,
             loc="upper left")
    a.set_title("Traffic and detections", color="#d7def0", loc="left", fontsize=11)
    for f, colour, label in (("syn_share", "#ff6b6b", "bare-SYN share"),
                             ("udp_share", "#c77dff", "UDP share"),
                             ("pkts_per_src", "#ff9f43", "packets per source (÷10)")):
        b.plot(w["sec"], w[f] / (10 if f == "pkts_per_src" else 1), color=colour, lw=1,
               label=label)
    b.set_xlabel("seconds", color="#7d8bb0")
    b.legend(facecolor="#121a33", edgecolor="#2a375f", labelcolor="#d7def0", fontsize=8,
             loc="upper left")
    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=110)
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode()


def render(w, packets: int, results: dict[str, dict]) -> str:
    inc = incidents(w)
    attacks = [i for i in inc if i.kind != "surge"]
    main = results["standard"]
    kpis = [("Packets analysed", f"{packets:,}"), ("Attacks detected", len(attacks)),
            ("Precision / recall", f"{main['detector']['precision']:.0%} / "
                                   f"{main['detector']['recall']:.0%}"),
            ("False-alarm seconds", f"{main['detector']['false_alarm_seconds']} vs "
                                    f"{main['threshold']['false_alarm_seconds']} (threshold)")]
    rows = "".join(
        f'<tr><td><span class="dot" style="background:{COLOURS[i.kind]}"></span>{NAMES[i.kind]}'
        f"</td><td>{i.start}s</td><td>{i.end - i.start + 1}s</td><td>{i.peak_pps:,}</td>"
        f"<td>{i.sources:,}</td><td>{i.top_share:.1%}</td></tr>" for i in inc)
    ev = "".join(
        f"<tr><td>{name}</td><td>{r['detector']['precision']:.0%} / {r['detector']['recall']:.0%}"
        f"</td><td>{r['detector']['false_alarm_seconds']}</td><td>{r['threshold']['precision']:.0%}"
        f" / {r['threshold']['recall']:.0%}</td><td>{r['threshold']['false_alarm_seconds']}</td></tr>"
        for name, r in results.items())
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>DDoS Detector</title>
<style>{CSS}</style></head><body><main><h1>DDoS Detection &middot; Traffic Analysis</h1>
<p class="sub">Generated {datetime.now():%d %b %Y, %H:%M} &middot; one-second windows, adaptive
robust baselines, attack signatures on top of volume</p>
<div class="kpis">{''.join(f'<div class="kpi"><b>{v}</b><span>{k}</span></div>' for k, v in kpis)}</div>
<h2>Timeline</h2><img src="data:image/png;base64,{_chart(w)}">
<h2>Incidents</h2><table><tr><th>Type</th><th>Start</th><th>Duration</th><th>Peak packets/s</th>
<th>Sources</th><th>Busiest source</th></tr>{rows}</table>
<h2>Evaluation (per second, against the simulation's ground truth)</h2>
<table><tr><th>Scenario</th><th>Detector precision / recall</th><th>False-alarm s</th>
<th>Rate threshold precision / recall</th><th>False-alarm s</th></tr>{ev}</table>
<p class="sub">The 60-second flash crowd is legitimate traffic: the rate threshold calls it an
attack, the detector reports it as a surge. In the mimicry scenario (an HTTP flood from 3,000
person-like bots) the detector also reports only a surge: at the packet level such a flood
is indistinguishable from a flash crowd.</p></main></body></html>"""
