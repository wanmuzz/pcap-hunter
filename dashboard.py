import os
import html
import tempfile
import datetime
import statistics

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from core.parser import stream_capture_metadata
from detectors.dns_entropy import inspect_dns_queries
from detectors.beaconing import extract_connection_flows, detect_beaconing
from intel.threatfox import query_threatfox

st.set_page_config(page_title="NetSentinel", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
#MainMenu, footer, .stDeployButton {visibility: hidden;}
.block-container {padding-top: 4rem; max-width: 1300px;}
.title {font-size: 2.6rem; font-weight: 800; color: #fff; line-height: 1.1;}
.title span {color: #22d3ee;}
.sub {color: #94a3b8; font-size: 1rem; margin: 4px 0 22px 0;}
.banner {border-radius: 12px; padding: 18px 24px; font-size: 1.15rem; font-weight: 600; margin-bottom: 22px;}
.red {background: #7f1d1d; border: 1px solid #ef4444; color: #fff;}
.amber {background: #78350f; border: 1px solid #f59e0b; color: #fff;}
.green {background: #14532d; border: 1px solid #22c55e; color: #fff;}
.blue {background: #0c4a6e; border: 1px solid #38bdf8; color: #fff;}
.card {background: #111827; border: 1px solid #1f2937; border-radius: 12px; padding: 16px 10px; text-align: center;}
.num {font-size: 2.6rem; font-weight: 800; color: #fff; line-height: 1.2;}
.lbl {color: #94a3b8; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1px;}
.h {font-size: 1.35rem; font-weight: 700; color: #f1f5f9; margin: 34px 0 8px 0;}
.help {background: #0f172a; border-left: 4px solid #22d3ee; border-radius: 8px; padding: 14px 18px; color: #cbd5e1; line-height: 1.6;}
.incident {background: #111827; border: 1px solid #ef4444; border-radius: 12px; padding: 20px 24px; margin-bottom: 10px;}
.incident .row {display: flex; flex-wrap: wrap; gap: 34px;}
.incident .l {color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px;}
.incident .v {color: #fff; font-size: 1.25rem; font-weight: 700; font-family: monospace;}
.tag {background: #ef4444; color: #fff; border-radius: 6px; padding: 2px 10px; font-weight: 700; font-size: 0.85rem;}
</style>
""", unsafe_allow_html=True)

RED, BLUE, GREY, GREEN, PURPLE = "#ef4444", "#22d3ee", "#64748b", "#22c55e", "#a78bfa"

DOMAIN_KEYS = ("domain", "query", "qname", "name", "dns_qry_name", "dns.qry.name")
SNI_KEYS = ("sni", "server_name", "tls_sni")


def pick(rec, keys):
    for k in keys:
        if k in rec and rec[k]:
            return str(rec[k])
    return ""


@st.cache_data(show_spinner="Reading the capture with tshark...")
def ingest(file_bytes, suffix):
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(file_bytes)
        path = tmp.name
    try:
        dns_records, tls_records = stream_capture_metadata(path)
        flows = extract_connection_flows(path)
    finally:
        os.remove(path)
    return dns_records, tls_records, flows


@st.cache_data(ttl=3600, show_spinner=False)
def intel(ip):
    try:
        res = query_threatfox(ip)
        if res.get("match"):
            return f"{res.get('malware_name', 'Known threat')} ({res.get('confidence', 0)}%)"
        return "Not listed in ThreatFox"
    except Exception:
        return "Lookup unavailable"


def flow_table(flows, flagged):
    rows = []
    for (src, dst, port), stamps in flows.items():
        ts = sorted(stamps)
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        gaps = [g for g in gaps if g >= 0.1]
        if len(gaps) < 2 or statistics.mean(gaps) <= 0:
            continue
        mean = statistics.mean(gaps)
        rows.append({"src": src, "dst": dst, "port": str(port), "calls": len(ts),
                     "interval": mean, "cv": statistics.stdev(gaps) / mean,
                     "bad": (src, dst, str(port)) in flagged})
    return pd.DataFrame(rows, columns=["src", "dst", "port", "calls", "interval", "cv", "bad"])


def base_layout(fig, title, height=380):
    fig.update_layout(template="plotly_dark", title=title, height=height,
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      margin=dict(l=10, r=10, t=50, b=10))
    return fig


def scatter(df, max_cv):
    fig = go.Figure()
    xmax = max(df["interval"].max() if not df.empty else 10, 10) * 1.1
    ymax = min(max(df["cv"].max() if not df.empty else 1, max_cv * 2.5), 3.0)
    fig.add_shape(type="rect", x0=2.0, x1=xmax, y0=0, y1=max_cv,
                  fillcolor="rgba(239,68,68,0.18)", line=dict(color=RED, dash="dash", width=1))
    fig.add_annotation(x=xmax, y=max_cv / 2, text="DANGER ZONE", xanchor="right",
                       showarrow=False, font=dict(color="#fca5a5", size=12))
    for bad, name, color, size in [(False, "Normal traffic", GREY, 10), (True, "C2 beacon", RED, 18)]:
        part = df[df["bad"] == bad]
        if part.empty:
            continue
        fig.add_trace(go.Scatter(
            x=part["interval"], y=part["cv"], mode="markers", name=name,
            marker=dict(size=size, color=color, opacity=0.85, line=dict(color="#fff", width=1 if bad else 0)),
            customdata=part[["dst", "port", "calls"]].values,
            hovertemplate="<b>%{customdata[0]}:%{customdata[1]}</b><br>Callbacks: %{customdata[2]}"
                          "<br>Interval: %{x:.1f}s<br>Jitter: %{y:.3f}<extra></extra>"))
        if bad:
            for _, r in part.iterrows():
                fig.add_annotation(x=r["interval"], y=r["cv"], text=f"{r['dst']}:{r['port']}",
                                   ax=50, ay=-50, arrowcolor="#fca5a5", font=dict(color="#fff", size=11),
                                   bgcolor="#7f1d1d")
    fig.update_xaxes(title="Time between callbacks (seconds)", range=[0, xmax], gridcolor="#1f2937")
    fig.update_yaxes(title="Jitter (lower = more robotic)", range=[0, ymax], gridcolor="#1f2937")
    fig.update_layout(legend=dict(orientation="h", y=-0.22))
    return base_layout(fig, "Which connections look like malware timers?")


def donut(dns_n, tls_n, flow_n, threats):
    vals = [dns_n, tls_n, flow_n, threats]
    fig = go.Figure(go.Pie(labels=["DNS queries", "TLS handshakes", "Connections", "Threats"],
                           values=vals, hole=0.6, sort=False, pull=[0, 0, 0, 0.1],
                           marker=dict(colors=[BLUE, PURPLE, GREEN, RED], line=dict(color="#0b1220", width=2)),
                           textinfo="label+value"))
    fig.add_annotation(text=f"<b>{sum(vals)}</b><br>items", showarrow=False, font=dict(size=22, color="#fff"))
    fig.update_layout(showlegend=False)
    return base_layout(fig, "What was analysed")


def wireshark(ip):
    return f"ip.addr == {ip} && (tcp.flags.syn == 1 || http.request || tls.handshake.type == 1)"


def report(name, counts, beacons, dns_hits, ent_thr, cv_thr):
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = ["# NetSentinel Incident Report", "",
           f"- Capture: `{name}`", f"- Generated: {now}",
           f"- Thresholds: entropy >= {ent_thr}, jitter (CV) <= {cv_thr}", "",
           "## Summary", "",
           f"- DNS queries: {counts[0]}", f"- TLS handshakes: {counts[1]}", f"- Connections tracked: {counts[2]}",
           f"- C2 beacons found: {len(beacons)}", f"- High-entropy DNS found: {len(dns_hits)}", "",
           "## C2 Beaconing (MITRE T1071.001)", ""]
    if not beacons:
        out += ["No beaconing found.", ""]
    for b in beacons:
        out += [f"### {b['src_ip']} -> {b['dst_ip']}:{b['dst_port']}", "",
                f"- Callbacks: {b['total_callbacks']}",
                f"- Mean interval: {b['interval_mean']:.2f}s",
                f"- Jitter (CV): {b['cv']:.3f}",
                f"- Threat intel: {b['intel']}", "",
                "Wireshark filter:", "", "```", wireshark(b["dst_ip"]), "```", ""]
    out += ["## DNS Tunneling (MITRE T1071.004)", ""]
    if not dns_hits:
        out += ["No high-entropy subdomains found.", ""]
    else:
        out += ["| Host | Domain | Entropy |", "|---|---|---|"]
        out += [f"| {h['src']} | {h['domain']} | {h['entropy']:.3f} |" for h in dns_hits[:50]]
    out += ["", "_Generated by NetSentinel (PCAP-Hunter)._"]
    return "\n".join(out)


# ---------------- Sidebar ----------------
with st.sidebar:
    st.markdown("### 🛡️ Controls")
    uploaded = st.file_uploader("Upload a PCAP file", type=["pcap", "pcapng"])
    ent_thr = st.slider("DNS entropy threshold", 3.0, 5.0, 3.8, 0.05)
    cv_thr = st.slider("Max jitter (CV)", 0.05, 0.80, 0.35, 0.01)
    min_count = st.slider("Min callbacks", 3, 20, 4, 1)
    use_intel = st.checkbox("Check ThreatFox", value=True)

# ---------------- Header ----------------
st.markdown('<div class="title">🛡️ Net<span>Sentinel</span></div>', unsafe_allow_html=True)
st.markdown('<div class="sub">Upload a packet capture. Find malware that phones home.</div>', unsafe_allow_html=True)

if uploaded is None:
    st.markdown('<div class="banner blue">📂 Upload a .pcap or .pcapng file in the sidebar to start.</div>',
                unsafe_allow_html=True)

# ---------------- Plain-English explainers ----------------
c1, c2 = st.columns(2)
c1.markdown('<div class="help"><b>🤖 Beaconing (jitter)</b><br>Malware checks in with its boss on a timer. '
            'Timer = very regular gaps. We measure that with <code>CV = stdev / mean</code>. '
            'A low CV (0.35 or less) means robot, not human.</div>', unsafe_allow_html=True)
c2.markdown('<div class="help" style="border-left-color:#a78bfa"><b>🔤 DNS tunneling (entropy)</b><br>'
            'Stolen data hidden inside domain names looks random. '
            'Shannon entropy <code>H(X)</code> measures randomness. A long label with H(X) of 3.8 or more is suspicious.</div>',
            unsafe_allow_html=True)

if uploaded is None:
    st.stop()

# ---------------- Analysis ----------------
dns_records, tls_records, flows = ingest(uploaded.getvalue(), os.path.splitext(uploaded.name)[1] or ".pcap")
dns_hits = inspect_dns_queries(dns_records, entropy_threshold=ent_thr, length_threshold=20)

beacons = [b for b in detect_beaconing(flows, min_count=min_count, max_cv=cv_thr) if b["interval_mean"] >= 2.0]
beacons.sort(key=lambda b: b["total_callbacks"], reverse=True)
for b in beacons:
    b["intel"] = intel(str(b["dst_ip"])) if use_intel else "Check disabled"

flagged = {(b["src_ip"], b["dst_ip"], str(b["dst_port"])) for b in beacons}
df = flow_table(flows, flagged)
dns_n, tls_n, flow_n = len(dns_records), len(tls_records), len(flows)
threats = len(beacons) + len(dns_hits)

# ---------------- Status banner ----------------
if beacons:
    hosts = ", ".join(sorted({str(b["src_ip"]) for b in beacons}))
    st.markdown(f'<div class="banner red">🚨 THREAT FOUND: {len(beacons)} C2 beacon(s) from {html.escape(hosts)}</div>',
                unsafe_allow_html=True)
elif dns_hits:
    st.markdown(f'<div class="banner amber">⚠️ SUSPICIOUS: {len(dns_hits)} high-entropy DNS name(s)</div>',
                unsafe_allow_html=True)
else:
    st.markdown('<div class="banner green">✅ ALL CLEAR: no beaconing or DNS tunneling found</div>',
                unsafe_allow_html=True)

# ---------------- Numbers ----------------
k = st.columns(4)
for col, (label, val, color) in zip(k, [("DNS queries", dns_n, BLUE), ("TLS handshakes", tls_n, PURPLE),
                                         ("Connections", flow_n, GREEN),
                                         ("Threats", threats, RED if threats else GREEN)]):
    col.markdown(f'<div class="card" style="border-top:3px solid {color}"><div class="num">{val:,}</div>'
                 f'<div class="lbl">{label}</div></div>', unsafe_allow_html=True)

# ---------------- Charts ----------------
st.markdown('<div class="h">📊 The big picture</div>', unsafe_allow_html=True)
left, right = st.columns([3, 2])
left.plotly_chart(scatter(df, cv_thr), use_container_width=True)
right.plotly_chart(donut(dns_n, tls_n, flow_n, threats), use_container_width=True)

# ---------------- C2 table ----------------
st.markdown('<div class="h">🚨 C2 beaconing <span class="tag">T1071.001</span></div>', unsafe_allow_html=True)
if beacons:
    st.dataframe(
        pd.DataFrame([{"Infected host": b["src_ip"], "C2 server": f"{b['dst_ip']}:{b['dst_port']}",
                       "Callbacks": b["total_callbacks"], "Interval (s)": b["interval_mean"],
                       "Jitter (CV)": b["cv"], "Threat intel": b["intel"]} for b in beacons]),
        hide_index=True, use_container_width=True,
        column_config={
            "Interval (s)": st.column_config.NumberColumn(format="%.2f"),
            "Jitter (CV)": st.column_config.ProgressColumn(min_value=0.0, max_value=1.0, format="%.3f"),
        })
else:
    st.success("No beaconing found.")

# ---------------- DNS table ----------------
st.markdown('<div class="h">📡 DNS tunneling <span class="tag" style="background:#22d3ee;color:#0b1220">T1071.004</span></div>',
            unsafe_allow_html=True)
if dns_hits:
    d = pd.DataFrame(dns_hits).sort_values("entropy", ascending=False)[["src", "domain", "subdomain", "entropy"]]
    st.dataframe(d, hide_index=True, use_container_width=True, column_config={
        "src": "Host", "domain": "Query", "subdomain": "Suspicious label",
        "entropy": st.column_config.ProgressColumn("Entropy", min_value=0.0, max_value=5.0, format="%.3f")})
else:
    st.success("No high-entropy subdomains found.")

# ---------------- Investigation ----------------
st.markdown('<div class="h">🔎 Investigate in Wireshark</div>', unsafe_allow_html=True)
if beacons:
    b = beacons[0]
    e = html.escape
    st.markdown(f"""
    <div class="incident"><div class="row">
      <div><div class="l">Infected host</div><div class="v">{e(str(b['src_ip']))}</div></div>
      <div><div class="l">C2 server</div><div class="v">{e(str(b['dst_ip']))}:{e(str(b['dst_port']))}</div></div>
      <div><div class="l">Callbacks</div><div class="v">{b['total_callbacks']}</div></div>
      <div><div class="l">Every</div><div class="v">{b['interval_mean']:.1f}s</div></div>
      <div><div class="l">Jitter</div><div class="v">{b['cv']:.3f}</div></div>
      <div><div class="l">MITRE</div><div class="v"><span class="tag">{e(str(b['mitre_id']))}</span></div></div>
    </div></div>""", unsafe_allow_html=True)
    st.caption("Paste this filter into Wireshark:")
    st.code(wireshark(str(b["dst_ip"])), language="text")
else:
    st.info("Nothing to investigate for this capture.")

st.download_button("⬇️ Download incident report (.md)",
                   data=report(uploaded.name, (dns_n, tls_n, flow_n), beacons, dns_hits, ent_thr, cv_thr),
                   file_name="netsentinel_report.md", mime="text/markdown", type="primary")
