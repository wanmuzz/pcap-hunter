import statistics
from collections import defaultdict
import pyshark

def extract_connection_flows(pcap_path: str):
    """
    Streams TCP and TLS SYN/handshake frames to record timestamps
    per destination conversation flow.
    """
    # Only capture initial handshake packets or outbound HTTP/TLS requests
    bpf = "tcp.flags.syn == 1 && tcp.flags.ack == 0 || http.request"
    cap = pyshark.FileCapture(pcap_path, display_filter=bpf, keep_packets=False)

    flows = defaultdict(list)
    for pkt in cap:
        try:
            ts = float(pkt.sniff_timestamp)
            src = pkt.ip.src
            dst = pkt.ip.dst
            port = pkt[pkt.transport_layer].dstport

            flow_key = (src, dst, port)
            flows[flow_key].append(ts)
        except AttributeError:
            continue

    cap.close()
    return flows

def detect_beaconing(flows: dict, min_count: int = 5, max_cv: float = 0.40):
    """
    Calculates intervals (delta-t) and Coefficient of Variation (CV).
    Flags flows with consistent interval timing (low jitter).
    """
    beacons = []

    for (src, dst, port), timestamps in flows.items():
        if len(timestamps) < min_count:
            continue

        timestamps.sort()
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]

        # Filter out simultaneous bursts (< 0.1s apart) to measure connection cycles
        meaningful_intervals = [dt for dt in intervals if dt > 0.1]
        if len(meaningful_intervals) < min_count:
            continue

        mean_interval = statistics.mean(meaningful_intervals)
        stdev_interval = statistics.stdev(meaningful_intervals) if len(meaningful_intervals) > 1 else 0.0

        if mean_interval > 0:
            cv = stdev_interval / mean_interval
        else:
            cv = 1.0

        # Low CV means predictable periodic callbacks
        if cv <= max_cv:
            beacons.append({
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": port,
                "total_callbacks": len(meaningful_intervals) + 1,
                "interval_mean": round(mean_interval, 2),
                "interval_stdev": round(stdev_interval, 2),
                "cv": round(cv, 3),
                "mitre_id": "T1071.001",
                "technique": "C2 Automated Periodic Beaconing"
            })

    return beacons
