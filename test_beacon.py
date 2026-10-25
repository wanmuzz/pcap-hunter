from detectors.beaconing import extract_connection_flows, detect_beaconing

print("[*] Extracting connection flows from PCAP...")
flows = extract_connection_flows("samples/2026-02-28-traffic-analysis-exercise.pcap")
print(f"[+] Identified {len(flows)} unique host-destination conversation flows.")

beacons = detect_beaconing(flows, min_count=4, max_cv=0.45)
print(f"[+] Flagged Beaconing Channels: {len(beacons)}")

for b in beacons:
    src = b["src_ip"]
    dst = b["dst_ip"]
    port = b["dst_port"]
    callbacks = b["total_callbacks"]
    interval = b["interval_mean"]
    cv = b["cv"]
    print(f"--> Target: {src} -> {dst}:{port} | Callbacks: {callbacks} | Interval: ~{interval}s (CV: {cv})")
