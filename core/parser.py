import pyshark

def stream_capture_metadata(pcap_path: str):
    """
    Parses network metadata (DNS and TLS SNI) using tshark under the hood.
    Streaming mode ensures low RAM usage even for large PCAP captures.
    """
    bpf_filter = "dns.flags.response == 0 || tls.handshake.type == 1"
    cap = pyshark.FileCapture(pcap_path, display_filter=bpf_filter, keep_packets=False)
    
    dns_records = []
    tls_sni_records = []

    for pkt in cap:
        try:
            ts = float(pkt.sniff_timestamp)
            src = pkt.ip.src
            dst = pkt.ip.dst

            # Extract DNS Query Names
            if hasattr(pkt, "dns") and hasattr(pkt.dns, "qry_name"):
                dns_records.append({
                    "timestamp": ts,
                    "src": src,
                    "dst": dst,
                    "query": pkt.dns.qry_name.lower().rstrip(".")
                })

            # Extract TLS SNI (Server Name Indication) from Client Hello
            if hasattr(pkt, "tls") and hasattr(pkt.tls, "handshake_extensions_server_name"):
                tls_sni_records.append({
                    "timestamp": ts,
                    "src": src,
                    "dst": dst,
                    "sni": pkt.tls.handshake_extensions_server_name.lower()
                })
        except AttributeError:
            continue

    cap.close()
    return dns_records, tls_sni_records
