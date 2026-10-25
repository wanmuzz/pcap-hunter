import argparse
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from core.parser import stream_capture_metadata
from detectors.dns_entropy import inspect_dns_queries
from detectors.beaconing import extract_connection_flows, detect_beaconing
from intel.threatfox import query_threatfox

console = Console()

def run_triage(pcap_path: str):
    header_text = Text("PCAP-HUNTER: AUTOMATED NETWORK THREAT TRIAGE & FORENSICS", style="bold cyan")
    console.print(Panel(header_text, subtitle="SOC Detection Engine", border_style="cyan"))

    # Phase 1: Dissect Telemetry
    with console.status("[bold green]Streaming and dissecting packet frames...[/bold green]"):
        try:
            dns_records, tls_records = stream_capture_metadata(pcap_path)
            flows = extract_connection_flows(pcap_path)
        except Exception as e:
            console.print(f"[bold red][-] Failed to parse PCAP file: {e}[/bold red]")
            sys.exit(1)

    console.print(f"[+] Total Ingested: [bold]{len(dns_records)}[/bold] DNS queries, [bold]{len(tls_records)}[/bold] TLS sessions, [bold]{len(flows)}[/bold] host conversations.\n")

    # Phase 2: DNS Entropy Detection
    suspicious_dns = inspect_dns_queries(dns_records, entropy_threshold=3.8, length_threshold=20)
    
    dns_table = Table(title="[bold yellow]Threat Detection: High-Entropy DNS (Tunneling / Exfiltration)[/bold yellow]", show_header=True, header_style="bold magenta")
    dns_table.add_column("Source IP", style="dim")
    dns_table.add_column("Queried Domain / Subdomain")
    dns_table.add_column("Entropy", justify="right")
    dns_table.add_column("Threat Intel")
    dns_table.add_column("MITRE Technique")

    if suspicious_dns:
        for alert in suspicious_dns:
            intel = query_threatfox(alert["domain"])
            status = f"[red]{intel['malware_name']}[/red]" if intel["match"] else "[yellow]Unlisted / Ephemeral[/yellow]"
            dns_table.add_row(alert["src"], alert["domain"], str(alert["entropy"]), status, alert["mitre_id"])
    else:
        dns_table.add_row("N/A", "No high-entropy DNS tunneling detected", "N/A", "Clean", "None")

    console.print(dns_table)
    console.print()

    # Phase 3: C2 Beaconing Detection
    flagged_beacons = detect_beaconing(flows, min_count=4, max_cv=0.40)

    beacon_table = Table(title="[bold red]Threat Detection: C2 Periodic Beaconing (Jitter Analysis)[/bold red]", show_header=True, header_style="bold red")
    beacon_table.add_column("Compromised Source", style="dim")
    beacon_table.add_column("Target C2 Server")
    beacon_table.add_column("Callbacks", justify="right")
    beacon_table.add_column("Mean Interval", justify="right")
    beacon_table.add_column("Jitter (CV)", justify="right")
    beacon_table.add_column("Threat Intel")
    beacon_table.add_column("MITRE Technique")

    primary_suspicious_ip = None

    if flagged_beacons:
        for b in flagged_beacons:
            dst_ip = b["dst_ip"]
            # Exclude short-burst fast pipelining (interval < 2 seconds) to reduce CDN noise
            if b["interval_mean"] < 2.0:
                continue

            primary_suspicious_ip = dst_ip
            intel = query_threatfox(dst_ip)
            status = f"[red]{intel['malware_name']}[/red]" if intel["match"] else "[yellow]Unlisted / Custom C2[/yellow]"
            
            beacon_table.add_row(
                b["src_ip"],
                f"{dst_ip}:{b['dst_port']}",
                str(b["total_callbacks"]),
                f"~{b['interval_mean']}s",
                str(b["cv"]),
                status,
                b["mitre_id"]
            )
    else:
        beacon_table.add_row("N/A", "No automated periodic beaconing detected", "N/A", "N/A", "N/A", "Clean", "None")

    console.print(beacon_table)
    console.print()

    # Phase 4: Actionable Wireshark Filter for Analyst Verification
    if primary_suspicious_ip:
        filter_str = f"ip.addr == {primary_suspicious_ip} && (tcp.flags.syn == 1 || http.request || tls.handshake.type == 1)"
        console.print(Panel(
            f"[bold green]Actionable Wireshark Display Filter for Immediate Verification:[/bold green]\n\n"
            f"[bold white]{filter_str}[/bold white]\n\n"
            f"[dim]Copy and paste this into Wireshark GUI to review raw conversation payloads and handshake certificates.[/dim]",
            border_style="green",
            title="Analyst Next Steps"
        ))

def main():
    parser = argparse.ArgumentParser(description="PCAP-Hunter: Network Traffic Threat Triage")
    parser.add_argument("--pcap", required=True, help="Path to raw .pcap or .pcapng file")
    args = parser.parse_args()

    run_triage(args.pcap)

if __name__ == "__main__":
    main()
