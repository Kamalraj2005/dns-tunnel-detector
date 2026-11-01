"""
Real-Time Terminal Monitor for DNS Tunneling Surveillance.
Captures live DNS packets on UDP port 53, evaluates threats instantly,
and displays alerts in the terminal console.
"""

import os
import sys
import time
import argparse

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.detection.incident_engine import IncidentDetectionEngine
from src.capture.live_sniffer import LiveDNSSniffer

def format_alert(record):
    q_threat = record["query_threat_score"]
    status_tag = "[BENIGN]"
    if q_threat >= 70:
        status_tag = "[CRITICAL ALERT]"
    elif q_threat >= 45:
        status_tag = "[HIGH ALERT]"
    elif q_threat >= 30:
        status_tag = "[SUSPICIOUS]"

    qname = record["fqdn"]
    if len(qname) > 60:
        qname = qname[:57] + "..."

    return (
        f"{status_tag:<16} | "
        f"Score: {q_threat:>5.1f} | "
        f"IP: {record['client_ip']:<15} | "
        f"Type: {record['record_type']:<4} | "
        f"Entropy: {record['subdomain_entropy']:>4.2f} | "
        f"Query: {qname}"
    )

def main():
    parser = argparse.ArgumentParser(description="Live Real-Time DNS Tunneling Monitor")
    parser.add_argument("--list-interfaces", action="store_true", help="List all available network adapters and exit")
    parser.add_argument("--iface", type=str, default=None, help="Name or description of interface to sniff on")
    parser.add_argument("--entropy", type=float, default=3.85, help="Subdomain entropy threshold (default: 3.85)")
    args = parser.parse_args()

    interfaces = LiveDNSSniffer.get_available_interfaces()

    if args.list_interfaces:
        print("\nAvailable Network Interfaces:")
        for idx, iface in enumerate(interfaces, 1):
            print(f"  [{idx}] {iface['description']} (Name: {iface['name']})")
        return

    print("=" * 70)
    print("[*] REAL-TIME DNS TUNNELING SURVEILLANCE SENSOR")
    print("=" * 70)

    selected_iface = args.iface
    if not selected_iface:
        default_iface = LiveDNSSniffer.get_default_interface()
        print(f"[*] Detected Default Active Interface: {default_iface}")
        selected_iface = default_iface

    engine = IncidentDetectionEngine(entropy_threshold=args.entropy)
    sniffer = LiveDNSSniffer(engine, interface=selected_iface)

    def packet_alert_callback(record):
        # Print all suspicious queries, or print periodic heartbeat
        if record["is_suspicious"]:
            print(format_alert(record))
            # If rules triggered, print them
            for r in record["rule_results"]["triggered_rules"]:
                print(f"      |-- [!] Triggered: {r['name']} - {r['detail']}")
        else:
            # Print benign queries concisely
            print(format_alert(record))

    sniffer.add_event_listener(packet_alert_callback)

    print(f"[*] Initiating packet capture on '{selected_iface}' (Filter: udp port 53)...")
    print("[*] Press Ctrl+C at any time to stop sniffing and generate Incident Report.\n")

    try:
        sniffer.start_sniffing()
        while sniffer.is_running:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n\n[!] Stopping live capture sensor...")
        sniffer.stop_sniffing()
    except Exception as e:
        print(f"\n[!] Live Sniffer Error: {e}")
        return

    print(f"\n[*] Total Packets Captured: {sniffer.captured_count}")
    print(f"[*] Suspicious Lookups Flagged: {sniffer.suspicious_count}")

    print("\n" + "=" * 70)
    print("CORRELATED SECURITY INCIDENTS REPORT")
    print("=" * 70)
    incidents = engine.correlate_incidents()
    if not incidents:
        print("[+] No persistent DNS tunneling sessions detected. Traffic is clean.")
    else:
        for idx, inc in enumerate(incidents, 1):
            print(f"\nINCIDENT #{idx}: {inc['incident_id']} [{inc['severity']}] - Threat Score: {inc['threat_score']}/100")
            print(f"  Client IP        : {inc['client_ip']}")
            print(f"  Target Apex      : {inc['apex_domain']}")
            print(f"  Queries Captured : {inc['total_queries']} ({inc['suspicious_queries']} suspicious)")
            print(f"  Estimated Exfil  : {inc['total_payload_bytes']} bytes")
            print(f"  Triggered Rules  : {', '.join(inc['rules_triggered'])}")
            if inc["reconstructed_payload"]["is_decodable"]:
                print(f"  Decoded Payload  : {inc['reconstructed_payload']['preview']}")

if __name__ == "__main__":
    main()
