"""
CLI PCAP Analyzer for DNS Tunneling Incidents.
Can be executed directly on any network capture file to produce a terminal SOC report.
"""

import sys
import os
import argparse

# Ensure standard output can handle utf-8 on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from src.capture.pcap_parser import PCAPParser
from src.detection.incident_engine import IncidentDetectionEngine

def analyze_file(pcap_path: str, entropy_threshold: float = 3.85):
    print(f"\n=======================================================")
    print(f"[*] DNS TUNNELING INCIDENT DETECTOR - PCAP ANALYSIS")
    print(f"[*] Target File: {pcap_path}")
    print(f"=======================================================\n")

    if not os.path.exists(pcap_path):
        print(f"[!] Error: File '{pcap_path}' not found.")
        return

    print("[1/3] Parsing DNS Packets...")
    queries = PCAPParser.parse_pcap(pcap_path)
    print(f"      Extracted {len(queries)} DNS query records.")

    if not queries:
        print("[!] No DNS queries found in PCAP.")
        return

    print("[2/3] Executing Heuristic Rules & Machine Learning Inference...")
    engine = IncidentDetectionEngine(entropy_threshold=entropy_threshold)
    for q in queries:
        engine.process_query(
            query_name=q["query_name"],
            record_type=q["qtype"],
            timestamp=q["timestamp"],
            client_ip=q["client_ip"],
            response_size=q.get("packet_size", 0)
        )

    print("[3/3] Correlating Security Incidents & Decoding Forensics...\n")
    incidents = engine.correlate_incidents()

    if not incidents:
        print("  [+] No malicious DNS tunneling activity detected. All traffic is classified as BENIGN.")
        return

    print(f"  [!] DETECTED {len(incidents)} SECURITY INCIDENT(S)!\n")
    
    for idx, inc in enumerate(incidents, 1):
        color_tag = "CRITICAL" if inc["severity"] == "CRITICAL" else inc["severity"]
        print(f"  -------------------------------------------------------------")
        print(f"  INCIDENT #{idx}: {inc['incident_id']} [{color_tag}] (Score: {inc['threat_score']}/100)")
        print(f"  -------------------------------------------------------------")
        print(f"  Source (Client IP)   : {inc['client_ip']}")
        print(f"  Target Apex Domain   : {inc['apex_domain']}")
        print(f"  Query Statistics     : {inc['total_queries']} total queries ({inc['suspicious_queries']} suspicious)")
        print(f"  Unique Subdomains    : {inc['unique_subdomains']} (Cache-Busting)")
        print(f"  Average Entropy      : {inc['avg_entropy']} (Max: {inc['max_entropy']})")
        print(f"  Average Subdomain Len: {inc['avg_subdomain_len']} characters")
        print(f"  Estimated Exfil Size : {inc['total_payload_bytes']} bytes (~{round(inc['total_payload_bytes']/1024, 2)} KB)")
        print(f"  Time Window          : {inc['start_time']} -> {inc['end_time']} ({inc['duration_seconds']}s)")
        
        print("\n  Triggered Detection Rules:")
        for r in inc["rules_triggered"]:
            print(f"    - {r}")
            
        print("\n  MITRE ATT&CK Mappings:")
        for m in inc["mitre_attacks"]:
            print(f"    - [{m['technique_id']}] {m['name']} ({m['tactic']})")

        print("\n  Forensics & Payload Reconstruction:")
        if inc["reconstructed_payload"]["is_decodable"]:
            print(f"    [+] Decoded Stream: {inc['reconstructed_payload']['preview']}")
        else:
            print(f"    [-] {inc['reconstructed_payload']['preview']}")
        print("")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze PCAP file for DNS Tunneling Incidents")
    parser.add_argument("pcap", nargs="?", default="data/raw_pcaps/mixed_enterprise_traffic.pcap", help="Path to .pcap file")
    parser.add_argument("--entropy", type=float, default=3.85, help="Subdomain entropy threshold (default: 3.85)")
    args = parser.parse_args()

    analyze_file(args.pcap, args.entropy)
