"""
Generates sample PCAPs for testing the DNS Tunneling Incident Detection system.
"""

import os
from src.generator.traffic_simulator import DNSTrafficSimulator

def generate_samples():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_dir = os.path.join(base_dir, "data", "raw_pcaps")
    os.makedirs(pcap_dir, exist_ok=True)

    print("1. Generating Benign DNS PCAP...")
    benign_recs = DNSTrafficSimulator.generate_benign_traffic(count=60, client_ip="192.168.1.105")
    benign_pcap = os.path.join(pcap_dir, "benign_traffic.pcap")
    DNSTrafficSimulator.export_to_pcap(benign_recs, benign_pcap)
    print(f"   Saved {len(benign_recs)} packets to {benign_pcap}")

    print("2. Generating Iodine-Style Data Exfiltration PCAP...")
    attack1_recs = DNSTrafficSimulator.generate_tunneling_attack(
        attack_type="iodine_exfiltration",
        client_ip="192.168.1.189",
        c2_domain="darknet-tunnel.org",
        record_count=45
    )
    attack1_pcap = os.path.join(pcap_dir, "tunneling_iodine_exfil.pcap")
    DNSTrafficSimulator.export_to_pcap(attack1_recs, attack1_pcap)
    print(f"   Saved {len(attack1_recs)} packets to {attack1_pcap}")

    print("3. Generating DNSCat2 C2 Interactive Tunnel PCAP...")
    attack2_recs = DNSTrafficSimulator.generate_tunneling_attack(
        attack_type="dnscat2_c2",
        client_ip="192.168.1.210",
        c2_domain="stealth-c2-operator.net",
        record_count=35
    )
    attack2_pcap = os.path.join(pcap_dir, "tunneling_dnscat2_c2.pcap")
    DNSTrafficSimulator.export_to_pcap(attack2_recs, attack2_pcap)
    print(f"   Saved {len(attack2_recs)} packets to {attack2_pcap}")

    print("4. Generating Mixed Enterprise Traffic PCAP (Benign + Attacks)...")
    mixed_recs = benign_recs + attack1_recs + attack2_recs
    mixed_recs.sort(key=lambda x: x["timestamp"])
    mixed_pcap = os.path.join(pcap_dir, "mixed_enterprise_traffic.pcap")
    DNSTrafficSimulator.export_to_pcap(mixed_recs, mixed_pcap)
    print(f"   Saved {len(mixed_recs)} packets to {mixed_pcap}")

    print("\nAll sample PCAPs successfully generated!")

if __name__ == "__main__":
    generate_samples()
