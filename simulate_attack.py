"""
Live DNS Tunneling Attack Injector.
Sends realistic simulated tunneling queries (Iodine exfiltration and dnscat2 C2)
over live UDP socket on port 53 to test real-time detection sensors.
"""

import sys
import time
import socket
import argparse

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from src.generator.traffic_simulator import DNSTrafficSimulator

def build_dns_query_packet(qname: str, qtype: str = "A") -> bytes:
    """
    Constructs a valid binary DNS wire-format query without external library dependencies.
    """
    type_codes = {"A": 1, "NS": 2, "CNAME": 5, "NULL": 10, "MX": 15, "TXT": 16, "AAAA": 28}
    qtype_int = type_codes.get(qtype.upper(), 1)

    # 12-byte DNS Header
    # ID: 0x1337, Flags: 0x0100 (Standard query, Recursion Desired), QDCOUNT: 1, ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: 0
    header = b"\x13\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"

    # Encode QNAME labels
    question = b""
    for part in qname.strip('.').split('.'):
        encoded_part = part.encode('utf-8', errors='ignore')
        question += bytes([len(encoded_part)]) + encoded_part
    question += b"\x00"  # Null terminator

    # QTYPE and QCLASS (IN = 0x0001)
    question += qtype_int.to_bytes(2, byteorder='big') + b"\x00\x01"

    return header + question

def inject_attack(target_ip: str = "127.0.0.1", port: int = 53, attack_type: str = "iodine", count: int = 25, delay: float = 0.15):
    print("=================================================================")
    print("[*] LIVE DNS TUNNELING ATTACK INJECTOR")
    print(f"[*] Target Resolver : {target_ip}:{port}")
    print(f"[*] Attack Profile  : {attack_type.upper()}")
    print(f"[*] Query Count     : {count}")
    print("=" * 65 + "\n")

    if attack_type == "iodine":
        queries = DNSTrafficSimulator.generate_tunneling_attack(
            attack_type="iodine_exfiltration",
            client_ip="192.168.1.189",
            c2_domain="darknet-tunnel.org",
            record_count=count
        )
    elif attack_type == "dnscat2":
        queries = DNSTrafficSimulator.generate_tunneling_attack(
            attack_type="dnscat2_c2",
            client_ip="192.168.1.210",
            c2_domain="stealth-c2-operator.net",
            record_count=count
        )
    else:
        queries = DNSTrafficSimulator.generate_benign_traffic(count=count)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)

    sent = 0
    print(f"[*] Firing {len(queries)} DNS packets into the network...")
    for idx, q in enumerate(queries, 1):
        qname = q["query_name"]
        qtype = q["qtype"]
        pkt_bytes = build_dns_query_packet(qname, qtype)

        try:
            sock.sendto(pkt_bytes, (target_ip, port))
            sent += 1
            print(f"  [{idx:02d}/{count:02d}] Sent {qtype:<4} -> {qname[:55]}")
        except Exception as e:
            print(f"  [!] Failed to send packet: {e}")

        time.sleep(delay)

    sock.close()
    print(f"\n[+] Successfully injected {sent} packets! Check your live sniffer or dashboard to verify alert generation.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Inject simulated DNS tunneling traffic over UDP port 53")
    parser.add_argument("--target", type=str, default="127.0.0.1", help="Target DNS resolver / listener IP (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=53, help="Port (default: 53)")
    parser.add_argument("--type", type=str, choices=["iodine", "dnscat2", "benign"], default="iodine", help="Attack profile")
    parser.add_argument("--count", type=int, default=25, help="Number of queries to fire")
    parser.add_argument("--delay", type=float, default=0.15, help="Delay between queries in seconds (default: 0.15)")
    args = parser.parse_args()

    inject_attack(args.target, args.port, args.type, args.count, args.delay)
