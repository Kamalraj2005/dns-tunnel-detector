"""
Network Packet Capture & PCAP/PCAPNG File Parser.
Reads standard .pcap and .pcapng files using Scapy and extracts DNS layer queries.
"""

import os
import tempfile
from scapy.all import rdpcap, IP, IPv6, UDP, TCP
from scapy.layers.dns import DNS, DNSQR
from scapy.utils import PcapNgReader

class PCAPParser:
    """
    Extracts DNS queries from offline network capture files (.pcap and .pcapng).
    """

    @classmethod
    def parse_pcap_bytes(cls, raw_bytes: bytes) -> list:
        """
        Parses raw bytes from uploaded PCAP/PCAPNG file.
        """
        if not raw_bytes or len(raw_bytes) < 24:
            return []

        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
                tmp.write(raw_bytes)
                tmp_path = tmp.name

            return cls.parse_pcap(tmp_path)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

    @classmethod
    def parse_pcap(cls, pcap_path: str) -> list:
        """
        Parses a PCAP or PCAPNG file and returns a list of DNS query dictionaries.
        """
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        packets = []
        try:
            packets = rdpcap(pcap_path)
        except Exception as e_rd:
            # Fallback to PcapNgReader if standard rdpcap fails on PCAPNG format
            try:
                with PcapNgReader(pcap_path) as reader:
                    packets = [p for p in reader]
            except Exception as e_ng:
                raise ValueError(f"Unable to parse capture file. Error: {e_rd} | PcapNG fallback: {e_ng}")

        dns_records = []
        seen_queries = set()  # Prevent duplicate counting of request + response pairs

        for pkt in packets:
            if not pkt.haslayer(DNS):
                continue

            dns = pkt[DNS]
            # Check for question records in either Query (qr=0) or Response (qr=1)
            if dns.qdcount > 0 and dns.qd is not None:
                # Handle Scapy PacketListField or single record
                questions = dns.qd if isinstance(dns.qd, list) else [dns.qd]
                
                # In responses, dns.an might be present, but dns.qd contains the original query
                is_response = getattr(dns, 'qr', 0) == 1
                dns_id = getattr(dns, 'id', 0)

                # Extract IP addresses
                src_ip = "127.0.0.1"
                dst_ip = "8.8.8.8"
                if pkt.haslayer(IP):
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                elif pkt.haslayer(IPv6):
                    src_ip = pkt[IPv6].src
                    dst_ip = pkt[IPv6].dst

                # If it's a response packet, the client is dst_ip, and server is src_ip
                client_ip = dst_ip if is_response else src_ip
                server_ip = src_ip if is_response else dst_ip

                timestamp = float(pkt.time) if hasattr(pkt, 'time') else 0.0
                pkt_size = len(pkt)

                for q in questions:
                    if q is None or not hasattr(q, 'qname'):
                        continue

                    # Decode query domain name
                    try:
                        if isinstance(q.qname, bytes):
                            qname = q.qname.decode('utf-8', errors='replace').rstrip('.')
                        else:
                            qname = str(q.qname).rstrip('.')
                    except Exception:
                        qname = str(q.qname).rstrip('.')

                    # Strip stringified byte prefixes like b'domain.com'
                    if qname.startswith("b'") and qname.endswith("'"):
                        qname = qname[2:-1].rstrip('.')
                    elif qname.startswith('b"') and qname.endswith('"'):
                        qname = qname[2:-1].rstrip('.')

                    if not qname:
                        continue

                    qtype = getattr(q, 'qtype', 1)

                    # Deduplication key: If we already recorded the query request, 
                    # skip recording the identical query echoed in the response packet
                    dedup_key = (dns_id, qname, qtype)
                    if dedup_key in seen_queries and is_response:
                        continue
                    seen_queries.add(dedup_key)

                    dns_records.append({
                        "timestamp": timestamp,
                        "client_ip": client_ip,
                        "server_ip": server_ip,
                        "query_name": qname,
                        "qtype": qtype,
                        "packet_size": pkt_size,
                        "is_response": is_response
                    })

        return dns_records
