"""
Live Network DNS Sniffer for Real-Time Threat Surveillance.
Captures live DNS packets (UDP port 53) from active Wi-Fi / Ethernet adapters
and feeds them to the Incident Detection Engine in real-time.
"""

import sys
import threading
import time
from scapy.all import conf, sniff, get_if_list, IP, IPv6, UDP, AsyncSniffer
from scapy.layers.dns import DNS, DNSQR

class LiveDNSSniffer:
    """
    Real-time DNS packet sniffer and incident streaming engine.
    """

    def __init__(self, incident_engine, interface=None, bpf_filter="udp port 53"):
        self.engine = incident_engine
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.is_running = False
        self.sniffer_thread = None
        self.async_sniffer = None
        self.captured_count = 0
        self.suspicious_count = 0
        self.callbacks = []

    @staticmethod
    def get_available_interfaces():
        """
        Returns a list of available network interfaces with human-readable descriptions.
        """
        interfaces = []
        try:
            for iface_name, iface_obj in conf.ifaces.items():
                ip_addr = getattr(iface_obj, 'ip', '0.0.0.0')
                desc = getattr(iface_obj, 'description', iface_name)
                # Only include interfaces with actual names
                interfaces.append({
                    "name": iface_name,
                    "description": f"{desc} ({ip_addr})",
                    "ip": ip_addr
                })
        except Exception:
            for iface in get_if_list():
                interfaces.append({
                    "name": iface,
                    "description": iface,
                    "ip": "N/A"
                })
        return interfaces

    @staticmethod
    def get_default_interface():
        """
        Identifies active non-loopback network interface (Wi-Fi or Ethernet).
        """
        try:
            # Check default route interface
            def_iface = conf.iface
            if def_iface:
                return def_iface.name if hasattr(def_iface, 'name') else str(def_iface)
        except Exception:
            pass
        return None

    def add_event_listener(self, callback):
        """
        Registers callback function called whenever a new query or incident occurs.
        """
        self.callbacks.append(callback)

    def _packet_handler(self, pkt):
        """
        Processes each raw packet intercepted from the wire.
        """
        if not pkt.haslayer(DNS):
            return

        dns = pkt[DNS]
        # Inspect query requests (qr == 0)
        if dns.qr == 0 and dns.qdcount > 0:
            try:
                q = dns.qd[0] if hasattr(dns.qd, '__getitem__') else dns.qd
            except Exception:
                q = dns.qd

            if q is None:
                return

            try:
                qname = q.qname.decode('utf-8', errors='ignore').rstrip('.')
            except Exception:
                qname = str(q.qname).rstrip('.')

            qtype = q.qtype

            # IP extraction
            src_ip = "127.0.0.1"
            dst_ip = "8.8.8.8"
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            elif pkt.haslayer(IPv6):
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst

            pkt_size = len(pkt)
            q_time = float(pkt.time) if hasattr(pkt, 'time') else time.time()

            # Process through the Incident Engine
            record = self.engine.process_query(
                query_name=qname,
                record_type=qtype,
                timestamp=q_time,
                client_ip=src_ip,
                response_size=pkt_size
            )

            self.captured_count += 1
            if record["is_suspicious"]:
                self.suspicious_count += 1

            # Notify listeners
            for cb in self.callbacks:
                try:
                    cb(record)
                except Exception:
                    pass

    def start_sniffing(self):
        """
        Starts non-blocking asynchronous packet capture.
        """
        if self.is_running:
            return

        self.is_running = True
        try:
            self.async_sniffer = AsyncSniffer(
                filter=self.bpf_filter,
                prn=self._packet_handler,
                store=False,
                iface=self.interface
            )
            self.async_sniffer.start()
        except Exception as e:
            self.is_running = False
            raise RuntimeError(
                f"Failed to start live packet sniffing ({e}).\n"
                "Note: On Windows, live packet sniffing requires Npcap (https://npcap.com/) installed with Administrator privileges."
            )

    def stop_sniffing(self):
        """
        Stops live capture gracefully.
        """
        if not self.is_running:
            return

        self.is_running = False
        if self.async_sniffer:
            try:
                self.async_sniffer.stop()
            except Exception:
                pass
