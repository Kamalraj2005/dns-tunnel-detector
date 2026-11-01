"""
Incident Correlation, Forensics, and Threat Scoring Engine.
Correlates individual DNS queries into session-level Security Incidents,
calculates exfiltration volume, and attempts automated payload reconstruction.
"""

import base64
import binascii
import re
from datetime import datetime
from collections import defaultdict
from .rules import RuleEvaluator
from .ml_engine import TunnelingMLClassifier
from ..features.extractor import extract_features_from_query

class IncidentDetectionEngine:
    """
    End-to-End DNS Tunneling Incident Detection & Correlation Engine.
    Combines rule-based heuristics, machine learning inference, and behavioral aggregation.
    """
    def __init__(self, entropy_threshold: float = 3.85):
        self.rule_evaluator = RuleEvaluator(entropy_threshold=entropy_threshold)
        self.ml_classifier = TunnelingMLClassifier()
        self.raw_queries = []
        self.incidents = {}

    def process_query(self, query_name: str, record_type: str = "A", timestamp: float = None, client_ip: str = "192.168.1.100", response_size: int = 0) -> dict:
        """
        Processes a single DNS query through the full detection pipeline.
        """
        if timestamp is None:
            timestamp = datetime.now().timestamp()

        # 1. Feature Extraction
        features = extract_features_from_query(query_name, record_type=record_type, timestamp=timestamp, client_ip=client_ip)
        features["response_size"] = response_size
        
        # 2. Rule-based Evaluation
        rule_res = self.rule_evaluator.evaluate(features)
        
        # 3. ML Inference
        ml_res = self.ml_classifier.predict(features)
        
        # 4. Query-Level Composite Threat Score
        # Heuristic weight 45%, ML weight 55%
        q_threat_score = round((rule_res["heuristic_score"] * 0.45) + (ml_res["ml_score"] * 0.55), 2)
        
        is_suspicious = q_threat_score >= 40.0 or rule_res["verdict"] == "MALICIOUS_TUNNEL" or ml_res["is_anomaly"]
        
        record = {
            **features,
            "rule_results": rule_res,
            "ml_results": ml_res,
            "query_threat_score": q_threat_score,
            "is_suspicious": is_suspicious
        }
        
        self.raw_queries.append(record)
        return record

    def correlate_incidents(self, time_window_seconds: int = 300) -> list:
        """
        Groups queries by (client_ip, apex_domain) within sliding windows to form incidents.
        Returns a sorted list of Security Incidents with MITRE ATT&CK tags and forensics.
        """
        grouped = defaultdict(list)
        for q in self.raw_queries:
            # Skip empty apex domains
            if not q["apex_domain"]:
                continue
            key = (q["client_ip"], q["apex_domain"])
            grouped[key].append(q)

        incidents = []

        for (client_ip, apex_domain), queries in grouped.items():
            query_count = len(queries)
            suspicious_queries = [q for q in queries if q["is_suspicious"]]
            suspicious_count = len(suspicious_queries)

            # Only generate an incident if there are suspicious queries detected
            if suspicious_count == 0:
                continue

            timestamps = [q["timestamp"] for q in queries]
            start_time = min(timestamps)
            end_time = max(timestamps)
            duration_sec = max(1.0, end_time - start_time)
            query_rate = round(query_count / duration_sec, 2)

            # Volumetric metrics
            subdomains = [q["subdomain"] for q in queries if q["subdomain"]]
            unique_subdomains = len(set(subdomains))
            
            # Estimated payload bytes carried in subdomains
            total_payload_bytes = sum(len(sub) for sub in subdomains)
            
            avg_entropy = round(sum(q["subdomain_entropy"] for q in queries) / max(1, len(subdomains)), 2)
            max_entropy = max([q["subdomain_entropy"] for q in queries], default=0.0)
            avg_sub_len = round(sum(q["subdomain_len"] for q in queries) / max(1, len(subdomains)), 1)
            
            txt_count = sum(1 for q in queries if q["record_type"] == "TXT")
            null_count = sum(1 for q in queries if q["record_type"] in ("NULL", "TYPE_10"))
            txt_ratio = round(txt_count / query_count, 2)

            # Aggregate behavioral score (0-100)
            behavior_score = 0
            if unique_subdomains >= 5 and (unique_subdomains / query_count) > 0.70:
                behavior_score += 30  # Strong cache-busting behavior
            if query_rate >= 2.0:
                behavior_score += 25  # High frequency tunneling
            if txt_ratio > 0.40 or null_count > 0:
                behavior_score += 25  # Heavy covert record usage
            if total_payload_bytes > 500:
                behavior_score += 20  # Significant exfiltration size

            # Average query threat score
            avg_q_threat = sum(q["query_threat_score"] for q in queries) / query_count
            
            # Composite Incident Score
            composite_score = min(100, round((avg_q_threat * 0.65) + (behavior_score * 0.35), 1))

            # Severity classification
            if composite_score >= 75:
                severity = "CRITICAL"
            elif composite_score >= 55:
                severity = "HIGH"
            elif composite_score >= 35:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            # Attempt automated exfiltration payload reconstruction
            reconstructed_payload = self.reconstruct_payload(subdomains)

            # MITRE ATT&CK Mapping
            mitre_mappings = [
                {"technique_id": "T1071.004", "name": "Application Layer Protocol: DNS", "tactic": "Command and Control"},
                {"technique_id": "T1048.003", "name": "Exfiltration Over Alternative Protocol: DNS Exfiltration", "tactic": "Exfiltration"}
            ]
            if unique_subdomains > 10:
                mitre_mappings.append({"technique_id": "T1568.002", "name": "Dynamic Resolution: Domain Generation Algorithms", "tactic": "Command and Control"})

            # Collect triggered rules
            all_triggered_rules = set()
            for q in suspicious_queries:
                for r in q["rule_results"]["triggered_rules"]:
                    all_triggered_rules.add(r["name"])

            incident = {
                "incident_id": f"INC-DNS-{abs(hash((client_ip, apex_domain, start_time))) % 100000:05d}",
                "client_ip": client_ip,
                "apex_domain": apex_domain,
                "severity": severity,
                "threat_score": composite_score,
                "start_time": datetime.fromtimestamp(start_time).strftime("%Y-%m-%d %H:%M:%S"),
                "end_time": datetime.fromtimestamp(end_time).strftime("%Y-%m-%d %H:%M:%S"),
                "duration_seconds": round(duration_sec, 1),
                "total_queries": query_count,
                "suspicious_queries": suspicious_count,
                "unique_subdomains": unique_subdomains,
                "query_rate_per_sec": query_rate,
                "avg_entropy": avg_entropy,
                "max_entropy": max_entropy,
                "avg_subdomain_len": avg_sub_len,
                "total_payload_bytes": total_payload_bytes,
                "txt_query_count": txt_count,
                "rules_triggered": list(all_triggered_rules),
                "mitre_attacks": mitre_mappings,
                "reconstructed_payload": reconstructed_payload,
                "raw_queries": queries
            }
            incidents.append(incident)

        # Sort incidents by severity and threat score
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        incidents.sort(key=lambda x: (severity_order.get(x["severity"], 4), -x["threat_score"]))
        return incidents

    def reconstruct_payload(self, subdomains: list) -> dict:
        """
        Attempts to decode chunked exfiltrated strings (Hex, Base64, Base32)
        from subdomains into readable text.
        """
        decoded_candidates = []
        combined_hex = ""
        combined_b64 = ""

        for sub in subdomains:
            labels = sub.split('.')
            for lbl in labels:
                # Strip known prefixes like 'b64-', 'exfil-', 'chunk-'
                clean_lbl = re.sub(r'^(b64-|exfil-|chunk\d+-|data-|dnscat\.)', '', lbl, flags=re.IGNORECASE)
                
                # Check for Base64 pattern
                if re.match(r'^[A-Za-z0-9+/=_-]{8,}$', clean_lbl):
                    try:
                        # Normalize base64
                        padded = clean_lbl + '=' * (-len(clean_lbl) % 4)
                        raw = base64.b64decode(padded, validate=False)
                        # Keep only printable ascii to avoid charmap / terminal encoding errors
                        text = raw.decode('ascii', errors='ignore')
                        clean_text = "".join(c for c in text if c.isprintable())
                        if len(clean_text) > 3:
                            decoded_candidates.append(clean_text.strip())
                    except Exception:
                        pass
                
                # Check for Hex pattern
                if re.match(r'^[0-9a-fA-F]{8,}$', clean_lbl):
                    try:
                        raw = bytes.fromhex(clean_lbl)
                        text = raw.decode('ascii', errors='ignore')
                        clean_text = "".join(c for c in text if c.isprintable())
                        if len(clean_text) > 3:
                            decoded_candidates.append(clean_text.strip())
                    except Exception:
                        pass

        preview_text = " | ".join(decoded_candidates[:10]) if decoded_candidates else "Payload is strongly encrypted or binary compressed."
        return {
            "is_decodable": len(decoded_candidates) > 0,
            "decoded_samples": decoded_candidates[:15],
            "preview": preview_text
        }
