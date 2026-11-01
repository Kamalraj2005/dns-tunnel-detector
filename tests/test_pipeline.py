"""
End-to-End Test Suite for DNS Tunneling Incident Detection.
Validates entropy calculation, feature extraction, rules, ML model, and incident correlation.
"""

import unittest
import os
import sys

# Ensure root is in path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.features.entropy import calculate_shannon_entropy, analyze_character_distribution
from src.features.lexical import parse_domain_structure
from src.features.extractor import extract_features_from_query
from src.detection.rules import RuleEvaluator
from src.detection.ml_engine import TunnelingMLClassifier
from src.detection.incident_engine import IncidentDetectionEngine
from src.capture.pcap_parser import PCAPParser

class TestDNSTunnelingDetection(unittest.TestCase):

    def test_shannon_entropy(self):
        # Human natural domain: low entropy (< 3.0)
        low_ent = calculate_shannon_entropy("google")
        self.assertLess(low_ent, 3.0)

        # High randomness / base64 string: high entropy (> 4.0)
        high_ent = calculate_shannon_entropy("a8f3b9c2d1e0f4a7b9c1e3f5a7d9b2c4")
        self.assertGreater(high_ent, 3.5)

    def test_lexical_structure(self):
        struct = parse_domain_structure("b64-chunk1.data.attacker-c2.co.uk")
        self.assertEqual(struct["apex_domain"], "attacker-c2.co.uk")
        self.assertEqual(struct["subdomain"], "b64-chunk1.data")
        self.assertEqual(struct["label_count"], 2)

    def test_rule_evaluator_catches_tunnel(self):
        evaluator = RuleEvaluator(entropy_threshold=3.85)
        # Malicious high entropy + oversized query
        q_feats = extract_features_from_query(
            "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f.tunnel.evil.com", 
            record_type="TXT"
        )
        res = evaluator.evaluate(q_feats)
        self.assertIn(res["verdict"], ["MALICIOUS_TUNNEL", "SUSPICIOUS"])
        self.assertGreater(res["heuristic_score"], 50)

    def test_rule_evaluator_passes_benign(self):
        evaluator = RuleEvaluator()
        q_feats = extract_features_from_query("www.wikipedia.org", record_type="A")
        res = evaluator.evaluate(q_feats)
        self.assertEqual(res["verdict"], "BENIGN")
        self.assertEqual(res["heuristic_score"], 0)

    def test_ml_classifier(self):
        clf = TunnelingMLClassifier()
        # Benign lookup
        b_feats = extract_features_from_query("mail.google.com", record_type="A")
        b_pred = clf.predict(b_feats)
        self.assertFalse(b_pred["is_anomaly"])
        self.assertLess(b_pred["ml_score"], 40.0)

        # Attack lookup
        a_feats = extract_features_from_query("01a748c08920bc49102837190283a001.c2.darknet-tunnel.org", record_type="TXT")
        a_pred = clf.predict(a_feats)
        self.assertTrue(a_pred["is_anomaly"])
        self.assertGreater(a_pred["ml_score"], 60.0)

    def test_pcap_parsing_and_incident_correlation(self):
        pcap_path = os.path.join(BASE_DIR, "data", "raw_pcaps", "mixed_enterprise_traffic.pcap")
        self.assertTrue(os.path.exists(pcap_path), "Sample PCAP missing")
        
        queries = PCAPParser.parse_pcap(pcap_path)
        self.assertGreater(len(queries), 50)

        engine = IncidentDetectionEngine()
        for q in queries:
            engine.process_query(
                query_name=q["query_name"],
                record_type=q["qtype"],
                timestamp=q["timestamp"],
                client_ip=q["client_ip"]
            )
        
        incidents = engine.correlate_incidents()
        self.assertGreaterEqual(len(incidents), 1)
        self.assertIn(incidents[0]["severity"], ["CRITICAL", "HIGH"])

    def test_live_sniffer_interface_discovery(self):
        from src.capture.live_sniffer import LiveDNSSniffer
        ifaces = LiveDNSSniffer.get_available_interfaces()
        self.assertIsInstance(ifaces, list)
        self.assertGreater(len(ifaces), 0)
        # Should detect the WiFi adapter or loopback
        descriptions = [i["description"] for i in ifaces]
        self.assertTrue(any("WiFi" in d or "Ethernet" in d or "Loopback" in d for d in descriptions))

    def test_mfa_authentication_workflow(self):
        from src.auth.mfa_manager import MFAManager
        # 1. Primary factor test
        valid_auth = MFAManager.authenticate_credentials("analyst@soc.corp", "CyberDefense@2026")
        self.assertTrue(valid_auth["success"])
        self.assertEqual(valid_auth["role"], "SOC Tier-2 Analyst")

        invalid_auth = MFAManager.authenticate_credentials("analyst@soc.corp", "WrongPass")
        self.assertFalse(invalid_auth["success"])

        # 2. Secondary factor (TOTP) test
        secret = valid_auth["mfa_secret"]
        active_otp = MFAManager.get_current_live_otp_for_demo(secret)
        self.assertEqual(len(active_otp), 6)
        self.assertTrue(MFAManager.verify_totp_token(secret, active_otp))
        self.assertFalse(MFAManager.verify_totp_token(secret, "000000" if active_otp != "000000" else "111111"))

        # 3. QR code generation test
        uri = MFAManager.get_totp_uri("analyst@soc.corp", secret)
        qr_b64 = MFAManager.generate_qr_code_base64(uri)
        self.assertTrue(qr_b64.startswith("data:image/png;base64,"))

if __name__ == "__main__":
    unittest.main()
