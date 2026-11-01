"""
Heuristic and Rule-Based Detection Engine for DNS Tunneling.
Provides instantaneous signature and statistical thresholding with explainability.
"""

class RuleEvaluator:
    """
    Evaluates DNS queries against expert cyber-defense heuristics.
    """
    
    # Whitelisted legitimate apex domains with high entropy CDNs/security tokens
    LEGITIMATE_HIGH_ENTROPY_WHITELIST = {
        "akamaiedge.net",
        "cloudfront.net",
        "fastly.net",
        "akadns.net",
        "azureedge.net"
    }

    def __init__(self, entropy_threshold: float = 3.85, max_label_threshold: int = 42, subdomain_len_threshold: int = 45):
        self.entropy_threshold = entropy_threshold
        self.max_label_threshold = max_label_threshold
        self.subdomain_len_threshold = subdomain_len_threshold

    def evaluate(self, features: dict) -> dict:
        """
        Runs all rules on extracted query features.
        Returns triggered rules, combined heuristic score (0-100), and verdict.
        """
        triggered_rules = []
        total_heuristic_score = 0
        
        apex = features.get("apex_domain", "").lower()
        is_whitelisted = any(apex.endswith(wl) for wl in self.LEGITIMATE_HIGH_ENTROPY_WHITELIST)

        subdomain = features.get("subdomain", "")
        sub_len = features.get("subdomain_len", 0)
        sub_entropy = features.get("subdomain_entropy", 0.0)
        max_label = features.get("max_label_len", 0)
        label_count = features.get("label_count", 0)
        record_type = features.get("record_type", "A")
        hex_ratio = features.get("hex_ratio", 0.0)
        vowel_ratio = features.get("vowel_ratio", 0.0)
        consonant_run = features.get("longest_consonant_run", 0)
        
        # Rule 1: High Shannon Entropy in Subdomain
        if sub_len >= 16 and sub_entropy >= self.entropy_threshold and not is_whitelisted:
            weight = 35 if sub_entropy >= 4.2 else 25
            triggered_rules.append({
                "rule_id": "DNS_TUNNEL_001_HIGH_ENTROPY",
                "name": "Abnormal Subdomain Entropy",
                "severity": "HIGH" if sub_entropy < 4.2 else "CRITICAL",
                "weight": weight,
                "detail": f"Subdomain exhibits Shannon entropy of {sub_entropy:.2f} (Threshold: {self.entropy_threshold}), indicative of encrypted or compressed payload."
            })
            total_heuristic_score += weight

        # Rule 2: Oversized Subdomain or Label (Bandwidth packing)
        if (sub_len >= self.subdomain_len_threshold or max_label >= self.max_label_threshold) and not is_whitelisted:
            weight = 25
            triggered_rules.append({
                "rule_id": "DNS_TUNNEL_002_OVERSIZED_LABEL",
                "name": "Oversized Subdomain Payload",
                "severity": "HIGH",
                "weight": weight,
                "detail": f"Subdomain length ({sub_len} chars) or maximum label length ({max_label} chars) exceeds standard DNS naming limits."
            })
            total_heuristic_score += weight

        # Rule 3: Anomalous Record Type with Large Data Payload (TXT, NULL, CNAME)
        if record_type in ("TXT", "NULL", "TYPE_10") and sub_len >= 20:
            weight = 25
            triggered_rules.append({
                "rule_id": "DNS_TUNNEL_003_COVERT_RECORD_TYPE",
                "name": "Suspicious Exfiltration Record Type",
                "severity": "HIGH",
                "weight": weight,
                "detail": f"High-capacity record type '{record_type}' requested with non-standard payload length ({sub_len} chars)."
            })
            total_heuristic_score += weight

        # Rule 4: Hexadecimal or Base32/Base64 High Density
        if sub_len >= 20 and (hex_ratio >= 0.85 or features.get("digit_ratio", 0) > 0.40):
            weight = 20
            triggered_rules.append({
                "rule_id": "DNS_TUNNEL_004_HEX_ENCODING",
                "name": "High Hexadecimal / Numerical Density",
                "severity": "MEDIUM",
                "weight": weight,
                "detail": f"{int(hex_ratio * 100)}% of subdomain consists of hexadecimal characters, typical of data exfiltration encoders."
            })
            total_heuristic_score += weight

        # Rule 5: Non-Human Pronounceability (Consonant Run / Low Vowel Ratio)
        if sub_len >= 20 and vowel_ratio < 0.10 and consonant_run >= 7:
            weight = 20
            triggered_rules.append({
                "rule_id": "DNS_TUNNEL_005_LOW_VOWEL_RUN",
                "name": "Consonant Clustering / Unpronounceable Sequence",
                "severity": "MEDIUM",
                "weight": weight,
                "detail": f"Consecutive consonant sequence of {consonant_run} characters with vowel ratio of {vowel_ratio:.2f}, violating standard lexical language distribution."
            })
            total_heuristic_score += weight

        # Rule 6: Deep Multi-Tier Subdomain Hierarchy
        if label_count >= 4 and sub_entropy >= 3.6:
            weight = 15
            triggered_rules.append({
                "rule_id": "DNS_TUNNEL_006_DEEP_HIERARCHY",
                "name": "Multi-Segment Tunneling Structure",
                "severity": "LOW",
                "weight": weight,
                "detail": f"Subdomain contains {label_count} nested segments with elevated entropy, common in chunked data tunneling."
            })
            total_heuristic_score += weight

        # Normalize heuristic score to 100 max
        score = min(100, total_heuristic_score)
        
        verdict = "BENIGN"
        if score >= 70:
            verdict = "MALICIOUS_TUNNEL"
        elif score >= 40:
            verdict = "SUSPICIOUS"
            
        return {
            "heuristic_score": score,
            "verdict": verdict,
            "triggered_rules": triggered_rules,
            "rule_count": len(triggered_rules),
            "is_whitelisted": is_whitelisted
        }
