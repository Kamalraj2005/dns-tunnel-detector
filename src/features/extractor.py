"""
Comprehensive Feature Extraction Engine for DNS Queries.
Combines Lexical, Structural, and Entropy Metrics into standard feature dictionaries
ready for Rule Assessment, ML Inference, and Training.
"""

from .entropy import calculate_shannon_entropy, calculate_normalized_entropy, analyze_character_distribution
from .lexical import parse_domain_structure, normalize_record_type

# Canonical list of feature names used for Machine Learning models
ML_FEATURE_NAMES = [
    "fqdn_len",
    "subdomain_len",
    "subdomain_entropy",
    "fqdn_entropy",
    "max_label_len",
    "avg_label_len",
    "label_count",
    "digit_ratio",
    "hex_ratio",
    "vowel_ratio",
    "consonant_ratio",
    "longest_consonant_run",
    "base64_ratio",
    "unique_char_ratio",
    "is_txt_record",
    "is_null_record",
    "is_cname_record",
    "is_a_record"
]

def extract_features_from_query(query_name: str, record_type: str = "A", timestamp: float = 0.0, client_ip: str = "127.0.0.1") -> dict:
    """
    Extracts all detection features for a single DNS query.
    Returns:
        dict containing both metadata (domain names, IP) and numeric feature vector.
    """
    struct = parse_domain_structure(query_name)
    subdomain = struct["subdomain"]
    
    # Entropy metrics
    subdomain_entropy = calculate_shannon_entropy(subdomain) if subdomain else 0.0
    fqdn_entropy = calculate_shannon_entropy(struct["fqdn"])
    
    # Character distribution of subdomain (where exfiltrated payload sits)
    # If subdomain is empty, fall back to registered domain for distribution
    target_text = subdomain if subdomain else struct["apex_domain"]
    char_dist = analyze_character_distribution(target_text)
    
    rtype = normalize_record_type(record_type)
    
    features = {
        # Metadata fields
        "timestamp": timestamp,
        "client_ip": client_ip,
        "fqdn": struct["fqdn"],
        "subdomain": subdomain,
        "apex_domain": struct["apex_domain"],
        "tld": struct["tld"],
        "record_type": rtype,
        
        # Numeric ML features
        "fqdn_len": struct["fqdn_len"],
        "subdomain_len": struct["subdomain_len"],
        "subdomain_entropy": subdomain_entropy,
        "fqdn_entropy": fqdn_entropy,
        "max_label_len": struct["max_label_len"],
        "avg_label_len": struct["avg_label_len"],
        "label_count": struct["label_count"],
        "digit_ratio": char_dist["digit_ratio"],
        "hex_ratio": char_dist["hex_ratio"],
        "vowel_ratio": char_dist["vowel_ratio"],
        "consonant_ratio": char_dist["consonant_ratio"],
        "longest_consonant_run": char_dist["longest_consonant_run"],
        "base64_ratio": char_dist["base64_ratio"],
        "unique_char_ratio": char_dist["unique_char_ratio"],
        "is_txt_record": 1 if rtype == "TXT" else 0,
        "is_null_record": 1 if rtype in ("NULL", "TYPE_10") else 0,
        "is_cname_record": 1 if rtype == "CNAME" else 0,
        "is_a_record": 1 if rtype in ("A", "AAAA") else 0,
    }
    
    return features

def get_ml_feature_vector(features: dict) -> list:
    """
    Extracts ordered list of floats matching ML_FEATURE_NAMES for classifier input.
    """
    return [float(features.get(feat, 0.0)) for feat in ML_FEATURE_NAMES]
