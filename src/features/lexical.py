"""
DNS Lexical and Structural Analysis
Extracts structural properties, subdomain depths, label lengths, and record types.
"""

import tldextract

# Standard DNS RR Type IDs
RECORD_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    10: "NULL",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY"
}

def parse_domain_structure(fqdn: str) -> dict:
    """
    Parses FQDN into subdomain, registered domain (apex), and suffix.
    Uses tldextract to accurately handle multi-level TLDs (e.g. .co.uk, .com.au).
    """
    clean_fqdn = fqdn.strip().rstrip('.').lower()
    
    extracted = tldextract.extract(clean_fqdn)
    subdomain = extracted.subdomain
    registered_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.domain and extracted.suffix else clean_fqdn
    
    # Subdomain labels
    labels = subdomain.split('.') if subdomain else []
    labels = [lbl for lbl in labels if lbl]
    
    max_label_len = max([len(l) for l in labels], default=0)
    avg_label_len = sum([len(l) for l in labels]) / len(labels) if labels else 0.0

    return {
        "fqdn": clean_fqdn,
        "subdomain": subdomain,
        "apex_domain": registered_domain,
        "tld": extracted.suffix,
        "fqdn_len": len(clean_fqdn),
        "subdomain_len": len(subdomain),
        "label_count": len(labels),
        "max_label_len": max_label_len,
        "avg_label_len": round(avg_label_len, 2),
        "hyphen_count": subdomain.count('-'),
        "dot_count": clean_fqdn.count('.')
    }

def normalize_record_type(qtype) -> str:
    """
    Converts record type int or str to standardized string.
    """
    if isinstance(qtype, int):
        return RECORD_TYPES.get(qtype, f"TYPE_{qtype}")
    qtype_str = str(qtype).upper()
    return qtype_str
