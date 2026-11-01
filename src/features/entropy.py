"""
DNS Entropy and Character Distribution Analysis
Computes Shannon Entropy, normalized entropy, and character distribution metrics
for detecting encoded/encrypted payloads hidden in DNS queries.
"""

import math
from collections import Counter
import re

VOWELS = set("aeiouAEIOU")
HEX_CHARS = set("0123456789abcdefABCDEF")
BASE64_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=-_")

def calculate_shannon_entropy(text: str) -> float:
    """
    Calculate Shannon Entropy: H(X) = -sum(P(x) * log2(P(x)))
    Higher entropy indicates random/encoded payload (Base64, Base32, Hex, encrypted).
    Normal human English domain names typically range from 2.0 to 3.2.
    Tunneling payloads usually exceed 3.8 - 4.5.
    """
    if not text:
        return 0.0
    
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def calculate_normalized_entropy(text: str) -> float:
    """
    Normalized entropy: H(X) / log2(N) where N is unique character alphabet count.
    Ranges between 0.0 and 1.0.
    """
    if not text or len(text) <= 1:
        return 0.0
    unique_chars = len(set(text))
    if unique_chars <= 1:
        return 0.0
    shannon = calculate_shannon_entropy(text)
    max_entropy = math.log2(unique_chars)
    return round(shannon / max_entropy, 4) if max_entropy > 0 else 0.0

def analyze_character_distribution(text: str) -> dict:
    """
    Analyzes lexical composition of a DNS query label or full subdomain.
    """
    if not text:
        return {
            "digit_ratio": 0.0,
            "hex_ratio": 0.0,
            "vowel_ratio": 0.0,
            "consonant_ratio": 0.0,
            "longest_consonant_run": 0,
            "base64_ratio": 0.0,
            "unique_char_ratio": 0.0
        }
        
    total_len = len(text)
    digits = sum(1 for c in text if c.isdigit())
    hex_chars = sum(1 for c in text if c in HEX_CHARS)
    letters = [c for c in text if c.isalpha()]
    total_letters = len(letters)
    
    vowels = sum(1 for c in letters if c in VOWELS)
    consonants = total_letters - vowels
    b64_chars = sum(1 for c in text if c in BASE64_CHARS)
    
    # Calculate longest consecutive consonant sequence
    consonant_runs = re.findall(r'[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]+', text)
    max_consonant_run = max([len(r) for r in consonant_runs], default=0)

    return {
        "digit_ratio": round(digits / total_len, 4),
        "hex_ratio": round(hex_chars / total_len, 4),
        "vowel_ratio": round(vowels / total_letters, 4) if total_letters > 0 else 0.0,
        "consonant_ratio": round(consonants / total_letters, 4) if total_letters > 0 else 0.0,
        "longest_consonant_run": max_consonant_run,
        "base64_ratio": round(b64_chars / total_len, 4),
        "unique_char_ratio": round(len(set(text)) / total_len, 4)
    }
