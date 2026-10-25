import math
from collections import Counter

def calculate_shannon_entropy(text: str) -> float:
    """Calculates the mathematical randomness (entropy) of a string."""
    if not text:
        return 0.0
    counts = Counter(text)
    total_len = len(text)
    return -sum((count / total_len) * math.log2(count / total_len) for count in counts.values())

def inspect_dns_queries(queries: list, entropy_threshold: float = 3.5, length_threshold: int = 20):
    """
    Evaluates DNS queries for encoded data or tunneling.
    Flags subdomains that exceed length and entropy thresholds.
    """
    flagged = []
    seen_domains = set()

    for item in queries:
        domain = item["query"]
        if domain in seen_domains:
            continue
        seen_domains.add(domain)

        parts = domain.split(".")
        if len(parts) >= 2:
            # Check the leftmost subdomain label
            subdomain = parts[0]
            entropy = calculate_shannon_entropy(subdomain)

            if entropy >= entropy_threshold and len(subdomain) >= length_threshold:
                flagged.append({
                    "timestamp": item["timestamp"],
                    "src": item["src"],
                    "dst": item["dst"],
                    "domain": domain,
                    "subdomain": subdomain,
                    "length": len(subdomain),
                    "entropy": round(entropy, 3),
                    "mitre_id": "T1071.004",
                    "technique": "Application Layer Protocol: DNS (Tunneling/Exfiltration)"
                })

    return flagged
