import numpy as np
import pandas as pd
from urllib.parse import urlparse
import tldextract
import re
from collections import Counter

def get_url_values(x):
    """Extract URL values from DataFrame or array"""
    if isinstance(x, pd.DataFrame):
        return x['url'].values
    return np.array(x)

COMMON_TLDS = [
    "com", "net", "org", "info", "co", "ru", "cn", "xyz", "top", "io", "biz",
    "us", "uk", "de", "jp", "in", "gov", "edu"
]

def numeric_features(urls):
    """Returns numeric/domain/TLD features for an iterable of url strings."""
    out = []
    for u in urls:
        s = str(u)
        lower = s.lower()
        length = len(s)
        digits = sum(c.isdigit() for c in s)
        dots = s.count('.')
        hyphens = s.count('-')
        at = s.count('@')
        
        # Improved IP address detection
        has_ip = int(bool(re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', s)))
        has_https = int(lower.startswith('https://'))

        # Domain parsing with error handling
        try:
            parsed = urlparse(s)
            ext = tldextract.extract(s)
            domain = ext.domain or (parsed.hostname or "")
            tld = ext.suffix or ""
            subdomain = ext.subdomain or ""
            hostname = ".".join([p for p in [subdomain, domain, tld] if p])
        except Exception:
            # Fallback if parsing fails
            domain = ""
            tld = ""
            subdomain = ""
            hostname = ""

        domain_length = len(domain)
        hostname_length = len(hostname)
        num_subdomains = subdomain.count('.') + (1 if subdomain else 0)

        # entropy calculation with safety
        entropy = 0.0
        if hostname:
            try:
                probs = np.array(list(Counter(hostname).values())) / len(hostname)
                entropy = -(probs * np.log2(probs)).sum()
            except Exception:
                entropy = 0.0

        suspicious_tokens = sum(1 for t in [
            'login','secure','account','verify','bank','confirm','signin',
            'admin','paypal','ebay','invoice'
        ] if t in lower)

        chunks = len([c for c in re.split(r'[^a-zA-Z0-9]+', s) if c])

        # TLD one-hot vector
        tld_vec = [1 if tld == t else 0 for t in COMMON_TLDS]
        tld_vec.append(0 if tld in COMMON_TLDS else 1)

        row = [
            length, digits, dots, hyphens, at, has_ip, has_https,
            domain_length, hostname_length, num_subdomains, entropy,
            suspicious_tokens, chunks
        ] + tld_vec

        out.append(row)

    return np.array(out)