from __future__ import annotations
from urllib.parse import urlparse, urljoin, urldefrag, urlunparse, parse_qsl, urlencode
from typing import Optional
import tldextract

def normalize_url(base: str, href: str) -> Optional[str]:
    """
    Resolve href against base, remove fragments, canonicalize query params.
    Returns None on parse failure.
    """
    try:
        resolved = urljoin(base, href)
        resolved, _ = urldefrag(resolved)
        p = urlparse(resolved)

        # canonicalize hostname & port
        hostname = p.hostname or ""
        netloc = hostname
        if p.port:
            if not ((p.scheme == "http" and p.port == 80) or (p.scheme == "https" and p.port == 443)):
                netloc = f"{hostname}:{p.port}"

        # canonicalize query string (sorted)
        qs = ""
        if p.query:
            qs = urlencode(sorted(parse_qsl(p.query, keep_blank_values=True)))

        return urlunparse((p.scheme, netloc, p.path or "/", p.params or "", qs, ""))
    except Exception:
        return None

def same_domain(seed: str, candidate: str, include_subdomains: bool = True) -> bool:
    """
    Return True if candidate is same domain (or same base domain if include_subdomains).
    Uses tldextract to compare effective TLD+1.
    """
    try:
        s = urlparse(seed)
        c = urlparse(candidate)
        if s.scheme not in {"http", "https"} or c.scheme not in {"http", "https"}:
            return False
        if s.hostname == c.hostname:
            return True
        if include_subdomains:
            e1 = tldextract.extract(s.hostname or "")
            e2 = tldextract.extract(c.hostname or "")
            base1 = f"{e1.domain}.{e1.suffix}".lower() if e1.suffix else e1.domain.lower()
            base2 = f"{e2.domain}.{e2.suffix}".lower() if e2.suffix else e2.domain.lower()
            return base1 == base2
        return False
    except Exception:
        return False
