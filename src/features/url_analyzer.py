"""
URL Analyzer — Extract URL-based features from email body.

Detects suspicious TLDs, IP-based URLs, shorteners, typosquatting,
and mismatched anchor text vs href.
"""

import re
from email.message import EmailMessage
from typing import Dict, List, Set
from urllib.parse import urlparse

from bs4 import BeautifulSoup

try:
    from Levenshtein import distance as levenshtein_distance
except ImportError:
    # Fallback if python-Levenshtein not installed
    def levenshtein_distance(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]


# Suspicious TLDs commonly abused in phishing
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".buzz", ".click", ".gq", ".ml", ".tk",
    ".cf", ".ga", ".pw", ".cc", ".icu", ".work", ".loan",
    ".racing", ".win", ".bid", ".stream"
}

# URL shortener domains
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "short.io",
    "tiny.cc", "rb.gy", "shorturl.at", "v.gd"
}

# Known brands for typosquatting detection
KNOWN_BRANDS = [
    "paypal", "microsoft", "apple", "google", "amazon",
    "netflix", "facebook", "instagram", "linkedin", "chase",
    "wellsfargo", "bankofamerica", "citibank", "hsbc",
    "dropbox", "docusign", "office365", "outlook", "ebay",
    "walmart", "costco", "usps", "fedex", "dhl"
]

# Regex to extract URLs from plain text
URL_REGEX = re.compile(
    r'https?://[^\s<>"\')\]]+',
    re.IGNORECASE
)

# Regex to detect IP-based URLs
IP_URL_REGEX = re.compile(
    r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
)


def _get_email_body(msg: EmailMessage) -> str:
    """Extract the full body content from an email (HTML preferred)."""
    html_body = ""
    text_body = ""

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    html_body = payload.decode("utf-8", errors="replace")
            elif ct == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    text_body = payload.decode("utf-8", errors="replace")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode("utf-8", errors="replace")
            if msg.get_content_type() == "text/html":
                html_body = body
            else:
                text_body = body

    return html_body if html_body else text_body


def _extract_urls_from_text(text: str) -> List[str]:
    """Extract URLs from plain text using regex."""
    return URL_REGEX.findall(text)


def _extract_urls_from_html(html: str) -> tuple:
    """
    Extract URLs from HTML, returning (all_urls, mismatched_pairs).
    mismatched_pairs: list of (href, anchor_text) where they differ.
    """
    urls = []
    mismatched = []

    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"].strip()
        if href.startswith(("http://", "https://")):
            urls.append(href)
            # Check for anchor text that looks like a different URL
            anchor_text = a_tag.get_text(strip=True)
            if anchor_text.startswith(("http://", "https://", "www.")):
                anchor_domain = urlparse(
                    anchor_text if "://" in anchor_text else f"http://{anchor_text}"
                ).netloc.lower().replace("www.", "")
                href_domain = urlparse(href).netloc.lower().replace("www.", "")
                if anchor_domain and href_domain and anchor_domain != href_domain:
                    mismatched.append((href, anchor_text))

    # Also grab URLs from text content
    text_urls = _extract_urls_from_text(soup.get_text())
    all_urls = list(set(urls + text_urls))

    return all_urls, mismatched


def _get_domain(url: str) -> str:
    """Extract clean domain from URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower().replace("www.", "")
    except Exception:
        return ""


def _check_typosquatting(domain: str) -> tuple:
    """
    Check if domain is a typosquat of known brands.
    Returns (is_typosquat: bool, min_distance: int, closest_brand: str).
    """
    # Strip TLD for comparison
    domain_base = domain.split(".")[0] if "." in domain else domain
    if not domain_base:
        return False, 99, ""

    min_dist = 99
    closest = ""

    for brand in KNOWN_BRANDS:
        # Exact match = not a typosquat (it's legit or a subdomain)
        if domain_base == brand:
            return False, 0, brand

        dist = levenshtein_distance(domain_base, brand)
        if dist < min_dist:
            min_dist = dist
            closest = brand

    # Typosquat if distance is 1-2 characters from a known brand
    is_typosquat = 1 <= min_dist <= 2
    return is_typosquat, min_dist, closest


def analyze_urls(msg: EmailMessage) -> Dict[str, float]:
    """
    Extract URL-based numeric features from an email.

    Args:
        msg: Parsed EmailMessage object.

    Returns:
        Dict with URL feature names → numeric values.
    """
    features = {}
    body = _get_email_body(msg)

    if not body:
        # No body → all zeros
        features["url_total_count"] = 0.0
        features["url_suspicious_tld_count"] = 0.0
        features["url_ip_based_count"] = 0.0
        features["url_shortener_count"] = 0.0
        features["url_typosquat_count"] = 0.0
        features["url_mismatched_anchor_count"] = 0.0
        features["url_unique_domains"] = 0.0
        features["url_has_urls"] = 0.0
        features["url_min_typo_distance"] = 99.0
        return features

    # Extract URLs based on content type
    all_urls = []
    mismatched = []

    if "<html" in body.lower() or "<a " in body.lower():
        all_urls, mismatched = _extract_urls_from_html(body)
    else:
        all_urls = _extract_urls_from_text(body)

    features["url_total_count"] = float(len(all_urls))
    features["url_has_urls"] = float(len(all_urls) > 0)

    # Analyze each URL
    suspicious_tld_count = 0
    ip_based_count = 0
    shortener_count = 0
    typosquat_count = 0
    min_typo_dist = 99
    domains: Set[str] = set()

    for url in all_urls:
        domain = _get_domain(url)
        if domain:
            domains.add(domain)

        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if url.lower().rstrip("/").endswith(tld) or f"{tld}/" in url.lower():
                suspicious_tld_count += 1
                break

        # IP-based URL
        if IP_URL_REGEX.match(url):
            ip_based_count += 1

        # URL shortener
        if domain in URL_SHORTENERS:
            shortener_count += 1

        # Typosquatting
        is_typo, dist, _ = _check_typosquatting(domain)
        if is_typo:
            typosquat_count += 1
        if dist < min_typo_dist:
            min_typo_dist = dist

    features["url_suspicious_tld_count"] = float(suspicious_tld_count)
    features["url_ip_based_count"] = float(ip_based_count)
    features["url_shortener_count"] = float(shortener_count)
    features["url_typosquat_count"] = float(typosquat_count)
    features["url_mismatched_anchor_count"] = float(len(mismatched))
    features["url_unique_domains"] = float(len(domains))
    features["url_min_typo_distance"] = float(min_typo_dist)

    return features
