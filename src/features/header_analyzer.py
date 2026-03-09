"""
Header Analyzer — Extract security-relevant features from email headers.

Analyzes Authentication-Results (SPF/DKIM/DMARC), sender mismatches,
received hop chain, and X-Mailer suspicious patterns.
"""

import re
import email
from email.message import EmailMessage
from email.utils import parseaddr
from typing import Dict


# Suspicious X-Mailer patterns (case-insensitive)
SUSPICIOUS_MAILERS = [
    "phpmailer", "swiftmailer", "python", "smtp",
    "mass", "bulk", "mailchimp", "sendinblue"
]


def _extract_domain(address: str) -> str:
    """Extract domain from an email address."""
    _, addr = parseaddr(address)
    if "@" in addr:
        return addr.split("@")[1].lower().strip()
    return ""


def _check_auth_result(auth_header: str, mechanism: str) -> int:
    """
    Check if a specific auth mechanism passed.
    Returns: 1 = pass, 0 = not present, -1 = fail/softfail/none
    """
    if not auth_header:
        return 0
    auth_lower = auth_header.lower()
    # Look for patterns like "spf=pass", "dkim=pass", "dmarc=pass"
    pattern = rf"{mechanism}\s*=\s*(\w+)"
    match = re.search(pattern, auth_lower)
    if not match:
        return 0
    result = match.group(1)
    if result == "pass":
        return 1
    return -1  # fail, softfail, none, temperror, etc.


def analyze_headers(msg: EmailMessage) -> Dict[str, float]:
    """
    Extract numeric features from email headers.

    Args:
        msg: Parsed EmailMessage object.

    Returns:
        Dict with header-based feature names → numeric values.
    """
    features = {}

    # --- Authentication Results ---
    auth_results = msg.get("Authentication-Results", "")
    features["header_spf_pass"] = float(_check_auth_result(auth_results, "spf") == 1)
    features["header_spf_fail"] = float(_check_auth_result(auth_results, "spf") == -1)
    features["header_dkim_pass"] = float(_check_auth_result(auth_results, "dkim") == 1)
    features["header_dkim_fail"] = float(_check_auth_result(auth_results, "dkim") == -1)
    features["header_dmarc_pass"] = float(_check_auth_result(auth_results, "dmarc") == 1)
    features["header_dmarc_fail"] = float(_check_auth_result(auth_results, "dmarc") == -1)
    features["header_has_auth_results"] = float(bool(auth_results))

    # --- Return-Path vs From mismatch ---
    from_addr = msg.get("From", "")
    return_path = msg.get("Return-Path", "")
    from_domain = _extract_domain(from_addr)
    return_path_domain = _extract_domain(return_path)

    if from_domain and return_path_domain:
        features["header_return_path_mismatch"] = float(from_domain != return_path_domain)
    else:
        features["header_return_path_mismatch"] = 0.0

    # --- Reply-To vs From mismatch ---
    reply_to = msg.get("Reply-To", "")
    reply_to_domain = _extract_domain(reply_to)

    if from_domain and reply_to_domain:
        features["header_reply_to_mismatch"] = float(from_domain != reply_to_domain)
    else:
        features["header_reply_to_mismatch"] = 0.0

    # --- Received hop count ---
    received_headers = msg.get_all("Received") or []
    features["header_received_hop_count"] = float(len(received_headers))
    # Unusually few hops (0-1) or many (>10) can be suspicious
    features["header_few_hops"] = float(len(received_headers) <= 1)
    features["header_many_hops"] = float(len(received_headers) > 8)

    # --- X-Mailer analysis ---
    x_mailer = (msg.get("X-Mailer") or "").lower()
    features["header_has_x_mailer"] = float(bool(x_mailer))
    features["header_suspicious_mailer"] = 0.0
    for pattern in SUSPICIOUS_MAILERS:
        if pattern in x_mailer:
            features["header_suspicious_mailer"] = 1.0
            break

    # --- Missing common headers ---
    features["header_missing_message_id"] = float(not msg.get("Message-ID"))
    features["header_missing_date"] = float(not msg.get("Date"))
    features["header_missing_subject"] = float(not msg.get("Subject"))

    # --- X-Priority (high priority = urgency tactic) ---
    x_priority = msg.get("X-Priority", "")
    features["header_high_priority"] = float(x_priority.strip() in ("1", "2"))

    return features
