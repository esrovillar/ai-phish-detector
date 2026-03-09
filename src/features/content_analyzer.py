"""
Content Analyzer — NLP and content-based feature extraction.

Analyzes email body text for urgency language, social engineering patterns,
HTML characteristics, and dangerous attachments.
"""

import os
import re
import pickle
from email.message import EmailMessage
from typing import Dict, Optional

from bs4 import BeautifulSoup


# Urgency keywords and phrases
URGENCY_WORDS = [
    "urgent", "immediately", "suspended", "verify", "confirm",
    "expire", "unauthorized", "alert", "warning", "click here",
    "act now", "limited time", "account locked", "security notice",
    "action required", "within 24 hours", "within 48 hours",
    "your account", "deactivated", "compromised", "unusual activity",
    "login attempt", "reset your password"
]

# Social engineering patterns (regex)
SOCIAL_ENGINEERING_PATTERNS = {
    "fear": [
        r"account.{0,20}(suspend|lock|clos|terminat|restrict)",
        r"unauthorized.{0,20}(access|transaction|activity)",
        r"security.{0,20}(breach|alert|warning|threat)",
        r"your.{0,20}(data|information).{0,20}(risk|compromis|stolen)",
    ],
    "authority": [
        r"(IT department|security team|admin|support team)",
        r"(official|authorized|verified).{0,10}(notice|communication)",
        r"(federal|government|IRS|FBI|police)",
        r"(CEO|director|manager).{0,20}(request|ask|need)",
    ],
    "urgency": [
        r"(immediate|urgent).{0,10}(action|attention|response)",
        r"(expire|deadline|last chance|final notice)",
        r"within.{0,5}\d+.{0,5}(hour|day|minute)",
        r"(act now|respond immediately|time.{0,5}sensitive)",
    ],
    "reward": [
        r"(won|winner|congratulat|prize|reward|gift)",
        r"(free|bonus|discount|offer|promotion)",
        r"(claim|collect|redeem).{0,10}(reward|prize|bonus)",
    ],
}

# Dangerous attachment extensions
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1",
    ".zip", ".rar", ".7z", ".iso", ".msi", ".dll", ".com",
    ".pif", ".wsf", ".hta", ".cpl"
}

# Default vectorizer path
VECTORIZER_PATH = os.path.join("models", "tfidf_vectorizer.pkl")


def _extract_text_from_email(msg: EmailMessage) -> tuple:
    """
    Extract plain text and HTML from email.
    Returns (plain_text, html_content, has_html).
    """
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
            decoded = payload.decode("utf-8", errors="replace")
            if msg.get_content_type() == "text/html":
                html_body = decoded
            else:
                text_body = decoded

    # If we have HTML but no plain text, extract text from HTML
    if html_body and not text_body:
        try:
            soup = BeautifulSoup(html_body, "lxml")
        except Exception:
            soup = BeautifulSoup(html_body, "html.parser")
        text_body = soup.get_text(separator=" ", strip=True)

    return text_body, html_body, bool(html_body)


def _count_urgency_words(text: str) -> Dict[str, float]:
    """Count urgency-related keywords in text."""
    text_lower = text.lower()
    total = 0
    for word in URGENCY_WORDS:
        count = text_lower.count(word.lower())
        total += count

    word_count = max(len(text.split()), 1)
    return {
        "content_urgency_word_count": float(total),
        "content_urgency_word_ratio": float(total / word_count),
    }


def _detect_social_engineering(text: str) -> Dict[str, float]:
    """Detect social engineering patterns by category."""
    text_lower = text.lower()
    features = {}
    total_patterns = 0

    for category, patterns in SOCIAL_ENGINEERING_PATTERNS.items():
        count = 0
        for pattern in patterns:
            if re.search(pattern, text_lower):
                count += 1
        features[f"content_se_{category}_count"] = float(count)
        total_patterns += count

    features["content_se_total_patterns"] = float(total_patterns)
    return features


def _html_text_ratio(html: str, text: str) -> float:
    """Calculate ratio of HTML markup to visible text."""
    if not html:
        return 0.0
    html_len = max(len(html), 1)
    text_len = max(len(text), 1)
    return float(html_len / text_len)


def _check_attachments(msg: EmailMessage) -> Dict[str, float]:
    """Analyze attachments for dangerous extensions."""
    dangerous_count = 0
    total_attachments = 0

    if msg.is_multipart():
        for part in msg.walk():
            filename = part.get_filename()
            if filename:
                total_attachments += 1
                ext = os.path.splitext(filename.lower())[1]
                if ext in DANGEROUS_EXTENSIONS:
                    dangerous_count += 1

    return {
        "content_total_attachments": float(total_attachments),
        "content_dangerous_attachments": float(dangerous_count),
        "content_has_dangerous_attachment": float(dangerous_count > 0),
    }


def analyze_content(msg: EmailMessage, vectorizer_path: Optional[str] = None) -> Dict[str, float]:
    """
    Extract content/NLP features from email body.

    Args:
        msg: Parsed EmailMessage object.
        vectorizer_path: Optional path to saved TF-IDF vectorizer pickle.

    Returns:
        Dict with content feature names → numeric values.
    """
    features = {}
    text, html, has_html = _extract_text_from_email(msg)

    # Basic text stats
    word_count = len(text.split()) if text else 0
    char_count = len(text) if text else 0

    features["content_word_count"] = float(word_count)
    features["content_char_count"] = float(char_count)
    features["content_has_html"] = float(has_html)
    features["content_html_text_ratio"] = _html_text_ratio(html, text)

    # Subject analysis
    subject = msg.get("Subject", "") or ""
    features["content_subject_length"] = float(len(subject))
    features["content_subject_has_re"] = float(
        bool(re.match(r"^(re|fw|fwd)\s*:", subject, re.IGNORECASE))
    )
    # Excessive caps in subject
    if subject:
        upper_ratio = sum(1 for c in subject if c.isupper()) / max(len(subject), 1)
        features["content_subject_caps_ratio"] = float(upper_ratio)
    else:
        features["content_subject_caps_ratio"] = 0.0

    # Urgency words
    urgency = _count_urgency_words(text)
    features.update(urgency)

    # Social engineering patterns
    se_features = _detect_social_engineering(text)
    features.update(se_features)

    # Attachments
    attachment_features = _check_attachments(msg)
    features.update(attachment_features)

    # Body characteristics
    if text:
        # Exclamation mark density
        features["content_exclamation_count"] = float(text.count("!"))
        # ALL CAPS words ratio
        words = text.split()
        caps_words = sum(1 for w in words if w.isupper() and len(w) > 1)
        features["content_caps_word_ratio"] = float(caps_words / max(len(words), 1))
        # Link-to-text ratio
        link_count = len(re.findall(r'https?://', text))
        features["content_link_density"] = float(link_count / max(word_count, 1))
    else:
        features["content_exclamation_count"] = 0.0
        features["content_caps_word_ratio"] = 0.0
        features["content_link_density"] = 0.0

    # TF-IDF features (only if vectorizer exists)
    vpath = vectorizer_path or VECTORIZER_PATH
    if os.path.exists(vpath) and text:
        try:
            with open(vpath, "rb") as f:
                vectorizer = pickle.load(f)
            tfidf_vector = vectorizer.transform([text])
            # Use top TF-IDF features as individual columns
            for i in range(min(tfidf_vector.shape[1], 50)):
                features[f"tfidf_{i}"] = float(tfidf_vector[0, i])
        except Exception:
            pass  # Skip TF-IDF if vectorizer can't be loaded

    return features


def get_email_text(msg: EmailMessage) -> str:
    """Utility: extract plain text from email for external use."""
    text, _, _ = _extract_text_from_email(msg)
    return text
