"""
Feature Engine — Combines all analyzers into a unified feature vector.

Takes an email.message.EmailMessage and returns a pandas DataFrame row
with all extracted features from headers, URLs, and content analysis.
"""

import email
import os
from email.message import EmailMessage
from typing import Dict, Optional, Union

import pandas as pd

from src.features.header_analyzer import analyze_headers
from src.features.url_analyzer import analyze_urls
from src.features.content_analyzer import analyze_content


def extract_features(
    msg: EmailMessage,
    vectorizer_path: Optional[str] = None
) -> Dict[str, float]:
    """
    Extract all features from an email message.

    Combines header, URL, and content analysis into a single
    flat dictionary of numeric features.

    Args:
        msg: Parsed EmailMessage object.
        vectorizer_path: Optional path to TF-IDF vectorizer.

    Returns:
        Dict mapping feature names to numeric values.
    """
    features = {}

    # Header features
    try:
        header_features = analyze_headers(msg)
        features.update(header_features)
    except Exception as e:
        # Fail gracefully — fill header features with zeros
        features["header_extraction_error"] = 1.0

    # URL features
    try:
        url_features = analyze_urls(msg)
        features.update(url_features)
    except Exception as e:
        features["url_extraction_error"] = 1.0

    # Content features
    try:
        content_features = analyze_content(msg, vectorizer_path)
        features.update(content_features)
    except Exception as e:
        features["content_extraction_error"] = 1.0

    return features


def extract_features_from_file(
    filepath: str,
    vectorizer_path: Optional[str] = None
) -> Dict[str, float]:
    """
    Extract features from an .eml file on disk.

    Args:
        filepath: Path to the .eml file.
        vectorizer_path: Optional path to TF-IDF vectorizer.

    Returns:
        Dict mapping feature names to numeric values.
    """
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        msg = email.message_from_file(f)
    return extract_features(msg, vectorizer_path)


def extract_features_dataframe(
    filepath: str,
    vectorizer_path: Optional[str] = None
) -> pd.DataFrame:
    """
    Extract features from an .eml file and return as a single-row DataFrame.

    Args:
        filepath: Path to the .eml file.
        vectorizer_path: Optional path to TF-IDF vectorizer.

    Returns:
        pandas DataFrame with one row of features.
    """
    features = extract_features_from_file(filepath, vectorizer_path)
    return pd.DataFrame([features])


def get_feature_names() -> list:
    """
    Return the list of expected feature names (without TF-IDF).
    Useful for ensuring consistent column ordering.
    """
    # Create a minimal dummy email to get feature names
    msg = EmailMessage()
    msg["From"] = "test@example.com"
    msg["Subject"] = "Test"
    msg.set_content("Test body")

    features = extract_features(msg)
    # Remove TF-IDF features (they're variable)
    return [k for k in sorted(features.keys()) if not k.startswith("tfidf_")]
