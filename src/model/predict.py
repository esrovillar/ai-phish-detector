"""
Prediction Module — Load trained model and classify emails.

Provides a PhishDetector class with analyze_email() method that returns
a score (0-100), verdict, and feature breakdown.
"""

import email
import os
import pickle
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from src.features.feature_engine import extract_features, extract_features_from_file


MODEL_PATH = os.path.join("models", "phish_detector.pkl")

# Scoring thresholds
PHISHING_THRESHOLD = 70
SUSPICIOUS_THRESHOLD = 40


@dataclass
class AnalysisResult:
    """Result of email phishing analysis."""
    score: float                           # 0-100 phishing probability
    verdict: str                           # PHISHING, SUSPICIOUS, or LEGITIMATE
    features: Dict[str, float] = field(default_factory=dict)
    top_indicators: List[Tuple[str, float]] = field(default_factory=list)
    model_loaded: bool = False
    error: Optional[str] = None

    @property
    def verdict_color(self) -> str:
        if self.verdict == "PHISHING":
            return "red"
        elif self.verdict == "SUSPICIOUS":
            return "yellow"
        return "green"

    def to_dict(self) -> dict:
        return {
            "score": round(self.score, 1),
            "verdict": self.verdict,
            "model_loaded": self.model_loaded,
            "top_indicators": [
                {"feature": name, "value": round(float(val), 4)}
                for name, val in self.top_indicators
            ],
            "features": {k: round(float(v), 4) for k, v in self.features.items()},
        }


class PhishDetector:
    """
    Phishing email detector using trained ML model.

    Can operate in two modes:
    1. With trained model: full ML prediction with confidence score.
    2. Without model: heuristic scoring based on extracted features.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or MODEL_PATH
        self.model = None
        self.feature_names = None
        self.model_loaded = False
        self._load_model()

    def _load_model(self):
        """Attempt to load the trained model."""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, "rb") as f:
                    model_data = pickle.load(f)
                self.model = model_data["model"]
                self.feature_names = model_data.get("feature_names", [])
                self.model_loaded = True
            except Exception as e:
                self.model_loaded = False

    def analyze_email(self, email_path: str) -> AnalysisResult:
        """
        Analyze a single .eml file for phishing indicators.

        Args:
            email_path: Path to the .eml file.

        Returns:
            AnalysisResult with score, verdict, and feature breakdown.
        """
        try:
            features = extract_features_from_file(email_path)
        except Exception as e:
            return AnalysisResult(
                score=0.0,
                verdict="ERROR",
                error=f"Feature extraction failed: {e}",
            )

        if self.model_loaded:
            return self._predict_with_model(features)
        else:
            return self._predict_heuristic(features)

    def analyze_message(self, msg) -> AnalysisResult:
        """
        Analyze an EmailMessage object directly.

        Args:
            msg: email.message.EmailMessage object.

        Returns:
            AnalysisResult with score, verdict, and feature breakdown.
        """
        try:
            features = extract_features(msg)
        except Exception as e:
            return AnalysisResult(
                score=0.0,
                verdict="ERROR",
                error=f"Feature extraction failed: {e}",
            )

        if self.model_loaded:
            return self._predict_with_model(features)
        else:
            return self._predict_heuristic(features)

    def _predict_with_model(self, features: Dict[str, float]) -> AnalysisResult:
        """Use the trained ML model for prediction."""
        # Build feature vector in expected order
        feature_vector = []
        for name in self.feature_names:
            feature_vector.append(features.get(name, 0.0))

        X = np.array([feature_vector])

        # Get probability
        proba = self.model.predict_proba(X)[0]
        phishing_prob = proba[1] if len(proba) > 1 else proba[0]
        score = phishing_prob * 100

        # Determine verdict
        verdict = self._score_to_verdict(score)

        # Get top contributing features
        importances = self.model.feature_importances_
        feature_contributions = []
        for i, name in enumerate(self.feature_names):
            val = features.get(name, 0.0)
            if val != 0:
                contribution = importances[i] * abs(val)
                feature_contributions.append((name, contribution))

        feature_contributions.sort(key=lambda x: x[1], reverse=True)
        top_indicators = feature_contributions[:10]

        return AnalysisResult(
            score=score,
            verdict=verdict,
            features=features,
            top_indicators=top_indicators,
            model_loaded=True,
        )

    def _predict_heuristic(self, features: Dict[str, float]) -> AnalysisResult:
        """
        Heuristic scoring when no ML model is available.
        Uses weighted feature indicators to estimate phishing likelihood.
        """
        score = 0.0
        indicators = []

        # Header-based signals
        rules = [
            ("header_spf_fail", 15, "SPF authentication failed"),
            ("header_dkim_fail", 15, "DKIM authentication failed"),
            ("header_dmarc_fail", 15, "DMARC authentication failed"),
            ("header_return_path_mismatch", 12, "Return-Path doesn't match From"),
            ("header_reply_to_mismatch", 10, "Reply-To doesn't match From"),
            ("header_suspicious_mailer", 8, "Suspicious X-Mailer"),
            ("header_missing_message_id", 5, "Missing Message-ID"),
            ("header_high_priority", 5, "High priority flag set"),
            ("header_few_hops", 5, "Unusually few routing hops"),

            # URL-based signals
            ("url_suspicious_tld_count", 12, "Suspicious TLD detected"),
            ("url_ip_based_count", 15, "IP-based URL detected"),
            ("url_shortener_count", 8, "URL shortener used"),
            ("url_typosquat_count", 18, "Typosquatting domain detected"),
            ("url_mismatched_anchor_count", 15, "Mismatched link text"),

            # Content-based signals
            ("content_urgency_word_count", 8, "Urgency language detected"),
            ("content_se_total_patterns", 10, "Social engineering patterns"),
            ("content_has_dangerous_attachment", 15, "Dangerous attachment type"),
            ("content_caps_word_ratio", 5, "Excessive capitalization"),
        ]

        for feature, weight, description in rules:
            val = features.get(feature, 0.0)
            if val > 0:
                contribution = min(weight, weight * val)
                score += contribution
                indicators.append((description, contribution))

        # Bonus for auth passing (reduce score)
        if features.get("header_spf_pass", 0):
            score -= 5
        if features.get("header_dkim_pass", 0):
            score -= 5
        if features.get("header_dmarc_pass", 0):
            score -= 5

        # Clamp score to 0-100
        score = max(0.0, min(100.0, score))
        verdict = self._score_to_verdict(score)

        indicators.sort(key=lambda x: x[1], reverse=True)

        return AnalysisResult(
            score=score,
            verdict=verdict,
            features=features,
            top_indicators=indicators[:10],
            model_loaded=False,
        )

    @staticmethod
    def _score_to_verdict(score: float) -> str:
        """Convert numeric score to verdict string."""
        if score > PHISHING_THRESHOLD:
            return "PHISHING"
        elif score > SUSPICIOUS_THRESHOLD:
            return "SUSPICIOUS"
        return "LEGITIMATE"
