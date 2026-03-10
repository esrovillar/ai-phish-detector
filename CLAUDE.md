# CLAUDE.md — AI Phish Detector

## About
ML-based phishing email detection. Extracts 47 features from email headers, URLs, and content. Random Forest classifier.

## Architecture
- `src/features/` — Feature extractors: header_features, url_features, content_features
- `src/models/` — ML pipeline: training, prediction, evaluation
- `src/pipeline/` — Email parsing and orchestration
- `data/` — Training data (synthetic emails)

## Features (47 total)
- **Headers:** SPF/DKIM/DMARC validation, Return-Path/Reply-To mismatches, hop count, X-Mailer analysis
- **URLs:** Suspicious TLDs, IP-based URLs, shorteners, typosquatting (Levenshtein distance)
- **Content/NLP:** Urgency words, social engineering patterns (fear, authority, scarcity, reward), HTML ratio, dangerous attachments

## Running
```bash
python -m src.pipeline.main --analyze email.eml
python -m src.models.train
```
