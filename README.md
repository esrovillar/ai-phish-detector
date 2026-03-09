# 🎣 AI-Phish-Detector

Machine learning-powered phishing email detection tool. Analyzes email headers, body content, URLs, and sender reputation to classify emails as phishing or legitimate.

## Features

- **ML Classification** — Trained model using NLP features (TF-IDF, linguistic patterns)
- **Header Analysis** — SPF, DKIM, DMARC validation, sender reputation checks
- **URL Analysis** — Suspicious URL detection, domain age, typosquatting detection
- **Content Analysis** — Urgency markers, social engineering patterns, brand impersonation
- **Real-time Scoring** — Confidence score (0-100) with detailed breakdown
- **Batch Processing** — Scan .eml files, mbox, or direct IMAP inbox
- **Dashboard** — CLI and web-based results viewer
- **API** — REST API for integration with email gateways

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Email Input │────▶│  Feature Engine   │────▶│  ML Classifier  │
│  (.eml/IMAP) │     │                  │     │  (scikit-learn)  │
└─────────────┘     │  ├─ Headers       │     └────────┬────────┘
                    │  ├─ URLs          │              │
                    │  ├─ Content/NLP   │     ┌────────▼────────┐
                    │  └─ Sender Rep    │     │  Risk Scorer    │
                    └──────────────────┘     │  (0-100 score)  │
                                             └────────┬────────┘
                                                      │
                                             ┌────────▼────────┐
                                             │  Report/Alert   │
                                             │  (CLI/API/TG)   │
                                             └─────────────────┘
```

## Datasets

Uses public phishing email datasets for training:
- [Nazario Phishing Corpus](https://monkey.org/~jose/phishing/)
- [SpamAssassin Public Corpus](https://spamassassin.apache.org/old/publiccorpus/)
- [IWSPA-AP Dataset](https://github.com/IWSPA-AP/IWSPA-AP-dataset)
- Custom labeled samples

## Quick Start

```bash
# Clone
git clone https://github.com/esrovillar/ai-phish-detector.git
cd ai-phish-detector

# Install
pip install -r requirements.txt

# Download & prepare training data
python -m src.data.download_datasets

# Train model
python -m src.model.train

# Analyze a single email
python -m src.cli.analyze --file suspicious_email.eml

# Scan your inbox
python -m src.cli.analyze --imap --server imap.gmail.com --user you@gmail.com

# Start API server
python -m src.api.server

# Dashboard
python -m src.cli.dashboard
```

## Feature Extraction

### Header Features
- SPF/DKIM/DMARC pass/fail
- Return-Path vs From mismatch
- Received chain analysis (hop count, suspicious relays)
- Reply-To mismatch
- X-Mailer analysis

### URL Features
- Total URL count
- Suspicious TLD detection (.xyz, .top, .buzz, etc.)
- IP-based URLs
- URL shorteners
- Typosquatting similarity score (Levenshtein distance to known brands)
- Mismatched anchor text vs href

### Content Features (NLP)
- TF-IDF vectorization
- Urgency word frequency (urgent, immediately, suspended, verify)
- Social engineering patterns (fear, authority, scarcity, reciprocity)
- Brand impersonation keywords
- Grammar/spelling error ratio
- HTML vs text ratio
- Attachment analysis (dangerous extensions)

### Sender Features
- Domain age (whois)
- Domain reputation
- First-time sender flag
- Freemail provider flag

## Project Structure

```
ai-phish-detector/
├── src/
│   ├── features/
│   │   ├── header_analyzer.py    # Email header extraction
│   │   ├── url_analyzer.py       # URL analysis & typosquatting
│   │   ├── content_analyzer.py   # NLP & content features
│   │   ├── sender_analyzer.py    # Sender reputation
│   │   └── feature_engine.py     # Combined feature extraction
│   ├── model/
│   │   ├── train.py              # Model training pipeline
│   │   ├── predict.py            # Prediction & scoring
│   │   └── evaluate.py           # Model evaluation & metrics
│   ├── data/
│   │   ├── download_datasets.py  # Dataset downloader
│   │   └── preprocess.py         # Data cleaning & labeling
│   ├── cli/
│   │   ├── analyze.py            # CLI analysis tool
│   │   └── dashboard.py          # Rich CLI dashboard
│   └── api/
│       └── server.py             # REST API (FastAPI)
├── models/                       # Trained model files
├── data/                         # Training datasets
├── config/
│   └── config.yaml               # Configuration
├── tests/
├── notebooks/                    # Jupyter notebooks for exploration
├── requirements.txt
├── setup.py
└── README.md
```

## Model Performance

| Metric | Score |
|--------|-------|
| Accuracy | TBD |
| Precision | TBD |
| Recall | TBD |
| F1-Score | TBD |
| AUC-ROC | TBD |

## Roadmap

- [x] Project structure & README
- [ ] Feature extraction: headers
- [ ] Feature extraction: URLs
- [ ] Feature extraction: content/NLP
- [ ] Dataset download & preprocessing
- [ ] Model training (Random Forest + XGBoost)
- [ ] CLI analysis tool
- [ ] Batch .eml scanning
- [ ] IMAP inbox scanning
- [ ] REST API
- [ ] Rich CLI dashboard
- [ ] Telegram alerting
- [ ] Model evaluation & tuning

## Requirements

- Python 3.9+
- scikit-learn
- pandas, numpy
- beautifulsoup4, lxml
- python-whois
- fastapi, uvicorn (API)

## Author

**Esteban Rojas Villar** — Senior Cybersecurity Incident Responder
- LinkedIn: [linkedin.com/in/estebanrojas](https://linkedin.com/in/estebanrojas)

## License

MIT
