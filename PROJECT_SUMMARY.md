# AmanQR - Project Summary

## Overview

AmanQR is a free, open-source cybersecurity tool that detects malicious QR codes (Quishing attacks) in real-time.

## Problem Statement

QR code phishing (Quishing) is a rapidly growing cybersecurity threat:
- Attackers place fake QR codes in restaurants, parking meters, emails
- When scanned, users are redirected to phishing sites
- Credentials and personal data are stolen

No free, accessible tool exists for the public to verify QR codes before scanning.

## Solution

AmanQR analyzes QR codes in 3 seconds and provides:
- Clear verdict (Safe, Unknown, Suspicious, Malicious)
- Confidence percentage
- Threat score (0-100)
- Detailed reasons for the decision

## Technical Architecture

5-Layer Hybrid Detection System:

1. QR Decoder (zxing-cpp)
2. URL Analyzer (25+ security rules)
3. WHOIS Domain Age Checker
4. LightGBM Machine Learning Classifier
5. External APIs (VirusTotal + URLhaus)

## Performance

- Accuracy: 99.5 percent (hold-out test set)
- Dataset: 200,000 QR codes
- Response time: less than 3 seconds
- Model size: 611 KB

## Technologies

- Python 3
- zxing-cpp for QR decoding
- LightGBM for ML classification
- python-whois for domain analysis
- VirusTotal API (70+ antivirus engines)
- URLhaus API (abuse.ch)
- Streamlit for web interface

## Key Achievements

- 99.5 percent accuracy on 200,000 QR codes
- 28 engineered features
- 5-layer detection system
- Real-time response (less than 3 seconds)
- 100 percent free and open source
- Bilingual (Arabic + English)
- Privacy-focused (no data storage)

## Links

- Live App: https://amanqr-3bjyry2nfnxf5d2rbrezdy.streamlit.app
- GitHub: https://github.com/hssoooni/AmanQR

## License

MIT License

---

Made with love for the community
