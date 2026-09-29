# AmanQR - Project Summary

## Overview

AmanQR is a free, open-source cybersecurity tool that detects 8 types of attacks in QR codes using a 9-layer hybrid detection system.

## Problem Statement

QR code phishing (Quishing) is a rapidly growing threat. Attackers hide malicious URLs in QR codes placed in restaurants, parking meters, and emails.

Advanced attacks like Homograph attacks use fake Unicode characters (e.g., Cyrillic a) that look identical to Latin letters - tricking even experienced users.

No free, accessible tool exists for the public to verify QR codes before scanning.

## Solution

AmanQR analyzes QR codes in less than 3 seconds and provides:
- Clear verdict (Safe, Unknown, Suspicious, Malicious)
- Attack classification (8 categories)
- Severity level (Critical, High, Medium, Safe)
- Confidence percentage
- Detailed reasons and indicators

## Technical Architecture

9-Layer Hybrid Detection System:

1. QR Decoder (zxing-cpp + preprocessing)
2. URL Unshortener (bit.ly, qrco.de)
3. Homograph Attack Detection (Cyrillic/Greek fake chars)
4. URL Analyzer (30+ rules + whitelist)
5. WHOIS Domain Age Checker
6. LightGBM Machine Learning Classifier
7. External APIs (VirusTotal + URLhaus)
8. Hosting Abuse Detection (GitHub, GitLab)
9. Threat Classifier (8 attack types, context-aware)

## Performance

- Accuracy: 99.5% (hold-out test set)
- Real-world: 100% on URLhaus feeds
- Homograph Detection: 4/4 attacks, 0/4 false positives
- Dataset: 200,000 QR codes
- Response time: less than 3 seconds
- Model size: 611 KB
- Layers: 9

## Attack Types Detected

1. HOMOGRAPH ATTACK (CRITICAL) - Fake Unicode chars
2. MALWARE (CRITICAL) - .exe, .ps1, .sh, IoT binaries
3. MALWARE-IOT (CRITICAL) - /mipsel, /arm7 (Mirai)
4. PHISHING (HIGH) - Fake login pages
5. HACKED SITE (HIGH) - Compromised websites
6. SCAM (HIGH) - High-risk TLDs, spam
7. SUSPICIOUS INFRA (MEDIUM) - Direct IPs, unusual ports
8. SAFE - Verified legitimate sites

## Technologies

- Python 3
- zxing-cpp for QR decoding
- LightGBM for ML classification
- python-whois for domain analysis
- VirusTotal API (70+ antivirus engines)
- URLhaus API (abuse.ch)
- Streamlit for web interface

## Key Achievements

- 99.5% accuracy on 200,000 QR codes
- 28 engineered features
- 9-layer detection system
- 8 attack types (including rare Homograph detection)
- Whitelist (40+ trusted services)
- Real-time response (less than 3 seconds)
- 100% free and open source
- Bilingual (Arabic + English)
- Privacy-focused (no data storage)

## Links

- Live App: https://amanqr-3bjyry2nfnxf5d2rbrezdy.streamlit.app
- GitHub: https://github.com/hssoooni/AmanQR

## License

MIT License

---

Made with love for the community
