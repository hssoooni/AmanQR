# AmanQR

**Free QR Code Safety Checker - AI-Powered Threat Detection**

AmanQR is a free, open-source cybersecurity tool that analyzes QR codes in real-time and detects 8 types of cyber attacks with AI-powered classification.

## Try it Live

Link: https://amanqr-3bjyry2nfnxf5d2rbrezdy.streamlit.app

No installation needed. Just upload a QR image.

## What it Detects

AmanQR identifies 8 types of attacks:

- HOMOGRAPH ATTACK (CRITICAL) - Fake Unicode characters (Cyrillic/Greek)
- MALWARE (CRITICAL) - .exe, .ps1, .sh downloads, IoT binaries
- MALWARE-IOT (CRITICAL) - /mipsel, /arm7 (Mirai botnet)
- PHISHING (HIGH) - Fake PayPal/Hotmail login pages
- HACKED SITE (HIGH) - Compromised legitimate websites
- SCAM (HIGH) - High-risk TLDs, spam patterns
- SUSPICIOUS INFRA (MEDIUM) - Direct IPs, unusual ports
- SAFE - Verified legitimate sites

## How it Works

AmanQR uses a 9-layer hybrid detection system:

### Layer 1: QR Decoder
- zxing-cpp with multi-attempt preprocessing
- Handles real-world photos (camera, blurry, tilted)
- Multiple rotation attempts

### Layer 2: URL Unshortener
- Expands shortened URLs (bit.ly, tinyurl, qrco.de)
- Follows HTTP + HTML + JavaScript redirects
- Reveals true destination

### Layer 3: Homograph Attack Detection (RARE)
- Detects Cyrillic/Greek characters that look like Latin
- Example: Cyrillic a (U+0430) looks like Latin a
- Detects apple.com vs aple.com (fake Cyrillic)
- Mixed script detection

### Layer 4: URL Analyzer (30+ Rules)
- Phishing keywords (login, verify, account)
- Typosquatting detection (paypa1, goog1e)
- Brand impersonation (fake PayPal, Microsoft)
- Free DNS services (.work.gd, .ddns.net)
- Gibberish domains (random strings)
- IoT malware binaries (/mipsel, /arm7, /x86)
- Dangerous scripts (.ps1, .bat, .vbs, .sh)
- Known malicious domains (URLhaus feed)
- Whitelist (40+ trusted services)

### Layer 5: WHOIS Checker
- Domain age analysis
- Hidden WHOIS detection
- New domain flags

### Layer 6: ML Model (LightGBM)
- Trained on 200,000 QR codes
- 28 engineered features
- URL entropy, vowel ratio, typosquatting, etc.
- 99.5% test accuracy

### Layer 7: External APIs
- VirusTotal: 70+ antivirus engines
- URLhaus: abuse.ch malicious URL database

### Layer 8: Hosting Abuse Detection
- GitHub /releases/, /raw/, .exe downloads
- GitLab/Bitbucket abuse patterns
- Blogspot/spam platforms

### Layer 9: Threat Classifier (Smart)
- Classifies attack type (8 categories)
- Determines severity (Critical/High/Medium/Safe)
- Context-aware (avoids false positives)
- Provides explanation (Arabic + English)
- Lists detailed indicators

## Results

- Accuracy: 99.5% (hold-out test set)
- Real-world accuracy: 100% on URLhaus feeds
- Homograph Detection: 4/4 attacks, 0/4 false positives
- Dataset: 200,000 QR codes
- Response Time: less than 3 seconds
- Model Size: 611 KB
- Layers: 9

## What Makes AmanQR Different

- 100% Free - No hidden costs
- AI-Powered - ML + Rule-based hybrid
- 8 Attack Types - Comprehensive classification
- Homograph Attack Detection - Rare capability
- Whitelist - 40+ trusted services (no false positives)
- Bilingual - Arabic + English interface
- Privacy First - No images stored
- Open Source - MIT License
- URL Unshortening - Reveals hidden destinations
- IoT Malware Detection - Mirai, botnets
- Real-time - less than 3 seconds
- Transparent - Every decision explained

## Tech Stack

- Python 3
- zxing-cpp - QR code decoding
- LightGBM - Machine Learning classifier
- python-whois - Domain analysis
- VirusTotal API - 70+ antivirus engines
- URLhaus API - Malicious URL database
- Streamlit - Web interface
- GitHub - Version control

## Privacy

- Your images are NOT stored
- Analysis happens in real-time
- No data is logged
- 100% local processing

## Use Cases

- Employees - Check QR codes in emails
- Students - Verify assignment QRs
- Banking - Check payment QRs
- Restaurants - Verify menu QRs
- Public - Any QR from unknown sources
- Cybersecurity Training - Educational resource

## Run Locally

Step 1: git clone https://github.com/hssoooni/AmanQR.git

Step 2: cd AmanQR

Step 3: pip install -r requirements.txt

Step 4: streamlit run app/streamlit_app.py

## Disclaimer

This tool is advisory. Always verify sensitive QR codes manually before sharing personal information.

## License

MIT License - Free to use, modify, and distribute.

## Acknowledgments

- Dataset: Kaggle - Malicious and Benign QR Codes by Samah Sadiq (200,000 QR codes)
- VirusTotal: Antivirus API (70+ engines)
- URLhaus (abuse.ch): Malicious URL database
- Streamlit Community Cloud: Free hosting

## Contact

- GitHub: https://github.com/hssoooni
- Live App: https://amanqr-3bjyry2nfnxf5d2rbrezdy.streamlit.app

---

Made with love for the community

AmanQR - حماية المجتمع من هجمات QR
