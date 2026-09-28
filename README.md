# AmanQR

**Free QR Code Safety Checker**

AmanQR is a free, open-source tool that analyzes QR codes and detects malicious content (phishing, malware, scam URLs) in real time.

## Try it Live

Link: https://amanqr-3bjyry2nfnxf5d2rbrezdy.streamlit.app

No installation needed. Just upload a QR image.

## What it Detects

- Phishing attacks - Fake login pages, email impersonation
- Malicious domains - Suspicious TLDs, new domains, hacked sites
- Brand impersonation - Typosquatting (paypa1, goog1e), fake PayPal/Apple/Microsoft
- Hacked websites - Compromised admin panels, exposed files
- Suspicious patterns - Random paths, IP addresses, URL shorteners
- Quishing attacks - QR-specific phishing threats

## How it Works

AmanQR uses a 5-layer hybrid detection system:

### Layer 1: QR Decoder
- zxing-cpp (fast and accurate)
- Extracts URL from QR image

### Layer 2: URL Analyzer (25+ rules)
- Phishing keywords detection
- Typosquatting detection (Levenshtein distance)
- Suspicious TLDs (.xyz, .tk, .online)
- Brand impersonation
- Random path detection
- IP address detection

### Layer 3: WHOIS Checker
- Domain age analysis
- Hidden WHOIS detection
- New domain flags

### Layer 4: Machine Learning (LightGBM)
- 28 engineered features
- Trained on 200,000 QR codes
- 99.5 percent accuracy on hold-out test set
- Features include: URL entropy, vowel ratio, domain length, subdomain count

### Layer 5: External APIs
- VirusTotal: 70+ antivirus engines
- URLhaus: abuse.ch malicious URL database

## Results

Test Accuracy: 99.5 percent
Dataset: 200,000 QR codes (Kaggle - Samah Sadiq)
Features: 28
Model Size: 611 KB
Response Time: less than 3 seconds

## What Makes AmanQR Different

- 100 percent Free - No hidden costs
- Bilingual - Arabic and English interface
- Privacy First - Images are NOT stored
- Open Source - MIT License
- Fast - Real-time analysis
- Transparent - Every decision is explained
- Available Everywhere - Works on any device

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
- 100 percent local processing

## Use Cases

- Employees checking QR codes in company emails
- Students verifying QR assignments
- Banking customers scanning payment QRs
- Restaurant menus safety check
- Anyone scanning a QR from an unknown source
- Cybersecurity awareness training

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
- VirusTotal - Antivirus API
- URLhaus (abuse.ch) - Malicious URL database
- Streamlit Community Cloud - Free hosting

## Contact

GitHub: https://github.com/hssoooni

---

Made with love for the community
