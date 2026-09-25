# AmanQR

**Free QR Code Safety Checker**

AmanQR is a free, open-source tool that analyzes QR codes and detects malicious content (phishing, malware, scam URLs) in real time.

## Try it Live

Link: https://amanqr-3bjry2nfnxf5d2rbreezy.streamlit.app

No installation needed. Just upload a QR image.

## What it Detects

- Phishing - Fake login pages, email impersonation
- Malicious domains - Suspicious TLDs (.xyz, .tk), new domains
- Hacked sites - Compromised admin panels, exposed files
- Brand impersonation - Typosquatting (paypa1, goog1e)
- Suspicious patterns - Random paths, IP addresses, shorteners

## How it Works

AmanQR uses a 4-layer hybrid detection system:

1. QR Decoder (OpenCV) - Extracts URL from image
2. URL Analyzer (18 rules) - Pattern-based threat detection
3. WHOIS Checker - Domain age and hidden WHOIS detection
4. Decision Engine - Combines signals with confidence scoring

## Tech Stack

- Python 3
- OpenCV - QR decoding
- python-whois - Domain analysis
- Streamlit - Web interface
- 18 detection rules - Handcrafted threat patterns

## Privacy

- Your images are NOT stored
- Analysis happens in real-time
- No data is logged
- 100 percent local processing

## Use Cases

- Employees checking QR codes in emails
- Students verifying QR assignments
- Banking customers scanning payment QRs
- Restaurant menus safety check
- Anyone scanning a QR from an unknown source

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

Dataset: Kaggle - Malicious and Benign QR Codes by Samah Sadiq (200,000 QR codes)

## Contact

GitHub: https://github.com/hssoooni

---

Made with love for the community
