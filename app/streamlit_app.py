
"""
AmanQR - Streamlit Web Interface
A free tool to check QR codes for malicious content.
"""
import streamlit as st
import cv2
import numpy as np
from PIL import Image
import io
import sys
import os
_current_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(_current_dir)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from src.qr_decoder import decode_qr
from src.decision_engine import decide


# ============================================================
# Page config
# ============================================================
st.set_page_config(
    page_title="AmanQR - QR Safety Check",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="expanded",
)

# ============================================================
# Custom CSS
# ============================================================
st.markdown("""
    <style>
    .main-header {
        text-align: center;
        padding: 1rem 0;
    }
    .main-header h1 {
        color: #1E88E5;
        font-size: 2.5rem;
        margin-bottom: 0.5rem;
    }
    .main-header p {
        color: #555;
        font-size: 1.1rem;
    }
    .result-box {
        padding: 2rem;
        border-radius: 15px;
        text-align: center;
        margin: 1.5rem 0;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .result-benign {
        background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
        border: 3px solid #28a745;
    }
    .result-suspicious {
        background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%);
        border: 3px solid #ffc107;
    }
    .result-malicious {
        background: linear-gradient(135deg, #f8d7da 0%, #f5c6cb 100%);
        border: 3px solid #dc3545;
    }
    .result-box h2 {
        font-size: 2rem;
        margin: 0.5rem 0;
    }
    .result-box p {
        font-size: 1.1rem;
        margin: 0.3rem 0;
    }
    .reason-item {
        background: #f8f9fa;
        padding: 0.6rem 1rem;
        border-radius: 8px;
        margin: 0.4rem 0;
        border-right: 4px solid #1E88E5;
        direction: rtl;
        text-align: right;
    }
    .stButton>button {
        width: 100%;
        background: #1E88E5;
        color: white;
        font-weight: bold;
        padding: 0.6rem 0;
        border-radius: 8px;
    }
    .stButton>button:hover {
        background: #1565C0;
    }
    </style>
""", unsafe_allow_html=True)


# ============================================================
# Header
# ============================================================
st.markdown("""
    <div class="main-header">
        <h1>🛡️ AmanQR</h1>
        <p>أداة مجانية للتحقق من أمان أكواد QR</p>
        <p><i>Free QR Code Safety Checker</i></p>
    </div>
""", unsafe_allow_html=True)


# ============================================================
# Sidebar
# ============================================================
with st.sidebar:
    st.header("ℹ️ About AmanQR")
    st.markdown("""
    **AmanQR** analyzes QR codes and their embedded URLs to detect:
    
    - 🎣 Phishing attacks
    - 🚨 Malicious domains
    - ⚠️ Suspicious patterns
    
    ---
    
    ### 🔒 Privacy
    - Your images are **NOT stored**
    - Analysis happens **in real-time**
    - No data is logged
    
    ---
    
    ### ⚠️ Disclaimer
    This tool is **advisory**. Always verify
    sensitive QR codes manually.
    """)
    
    st.markdown("---")
    st.caption("v1.0 | Free & Open Source")


# ============================================================
# Main content
# ============================================================
st.markdown("### 📤 Upload a QR Code Image")
st.markdown("ارفع صورة كود QR للتحقق منها")

uploaded_file = st.file_uploader(
    "Choose a QR code image...",
    type=["png", "jpg", "jpeg", "webp"],
    help="Supported formats: PNG, JPG, JPEG, WEBP",
)

# Alternative: Camera input
st.markdown("**Or**")
camera_image = st.camera_input("📷 Take a photo of a QR code")


# ============================================================
# Process
# ============================================================
image_source = uploaded_file if uploaded_file else camera_image

if image_source is not None:
    # Load image
    image_bytes = image_source.read() if hasattr(image_source, 'read') else image_source
    pil_image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    img_array = np.array(pil_image)
    
    # Display image
    col1, col2 = st.columns([1, 1])
    with col1:
        st.image(pil_image, caption="Uploaded QR Code", use_container_width=True)
    
    # Decode QR
    with st.spinner("🔍 Analyzing..."):
        rgb_for_decoder = cv2.cvtColor(img_array, cv2.COLOR_RGB2BGR)
        decoded_url = decode_qr(rgb_for_decoder)
        
        # Clean URL for display (remove pandas artifacts)
        if decoded_url:
            import re as _re
            clean_display = _re.split(r'\s*Name:', decoded_url)[0]
            clean_display = _re.sub(r'^\d+\s+', '', clean_display)
            clean_display = clean_display.replace('\n', ' ').strip()
            if 'http' in clean_display.lower():
                clean_display = clean_display[clean_display.lower().index('http'):]
            decoded_url_clean = clean_display
        else:
            decoded_url_clean = decoded_url
        
        result = decide(decoded_url)
        result['display_url'] = decoded_url_clean
    
    # Display result
    with col2:
        st.markdown("### 📊 Result")
        
        if result["verdict"] == "ERROR":
            st.warning("⚠️ Could not decode QR code")
            st.info("Please ensure the image is clear and contains a valid QR code.")
        else:
            # Result box
            css_class = f"result-{result['verdict'].lower()}"
            st.markdown(f"""
                <div class="result-box {css_class}">
                    <h2>{result['emoji']} {result['verdict']}</h2>
                    <p><b>Confidence:</b> {result['confidence']:.0f}%</p>
                    <p><b>Threat Score:</b> {result['score']:.0f}/100</p>
                </div>
            """, unsafe_allow_html=True)
    
    # Show decoded URL + reasons (full width)
    if result["verdict"] != "ERROR":
        st.markdown("---")
        st.markdown("### 🔗 Decoded URL")
        display_url = result.get('display_url', result.get('url', ''))
        st.code(display_url, language=None)
        
        st.markdown("### 📋 Detection Reasons")
        st.markdown("*الأسباب / Reasons:*")
        for reason in result['reasons']:
            st.markdown(f'<div class="reason-item">• {reason}</div>', unsafe_allow_html=True)


# ============================================================
# Footer
# ============================================================
st.markdown("---")
st.markdown("""
    <div style="text-align: center; color: #888; font-size: 0.9rem;">
    <p>🛡️ <b>AmanQR</b> — Free QR Code Safety Checker</p>
    <p>Made with ❤️ for the community</p>
    </div>
""", unsafe_allow_html=True)
