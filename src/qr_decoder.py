"""
AmanQR - QR Decoder with Preprocessing
Handles real-world photos (low light, tilted, blurry)
"""
import cv2
import numpy as np


def preprocess_image(img):
    """Apply multiple preprocessing techniques"""
    if not isinstance(img, np.ndarray):
        return None, None, None
    
    # Convert to grayscale
    if len(img.shape) == 3:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    else:
        gray = img.copy()
    
    # Resize if too small
    h, w = gray.shape
    if max(h, w) < 400:
        scale = 400 / max(h, w)
        gray = cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
    
    # Denoise
    denoised = cv2.fastNlMeansDenoising(gray, None, 10, 7, 21)
    
    # Apply adaptive thresholding
    thresh = cv2.adaptiveThreshold(
        denoised, 255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY,
        11, 2
    )
    
    return gray, denoised, thresh


def decode_qr(image_path_or_array):
    """
    Decode QR from image with multiple preprocessing attempts.
    """
    if isinstance(image_path_or_array, str):
        img = cv2.imread(image_path_or_array)
    else:
        img = image_path_or_array
    
    if img is None:
        return None
    
    # Attempt 1: zxing-cpp on original
    try:
        import zxingcpp
        results = zxingcpp.read_barcodes(img)
        if results:
            return results[0].text
    except Exception:
        pass
    
    # Attempt 2: OpenCV on original
    try:
        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(img)
        if data:
            return data
    except Exception:
        pass
    
    # Attempt 3: Preprocessing
    try:
        gray, denoised, thresh = preprocess_image(img)
        
        for variant in [gray, denoised, thresh]:
            if variant is None:
                continue
            
            try:
                import zxingcpp
                results = zxingcpp.read_barcodes(variant)
                if results:
                    return results[0].text
            except Exception:
                pass
            
            try:
                detector = cv2.QRCodeDetector()
                data, _, _ = detector.detectAndDecode(variant)
                if data:
                    return data
            except Exception:
                pass
    except Exception:
        pass
    
    # Attempt 4: Rotations
    try:
        for angle in [90, 180, 270]:
            if angle == 90:
                rotated = cv2.rotate(img, cv2.ROTATE_90_CLOCKWISE)
            elif angle == 180:
                rotated = cv2.rotate(img, cv2.ROTATE_180)
            else:
                rotated = cv2.rotate(img, cv2.ROTATE_90_COUNTERCLOCKWISE)
            
            try:
                import zxingcpp
                results = zxingcpp.read_barcodes(rotated)
                if results:
                    return results[0].text
            except Exception:
                pass
    except Exception:
        pass
    
    return None
