
"""
AmanQR - QR Code Decoder Module
Uses OpenCV's built-in QR detector (no external deps).
"""
import cv2


def decode_qr(image_path_or_array):
    """
    Decode QR from image path or numpy array.
    Returns: decoded text or None
    """
    if isinstance(image_path_or_array, str):
        img = cv2.imread(image_path_or_array)
    else:
        img = image_path_or_array
    
    if img is None:
        return None
    
    try:
        detector = cv2.QRCodeDetector()
        data, points, _ = detector.detectAndDecode(img)
        if data:
            return data
    except Exception:
        pass
    
    return None
