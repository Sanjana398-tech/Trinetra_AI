"""
TRINETRA AI - QR Code Decoding
=================================
Decodes an uploaded QR code image using OpenCV's built-in
QRCodeDetector. Deliberately avoids the pyzbar/libzbar system
dependency — cv2 (already a project dependency) can decode QR codes
on its own, which keeps installation simpler across platforms.
"""

import cv2


def decode_qr(image_path: str):
    """
    Decode the first QR code found in an image file.

    Returns (data, error):
        data  - decoded string, or None if nothing was found/decodable
        error - human-readable reason when data is None, else None
    """
    image = cv2.imread(image_path)
    if image is None:
        return None, "Couldn't read that file as an image. Try a PNG, JPG, or WEBP screenshot."

    detector = cv2.QRCodeDetector()
    try:
        data, points, _ = detector.detectAndDecode(image)
    except cv2.error:
        return None, "This image couldn't be processed. Try a clearer, uncropped screenshot of the QR code."

    if not data:
        # Try again on a larger version — small/low-res QR crops often fail first try.
        try:
            upscaled = cv2.resize(image, None, fx=1.8, fy=1.8, interpolation=cv2.INTER_CUBIC)
            data, points, _ = detector.detectAndDecode(upscaled)
        except cv2.error:
            data = ""

    if not data:
        return None, "No QR code could be detected in this image. Make sure it's clear, upright, and not cropped."

    return data, None
