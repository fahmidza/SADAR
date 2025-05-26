# Pipeline Step 1: OCR (Optical Character Recognition)
# Menggunakan Tesseract OCR untuk membaca teks dari screenshot

# Install Tesseract OCR terlebih dahulu jika belum terpasang:

import pytesseract
from PIL import Image
import os

def extract_text_from_image(image_path):
    """
    Mengambil teks dari gambar menggunakan Tesseract OCR.
    Pastikan Tesseract sudah terinstall dan path-nya terdeteksi.
    """
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"File tidak ditemukan: {image_path}")

    # Membuka gambar
    image = Image.open(image_path)

    # Menggunakan pytesseract untuk ekstraksi teks
    extracted_text = pytesseract.image_to_string(image, lang='eng')

    return extracted_text