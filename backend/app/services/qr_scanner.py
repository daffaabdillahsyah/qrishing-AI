from PIL import Image
from pyzbar.pyzbar import decode
from io import BytesIO
from typing import Optional, Dict
import magic
from .url_scanner import URLScanner

class QRScanner:
    def __init__(self):
        self.url_scanner = URLScanner()
        
    def _is_valid_image(self, file_content: bytes) -> bool:
        """Check if the uploaded file is a valid image."""
        mime = magic.Magic(mime=True)
        file_type = mime.from_buffer(file_content)
        return file_type.startswith('image/')
        
    def scan_qr_code(self, file_content: bytes) -> Dict:
        """
        Scan QR code from image and analyze the URL for phishing.
        Returns:
            Dict containing:
            - success: bool
            - message: str
            - url: Optional[str]
            - scan_result: Optional[Dict] - URL scan results if URL found
        """
        try:
            if not self._is_valid_image(file_content):
                return {
                    "success": False,
                    "message": "Invalid file type. Please upload an image file.",
                    "url": None,
                    "scan_result": None
                }
            
            # Open image using PIL
            image = Image.open(BytesIO(file_content))
            
            # Decode QR code
            decoded_objects = decode(image)
            
            if not decoded_objects:
                return {
                    "success": False,
                    "message": "No QR code found in the image.",
                    "url": None,
                    "scan_result": None
                }
            
            # Get URL from QR code
            qr_data = decoded_objects[0].data.decode('utf-8')
            
            # Analyze URL for phishing
            scan_result = self.url_scanner.scan_url(qr_data)
            
            return {
                "success": True,
                "message": "QR code successfully scanned and analyzed.",
                "url": qr_data,
                "scan_result": scan_result
            }
            
        except Exception as e:
            return {
                "success": False,
                "message": f"Error processing QR code: {str(e)}",
                "url": None,
                "scan_result": None
            } 