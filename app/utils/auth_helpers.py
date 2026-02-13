import pyotp
import qrcode
import io
import base64
from ..config import Config

def generate_otp_secret():
    """Generate a new OTP secret for 2FA"""
    return pyotp.random_base32()

def verify_totp(secret, token):
    """Verify a TOTP token"""
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)
    except Exception:
        return False

def generate_qr_code(username, secret):
    """Generate QR code for 2FA setup"""
    try:
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name=Config.APP_NAME
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64 for embedding in HTML
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_str = base64.b64encode(img_buffer.getvalue()).decode()
        
        return img_str
    except Exception as e:
        print(f"Error generating QR code: {e}")
        return None

def get_domain_access_info(email):
    """Get access information based on email domain"""
    if not email:
        return {'access_level': 'basic', 'description': 'Basic access'}
    
    domain = email.split('@')[-1].lower()
    return Config.DOMAIN_ACCESS.get(domain, {
        'access_level': 'basic',
        'description': 'Basic access - requires admin approval'
    })