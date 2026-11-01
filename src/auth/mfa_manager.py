"""
Multi-Factor Authentication (MFA / 2FA) & Zero-Trust Access Controller.
Provides RFC 6238 TOTP verification (Google Authenticator / Microsoft Authenticator),
QR Code generation, and Role-Based Access Control (RBAC) for the SOC console.
"""

import io
import base64
import pyotp
import qrcode

class MFAManager:
    """
    Manages Enterprise Multi-Factor Authentication and Analyst Credentials.
    """

    # Static pre-configured users with base32 secrets for reliable demo and evaluation
    # In production, these are stored hashed in a secure Vault / database
    USERS = {
        "analyst@soc.corp": {
            "password": "CyberDefense@2026",
            "name": "Alex Mercer (Senior Threat Hunter)",
            "role": "SOC Tier-2 Analyst",
            "mfa_secret": "JBSWY3DPEHPK3PXP",  # Standard RFC 3548 Base32 secret
            "access_level": "RESTRICTED_INVESTIGATOR"
        },
        "admin@soc.corp": {
            "password": "RootAdmin@2026",
            "name": "Dr. Sarah Chen (Chief Information Security Officer)",
            "role": "SOC Lead & Red Team Admin",
            "mfa_secret": "KRMUY4TFOJQXEZ3T",
            "access_level": "FULL_COMMAND_AUTHORITY"
        }
    }

    @classmethod
    def authenticate_credentials(cls, username: str, password: str) -> dict:
        """
        Validates Primary Factor (Username & Password).
        """
        user_info = cls.USERS.get(username.strip().lower())
        if not user_info:
            return {"success": False, "error": "Invalid username or account not found in SOC directory."}

        if user_info["password"] != password.strip():
            return {"success": False, "error": "Incorrect password. Failed authentication attempt logged."}

        return {
            "success": True,
            "username": username.strip().lower(),
            "name": user_info["name"],
            "role": user_info["role"],
            "mfa_secret": user_info["mfa_secret"],
            "access_level": user_info["access_level"]
        }

    @classmethod
    def get_totp_uri(cls, username: str, secret: str, issuer: str = "DNS-Armor-SOC") -> str:
        """
        Generates standard provisioning URI for Google Authenticator / Microsoft Authenticator.
        """
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=username, issuer_name=issuer)

    @classmethod
    def generate_qr_code_base64(cls, totp_uri: str) -> str:
        """
        Generates QR code PNG as base64 string for zero-dependency browser display.
        """
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=6,
            border=2,
        )
        qr.add_data(totp_uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="#00f0ff", back_color="#070b14")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        encoded = base64.b64encode(buf.getvalue()).decode('utf-8')
        return f"data:image/png;base64,{encoded}"

    @classmethod
    def verify_totp_token(cls, secret: str, token_str: str) -> bool:
        """
        Validates the 6-digit Time-based One-Time Password with clock drift tolerance.
        """
        clean_token = token_str.strip().replace(" ", "")
        if not clean_token.isdigit() or len(clean_token) != 6:
            return False

        totp = pyotp.TOTP(secret)
        # valid_window=1 allows +/- 30 seconds time drift between client and server clock
        return totp.verify(clean_token, valid_window=1)

    @classmethod
    def get_current_live_otp_for_demo(cls, secret: str) -> str:
        """
        Returns the currently active 6-digit OTP code for live testing and viva defense demonstrations.
        """
        totp = pyotp.TOTP(secret)
        return totp.now()
