"""
Reset Admin 2FA

This script is used to reset the admin user's 2FA settings in case they get locked out.
It will:
1. Find the admin user
2. Disable 2FA for that user
3. Save changes to the database

Run this script directly with:
python reset_admin_2fa.py
"""

from app import app, db
from app.models import User
import sys

def reset_admin_2fa():
    with app.app_context():
        try:
            # Find admin user
            admin = User.query.filter_by(is_admin=True).first()
            
            if not admin:
                print("Error: No admin user found.")
                return False
            
            # Reset 2FA settings
            admin.is_2fa_enabled = False
            admin.otp_secret = None
            
            # Save changes
            db.session.commit()
            
            print(f"Success: 2FA has been disabled for admin user: {admin.username}")
            print("You can now log in as admin without 2FA.")
            return True
        except Exception as e:
            print(f"Error: {e}")
            return False

if __name__ == "__main__":
    print("Resetting admin 2FA settings...")
    success = reset_admin_2fa()
    sys.exit(0 if success else 1)