import random
import time
import hashlib
import secrets
from datetime import datetime, timedelta
import json
import os
from typing import Dict, List, Tuple, Optional

class OTPService:
    def __init__(self, otp_expiry_minutes: int = 5, max_attempts: int = 3):
        self.otp_expiry_minutes = otp_expiry_minutes
        self.max_attempts = max_attempts
        self.pending_verifications = {}
        self.failed_attempts = {}
        
    def generate_otp(self, length: int = 6) -> str:
        """Generate a random numeric OTP"""
        return ''.join(random.choices('0123456789', k=length))
    
    def send_otp_email(self, email: str, otp: str) -> bool:
        """
        Send OTP via email (mock implementation)
        In production, integrate with actual email service
        """
        try:
            # Mock email sending - replace with actual email service
            print(f"Sending OTP to {email}: {otp}")
            print(f"Email content: Your verification code is: {otp}")
            return True
        except Exception as e:
            print(f"Failed to send email: {e}")
            return False
    
    def send_otp_sms(self, phone: str, otp: str) -> bool:
        """
        Send OTP via SMS (mock implementation)
        In production, integrate with SMS service
        """
        try:
            # Mock SMS sending
            print(f"Sending OTP to {phone}: {otp}")
            return True
        except Exception as e:
            print(f"Failed to send SMS: {e}")
            return False
    
    def initiate_verification(self, identifier: str, method: str = "email") -> Tuple[bool, str]:
        """Initiate OTP verification process"""
        if identifier in self.pending_verifications:
            # Prevent spam - limit OTP requests
            last_request = self.pending_verifications[identifier]['created_at']
            if datetime.now() - last_request < timedelta(minutes=1):
                return False, "Please wait before requesting another OTP"
        
        otp = self.generate_otp()
        expiry_time = datetime.now() + timedelta(minutes=self.otp_expiry_minutes)
        
        # Store OTP with expiry and attempt count
        self.pending_verifications[identifier] = {
            'otp': otp,
            'expiry_time': expiry_time,
            'attempts': 0,
            'created_at': datetime.now()
        }
        
        # Reset failed attempts for this identifier
        self.failed_attempts[identifier] = 0
        
        # Send OTP based on method
        success = False
        if method == "email":
            success = self.send_otp_email(identifier, otp)
        elif method == "sms":
            success = self.send_otp_sms(identifier, otp)
        
        if success:
            return True, "OTP sent successfully"
        else:
            del self.pending_verifications[identifier]
            return False, "Failed to send OTP"
    
    def verify_otp(self, identifier: str, user_otp: str) -> Tuple[bool, str]:
        """Verify the provided OTP"""
        if identifier not in self.pending_verifications:
            return False, "No pending verification found"
        
        verification_data = self.pending_verifications[identifier]
        
        # Check if OTP has expired
        if datetime.now() > verification_data['expiry_time']:
            del self.pending_verifications[identifier]
            return False, "OTP has expired"
        
        # Check attempt limit
        if verification_data['attempts'] >= self.max_attempts:
            del self.pending_verifications[identifier]
            return False, "Too many failed attempts"
        
        verification_data['attempts'] += 1
        
        # Verify OTP
        if user_otp == verification_data['otp']:
            # Successful verification
            del self.pending_verifications[identifier]
            self.failed_attempts[identifier] = 0
            return True, "Verification successful"
        else:
            # Failed attempt
            self.failed_attempts[identifier] = self.failed_attempts.get(identifier, 0) + 1
            remaining_attempts = self.max_attempts - verification_data['attempts']
            return False, f"Invalid OTP. {remaining_attempts} attempts remaining"


class UserManager:
    ROLES = ["community_health_worker", "doctor", "supervisor"]
    
    def __init__(self, data_file: str = "users.json"):
        self.data_file = data_file
        self.users = self.load_users()
        
        # Create default admin/supervisor if no users exist
        if not self.users:
            self.create_default_admin()
    
    def load_users(self) -> Dict:
        """Load users from JSON file"""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def save_users(self):
        """Save users to JSON file"""
        with open(self.data_file, 'w') as f:
            json.dump(self.users, f, indent=2)
    
    def create_default_admin(self):
        """Create a default supervisor account if no users exist"""
        hashed_password = self.hash_password("admin123")
        self.users["supervisor_admin"] = {
            'email': "supervisor@health.org",
            'password': hashed_password,
            'role': "supervisor",
            'full_name': "Default Supervisor",
            'phone': "+1234567890",
            'created_at': datetime.now().isoformat(),
            'is_verified': True
        }
        self.save_users()
        print("Default supervisor account created:")
        print("Username: supervisor_admin")
        print("Password: admin123")
        print("Please change the password after first login!")
    
    def hash_password(self, password: str) -> str:
        """Hash password using SHA-256 with salt"""
        salt = secrets.token_hex(16)
        hashed = hashlib.sha256((password + salt).encode()).hexdigest()
        return f"{salt}${hashed}"
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        if '$' not in hashed_password:
            return False
        
        salt, stored_hash = hashed_password.split('$', 1)
        computed_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        return computed_hash == stored_hash
    
    def register_user(self, username: str, user_data: Dict) -> Tuple[bool, str]:
        """Register a new user with role"""
        if username in self.users:
            return False, "Username already exists"
        
        if user_data['email'] in [user['email'] for user in self.users.values()]:
            return False, "Email already registered"
        
        # Validate role
        if user_data['role'] not in self.ROLES:
            return False, f"Invalid role. Must be one of: {', '.join(self.ROLES)}"
        
        # Hash password
        user_data['password'] = self.hash_password(user_data['password'])
        user_data['created_at'] = datetime.now().isoformat()
        user_data['is_verified'] = False
        
        self.users[username] = user_data
        self.save_users()
        return True, "Registration successful. Please verify your email."
    
    def verify_user_email(self, username: str) -> bool:
        """Mark user email as verified"""
        if username in self.users:
            self.users[username]['is_verified'] = True
            self.save_users()
            return True
        return False
    
    def authenticate_user(self, username: str, password: str) -> Tuple[bool, str, Optional[Dict]]:
        """Authenticate user with password and return user data if successful"""
        if username not in self.users:
            return False, "Invalid credentials", None
        
        user = self.users[username]
        if not self.verify_password(password, user['password']):
            return False, "Invalid credentials", None
        
        if not user.get('is_verified', False):
            return False, "Please verify your email first", None
        
        # Return user data without password
        user_data = user.copy()
        user_data.pop('password', None)
        return True, "Authentication successful", user_data
    
    def get_users_by_role(self, role: str) -> List[Dict]:
        """Get all users with a specific role"""
        if role not in self.ROLES:
            return []
        
        return [{"username": un, **{k: v for k, v in data.items() if k != 'password'}} 
                for un, data in self.users.items() if data.get('role') == role]
    
    def change_password(self, username: str, old_password: str, new_password: str) -> Tuple[bool, str]:
        """Change user password"""
        if username not in self.users:
            return False, "User not found"
        
        if not self.verify_password(old_password, self.users[username]['password']):
            return False, "Current password is incorrect"
        
        self.users[username]['password'] = self.hash_password(new_password)
        self.save_users()
        return True, "Password changed successfully"


class AuthenticationSystem:
    def __init__(self):
        self.otp_service = OTPService()
        self.user_manager = UserManager()
        self.sessions = {}
        self.current_user = None
    
    def generate_user_id(self) -> str:
        """Generate a unique user ID"""
        return secrets.token_urlsafe(8)
    
    def register(self):
        """User registration flow with role selection"""
        print("\n=== Registration ===")
        
        # Get user role
        print("Select your role:")
        for i, role in enumerate(self.user_manager.ROLES, 1):
            print(f"{i}. {role.replace('_', ' ').title()}")
        
        try:
            role_choice = int(input("Enter role number: ").strip())
            if role_choice < 1 or role_choice > len(self.user_manager.ROLES):
                print("Invalid role selection")
                return
            role = self.user_manager.ROLES[role_choice-1]
        except ValueError:
            print("Please enter a valid number")
            return
        
        # Get user details
        username = input("Enter username: ").strip()
        email = input("Enter email: ").strip()
        phone = input("Enter phone number: ").strip()
        full_name = input("Enter full name: ").strip()
        password = input("Enter password: ").strip()
        confirm_password = input("Confirm password: ").strip()
        
        if password != confirm_password:
            print("Passwords do not match")
            return
        
        user_data = {
            'email': email,
            'phone': phone,
            'full_name': full_name,
            'role': role,
            'password': password
        }
        
        success, message = self.user_manager.register_user(username, user_data)
        print(message)
        
        if success:
            # Initiate email verification
            success, msg = self.otp_service.initiate_verification(email, "email")
            print(msg)
            if success:
                self.verify_email_after_registration(email, username)
    
    def verify_email_after_registration(self, email: str, username: str):
        """Handle email verification after registration"""
        print("\n=== Email Verification ===")
        otp = input("Enter OTP sent to your email: ").strip()
        
        success, message = self.otp_service.verify_otp(email, otp)
        print(message)
        
        if success:
            self.user_manager.verify_user_email(username)
            print("Email verified successfully! You can now login.")
    
    def login(self):
        """User login flow with role-based access"""
        print("\n=== Login ===")
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        
        # First verify password and get user data
        success, message, user_data = self.user_manager.authenticate_user(username, password)
        if not success:
            print(message)
            return
        
        # If password is correct, initiate OTP verification
        user_email = user_data['email']
        success, msg = self.otp_service.initiate_verification(user_email, "email")
        print(msg)
        
        if success:
            self.verify_otp_for_login(user_email, username, user_data)
    
    def verify_otp_for_login(self, email: str, username: str, user_data: Dict):
        """Handle OTP verification for login"""
        print("\n=== OTP Verification ===")
        otp = input("Enter OTP sent to your email: ").strip()
        
        success, message = self.otp_service.verify_otp(email, otp)
        print(message)
        
        if success:
            # Create session
            session_token = secrets.token_urlsafe(32)
            self.sessions[session_token] = {
                'username': username,
                'user_data': user_data,
                'login_time': datetime.now().isoformat()
            }
            self.current_user = username
            print(f"\n🎉 Login successful! Welcome {user_data['full_name']}")
            print(f"Role: {user_data['role'].replace('_', ' ').title()}")
            print(f"Session token: {session_token}")
            
            # Show role-specific dashboard
            self.show_dashboard(user_data)
    
    def show_dashboard(self, user_data: Dict):
        """Show role-specific dashboard after login"""
        role = user_data['role']
        print(f"\n=== {role.replace('_', ' ').title()} Dashboard ===")
        
        if role == "community_health_worker":
            print("1. View Patient Records")
            print("2. Add Health Data")
            print("3. Schedule Visits")
            print("4. Generate Reports")
            
        elif role == "doctor":
            print("1. View Patient History")
            print("2. Prescribe Medication")
            print("3. Review Test Results")
            print("4. Consult with Specialists")
            
        elif role == "supervisor":
            print("1. Manage Health Workers")
            print("2. View System Analytics")
            print("3. Generate Performance Reports")
            print("4. Manage System Settings")
            
            # Show all users for supervisor
            print("\n=== User Management ===")
            for role_type in self.user_manager.ROLES:
                users = self.user_manager.get_users_by_role(role_type)
                print(f"\n{role_type.replace('_', ' ').title()}s ({len(users)}):")
                for user in users:
                    print(f"  - {user['username']}: {user['full_name']} ({user['email']})")
        
        print("\n5. Change Password")
        print("6. Logout")
        
        choice = input("Select an option: ").strip()
        self.handle_dashboard_choice(choice, user_data)
    
    def handle_dashboard_choice(self, choice: str, user_data: Dict):
        """Handle dashboard menu choices"""
        if choice == "5":
            self.change_password()
        elif choice == "6":
            self.logout()
        else:
            role = user_data['role']
            print(f"Option {choice} selected for {role} (functionality to be implemented)")
            input("Press Enter to continue...")
            self.show_dashboard(user_data)
    
    def change_password(self):
        """Change password functionality"""
        if not self.current_user:
            print("Not logged in")
            return
        
        print("\n=== Change Password ===")
        old_password = input("Enter current password: ").strip()
        new_password = input("Enter new password: ").strip()
        confirm_password = input("Confirm new password: ").strip()
        
        if new_password != confirm_password:
            print("Passwords do not match")
            return
        
        success, message = self.user_manager.change_password(self.current_user, old_password, new_password)
        print(message)
        
        if success:
            input("Press Enter to continue...")
            self.show_dashboard(self.user_manager.users[self.current_user])
    
    def logout(self):
        """Logout current user"""
        if self.current_user:
            print(f"Goodbye, {self.current_user}!")
            self.current_user = None
        else:
            print("Not logged in")
    
    def forgot_password(self):
        """Password reset flow"""
        print("\n=== Forgot Password ===")
        email = input("Enter your email: ").strip()
        
        # Find user by email
        user = None
        for username, user_data in self.user_manager.users.items():
            if user_data['email'] == email:
                user = username
                break
        
        if not user:
            print("Email not found")
            return
        
        # Send OTP for password reset
        success, msg = self.otp_service.initiate_verification(email, "email")
        print(msg)
        
        if success:
            self.reset_password_with_otp(email, user)
    
    def reset_password_with_otp(self, email: str, username: str):
        """Reset password after OTP verification"""
        print("\n=== Password Reset ===")
        otp = input("Enter OTP sent to your email: ").strip()
        
        success, message = self.otp_service.verify_otp(email, otp)
        if not success:
            print(message)
            return
        
        # OTP verified, allow password reset
        new_password = input("Enter new password: ").strip()
        confirm_password = input("Confirm new password: ").strip()
        
        if new_password != confirm_password:
            print("Passwords do not match")
            return
        
        # Update password
        hashed_password = self.user_manager.hash_password(new_password)
        self.user_manager.users[username]['password'] = hashed_password
        self.user_manager.save_users()
        print("Password reset successfully!")


def main():
    auth_system = AuthenticationSystem()
    
    while True:
        print("\nHealth System Authentication")
        print("1. Register")
        print("2. Login")
        print("3. Forgot Password")
        print("4. Exit")
        
        choice = input("Choose an option (1-4): ").strip()
        
        if choice == "1":
            auth_system.register()
        elif choice == "2":
            auth_system.login()
        elif choice == "3":
            auth_system.forgot_password()
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()