import json
import os
from datetime import datetime
from auth.account_manager import AccountManager
from auth.face_recognizer import FaceRecognizer

class AuthSystem:
    def __init__(self, account_manager=None):
        # FIX: accept a shared AccountManager instance instead of always
        # creating a new one. Previously this always did
        # `self.account_manager = AccountManager()`, which silently
        # created a SECOND, separate in-memory AccountManager alongside
        # main_gui.py's own self.account_mgr. Both wrote to the same
        # db/accounts.json file on disk, but neither ever saw the
        # other's in-memory changes — so a user registered mid-session
        # was invisible to main_gui.py's lockout/after-hours-trust
        # checks (which use main_gui.py's self.account_mgr), even
        # though the account genuinely existed on disk. Passing the
        # same instance in from main_gui.py eliminates this desync.
        self.account_manager = account_manager if account_manager is not None else AccountManager()
        self.face_recognizer = FaceRecognizer()
        self.users_file = "db/users.json"
        self.load_users()

    def load_users(self):
        if os.path.exists(self.users_file):
            with open(self.users_file, 'r') as f:
                self.users = json.load(f)
        else:
            self.users = {}

    def save_users(self):
        os.makedirs("db", exist_ok=True)
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f, indent=4)

    def user_exists(self, username):
        return username in self.users

    def create_account(self, username, email, full_name, department, 
                      phone, role="user"):
        """Create new user account."""
        if self.user_exists(username):
            return False, "Username already exists"

        self.account_manager.create_account(username, role=role)

        self.users[username] = {
            "username": username,
            "email": email,
            "full_name": full_name,
            "department": department,
            "phone": phone,
            "role": role,
            "created_at": datetime.now().isoformat(),
            "enrolled": False,
            "enrollment_frames": 0,
            "face_enrolled_at": None,
            "last_login": None,
            "login_count": 0,
            "profile_photo": None
        }
        self.save_users()
        return True, f"Account created for {username}"

    def enroll_face_for_user(self, username, frames):
        """Enroll face for existing user."""
        if not self.user_exists(username):
            return False, "User not found"

        ok = self.face_recognizer.enroll(username, frames)
        if ok:
            self.account_manager.enroll_face(
                username,
                self.face_recognizer.database[username]
            )
            self.users[username]['enrolled'] = True
            self.users[username]['enrollment_frames'] = len(frames)
            self.users[username]['face_enrolled_at'] = (
                datetime.now().isoformat()
            )
            self.save_users()
            return True, f"Face enrolled for {username}"
        return False, "Face enrollment failed"

    def authenticate_user(self, username, frame):
        """Authenticate existing user."""
        if not self.user_exists(username):
            return False, 0.0, "User not found"

        if not self.users[username]['enrolled']:
            return False, 0.0, "User face not enrolled"

        user, conf = self.face_recognizer.recognize(frame)
        
        if user == username and conf > 0.5:
            self.users[username]['last_login'] = (
                datetime.now().isoformat()
            )
            self.users[username]['login_count'] += 1
            self.save_users()
            return True, conf, "Authentication successful"
        return False, conf, "Face not recognized"

    def get_user_info(self, username):
        if not self.user_exists(username):
            return None
        return self.users[username]

    def list_users(self):
        return list(self.users.values())