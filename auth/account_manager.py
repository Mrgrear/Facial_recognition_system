import json
import os
import time
import pickle
import numpy as np
from datetime import datetime

class AccountManager:
    def __init__(self, db_path="db/accounts.json",
                 embedding_path="db/face_db.pkl"):
        self.db_path = db_path
        self.embedding_path = embedding_path
        self.accounts = {}
        self.face_db = {}

        # Lockout settings
        self.max_failed_attempts = 3
        self.max_spoof_attempts = 2
        self.temp_lockout_duration = 300    # 5 minutes
        self.spoof_lockout_duration = 600   # 10 minutes
        self.full_lockout_threshold = 5     # attempts before full lock

        os.makedirs("db", exist_ok=True)
        os.makedirs("logs", exist_ok=True)

        self.load_accounts()
        self.load_face_db()

    # ─────────────────────────────────────────
    # DATABASE MANAGEMENT
    # ─────────────────────────────────────────

    def load_accounts(self):
        if os.path.exists(self.db_path):
            with open(self.db_path, 'r') as f:
                self.accounts = json.load(f)
        else:
            self.accounts = {}

    def save_accounts(self):
        with open(self.db_path, 'w') as f:
            json.dump(self.accounts, f, indent=4)

    def load_face_db(self):
        if os.path.exists(self.embedding_path):
            with open(self.embedding_path, 'rb') as f:
                raw = pickle.load(f)
                # Convert lists back to numpy arrays
                self.face_db = {
                    k: np.array(v) for k, v in raw.items()
                }
        else:
            self.face_db = {}

    def save_face_db(self):
        # Convert numpy arrays to lists for pickle
        saveable = {
            k: v.tolist() for k, v in self.face_db.items()
        }
        with open(self.embedding_path, 'wb') as f:
            pickle.dump(saveable, f)

    # ─────────────────────────────────────────
    # ACCOUNT CREATION
    # ─────────────────────────────────────────

    def create_account(self, username, role="user"):
        if username in self.accounts:
            return False, "Account already exists."

        self.accounts[username] = {
            "username": username,
            "role": role,
            "created_at": datetime.now().isoformat(),
            "failed_attempts": 0,
            "spoof_attempts": 0,
            "total_failed": 0,
            "is_locked": False,
            "lock_type": None,
            "lock_time": None,
            "lock_reason": None,
            "last_login": None,
            "last_failed": None,
            "enrolled": False,
            "recovery_pending": False,
            "login_history": [],
            "after_hours_trusted": False
        }
        self.save_accounts()
        return True, f"Account created for {username}."

    # ─────────────────────────────────────────
    # SINGLE FACE ENFORCEMENT
    # ─────────────────────────────────────────

    def check_single_face(self, face_count):
        """
        Enforce only one face in frame.
        Returns: allowed(bool), message(str)
        """
        if face_count == 0:
            return False, "No face detected. Please face the camera."
        elif face_count == 1:
            return True, "Face detected."
        else:
            return (
                False,
                f"Multiple faces detected ({face_count}). "
                f"Please authenticate alone."
            )

    # ─────────────────────────────────────────
    # LOCKOUT MANAGEMENT
    # ─────────────────────────────────────────

    def is_account_locked(self, username):
        """
        Check if account is locked.
        Returns: locked(bool), reason(str), remaining(int seconds)
        """
        if username not in self.accounts:
            return False, "Account not found.", 0

        acc = self.accounts[username]

        if not acc['is_locked']:
            return False, "", 0

        lock_type = acc.get('lock_type', 'full')

        # Full lockout — admin must unlock
        if lock_type == 'full':
            return (
                True,
                f"Account fully locked: {acc['lock_reason']}. "
                f"Contact admin.",
                -1
            )

        # Temporary lockout — check if expired
        lock_time = acc.get('lock_time')
        if lock_time:
            elapsed = time.time() - lock_time
            if lock_type == 'temp':
                duration = self.temp_lockout_duration
            else:
                duration = self.spoof_lockout_duration

            remaining = duration - elapsed
            if remaining <= 0:
                # Lockout expired — auto unlock
                self.unlock_account(username, auto=True)
                return False, "", 0
            else:
                mins = int(remaining // 60)
                secs = int(remaining % 60)
                return (
                    True,
                    f"Account temporarily locked. "
                    f"Try again in {mins}m {secs}s.",
                    int(remaining)
                )

        return False, "", 0

    def record_failed_attempt(self, username):
        """
        Record a failed login attempt.
        Returns: locked(bool), lock_type(str), message(str)
        """
        if username not in self.accounts:
            return False, None, "Account not found."

        acc = self.accounts[username]
        acc['failed_attempts'] += 1
        acc['total_failed'] += 1
        acc['last_failed'] = datetime.now().isoformat()

        self._log_event(username, "FAILED_LOGIN",
                        f"Attempt {acc['failed_attempts']}")

        # Check thresholds
        if acc['total_failed'] >= self.full_lockout_threshold:
            self._lock_account(
                username, 'full',
                f"Exceeded {self.full_lockout_threshold} "
                f"total failed attempts"
            )
            return (
                True, 'full',
                f"Account locked after "
                f"{self.full_lockout_threshold} failed attempts. "
                f"Contact admin."
            )

        if acc['failed_attempts'] >= self.max_failed_attempts:
            self._lock_account(
                username, 'temp',
                f"Exceeded {self.max_failed_attempts} "
                f"consecutive failed attempts"
            )
            mins = self.temp_lockout_duration // 60
            return (
                True, 'temp',
                f"Too many failed attempts. "
                f"Account locked for {mins} minutes."
            )

        remaining = self.max_failed_attempts - acc['failed_attempts']
        self.save_accounts()
        return (
            False, None,
            f"Authentication failed. "
            f"{remaining} attempt(s) remaining."
        )

    def record_spoof_attempt(self, username):
        """
        Record a spoofing attempt.
        Returns: locked(bool), message(str)
        """
        if username not in self.accounts:
            return False, "Account not found."

        acc = self.accounts[username]
        acc['spoof_attempts'] += 1
        acc['total_failed'] += 1

        self._log_event(username, "SPOOF_ATTEMPT",
                        f"Spoof #{acc['spoof_attempts']}")

        # First spoof — alert only
        if acc['spoof_attempts'] == 1:
            self.save_accounts()
            return (
                False,
                "Spoofing detected! Admin has been alerted."
            )

        # Second spoof — spoof lockout
        if acc['spoof_attempts'] >= self.max_spoof_attempts:
            self._lock_account(
                username, 'spoof',
                "Repeated spoofing detected"
            )
            mins = self.spoof_lockout_duration // 60
            return (
                True,
                f"Repeated spoofing detected. "
                f"Account locked for {mins} minutes."
            )

        self.save_accounts()
        return False, "Spoofing detected. One more attempt locks account."

    def record_success(self, username):
        """Record successful login and reset counters."""
        if username not in self.accounts:
            return

        acc = self.accounts[username]
        acc['failed_attempts'] = 0
        acc['spoof_attempts'] = 0
        acc['last_login'] = datetime.now().isoformat()
        acc['login_history'].append(datetime.now().isoformat())

        # Keep only last 20 login records
        if len(acc['login_history']) > 20:
            acc['login_history'] = acc['login_history'][-20:]

        self._log_event(username, "SUCCESS", "Login successful")
        self.save_accounts()

    def _lock_account(self, username, lock_type, reason):
        acc = self.accounts[username]
        acc['is_locked'] = True
        acc['lock_type'] = lock_type
        acc['lock_time'] = time.time()
        acc['lock_reason'] = reason
        self._log_event(username, "ACCOUNT_LOCKED",
                        f"{lock_type}: {reason}")
        self.save_accounts()

    def unlock_account(self, username, auto=False):
        """Unlock account — called by admin or auto after timeout."""
        if username not in self.accounts:
            return False, "Account not found."

        acc = self.accounts[username]
        acc['is_locked'] = False
        acc['lock_type'] = None
        acc['lock_time'] = None
        acc['lock_reason'] = None
        acc['failed_attempts'] = 0
        acc['spoof_attempts'] = 0

        if not auto:
            acc['total_failed'] = 0
            self._log_event(username, "ADMIN_UNLOCK",
                            "Admin manually unlocked account")
        else:
            self._log_event(username, "AUTO_UNLOCK",
                            "Temporary lockout expired")

        self.save_accounts()
        return True, f"Account {username} unlocked."

    # ─────────────────────────────────────────
    # AFTER-HOURS ADMIN OVERRIDE
    # ─────────────────────────────────────────

    def is_after_hours_trusted(self, username):
        """Whether this user is exempt from the automatic after-hours
        block in HybridIDS.quick_rules(). Defaults to False for any
        account created before this flag existed (via .get fallback)."""
        if username not in self.accounts:
            return False
        return self.accounts[username].get('after_hours_trusted', False)

    def set_after_hours_trusted(self, username, trusted, admin_username="admin"):
        """Admin-only toggle. Does NOT skip logging — after-hours
        access by a trusted user is still recorded in the audit log,
        it just isn't auto-blocked by quick_rules()."""
        if username not in self.accounts:
            return False, "Account not found."

        self.accounts[username]['after_hours_trusted'] = bool(trusted)
        self._log_event(
            username, "AFTER_HOURS_TRUST_CHANGED",
            f"Set to {bool(trusted)} by {admin_username}"
        )
        self.save_accounts()
        state = "enabled" if trusted else "disabled"
        return True, f"After-hours trust {state} for {username}."

    # ─────────────────────────────────────────
    # FACE ENROLLMENT
    # ─────────────────────────────────────────

    def enroll_face(self, username, embedding):
        """Enroll or update face embedding for a user."""
        if username not in self.accounts:
            return False, "Account not found."

        self.face_db[username] = embedding
        self.accounts[username]['enrolled'] = True
        self.save_face_db()
        self.save_accounts()
        return True, f"Face enrolled for {username}."

    # ─────────────────────────────────────────
    # ACCOUNT RECOVERY
    # ─────────────────────────────────────────

    def initiate_recovery(self, username, admin_username, reason):
        """
        Admin initiates recovery for a user after physical
        verification (accident, injury, facial change etc.)
        """
        if username not in self.accounts:
            return False, "User account not found."

        if admin_username not in self.accounts:
            return False, "Admin account not found."

        admin = self.accounts[admin_username]
        if admin.get('role') != 'admin':
            return False, "Only admins can initiate recovery."

        # Mark account as recovery pending
        acc = self.accounts[username]
        acc['recovery_pending'] = True
        acc['recovery_reason'] = reason
        acc['recovery_initiated_by'] = admin_username
        acc['recovery_initiated_at'] = datetime.now().isoformat()

        # Unlock account for re-enrollment
        acc['is_locked'] = False
        acc['lock_type'] = None
        acc['lock_time'] = None
        acc['failed_attempts'] = 0
        acc['spoof_attempts'] = 0
        acc['total_failed'] = 0

        self._log_event(
            username, "RECOVERY_INITIATED",
            f"Admin: {admin_username} | Reason: {reason}"
        )
        self.save_accounts()
        return (
            True,
            f"Recovery initiated for {username}. "
            f"Please enroll new face data."
        )

    def complete_recovery(self, username, new_embedding,
                          admin_username):
        """
        Complete recovery by replacing old face embedding
        with new one. ALL existing data is preserved.
        """
        if username not in self.accounts:
            return False, "User account not found."

        acc = self.accounts[username]
        if not acc.get('recovery_pending'):
            return False, "No recovery pending for this account."

        # Replace face embedding — preserve all other data
        old_embedding_exists = username in self.face_db
        self.face_db[username] = new_embedding
        self.save_face_db()

        # Clear recovery flags
        acc['recovery_pending'] = False
        acc['recovery_completed_at'] = datetime.now().isoformat()
        acc['recovery_completed_by'] = admin_username
        acc['enrolled'] = True

        self._log_event(
            username, "RECOVERY_COMPLETED",
            f"New face enrolled by admin: {admin_username}. "
            f"Previous embedding replaced: {old_embedding_exists}. "
            f"All existing data preserved."
        )
        self.save_accounts()
        return (
            True,
            f"Recovery complete for {username}. "
            f"New face enrolled. All existing data preserved."
        )

    def get_recovery_status(self, username):
        """Get recovery status for a user."""
        if username not in self.accounts:
            return None
        acc = self.accounts[username]
        return {
            'recovery_pending': acc.get('recovery_pending', False),
            'recovery_reason': acc.get('recovery_reason', ''),
            'recovery_initiated_by': acc.get(
                'recovery_initiated_by', ''),
            'recovery_initiated_at': acc.get(
                'recovery_initiated_at', '')
        }

    # ─────────────────────────────────────────
    # EVENT LOGGING
    # ─────────────────────────────────────────

    def _log_event(self, username, event_type, details):
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'event': event_type,
            'details': details
        }
        log_file = "logs/auth_log.json"
        logs = []
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                try:
                    logs = json.load(f)
                except Exception:
                    logs = []
        logs.append(log_entry)
        with open(log_file, 'w') as f:
            json.dump(logs, f, indent=4)

    # ─────────────────────────────────────────
    # ADMIN UTILITIES
    # ─────────────────────────────────────────

    def get_account_status(self, username):
        """Get full account status."""
        if username not in self.accounts:
            return None
        return self.accounts[username]

    def list_locked_accounts(self):
        """Return list of all locked accounts."""
        return [
            u for u, d in self.accounts.items()
            if d.get('is_locked')
        ]

    def list_all_accounts(self):
        """Return all accounts with status summary."""
        summary = []
        for username, data in self.accounts.items():
            summary.append({
                'username': username,
                'role': data.get('role'),
                'enrolled': data.get('enrolled'),
                'is_locked': data.get('is_locked'),
                'lock_type': data.get('lock_type'),
                'failed_attempts': data.get('failed_attempts'),
                'spoof_attempts': data.get('spoof_attempts'),
                'last_login': data.get('last_login'),
                'recovery_pending': data.get('recovery_pending'),
                'after_hours_trusted': data.get('after_hours_trusted', False)
            })
        return summary