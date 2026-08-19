import json
import os
import time
from datetime import datetime, timedelta
import uuid

class SessionManager:
    def __init__(self, session_timeout_minutes=30):
        self.sessions_file = "db/sessions.json"
        self.session_timeout = session_timeout_minutes * 60
        self.sessions = self.load_sessions()

    def load_sessions(self):
        if os.path.exists(self.sessions_file):
            with open(self.sessions_file, 'r') as f:
                return json.load(f)
        return {}

    def save_sessions(self):
        os.makedirs("db", exist_ok=True)
        with open(self.sessions_file, 'w') as f:
            json.dump(self.sessions, f, indent=4)

    def create_session(self, username, ip_address, device_id):
        """Create new session."""
        # Check concurrent sessions
        active = [s for s in self.sessions.values() 
                 if s['username'] == username and not s['expired']]
        if active:
            # Invalidate previous session
            for session in active:
                session['expired'] = True

        session_id = str(uuid.uuid4())
        self.sessions[session_id] = {
            'session_id': session_id,
            'username': username,
            'ip_address': ip_address,
            'device_id': device_id,
            'created_at': datetime.now().isoformat(),
            'last_activity': datetime.now().isoformat(),
            'expired': False
        }
        self.save_sessions()
        return session_id

    def validate_session(self, session_id, ip_address):
        """Validate and update session."""
        if session_id not in self.sessions:
            return False, "Session not found"

        session = self.sessions[session_id]
        
        if session['expired']:
            return False, "Session expired"

        # Check timeout
        last_activity = datetime.fromisoformat(session['last_activity'])
        if datetime.now() - last_activity > timedelta(seconds=self.session_timeout):
            session['expired'] = True
            self.save_sessions()
            return False, "Session timeout"

        # Check IP change (detect compromise)
        if session['ip_address'] != ip_address:
            session['expired'] = True
            self.save_sessions()
            return False, "IP address mismatch - possible compromise"

        # Update activity
        session['last_activity'] = datetime.now().isoformat()
        self.save_sessions()
        return True, "Session valid"

    def end_session(self, session_id):
        """End session."""
        if session_id in self.sessions:
            self.sessions[session_id]['expired'] = True
            self.save_sessions()

    def get_active_sessions(self, username):
        """Get user's active sessions."""
        return [s for s in self.sessions.values() 
               if s['username'] == username and not s['expired']]

    def get_all_sessions(self):
        """Get all sessions."""
        return list(self.sessions.values())