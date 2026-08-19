import json
import os
from datetime import datetime

class AuditLogger:
    def __init__(self):
        self.log_file = "db/audit_log.json"
        self.load_logs()

    def load_logs(self):
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, 'r') as f:
                    self.logs = json.load(f)
                return
            except (json.JSONDecodeError, ValueError) as e:
                # Corrupted log file (e.g. from an abrupt app close mid-write).
                # Back it up instead of crashing the whole application on
                # every future startup, and start fresh with an empty log.
                backup_path = self.log_file + ".corrupted"
                try:
                    os.replace(self.log_file, backup_path)
                    print(f"[WARN] Corrupted audit log detected ({e}). "
                          f"Backed up to '{backup_path}' and starting a fresh log.")
                except Exception as backup_err:
                    print(f"[WARN] Corrupted audit log detected ({e}). "
                          f"Could not back it up ({backup_err}); starting fresh anyway.")
                self.logs = []
        else:
            self.logs = []

    def save_logs(self):
        os.makedirs("db", exist_ok=True)
        with open(self.log_file, 'w') as f:
            json.dump(self.logs, f, indent=4)

    def log_event(self, username, event_type, details, severity="INFO"):
        """Log an event."""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'event_type': event_type,
            'details': details,
            'severity': severity
        }
        self.logs.append(log_entry)
        self.save_logs()

    def log_login(self, username, success, confidence=None, ip_address=None):
        """Log login attempt."""
        details = {
            'success': success,
            'ip_address': ip_address,
            'confidence': confidence
        }
        severity = "INFO" if success else "WARNING"
        self.log_event(username, "LOGIN", details, severity)

    def log_failed_attempt(self, username, reason, ip_address=None):
        """Log failed authentication."""
        details = {'reason': reason, 'ip_address': ip_address}
        self.log_event(username, "FAILED_AUTH", details, "WARNING")

    def log_lockout(self, username, lock_type, reason):
        """Log account lockout."""
        details = {'lock_type': lock_type, 'reason': reason}
        self.log_event(username, "LOCKOUT", details, "CRITICAL")

    def log_ids_alert(self, username, level, reason):
        """Log IDS alert."""
        details = {'alert_level': level, 'reason': reason}
        self.log_event(username, "IDS_ALERT", details, "CRITICAL")

    def log_admin_action(self, admin, action, target_user, details=None):
        """Log admin actions."""
        event_details = {
            'action': action,
            'target_user': target_user,
            'additional_details': details
        }
        self.log_event(admin, "ADMIN_ACTION", event_details, "INFO")

    def get_user_audit_trail(self, username, limit=50):
        """Get user's audit trail."""
        trail = [log for log in self.logs if log['username'] == username]
        return trail[-limit:]

    def get_recent_events(self, event_type=None, severity=None, limit=100):
        """Get recent events."""
        events = self.logs
        if event_type:
            events = [e for e in events if e['event_type'] == event_type]
        if severity:
            events = [e for e in events if e['severity'] == severity]
        return events[-limit:]

    def get_alerts(self):
        """Get all critical alerts."""
        return [e for e in self.logs if e['severity'] in ["WARNING", "CRITICAL"]]