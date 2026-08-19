import numpy as np
import time

class FeatureExtractor:
    def __init__(self):
        self.login_times = []
        self.failed_attempts = 0
        self.successful_attempts = 0
        self.spoof_attempts = 0
        self.last_login_time = None
        self.ip_changes = 0
        self.last_ip = None

    def update(self, event):
        timestamp = event.get('timestamp', time.time())
        self.login_times.append(timestamp)

        if event.get('success'):
            self.successful_attempts += 1
        else:
            self.failed_attempts += 1

        if event.get('spoof_detected'):
            self.spoof_attempts += 1

        ip = event.get('ip_address', '127.0.0.1')
        if self.last_ip and ip != self.last_ip:
            self.ip_changes += 1
        self.last_ip = ip
        self.last_login_time = timestamp

    def extract(self, event, network_features=None):
        """Extract full 17-feature vector."""
        timestamp = event.get('timestamp', time.time())
        confidence = event.get('confidence_score', 0.0)
        spoof = 1 if event.get('spoof_detected') else 0
        success = 1 if event.get('success') else 0

        if self.last_login_time:
            time_since_last = timestamp - self.last_login_time
        else:
            time_since_last = 0.0

        recent = [t for t in self.login_times
                  if timestamp - t <= 60]
        login_frequency = len(recent)

        total = self.failed_attempts + self.successful_attempts
        failed_ratio = (
            self.failed_attempts / total if total > 0 else 0.0
        )

        # Auth features F1-F10
        auth_features = [
            self.failed_attempts,
            self.successful_attempts,
            failed_ratio,
            confidence,
            spoof,
            self.spoof_attempts,
            time_since_last,
            login_frequency,
            self.ip_changes,
            success
        ]

        # Network features F11-F17
        if network_features is None:
            network_features = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

        full_vector = auth_features + network_features
        return np.array(full_vector, dtype=np.float32)

    def reset(self):
        self.login_times = []
        self.failed_attempts = 0
        self.successful_attempts = 0
        self.spoof_attempts = 0
        self.last_login_time = None
        self.ip_changes = 0
        self.last_ip = None