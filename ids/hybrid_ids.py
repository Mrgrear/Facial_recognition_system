import numpy as np
import pandas as pd
import pickle
import os
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

class HybridIDS:
    def __init__(self, model_path="models/ids_models.pkl"):
        self.model_path = model_path
        self.rf_model = None
        self.if_model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.alert_log = []

        self.max_failed = 5
        self.max_spoof = 3
        self.max_login_freq = 15
        self.max_syn = 20
        self.max_ports = 50

    def quick_rules(self, features):
        failed = features[0]
        spoof = features[4]
        spoof_attempts = features[5]
        login_freq = features[7]
        unique_ports = features[12] if len(features) > 12 else 0
        syn_count = features[13] if len(features) > 13 else 0
        after_hours = features[16] if len(features) > 16 else 0

        if after_hours == 1:
            return True, "After-hours access detected"
        if failed >= self.max_failed:
            return True, "Brute force detected"
        if spoof == 1 and spoof_attempts >= self.max_spoof:
            return True, "Repeated spoofing detected"
        if login_freq >= self.max_login_freq:
            return True, "High login frequency"
        if syn_count >= self.max_syn:
            return True, "Port scan (high SYN count)"
        if unique_ports >= self.max_ports:
            return True, "Port scan (many unique ports)"
        return False, ""

    def train(self, data_path="dataset/ids_training_data.csv"):
        df = pd.read_csv(data_path)
        feature_cols = [
            'failed_attempts', 'successful_attempts', 'failed_ratio',
            'confidence_score', 'spoof_indicator', 'spoof_attempts',
            'time_since_last', 'login_frequency', 'ip_changes',
            'current_success', 'packets_per_sec', 'bytes_per_sec',
            'unique_ports', 'syn_count', 'failed_connections',
            'traffic_ratio', 'after_hours'
        ]
        X = df[feature_cols].values
        y = df['label'].values

        X_scaled = self.scaler.fit_transform(X)
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42
        )

        print("Training Random Forest (17 features)...")
        self.rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        self.rf_model.fit(X_train, y_train)

        print("Training Isolation Forest...")
        X_normal = X_scaled[y == 0]
        self.if_model = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )
        self.if_model.fit(X_normal)

        self.is_trained = True
        self.save_models()

        y_pred = self.rf_model.predict(X_test)
        print("\n--- Random Forest Evaluation ---")
        print(classification_report(
            y_test, y_pred,
            target_names=['Normal', 'Attack']
        ))
        print("Confusion Matrix:")
        print(confusion_matrix(y_test, y_pred))
        return y_test, y_pred

    def save_models(self):
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump({
                'rf': self.rf_model,
                'if': self.if_model,
                'scaler': self.scaler
            }, f)
        print(f"Models saved to {self.model_path}")

    def load_models(self):
        if os.path.exists(self.model_path):
            with open(self.model_path, 'rb') as f:
                data = pickle.load(f)
                self.rf_model = data['rf']
                self.if_model = data['if']
                self.scaler = data['scaler']
                self.is_trained = True
            print("IDS models loaded.")
            return True
        return False

    def predict(self, features):
        flagged, reason = self.quick_rules(features)
        if flagged:
            self._log_alert("HIGH", reason, features)
            return True, "HIGH", reason

        if not self.is_trained:
            return False, "LOW", "IDS not trained"

        X = self.scaler.transform([features])
        rf_pred = self.rf_model.predict(X)[0]
        rf_prob = self.rf_model.predict_proba(X)[0][1]
        if_score = self.if_model.decision_function(X)[0]
        if_anomaly = self.if_model.predict(X)[0]

        if rf_pred == 1 and if_anomaly == -1:
            level = "HIGH"
            reason = f"RF+IF flagged (RF:{rf_prob:.2f})"
            alert = True
        elif rf_pred == 1:
            level = "MEDIUM"
            reason = f"RF flagged (prob:{rf_prob:.2f})"
            alert = True
        elif if_anomaly == -1:
            level = "MEDIUM"
            reason = f"IF anomaly (score:{if_score:.2f})"
            alert = True
        else:
            level = "LOW"
            reason = "Normal behaviour"
            alert = False

        if alert:
            self._log_alert(level, reason, features)
        return alert, level, reason

    def _log_alert(self, level, reason, features):
        import time
        self.alert_log.append({
            'timestamp': time.time(),
            'level': level,
            'reason': reason,
            'failed_attempts': features[0],
            'confidence': features[3],
            'spoof': features[4],
            'packets_ps': features[10] if len(features) > 10 else 0,
            'syn_count': features[13] if len(features) > 13 else 0,
            'unique_ports': features[12] if len(features) > 12 else 0,
            'after_hours': features[16] if len(features) > 16 else 0
        })