import numpy as np
import pandas as pd

def generate_training_data(n_normal=500, n_attack=200):
    data = []
    labels = []

    # Normal behaviour — work hours (8AM–5PM)
    for _ in range(n_normal):
        failed = np.random.randint(0, 2)
        success = np.random.randint(1, 5)
        total = failed + success
        failed_ratio = failed / total if total > 0 else 0
        confidence = np.random.uniform(0.6, 0.99)
        spoof = 0
        spoof_attempts = 0
        time_since = np.random.uniform(60, 3600)
        login_freq = np.random.randint(1, 5)
        ip_changes = 0
        current_success = 1
        packets_ps = np.random.uniform(10, 200)
        bytes_ps = np.random.uniform(1000, 50000)
        unique_ports = np.random.randint(1, 10)
        syn_count = np.random.randint(0, 2)
        failed_conn = np.random.randint(0, 2)
        traffic_ratio = np.random.uniform(0.5, 2.0)
        after_hours = 0  # Work hours = legitimate

        data.append([
            failed, success, failed_ratio, confidence,
            spoof, spoof_attempts, time_since,
            login_freq, ip_changes, current_success,
            packets_ps, bytes_ps, unique_ports,
            syn_count, failed_conn, traffic_ratio,
            after_hours
        ])
        labels.append(0)

    # Attack behaviour
    for _ in range(n_attack):
        attack_type = np.random.choice([
            'brute_force', 'spoof',
            'port_scan', 'after_hours', 'anomaly'
        ])

        if attack_type == 'brute_force':
            failed = np.random.randint(5, 20)
            success = np.random.randint(0, 2)
            total = failed + success + 1
            failed_ratio = failed / total
            confidence = np.random.uniform(0.1, 0.4)
            spoof = 0
            spoof_attempts = 0
            time_since = np.random.uniform(1, 30)
            login_freq = np.random.randint(10, 30)
            ip_changes = np.random.randint(0, 3)
            current_success = 0
            packets_ps = np.random.uniform(500, 2000)
            bytes_ps = np.random.uniform(50000, 500000)
            unique_ports = np.random.randint(1, 5)
            syn_count = np.random.randint(0, 3)
            failed_conn = np.random.randint(3, 10)
            traffic_ratio = np.random.uniform(0.1, 0.5)
            after_hours = np.random.randint(0, 2)

        elif attack_type == 'spoof':
            failed = np.random.randint(1, 5)
            success = 0
            total = failed + 1
            failed_ratio = failed / total
            confidence = np.random.uniform(0.3, 0.6)
            spoof = 1
            spoof_attempts = np.random.randint(1, 5)
            time_since = np.random.uniform(5, 60)
            login_freq = np.random.randint(3, 10)
            ip_changes = np.random.randint(0, 2)
            current_success = 0
            packets_ps = np.random.uniform(100, 500)
            bytes_ps = np.random.uniform(10000, 100000)
            unique_ports = np.random.randint(1, 5)
            syn_count = np.random.randint(0, 2)
            failed_conn = np.random.randint(1, 5)
            traffic_ratio = np.random.uniform(1.0, 3.0)
            after_hours = np.random.randint(0, 2)

        elif attack_type == 'port_scan':
            failed = np.random.randint(0, 3)
            success = 0
            total = failed + 1
            failed_ratio = failed / total
            confidence = np.random.uniform(0.2, 0.5)
            spoof = 0
            spoof_attempts = 0
            time_since = np.random.uniform(1, 20)
            login_freq = np.random.randint(5, 15)
            ip_changes = np.random.randint(1, 5)
            current_success = 0
            packets_ps = np.random.uniform(1000, 5000)
            bytes_ps = np.random.uniform(10000, 100000)
            unique_ports = np.random.randint(50, 500)
            syn_count = np.random.randint(20, 100)
            failed_conn = np.random.randint(10, 50)
            traffic_ratio = np.random.uniform(5.0, 10.0)
            after_hours = np.random.randint(0, 2)

        elif attack_type == 'after_hours':
            # After hours access — key attack type
            failed = np.random.randint(0, 3)
            success = np.random.randint(0, 2)
            total = failed + success + 1
            failed_ratio = failed / total
            confidence = np.random.uniform(0.4, 0.8)
            spoof = np.random.randint(0, 2)
            spoof_attempts = np.random.randint(0, 2)
            time_since = np.random.uniform(100, 1000)
            login_freq = np.random.randint(1, 5)
            ip_changes = np.random.randint(0, 3)
            current_success = np.random.randint(0, 2)
            packets_ps = np.random.uniform(10, 300)
            bytes_ps = np.random.uniform(1000, 80000)
            unique_ports = np.random.randint(1, 15)
            syn_count = np.random.randint(0, 5)
            failed_conn = np.random.randint(0, 5)
            traffic_ratio = np.random.uniform(0.5, 3.0)
            after_hours = 1  # Always after hours

        else:  # anomaly
            failed = np.random.randint(2, 8)
            success = np.random.randint(0, 3)
            total = failed + success + 1
            failed_ratio = failed / total
            confidence = np.random.uniform(0.2, 0.5)
            spoof = np.random.randint(0, 2)
            spoof_attempts = np.random.randint(0, 3)
            time_since = np.random.uniform(0, 10)
            login_freq = np.random.randint(8, 20)
            ip_changes = np.random.randint(1, 5)
            current_success = 0
            packets_ps = np.random.uniform(300, 1500)
            bytes_ps = np.random.uniform(30000, 300000)
            unique_ports = np.random.randint(10, 50)
            syn_count = np.random.randint(5, 20)
            failed_conn = np.random.randint(5, 20)
            traffic_ratio = np.random.uniform(3.0, 8.0)
            after_hours = np.random.randint(0, 2)

        data.append([
            failed, success, failed_ratio, confidence,
            spoof, spoof_attempts, time_since,
            login_freq, ip_changes, current_success,
            packets_ps, bytes_ps, unique_ports,
            syn_count, failed_conn, traffic_ratio,
            after_hours
        ])
        labels.append(1)

    columns = [
        'failed_attempts', 'successful_attempts', 'failed_ratio',
        'confidence_score', 'spoof_indicator', 'spoof_attempts',
        'time_since_last', 'login_frequency', 'ip_changes',
        'current_success', 'packets_per_sec', 'bytes_per_sec',
        'unique_ports', 'syn_count', 'failed_connections',
        'traffic_ratio', 'after_hours'
    ]

    df = pd.DataFrame(data, columns=columns)
    df['label'] = labels
    df.to_csv('dataset/ids_training_data.csv', index=False)
    print(f"Dataset: {n_normal} normal + {n_attack} attack samples")
    print(f"Features: 17 (10 auth + 6 network + 1 time)")
    return df

if __name__ == "__main__":
    df = generate_training_data()
    print(df['label'].value_counts())