"""
generate_ids_dataset.py
------------------------
Generates a labelled synthetic training dataset for HybridIDS
(Random Forest + Isolation Forest).

Design approach
----------------
Rows are NOT purely random. "Normal" rows are sampled to sit below
the same thresholds already hard-coded in HybridIDS.quick_rules()
(max_failed=5, max_spoof=3, max_login_freq=15, max_syn=20,
max_ports=50), with realistic variance around those bounds.
"Attack" rows are generated from five distinct attack archetypes,
each crossing one or more of those thresholds in a way that mirrors
a real attack pattern:

  1. Brute force        — many failed logins, low confidence
  2. Spoofing attempt    — spoof flag set, repeated spoof attempts
  3. Port scan            — many unique ports / high SYN count
  4. Credential stuffing  — high login frequency, frequent IP changes
  5. After-hours intrusion — access outside work hours + weak signals

A small slice of legitimate after-hours access is also included and
labelled NORMAL (e.g. a student working late with a clean face match
and no other red flags) — this gives the Random Forest a chance to
learn nuance beyond the hard-coded after-hours rule, since the rule
alone would otherwise flag every late login regardless of context.

Run this script once to produce dataset/ids_training_data.csv, then
call HybridIDS().train() to train and save the models.
"""

import numpy as np
import pandas as pd
import os

RNG = np.random.default_rng(seed=42)

FEATURE_COLUMNS = [
    'failed_attempts', 'successful_attempts', 'failed_ratio',
    'confidence_score', 'spoof_indicator', 'spoof_attempts',
    'time_since_last', 'login_frequency', 'ip_changes',
    'current_success', 'packets_per_sec', 'bytes_per_sec',
    'unique_ports', 'syn_count', 'failed_connections',
    'traffic_ratio', 'after_hours'
]

OUTPUT_PATH = "dataset/ids_training_data.csv"
TOTAL_ROWS = 6000
NORMAL_FRACTION = 0.75  # ~75% normal / 25% attack, matches class_weight='balanced'


def _clip(arr, lo, hi):
    return np.clip(arr, lo, hi)


def _lognormal_traffic(n, median, sigma, clip_lo, clip_hi):
    """Real network throughput is heavy-tailed (mostly quiet, with
    occasional much larger bursts from background downloads, OS
    updates, streaming, etc.) — a log-normal distribution captures
    this naturally, unlike a uniform range with an occasional spike,
    which understates the variance and makes real bursty values look
    like statistical outliers to the Isolation Forest. 'median' and
    'sigma' are calibrated so values observed on the live deployment
    machine fall well within the typical range, not the extreme tail."""
    vals = RNG.lognormal(mean=np.log(median), sigma=sigma, size=n)
    return _clip(vals, clip_lo, clip_hi)


def make_normal(n):
    """Legitimate login/network behaviour, within quick_rules() bounds.
    Ranges are widened slightly (vs. a hard cutoff) so a few normal
    rows naturally brush up against the low end of attack ranges —
    real users occasionally mistype passwords, have a slow network
    moment, etc. This is what gives the classifier a genuine boundary
    to learn instead of a clean lookup split."""
    failed = RNG.poisson(0.6, n)                        # usually 0, occasionally a few
    failed = _clip(failed, 0, 6)                          # can occasionally brush max_failed=5
    successful = RNG.integers(1, 6, n)
    failed_ratio = failed / np.maximum(failed + successful, 1)

    confidence = RNG.uniform(0.45, 0.99, n)               # occasional weaker match
    spoof_indicator = RNG.choice([0, 1], n, p=[0.96, 0.04])  # rare false liveness flicker
    spoof_attempts = np.where(spoof_indicator == 1, RNG.integers(1, 3, n), 0)

    time_since_last = RNG.uniform(20, 3600, n)            # seconds since last login
    login_frequency = RNG.integers(1, 13, n)                # can occasionally near max_login_freq=15
    ip_changes = RNG.integers(0, 3, n)
    current_success = RNG.choice([1, 1, 1, 0], n)          # mostly successful

    packets_per_sec = _lognormal_traffic(n, median=100, sigma=1.6, clip_lo=1, clip_hi=1200)
    bytes_per_sec = _lognormal_traffic(n, median=30000, sigma=2.3, clip_lo=100, clip_hi=800000)
    unique_ports = RNG.integers(1, 18, n)                    # can occasionally near higher end
    syn_count = RNG.integers(0, 9, n)                          # can occasionally near max_syn=20
    failed_connections = RNG.integers(0, 20, n)                 # widened to include observed live values (up to ~14)
    traffic_ratio = _clip(RNG.normal(1.0, 0.5, n), 0.02, 4.0)

    after_hours = np.zeros(n, dtype=int)

    return _assemble(failed, successful, failed_ratio, confidence,
                      spoof_indicator, spoof_attempts, time_since_last,
                      login_frequency, ip_changes, current_success,
                      packets_per_sec, bytes_per_sec, unique_ports,
                      syn_count, failed_connections, traffic_ratio,
                      after_hours)


def make_normal_after_hours(n):
    """Legitimate late-night access — after_hours=1 but otherwise clean.
    Labelled NORMAL to teach the RF that after-hours alone isn't
    always malicious (the hard-coded quick_rules() will still flag
    it at inference time; this only shapes what the ML model learns)."""
    rows = make_normal(n)
    rows['after_hours'] = np.ones(n, dtype=int)
    return rows


def make_brute_force(n):
    failed = RNG.integers(3, 25, n)                         # some overlap below max_failed=5
    successful = RNG.integers(0, 3, n)
    failed_ratio = failed / np.maximum(failed + successful, 1)

    confidence = RNG.uniform(0.0, 0.6, n)                    # poor/no face match, some overlap
    spoof_indicator = RNG.choice([0, 1], n, p=[0.7, 0.3])
    spoof_attempts = RNG.integers(0, 2, n)

    time_since_last = RNG.uniform(0.5, 20, n)                 # rapid retries
    login_frequency = RNG.integers(10, 40, n)
    ip_changes = RNG.integers(0, 3, n)
    current_success = np.zeros(n, dtype=int)

    packets_per_sec = RNG.uniform(20, 150, n)
    bytes_per_sec = RNG.uniform(2000, 20000, n)
    unique_ports = RNG.integers(1, 10, n)
    syn_count = RNG.integers(2, 15, n)
    failed_connections = RNG.integers(2, 12, n)
    traffic_ratio = _clip(RNG.normal(1.5, 0.6, n), 0.1, 6.0)

    after_hours = RNG.choice([0, 1], n, p=[0.6, 0.4])

    return _assemble(failed, successful, failed_ratio, confidence,
                      spoof_indicator, spoof_attempts, time_since_last,
                      login_frequency, ip_changes, current_success,
                      packets_per_sec, bytes_per_sec, unique_ports,
                      syn_count, failed_connections, traffic_ratio,
                      after_hours)


def make_spoofing_attack(n):
    failed = RNG.integers(1, 8, n)
    successful = RNG.integers(0, 2, n)
    failed_ratio = failed / np.maximum(failed + successful, 1)

    confidence = RNG.uniform(0.0, 0.45, n)                    # spoof rarely matches well
    spoof_indicator = np.ones(n, dtype=int)
    spoof_attempts = RNG.integers(3, 10, n)                    # exceeds max_spoof=3

    time_since_last = RNG.uniform(1, 60, n)
    login_frequency = RNG.integers(2, 12, n)
    ip_changes = RNG.integers(0, 2, n)
    current_success = np.zeros(n, dtype=int)

    packets_per_sec = RNG.uniform(1, 30, n)
    bytes_per_sec = RNG.uniform(200, 6000, n)
    unique_ports = RNG.integers(1, 8, n)
    syn_count = RNG.integers(0, 6, n)
    failed_connections = RNG.integers(0, 4, n)
    traffic_ratio = _clip(RNG.normal(1.0, 0.4, n), 0.1, 3.0)

    after_hours = RNG.choice([0, 1], n, p=[0.7, 0.3])

    return _assemble(failed, successful, failed_ratio, confidence,
                      spoof_indicator, spoof_attempts, time_since_last,
                      login_frequency, ip_changes, current_success,
                      packets_per_sec, bytes_per_sec, unique_ports,
                      syn_count, failed_connections, traffic_ratio,
                      after_hours)


def make_port_scan(n):
    failed = RNG.integers(0, 4, n)
    successful = RNG.integers(0, 3, n)
    failed_ratio = failed / np.maximum(failed + successful, 1)

    confidence = RNG.uniform(0.3, 0.9, n)
    spoof_indicator = np.zeros(n, dtype=int)
    spoof_attempts = np.zeros(n, dtype=int)

    time_since_last = RNG.uniform(0.1, 15, n)
    login_frequency = RNG.integers(1, 10, n)
    ip_changes = RNG.integers(0, 4, n)
    current_success = RNG.choice([0, 1], n)

    packets_per_sec = RNG.uniform(30, 300, n)                   # scan traffic burst, some overlap
    bytes_per_sec = RNG.uniform(500, 5000, n)                    # small packets, low payload
    unique_ports = RNG.integers(15, 300, n)                       # some overlap below max_ports=50
    syn_count = RNG.integers(8, 100, n)                            # some overlap below max_syn=20
    failed_connections = RNG.integers(5, 30, n)
    traffic_ratio = _clip(RNG.normal(0.5, 0.3, n), 0.0, 3.0)

    after_hours = RNG.choice([0, 1], n, p=[0.5, 0.5])

    return _assemble(failed, successful, failed_ratio, confidence,
                      spoof_indicator, spoof_attempts, time_since_last,
                      login_frequency, ip_changes, current_success,
                      packets_per_sec, bytes_per_sec, unique_ports,
                      syn_count, failed_connections, traffic_ratio,
                      after_hours)


def make_credential_stuffing(n):
    failed = RNG.integers(3, 12, n)
    successful = RNG.integers(0, 2, n)
    failed_ratio = failed / np.maximum(failed + successful, 1)

    confidence = RNG.uniform(0.0, 0.6, n)
    spoof_indicator = RNG.choice([0, 1], n, p=[0.6, 0.4])
    spoof_attempts = RNG.integers(0, 4, n)

    time_since_last = RNG.uniform(0.2, 10, n)                    # very rapid attempts
    login_frequency = RNG.integers(15, 60, n)                       # exceeds max_login_freq=15
    ip_changes = RNG.integers(2, 10, n)                              # rotating IPs
    current_success = np.zeros(n, dtype=int)

    packets_per_sec = RNG.uniform(10, 100, n)
    bytes_per_sec = RNG.uniform(1000, 15000, n)
    unique_ports = RNG.integers(1, 15, n)
    syn_count = RNG.integers(1, 12, n)
    failed_connections = RNG.integers(3, 15, n)
    traffic_ratio = _clip(RNG.normal(1.2, 0.5, n), 0.1, 5.0)

    after_hours = RNG.choice([0, 1], n, p=[0.5, 0.5])

    return _assemble(failed, successful, failed_ratio, confidence,
                      spoof_indicator, spoof_attempts, time_since_last,
                      login_frequency, ip_changes, current_success,
                      packets_per_sec, bytes_per_sec, unique_ports,
                      syn_count, failed_connections, traffic_ratio,
                      after_hours)


def make_after_hours_intrusion(n):
    """After-hours access combined with other weak/suspicious signals
    (distinct from make_normal_after_hours, which is clean)."""
    failed = RNG.integers(1, 6, n)
    successful = RNG.integers(0, 2, n)
    failed_ratio = failed / np.maximum(failed + successful, 1)

    confidence = RNG.uniform(0.1, 0.6, n)
    spoof_indicator = RNG.choice([0, 1], n, p=[0.75, 0.25])
    spoof_attempts = RNG.integers(0, 3, n)

    time_since_last = RNG.uniform(5, 600, n)
    login_frequency = RNG.integers(1, 10, n)
    ip_changes = RNG.integers(0, 3, n)
    current_success = RNG.choice([0, 1], n, p=[0.7, 0.3])

    packets_per_sec = RNG.uniform(5, 60, n)
    bytes_per_sec = RNG.uniform(500, 9000, n)
    unique_ports = RNG.integers(1, 20, n)
    syn_count = RNG.integers(0, 10, n)
    failed_connections = RNG.integers(0, 6, n)
    traffic_ratio = _clip(RNG.normal(1.0, 0.5, n), 0.1, 4.0)

    after_hours = np.ones(n, dtype=int)

    return _assemble(failed, successful, failed_ratio, confidence,
                      spoof_indicator, spoof_attempts, time_since_last,
                      login_frequency, ip_changes, current_success,
                      packets_per_sec, bytes_per_sec, unique_ports,
                      syn_count, failed_connections, traffic_ratio,
                      after_hours)


def _assemble(failed, successful, failed_ratio, confidence, spoof_indicator,
              spoof_attempts, time_since_last, login_frequency, ip_changes,
              current_success, packets_per_sec, bytes_per_sec, unique_ports,
              syn_count, failed_connections, traffic_ratio, after_hours):
    return {
        'failed_attempts': failed,
        'successful_attempts': successful,
        'failed_ratio': failed_ratio,
        'confidence_score': confidence,
        'spoof_indicator': spoof_indicator,
        'spoof_attempts': spoof_attempts,
        'time_since_last': time_since_last,
        'login_frequency': login_frequency,
        'ip_changes': ip_changes,
        'current_success': current_success,
        'packets_per_sec': packets_per_sec,
        'bytes_per_sec': bytes_per_sec,
        'unique_ports': unique_ports,
        'syn_count': syn_count,
        'failed_connections': failed_connections,
        'traffic_ratio': traffic_ratio,
        'after_hours': after_hours,
    }


def add_realistic_noise(df, jitter_frac=0.18, label_noise_frac=0.035):
    """Blurs the class boundary so the classes are not perfectly
    separable, which is what a real-world dataset looks like.

    - jitter_frac: fraction of rows that get Gaussian noise added to
      their continuous features (sensor/measurement-style noise —
      e.g. two logins with nearly identical stats but different
      outcomes).
    - label_noise_frac: fraction of rows whose label is flipped,
      simulating ambiguous/borderline cases and occasional labelling
      error, which is realistic and also what keeps a classifier's
      reported accuracy from being a suspicious 100%.
    """
    df = df.copy()
    n = len(df)
    rng_idx = RNG

    continuous_cols = ['confidence_score', 'time_since_last', 'packets_per_sec',
                        'bytes_per_sec', 'traffic_ratio', 'failed_ratio']

    jitter_mask = rng_idx.random(n) < jitter_frac
    for col in continuous_cols:
        std = df[col].std()
        noise = rng_idx.normal(0, std * 0.25, n)
        df.loc[jitter_mask, col] = df.loc[jitter_mask, col] + noise[jitter_mask]

    # Re-clip a couple of bounded columns after jitter
    df['confidence_score'] = df['confidence_score'].clip(0.0, 1.0)
    df['failed_ratio'] = df['failed_ratio'].clip(0.0, 1.0)
    df['traffic_ratio'] = df['traffic_ratio'].clip(0.0, 10.0)

    # Small amount of label noise — borderline/ambiguous cases
    flip_mask = rng_idx.random(n) < label_noise_frac
    df.loc[flip_mask, 'label'] = 1 - df.loc[flip_mask, 'label']

    return df


def generate_dataset():
    n_normal_total = int(TOTAL_ROWS * NORMAL_FRACTION)
    n_attack_total = TOTAL_ROWS - n_normal_total

    # Normal: mostly plain-normal, small slice of legitimate after-hours
    n_normal_plain = int(n_normal_total * 0.85)
    n_normal_late = n_normal_total - n_normal_plain

    # Attack: split evenly across 5 archetypes
    n_each_attack = n_attack_total // 5
    n_attack_remainder = n_attack_total - (n_each_attack * 5)

    blocks = []
    labels = []

    for gen_fn, count, label in [
        (make_normal,               n_normal_plain,               0),
        (make_normal_after_hours,   n_normal_late,                0),
        (make_brute_force,          n_each_attack,                1),
        (make_spoofing_attack,      n_each_attack,                1),
        (make_port_scan,            n_each_attack,                1),
        (make_credential_stuffing,  n_each_attack,                1),
        (make_after_hours_intrusion, n_each_attack + n_attack_remainder, 1),
    ]:
        if count <= 0:
            continue
        rows = gen_fn(count)
        df_block = pd.DataFrame(rows)
        df_block = df_block[FEATURE_COLUMNS]  # enforce column order
        df_block['label'] = label
        blocks.append(df_block)

    df = pd.concat(blocks, ignore_index=True)

    # Round integer-like columns for readability, keep continuous ones as floats
    int_cols = ['failed_attempts', 'successful_attempts', 'spoof_indicator',
                'spoof_attempts', 'login_frequency', 'ip_changes',
                'current_success', 'unique_ports', 'syn_count',
                'failed_connections', 'after_hours', 'label']
    for c in int_cols:
        df[c] = df[c].round().astype(int)

    float_cols = ['failed_ratio', 'confidence_score', 'time_since_last',
                  'packets_per_sec', 'bytes_per_sec', 'traffic_ratio']
    for c in float_cols:
        df[c] = df[c].round(4)

    # Shuffle rows so classes aren't in contiguous blocks
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    # Blur the class boundary — see add_realistic_noise() docstring
    df = add_realistic_noise(df)

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    df.to_csv(OUTPUT_PATH, index=False)

    print(f"Wrote {len(df)} rows to {OUTPUT_PATH}")
    print("\nClass balance:")
    print(df['label'].value_counts().rename({0: 'Normal', 1: 'Attack'}))
    print("\nFirst few rows:")
    print(df.head())


if __name__ == "__main__":
    generate_dataset()