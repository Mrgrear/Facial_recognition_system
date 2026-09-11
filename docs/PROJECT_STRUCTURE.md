# Project Structure

This document explains the role of the main directories and files in the Enhanced Facial Authentication System with Hybrid IDS.

```text
Facial_recognition_system/
├── auth/                 # Authentication, face recognition and anti-spoofing logic
├── GUI/                  # Tkinter application and interface pages/components
├── ids/                  # Hybrid intrusion detection and network monitoring
├── utils/                # Enrollment, camera discovery and calibration utilities
├── db/                   # Local application data and audit/model state
├── models/               # Trained ML/model artifacts
├── dataset/              # Training/evaluation data where applicable
├── docs/                 # Documentation and evaluation figures
├── main.py               # Primary application entry point
├── setup_and_run.py      # Optional project setup/scaffolding utility
├── requirements.txt      # Python dependencies
├── .gitignore            # Excludes environments, caches and local runtime artifacts
├── LICENSE               # Project usage/copyright notice
└── README.md             # Main project documentation
```

## Design principle

Source code is separated by responsibility: authentication code belongs in `auth/`, user-interface code in `GUI/`, intrusion-detection code in `ids/`, and operational helpers in `utils/`. Documentation and experiment figures belong in `docs/` rather than the repository root.

Generated Python bytecode, virtual environments, editor files, logs and other local artifacts should not be committed. Existing runtime databases and trained model files should be handled carefully because they may contain biometric or operational data.

## Main execution flow

`main.py` starts `GUI.main_gui`, which coordinates the login, administration and monitoring pages. Authentication modules provide facial detection/recognition, liveness and anti-spoof decisions, while the IDS modules analyse authentication and network-related activity.
