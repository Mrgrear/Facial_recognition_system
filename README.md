# Enhanced Facial Authentication System with Hybrid IDS

A Python-based security system that combines **facial authentication, liveness/anti-spoofing checks, audit logging, session controls, and a hybrid machine-learning intrusion detection system (IDS)** in a desktop GUI.

> **Academic project:** Nigerian Army University Biu (NAUB), Department of Cyber Security  
> **Student:** Omu John Efu (CYB/23U/3983)  
> **Supervisor:** Dr. A. H. Desina

## Overview

The project is designed as a layered authentication and monitoring platform. A user is verified through facial recognition, while liveness and anti-spoofing controls help distinguish a live user from presentation attacks such as photographs or screen replays. Authentication events are logged and supplied to a hybrid IDS that combines supervised and unsupervised machine learning.

The current implementation includes a production-style Tkinter GUI and separates the major security functions into authentication (`auth/`), intrusion detection (`ids/`), GUI (`GUI/`), utilities (`utils/`), data (`dataset/` and `db/`), and analysis outputs (`docs/results/`).

## Key Features

- **Face detection** using InsightFace/face-analysis components.
- **Face recognition** using ArcFace-style embeddings and cosine similarity matching.
- **Liveness detection** using blink-based verification and Eye Aspect Ratio (EAR).
- **Multi-signal anti-spoofing** combining independent visual signals and calibrated thresholds.
- **Burst verification** to reduce dependence on a single video frame.
- **Authentication management** including account handling and failed-attempt controls.
- **Session management** with configurable session timeout.
- **Audit logging** of authentication/security events.
- **Hybrid IDS** using Random Forest classification and Isolation Forest anomaly detection.
- **Network monitoring** for collecting network-related security features.
- **Feature extraction** for building IDS input vectors from authentication and network events.
- **Administrator and monitoring GUI** for system operation and security visibility.
- **Evaluation/visualisation scripts** for embeddings, anti-spoofing signals, and authentication performance.

## Architecture

```text
                           +----------------------+
                           |      main.py         |
                           |   Application Entry  |
                           +----------+-----------+
                                      |
                                      v
                           +----------------------+
                           |     GUI/main_gui.py  |
                           |   Tkinter Application |
                           +----------+-----------+
                                      |
                    +-----------------+-----------------+
                    |                                   |
                    v                                   v
          +-------------------+                +-------------------+
          | Authentication    |                | Security Monitor  |
          |      auth/         |                |       ids/         |
          +---------+---------+                +---------+---------+
                    |                                    |
        +-----------+-----------+              +---------+----------+
        |           |           |              |         |          |
        v           v           v              v         v          v
   Detection   Recognition  Liveness/      Feature   Network    Hybrid IDS
                            Anti-Spoof      Extractor  Monitor  RF + IF
        |           |           |              |         |          |
        +-----------+-----------+--------------+---------+----------+
                                      |
                                      v
                           +----------------------+
                           | Audit / Session / DB |
                           |       db/            |
                           +----------------------+
```

## Project Structure

```text
Facial_recognition_system/
├── main.py                         # Main application entry point
├── GUI/                            # Desktop GUI and pages/components
│   ├── main_gui.py
│   ├── config.py
│   ├── styles.py
│   ├── login_page.py
│   ├── pages/
│   │   ├── login_page.py
│   │   ├── admin_panel.py
│   │   └── monitoring_page.py
│   │   └── components/
│   └── ...
├── auth/                           # Authentication and biometric security
│   ├── auth_system.py
│   ├── account_manager.py
│   ├── face_detector.py
│   ├── face_recognizer.py
│   ├── liveness_detector.py
│   ├── anti_spoof.py
│   ├── session_manager.py
│   └── audit_logger.py
├── ids/                            # Intrusion detection subsystem
│   ├── hybrid_ids.py
│   ├── feature_extractor.py
│   ├── network_monitor.py
│   ├── dataset_generator.py
│   └── train_ids.py
├── utils/                          # Enrollment and diagnostic utilities
│   ├── enroll_face.py
│   ├── find_cameras.py
│   ├── arcface_test.py
│   └── test_*.py
├── dataset/                        # Training/experimental datasets
├── db/                             # Local application data and models
├── docs/
│   └── results/                    # Evaluation figures and visual outputs
├── calibrate_anti_spoof.py         # Anti-spoof calibration utility
├── generate_*.py                   # Evaluation/data-generation utilities
├── visualize_embeddings.py         # Embedding visualisation
├── testing_framework*.py           # System evaluation frameworks
└── .gitignore
```

> The tree above describes the intended organization. The source modules retain their existing import paths so the application can be run without a large-scale refactor.

## Technologies

| Area | Technology |
|---|---|
| Language | Python 3 |
| GUI | Tkinter |
| Computer vision | OpenCV |
| Face analysis | InsightFace |
| Face representation | ArcFace embeddings |
| Numerical processing | NumPy |
| Machine learning | scikit-learn |
| Data processing | pandas |
| Visualisation | Matplotlib |
| System/network monitoring | psutil |
| Image handling | Pillow |

## How the Authentication Pipeline Works

1. The application starts through `main.py` and launches the Tkinter GUI.
2. The camera subsystem captures frames in a background thread so camera processing does not block the GUI.
3. A face is detected and an embedding is produced for recognition.
4. The live user is checked using blink/liveness logic.
5. Anti-spoofing signals are evaluated and combined using the calibrated detector.
6. The face similarity score is compared with the configured recognition threshold.
7. Authentication, lockout, session, and audit information is updated.
8. Relevant authentication/network features are supplied to the IDS.
9. The hybrid IDS combines Random Forest classification with Isolation Forest anomaly detection to identify suspicious activity.

## Hybrid IDS

The IDS subsystem contains three main stages:

### 1. Feature extraction

`ids/feature_extractor.py` converts authentication and network observations into a structured feature vector.

### 2. Supervised detection

`ids/hybrid_ids.py` uses a **Random Forest** classifier for labelled security events.

### 3. Unsupervised anomaly detection

An **Isolation Forest** model provides an additional anomaly signal for activity that differs from normal behaviour.

This hybrid approach is intended to provide both known-event classification and anomaly detection rather than relying on one detection technique.

## Anti-Spoofing and Liveness

The anti-spoofing subsystem is implemented in `auth/anti_spoof.py`, while blink-based liveness is handled by `auth/liveness_detector.py`.

The repository also contains calibration and evaluation utilities for determining suitable thresholds on the target camera and lighting conditions. The generated figures in `docs/results/` provide visual evidence for the evaluation work.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Mrgrear/Facial_recognition_system.git
cd Facial_recognition_system
```

### 2. Create a virtual environment

Windows:

```bash
python -m venv .venv
.venv\Scripts\activate
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install the project dependencies

Install the Python packages required by the modules in the repository. A typical environment includes:

```bash
pip install numpy opencv-python pillow insightface onnxruntime scikit-learn pandas matplotlib psutil
```

If a package installation fails because of the local Python version or hardware-specific InsightFace/ONNX requirements, use the compatible package versions for that Python environment.

## Running the System

From the repository root:

```bash
python main.py
```

The GUI entry point is `GUI/main_gui.py` and the main application imports it from `main.py`.

## Useful Utilities

### Face enrollment

```bash
python utils/enroll_face.py
```

### Find available cameras

```bash
python utils/find_cameras.py
```

### Calibrate anti-spoofing

```bash
python calibrate_anti_spoof.py
```

### Train the IDS

The IDS training workflow uses the dataset-generation/training scripts in the repository. For the dedicated IDS trainer:

```bash
python ids/train_ids.py
```

### Visualise face embeddings

```bash
python visualize_embeddings.py
```

## Data and Security Notes

- Do **not** commit real users' biometric images, credentials, API keys, or other sensitive information.
- Local databases and generated model files may contain sensitive biometric/security information; protect them appropriately when deploying the system.
- Use synthetic or anonymised data for demonstrations and public repositories whenever possible.
- Camera index and anti-spoof thresholds are hardware/environment dependent and should be calibrated before deployment.

## Evaluation Outputs

The `docs/results/` directory contains generated evaluation figures covering areas such as:

- ArcFace embedding visualisation
- EAR distribution and threshold analysis
- FAR/FRR/DET performance
- Anti-spoof score distributions
- Anti-spoof burst verification
- Three-signal contribution analysis

These figures support the experimental/evaluation stage of the project and are separate from the runtime source code.

## Development Notes

The repository intentionally separates runtime modules from diagnostic and evaluation utilities. Before adding new functionality, place code in the subsystem it belongs to rather than adding another large script to the repository root.

Recommended locations:

- Authentication/biometric logic → `auth/`
- IDS and security analytics → `ids/`
- GUI functionality → `GUI/`
- Small diagnostics/enrollment helpers → `utils/`
- Evaluation figures → `docs/results/`
- Datasets → `dataset/`
- Runtime/local state → `db/`

## Project Status

This repository represents an academic prototype/final-year project implementation. It is suitable for research, demonstration, and controlled testing, but should undergo additional security, privacy, performance, and usability testing before production deployment.

## License

No license is currently specified for this repository. Until a license is added, the source should be treated as **all rights reserved**.
