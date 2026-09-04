# Enhanced Facial Authentication System with Hybrid IDS

A Python-based security system that combines **facial authentication, liveness and anti-spoofing checks, audit logging, session controls, and a hybrid machine-learning intrusion detection system (IDS)** in a desktop GUI.

> **Academic project:** Nigerian Army University Biu (NAUB), Department of Cyber Security  
> **Student:** Omu John Efu (CYB/23U/3983)  
> **Supervisor:** Dr. A. H. Desina

## Overview

The system is designed as a layered authentication and security-monitoring platform. A user is verified through facial recognition, while liveness and anti-spoofing controls help detect presentation attacks. Authentication and network activity are recorded and analysed by a hybrid IDS that combines supervised and unsupervised machine learning.

The implementation is organized into authentication (`auth/`), intrusion detection (`ids/`), graphical interface (`GUI/`), utilities (`utils/`), local data/model storage (`db/` and `models/`), datasets (`dataset/`), and documentation/evaluation outputs (`docs/`).

## Key Features

- Face detection using InsightFace.
- Face recognition using ArcFace-style embeddings and similarity matching.
- Blink-based liveness verification using Eye Aspect Ratio (EAR).
- Multi-signal anti-spoofing with calibrated thresholds.
- Burst verification to reduce dependence on a single frame.
- Account management and failed-attempt controls.
- Session management and authentication-state handling.
- Audit logging of security events.
- Hybrid IDS using Random Forest classification and Isolation Forest anomaly detection.
- Network monitoring and IDS feature extraction.
- Administrator and monitoring interfaces.
- Evaluation/calibration utilities for biometric and IDS experiments.

## System Architecture

```text
                         +----------------------+
                         |       main.py        |
                         |  Application Entry    |
                         +----------+-----------+
                                    |
                                    v
                         +----------------------+
                         |   GUI/main_gui.py    |
                         |    Tkinter GUI        |
                         +----------+-----------+
                                    |
                 +------------------+------------------+
                 |                                     |
                 v                                     v
       +--------------------+                +--------------------+
       | Authentication     |                | Security / IDS     |
       |      auth/         |                |       ids/         |
       +---------+----------+                +---------+----------+
                 |                                     |
     +-----------+-----------+              +----------+----------+
     |           |           |              |          |          |
     v           v           v              v          v          v
 Detection  Recognition  Liveness/      Features  Network     Hybrid IDS
                         Anti-Spoof      Extractor  Monitor    RF + IF
     |           |           |              |          |          |
     +-----------+-----------+--------------+----------+----------+
                                    |
                                    v
                         +----------------------+
                         | Audit / Session / DB |
                         |       db/            |
                         +----------------------+
```

## Repository Structure

```text
Facial_recognition_system/
├── main.py                    # Primary application entry point
├── setup_and_run.py           # Optional setup/scaffolding utility
├── requirements.txt           # Python dependencies
├── LICENSE                    # Project usage/copyright notice
├── README.md                  # Main project documentation
├── .gitignore                 # Ignores local/sensitive generated data
│
├── auth/                      # Biometric authentication and security logic
│   ├── account_manager.py
│   ├── anti_spoof.py
│   ├── audit_logger.py
│   ├── auth_system.py
│   ├── face_detector.py
│   ├── face_recognizer.py
│   ├── liveness_detector.py
│   └── session_manager.py
│
├── GUI/                      # Tkinter desktop interface
│   ├── main_gui.py
│   ├── config.py
│   ├── styles.py
│   ├── login_page.py
│   ├── pages/
│   │   ├── login_page.py
│   │   ├── admin_panel.py
│   │   └── monitoring_page.py
│   └── components/
│
├── ids/                      # Hybrid intrusion detection subsystem
│   ├── hybrid_ids.py
│   ├── feature_extractor.py
│   ├── network_monitor.py
│   ├── dataset_generator.py
│   └── train_ids.py
│
├── utils/                    # Enrollment, diagnostics and test helpers
├── dataset/                  # Training/experimental data
├── db/                       # Local runtime state (kept out of public Git)
├── models/                   # Trained model artifacts (kept out of public Git)
│
├── docs/
│   ├── PROJECT_STRUCTURE.md
│   └── results/              # Evaluation figures
│
├── calibrate_anti_spoof.py   # Anti-spoof calibration
└── visualize_embeddings.py   # Embedding visualization
```

Generated `__pycache__` directories and runtime biometric/model data are intentionally excluded from version control. The repository should contain source code and reproducible documentation, not private user data.

## Technologies

| Area | Technology |
|---|---|
| Programming language | Python 3 |
| GUI | Tkinter |
| Computer vision | OpenCV |
| Face analysis | InsightFace |
| Face representation | ArcFace embeddings |
| Numerical processing | NumPy |
| Machine learning | scikit-learn |
| Data processing | pandas |
| Visualisation | Matplotlib |
| Image handling | Pillow |
| System/network monitoring | psutil |
| ONNX inference | ONNX Runtime |

## Authentication Workflow

1. `main.py` starts the desktop application.
2. `GUI/main_gui.py` coordinates the GUI pages.
3. Camera frames are captured for authentication.
4. A face is detected and an embedding is generated.
5. The embedding is compared against enrolled identities.
6. Liveness is verified using blink/EAR behaviour.
7. Anti-spoofing signals are evaluated, including burst verification where configured.
8. Authentication and session state are updated.
9. Security events are written to the local audit system.
10. Relevant authentication/network features are passed to the IDS.
11. The hybrid IDS evaluates the event using classification and anomaly detection.
12. The GUI reports the resulting authentication/security state.

## Hybrid Intrusion Detection System

The IDS is divided into complementary stages:

### Feature extraction

`ids/feature_extractor.py` converts authentication and network observations into structured features suitable for machine-learning models.

### Random Forest classification

The supervised component uses **Random Forest** to classify labelled security events. It is useful when examples of known normal and suspicious behaviours are available.

### Isolation Forest anomaly detection

The unsupervised component uses **Isolation Forest** to identify observations that differ from learned normal behaviour. This provides an additional signal for previously unseen or unusual activity.

The combination is intended to reduce reliance on a single detection technique and provide both known-pattern classification and anomaly detection.

## Liveness and Anti-Spoofing

The liveness subsystem uses blink/EAR-based verification, while `auth/anti_spoof.py` provides additional anti-spoofing logic. Calibration and evaluation scripts are included so thresholds can be studied under different cameras and lighting conditions.

The repository includes evaluation figures for EAR behaviour, anti-spoof scores, burst verification, three-signal analysis, and authentication performance.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Mrgrear/Facial_recognition_system.git
cd Facial_recognition_system
```

### 2. Create a virtual environment

**Windows**

```bash
python -m venv .venv
.venv\Scripts\activate
```

**Linux/macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

> InsightFace/ONNX Runtime can have Python-version and platform-specific requirements. If installation fails, use a Python version supported by the installed InsightFace/ONNX Runtime packages.

## Running the Application

From the repository root:

```bash
python main.py
```

`main.py` is the supported application entry point and launches `GUI/main_gui.py`.

## Useful Commands

### Enrol a face

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

```bash
python ids/train_ids.py
```

### Visualise face embeddings

```bash
python visualize_embeddings.py
```

## Data and Security

This is a biometric-security project, so repository hygiene is important.

- Never commit real users' face images, embeddings, passwords, email addresses, API keys, or audit records.
- Runtime files under `db/` and trained artifacts under `models/` may contain sensitive information and are ignored by Git.
- Use synthetic, anonymised, or explicitly approved sample data for demonstrations.
- Camera settings and anti-spoof thresholds should be calibrated for the deployment environment.
- Do not treat this academic prototype as production-ready without additional security, privacy, performance, and usability testing.

## Evaluation Results

Generated figures are stored in `docs/results/` instead of cluttering the repository root. They include analyses of:

- ArcFace embedding distributions/visualisation
- EAR distributions and thresholds
- FAR/FRR and DET performance
- Anti-spoof score distributions
- Burst verification performance
- Three-signal anti-spoof contribution

## Development Guidelines

Keep new code in the subsystem responsible for it:

- Authentication/biometrics → `auth/`
- Intrusion detection/network security → `ids/`
- GUI → `GUI/`
- Small operational utilities → `utils/`
- Documentation/evaluation figures → `docs/`
- Datasets → `dataset/`
- Local runtime state → `db/`
- Trained model artifacts → `models/`

Avoid adding large experimental scripts or generated data directly to the repository root.

## Academic Project

**Institution:** Nigerian Army University Biu (NAUB)  
**Faculty:** Faculty of Computing  
**Department:** Cyber Security  
**Student:** Omu John Efu (CYB/23U/3983)  
**Supervisor:** Dr. A. H. Desina

## License

This project is currently distributed under the repository's **all-rights-reserved academic project notice**. See [`LICENSE`](LICENSE) for details.
