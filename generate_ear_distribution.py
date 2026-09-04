"""
generate_ear_distribution.py
------------------------------
Generates Figure 5.5: a histogram of real EAR (Eye Aspect Ratio)
values collected across two live capture phases:

  Phase 1 - EYES OPEN  : several seconds of frames with eyes open normally
  Phase 2 - EYES CLOSED: several seconds of frames with eyes held shut

Uses the EXISTING LivenessDetector.detect() method directly, so the
EAR values plotted are computed by the same code your system actually
uses during login/signup - not a separate mock calculation.

Usage:
    python generate_ear_distribution.py

Controls:
    Just follow the on-screen countdown for each phase.
    ESC = quit at any time.
"""

import sys
sys.path.append(".")

import cv2
import numpy as np
import matplotlib.pyplot as plt

from auth.liveness_detector import LivenessDetector

CAMERA_INDEX = 1
PHASE_SECONDS = 5          # how long each phase captures for
EAR_THRESHOLD = 0.25        # must match main_gui.py / LivenessDetector default


def run_phase(cap, liveness_det, label, seconds):
    print(f"\n=== PHASE: {label} — hold this for {seconds} seconds ===")
    import time
    ear_values = []
    start = time.time()
    while time.time() - start < seconds:
        ret, frame = cap.read()
        if not ret:
            continue
        remaining = seconds - (time.time() - start)
        disp = frame.copy()
        cv2.putText(disp, label, (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 255, 0), 2)
        cv2.putText(disp, f"Time remaining: {remaining:.1f}s", (10, 65),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.65, (0, 255, 255), 2)
        cv2.imshow("EAR Distribution Capture", disp)

        key = cv2.waitKey(1) & 0xFF
        if key == 27:
            cv2.destroyAllWindows()
            sys.exit(0)

        is_live, blinks, ear = liveness_det.detect(frame)
        if ear > 0:
            ear_values.append(ear)

    print(f"  Collected {len(ear_values)} EAR samples for '{label}'")
    return ear_values


def main():
    print("Loading liveness detector...")
    liveness_det = LivenessDetector()

    cap = cv2.VideoCapture(CAMERA_INDEX)
    if not cap.isOpened():
        cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("[ERROR] Could not open camera.")
        return

    print("\nThis will capture two phases. Follow the on-screen prompts.")
    print("Get ready to look at the camera with EYES OPEN normally first...")
    cv2.waitKey(1500)
    open_ears = run_phase(cap, liveness_det, "EYES OPEN - look normally", PHASE_SECONDS)

    print("\nNow get ready to hold your EYES CLOSED...")
    cv2.waitKey(1500)
    liveness_det.reset()
    closed_ears = run_phase(cap, liveness_det, "EYES CLOSED - hold shut", PHASE_SECONDS)

    cap.release()
    cv2.destroyAllWindows()

    if not open_ears or not closed_ears:
        print("[ERROR] Not enough samples captured in one or both phases.")
        return

    open_ears = np.array(open_ears)
    closed_ears = np.array(closed_ears)

    print(f"\nOpen-eye EAR:   n={len(open_ears)}  mean={open_ears.mean():.3f}  "
          f"min={open_ears.min():.3f}  max={open_ears.max():.3f}")
    print(f"Closed-eye EAR: n={len(closed_ears)}  mean={closed_ears.mean():.3f}  "
          f"min={closed_ears.min():.3f}  max={closed_ears.max():.3f}")

    overlap = np.sum(closed_ears >= EAR_THRESHOLD) + np.sum(open_ears < EAR_THRESHOLD)
    print(f"Samples crossing the {EAR_THRESHOLD} threshold in the 'wrong' direction: {overlap}")

    plt.figure(figsize=(9, 6))
    plt.hist(open_ears, bins=25, alpha=0.7, color="#3fb950", label=f"Eyes Open (n={len(open_ears)})")
    plt.hist(closed_ears, bins=25, alpha=0.7, color="#f85149", label=f"Eyes Closed (n={len(closed_ears)})")
    plt.axvline(EAR_THRESHOLD, color="black", linestyle="--", linewidth=2,
                label=f"Threshold ({EAR_THRESHOLD})")
    plt.xlabel("Eye Aspect Ratio (EAR)")
    plt.ylabel("Frame Count")
    plt.title("EAR Value Distribution: Open vs. Closed Eyes")
    plt.legend()
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig("EAR_Distribution_and_Threshold.png", dpi=300)
    plt.close()
    print("\nSaved EAR_Distribution_and_Threshold.png")


if __name__ == "__main__":
    main()