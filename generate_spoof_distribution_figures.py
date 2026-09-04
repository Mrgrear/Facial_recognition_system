"""
generate_spoof_distribution_figures.py
-----------------------------------------
Generates Figure 5.7 (spoof score distribution across three conditions)
and Figure 5.8 (per-signal contribution breakdown), using REAL captured
bursts and the actual AntiSpoofDetector signal computations.

Captures three conditions:
  1. LIVE FACE
  2. PHOTO SPOOF (printed photo held to camera)
  3. VIDEO REPLAY (phone/monitor showing your face)

Usage:
    python generate_spoof_distribution_figures.py

Controls:
    SPACE = capture a frame
    ENTER = finish this condition's batch / move to next
    ESC   = quit
"""

import sys
sys.path.append(".")

import cv2
import numpy as np
import matplotlib.pyplot as plt

from auth.face_detector import FaceDetector
from auth.anti_spoof import AntiSpoofDetector

CAMERA_INDEX = 1
FRAMES_PER_CONDITION = 15
COMBINED_THRESHOLD = 0.70          # matches main_gui.py
SPOOF_SCORE_THRESHOLD = 1.0 - COMBINED_THRESHOLD   # = 0.30, the correct cutoff on this plotted scale


def capture_condition(cap, face_detector, anti_spoof, label, n_frames):
    print(f"\n=== Capturing '{label}' — SPACE=capture, ENTER=finish early, ESC=quit ===")
    spoof_scores = []
    sharp_contribs, moire_contribs, color_contribs = [], [], []
    captured = 0
    while captured < n_frames:
        ret, frame = cap.read()
        if not ret:
            continue
        disp = frame.copy()
        cv2.putText(disp, f"{label}: {captured}/{n_frames} captured",
                    (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
        cv2.putText(disp, "SPACE=capture  ENTER=finish  ESC=quit",
                    (10, 60), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 255), 1)
        cv2.imshow("Spoof Distribution Capture", disp)
        key = cv2.waitKey(1) & 0xFF
        if key == 27:
            cv2.destroyAllWindows()
            sys.exit(0)
        elif key == 13:
            break
        elif key == 32:
            faces = face_detector.detect_sync(frame)
            if len(faces) != 1:
                print(f"  Need exactly 1 face, found {len(faces)}. Try again.")
                continue
            is_live, spoof_score, details = anti_spoof.analyze(frame, faces[0])
            spoof_scores.append(spoof_score)
            # Per-signal contribution to spoof_score, using the ACTUAL
            # weights from anti_spoof.py: 0.4 / 0.4 / 0.2
            sharp_contribs.append((1 - details["sharpness_score"]) * 0.4)
            moire_contribs.append((1 - details["moire_score"]) * 0.4)
            color_contribs.append((1 - details["color_score"]) * 0.2)
            captured += 1
            print(f"  Frame {captured}: spoof_score={spoof_score:.3f}  {details}")

    return {
        "spoof_scores": spoof_scores,
        "sharp": sharp_contribs,
        "moire": moire_contribs,
        "color": color_contribs,
    }


def main():
    print("Loading models...")
    face_detector = FaceDetector()
    anti_spoof = AntiSpoofDetector(combined_threshold=COMBINED_THRESHOLD)

    cap = cv2.VideoCapture(CAMERA_INDEX)
    if not cap.isOpened():
        cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("[ERROR] Could not open camera.")
        return

    live_data = capture_condition(cap, face_detector, anti_spoof,
                                   "LIVE FACE - position normally", FRAMES_PER_CONDITION)

    print("\nGet ready to hold up a PRINTED PHOTO of your face...")
    cv2.waitKey(1500)
    photo_data = capture_condition(cap, face_detector, anti_spoof,
                                    "PHOTO SPOOF - hold up printed photo", FRAMES_PER_CONDITION)

    print("\nGet ready to hold up your PHONE/MONITOR showing your face...")
    cv2.waitKey(1500)
    video_data = capture_condition(cap, face_detector, anti_spoof,
                                    "VIDEO REPLAY - hold up phone/screen", FRAMES_PER_CONDITION)

    cap.release()
    cv2.destroyAllWindows()

    conditions = {"Live Face": live_data, "Photo Spoof": photo_data, "Video Replay": video_data}

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for name, data in conditions.items():
        arr = np.array(data["spoof_scores"])
        if len(arr) == 0:
            print(f"{name}: no samples captured.")
            continue
        print(f"{name:<15} n={len(arr):<3} mean={arr.mean():.3f}  min={arr.min():.3f}  max={arr.max():.3f}")

    # ── Figure 5.7: histogram of spoof scores across the three conditions ──
    plt.figure(figsize=(10, 6))
    colors = {"Live Face": "#3fb950", "Photo Spoof": "#f85149", "Video Replay": "#d29922"}
    for name, data in conditions.items():
        arr = np.array(data["spoof_scores"])
        if len(arr) > 0:
            plt.hist(arr, bins=15, alpha=0.65, label=f"{name} (n={len(arr)}, mean={arr.mean():.2f})",
                      color=colors[name])
    plt.axvline(SPOOF_SCORE_THRESHOLD, color="black", linestyle="--", linewidth=2,
                label=f"Threshold ({SPOOF_SCORE_THRESHOLD:.2f})")
    plt.xlabel("Combined Spoof Score (0 = looks real, 1 = looks fake)")
    plt.ylabel("Frame Count")
    plt.title("Anti-Spoofing Score Distribution: Live vs. Photo vs. Video Replay")
    plt.legend()
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig("Anti_Spoof_Score_Distribution.png", dpi=300)
    plt.close()
    print("\nSaved Anti_Spoof_Score_Distribution.png")

    # ── Figure 5.8: stacked bar chart of average per-signal contribution ──
    labels = list(conditions.keys())
    sharp_means = [np.mean(conditions[l]["sharp"]) if conditions[l]["sharp"] else 0 for l in labels]
    moire_means = [np.mean(conditions[l]["moire"]) if conditions[l]["moire"] else 0 for l in labels]
    color_means = [np.mean(conditions[l]["color"]) if conditions[l]["color"] else 0 for l in labels]

    x = np.arange(len(labels))
    plt.figure(figsize=(9, 6))
    p1 = plt.bar(x, sharp_means, label="Laplacian Sharpness (weight 0.40)", color="#1f6feb")
    p2 = plt.bar(x, moire_means, bottom=sharp_means, label="FFT Moir\u00e9 (weight 0.40)", color="#f85149")
    bottom2 = np.array(sharp_means) + np.array(moire_means)
    p3 = plt.bar(x, color_means, bottom=bottom2, label="HSV Saturation (weight 0.20)", color="#d29922")

    totals = np.array(sharp_means) + np.array(moire_means) + np.array(color_means)
    for xi, t in zip(x, totals):
        plt.text(xi, t + 0.01, f"{t:.3f}", ha="center", fontweight="bold")

    plt.xticks(x, labels)
    plt.ylabel("Average Contribution to Spoof Score")
    plt.title("Per-Signal Contribution to Spoof Score by Condition\n(Laplacian 40% + FFT 40% + HSV 20%)")
    plt.legend()
    plt.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig("Three_Signal_Contribution_Analysis.png", dpi=300)
    plt.close()
    print("Saved Three_Signal_Contribution_Analysis.png")

    print("\nDone. Update your captions with these REAL numbers instead of placeholders.")


if __name__ == "__main__":
    main()