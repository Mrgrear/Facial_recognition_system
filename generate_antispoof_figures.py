"""
generate_antispoof_figures.py
------------------------------
Generates Figure 4.5 (three-signal comparison) and Figure 4.6
(4-frame burst verification) for Chapter 4, using the real
AntiSpoofDetector signal computations and the actual 40/40/20
weighting + 0.70 threshold used in main_gui.py.

Controls:
    SPACE = capture a frame
    ENTER = move to next stage
    ESC   = quit
"""

import sys
sys.path.append(".")

import cv2
import numpy as np
import matplotlib.pyplot as plt

from auth.face_detector import FaceDetector
from auth.anti_spoof import AntiSpoofDetector

CAMERA_INDEX = 1          # match your main_gui.py setting
BURST_N = 4                # matches ANTI_SPOOF_BURST_FRAMES in main_gui.py
COMBINED_THRESHOLD = 0.70  # matches main_gui.py's AntiSpoofDetector(combined_threshold=0.70)


def get_face_crop(frame, face_detector):
    faces = face_detector.detect_sync(frame)
    if len(faces) != 1:
        return None, None
    x1, y1, x2, y2 = faces[0][0], faces[0][1], faces[0][2], faces[0][3]
    h, w = frame.shape[:2]
    x1, y1 = max(0, x1), max(0, y1)
    x2, y2 = min(w, x2), min(h, y2)
    if x2 <= x1 or y2 <= y1:
        return None, None
    face_bgr = frame[y1:y2, x1:x2]
    face_bgr = cv2.resize(face_bgr, (200, 200))
    face_gray = cv2.cvtColor(face_bgr, cv2.COLOR_BGR2GRAY)
    return face_bgr, face_gray


def capture_one_good_frame(cap, face_detector, prompt_lines):
    """Shows a live prompt window until SPACE captures a frame with
    exactly one detected face."""
    while True:
        ret, frame = cap.read()
        if not ret:
            continue
        disp = frame.copy()
        y = 30
        for line in prompt_lines:
            cv2.putText(disp, line, (10, y), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 255), 2)
            y += 30
        cv2.putText(disp, "SPACE=capture  ESC=quit", (10, y + 10),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.55, (0, 255, 0), 2)
        cv2.imshow("Anti-Spoof Figure Capture", disp)
        key = cv2.waitKey(1) & 0xFF
        if key == 27:
            cv2.destroyAllWindows()
            sys.exit(0)
        elif key == 32:
            faces = face_detector.detect_sync(frame)
            if len(faces) == 1:
                return frame.copy()
            print(f"  Need exactly 1 face, found {len(faces)}. Try again.")


def capture_burst(cap, face_detector, n, prompt_lines):
    frames = []
    while len(frames) < n:
        f = capture_one_good_frame(cap, face_detector,
                                    prompt_lines + [f"Captured {len(frames)}/{n}"])
        frames.append(f)
    return frames


def wait_enter(cap, lines):
    while True:
        ret, frame = cap.read()
        if not ret:
            continue
        disp = frame.copy()
        y = 30
        for line in lines:
            cv2.putText(disp, line, (10, y), cv2.FONT_HERSHEY_SIMPLEX, 0.65, (0, 255, 255), 2)
            y += 35
        cv2.putText(disp, "Press ENTER when ready, ESC to quit", (10, y + 10),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
        cv2.imshow("Anti-Spoof Figure Capture", disp)
        key = cv2.waitKey(1) & 0xFF
        if key == 13:
            return
        elif key == 27:
            cv2.destroyAllWindows()
            sys.exit(0)


# ── Figure 4.5: three-signal panel comparison ──────────────────────

def build_figure_4_5(detector, real_frame, spoof_frame):
    fig, axes = plt.subplots(2, 3, figsize=(15, 9))
    row_labels = ["Live Face", "Spoofed Image"]

    for row, frame in enumerate([real_frame, spoof_frame]):
        face_bgr, face_gray = get_face_crop(frame, detector["face_detector"])
        if face_bgr is None:
            for col in range(3):
                axes[row, col].set_title("No face detected")
                axes[row, col].axis("off")
            continue

        anti_spoof = detector["anti_spoof"]
        sharp_score, lap_var = anti_spoof._sharpness_score(face_gray)
        moire_score, moire_strength, moire_flagged = anti_spoof._moire_score(face_gray)
        color_score, mean_sat, std_sat = anti_spoof._color_naturalness_score(face_bgr)
        combined = (sharp_score * 0.4) + (moire_score * 0.4) + (color_score * 0.2)
        if moire_strength > 0.65:
            combined = min(combined, 0.3)
        spoof_score = 1.0 - combined
        verdict = "LIVE" if combined >= COMBINED_THRESHOLD else "SPOOF"

        # --- Panel 1: Laplacian sharpness heatmap ---
        lap = cv2.Laplacian(face_gray, cv2.CV_64F)
        axes[row, 0].imshow(np.abs(lap), cmap="jet")
        axes[row, 0].set_title(f"Laplacian Sharpness\nscore={sharp_score:.3f}  (var={lap_var:.1f})")
        axes[row, 0].axis("off")

        # --- Panel 2: FFT frequency spectrum ---
        f = np.fft.fft2(face_gray.astype(np.float32))
        fshift = np.fft.fftshift(f)
        magnitude = np.log(np.abs(fshift) + 1)
        axes[row, 1].imshow(magnitude, cmap="viridis")
        axes[row, 1].set_title(f"FFT Moir\u00e9 Detection\nscore={moire_score:.3f}  "
                                f"(strength={moire_strength:.3f})")
        axes[row, 1].axis("off")

        # --- Panel 3: HSV saturation histogram ---
        hsv = cv2.cvtColor(face_bgr, cv2.COLOR_BGR2HSV)
        sat = hsv[:, :, 1].astype(np.float32) / 255.0
        axes[row, 2].hist(sat.ravel(), bins=40, color="orange", alpha=0.8)
        axes[row, 2].axvline(mean_sat, color="red", linestyle="--", label=f"mean={mean_sat:.3f}")
        axes[row, 2].set_title(f"HSV Saturation\nscore={color_score:.3f}  (std={std_sat:.3f})")
        axes[row, 2].legend(fontsize=8)

        fig.text(0.02, 0.75 - row * 0.5,
                  f"{row_labels[row]}\nCombined: {combined:.3f}\nVerdict: {verdict}",
                  fontsize=11, fontweight="bold",
                  color="green" if verdict == "LIVE" else "red",
                  va="center")

    plt.suptitle("Three-Signal Anti-Spoofing Analysis (Laplacian 40% + FFT Moir\u00e9 40% + HSV 20%)",
                  fontsize=13, fontweight="bold")
    plt.tight_layout(rect=[0.08, 0, 1, 0.95])
    plt.savefig("Anti_Spoof_Three_Signal_Analysis.png", dpi=300)
    plt.close()
    print("Saved: Anti_Spoof_Three_Signal_Analysis.png")


# ── Figure 4.6: burst verification bar chart ───────────────────────

def build_figure_4_6(detector, real_frames, spoof_frames):
    def burst_scores(frames):
        out = []
        for f in frames:
            faces = detector["face_detector"].detect_sync(f)
            if len(faces) != 1:
                continue
            _, spoof_score, details = detector["anti_spoof"].analyze(f, faces[0])
            out.append(spoof_score)
        return out

    real_scores = burst_scores(real_frames)
    spoof_scores = burst_scores(spoof_frames)

    fig, axes = plt.subplots(1, 2, figsize=(12, 5), sharey=True)
    threshold_line = 1.0 - COMBINED_THRESHOLD  # spoof_score threshold equivalent

    for ax, scores, label in zip(axes, [real_scores, spoof_scores], ["Live Face", "Spoofed Image"]):
        colors = ["#3fb950" if s < threshold_line else "#f85149" for s in scores]
        ax.bar(range(1, len(scores) + 1), scores, color=colors)
        ax.axhline(threshold_line, color="black", linestyle="--", linewidth=1.5,
                   label=f"Threshold ({threshold_line:.2f})")
        ax.set_xlabel("Frame Number")
        ax.set_ylabel("Spoof Score")
        ax.set_title(f"{label} — Burst Verification ({len(scores)} frames)")
        ax.set_ylim(0, 1)
        ax.legend()

    plt.suptitle("4-Frame Burst Verification: Live Face vs. Spoofed Image", fontsize=13, fontweight="bold")
    plt.tight_layout()
    plt.savefig("Anti_Spoof_Burst_Verification_Results.png", dpi=300)
    plt.close()
    print("Saved: Anti_Spoof_Burst_Verification_Results.png")


# ── Main ─────────────────────────────────────────────────────────

def main():
    print("Loading models...")
    face_detector = FaceDetector()
    anti_spoof = AntiSpoofDetector(combined_threshold=COMBINED_THRESHOLD)
    detector = {"face_detector": face_detector, "anti_spoof": anti_spoof}

    cap = cv2.VideoCapture(CAMERA_INDEX)
    if not cap.isOpened():
        cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("[ERROR] Could not open camera.")
        return

    print("\n--- STAGE 1: Live face burst (4 frames) ---")
    real_frames = capture_burst(cap, face_detector, BURST_N,
                                 ["STAGE 1: Position your REAL FACE normally"])

    wait_enter(cap, ["Stage 1 done. Now hold up a PRINTED PHOTO",
                      "or PHONE/SCREEN showing your face."])

    print("\n--- STAGE 2: Spoofed image burst (4 frames) ---")
    spoof_frames = capture_burst(cap, face_detector, BURST_N,
                                  ["STAGE 2: Hold up the PRINTED PHOTO or SCREEN"])

    cap.release()
    cv2.destroyAllWindows()

    print("\nGenerating Figure 4.5 (three-signal comparison)...")
    build_figure_4_5(detector, real_frames[0], spoof_frames[0])

    print("Generating Figure 4.6 (burst verification)...")
    build_figure_4_6(detector, real_frames, spoof_frames)

    print("\nDone. Both PNG files saved in the project root.")


if __name__ == "__main__":
    main()