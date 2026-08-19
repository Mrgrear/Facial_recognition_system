"""
calibrate_anti_spoof.py
-------------------------
Run this locally (with your webcam connected) to calibrate
AntiSpoofDetector's thresholds against REAL captured data instead of
synthetic guesses.

It walks you through capturing three batches of frames:
  1. Your real face (normal login conditions)
  2. A printed photo of your face held up to the camera
  3. Your phone or a monitor showing your photo/video, held up to
     the camera (screen replay)

For each batch it runs the current AntiSpoofDetector and prints the
resulting spoof_score distribution, so you can see exactly where
"real" and "fake" separate on YOUR hardware/lighting, and pick a
combined_threshold with real evidence behind it.

Usage:
    python calibrate_anti_spoof.py

Controls during capture:
    SPACE = capture a frame for the current batch
    ENTER = finish this batch early / move to next
    ESC   = quit calibration entirely
"""

import sys
sys.path.append(".")

import cv2
import numpy as np

from auth.face_detector import FaceDetector
from auth.anti_spoof import AntiSpoofDetector

CAMERA_INDEX = 1   # match your main_gui.py CAMERA_INDEX setting
FRAMES_PER_BATCH = 15


def wait_for_enter_in_window(cap, lines):
    """Shows a prompt INSIDE the camera window and waits for ENTER
    there, instead of blocking on console input() — blocking on
    input() stops the camera window's event loop from being serviced,
    which makes Windows show it as 'Not Responding' even though
    nothing has actually crashed."""
    while True:
        ret, frame = cap.read()
        if not ret:
            continue
        disp = frame.copy()
        y = 30
        for line in lines:
            cv2.putText(disp, line, (10, y), cv2.FONT_HERSHEY_SIMPLEX,
                        0.65, (0, 255, 255), 2)
            y += 35
        cv2.putText(disp, "Press ENTER when ready, ESC to quit",
                    (10, y + 10), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
        cv2.imshow("Anti-Spoof Calibration", disp)

        key = cv2.waitKey(1) & 0xFF
        if key == 13:  # ENTER
            return
        elif key == 27:  # ESC
            cv2.destroyAllWindows()
            sys.exit(0)


def capture_batch(cap, detector, label, n_frames):
    print(f"\n=== Capturing '{label}' — press SPACE to capture, "
          f"ENTER to finish early, ESC to quit ===")
    scores = []
    details_list = []
    captured = 0

    while captured < n_frames:
        ret, frame = cap.read()
        if not ret:
            continue

        disp = frame.copy()
        cv2.putText(disp, f"{label}: {captured}/{n_frames} captured",
                    (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
        cv2.putText(disp, "SPACE=capture  ENTER=next batch  ESC=quit",
                    (10, 60), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 255), 1)
        cv2.imshow("Anti-Spoof Calibration", disp)

        key = cv2.waitKey(1) & 0xFF
        if key == 27:  # ESC
            cv2.destroyAllWindows()
            sys.exit(0)
        elif key == 13:  # ENTER
            break
        elif key == 32:  # SPACE
            faces = detector["face_detector"].detect_sync(frame)
            if len(faces) != 1:
                print(f"  ⚠ Need exactly 1 face, found {len(faces)}. Try again.")
                continue
            is_live, spoof_score, details = detector["anti_spoof"].analyze(frame, faces[0])
            scores.append(spoof_score)
            details_list.append(details)
            captured += 1
            print(f"  Frame {captured}: spoof_score={spoof_score:.3f}  "
                  f"is_live={is_live}  {details}")

    # Final redraw so the on-screen counter reflects the true final
    # count before we move to the next batch's wait screen.
    ret, frame = cap.read()
    if ret:
        disp = frame.copy()
        cv2.putText(disp, f"{label}: {captured}/{n_frames} captured — done",
                    (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
        cv2.imshow("Anti-Spoof Calibration", disp)
        cv2.waitKey(1)

    return scores, details_list


def main():
    print("Loading models (this may take a moment)...")
    face_detector = FaceDetector()
    anti_spoof = AntiSpoofDetector()
    detector = {"face_detector": face_detector, "anti_spoof": anti_spoof}

    cap = cv2.VideoCapture(CAMERA_INDEX)
    if not cap.isOpened():
        cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("[ERROR] Could not open camera.")
        return

    print("\nThis will capture three batches. Follow the on-screen prompts.")

    real_scores, _ = capture_batch(cap, detector, "REAL FACE (normal login)", FRAMES_PER_BATCH)

    wait_for_enter_in_window(cap, [
        "Batch 1 done. Now hold up a PRINTED PHOTO",
        "of your face to the camera."
    ])
    print_scores, _ = capture_batch(cap, detector, "PRINTED PHOTO", FRAMES_PER_BATCH)

    wait_for_enter_in_window(cap, [
        "Batch 2 done. Now hold up your PHONE/MONITOR",
        "showing your photo or a video of yourself."
    ])
    screen_scores, _ = capture_batch(cap, detector, "SCREEN REPLAY", FRAMES_PER_BATCH)

    cap.release()
    cv2.destroyAllWindows()

    def stats(name, scores):
        if not scores:
            print(f"{name}: no samples captured.")
            return
        arr = np.array(scores)
        print(f"{name:<15} n={len(arr):<3} mean={arr.mean():.3f}  "
              f"min={arr.min():.3f}  max={arr.max():.3f}  std={arr.std():.3f}")

    print("\n" + "=" * 60)
    print("SPOOF SCORE SUMMARY  (0.0 = looks fully real, 1.0 = looks fully fake)")
    print("=" * 60)
    stats("Real face", real_scores)
    stats("Printed photo", print_scores)
    stats("Screen replay", screen_scores)

    if real_scores and (print_scores or screen_scores):
        real_max = max(real_scores)
        fake_scores = print_scores + screen_scores
        fake_min = min(fake_scores) if fake_scores else None

        print("\n--- Suggested threshold ---")
        if fake_min is not None and fake_min > real_max:
            suggested = (real_max + fake_min) / 2
            print(f"Clean separation found. Real max={real_max:.3f}, "
                  f"Fake min={fake_min:.3f}")
            print(f"Suggested combined_threshold (spoof_score cutoff): "
                  f"{1 - suggested:.3f}")
            print(f"(i.e. set AntiSpoofDetector(combined_threshold="
                  f"{1 - suggested:.3f}) in main_gui.py)")
        else:
            print("⚠ Overlap detected between real and fake score ranges.")
            print(f"  Real face max spoof_score: {real_max:.3f}")
            print(f"  Fake min spoof_score:      {fake_min:.3f}" if fake_min else "")
            print("  This means the current heuristics don't cleanly separate")
            print("  real vs fake on your hardware yet. Consider: better")
            print("  lighting, closer/steadier camera framing during capture,")
            print("  or share these numbers so the detection logic can be")
            print("  adjusted further before enabling auto-block.")


if __name__ == "__main__":
    main()