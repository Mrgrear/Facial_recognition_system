"""
generate_far_frr_curves.py
----------------------------
Generates Figure 5.3 (FAR/FRR DET curve with EER point) and
Figure 5.4 (ROC curve, TAR vs FAR) from REAL data:

  - Impostor scores: computed from ALL pairwise comparisons between
    templates already stored in db/face_db.pkl (no new capture needed).
  - Genuine scores: computed by freshly capturing several live frames
    of whichever already-enrolled user(s) are physically available
    right now, compared against THEIR OWN stored template.

Usage:
    python generate_far_frr_curves.py

Controls during capture:
    SPACE = capture a frame
    ENTER = finish this user's batch / move to next
    ESC   = quit
"""

import sys
sys.path.append(".")

import pickle
import numpy as np
import cv2
import matplotlib.pyplot as plt

from auth.face_detector import FaceDetector
from auth.face_recognizer import FaceRecognizer

CAMERA_INDEX = 1
FRAMES_PER_USER = 8


def cosine_sim(a, b):
    n = np.linalg.norm(a) * np.linalg.norm(b)
    return float(np.dot(a, b) / (n + 1e-8))


def capture_fresh_samples(cap, face_detector, face_recognizer, username, n_frames):
    print(f"\n=== Capturing fresh live frames for '{username}' ===")
    print("Position your face normally. SPACE=capture, ENTER=finish early, ESC=quit")
    embeddings = []
    while len(embeddings) < n_frames:
        ret, frame = cap.read()
        if not ret:
            continue
        disp = frame.copy()
        cv2.putText(disp, f"{username}: {len(embeddings)}/{n_frames} captured",
                    (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
        cv2.putText(disp, "SPACE=capture  ENTER=finish  ESC=quit",
                    (10, 60), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 255), 1)
        cv2.imshow("FAR/FRR Genuine Sample Capture", disp)
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
            emb = face_recognizer.get_embedding(frame)
            if emb is not None:
                embeddings.append(emb)
                print(f"  Captured {len(embeddings)}/{n_frames}")
    return embeddings


def main():
    print("Loading models and face database...")
    face_detector = FaceDetector()
    face_recognizer = FaceRecognizer()
    db = face_recognizer.database  # {username: embedding}
    usernames = list(db.keys())
    print(f"Found {len(usernames)} enrolled templates in db/face_db.pkl")

    # -- Impostor scores: every stored template compared against every
    # OTHER stored template. No new capture needed. --
    impostor_scores = []
    for i, u1 in enumerate(usernames):
        for j, u2 in enumerate(usernames):
            if i >= j:
                continue
            impostor_scores.append(cosine_sim(db[u1], db[u2]))
    print(f"Computed {len(impostor_scores)} impostor score pairs from existing templates.")

    # -- Genuine scores: fresh live capture(s) vs the SAME user's stored template --
    cap = cv2.VideoCapture(CAMERA_INDEX)
    if not cap.isOpened():
        cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("[ERROR] Could not open camera.")
        return

    genuine_scores = []
    tested_users = []
    print("\nYou will now capture fresh live frames for whichever enrolled")
    print("user(s) are physically available right now.")
    while True:
        uname = input("\nEnter an ALREADY-ENROLLED username to test (or press Enter to finish): ").strip()
        if uname == "":
            break
        if uname not in db:
            print(f"  '{uname}' not found in database. Available: {usernames}")
            continue
        embeddings = capture_fresh_samples(cap, face_detector, face_recognizer, uname, FRAMES_PER_USER)
        for emb in embeddings:
            genuine_scores.append(cosine_sim(emb, db[uname]))
        tested_users.append(uname)

    cap.release()
    cv2.destroyAllWindows()

    if not genuine_scores:
        print("[ERROR] No genuine samples captured -- cannot compute FAR/FRR curves.")
        return

    genuine_scores = np.array(genuine_scores)
    impostor_scores = np.array(impostor_scores)
    print(f"\nGenuine scores: n={len(genuine_scores)} from {len(tested_users)} user(s): {tested_users}")
    print(f"Impostor scores: n={len(impostor_scores)} from {len(usernames)} enrolled templates")

    # -- Sweep thresholds 0.30 to 0.70 --
    thresholds = np.arange(0.30, 0.701, 0.01)
    far_list, frr_list = [], []
    for t in thresholds:
        far = np.mean(impostor_scores >= t) * 100  # impostors wrongly accepted
        frr = np.mean(genuine_scores < t) * 100    # genuine users wrongly rejected
        far_list.append(far)
        frr_list.append(frr)
    far_arr, frr_arr = np.array(far_list), np.array(frr_list)

    # Find EER: point where FAR and FRR curves cross
    diffs = np.abs(far_arr - frr_arr)
    eer_idx = np.argmin(diffs)
    eer_threshold = thresholds[eer_idx]
    eer_value = (far_arr[eer_idx] + frr_arr[eer_idx]) / 2

    print(f"\nEER \u2248 {eer_value:.2f}% at threshold {eer_threshold:.2f}")
    print(f"At threshold {eer_threshold:.2f}: FAR={far_arr[eer_idx]:.2f}%  FRR={frr_arr[eer_idx]:.2f}%")

    # -- Figure 5.3: DET-style curve (FAR & FRR vs threshold) --
    plt.figure(figsize=(9, 6))
    plt.plot(thresholds, far_arr, label="FAR (False Acceptance Rate)", color="#f85149", linewidth=2)
    plt.plot(thresholds, frr_arr, label="FRR (False Rejection Rate)", color="#1f6feb", linewidth=2)
    plt.scatter([eer_threshold], [eer_value], color="black", zorder=5, s=80,
                label=f"EER \u2248 {eer_value:.2f}% @ threshold {eer_threshold:.2f}")
    plt.axvline(eer_threshold, color="gray", linestyle=":", linewidth=1)
    plt.xlabel("Cosine Similarity Threshold")
    plt.ylabel("Error Rate (%)")
    plt.title("FAR vs. FRR as a Function of Threshold, with EER Point")
    plt.legend()
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig("FAR_FRR_DET_Curve.png", dpi=300)
    plt.close()
    print("Saved FAR_FRR_DET_Curve.png")

    # -- Figure 5.4: ROC curve (TAR vs FAR) --
    roc_thresholds = np.arange(0.0, 1.001, 0.005)
    tar_list, far2_list = [], []
    for t in roc_thresholds:
        tar = np.mean(genuine_scores >= t) * 100
        far2 = np.mean(impostor_scores >= t) * 100
        tar_list.append(tar)
        far2_list.append(far2)
    tar_arr = np.array(tar_list) / 100
    far2_arr = np.array(far2_list) / 100

    # sort by FAR ascending for a proper AUC integration
    order = np.argsort(far2_arr)
    far_sorted, tar_sorted = far2_arr[order], tar_arr[order]
    auc = np.trapz(tar_sorted, far_sorted)

    plt.figure(figsize=(7, 7))
    plt.plot(far_sorted, tar_sorted, color="#3fb950", linewidth=2.5, label=f"ROC (AUC = {auc:.3f})")
    plt.plot([0, 1], [0, 1], color="gray", linestyle="--", linewidth=1, label="Random guess")
    plt.xlabel("False Acceptance Rate (FAR)")
    plt.ylabel("True Acceptance Rate (TAR)")
    plt.title("ROC Curve \u2014 Facial Recognition (ArcFace Cosine Similarity)")
    plt.legend(loc="lower right")
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig("Facial_Recognition_ROC_Curve.png", dpi=300)
    plt.close()
    print(f"Saved Facial_Recognition_ROC_Curve.png  (AUC \u2248 {auc:.3f})")

    print("\nDone. Update Chapter 5 text with these REAL figures:")
    print(f"   EER \u2248 {eer_value:.2f}%  at threshold {eer_threshold:.2f}")
    print(f"   FAR \u2248 {far_arr[eer_idx]:.2f}%   FRR \u2248 {frr_arr[eer_idx]:.2f}%")
    print(f"   AUC \u2248 {auc:.3f}")


if __name__ == "__main__":
    main()