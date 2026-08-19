"""
anti_spoof.py
--------------
Lightweight, classical (non-deep-learning) anti-spoofing detector.

Combines three independent signals computed on the detected face
region of a single frame:

  1. Sharpness / texture (Laplacian variance)
     Real skin under a webcam has natural high-frequency detail
     (pores, fine texture). Printed photos and re-captured screens
     typically lose sharpness in reproduction — variance of the
     Laplacian is a standard, well-documented blur/texture measure.

  2. Frequency-domain moiré detection (FFT)
     Phone and monitor screens have a regular pixel grid. When a
     screen is re-photographed by another camera, this grid beats
     against the camera's own sensor grid and produces moiré —
     periodic patterns that show up as sharp peaks in the frequency
     spectrum, well above what a real face's frequency content looks
     like. This is a classic, well-established screen-replay tell.

  3. Colour / saturation naturalness (HSV histogram)
     Printed ink and screen-reproduced skin tones tend to have
     compressed, shifted, or more uniform saturation distributions
     compared to real skin under normal ambient lighting.

Each signal is scored 0.0 (looks fake) to 1.0 (looks real), then
combined into a single spoof_score. This is deliberately a
classical, explainable approach rather than a deep CNN classifier —
appropriate for a CPU-only deployment and defensible without a large
labelled spoof-image dataset, since every threshold here is a
documented, well-known technique rather than a black-box model.

This runs ALONGSIDE the existing blink-based liveness check (which
proves temporal aliveness) — this module adds a spatial, per-frame
check that blink detection alone cannot catch (e.g. a video replay
that includes real blinks).
"""

import cv2
import numpy as np


class AntiSpoofDetector:
    def __init__(self,
                 sharpness_threshold=60.0,
                 moire_threshold=0.18,
                 color_threshold=0.35,
                 combined_threshold=0.5):
        """
        Thresholds are starting points calibrated for a typical
        laptop/USB webcam at close range under normal indoor
        lighting. If real users are being falsely flagged, raise
        combined_threshold slightly (less strict); if spoofs are
        getting through, lower it.
        """
        self.sharpness_threshold = sharpness_threshold
        self.moire_threshold = moire_threshold
        self.color_threshold = color_threshold
        self.combined_threshold = combined_threshold

    # ── Individual signal checks ────────────────────────────────

    def _sharpness_score(self, face_gray):
        """Higher Laplacian variance = sharper/more natural texture.
        Returns a 0-1 score (1 = looks real/sharp)."""
        lap_var = cv2.Laplacian(face_gray, cv2.CV_64F).var()
        score = min(lap_var / (self.sharpness_threshold * 2), 1.0)
        return float(score), float(lap_var)

    def _moire_score(self, face_gray):
        """Detects periodic screen-grid patterns via FFT. Returns a
        0-1 score (1 = no moiré detected / looks real)."""
        f = np.fft.fft2(face_gray.astype(np.float32))
        fshift = np.fft.fftshift(f)
        magnitude = np.log(np.abs(fshift) + 1)

        h, w = magnitude.shape
        cy, cx = h // 2, w // 2

        # Exclude the low-frequency center (normal image content lives
        # here) and look at mid/high-frequency energy, where a screen's
        # regular pixel grid shows up as unnaturally concentrated peaks.
        mask = np.ones((h, w), dtype=bool)
        radius = min(h, w) // 8
        y, x = np.ogrid[:h, :w]
        center_mask = (x - cx) ** 2 + (y - cy) ** 2 <= radius ** 2
        mask[center_mask] = False

        high_freq = magnitude[mask]
        if high_freq.size == 0:
            return 1.0, 0.0, False

        # A real face has fairly smooth, diffuse high-frequency energy.
        # A periodic screen grid produces a small number of sharply
        # concentrated peaks — measured as how far the single strongest
        # point rises above the average high-frequency energy. This is
        # far more sensitive to genuine periodicity than a percentile
        # average, which gets diluted by broadly-elevated energy from
        # ordinary sharp/noisy real textures.
        peak_ratio = high_freq.max() / (high_freq.mean() + 1e-6)
        # Empirically, real faces sit close to ~1.2-1.4; a clear
        # periodic grid pattern pushes this to ~1.5+.
        moire_strength = min(max((peak_ratio - 1.2) / 0.8, 0.0), 1.0)

        score = 1.0 - moire_strength
        flagged = moire_strength > self.moire_threshold
        return float(max(score, 0.0)), float(moire_strength), flagged

    def _color_naturalness_score(self, face_bgr):
        """Checks HSV saturation distribution against a plausible
        real-skin range. Returns a 0-1 score (1 = looks natural)."""
        hsv = cv2.cvtColor(face_bgr, cv2.COLOR_BGR2HSV)
        sat = hsv[:, :, 1].astype(np.float32) / 255.0

        mean_sat = sat.mean()
        std_sat = sat.std()

        # Real skin under normal lighting typically shows moderate
        # saturation with some natural variance. Very low variance
        # (flat/uniform colour, common in print/screen reproduction)
        # or extreme mean saturation are treated as suspicious.
        variance_score = min(std_sat / 0.12, 1.0)  # low variance = suspicious
        extremity_penalty = abs(mean_sat - 0.35) / 0.35
        extremity_score = max(1.0 - extremity_penalty, 0.0)

        score = (variance_score * 0.6) + (extremity_score * 0.4)
        return float(min(max(score, 0.0), 1.0)), float(mean_sat), float(std_sat)

    # ── Public API ───────────────────────────────────────────────

    def analyze(self, frame, face_box):
        """
        frame: full BGR frame (as captured by the camera).
        face_box: (x1, y1, x2, y2, conf) — from FaceDetector.detect_sync().

        Returns: (is_live: bool, spoof_score: float, details: dict)
        spoof_score is 0.0 (looks completely real) to 1.0 (looks
        completely fake) — the inverse of the combined signal score,
        so it lines up with HybridIDS's spoof_indicator convention.
        """
        x1, y1, x2, y2 = face_box[0], face_box[1], face_box[2], face_box[3]
        h, w = frame.shape[:2]
        x1, y1 = max(0, x1), max(0, y1)
        x2, y2 = min(w, x2), min(h, y2)

        if x2 <= x1 or y2 <= y1:
            # Degenerate box — can't analyse, fail safe as suspicious
            return False, 1.0, {"error": "invalid face box"}

        face_bgr = frame[y1:y2, x1:x2]
        if face_bgr.size == 0:
            return False, 1.0, {"error": "empty face crop"}

        face_gray = cv2.cvtColor(face_bgr, cv2.COLOR_BGR2GRAY)
        # Normalize size so thresholds behave consistently regardless
        # of how close/far the face is from the camera.
        face_gray = cv2.resize(face_gray, (200, 200))
        face_bgr_resized = cv2.resize(face_bgr, (200, 200))

        sharp_score, lap_var = self._sharpness_score(face_gray)
        moire_score, moire_strength, moire_flagged = self._moire_score(face_gray)
        color_score, mean_sat, std_sat = self._color_naturalness_score(face_bgr_resized)

        # Weighted combination — texture and moiré are the strongest,
        # most literature-backed signals; colour is a supporting signal.
        combined_score = (sharp_score * 0.4) + (moire_score * 0.4) + (color_score * 0.2)

        # Override: a strongly-confirmed periodic moiré pattern is one
        # of the most reliable single tells for a screen replay attack
        # — a naturally sharp face crop should not be able to talk it
        # back up to "live". A weak/borderline moiré reading still just
        # feeds into the weighted score above, since single-frame FFT
        # peaks can be noisy on their own.
        if moire_strength > 0.65:
            combined_score = min(combined_score, 0.3)

        spoof_score = 1.0 - combined_score
        is_live = combined_score >= self.combined_threshold

        details = {
            "sharpness_score": round(sharp_score, 3),
            "laplacian_variance": round(lap_var, 1),
            "moire_score": round(moire_score, 3),
            "moire_strength": round(moire_strength, 3),
            "moire_flagged": moire_flagged,
            "color_score": round(color_score, 3),
            "mean_saturation": round(mean_sat, 3),
            "saturation_std": round(std_sat, 3),
            "combined_score": round(combined_score, 3),
        }

        return is_live, float(spoof_score), details