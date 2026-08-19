import cv2
import numpy as np
from insightface.app import FaceAnalysis
import threading
import time


class FaceDetector:
    def __init__(self):
        # FIX: allowed_modules restricts InsightFace to only load the
        # detection model — .bbox and .det_score never needed the
        # landmark/age/gender sub-models, so skipping them speeds up
        # every single detection call.
        self.app = FaceAnalysis(name='buffalo_l', allowed_modules=['detection'])
        self.app.prepare(ctx_id=0, det_size=(320, 320))
        self.confidence_threshold = 0.5
        self.faces = []
        self.frame_to_process = None
        self.lock = threading.Lock()
        self.running = True

        # Run detection in background thread (used for continuous/live
        # detection scenarios only — NOT for one-shot captures, see
        # detect_sync() below).
        self.thread = threading.Thread(target=self._detect_loop, daemon=True)
        self.thread.start()

    def _detect_loop(self):
        while self.running:
            if self.frame_to_process is not None:
                with self.lock:
                    frame = self.frame_to_process.copy()
                    self.frame_to_process = None

                # Resize for faster detection
                small = cv2.resize(frame, (320, 240))
                faces = self.app.get(small)

                scale_x = frame.shape[1] / 320
                scale_y = frame.shape[0] / 240

                result = []
                for face in faces:
                    box = face.bbox.astype(int)
                    x1 = int(box[0] * scale_x)
                    y1 = int(box[1] * scale_y)
                    x2 = int(box[2] * scale_x)
                    y2 = int(box[3] * scale_y)
                    conf = float(face.det_score)
                    if conf > self.confidence_threshold:
                        result.append((x1, y1, x2, y2, conf))

                with self.lock:
                    self.faces = result
            else:
                # FIX: without this sleep, the loop spins as fast as
                # possible whenever there's no frame queued, pegging a
                # CPU core at 100% constantly and starving the Tkinter
                # main loop / other background threads. This was the
                # main cause of the camera freezing.
                time.sleep(0.01)

    def detect(self, frame):
        """Async/live detection. Queues the frame for the background loop
        and immediately returns whatever the loop last computed — this
        may be from a PREVIOUS frame, not this one. Fine for a live
        on-screen indicator, but NOT reliable for one-shot captures."""
        with self.lock:
            self.frame_to_process = frame.copy()
        return self.faces

    def detect_sync(self, frame):
        """Blocking detection on the EXACT frame passed in. Use this for
        one-shot captures (enrollment frame capture, login face match)
        where you need the result for that specific frame. Safe to call
        from a background thread (e.g. inside _run_bg) — do not call
        directly from the Tkinter main thread, since it can take a
        noticeable fraction of a second."""
        small = cv2.resize(frame, (320, 240))
        faces = self.app.get(small)

        scale_x = frame.shape[1] / 320
        scale_y = frame.shape[0] / 240

        result = []
        for face in faces:
            box = face.bbox.astype(int)
            x1 = int(box[0] * scale_x)
            y1 = int(box[1] * scale_y)
            x2 = int(box[2] * scale_x)
            y2 = int(box[3] * scale_y)
            conf = float(face.det_score)
            if conf > self.confidence_threshold:
                result.append((x1, y1, x2, y2, conf))
        return result

    def draw(self, frame, faces):
        for (x1, y1, x2, y2, conf) in faces:
            cv2.rectangle(frame, (x1, y1), (x2, y2), (0, 255, 0), 2)
            cv2.putText(frame, f"{conf:.2f}", (x1, y1 - 10),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 1)
        return frame

    def stop(self):
        self.running = False