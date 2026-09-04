import mediapipe as mp
import numpy as np
import cv2

class LivenessDetector:
    def __init__(self, ear_threshold=0.25, blink_frames=2, required_blinks=1):
        self.ear_threshold = ear_threshold
        self.blink_frames = blink_frames
        self.required_blinks = required_blinks
        self.blink_counter = 0
        self.frame_counter = 0
        self.is_live = False

        self.LEFT_EYE = [362, 385, 387, 263, 373, 380]
        self.RIGHT_EYE = [33, 160, 158, 133, 153, 144]

        # New MediaPipe API
        BaseOptions = mp.tasks.BaseOptions
        FaceLandmarker = mp.tasks.vision.FaceLandmarker
        FaceLandmarkerOptions = mp.tasks.vision.FaceLandmarkerOptions
        VisionRunningMode = mp.tasks.vision.RunningMode

        self.latest_landmarks = None

        options = FaceLandmarkerOptions(
            base_options=BaseOptions(
                model_asset_path=self._get_model_path()
            ),
            running_mode=VisionRunningMode.IMAGE,
            num_faces=1
        )
        self.landmarker = FaceLandmarker.create_from_options(options)

    def _get_model_path(self):
        import urllib.request
        import os
        model_path = "models/face_landmarker.task"
        
        # Create models directory if it doesn't exist
        os.makedirs("models", exist_ok=True)
        
        if not os.path.exists(model_path):
            print("Downloading MediaPipe face landmarker model...")
            url = "https://storage.googleapis.com/mediapipe-models/face_landmarker/face_landmarker/float16/1/face_landmarker.task"
            try:
                urllib.request.urlretrieve(url, model_path)
                print("✅ Download complete.")
            except Exception as e:
                print(f"❌ Download failed: {e}")
        else:
            print(f"✅ Model found at: {model_path}")
        return model_path

    def eye_aspect_ratio(self, landmarks, eye_indices):
        points = []
        for idx in eye_indices:
            lm = landmarks[idx]
            points.append((lm.x, lm.y))
        A = np.linalg.norm(np.array(points[1]) - np.array(points[5]))
        B = np.linalg.norm(np.array(points[2]) - np.array(points[4]))
        C = np.linalg.norm(np.array(points[0]) - np.array(points[3]))
        ear = (A + B) / (2.0 * C)
        return ear

    def detect(self, frame):
        ear = 0.0
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        mp_image = mp.Image(
            image_format=mp.ImageFormat.SRGB,
            data=rgb
        )
        result = self.landmarker.detect(mp_image)

        if result.face_landmarks:
            landmarks = result.face_landmarks[0]
            left_ear = self.eye_aspect_ratio(landmarks, self.LEFT_EYE)
            right_ear = self.eye_aspect_ratio(landmarks, self.RIGHT_EYE)
            ear = (left_ear + right_ear) / 2.0

            if ear < self.ear_threshold:
                self.frame_counter += 1
            else:
                if self.frame_counter >= self.blink_frames:
                    self.blink_counter += 1
                self.frame_counter = 0

            if self.blink_counter >= self.required_blinks:
                self.is_live = True

        return self.is_live, self.blink_counter, ear

    def reset(self):
        self.blink_counter = 0
        self.frame_counter = 0
        self.is_live = False