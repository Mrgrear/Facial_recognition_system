import cv2
import numpy as np
import pickle
import os
from insightface.app import FaceAnalysis


class FaceRecognizer:
    def __init__(self, db_path="db/face_db.pkl", threshold=0.5):
        # Needs BOTH 'detection' and 'recognition' modules — recognition
        # is what actually populates faces[0].embedding, which
        # get_embedding() below depends on.
        self.app = FaceAnalysis(name='buffalo_l', allowed_modules=['detection', 'recognition'])
        self.app.prepare(ctx_id=0, det_size=(320, 320))
        self.db_path = db_path
        self.threshold = threshold
        self.database = self.load_database()

    def load_database(self):
        if os.path.exists(self.db_path):
            with open(self.db_path, 'rb') as f:
                raw = pickle.load(f)
                # Convert lists back to numpy arrays
                return {
                    k: np.array(v) if isinstance(v, list) else v
                    for k, v in raw.items()
                }
        return {}

    def save_database(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        # Convert numpy arrays to lists for pickle
        saveable = {
            k: v.tolist() if isinstance(v, np.ndarray) else v
            for k, v in self.database.items()
        }
        with open(self.db_path, 'wb') as f:
            pickle.dump(saveable, f)

    def get_embedding(self, frame):
        small = cv2.resize(frame, (320, 240))
        faces = self.app.get(small)
        if faces:
            return faces[0].embedding
        return None

    def enroll(self, name, frames):
        embeddings = []
        for frame in frames:
            emb = self.get_embedding(frame)
            if emb is not None:
                embeddings.append(emb)
        if embeddings:
            mean_embedding = np.mean(embeddings, axis=0)
            self.database[name] = mean_embedding
            self.save_database()
            print(f"Enrolled: {name} with {len(embeddings)} embeddings")
            return True
        return False

    def cosine_similarity(self, emb1, emb2):
        return np.dot(emb1, emb2) / (
            np.linalg.norm(emb1) * np.linalg.norm(emb2)
        )

    def recognize(self, frame):
        embedding = self.get_embedding(frame)
        if embedding is None:
            return None, 0.0
        best_match = None
        best_score = -1
        for name, db_emb in self.database.items():
            score = self.cosine_similarity(embedding, db_emb)
            if score > best_score:
                best_score = score
                best_match = name
        if best_score >= self.threshold:
            return best_match, float(best_score)
        return "Unknown", float(best_score)