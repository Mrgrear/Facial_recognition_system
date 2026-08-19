import cv2
import insightface
from insightface.app import FaceAnalysis

# Initialize InsightFace with ArcFace
app = FaceAnalysis(name='buffalo_l')
app.prepare(ctx_id=0, det_size=(640, 640))

# Capture frame with warm-up
cap = cv2.VideoCapture(0)
cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)

# Warm up camera - read 10 frames first
print("Warming up camera...")
for i in range(10):
    ret, frame = cap.read()

# Now capture the actual frame
ret, frame = cap.read()
cap.release()

if not ret:
    print("ERROR: Could not capture frame.")
else:
    # Save captured frame
    cv2.imwrite("test_face.jpg", frame)
    print("Face image captured.")

    # Extract ArcFace embedding
    faces = app.get(frame)
    if faces:
        embedding = faces[0].embedding
        print("ArcFace embedding extracted successfully.")
        print(f"Embedding length: {len(embedding)}")
    else:
        print("No face detected. Please ensure your face is visible.")