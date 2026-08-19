import cv2
import sys
sys.path.append(".")
from auth.face_detector import FaceDetector

detector = FaceDetector()

cap = cv2.VideoCapture(0)
cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
cap.set(cv2.CAP_PROP_FPS, 30)

print("Face detector running. Press Q to quit.")

while True:
    ret, frame = cap.read()
    if not ret:
        break

    faces = detector.detect(frame)
    frame = detector.draw(frame, faces)

    cv2.putText(frame, f"Faces: {len(faces)}", (10, 30),
                cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 255, 0), 2)

    cv2.imshow("Face Detector Test", frame)

    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

detector.stop()
cap.release()
cv2.destroyAllWindows()