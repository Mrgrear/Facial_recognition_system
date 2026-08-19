import cv2
import sys
sys.path.append(".")
from auth.liveness_detector import LivenessDetector

detector = LivenessDetector(required_blinks=2)

cap = cv2.VideoCapture(0)
cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)

# Warm up camera
for i in range(5):
    cap.read()

print("Liveness detector running. Blink twice. Press Q to quit.")

while True:
    ret, frame = cap.read()
    if not ret:
        print("Camera read failed - retrying...")
        continue

    is_live, blinks, ear = detector.detect(frame)

    status = "LIVE ✓" if is_live else "Blink to verify..."
    color = (0, 255, 0) if is_live else (0, 0, 255)

    cv2.putText(frame, f"Status: {status}", (10, 30),
                cv2.FONT_HERSHEY_SIMPLEX, 0.8, color, 2)
    cv2.putText(frame, f"Blinks: {blinks}", (10, 60),
                cv2.FONT_HERSHEY_SIMPLEX, 0.8, (255, 255, 0), 2)
    cv2.putText(frame, f"EAR: {ear:.2f}", (10, 90),
                cv2.FONT_HERSHEY_SIMPLEX, 0.8, (255, 255, 0), 2)

    cv2.imshow("Liveness Detection Test", frame)

    key = cv2.waitKey(1) & 0xFF
    if key == ord('q'):
        break

cap.release()
cv2.destroyAllWindows()
print(f"Final blink count: {blinks}")
print(f"Live status: {is_live}")