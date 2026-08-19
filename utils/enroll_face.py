import sys
sys.path.append(".")
import cv2
import numpy as np
from auth.face_detector import FaceDetector
from auth.face_recognizer import FaceRecognizer
from auth.account_manager import AccountManager

print("=== Face Enrollment ===\n")

# Get username
username = input("Enter username to enroll: ").strip()
if not username:
    print("❌ Username required")
    exit(1)

# Initialize
account_manager = AccountManager()
face_detector = FaceDetector()
face_recognizer = FaceRecognizer()

# Create account if not exists
if username not in account_manager.accounts:
    account_manager.create_account(username, role="user")
    print(f"✅ Account created for {username}")
else:
    print(f"✅ Account exists for {username}")

# Enroll face
print("\nCapturing face... Position your face in the camera.")
print("Press 'SPACE' to capture frames")
print("Press 'Q' to finish enrollment\n")

cap = cv2.VideoCapture(1)
cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)

frames_captured = []

while True:
    ret, frame = cap.read()
    if not ret:
        continue

    faces = face_detector.detect(frame)
    frame = face_detector.draw(frame, faces)

    cv2.putText(
        frame,
        f"Faces: {len(faces)} | Space to capture | Q to finish",
        (10, 30),
        cv2.FONT_HERSHEY_SIMPLEX,
        0.7,
        (0, 255, 0),
        2
    )

    cv2.putText(
        frame,
        f"Frames captured: {len(frames_captured)}/5",
        (10, 70),
        cv2.FONT_HERSHEY_SIMPLEX,
        0.7,
        (0, 255, 0),
        2
    )

    cv2.imshow("Face Enrollment", frame)

    key = cv2.waitKey(1) & 0xFF
    if key == ord(' '):  # Space to capture
        if len(faces) == 1:
            frames_captured.append(frame.copy())
            print(f"✅ Frame {len(frames_captured)}/5 captured")
            if len(frames_captured) >= 5:
                print("✅ 5 frames captured. Enrolling...")
                break
        else:
            print(f"⚠️ Need exactly 1 face. Found {len(faces)}")
    elif key == ord('q') or key == ord('Q'):
        if len(frames_captured) >= 3:
            print(f"✅ Enrolling with {len(frames_captured)} frames...")
            break
        else:
            print(f"⚠️ Need at least 3 frames. Captured: {len(frames_captured)}")

cap.release()
cv2.destroyAllWindows()

# Enroll
if len(frames_captured) >= 3:
    ok = face_recognizer.enroll(username, frames_captured)
    if ok:
        account_manager.enroll_face(
            username,
            face_recognizer.database[username]
        )
        print(f"✅ Face enrolled successfully for {username}!")
        print(f"   Captured {len(frames_captured)} frames")
    else:
        print("❌ Enrollment failed")
else:
    print("❌ Not enough frames captured")