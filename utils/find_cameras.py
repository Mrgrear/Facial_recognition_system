import cv2

print("Scanning for cameras...\n")

for i in range(5):
    cap = cv2.VideoCapture(i)
    if cap.isOpened():
        print(f"✅ Camera found at index {i}")
        ret, frame = cap.read()
        if ret:
            h, w = frame.shape[:2]
            print(f"   Resolution: {w}x{h}")
        cap.release()
    else:
        print(f"❌ No camera at index {i}")

print("\nNote: Update main_gui.py to use the correct camera index")