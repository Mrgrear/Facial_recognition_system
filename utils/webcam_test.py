import cv2

cap = cv2.VideoCapture(0)

# Set to 720p
cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)

width = cap.get(cv2.CAP_PROP_FRAME_WIDTH)
height = cap.get(cv2.CAP_PROP_FRAME_HEIGHT)
print(f"Resolution set to: {int(width)} x {int(height)}")

if not cap.isOpened():
    print("ERROR: Webcam not detected.")
else:
    print("Webcam OK. Press Q to quit.")
    while True:
        ret, frame = cap.read()
        cv2.imshow(f"Webcam Test - {int(width)}x{int(height)}", frame)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

cap.release()
cv2.destroyAllWindows()