import sys
sys.path.append(".")
import time

print("Testing module imports...\n")

try:
    print("1. Testing Face Detector...")
    from auth.face_detector import FaceDetector
    print("   ✅ Face Detector OK")
except Exception as e:
    print(f"   ❌ Face Detector FAILED: {e}")

try:
    print("2. Testing Face Recognizer...")
    from auth.face_recognizer import FaceRecognizer
    print("   ✅ Face Recognizer OK")
except Exception as e:
    print(f"   ❌ Face Recognizer FAILED: {e}")

try:
    print("3. Testing Liveness Detector...")
    from auth.liveness_detector import LivenessDetector
    print("   ✅ Liveness Detector OK")
except Exception as e:
    print(f"   ❌ Liveness Detector FAILED: {e}")

try:
    print("4. Testing Account Manager...")
    from auth.account_manager import AccountManager
    print("   ✅ Account Manager OK")
except Exception as e:
    print(f"   ❌ Account Manager FAILED: {e}")

try:
    print("5. Testing Hybrid IDS...")
    from ids.hybrid_ids import HybridIDS
    print("   ✅ Hybrid IDS OK")
except Exception as e:
    print(f"   ❌ Hybrid IDS FAILED: {e}")

print("\n✅ Module test complete!")