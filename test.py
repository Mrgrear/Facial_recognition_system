import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import cv2
from PIL import Image, ImageTk
from datetime import datetime
import sys
import time
import socket
import numpy as np
from scipy.spatial.distance import cosine

sys.path.append(".")

print("Loading modules...")
from auth.face_detector import FaceDetector
from auth.face_recognizer import FaceRecognizer
from auth.liveness_detector import LivenessDetector
from auth.account_manager import AccountManager
from auth.auth_system import AuthSystem
from auth.session_manager import SessionManager
from auth.audit_logger import AuditLogger
from ids.hybrid_ids import HybridIDS
print("✅ All modules loaded!")

SIGNUP_REQUIRED_BLINKS = 3
LOGIN_REQUIRED_BLINKS = 2
FACE_MATCH_THRESHOLD = 0.6  # Cosine similarity threshold (0.6 = 60% match required)

class FacialAuthGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Zero Trust Authentication System - SECURITY FIXED")
        self.root.geometry("1000x750")
        self.root.configure(bg="#1e1e1e")

        self.face_detector = FaceDetector()
        self.face_recognizer = FaceRecognizer()
        self.liveness_detector = LivenessDetector(required_blinks=SIGNUP_REQUIRED_BLINKS)
        self.account_manager = AccountManager()
        self.auth_system = AuthSystem()
        self.session_manager = SessionManager(session_timeout_minutes=30)
        self.audit_logger = AuditLogger()
        self.ids = HybridIDS()
        self.ids.load_models()

        self.current_user = None
        self.current_session = None
        self.is_authenticated = False
        self.cap = None
        self.auth_running = False
        self.enrollment_running = False
        self.signup_data = {}
        self.enrollment_frames = []
        self.space_pressed = False
        self.ip_address = self.get_ip_address()
        self.device_id = self.get_device_id()
        self.flow_type = "signup"
        self.liveness_completed = False
        self.frame_skip_counter = 0  # For camera optimization

        self.root.bind('<space>', self.on_space_pressed)
        self.show_home_screen()

    def get_ip_address(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def get_device_id(self):
        import uuid
        try:
            mac = uuid.getnode()
            return str(mac)
        except:
            return "unknown"

    def on_space_pressed(self, event):
        self.space_pressed = True

    def release_camera(self):
        """Properly release camera."""
        if self.cap:
            try:
                for _ in range(5):
                    try:
                        self.cap.release()
                        break
                    except:
                        time.sleep(0.1)
            except:
                pass
            self.cap = None
        time.sleep(0.5)

    def get_face_embedding(self, frame):
        """Extract face embedding from frame using ArcFace."""
        try:
            faces = self.face_detector.detect(frame)
            if len(faces) == 1:
                # Extract face region
                (x, y, w, h) = faces[0]
                face_region = frame[y:y+h, x:x+w]
                
                # Get embedding from face_recognizer
                embedding = self.face_recognizer.get_embedding(face_region)
                return embedding, faces[0]
            return None, None
        except Exception as e:
            print(f"[ERROR] get_face_embedding: {e}")
            return None, None

    def compare_faces(self, embedding1, embedding2):
        """
        Compare two face embeddings using cosine similarity.
        Returns similarity score (0.0 to 1.0, where 1.0 = identical)
        """
        try:
            if embedding1 is None or embedding2 is None:
                return 0.0
            
            # Cosine similarity: 1 - distance
            # distance ranges 0-2, so similarity ranges -1 to 1
            # We normalize to 0-1
            distance = cosine(embedding1, embedding2)
            similarity = 1 - distance
            return max(0.0, similarity)  # Ensure non-negative
        except Exception as e:
            print(f"[ERROR] compare_faces: {e}")
            return 0.0

    def show_home_screen(self):
        """Show home screen."""
        for widget in self.root.winfo_children():
            widget.destroy()

        main_frame = tk.Frame(self.root, bg="#1e1e1e")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        title = tk.Label(
            main_frame,
            text="ZERO TRUST AUTHENTICATION SYSTEM",
            font=("Arial", 24, "bold"),
            bg="#1e1e1e",
            fg="#00ff00"
        )
        title.pack(pady=20)

        subtitle = tk.Label(
            main_frame,
            text="Facial Recognition + Liveness + Face Matching",
            font=("Arial", 11),
            bg="#1e1e1e",
            fg="#cccccc"
        )
        subtitle.pack(pady=5)

        status_text = f"System Status: ACTIVE | IP: {self.ip_address}"
        status = tk.Label(
            main_frame,
            text=status_text,
            font=("Arial", 9),
            bg="#1e1e1e",
            fg="#ffff00"
        )
        status.pack(pady=5)

        info_frame = tk.Frame(main_frame, bg="#2d2d2d", relief=tk.RIDGE, bd=2)
        info_frame.pack(fill=tk.BOTH, expand=True, pady=20)

        info_text = tk.Label(
            info_frame,
            text="SECURITY FIX APPLIED:\n\n"
                 "✓ Face Enrollment (5 images)\n"
                 "✓ Liveness Verification (EAR + Blink detection)\n"
                 "✓ Face Matching (ArcFace + Cosine Similarity)\n"
                 "✓ Threshold: {} (60% match required)\n"
                 "✓ Only YOUR face can login to YOUR account\n\n"
                 "👤 LOGIN  •  📝 NEW USER  •  👨‍💼 ADMIN".format(FACE_MATCH_THRESHOLD),
            font=("Arial", 10),
            bg="#2d2d2d",
            fg="#00ff00",
            justify=tk.LEFT,
            padx=20,
            pady=20
        )
        info_text.pack(fill=tk.BOTH, expand=True)

        button_frame = tk.Frame(main_frame, bg="#1e1e1e")
        button_frame.pack(fill=tk.X, pady=20)

        login_btn = tk.Button(
            button_frame,
            text="👤 Login",
            command=self.show_login_screen,
            bg="#0066ff",
            fg="#ffffff",
            font=("Arial", 11, "bold"),
            padx=25,
            pady=10,
            cursor="hand2"
        )
        login_btn.pack(side=tk.LEFT, padx=5)

        signup_btn = tk.Button(
            button_frame,
            text="📝 New User",
            command=self.show_signup_screen,
            bg="#00ff00",
            fg="#000000",
            font=("Arial", 11, "bold"),
            padx=25,
            pady=10,
            cursor="hand2"
        )
        signup_btn.pack(side=tk.LEFT, padx=5)

        admin_btn = tk.Button(
            button_frame,
            text="👨‍💼 Admin",
            command=self.show_admin_panel,
            bg="#ff6600",
            fg="#ffffff",
            font=("Arial", 11, "bold"),
            padx=25,
            pady=10,
            cursor="hand2"
        )
        admin_btn.pack(side=tk.LEFT, padx=5)

        exit_btn = tk.Button(
            button_frame,
            text="Exit",
            command=self.root.quit,
            bg="#333333",
            fg="#ffffff",
            font=("Arial", 11, "bold"),
            padx=25,
            pady=10,
            cursor="hand2"
        )
        exit_btn.pack(side=tk.RIGHT, padx=5)

    def show_login_screen(self):
        """Show login screen."""
        for widget in self.root.winfo_children():
            widget.destroy()

        main_frame = tk.Frame(self.root, bg="#1e1e1e")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        title = tk.Label(
            main_frame,
            text="User Login",
            font=("Arial", 20, "bold"),
            bg="#1e1e1e",
            fg="#00ff00"
        )
        title.pack(pady=10)

        form_frame = tk.Frame(main_frame, bg="#2d2d2d", relief=tk.RIDGE, bd=2)
        form_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        tk.Label(
            form_frame,
            text="Username:",
            font=("Arial", 11),
            bg="#2d2d2d",
            fg="#00ff00"
        ).pack(pady=5)

        username_entry = tk.Entry(
            form_frame,
            font=("Arial", 11),
            width=40,
            bg="#1e1e1e",
            fg="#00ff00",
            insertbackground="#00ff00"
        )
        username_entry.pack(pady=5)

        button_frame = tk.Frame(main_frame, bg="#1e1e1e")
        button_frame.pack(fill=tk.X, pady=10)

        def proceed_login():
            username = username_entry.get().strip()
            if not username:
                messagebox.showwarning("Error", "Please enter username")
                return
            if not self.auth_system.user_exists(username):
                messagebox.showerror("Error", "User not found")
                self.audit_logger.log_failed_attempt(
                    username, "User not found", self.ip_address
                )
                return
            
            user_info = self.auth_system.get_user_info(username)
            if not user_info.get('authenticated', False):
                messagebox.showerror(
                    "Error",
                    "User not authenticated.\n\n"
                    "Must complete enrollment and liveness during signup."
                )
                return
            
            self.current_user = username
            self.flow_type = "login"
            self.show_liveness_login_screen()

        proceed_btn = tk.Button(
            button_frame,
            text="▶ Continue",
            command=proceed_login,
            bg="#0066ff",
            fg="#ffffff",
            font=("Arial", 11, "bold"),
            padx=20,
            pady=10,
            cursor="hand2"
        )
        proceed_btn.pack(side=tk.LEFT, padx=5)

        back_btn = tk.Button(
            button_frame,
            text="Back",
            command=self.show_home_screen,
            bg="#666666",
            fg="#ffffff",
            font=("Arial", 11, "bold"),
            padx=20,
            pady=10,
            cursor="hand2"
        )
        back_btn.pack(side=tk.RIGHT, padx=5)

    def show_signup_screen(self):
        """Show signup form."""
        for widget in self.root.winfo_children():
            widget.destroy()

        main_frame = tk.Frame(self.root, bg="#1e1e1e")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        title = tk.Label(
            main_frame,
            text="Create New Account",
            font=("Arial", 20, "bold"),
            bg="#1e1e1e",
            fg="#00ff00"
        )
        title.pack(pady=10)

        form_frame = tk.Frame(main_frame, bg="#2d2d2d", relief=tk.RIDGE, bd=2)
        form_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        tk.Label(
            form_frame,
            text="Username:",
            font=("Arial", 11),
            bg="#2d2d2d",
            fg="#00ff00"
        ).pack(pady=5, padx=20, anchor="w")

        username_entry = tk.Entry(
            form_frame,
            font=("Arial", 11),
            width=50,
            bg="#1e1e1e",
            fg="#00ff00",
            insertbackground="#00ff00"
        )
        username_entry.pack(pady=5, padx=20, fill=tk.X)

        tk.Label(
            form_frame,
            text="Email:",
            font=("Arial", 11),
            bg="#2d2d2d",
            fg="#00ff00"
        ).pack(pady=5, padx=20, anchor="w")

        email_entry = tk.Entry(
            form_frame,
            font=("Arial", 11),
            width=50,
            bg="#1e1e1e",
            fg="#00ff00",
            insertbackground="#00ff00"
        )
        email_entry.pack(pady=5, padx=20, fill=tk.X)

        tk.Label(
            form_frame,
            text="Full Name:",
            font=("Arial", 11),
            bg="#2d2d2d",
            fg="#00ff00"
        ).pack(pady=5, padx=20, anchor="w")

        full_name_entry = tk.Entry(
            form_frame,
            font=("Arial", 11),
            width=50,
            bg="#1e1e1e",
            fg="#00ff00",
            insertbackground="#00ff00"
        )
        full_name_entry.pack(pady=5, padx=20, fill=tk.X)

        tk.Label(
            form_frame,
            text="Department:",
            font=("Arial", 11),
            bg="#2d2d2d",
            fg="#00ff00"
        ).pack(pady=5, padx=20, anchor="w")

        department_entry = tk.Entry(
            form_frame,
            font=("Arial", 11),
            width=50,
            bg="#1e1e1e",
            fg="#00ff00",
            insertbackground="#00ff00"
        )
        department_entry.pack(pady=5, padx=20, fill=tk.X)

        tk.Label(
            form_frame,
            text="Phone:",
            font=("Arial", 11),
            bg="#2d2d2d",
            fg="#00ff00"
        ).pack(pady=5, padx=20, anchor="w")

        phone_entry = tk.Entry(
            form_frame,
            font=("Arial", 11),
            width=50,
            bg="#1e1e1e",
            fg="#00ff00",
            insertbackground="#00ff00"
        )
        phone_entry.pack(pady=5, padx=20, fill=tk.X)

        button_frame = tk.Frame(main_frame, bg="#1e1e1e")
        button_frame.pack(fill=tk.X, pady=10)

        def proceed_signup():
            data = {
                'username': username_entry.get().strip(),
                'email': email_entry.get().strip(),
                'full_name': full_name_entry.get().strip(),
                'department': department_entry.get().strip(),
                'phone': phone_entry.get().strip()
            }

            if not all(data.values()):
                messagebox.showwarning("Error", "All fields required")
                return

            if self.auth_system.user_exists(data['username']):
                messagebox.showerror("Error", "Username exists")
                return

            ok, msg = self.auth_system.create_account(
                data['username'], data['email'],
                data['full_name'], data['department'],
                data['phone']
            )

            if ok:
                self.signup_data = data
                self.current_user = data['username']
                self.flow_type = "signup"
                self.liveness_completed = False
                self.audit_logger.log_event(
                    data['username'], "SIGNUP", {'email': data['email']}, "INFO"
                )
                messagebox.showinfo("Success", msg)
                self.show_enrollment_screen()
            else:
                messagebox.showerror("Error", msg)

        signup_btn = tk.Button(
            button_frame,
            text="Create Account",
            command=proceed_signup,
            bg="#00ff00",
            fg="#000000",
            font=("Arial", 11, "bold"),
            padx=20,
            pady=10,
            cursor="hand2"
        )
        signup_btn.pack(side=tk.LEFT, padx=5)

        back_btn = tk.Button(
            button_frame,
            text="Back",
            command=self.show_home_screen,
            bg="#666666",
            fg="#ffffff",
            font=("Arial", 11, "bold"),
            padx=20,
            pady=10,
            cursor="hand2"
        )
        back_btn.pack(side=tk.RIGHT, padx=5)

    def show_enrollment_screen(self):
        """Show enrollment."""
        for widget in self.root.winfo_children():
            widget.destroy()

        main_frame = tk.Frame(self.root, bg="#1e1e1e")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        title = tk.Label(
            main_frame,
            text="Face Enrollment - Capture 5 Images",
            font=("Arial", 20, "bold"),
            bg="#1e1e1e",
            fg="#00ff00"
        )
        title.pack(pady=10)

        subtitle = tk.Label(
            main_frame,
            text="Position your face center. Press SPACE to capture.",
            font=("Arial", 11),
            bg="#1e1e1e",
            fg="#cccccc"
        )
        subtitle.pack(pady=5)

        self.webcam_label = tk.Label(
            main_frame,
            width=640,
            height=400,
            bg="#000000",
            text="Starting camera...",
            fg="#00ff00"
        )
        self.webcam_label.pack(pady=10)

        status_frame = tk.Frame(main_frame, bg="#2d2d2d", relief=tk.RIDGE, bd=2)
        status_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.enrollment_text = scrolledtext.ScrolledText(
            status_frame,
            height=4,
            width=80,
            bg="#2d2d2d",
            fg="#00ff00",
            font=("Courier", 9)
        )
        self.enrollment_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.add_enrollment_status("Initializing...")

        button_frame = tk.Frame(main_frame, bg="#1e1e1e")
        button_frame.pack(fill=tk.X, pady=10)

        cancel_btn = tk.Button(
            button_frame,
            text="Cancel",
            command=self.cancel_signup,
            bg="#ff0000",
            fg="#ffffff",
            font=("Arial", 11, "bold"),
            padx=20,
            pady=10,
            cursor="hand2"
        )
        cancel_btn.pack(side=tk.LEFT, padx=5)

        self.enrollment_running = True
        self.enrollment_frames = []
        self.space_pressed = False
        self.frame_skip_counter = 0
        
        camera_thread = threading.Thread(
            target=self.run_enrollment_loop,
            daemon=True
        )
        camera_thread.start()

    def run_enrollment_loop(self):
        """Optimized enrollment loop."""
        try:
            self.release_camera()
            time.sleep(1)
            
            self.cap = cv2.VideoCapture(0)
            if not self.cap.isOpened():
                self.add_enrollment_status("❌ Camera not found!")
                self.enrollment_running = False
                return

            # Optimize camera
            self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, 480)
            self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 360)
            self.cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
            self.cap.set(cv2.CAP_PROP_FPS, 30)

            self.add_enrollment_status("✅ Camera ready")
            time.sleep(1)
            
            # Warm up
            for _ in range(30):
                ret, frame = self.cap.read()
                if ret:
                    break
                time.sleep(0.05)

            self.add_enrollment_status("Ready. Press SPACE to capture.")

            while self.enrollment_running and self.cap.isOpened():
                ret, frame = self.cap.read()
                if not ret or frame is None or frame.size == 0:
                    time.sleep(0.01)
                    continue

                # Skip frames for performance
                self.frame_skip_counter += 1
                if self.frame_skip_counter % 2 != 0:
                    time.sleep(0.01)
                    continue

                faces = self.face_detector.detect(frame)
                frame_display = self.face_detector.draw(frame.copy(), faces)

                cv2.putText(
                    frame_display,
                    f"Captured: {len(self.enrollment_frames)}/5",
                    (10, 30),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.7,
                    (0, 255, 0),
                    2
                )

                if self.space_pressed and len(faces) == 1:
                    self.enrollment_frames.append(frame.copy())
                    self.add_enrollment_status(f"✅ Frame {len(self.enrollment_frames)}/5")
                    self.space_pressed = False

                    if len(self.enrollment_frames) >= 5:
                        break
                elif self.space_pressed:
                    self.add_enrollment_status(f"⚠️ Need 1 face, found {len(faces)}")
                    self.space_pressed = False

                try:
                    frame_small = cv2.resize(frame_display, (480, 360))
                    frame_rgb = cv2.cvtColor(frame_small, cv2.COLOR_BGR2RGB)
                    img = Image.fromarray(frame_rgb)
                    imgtk = ImageTk.PhotoImage(image=img)
                    self.webcam_label.imgtk = imgtk
                    self.webcam_label.configure(image=imgtk, text="")
                except Exception:
                    pass

                self.root.update()
                time.sleep(0.01)

            if len(self.enrollment_frames) >= 5:
                self.add_enrollment_status("Processing embeddings...")
                
                # Get embeddings
                embeddings = []
                for i, frame in enumerate(self.enrollment_frames):
                    embedding, _ = self.get_face_embedding(frame)
                    if embedding is not None:
                        embeddings.append(embedding)
                    self.add_enrollment_status(f"Processing frame {i+1}/5...")

                if len(embeddings) >= 3:
                    # Store mean embedding
                    mean_embedding = np.mean(embeddings, axis=0)
                    
                    # Save to auth system
                    self.auth_system.users[self.current_user]['face_embedding'] = mean_embedding.tolist()
                    self.auth_system.save_users()
                    
                    self.audit_logger.log_event(
                        self.current_user, "ENROLLMENT",
                        {'frames': len(self.enrollment_frames), 'embeddings': len(embeddings)},
                        "INFO"
                    )
                    self.add_enrollment_status("✅ Face enrolled! Next: Liveness verification")
                    time.sleep(1)
                    self.enrollment_running = False
                    self.root.after(500, self.show_liveness_signup_screen)
                else:
                    self.add_enrollment_status("❌ Not enough valid faces")
            else:
                self.add_enrollment_status(f"❌ Incomplete: {len(self.enrollment_frames)}/5")

        except Exception as e:
            self.add_enrollment_status(f"Error: {str(e)}")
        finally:
            self.release_camera()

    def show_liveness_signup_screen(self):
        """Show liveness for signup."""
        for widget in self.root.winfo_children():
            widget.destroy()

        main_frame = tk.Frame(self.root, bg="#1e1e1e")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        title = tk.Label(
            main_frame,
            text="Liveness Verification - Signup",
            font=("Arial", 20, "bold"),
            bg="#1e1e1e",
            fg="#00ff00"
        )
        title.pack(pady=10)

        subtitle = tk.Label(
            main_frame,
            text=f"Please blink your eyes {SIGNUP_REQUIRED_BLINKS} times",
            font=("Arial", 12),
            bg="#1e1e1e",
            fg="#ffff00"
        )
        subtitle.pack(pady=5)

        self.webcam_label = tk.Label(
            main_frame,
            width=640,
            height=400,
            bg="#000000",
            text="Starting camera...",
            fg="#00ff00"
        )
        self.webcam_label.pack(pady=10)

        status_frame = tk.Frame(main_frame, bg="#2d2d2d", relief=tk.RIDGE, bd=2)
        status_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.status_text = scrolledtext.ScrolledText(
            status_frame,
            height=4,
            width=80,
            bg="#2d2d2d",
            fg="#00ff00",
            font=("Courier", 9)
        )
        self.status_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.add_status(f"Waiting for {SIGNUP_REQUIRED_BLINKS} blinks...")

        button_frame = tk.Frame(main_frame, bg="#1e1e1e")
        button_frame.pack(fill=tk.X, pady=10)

        cancel_btn = tk.Button(
            button_frame,
            text="Cancel",
            command=self.cancel_signup,
            bg="#ff0000",
            fg="#ffffff",
            font=("Arial", 11, "bold"),
            padx=20,
            pady=10,
            cursor="hand2"
        )
        cancel_btn.pack(side=tk.LEFT, padx=5)

        self.auth_running = True
        self.liveness_detector.reset()
        self.liveness_detector.required_blinks = SIGNUP_REQUIRED_BLINKS
        self.frame_skip_counter = 0
        
        camera_thread = threading.Thread(
            target=self.run_liveness_signup_loop,
            daemon=True
        )
        camera_thread.start()

    def run_liveness_signup_loop(self):
        """Optimized liveness loop."""
        try:
            self.release_camera()
            time.sleep(1)
            
            self.cap = cv2.VideoCapture(0)
            if not self.cap.isOpened():
                self.add_status("❌ Camera not found!")
                self.auth_running = False
                return

            self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, 480)
            self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 360)
            self.cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
            self.cap.set(cv2.CAP_PROP_FPS, 30)

            self.add_status("✅ Camera ready")
            time.sleep(1)
            
            for _ in range(30):
                ret, frame = self.cap.read()
                if ret:
                    break
                time.sleep(0.05)

            while self.auth_running and self.cap.isOpened():
                ret, frame = self.cap.read()
                if not ret or frame is None or frame.size == 0:
                    time.sleep(0.01)
                    continue

                self.frame_skip_counter += 1
                if self.frame_skip_counter % 2 != 0:
                    time.sleep(0.01)
                    continue

                faces = self.face_detector.detect(frame)
                frame_display = self.face_detector.draw(frame.copy(), faces)

                if len(faces) == 1:
                    is_live, blinks, ear = self.liveness_detector.detect(frame)
                    self.add_status(f"Blinks: {blinks}/{SIGNUP_REQUIRED_BLINKS} | EAR: {ear:.2f}")

                    if is_live:
                        self.add_status("✅ Liveness verified!")
                        self.auth_system.users[self.current_user]['authenticated'] = True
                        self.auth_system.save_users()
                        self.liveness_completed = True
                        self.audit_logger.log_event(
                            self.current_user, "LIVENESS_VERIFIED",
                            {'blinks': blinks, 'type': 'signup'}, "INFO"
                        )
                        self.auth_running = False
                        time.sleep(1)
                        break
                else:
                    self.add_status(f"Need 1 face, found {len(faces)}")

                try:
                    frame_small = cv2.resize(frame_display, (480, 360))
                    frame_rgb = cv2.cvtColor(frame_small, cv2.COLOR_BGR2RGB)
                    img = Image.fromarray(frame_rgb)
                    imgtk = ImageTk.PhotoImage(image=img)
                    self.webcam_label.imgtk = imgtk
                    self.webcam_label.configure(image=imgtk, text="")
                except Exception:
                    pass

                self.root.update()
                time.sleep(0.01)

        except Exception as e:
            self.add_status(f"Error: {str(e)}")
        finally:
            self.release_camera()

        if self.liveness_completed:
            self.add_status("Signup complete! Redirecting...")
            time.sleep(1)
            self.root.after(500, self.show_login_screen)
        else:
            self.add_status("❌ Liveness failed. Deleting account...")
            time.sleep(1)
            self.delete_incomplete_user(self.current_user)
            self.root.after(500, self.show_home_screen)

    def delete_incomplete_user(self, username):
        """Delete user who didn't complete signup."""
        try:
            if username in self.auth_system.users:
                del self.auth_system.users[username]
                self.auth_system.save_users()
            messagebox.showwarning("Signup Incomplete", "Account deleted. Try again.")
        except:
            pass

    def show_liveness_login_screen(self):
        """Show liveness for login."""
        for widget in self.root.winfo_children():
            widget.destroy()

        main_frame = tk.Frame(self.root, bg="#1e1e1e")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        title = tk.Label(
            main_frame,
            text="Liveness Verification - Login",
            font=("Arial", 20, "bold"),
            bg="#1e1e1e",
            fg="#00ff00"
        )
        title.pack(pady=10)

        subtitle = tk.Label(
            main_frame,
            text=f"Blink {LOGIN_REQUIRED_BLINKS} times, then face matching will verify identity",
            font=("Arial", 11),
            bg="#1e1e1e",
            fg="#ffff00"
        )
        subtitle.pack(pady=5)

        self.webcam_label = tk.Label(
            main_frame,
            width=640,
            height=400,
            bg="#000000",
            text="Starting camera...",
            fg="#00ff00"
        )
        self.webcam_label.pack(pady=10)

        status_frame = tk.Frame(main_frame, bg="#2d2d2d", relief=tk.RIDGE, bd=2)
        status_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.status_text = scrolledtext.ScrolledText(
            status_frame,
            height=4,
            width=80,
            bg="#2d2d2d",
            fg="#00ff00",
            font=("Courier", 9)
        )
        self.status_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.add_status(f"Waiting for {LOGIN_REQUIRED_BLINKS} blinks...")

        button_frame = tk.Frame(main_frame, bg="#1e1e1e")
        button_frame.pack(fill=tk.X, pady=10)

        cancel_btn = tk.Button(
            button_frame,
            text="Cancel",
            command=self.cancel_authentication,
            bg="#ff0000",
            fg="#ffffff",
            font=("Arial", 11, "bold"),
            padx=20,
            pady=10,
            cursor="hand2"
        )
        cancel_btn.pack(side=tk.LEFT, padx=5)

        self.auth_running = True
        self.liveness_detector.reset()
        self.liveness_detector.required_blinks = LOGIN_REQUIRED_BLINKS
        self.frame_skip_counter = 0
        
        camera_thread = threading.Thread(
            target=self.run_liveness_login_loop,
            daemon=True
        )
        camera_thread.start()

    def run_liveness_login_loop(self):
        """FIXED: Liveness + Face Matching for login."""
        try:
            self.release_camera()
            time.sleep(1)
            
            self.cap = cv2.VideoCapture(0)
            if not self.cap.isOpened():
                self.add_status("❌ Camera not found!")
                self.auth_running = False
                return

            self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, 480)
            self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 360)
            self.cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
            self.cap.set(cv2.CAP_PROP_FPS, 30)

            self.add_status("✅ Camera ready")
            time.sleep(1)
            
            for _ in range(30):
                ret, frame = self.cap.read()
                if ret:
                    break
                time.sleep(0.05)

            liveness_passed = False
            last_frame_for_matching = None

            while self.auth_running and self.cap.isOpened():
                ret, frame = self.cap.read()
                if not ret or frame is None or frame.size == 0:
                    time.sleep(0.01)
                    continue

                self.frame_skip_counter += 1
                if self.frame_skip_counter % 2 != 0:
                    time.sleep(0.01)
                    continue

                faces = self.face_detector.detect(frame)
                frame_display = self.face_detector.draw(frame.copy(), faces)

                if len(faces) == 1:
                    is_live, blinks, ear = self.liveness_detector.detect(frame)
                    
                    if not liveness_passed:
                        self.add_status(f"Blinks: {blinks}/{LOGIN_REQUIRED_BLINKS} | EAR: {ear:.2f}")
                        
                        if is_live:
                            liveness_passed = True
                            last_frame_for_matching = frame.copy()
                            self.add_status("✅ Liveness passed! Matching face to enrollment...")
                            time.sleep(1)
                    else:
                        # Liveness passed, now do face matching
                        enrolled_embedding_list = self.auth_system.users[self.current_user].get('face_embedding')
                        
                        if enrolled_embedding_list is None:
                            self.add_status("❌ No enrollment found!")
                            self.auth_running = False
                            break

                        enrolled_embedding = np.array(enrolled_embedding_list)
                        
                        # Get current frame embedding
                        current_embedding, _ = self.get_face_embedding(frame)
                        
                        if current_embedding is not None:
                            similarity = self.compare_faces(current_embedding, enrolled_embedding)
                            self.add_status(f"Face Match: {similarity:.2%} | Threshold: {FACE_MATCH_THRESHOLD:.2%}")
                            
                            if similarity >= FACE_MATCH_THRESHOLD:
                                self.add_status("✅ FACE MATCHED! Granting access...")
                                
                                # Create session & log
                                session_id = self.session_manager.create_session(
                                    self.current_user, self.ip_address, self.device_id
                                )
                                self.current_session = session_id
                                
                                self.audit_logger.log_login(
                                    self.current_user, True, similarity, self.ip_address
                                )
                                
                                self.is_authenticated = True
                                self.account_manager.record_success(self.current_user)
                                self.auth_running = False
                                time.sleep(1)
                                break
                            else:
                                self.add_status(f"❌ Face not matched ({similarity:.2%}). Access denied.")
                                self.audit_logger.log_failed_attempt(
                                    self.current_user,
                                    f"Face not matched ({similarity:.2%})",
                                    self.ip_address
                                )
                                self.auth_running = False
                                time.sleep(1)
                                break
                else:
                    self.add_status(f"Need 1 face, found {len(faces)}")

                try:
                    frame_small = cv2.resize(frame_display, (480, 360))
                    frame_rgb = cv2.cvtColor(frame_small, cv2.COLOR_BGR2RGB)
                    img = Image.fromarray(frame_rgb)
                    imgtk = ImageTk.PhotoImage(image=img)
                    self.webcam_label.imgtk = imgtk
                    self.webcam_label.configure(image=imgtk, text="")
                except Exception:
                    pass

                self.root.update()
                time.sleep(0.01)

        except Exception as e:
            self.add_status(f"Error: {str(e)}")
        finally:
            self.release_camera()

        if self.is_authenticated:
            self.root.after(500, self.show_success_screen)
        else:
            self.root.after(500, self.show_home_screen)

    def show_success_screen(self):
        """Show success."""
        for widget in self.root.winfo_children():
            widget.destroy()

        main_frame = tk.Frame(self.root, bg="#1e1e1e")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        title = tk.Label(
            main_frame,
            text="✅ Authentication Successful",
            font=("Arial", 26, "bold"),
            bg="#1e1e1e",
            fg="#00ff00"
        )
        title.pack(pady=20)

        welcome = tk.Label(
            main_frame,
            text=f"Welcome {self.current_user}",
            font=("Arial", 18),
            bg="#1e1e1e",
            fg="#00ff00"
        )
        welcome.pack(pady=10)

        user_info = self.auth_system.get_user_info(self.current_user)
        
        info_text = (
            f"Name: {user_info.get('full_name', 'N/A')}\n"
            f"Department: {user_info.get('department', 'N/A')}\n"
            f"Session: {self.current_session[:8]}...\n\n"
            f"✓ Liveness Verified\n"
            f"✓ Face Matched\n"
            f"✓ Access Granted"
        )

        msg = tk.Label(
            main_frame,
            text=info_text,
            font=("Arial", 12),
            bg="#1e1e1e",
            fg="#cccccc"
        )
        msg.pack(pady=15)

        logout_btn = tk.Button(
            main_frame,
            text="Logout",
            command=self.logout,
            bg="#ff0000",
            fg="#ffffff",
            font=("Arial", 12, "bold"),
            padx=30,
            pady=12,
            cursor="hand2"
        )
        logout_btn.pack(pady=15)

    def logout(self):
        """Logout."""
        if self.current_session:
            self.session_manager.end_session(self.current_session)
            self.audit_logger.log_event(
                self.current_user, "LOGOUT",
                {'session': self.current_session}, "INFO"
            )
        self.is_authenticated = False
        self.current_user = None
        self.current_session = None
        self.liveness_detector.reset()
        self.show_home_screen()

    def cancel_signup(self):
        """Cancel signup."""
        self.auth_running = False
        self.enrollment_running = False
        self.release_camera()
        if self.current_user and not self.liveness_completed:
            self.delete_incomplete_user(self.current_user)
        self.show_home_screen()

    def cancel_authentication(self):
        """Cancel auth."""
        self.auth_running = False
        self.release_camera()
        self.show_home_screen()

    def show_admin_panel(self):
        """Show admin."""
        for widget in self.root.winfo_children():
            widget.destroy()

        main_frame = tk.Frame(self.root, bg="#1e1e1e")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        title = tk.Label(
            main_frame,
            text="Admin Panel",
            font=("Arial", 18, "bold"),
            bg="#1e1e1e",
            fg="#0066ff"
        )
        title.pack(pady=10)

        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        users_frame = ttk.Frame(notebook)
        notebook.add(users_frame, text="Users")

        users_text = scrolledtext.ScrolledText(
            users_frame,
            height=20,
            width=100,
            bg="#2d2d2d",
            fg="#00ff00",
            font=("Courier", 8)
        )
        users_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        users = self.auth_system.list_users()
        users_text.insert(tk.END, "Username | Name | Email | Authenticated\n")
        users_text.insert(tk.END, "-" * 70 + "\n")
        for user in users:
            auth = "✓" if user.get('authenticated', False) else "✗"
            users_text.insert(
                tk.END,
                f"{user['username']:<15} | {user['full_name']:<15} | {user['email']:<20} | {auth}\n"
            )

        audit_frame = ttk.Frame(notebook)
        notebook.add(audit_frame, text="Audit Log")

        audit_text = scrolledtext.ScrolledText(
            audit_frame,
            height=20,
            width=100,
            bg="#2d2d2d",
            fg="#ffff00",
            font=("Courier", 8)
        )
        audit_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        recent = self.audit_logger.get_recent_events(limit=50)
        audit_text.insert(tk.END, "Time | User | Event | Severity\n")
        audit_text.insert(tk.END, "-" * 70 + "\n")
        for event in reversed(recent):
            audit_text.insert(
                tk.END,
                f"{event['timestamp'][-8:]} | {event['username']:<12} | {event['event_type']:<15} | {event['severity']}\n"
            )

        back_btn = tk.Button(
            main_frame,
            text="Back",
            command=self.show_home_screen,
            bg="#0066ff",
            fg="#ffffff",
            font=("Arial", 11, "bold"),
            padx=20,
            pady=10,
            cursor="hand2"
        )
        back_btn.pack(pady=10)

    def add_enrollment_status(self, message):
        """Add enrollment status."""
        try:
            self.enrollment_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
            self.enrollment_text.see(tk.END)
            self.root.update()
        except:
            pass

    def add_status(self, message):
        """Add status."""
        try:
            self.status_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
            self.status_text.see(tk.END)
            self.root.update()
        except:
            pass


if __name__ == "__main__":
    root = tk.Tk()
    app = FacialAuthGUI(root)
    root.mainloop()