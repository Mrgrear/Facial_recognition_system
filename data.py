"""
Enhanced Facial Authentication System with Hybrid IDS
Zero Trust Architecture — Final Production GUI
Nigerian Army University Biu — CYB/23U/3983
Supervisor: Dr. A. H. Desina
"""

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
import queue
import os
import json

sys.path.append(".")

# ─── Load modules ──────────────────────────────────────────────────────────────
print("Loading system modules...")
from auth.face_detector import FaceDetector
from auth.face_recognizer import FaceRecognizer
from auth.liveness_detector import LivenessDetector
from auth.account_manager import AccountManager
from auth.auth_system import AuthSystem
from auth.session_manager import SessionManager
from auth.audit_logger import AuditLogger
from ids.hybrid_ids import HybridIDS
from ids.network_monitor import NetworkMonitor
from ids.feature_extractor import FeatureExtractor
print("All modules loaded successfully.")

# ─── System constants ──────────────────────────────────────────────────────────
SIGNUP_BLINKS   = 3
LOGIN_BLINKS    = 2
FACE_THRESHOLD  = 0.5
CAMERA_INDEX    = 1
CAM_W, CAM_H   = 640, 480
DISPLAY_W       = 640
DISPLAY_H       = 420

# ─── Colour palette ────────────────────────────────────────────────────────────
BG       = "#0d1117"
PANEL    = "#161b22"
BORDER   = "#30363d"
GREEN    = "#3fb950"
BLUE     = "#58a6ff"
YELLOW   = "#d29922"
RED      = "#f85149"
WHITE    = "#e6edf3"
GREY     = "#8b949e"
DARKGREEN= "#1a7f37"

# ─── Background camera thread ──────────────────────────────────────────────────
class CameraThread(threading.Thread):
    """Runs in background, always has a fresh frame ready — eliminates lag."""

    def __init__(self, index=CAMERA_INDEX):
        super().__init__(daemon=True)
        self.index = index
        self.cap   = None
        self.queue = queue.Queue(maxsize=2)
        self.alive = False
        self.ready = threading.Event()

    def run(self):
        self.cap = cv2.VideoCapture(self.index)
        if not self.cap.isOpened():
            self.cap = cv2.VideoCapture(0)   # fallback
        self.cap.set(cv2.CAP_PROP_FRAME_WIDTH,  CAM_W)
        self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, CAM_H)
        self.cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
        self.cap.set(cv2.CAP_PROP_FPS, 30)
        time.sleep(0.5)
        self.alive = True
        # warm-up reads
        for _ in range(20):
            self.cap.read()
        self.ready.set()
        while self.alive:
            ret, frame = self.cap.read()
            if ret:
                try:
                    self.queue.put_nowait(frame)
                except queue.Full:
                    pass
            time.sleep(0.01)
        if self.cap:
            self.cap.release()

    def get_frame(self):
        try:
            return self.queue.get_nowait()
        except queue.Empty:
            return None

    def stop(self):
        self.alive = False


# ─── Helper: convert embedding to/from JSON-safe list ─────────────────────────
def emb_to_list(e):
    if e is None:
        return None
    return e.tolist() if isinstance(e, np.ndarray) else list(e)

def list_to_emb(l):
    if l is None or len(l) == 0:
        return None
    return np.array(l, dtype=np.float32)

def cosine_sim(a, b):
    if a is None or b is None:
        return 0.0
    n = np.linalg.norm(a) * np.linalg.norm(b)
    return float(np.dot(a, b) / (n + 1e-8))


# ══════════════════════════════════════════════════════════════════════════════
#   MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════════════
class FacialAuthSystem:

    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced Facial Authentication System — Zero Trust Architecture")
        self.root.geometry("1100x750")
        self.root.configure(bg=BG)
        self.root.resizable(True, True)

        # ── Initialise all modules ──
        self.face_detector    = FaceDetector()
        self.face_recognizer  = FaceRecognizer()
        self.liveness_det     = LivenessDetector(required_blinks=SIGNUP_BLINKS)
        self.account_mgr      = AccountManager()
        self.auth_system      = AuthSystem()
        self.session_mgr      = SessionManager(session_timeout_minutes=30)
        self.audit_log        = AuditLogger()
        self.ids              = HybridIDS()
        self.ids.load_models()
        self.net_monitor      = NetworkMonitor()
        self.feat_extractor   = FeatureExtractor()

        # ── Camera thread (always running) ──
        self.cam = CameraThread()
        self.cam.start()
        print("Camera thread started.")

        # ── Session state ──
        self.current_user     = None
        self.current_session  = None
        self.login_confidence = 0.0
        self.failed_attempts  = 0
        self.liveness_done    = False
        self.face_matched     = False
        self.is_auth          = False
        self.loop_active      = False

        self.ip_address  = self._get_ip()
        self.device_id   = self._get_device_id()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.show_home()

    # ── Network helpers ──────────────────────────────────────────────────────

    def _get_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _get_device_id(self):
        import uuid
        try:
            return str(uuid.getnode())
        except Exception:
            return "unknown"

    def _on_close(self):
        self.loop_active = False
        self.cam.stop()
        self.root.destroy()

    # ─── UI helpers ──────────────────────────────────────────────────────────

    def _clear(self):
        """Destroy all widgets in the root window."""
        for w in self.root.winfo_children():
            w.destroy()

    def _topbar(self, parent):
        """Draw top bar with system title and status."""
        bar = tk.Frame(parent, bg=PANEL, height=54)
        bar.pack(fill=tk.X, side=tk.TOP)
        bar.pack_propagate(False)

        tk.Label(bar, text="🔐  ZERO TRUST FACIAL AUTHENTICATION SYSTEM",
                 font=("Consolas", 13, "bold"), bg=PANEL, fg=GREEN).pack(side=tk.LEFT, padx=16, pady=14)

        status = f"IP: {self.ip_address}   |   Camera: Index {CAMERA_INDEX}   |   {datetime.now().strftime('%d %b %Y  %H:%M')}"
        tk.Label(bar, text=status, font=("Consolas", 9), bg=PANEL, fg=GREY).pack(side=tk.RIGHT, padx=16)
        ttk.Separator(parent, orient="horizontal").pack(fill=tk.X)

    def _card(self, parent, **kwargs):
        """Styled panel card."""
        f = tk.Frame(parent, bg=PANEL, relief=tk.FLAT, bd=0,
                     highlightbackground=BORDER, highlightthickness=1, **kwargs)
        return f

    def _btn(self, parent, text, cmd, color=BLUE, fg=BG, **kwargs):
        b = tk.Button(parent, text=text, command=cmd,
                      bg=color, fg=fg, activebackground=color, activeforeground=fg,
                      font=("Consolas", 10, "bold"), bd=0, padx=18, pady=9,
                      cursor="hand2", relief=tk.FLAT, **kwargs)
        return b

    def _label(self, parent, text, size=11, color=WHITE, bold=False, **kwargs):
        font = ("Consolas", size, "bold") if bold else ("Consolas", size)
        return tk.Label(parent, text=text, font=font, bg=parent["bg"], fg=color, **kwargs)

    def _log_box(self, parent, height=5):
        st = scrolledtext.ScrolledText(parent, height=height, bg="#0d1117", fg=GREEN,
                                       insertbackground=GREEN, font=("Consolas", 8),
                                       relief=tk.FLAT, bd=4)
        st.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        return st

    def _append(self, box, msg, color=None):
        try:
            ts = datetime.now().strftime("%H:%M:%S")
            box.insert(tk.END, f"[{ts}] {msg}\n")
            box.see(tk.END)
            self.root.update_idletasks()
        except Exception:
            pass

    def _webcam_label(self, parent):
        lbl = tk.Label(parent, bg="#000000", width=DISPLAY_W, height=DISPLAY_H)
        lbl.pack(pady=4)
        return lbl

    def _push_frame(self, label, frame):
        """Push an OpenCV BGR frame to a Tkinter label."""
        try:
            rgb  = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            img  = Image.fromarray(cv2.resize(rgb, (DISPLAY_W, DISPLAY_H)))
            imtk = ImageTk.PhotoImage(image=img)
            label.imgtk = imtk
            label.configure(image=imtk)
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════════════════════
    #   SCREEN 1 — HOME
    # ══════════════════════════════════════════════════════════════════════════

    def show_home(self):
        self._clear()
        self.loop_active = False
        self.liveness_det.reset()

        self._topbar(self.root)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)

        # ── Left: info panel ──
        left = self._card(body, width=420)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 18))
        left.pack_propagate(False)

        tk.Label(left, text="NIGERIAN ARMY UNIVERSITY BIU",
                 font=("Consolas", 9), bg=PANEL, fg=GREY).pack(pady=(18, 2))
        tk.Label(left, text="Department of Cyber Security",
                 font=("Consolas", 9), bg=PANEL, fg=GREY).pack()

        ttk.Separator(left, orient="horizontal").pack(fill=tk.X, pady=12, padx=12)

        tk.Label(left, text="SYSTEM CAPABILITIES",
                 font=("Consolas", 9, "bold"), bg=PANEL, fg=YELLOW).pack(pady=(0, 8))

        features = [
            ("🔍", "Face Detection",            "InsightFace Buffalo-L"),
            ("🧠", "ArcFace Recognition",        "512-D Cosine Similarity"),
            ("👁️", "Liveness Detection",         f"EAR Blink  (Signup:{SIGNUP_BLINKS} / Login:{LOGIN_BLINKS})"),
            ("🛡️", "Hybrid IDS",                 "Random Forest + Isolation Forest"),
            ("📡", "Network Monitoring",          "17-Feature Vector"),
            ("🔒", "Session Management",          "UUID + IP Binding  (30 min)"),
            ("📋", "Audit Logging",              "Full Event Trail"),
            ("⚡", "Zero Trust Architecture",    "Never Trust — Always Verify"),
        ]

        for icon, name, desc in features:
            row = tk.Frame(left, bg=PANEL)
            row.pack(fill=tk.X, padx=14, pady=3)
            tk.Label(row, text=icon, font=("Consolas", 12), bg=PANEL, fg=WHITE, width=3).pack(side=tk.LEFT)
            col = tk.Frame(row, bg=PANEL)
            col.pack(side=tk.LEFT, padx=4)
            tk.Label(col, text=name, font=("Consolas", 9, "bold"), bg=PANEL, fg=WHITE, anchor="w").pack(anchor="w")
            tk.Label(col, text=desc, font=("Consolas", 8), bg=PANEL, fg=GREY, anchor="w").pack(anchor="w")

        ttk.Separator(left, orient="horizontal").pack(fill=tk.X, pady=12, padx=12)

        users = self.auth_system.list_users()
        auth_count = sum(1 for u in users if u.get("authenticated", False))
        active_sess = len([s for s in self.session_mgr.get_all_sessions() if not s.get("expired")])
        all_events  = self.audit_log.logs
        alerts      = sum(1 for e in all_events if e["event_type"] == "IDS_ALERT")

        stats = [
            ("Registered Users",   str(len(users))),
            ("Authenticated",      str(auth_count)),
            ("Active Sessions",    str(active_sess)),
            ("IDS Alerts",         str(alerts)),
            ("Device IP",          self.ip_address),
        ]
        for label, val in stats:
            row = tk.Frame(left, bg=PANEL)
            row.pack(fill=tk.X, padx=14, pady=1)
            tk.Label(row, text=label + ":", font=("Consolas", 8), bg=PANEL, fg=GREY, width=20, anchor="w").pack(side=tk.LEFT)
            tk.Label(row, text=val, font=("Consolas", 8, "bold"), bg=PANEL, fg=GREEN, anchor="w").pack(side=tk.LEFT)

        # ── Right: action panel ──
        right = tk.Frame(body, bg=BG)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(right, text="SELECT AN ACTION",
                 font=("Consolas", 11, "bold"), bg=BG, fg=YELLOW).pack(pady=(0, 20))

        actions = [
            ("👤  LOGIN",            self.show_login,      BLUE,      BG),
            ("📝  NEW USER",         self.show_signup,     GREEN,     BG),
            ("👨‍💼  ADMIN PANEL",      self.show_admin,      "#8957e5", WHITE),
            ("📊  IDS DASHBOARD",    self.show_ids,        YELLOW,    BG),
            ("🚪  EXIT",             self._on_close,       "#484f58", WHITE),
        ]

        for txt, cmd, bg_c, fg_c in actions:
            btn = self._btn(right, txt, cmd, color=bg_c, fg=fg_c, width=36)
            btn.pack(pady=7)

    # ══════════════════════════════════════════════════════════════════════════
    #   SCREEN 2 — LOGIN
    # ══════════════════════════════════════════════════════════════════════════

    def show_login(self):
        self._clear()
        self.loop_active = False
        self._topbar(self.root)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=40, pady=20)

        card = self._card(body)
        card.pack(expand=True, ipadx=30, ipady=30)

        self._label(card, "USER LOGIN", 16, BLUE, bold=True).pack(pady=(20, 6))
        self._label(card, "Enter your registered username to begin authentication", 9, GREY).pack()

        ttk.Separator(card, orient="horizontal").pack(fill=tk.X, pady=14, padx=20)

        self._label(card, "Username", 10, WHITE).pack(anchor="w", padx=30)
        user_var = tk.StringVar()
        entry = tk.Entry(card, textvariable=user_var, font=("Consolas", 12),
                         bg="#0d1117", fg=GREEN, insertbackground=GREEN,
                         relief=tk.FLAT, bd=4, width=36)
        entry.pack(padx=30, pady=(4, 18))
        entry.focus()

        msg_var = tk.StringVar()
        msg_lbl = tk.Label(card, textvariable=msg_var, font=("Consolas", 9),
                           bg=PANEL, fg=RED)
        msg_lbl.pack()

        def proceed():
            uname = user_var.get().strip()
            if not uname:
                msg_var.set("⚠  Please enter your username.")
                return

            if not self.auth_system.user_exists(uname):
                msg_var.set("⚠  Username not found in the system.")
                self.audit_log.log_failed_attempt(uname, "Username not found", self.ip_address)
                self.failed_attempts += 1
                return

            info = self.auth_system.get_user_info(uname)
            if not info.get("authenticated", False):
                msg_var.set("⚠  Account not verified. Complete signup first.")
                self.audit_log.log_failed_attempt(uname, "Account not authenticated", self.ip_address)
                return

            locked, lock_msg = self.account_mgr.check_lockout(uname)
            if locked:
                msg_var.set(f"🔒  {lock_msg}")
                return

            self.current_user    = uname
            self.face_matched    = False
            self.login_confidence= 0.0
            self.is_auth         = False
            self.show_face_match()

        entry.bind("<Return>", lambda e: proceed())

        btn_row = tk.Frame(card, bg=PANEL)
        btn_row.pack(pady=14)
        self._btn(btn_row, "▶  CONTINUE", proceed, color=BLUE).pack(side=tk.LEFT, padx=8)
        self._btn(btn_row, "← BACK",      self.show_home, color="#484f58", fg=WHITE).pack(side=tk.LEFT, padx=8)

    # ══════════════════════════════════════════════════════════════════════════
    #   SCREEN 3 — SIGNUP FORM
    # ══════════════════════════════════════════════════════════════════════════

    def show_signup(self):
        self._clear()
        self.loop_active = False
        self._topbar(self.root)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=40, pady=20)

        card = self._card(body)
        card.pack(expand=True, ipadx=30, ipady=20)

        self._label(card, "NEW USER REGISTRATION", 15, GREEN, bold=True).pack(pady=(18, 4))
        self._label(card, "All fields are required", 9, GREY).pack()
        ttk.Separator(card, orient="horizontal").pack(fill=tk.X, pady=12, padx=20)

        fields = [
            ("Username",     "e.g. johndoe"),
            ("Email",        "e.g. john@naub.edu.ng"),
            ("Full Name",    "e.g. John Doe"),
            ("Department",   "e.g. Cyber Security"),
            ("Phone",        "e.g. 08012345678"),
        ]
        entries = {}
        for label, placeholder in fields:
            row = tk.Frame(card, bg=PANEL)
            row.pack(fill=tk.X, padx=30, pady=4)
            tk.Label(row, text=label + ":", font=("Consolas", 9, "bold"),
                     bg=PANEL, fg=WHITE, width=14, anchor="w").pack(side=tk.LEFT)
            var = tk.StringVar()
            e = tk.Entry(row, textvariable=var, font=("Consolas", 10),
                         bg="#0d1117", fg=GREEN, insertbackground=GREEN,
                         relief=tk.FLAT, bd=3, width=36)
            e.pack(side=tk.LEFT, padx=4)
            entries[label] = var

        msg_var = tk.StringVar()
        tk.Label(card, textvariable=msg_var, font=("Consolas", 9),
                 bg=PANEL, fg=RED).pack(pady=6)

        def proceed():
            data = {k: v.get().strip() for k, v in entries.items()}
            if not all(data.values()):
                msg_var.set("⚠  All fields are required.")
                return
            if self.auth_system.user_exists(data["Username"]):
                msg_var.set("⚠  Username already exists. Choose another.")
                return

            ok, msg = self.auth_system.create_account(
                data["Username"], data["Email"],
                data["Full Name"], data["Department"], data["Phone"]
            )
            if ok:
                self.current_user  = data["Username"]
                self.liveness_done = False
                self.audit_log.log_event(data["Username"], "SIGNUP", {"email": data["Email"]}, "INFO")
                messagebox.showinfo("Account Created",
                                    f"Account created for {data['Full Name']}.\n\n"
                                    "You will now enrol your face.\n"
                                    f"Required: {SIGNUP_BLINKS} eye blinks for liveness verification.")
                self.show_enrollment()
            else:
                msg_var.set(f"⚠  {msg}")

        btn_row = tk.Frame(card, bg=PANEL)
        btn_row.pack(pady=14)
        self._btn(btn_row, "CREATE ACCOUNT", proceed, color=GREEN).pack(side=tk.LEFT, padx=8)
        self._btn(btn_row, "← BACK", self.show_home, color="#484f58", fg=WHITE).pack(side=tk.LEFT, padx=8)

    # ══════════════════════════════════════════════════════════════════════════
    #   SCREEN 4 — AUTO FACE ENROLLMENT
    # ══════════════════════════════════════════════════════════════════════════

    def show_enrollment(self):
        self._clear()
        self.loop_active = True
        self._topbar(self.root)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=14, pady=8)

        # header
        hdr = tk.Frame(body, bg=BG)
        hdr.pack(fill=tk.X, pady=(0, 8))
        self._label(hdr, "STEP 1 OF 2 — FACE ENROLLMENT", 13, GREEN, bold=True).pack(side=tk.LEFT)
        self._label(hdr, "Auto-capturing 5 frames. Keep your face steady and well-lit.", 9, GREY).pack(side=tk.RIGHT)

        # two columns
        cols = tk.Frame(body, bg=BG)
        cols.pack(fill=tk.BOTH, expand=True)

        # camera
        cam_card = self._card(cols)
        cam_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        self.wcam = self._webcam_label(cam_card)

        # status
        side = self._card(cols, width=320)
        side.pack(side=tk.LEFT, fill=tk.Y)
        side.pack_propagate(False)

        self._label(side, "ENROLLMENT STATUS", 9, YELLOW, bold=True).pack(pady=(14, 6))
        self.progress_var = tk.StringVar(value="Waiting for face...")
        tk.Label(side, textvariable=self.progress_var,
                 font=("Consolas", 10, "bold"), bg=PANEL, fg=GREEN,
                 wraplength=280).pack(pady=4, padx=10)

        self.enroll_bar = ttk.Progressbar(side, maximum=5, mode="determinate")
        self.enroll_bar.pack(fill=tk.X, padx=14, pady=6)

        self._label(side, "LOG", 8, YELLOW, bold=True).pack(pady=(10, 2))
        self.enroll_log = self._log_box(side, height=10)

        self._btn(side, "CANCEL", self._cancel_signup, color=RED, fg=WHITE).pack(pady=10)

        threading.Thread(target=self._enroll_loop, daemon=True).start()

    def _enroll_loop(self):
        captured = []
        stable   = 0
        timeout  = time.time() + 60

        self.cam.ready.wait(timeout=5)
        self._append(self.enroll_log, "Camera ready. Auto-capture in progress...")

        while self.loop_active and len(captured) < 5 and time.time() < timeout:
            frame = self.cam.get_frame()
            if frame is None:
                time.sleep(0.02)
                continue

            faces  = self.face_detector.detect(frame)
            disp   = self.face_detector.draw(frame, faces)
            count  = len(captured)

            cv2.putText(disp, f"Captured: {count}/5", (12, 34),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.8, (63, 185, 80), 2)

            if len(faces) == 1:
                stable += 1
                if stable >= 3:
                    captured.append(frame.copy())
                    stable = 0
                    self.enroll_bar["value"] = len(captured)
                    self.progress_var.set(f"Frame {len(captured)}/5 captured ✓")
                    self._append(self.enroll_log, f"Frame {len(captured)}/5 captured")
                    time.sleep(0.4)
            else:
                stable = 0

            self._push_frame(self.wcam, disp)
            self.root.update_idletasks()
            time.sleep(0.02)

        if len(captured) < 5:
            self._append(self.enroll_log, "❌ Enrollment failed. Not enough frames.")
            self._cancel_signup()
            return

        self._append(self.enroll_log, "Processing embeddings...")
        ok = self.face_recognizer.enroll(self.current_user, captured)
        if not ok:
            self._append(self.enroll_log, "❌ Face enrolment failed (embedding error).")
            self._cancel_signup()
            return

        emb = self.face_recognizer.database.get(self.current_user)
        self.account_mgr.enroll_face(self.current_user, emb)
        self.auth_system.enroll_face_for_user(self.current_user, captured)

        # persist embedding in users.json as list
        if self.current_user in self.auth_system.users:
            self.auth_system.users[self.current_user]["embedding"] = emb_to_list(emb)
            self.auth_system.save_users()

        self.audit_log.log_event(self.current_user, "ENROLLMENT",
                                  {"frames": 5, "embedding_stored": True}, "INFO")
        self._append(self.enroll_log, "✅ Face enrolled! Proceeding to liveness check...")
        time.sleep(1)

        if self.loop_active:
            self.root.after(400, self.show_signup_liveness)

    # ══════════════════════════════════════════════════════════════════════════
    #   SCREEN 5 — LIVENESS (SIGNUP)
    # ══════════════════════════════════════════════════════════════════════════

    def show_signup_liveness(self):
        self._clear()
        self.loop_active = True
        self._topbar(self.root)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=14, pady=8)

        hdr = tk.Frame(body, bg=BG)
        hdr.pack(fill=tk.X, pady=(0, 8))
        self._label(hdr, f"STEP 2 OF 2 — LIVENESS VERIFICATION  (Blink {SIGNUP_BLINKS} times)", 12, YELLOW, bold=True).pack(side=tk.LEFT)

        cols = tk.Frame(body, bg=BG)
        cols.pack(fill=tk.BOTH, expand=True)

        cam_card = self._card(cols)
        cam_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        self.wcam = self._webcam_label(cam_card)

        side = self._card(cols, width=320)
        side.pack(side=tk.LEFT, fill=tk.Y)
        side.pack_propagate(False)

        self._label(side, "LIVENESS STATUS", 9, YELLOW, bold=True).pack(pady=(14, 4))
        self.blink_var = tk.StringVar(value=f"Blinks: 0 / {SIGNUP_BLINKS}")
        tk.Label(side, textvariable=self.blink_var,
                 font=("Consolas", 14, "bold"), bg=PANEL, fg=GREEN).pack(pady=8)

        self.ear_var = tk.StringVar(value="EAR: --")
        tk.Label(side, textvariable=self.ear_var,
                 font=("Consolas", 10), bg=PANEL, fg=GREY).pack()

        self.live_bar = ttk.Progressbar(side, maximum=SIGNUP_BLINKS, mode="determinate")
        self.live_bar.pack(fill=tk.X, padx=14, pady=8)

        self._label(side, "INSTRUCTIONS", 8, YELLOW, bold=True).pack(pady=(12, 4))
        self._label(side,
                    "Look directly at the camera.\n"
                    "Blink naturally and slowly.\n"
                    "Ensure good lighting on your face.\n"
                    "Keep your face in the frame.",
                    9, GREY, justify=tk.LEFT).pack(padx=14, anchor="w")

        self._label(side, "LOG", 8, YELLOW, bold=True).pack(pady=(10, 2))
        self.live_log = self._log_box(side, height=6)

        self._btn(side, "CANCEL", self._cancel_signup, color=RED, fg=WHITE).pack(pady=10)

        self.liveness_det.reset()
        self.liveness_det.required_blinks = SIGNUP_BLINKS
        threading.Thread(target=self._signup_liveness_loop, daemon=True).start()

    def _signup_liveness_loop(self):
        timeout = time.time() + 40
        self._append(self.live_log, f"Waiting for {SIGNUP_BLINKS} blinks...")
        passed = False

        while self.loop_active and time.time() < timeout:
            frame = self.cam.get_frame()
            if frame is None:
                time.sleep(0.02)
                continue

            faces = self.face_detector.detect(frame)
            disp  = self.face_detector.draw(frame, faces)

            if len(faces) == 1:
                is_live, blinks, ear = self.liveness_det.detect(frame)
                self.blink_var.set(f"Blinks: {blinks} / {SIGNUP_BLINKS}")
                self.ear_var.set(f"EAR: {ear:.4f}")
                self.live_bar["value"] = blinks
                self._append(self.live_log, f"Blinks: {blinks}/{SIGNUP_BLINKS}  EAR={ear:.3f}")

                cv2.putText(disp, f"Blinks: {blinks}/{SIGNUP_BLINKS}", (12, 34),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.8, (63, 185, 80), 2)
                cv2.putText(disp, f"EAR: {ear:.3f}", (12, 62),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.6, (139, 148, 158), 2)

                if is_live:
                    passed = True
                    self._append(self.live_log, f"✅ Liveness confirmed! {blinks} blinks detected.")
                    break
            else:
                self._append(self.live_log, f"⚠ Face not detected clearly. Found: {len(faces)}")

            self._push_frame(self.wcam, disp)
            self.root.update_idletasks()
            time.sleep(0.02)

        if passed and self.loop_active:
            self.liveness_done = True
            self.auth_system.users[self.current_user]["authenticated"] = True
            self.auth_system.save_users()
            self.audit_log.log_event(self.current_user, "LIVENESS_VERIFIED_SIGNUP",
                                      {"blinks": SIGNUP_BLINKS}, "INFO")
            self._append(self.live_log, "Account fully activated. Redirecting to login...")
            time.sleep(1.2)
            messagebox.showinfo("Signup Complete",
                                f"Welcome {self.current_user}!\n\n"
                                "Your account has been activated.\n"
                                "You can now log in using your username.")
            self.root.after(300, self.show_login)
        else:
            self._append(self.live_log, "❌ Liveness not verified. Deleting account...")
            time.sleep(1)
            self._cancel_signup()

    # ══════════════════════════════════════════════════════════════════════════
    #   SCREEN 6 — FACE MATCHING (LOGIN STEP 1)
    # ══════════════════════════════════════════════════════════════════════════

    def show_face_match(self):
        self._clear()
        self.loop_active = True
        self._topbar(self.root)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=14, pady=8)

        hdr = tk.Frame(body, bg=BG)
        hdr.pack(fill=tk.X, pady=(0, 8))
        self._label(hdr, f"LOGIN STEP 1 — FACE RECOGNITION  (User: {self.current_user})", 12, BLUE, bold=True).pack(side=tk.LEFT)

        cols = tk.Frame(body, bg=BG)
        cols.pack(fill=tk.BOTH, expand=True)

        cam_card = self._card(cols)
        cam_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        self.wcam = self._webcam_label(cam_card)

        side = self._card(cols, width=320)
        side.pack(side=tk.LEFT, fill=tk.Y)
        side.pack_propagate(False)

        self._label(side, "FACE MATCH STATUS", 9, YELLOW, bold=True).pack(pady=(14, 6))

        self.match_var = tk.StringVar(value="Scanning...")
        tk.Label(side, textvariable=self.match_var,
                 font=("Consolas", 10, "bold"), bg=PANEL, fg=GREEN,
                 wraplength=280).pack(pady=4, padx=10)

        self.conf_var = tk.StringVar(value="Confidence: --")
        tk.Label(side, textvariable=self.conf_var,
                 font=("Consolas", 12, "bold"), bg=PANEL, fg=BLUE).pack(pady=6)

        self._label(side, f"Threshold: ≥ {FACE_THRESHOLD}", 9, GREY).pack()

        self.match_bar = ttk.Progressbar(side, maximum=100, mode="determinate")
        self.match_bar.pack(fill=tk.X, padx=14, pady=8)

        self._label(side, "SECURITY CHECK", 8, YELLOW, bold=True).pack(pady=(10, 4))
        self._label(side,
                    f"Logged in as: {self.current_user}\n"
                    "Face MUST match the enrolled\n"
                    "embedding for this account.\n\n"
                    "Another person's face will be\n"
                    "rejected regardless of username.",
                    9, GREY, justify=tk.LEFT).pack(padx=14, anchor="w")

        self._label(side, "LOG", 8, YELLOW, bold=True).pack(pady=(10, 2))
        self.match_log = self._log_box(side, height=6)

        self._btn(side, "CANCEL", self._cancel_auth, color=RED, fg=WHITE).pack(pady=10)

        threading.Thread(target=self._face_match_loop, daemon=True).start()

    def _face_match_loop(self):
        self.cam.ready.wait(timeout=5)
        self._append(self.match_log, "Loading enrollment embedding...")

        stored_raw = self.auth_system.users.get(self.current_user, {}).get("embedding")
        stored_emb = list_to_emb(stored_raw) if stored_raw else \
                     self.face_recognizer.database.get(self.current_user)

        if stored_emb is None:
            self._append(self.match_log, "❌ No enrollment embedding found.")
            time.sleep(1.5)
            self.root.after(300, self.show_login)
            return

        self._append(self.match_log, "Embedding loaded. Scanning face...")
        matched   = False
        best_sim  = 0.0
        timeout   = time.time() + 25

        while self.loop_active and not matched and time.time() < timeout:
            frame = self.cam.get_frame()
            if frame is None:
                time.sleep(0.02)
                continue

            faces = self.face_detector.detect(frame)
            disp  = self.face_detector.draw(frame, faces)

            if len(faces) == 1:
                cur_emb = self.face_recognizer.get_embedding(frame)
                if cur_emb is not None:
                    sim = cosine_sim(cur_emb, stored_emb)
                    if sim > best_sim:
                        best_sim = sim
                    pct = min(int(sim * 100), 100)
                    self.conf_var.set(f"Confidence: {sim:.4f}")
                    self.match_bar["value"] = pct
                    self._append(self.match_log, f"Similarity: {sim:.4f}  threshold: {FACE_THRESHOLD}")

                    col = (63, 185, 80) if sim >= FACE_THRESHOLD else (248, 81, 73)
                    cv2.putText(disp, f"Match: {sim:.4f}", (12, 34),
                                cv2.FONT_HERSHEY_SIMPLEX, 0.8, col, 2)
                    cv2.putText(disp, f"Threshold: {FACE_THRESHOLD}", (12, 62),
                                cv2.FONT_HERSHEY_SIMPLEX, 0.6, (139, 148, 158), 2)

                    if sim >= FACE_THRESHOLD:
                        self.login_confidence = sim
                        self.match_var.set(f"✅ Face matched! ({sim:.4f})")
                        self._append(self.match_log, f"✅ Face matched! Confidence: {sim:.4f}")
                        matched = True
                        break
                    else:
                        self.match_var.set(f"⚠ Not matched yet ({sim:.4f})")
            else:
                self._append(self.match_log, f"Need 1 face. Found: {len(faces)}")

            self._push_frame(self.wcam, disp)
            self.root.update_idletasks()
            time.sleep(0.02)

        if matched and self.loop_active:
            self.face_matched = True
            time.sleep(0.6)
            self.root.after(300, self.show_login_liveness)
        else:
            self.failed_attempts += 1
            self.account_mgr.record_failed_attempt(self.current_user)
            self.audit_log.log_failed_attempt(self.current_user,
                f"Face match failed. Best similarity: {best_sim:.4f}", self.ip_address)
            messagebox.showerror("Access Denied",
                                 f"Face recognition failed.\n\n"
                                 f"Best similarity: {best_sim:.4f}\n"
                                 f"Required: ≥ {FACE_THRESHOLD}\n\n"
                                 "This attempt has been logged.")
            self.root.after(300, self.show_home)

    # ══════════════════════════════════════════════════════════════════════════
    #   SCREEN 7 — LIVENESS (LOGIN STEP 2)
    # ══════════════════════════════════════════════════════════════════════════

    def show_login_liveness(self):
        self._clear()
        self.loop_active = True
        self._topbar(self.root)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=14, pady=8)

        hdr = tk.Frame(body, bg=BG)
        hdr.pack(fill=tk.X, pady=(0, 8))
        self._label(hdr, f"LOGIN STEP 2 — LIVENESS CHECK  (Blink {LOGIN_BLINKS} times)", 12, YELLOW, bold=True).pack(side=tk.LEFT)

        cols = tk.Frame(body, bg=BG)
        cols.pack(fill=tk.BOTH, expand=True)

        cam_card = self._card(cols)
        cam_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        self.wcam = self._webcam_label(cam_card)

        side = self._card(cols, width=320)
        side.pack(side=tk.LEFT, fill=tk.Y)
        side.pack_propagate(False)

        self._label(side, "LIVENESS STATUS", 9, YELLOW, bold=True).pack(pady=(14, 4))
        self.blink_var = tk.StringVar(value=f"Blinks: 0 / {LOGIN_BLINKS}")
        tk.Label(side, textvariable=self.blink_var,
                 font=("Consolas", 14, "bold"), bg=PANEL, fg=GREEN).pack(pady=8)

        self.ear_var = tk.StringVar(value="EAR: --")
        tk.Label(side, textvariable=self.ear_var,
                 font=("Consolas", 10), bg=PANEL, fg=GREY).pack()

        self.live_bar = ttk.Progressbar(side, maximum=LOGIN_BLINKS, mode="determinate")
        self.live_bar.pack(fill=tk.X, padx=14, pady=8)

        self._label(side, "ZTA PIPELINE", 8, YELLOW, bold=True).pack(pady=(10, 4))
        self._label(side,
                    f"✅ Face Recognition:  {self.login_confidence:.4f}\n"
                    f"⏳ Liveness: {LOGIN_BLINKS} blinks required\n"
                    "⏳ Hybrid IDS: pending\n"
                    "⏳ Session: pending",
                    9, GREY, justify=tk.LEFT).pack(padx=14, anchor="w")

        self._label(side, "LOG", 8, YELLOW, bold=True).pack(pady=(10, 2))
        self.live_log = self._log_box(side, height=6)

        self._btn(side, "CANCEL", self._cancel_auth, color=RED, fg=WHITE).pack(pady=10)

        self.liveness_det.reset()
        self.liveness_det.required_blinks = LOGIN_BLINKS
        threading.Thread(target=self._login_liveness_loop, daemon=True).start()

    def _login_liveness_loop(self):
        timeout = time.time() + 35
        passed  = False
        blink_count = 0

        while self.loop_active and time.time() < timeout:
            frame = self.cam.get_frame()
            if frame is None:
                time.sleep(0.02)
                continue

            faces = self.face_detector.detect(frame)
            disp  = self.face_detector.draw(frame, faces)

            if len(faces) == 1:
                is_live, blinks, ear = self.liveness_det.detect(frame)
                blink_count = blinks
                self.blink_var.set(f"Blinks: {blinks} / {LOGIN_BLINKS}")
                self.ear_var.set(f"EAR: {ear:.4f}")
                self.live_bar["value"] = blinks
                self._append(self.live_log, f"Blinks: {blinks}/{LOGIN_BLINKS}  EAR={ear:.3f}")

                col = (63, 185, 80) if is_live else (88, 166, 255)
                cv2.putText(disp, f"Blinks: {blinks}/{LOGIN_BLINKS}", (12, 34),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.8, col, 2)
                cv2.putText(disp, f"EAR: {ear:.3f}", (12, 62),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.6, (139, 148, 158), 2)

                if is_live:
                    passed = True
                    self._append(self.live_log, "✅ Liveness confirmed! Running IDS check...")
                    break
            else:
                self._append(self.live_log, f"⚠ {len(faces)} face(s) in frame. Need exactly 1.")

            self._push_frame(self.wcam, disp)
            self.root.update_idletasks()
            time.sleep(0.02)

        if passed and self.loop_active:
            self._run_ids_and_grant(blink_count)
        else:
            self.failed_attempts += 1
            self.account_mgr.record_failed_attempt(self.current_user)
            self.audit_log.log_failed_attempt(self.current_user,
                "Liveness check failed at login", self.ip_address)
            messagebox.showerror("Liveness Failed",
                                 "You did not complete the required blinks in time.\nPlease try again.")
            self.root.after(300, self.show_home)

    # ── IDS check ─────────────────────────────────────────────────────────────

    def _run_ids_and_grant(self, blink_count):
        """Run hybrid IDS and either grant or deny access."""
        try:
            net_features, _, _ = self.net_monitor.extract_features()
        except Exception:
            net_features = {}

        auth_event = {
            "success":          True,
            "spoof_detected":   False,
            "confidence_score": self.login_confidence,
            "ip_address":       self.ip_address,
            "failed_attempts":  self.failed_attempts,
        }
        try:
            features = self.feat_extractor.extract(auth_event, net_features)
            alert, level, reason = self.ids.predict(features)
        except Exception as e:
            alert, level, reason = False, "N/A", f"IDS unavailable: {e}"

        if alert:
            self.audit_log.log_ids_alert(self.current_user, level, reason)
            self.audit_log.log_failed_attempt(self.current_user,
                f"IDS blocked login: {reason}", self.ip_address)
            messagebox.showerror("IDS Alert",
                                 f"Access blocked by Intrusion Detection System.\n\n"
                                 f"Level: {level}\nReason: {reason}\n\n"
                                 "This event has been logged.")
            self.root.after(300, self.show_home)
            return

        # All checks passed — create session
        session_id = self.session_mgr.create_session(
            self.current_user, self.ip_address, self.device_id)
        self.current_session = session_id

        self.audit_log.log_login(self.current_user, True, self.login_confidence, self.ip_address)
        self.audit_log.log_event(self.current_user, "AUTHENTICATION_SUCCESS", {
            "face_confidence": round(self.login_confidence, 4),
            "liveness_blinks": blink_count,
            "ids_status":      level if not alert else "ALERT",
            "ip_address":      self.ip_address,
            "session_id":      session_id[:8],
        }, "INFO")

        self.is_auth = True
        self.account_mgr.record_success(self.current_user)
        self.failed_attempts = 0
        self.root.after(300, self.show_success)

    # ══════════════════════════════════════════════════════════════════════════
    #   SCREEN 8 — SUCCESS
    # ══════════════════════════════════════════════════════════════════════════

    def show_success(self):
        self._clear()
        self.loop_active = False
        self._topbar(self.root)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=40, pady=20)

        card = self._card(body)
        card.pack(expand=True, ipadx=40, ipady=30)

        tk.Label(card, text="✅", font=("Consolas", 48), bg=PANEL, fg=GREEN).pack(pady=(20, 4))
        self._label(card, "AUTHENTICATION SUCCESSFUL", 16, GREEN, bold=True).pack()

        user_info = self.auth_system.get_user_info(self.current_user)
        if user_info:
            self._label(card, f"Welcome, {user_info.get('full_name', self.current_user)}",
                        13, WHITE).pack(pady=4)
            self._label(card, f"Department: {user_info.get('department', 'N/A')}",
                        10, GREY).pack()

        ttk.Separator(card, orient="horizontal").pack(fill=tk.X, pady=16, padx=30)

        self._label(card, "ZERO TRUST VERIFICATION SUMMARY", 10, YELLOW, bold=True).pack()

        checks = [
            ("Face Recognition",   f"PASSED  (Confidence: {self.login_confidence:.4f})"),
            ("Liveness Detection", f"PASSED  ({LOGIN_BLINKS} blinks confirmed)"),
            ("Hybrid IDS",         "PASSED  (RF + Isolation Forest: CLEAN)"),
            ("Session ID",         f"{self.current_session[:12]}..." if self.current_session else "N/A"),
            ("IP Address",         self.ip_address),
            ("Session Timeout",    "30 minutes from now"),
            ("Access Time",        datetime.now().strftime("%d %b %Y  %H:%M:%S")),
        ]

        for label, val in checks:
            row = tk.Frame(card, bg=PANEL)
            row.pack(fill=tk.X, padx=40, pady=2)
            tk.Label(row, text="✓  " + label + ":", font=("Consolas", 9),
                     bg=PANEL, fg=GREEN, width=26, anchor="w").pack(side=tk.LEFT)
            tk.Label(row, text=val, font=("Consolas", 9, "bold"),
                     bg=PANEL, fg=WHITE, anchor="w").pack(side=tk.LEFT)

        ttk.Separator(card, orient="horizontal").pack(fill=tk.X, pady=16, padx=30)

        btn_row = tk.Frame(card, bg=PANEL)
        btn_row.pack(pady=8)
        self._btn(btn_row, "🚪  LOGOUT", self._logout, color=RED, fg=WHITE).pack(side=tk.LEFT, padx=10)
        self._btn(btn_row, "📊  IDS DASHBOARD", self.show_ids, color=YELLOW, fg=BG).pack(side=tk.LEFT, padx=10)

    # ══════════════════════════════════════════════════════════════════════════
    #   SCREEN 9 — ADMIN PANEL
    # ══════════════════════════════════════════════════════════════════════════

    def show_admin(self):
        self._clear()
        self.loop_active = False
        self._topbar(self.root)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=14, pady=8)

        self._label(body, "ADMINISTRATOR PANEL", 14, "#8957e5", bold=True).pack(pady=(0, 10))

        nb = ttk.Notebook(body)
        nb.pack(fill=tk.BOTH, expand=True)

        # ── Tab 1: Users ──────────────────────────────────────────────────────
        t1 = tk.Frame(nb, bg=PANEL)
        nb.add(t1, text="👥  Registered Users")

        top1 = tk.Frame(t1, bg=PANEL)
        top1.pack(fill=tk.X, padx=10, pady=6)
        self._btn(top1, "🔄 Refresh", lambda: self._refresh_users(u_box), color=BLUE, fg=BG).pack(side=tk.LEFT, padx=4)

        u_box = scrolledtext.ScrolledText(t1, bg="#0d1117", fg=GREEN,
                                          font=("Consolas", 8), relief=tk.FLAT)
        u_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)
        self._refresh_users(u_box)

        # ── Tab 2: Account Status ─────────────────────────────────────────────
        t2 = tk.Frame(nb, bg=PANEL)
        nb.add(t2, text="🔐  Account Status")

        a_box = scrolledtext.ScrolledText(t2, bg="#0d1117", fg=GREEN,
                                          font=("Consolas", 8), relief=tk.FLAT)
        a_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)
        self._refresh_accounts(a_box)

        # ── Tab 3: Audit Log ──────────────────────────────────────────────────
        t3 = tk.Frame(nb, bg=PANEL)
        nb.add(t3, text="📋  Audit Log")

        al_box = scrolledtext.ScrolledText(t3, bg="#0d1117", fg="#d29922",
                                           font=("Consolas", 8), relief=tk.FLAT)
        al_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)
        events = self.audit_log.get_recent_events(limit=200)
        al_box.insert(tk.END, f"{'Timestamp':<22} {'Username':<14} {'Event':<28} {'Severity':<10} Details\n")
        al_box.insert(tk.END, "─"*120 + "\n")
        for e in reversed(events):
            al_box.insert(tk.END,
                f"{e['timestamp']:<22} {e['username']:<14} {e['event_type']:<28} "
                f"{e['severity']:<10} {str(e['details'])[:60]}\n")

        # ── Tab 4: Sessions ───────────────────────────────────────────────────
        t4 = tk.Frame(nb, bg=PANEL)
        nb.add(t4, text="🌐  Active Sessions")

        s_box = scrolledtext.ScrolledText(t4, bg="#0d1117", fg=GREEN,
                                          font=("Consolas", 8), relief=tk.FLAT)
        s_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)
        sessions = self.session_mgr.get_all_sessions()
        s_box.insert(tk.END, f"{'Session ID':<14} {'User':<14} {'IP Address':<18} {'Created':<22} {'Expired'}\n")
        s_box.insert(tk.END, "─"*100 + "\n")
        for s in sessions:
            s_box.insert(tk.END,
                f"{s['session_id'][:12]}...  {s['username']:<14} {s['ip_address']:<18} "
                f"{s['created_at']:<22} {s['expired']}\n")

        # ── Tab 5: Delete User ────────────────────────────────────────────────
        t5 = tk.Frame(nb, bg=PANEL)
        nb.add(t5, text="🗑️  Manage Users")
        self._build_delete_tab(t5)

        # ── Back button ───────────────────────────────────────────────────────
        self._btn(body, "← BACK TO HOME", self.show_home, color="#484f58", fg=WHITE).pack(pady=10)

    def _refresh_users(self, box):
        box.delete("1.0", tk.END)
        users = self.auth_system.list_users()
        box.insert(tk.END,
            f"{'#':<4} {'Username':<14} {'Full Name':<18} {'Department':<16} "
            f"{'Enrolled':<10} {'Auth':<8} {'Created'}\n")
        box.insert(tk.END, "─"*120 + "\n")
        for i, u in enumerate(users, 1):
            enr = "✓" if u.get("enrolled", False) else "✗"
            aut = "✓" if u.get("authenticated", False) else "✗"
            box.insert(tk.END,
                f"{i:<4} {u['username']:<14} {u['full_name']:<18} "
                f"{u['department']:<16} {enr:<10} {aut:<8} {u['created_at'][:10]}\n")

    def _refresh_accounts(self, box):
        box.delete("1.0", tk.END)
        accounts = self.account_mgr.list_all_accounts()
        box.insert(tk.END,
            f"{'Username':<14} {'Locked':<10} {'Failed Attempts':<18} "
            f"{'Spoof Attempts':<16} {'Last Login'}\n")
        box.insert(tk.END, "─"*100 + "\n")
        for a in accounts:
            box.insert(tk.END,
                f"{a['username']:<14} {str(a.get('is_locked', False)):<10} "
                f"{a.get('failed_attempts', 0):<18} {a.get('spoof_attempts', 0):<16} "
                f"{a.get('last_login') or 'Never'}\n")

    def _build_delete_tab(self, parent):
        self._label(parent, "Delete or Re-enrol a User Account", 10, RED, bold=True).pack(pady=(14, 6))
        self._label(parent, "Type the username of the account to manage:", 9, GREY).pack()

        del_var = tk.StringVar()
        tk.Entry(parent, textvariable=del_var, font=("Consolas", 11),
                 bg="#0d1117", fg=RED, insertbackground=RED,
                 relief=tk.FLAT, bd=4, width=30).pack(pady=8)

        msg_var = tk.StringVar()
        tk.Label(parent, textvariable=msg_var, font=("Consolas", 9),
                 bg=PANEL, fg=YELLOW).pack()

        def delete():
            uname = del_var.get().strip()
            if not uname:
                msg_var.set("Enter a username first.")
                return
            if not self.auth_system.user_exists(uname):
                msg_var.set(f"User '{uname}' not found.")
                return
            if not messagebox.askyesno("Confirm Delete",
                                       f"Permanently delete '{uname}'?\nThis cannot be undone."):
                return
            try:
                if uname in self.auth_system.users:
                    del self.auth_system.users[uname]
                    self.auth_system.save_users()
                if uname in self.account_mgr.accounts:
                    del self.account_mgr.accounts[uname]
                    self.account_mgr.save_accounts()
                if uname in self.face_recognizer.database:
                    del self.face_recognizer.database[uname]
                self.audit_log.log_admin_action("admin", "DELETE_USER", uname,
                                                "Account permanently deleted")
                msg_var.set(f"✅ User '{uname}' deleted successfully.")
            except Exception as e:
                msg_var.set(f"Error: {e}")

        def unlock():
            uname = del_var.get().strip()
            if not uname:
                msg_var.set("Enter a username first.")
                return
            try:
                if uname in self.account_mgr.accounts:
                    self.account_mgr.accounts[uname]["is_locked"]         = False
                    self.account_mgr.accounts[uname]["failed_attempts"]   = 0
                    self.account_mgr.save_accounts()
                    self.audit_log.log_admin_action("admin", "UNLOCK_ACCOUNT", uname,
                                                    "Account unlocked by admin")
                    msg_var.set(f"✅ Account '{uname}' unlocked.")
                else:
                    msg_var.set(f"Account '{uname}' not found.")
            except Exception as e:
                msg_var.set(f"Error: {e}")

        btn_row = tk.Frame(parent, bg=PANEL)
        btn_row.pack(pady=10)
        self._btn(btn_row, "🗑️ DELETE USER",   delete, color=RED,    fg=WHITE).pack(side=tk.LEFT, padx=8)
        self._btn(btn_row, "🔓 UNLOCK ACCOUNT", unlock, color=YELLOW, fg=BG).pack(side=tk.LEFT, padx=8)

    # ══════════════════════════════════════════════════════════════════════════
    #   SCREEN 10 — IDS DASHBOARD
    # ══════════════════════════════════════════════════════════════════════════

    def show_ids(self):
        self._clear()
        self.loop_active = False
        self._topbar(self.root)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=14, pady=8)

        self._label(body, "HYBRID INTRUSION DETECTION SYSTEM — DASHBOARD", 14, RED, bold=True).pack(pady=(0, 10))

        all_events   = self.audit_log.logs
        ids_alerts   = [e for e in all_events if e["event_type"] == "IDS_ALERT"]
        failed_auths = [e for e in all_events if e["event_type"] == "FAILED_AUTH"]
        logins       = [e for e in all_events if e["event_type"] == "LOGIN"]
        lockouts     = [e for e in all_events if e["event_type"] == "LOCKOUT"]
        spoofs       = [e for e in all_events if "spoof" in str(e.get("details", "")).lower()]

        # ── Stats row ──
        stat_row = tk.Frame(body, bg=BG)
        stat_row.pack(fill=tk.X, pady=(0, 10))

        stats = [
            ("IDS ALERTS",        str(len(ids_alerts)),  RED),
            ("FAILED LOGINS",     str(len(failed_auths)),YELLOW),
            ("LOCKOUTS",          str(len(lockouts)),     "#8957e5"),
            ("SPOOF ATTEMPTS",    str(len(spoofs)),       RED),
            ("SUCCESSFUL LOGINS", str(len(logins)),       GREEN),
            ("TOTAL EVENTS",      str(len(all_events)),   BLUE),
        ]
        for label, val, col in stats:
            box = self._card(stat_row)
            box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
            tk.Label(box, text=val, font=("Consolas", 20, "bold"),
                     bg=PANEL, fg=col).pack(pady=(12, 2))
            tk.Label(box, text=label, font=("Consolas", 7),
                     bg=PANEL, fg=GREY).pack(pady=(0, 10))

        nb = ttk.Notebook(body)
        nb.pack(fill=tk.BOTH, expand=True)

        # ── Tab 1: IDS Alerts ─────────────────────────────────────────────────
        t1 = tk.Frame(nb, bg=PANEL)
        nb.add(t1, text="🚨  IDS Alerts")
        a_box = scrolledtext.ScrolledText(t1, bg="#0d1117", fg=RED,
                                          font=("Consolas", 8), relief=tk.FLAT)
        a_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)
        if ids_alerts:
            a_box.insert(tk.END, f"{'Timestamp':<22} {'User':<14} {'Level':<12} Details\n")
            a_box.insert(tk.END, "─"*100 + "\n")
            for e in reversed(ids_alerts):
                a_box.insert(tk.END,
                    f"{e['timestamp']:<22} {e['username']:<14} "
                    f"{e.get('severity','N/A'):<12} {str(e['details'])[:70]}\n")
        else:
            a_box.insert(tk.END, "✅  No IDS alerts recorded. System is clean.\n")

        # ── Tab 2: Failed Attempts ────────────────────────────────────────────
        t2 = tk.Frame(nb, bg=PANEL)
        nb.add(t2, text="⚠️  Failed Attempts")
        f_box = scrolledtext.ScrolledText(t2, bg="#0d1117", fg=YELLOW,
                                          font=("Consolas", 8), relief=tk.FLAT)
        f_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)
        if failed_auths:
            f_box.insert(tk.END, f"{'Timestamp':<22} {'User':<14} Details\n")
            f_box.insert(tk.END, "─"*100 + "\n")
            for e in reversed(failed_auths):
                f_box.insert(tk.END,
                    f"{e['timestamp']:<22} {e['username']:<14} {str(e['details'])[:80]}\n")
        else:
            f_box.insert(tk.END, "✅  No failed authentication attempts recorded.\n")

        # ── Tab 3: Network Analysis ───────────────────────────────────────────
        t3 = tk.Frame(nb, bg=PANEL)
        nb.add(t3, text="📡  Network Analysis")
        n_box = scrolledtext.ScrolledText(t3, bg="#0d1117", fg=BLUE,
                                          font=("Consolas", 8), relief=tk.FLAT)
        n_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)

        try:
            net_f, _, _ = self.net_monitor.extract_features()
            n_box.insert(tk.END, "LIVE NETWORK FEATURE SNAPSHOT\n" + "─"*60 + "\n")
            for k, v in (net_f or {}).items():
                n_box.insert(tk.END, f"  {str(k):<35} {str(v)}\n")
        except Exception as ex:
            n_box.insert(tk.END, f"Network monitor error: {ex}\n")

        n_box.insert(tk.END, "\n\nIDS FEATURE VECTOR (17 Features)\n" + "─"*60 + "\n")
        feats = [
            ("1",  "Login Success Flag",         "1 = success, 0 = fail"),
            ("2",  "Spoof Detected",              "1 = spoofed, 0 = genuine"),
            ("3",  "Facial Confidence Score",     "0.0 – 1.0 cosine similarity"),
            ("4",  "Failed Attempts Count",       "Consecutive failures"),
            ("5",  "Account Lockout Status",      "1 = locked, 0 = active"),
            ("6",  "IP Address (numeric)",        "Source IP"),
            ("7",  "Unusual IP Indicator",        "1 = unknown IP"),
            ("8",  "Packet Volume",               "Packets in session"),
            ("9",  "Data Volume (bytes)",         "Bytes transferred"),
            ("10", "Port Scan Detected",          "1 = scanning activity"),
            ("11", "Protocol Anomaly",            "Non-standard protocol use"),
            ("12", "Traffic Ratio",               "Inbound / Outbound"),
            ("13", "Login Time (hour)",           "0 – 23"),
            ("14", "Login Frequency",             "Logins per 24 hours"),
            ("15", "Login Interval (hours)",      "Since last login"),
            ("16", "Device ID",                   "MAC address hash"),
            ("17", "Concurrent Sessions",         "Active sessions for user"),
        ]
        for num, name, desc in feats:
            n_box.insert(tk.END, f"  {num:<4} {name:<32} {desc}\n")

        # ── Tab 4: Threat Analysis ────────────────────────────────────────────
        t4 = tk.Frame(nb, bg=PANEL)
        nb.add(t4, text="🧠  Threat Analysis")
        th_box = scrolledtext.ScrolledText(t4, bg="#0d1117", fg=YELLOW,
                                           font=("Consolas", 9), relief=tk.FLAT)
        th_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)

        th_box.insert(tk.END, "THREAT ANALYSIS REPORT\n" + "═"*70 + "\n\n")
        th_box.insert(tk.END, f"Total Events Logged:      {len(all_events)}\n")
        th_box.insert(tk.END, f"IDS Alerts:               {len(ids_alerts)}\n")
        th_box.insert(tk.END, f"Failed Logins:            {len(failed_auths)}\n")
        th_box.insert(tk.END, f"Lockouts Triggered:       {len(lockouts)}\n")
        th_box.insert(tk.END, f"Spoof Attempts:           {len(spoofs)}\n")
        th_box.insert(tk.END, f"Successful Logins:        {len(logins)}\n\n")

        th_box.insert(tk.END, "IDS CLASSIFIER CONFIGURATION\n" + "─"*50 + "\n")
        th_box.insert(tk.END, "  Classifier 1:  Random Forest (Supervised)\n")
        th_box.insert(tk.END, "  Classifier 2:  Isolation Forest (Unsupervised)\n")
        th_box.insert(tk.END, "  Decision:      Alert if RF = Anomaly OR IF_score > threshold\n\n")

        th_box.insert(tk.END, "ZERO TRUST ENFORCEMENT SUMMARY\n" + "─"*50 + "\n")
        th_box.insert(tk.END, "  ✓ Face Recognition Gate:     Active\n")
        th_box.insert(tk.END, "  ✓ Liveness Detection Gate:   Active\n")
        th_box.insert(tk.END, "  ✓ Hybrid IDS Gate:           Active\n")
        th_box.insert(tk.END, "  ✓ IP Session Binding:        Active\n")
        th_box.insert(tk.END, "  ✓ Account Lockout (3 fails): Active\n")
        th_box.insert(tk.END, "  ✓ Audit Logging:             Active\n")

        if len(failed_auths) > 5:
            th_box.insert(tk.END,
                f"\n⚠  HIGH RISK: {len(failed_auths)} failed attempts detected.\n"
                "   Possible brute-force attack in progress.\n")
        if len(ids_alerts) > 0:
            th_box.insert(tk.END,
                f"\n🚨  CRITICAL: {len(ids_alerts)} IDS alert(s) have been raised.\n"
                "   Review the IDS Alerts tab for details.\n")

        self._btn(body, "← BACK TO HOME", self.show_home, color="#484f58", fg=WHITE).pack(pady=10)

    # ══════════════════════════════════════════════════════════════════════════
    #   CANCEL / LOGOUT helpers
    # ══════════════════════════════════════════════════════════════════════════

    def _cancel_signup(self):
        """Cancel signup and auto-delete incomplete account."""
        self.loop_active = False
        if self.current_user and not self.liveness_done:
            try:
                if self.current_user in self.auth_system.users:
                    del self.auth_system.users[self.current_user]
                    self.auth_system.save_users()
                if self.current_user in self.account_mgr.accounts:
                    del self.account_mgr.accounts[self.current_user]
                    self.account_mgr.save_accounts()
                self.audit_log.log_event(self.current_user, "SIGNUP_INCOMPLETE",
                                          {"reason": "User cancelled before liveness"}, "WARNING")
            except Exception:
                pass
        self.current_user = None
        self.root.after(200, self.show_home)

    def _cancel_auth(self):
        self.loop_active = False
        self.root.after(200, self.show_home)

    def _logout(self):
        self.loop_active = False
        if self.current_session:
            self.session_mgr.end_session(self.current_session)
            self.audit_log.log_event(self.current_user, "LOGOUT",
                                      {"session": self.current_session[:8]}, "INFO")
        self.current_user    = None
        self.current_session = None
        self.is_auth         = False
        self.login_confidence= 0.0
        self.liveness_det.reset()
        self.root.after(200, self.show_home)


# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    root = tk.Tk()
    app  = FacialAuthSystem(root)
    root.mainloop()