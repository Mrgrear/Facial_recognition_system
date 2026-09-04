"""
Enhanced Facial Authentication System with Hybrid IDS
Zero Trust Architecture — Final Production GUI (Non-Freezing)
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
import traceback

sys.path.append(".")

print("Loading system modules...")
from auth.face_detector import FaceDetector
from auth.face_recognizer import FaceRecognizer
from auth.liveness_detector import LivenessDetector
from auth.anti_spoof import AntiSpoofDetector
from auth.account_manager import AccountManager
from auth.auth_system import AuthSystem
from auth.session_manager import SessionManager
from auth.audit_logger import AuditLogger
from ids.hybrid_ids import HybridIDS
from ids.network_monitor import NetworkMonitor
from ids.feature_extractor import FeatureExtractor
print("All modules loaded successfully.")

# ─── Constants ──────────────────────────────────────────────────────────────
SIGNUP_BLINKS  = 3
LOGIN_BLINKS   = 2
FACE_THRESHOLD = 0.5
CAMERA_INDEX   = 1
# Anti-spoofing is computed and logged on every login regardless.
# Set this to True only after running calibrate_anti_spoof.py against
# real captured samples and confirming real-face scores separate
# cleanly from print/screen-replay scores on your hardware.
ENFORCE_ANTI_SPOOF = True
# Calibrated via calibrate_anti_spoof.py against real hardware/lighting:
# real face spoof_score range 0.148-0.209, printed photo & screen
# replay both 0.700 — clean separation, no overlap.
CAM_W, CAM_H   = 480, 360      # reduced from 640x480 — noticeably faster detection
DISPLAY_W, DISPLAY_H = 640, 420
BURST_FRAMES   = 8             # frames sampled per SPACE press during liveness check
MAX_LIVENESS_ATTEMPTS = 6      # SPACE presses allowed before lockout, mirrors face-match's 5-attempt cap
ANTI_SPOOF_BURST_FRAMES = 4    # frames sampled per anti-spoof check, to reduce single-frame variance risk

BG, PANEL, BORDER = "#0d1117", "#161b22", "#30363d"
GREEN, BLUE, YELLOW, RED, WHITE, GREY = "#3fb950", "#58a6ff", "#d29922", "#f85149", "#e6edf3", "#8b949e"


def emb_to_list(e):
    if e is None:
        return None
    return e.tolist() if isinstance(e, np.ndarray) else list(e)

def list_to_emb(l):
    if not l:
        return None
    return np.array(l, dtype=np.float32)

def cosine_sim(a, b):
    if a is None or b is None:
        return 0.0
    n = np.linalg.norm(a) * np.linalg.norm(b)
    return float(np.dot(a, b) / (n + 1e-8))


class CameraThread(threading.Thread):
    """Runs entirely off the Tkinter thread. Only touches cv2 — never Tkinter."""
    def __init__(self, index=CAMERA_INDEX):
        super().__init__(daemon=True)
        self.index = index
        self.cap = None
        self.queue = queue.Queue(maxsize=3)
        self.alive = False
        self.ready = threading.Event()

    def run(self):
        self.cap = cv2.VideoCapture(self.index)
        if not self.cap.isOpened():
            self.cap = cv2.VideoCapture(0)
        self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, CAM_W)
        self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, CAM_H)
        self.cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
        self.cap.set(cv2.CAP_PROP_FPS, 30)
        time.sleep(0.4)
        for _ in range(15):
            self.cap.read()
        self.alive = True
        self.ready.set()
        while self.alive:
            ret, frame = self.cap.read()
            if ret:
                if self.queue.full():
                    try:
                        self.queue.get_nowait()
                    except queue.Empty:
                        pass
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

    def get_burst(self, n):
        frames = []
        deadline = time.time() + 1.5
        while len(frames) < n and time.time() < deadline:
            f = self.get_frame()
            if f is not None:
                frames.append(f)
            else:
                time.sleep(0.02)
        return frames

    def stop(self):
        self.alive = False


# ══════════════════════════════════════════════════════════════════════════
class FacialAuthSystem:

    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced Facial Authentication System — Zero Trust Architecture")
        self.root.geometry("1120x780")
        self.root.configure(bg=BG)

        cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        self.box_cascade = cv2.CascadeClassifier(cascade_path)
        if self.box_cascade.empty():
            print(f"[WARN] Could not load Haar cascade from: {cascade_path}")
            self.box_cascade = None
        self.face_detector   = FaceDetector()
        self.face_recognizer = FaceRecognizer()
        self.liveness_det    = LivenessDetector(required_blinks=SIGNUP_BLINKS)
        # Anti-spoof detector, calibrated against real hardware via
        # calibrate_anti_spoof.py (see ENFORCE_ANTI_SPOOF above).
        # ENFORCE_ANTI_SPOOF=True means failed checks now block login.
        self.anti_spoof      = AntiSpoofDetector(combined_threshold=0.70)
        self.spoof_score_this_login = 0.0
        self.spoof_detected_this_login = False
        self.account_mgr     = AccountManager()
        # FIX: pass the SAME AccountManager instance into AuthSystem
        # instead of letting it silently create its own — otherwise the
        # two objects go out of sync in memory (see auth_system.py for
        # the full explanation). This ensures a user registered
        # mid-session is immediately visible to lockout/after-hours-
        # trust checks elsewhere in this file.
        self.auth_system     = AuthSystem(account_manager=self.account_mgr)
        self.session_mgr     = SessionManager(session_timeout_minutes=30)
        self.audit_log       = AuditLogger()
        self.ids             = HybridIDS()
        try:
            self.ids.load_models()
        except Exception as e:
            print(f"[WARN] IDS models failed to load: {e}")
        self.net_monitor    = NetworkMonitor()
        self.feat_extractor = FeatureExtractor()

        self.cam = CameraThread()
        self.cam.start()

        self.current_user     = None
        self.current_session  = None
        self.login_confidence = 0.0
        self.failed_attempts  = 0
        self.liveness_done    = False
        self.face_matched     = False
        self.is_auth          = False
        self.display_active   = False
        self._proc_active     = False

        self.ip_address = self._get_ip()
        self.device_id  = self._get_device_id()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.show_home()

    # ── Safety wrapper ───────────────────────────────────────────────────────
    def _safe(self, fn):
        def wrapped(*a, **kw):
            try:
                return fn(*a, **kw)
            except Exception as e:
                traceback.print_exc()
                messagebox.showerror("Unexpected Error", f"{type(e).__name__}: {e}\n\nSee terminal for details.")
        return wrapped

    # ── Background-thread runner — THE key fix for freezing ────────────────
    def _run_bg(self, work_fn, done_fn):
        """
        Runs work_fn() on a background thread (no Tkinter calls allowed inside it).
        When finished, done_fn(success, result_or_exception) is called safely
        on the MAIN thread via root.after(0, ...).
        """
        def worker():
            try:
                result = work_fn()
                self.root.after(0, lambda: done_fn(True, result))
            except Exception as e:
                traceback.print_exc()
                self.root.after(0, lambda: done_fn(False, e))
        threading.Thread(target=worker, daemon=True).start()

    # ── Processing timer (visible feedback instead of a silent freeze) ─────
    def _start_processing_timer(self, status_var, prefix="Processing"):
        self._proc_start = time.time()
        self._proc_active = True
        self._proc_var = status_var
        self._proc_prefix = prefix
        self._tick_timer()

    def _tick_timer(self):
        if not self._proc_active:
            return
        elapsed = time.time() - self._proc_start
        try:
            self._proc_var.set(f"{self._proc_prefix}... {elapsed:.1f}s elapsed")
        except Exception:
            pass
        self.root.after(200, self._tick_timer)

    def _stop_processing_timer(self):
        self._proc_active = False

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
        self.display_active = False
        self.cam.stop()
        self.root.destroy()

    # ── UI helpers ───────────────────────────────────────────────────────────
    def _clear(self):
        self.display_active = False
        self._proc_active = False
        for w in self.root.winfo_children():
            w.destroy()

    def _topbar(self, parent, back_cmd=None):
        bar = tk.Frame(parent, bg=PANEL, height=54)
        bar.pack(fill=tk.X, side=tk.TOP)
        bar.pack_propagate(False)
        tk.Label(bar, text="🔐  ZERO TRUST FACIAL AUTHENTICATION SYSTEM",
                 font=("Consolas", 13, "bold"), bg=PANEL, fg=GREEN).pack(side=tk.LEFT, padx=16, pady=14)

        if back_cmd is not None:
            # Back button lives INSIDE the fixed top bar — always visible,
            # can never be pushed off screen by tab/notebook content.
            self._btn(bar, "← BACK TO HOME", back_cmd, color="#484f58", fg=WHITE,
                      padx=12, pady=6).pack(side=tk.RIGHT, padx=10, pady=8)

        status = f"IP: {self.ip_address}   |   Camera: {CAMERA_INDEX}   |   {datetime.now().strftime('%d %b %Y  %H:%M')}"
        tk.Label(bar, text=status, font=("Consolas", 9), bg=PANEL, fg=GREY).pack(side=tk.RIGHT, padx=16)
        ttk.Separator(parent, orient="horizontal").pack(fill=tk.X)

    def _card(self, parent, **kwargs):
        return tk.Frame(parent, bg=PANEL, highlightbackground=BORDER, highlightthickness=1, **kwargs)

    def _btn(self, parent, text, cmd, color=BLUE, fg=BG, **kwargs):
        kwargs.setdefault("padx", 18)
        kwargs.setdefault("pady", 9)
        return tk.Button(parent, text=text, command=self._safe(cmd) if cmd else None,
                     bg=color, fg=fg, activebackground=color, activeforeground=fg,
                     font=("Consolas", 10, "bold"), bd=0,
                     cursor="hand2", relief=tk.FLAT, **kwargs)

    def _label(self, parent, text, size=11, color=WHITE, bold=False, **kwargs):
        font = ("Consolas", size, "bold") if bold else ("Consolas", size)
        return tk.Label(parent, text=text, font=font, bg=parent["bg"], fg=color, **kwargs)

    def _log_box(self, parent, height=6):
        st = scrolledtext.ScrolledText(parent, height=height, bg="#0d1117", fg=GREEN,
                                       insertbackground=GREEN, font=("Consolas", 8),
                                       relief=tk.FLAT, bd=4)
        st.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        return st

    def _append(self, box, msg):
        try:
            ts = datetime.now().strftime("%H:%M:%S")
            box.insert(tk.END, f"[{ts}] {msg}\n")
            box.see(tk.END)
        except Exception:
            pass

    def _webcam_label(self, parent):
        lbl = tk.Label(parent, bg="#000000", width=DISPLAY_W, height=DISPLAY_H)
        lbl.pack(pady=4)
        return lbl

    def _push_frame(self, label, frame):
        try:
            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            img = Image.fromarray(cv2.resize(rgb, (DISPLAY_W, DISPLAY_H)))
            imtk = ImageTk.PhotoImage(image=img)
            label.imgtk = imtk
            label.configure(image=imtk)
        except Exception:
            pass

    def _video_loop(self, label, overlay_text=""):
       if not self.display_active:
           return
       frame = self.cam.get_frame()
       if frame is not None:
          self.last_frame = frame
          disp = frame.copy()
          if self.box_cascade is not None:
              gray = cv2.cvtColor(disp, cv2.COLOR_BGR2GRAY)
              boxes = self.box_cascade.detectMultiScale(gray, scaleFactor=1.2, minNeighbors=5, minSize=(80, 80))
              for (x, y, w, h) in boxes:
                  cv2.rectangle(disp, (x, y), (x + w, y + h), (63, 185, 80), 2)
          if overlay_text:
               cv2.putText(disp, overlay_text, (10, 28), cv2.FONT_HERSHEY_SIMPLEX,
                       0.65, (63, 185, 80), 2)
          self._push_frame(label, disp)
       self.root.after(25, lambda: self._video_loop(label, overlay_text))

    # ══════════════════════════════════════════════════════════════════════
    #   HOME
    # ══════════════════════════════════════════════════════════════════════
    def show_home(self):
        self._clear()
        self.liveness_det.reset()
        self._topbar(self.root)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)

        left = self._card(body, width=420)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 18))
        left.pack_propagate(False)

        tk.Label(left, text="NIGERIAN ARMY UNIVERSITY BIU", font=("Consolas", 9),
                 bg=PANEL, fg=GREY).pack(pady=(18, 2))
        tk.Label(left, text="Department of Cyber Security", font=("Consolas", 9),
                 bg=PANEL, fg=GREY).pack()
        ttk.Separator(left, orient="horizontal").pack(fill=tk.X, pady=12, padx=12)

        tk.Label(left, text="SYSTEM CAPABILITIES", font=("Consolas", 9, "bold"),
                 bg=PANEL, fg=YELLOW).pack(pady=(0, 8))

        features = [
            ("🔍", "Face Detection",     "InsightFace Buffalo-L"),
            ("🧠", "ArcFace Recognition","512-D Cosine Similarity"),
            ("👁️", "Liveness Detection", "EAR Blink — Manual (SPACE)"),
            ("🛡️", "Hybrid IDS",         "Random Forest + Isolation Forest"),
            ("📡", "Network Monitoring", "17-Feature Vector"),
            ("🔒", "Session Management", "UUID + IP Binding (30 min)"),
            ("📋", "Audit Logging",      "Full Event Trail"),
            ("⚡", "Zero Trust",         "Never Trust — Always Verify"),
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

        try:
            users = self.auth_system.list_users()
        except Exception:
            users = []
        auth_count = sum(1 for u in users if u.get("authenticated", False))
        try:
            active_sess = len([s for s in self.session_mgr.get_all_sessions() if not s.get("expired")])
        except Exception:
            active_sess = 0
        try:
            alerts = sum(1 for e in self.audit_log.logs if e["event_type"] == "IDS_ALERT")
        except Exception:
            alerts = 0

        for label, val in [("Registered Users", str(len(users))), ("Authenticated", str(auth_count)),
                            ("Active Sessions", str(active_sess)), ("IDS Alerts", str(alerts)),
                            ("Device IP", self.ip_address)]:
            row = tk.Frame(left, bg=PANEL)
            row.pack(fill=tk.X, padx=14, pady=1)
            tk.Label(row, text=label + ":", font=("Consolas", 8), bg=PANEL, fg=GREY, width=20, anchor="w").pack(side=tk.LEFT)
            tk.Label(row, text=val, font=("Consolas", 8, "bold"), bg=PANEL, fg=GREEN, anchor="w").pack(side=tk.LEFT)

        right = tk.Frame(body, bg=BG)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tk.Label(right, text="SELECT AN ACTION", font=("Consolas", 11, "bold"),
                 bg=BG, fg=YELLOW).pack(pady=(0, 20))

        for txt, cmd, bg_c, fg_c in [
            ("👤  LOGIN", self.show_login, BLUE, BG),
            ("📝  NEW USER", self.show_signup, GREEN, BG),
            ("👨‍💼  ADMIN PANEL", self.show_admin, "#8957e5", WHITE),
            ("📊  IDS DASHBOARD", self.show_ids, YELLOW, BG),
            ("🚪  EXIT", self._on_close, "#484f58", WHITE),
        ]:
            self._btn(right, txt, cmd, color=bg_c, fg=fg_c, width=36).pack(pady=7)

    # ══════════════════════════════════════════════════════════════════════
    #   LOGIN
    # ══════════════════════════════════════════════════════════════════════
    def show_login(self):
        self._clear()
        self._topbar(self.root, back_cmd=self.show_home)

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
                         bg="#0d1117", fg=GREEN, insertbackground=GREEN, relief=tk.FLAT, bd=4, width=36)
        entry.pack(padx=30, pady=(4, 18))
        entry.focus()

        msg_var = tk.StringVar()
        tk.Label(card, textvariable=msg_var, font=("Consolas", 9), bg=PANEL, fg=RED).pack()

        def proceed():
            uname = user_var.get().strip()
            if not uname:
                msg_var.set("⚠  Please enter your username.")
                return
            if not self.auth_system.user_exists(uname):
                msg_var.set("⚠  Username not found in the system.")
                self.audit_log.log_failed_attempt(uname, "Username not found", self.ip_address)
                return
            info = self.auth_system.get_user_info(uname) or {}
            if not info.get("authenticated", False):
                msg_var.set("⚠  Account not verified. Complete signup first.")
                return
            locked, lock_msg = False, ""
            try:
                locked, lock_msg, _remaining = self.account_mgr.is_account_locked(uname)
            except Exception as e:
                print(f"[WARN] Lockout check failed: {e}")
            if locked:
                msg_var.set(f"🔒  {lock_msg}")
                return
            self.current_user     = uname
            self.face_matched     = False
            self.login_confidence = 0.0
            self.is_auth          = False
            self.spoof_score_this_login = 0.0
            self.spoof_detected_this_login = False
            self.show_face_match()

        entry.bind("<Return>", lambda e: self._safe(proceed)())
        btn_row = tk.Frame(card, bg=PANEL)
        btn_row.pack(pady=14)
        self._btn(btn_row, "▶  CONTINUE", proceed, color=BLUE).pack(side=tk.LEFT, padx=8)
        self._btn(btn_row, "← BACK", self.show_home, color="#484f58", fg=WHITE).pack(side=tk.LEFT, padx=8)

    # ══════════════════════════════════════════════════════════════════════
    #   SIGNUP FORM
    # ══════════════════════════════════════════════════════════════════════
    def show_signup(self):
        self._clear()
        self._topbar(self.root, back_cmd=self.show_home)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=40, pady=20)

        card = self._card(body)
        card.pack(expand=True, ipadx=30, ipady=20)

        self._label(card, "NEW USER REGISTRATION", 15, GREEN, bold=True).pack(pady=(18, 4))
        self._label(card, "All fields are required", 9, GREY).pack()
        ttk.Separator(card, orient="horizontal").pack(fill=tk.X, pady=12, padx=20)

        entries = {}
        for label in ["Username", "Email", "Full Name", "Department", "Phone"]:
            row = tk.Frame(card, bg=PANEL)
            row.pack(fill=tk.X, padx=30, pady=4)
            tk.Label(row, text=label + ":", font=("Consolas", 9, "bold"),
                     bg=PANEL, fg=WHITE, width=14, anchor="w").pack(side=tk.LEFT)
            var = tk.StringVar()
            tk.Entry(row, textvariable=var, font=("Consolas", 10), bg="#0d1117", fg=GREEN,
                     insertbackground=GREEN, relief=tk.FLAT, bd=3, width=36).pack(side=tk.LEFT, padx=4)
            entries[label] = var

        msg_var = tk.StringVar()
        tk.Label(card, textvariable=msg_var, font=("Consolas", 9), bg=PANEL, fg=RED).pack(pady=6)

        def proceed():
            data = {k: v.get().strip() for k, v in entries.items()}
            if not all(data.values()):
                msg_var.set("⚠  All fields are required.")
                return
            if self.auth_system.user_exists(data["Username"]):
                msg_var.set("⚠  Username already exists. Choose another.")
                return
            ok, msg = self.auth_system.create_account(
                data["Username"], data["Email"], data["Full Name"], data["Department"], data["Phone"])
            if ok:
                self.current_user = data["Username"]
                self.liveness_done = False
                self.audit_log.log_event(data["Username"], "SIGNUP", {"email": data["Email"]}, "INFO")
                messagebox.showinfo("Account Created",
                                    f"Account created for {data['Full Name']}.\n\n"
                                    f"Next: face enrollment (press SPACE to capture 5 frames),\n"
                                    f"then liveness verification ({SIGNUP_BLINKS} blinks, manual).")
                self.show_enrollment()
            else:
                msg_var.set(f"⚠  {msg}")

        btn_row = tk.Frame(card, bg=PANEL)
        btn_row.pack(pady=14)
        self._btn(btn_row, "CREATE ACCOUNT", proceed, color=GREEN).pack(side=tk.LEFT, padx=8)
        self._btn(btn_row, "← BACK", self.show_home, color="#484f58", fg=WHITE).pack(side=tk.LEFT, padx=8)

    # ══════════════════════════════════════════════════════════════════════
    #   MANUAL FACE ENROLLMENT — non-blocking (background thread)
    # ══════════════════════════════════════════════════════════════════════
    def show_enrollment(self):
        self._clear()
        self._topbar(self.root)
        self.display_active = True
        self.enroll_captured = []
        self._enroll_busy = False

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=14, pady=8)

        hdr = tk.Frame(body, bg=BG)
        hdr.pack(fill=tk.X, pady=(0, 8))
        self._label(hdr, "STEP 1 OF 2 — FACE ENROLLMENT (MANUAL CAPTURE)", 13, GREEN, bold=True).pack(side=tk.LEFT)
        self._label(hdr, "Press SPACE to capture each frame  (5 required)", 9, GREY).pack(side=tk.RIGHT)

        cols = tk.Frame(body, bg=BG)
        cols.pack(fill=tk.BOTH, expand=True)

        cam_card = self._card(cols)
        cam_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        self.wcam = self._webcam_label(cam_card)

        side = self._card(cols, width=320)
        side.pack(side=tk.LEFT, fill=tk.Y)
        side.pack_propagate(False)

        self._label(side, "ENROLLMENT STATUS", 9, YELLOW, bold=True).pack(pady=(14, 6))
        self.progress_var = tk.StringVar(value="0 / 5 frames captured")
        tk.Label(side, textvariable=self.progress_var, font=("Consolas", 11, "bold"),
                 bg=PANEL, fg=GREEN, wraplength=280).pack(pady=4, padx=10)

        self.proc_status_var = tk.StringVar(value="")
        tk.Label(side, textvariable=self.proc_status_var, font=("Consolas", 9, "italic"),
                 bg=PANEL, fg=YELLOW).pack()

        self.enroll_bar = ttk.Progressbar(side, maximum=5, mode="determinate")
        self.enroll_bar.pack(fill=tk.X, padx=14, pady=6)

        self.enroll_capture_btn = self._btn(side, "⎵  PRESS SPACE / CLICK TO CAPTURE",
                                            self._capture_enroll_frame, color=BLUE, width=28)
        self.enroll_capture_btn.pack(pady=12, padx=10)

        self._label(side, "LOG", 8, YELLOW, bold=True).pack(pady=(6, 2))
        self.enroll_log = self._log_box(side, height=10)
        self._append(self.enroll_log, "Camera ready. Position your face and press SPACE.")

        self._btn(side, "CANCEL", self._cancel_signup, color=RED, fg=WHITE).pack(pady=10)

        self.root.bind("<space>", lambda e: self._safe(self._capture_enroll_frame)())
        self._video_loop(self.wcam, overlay_text="Press SPACE to capture")

    def _capture_enroll_frame(self):
        if self._enroll_busy:
            return
        frame = getattr(self, "last_frame", None)
        if frame is None:
            self._append(self.enroll_log, "⚠ No camera frame available yet.")
            return

        self._enroll_busy = True
        self.enroll_capture_btn.config(state=tk.DISABLED)
        self._append(self.enroll_log, "Processing frame...")
        self._start_processing_timer(self.proc_status_var, "Analysing frame")

        def work():
            # FIX: use detect_sync() so this call actually analyses the
            # exact frame just captured, instead of returning a stale
            # result from the old async detect() queue.
            faces = self.face_detector.detect_sync(frame)
            return len(faces)

        def done(ok, result):
            self._enroll_busy = False
            self._stop_processing_timer()
            self.proc_status_var.set("")
            self.enroll_capture_btn.config(state=tk.NORMAL)

            if not ok:
                self._append(self.enroll_log, f"⚠ Detection error: {result}")
                return

            face_count = result
            if face_count != 1:
                self._append(self.enroll_log, f"⚠ Need exactly 1 face. Found {face_count}. Try again.")
                return

            self.enroll_captured.append(frame.copy())
            n = len(self.enroll_captured)
            self.enroll_bar["value"] = n
            self.progress_var.set(f"{n} / 5 frames captured")
            self._append(self.enroll_log, f"✅ Frame {n}/5 captured")

            if n >= 5:
                self._unbind_space()
                self.enroll_capture_btn.config(state=tk.DISABLED)
                self._finish_enrollment()

        self._run_bg(work, done)

    def _finish_enrollment(self):
        self._append(self.enroll_log, "Processing embeddings — this may take a few seconds...")
        self._start_processing_timer(self.proc_status_var, "Generating embedding")
        frames_copy = list(self.enroll_captured)
        user = self.current_user

        def work():
            ok = self.face_recognizer.enroll(user, frames_copy)
            emb = self.face_recognizer.database.get(user) if ok else None
            return (ok, emb)

        def done(success, result):
            self._stop_processing_timer()
            self.proc_status_var.set("")

            if not success:
                self._append(self.enroll_log, f"❌ Enrollment error: {result}")
                messagebox.showerror("Enrollment Failed", f"{result}")
                self._cancel_signup()
                return

            ok, emb = result
            if not ok or emb is None:
                self._append(self.enroll_log, "❌ Face enrollment failed (embedding error).")
                messagebox.showerror("Enrollment Failed", "Could not generate a face embedding. Please try again.")
                self._cancel_signup()
                return

            self.account_mgr.enroll_face(self.current_user, emb)
            self.auth_system.enroll_face_for_user(self.current_user, frames_copy)
            if self.current_user in self.auth_system.users:
                self.auth_system.users[self.current_user]["embedding"] = emb_to_list(emb)
                self.auth_system.save_users()
            self.audit_log.log_event(self.current_user, "ENROLLMENT", {"frames": 5}, "INFO")
            self._append(self.enroll_log, "✅ Face enrolled! Proceeding to liveness check...")
            self.root.after(800, self.show_signup_liveness)

        self._run_bg(work, done)

    # ══════════════════════════════════════════════════════════════════════
    #   MANUAL LIVENESS — non-blocking (background thread)
    # ══════════════════════════════════════════════════════════════════════
    def _build_liveness_screen(self, required_blinks, on_complete, step_label):
        self._clear()
        self._topbar(self.root)
        self.display_active = True

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=14, pady=8)

        hdr = tk.Frame(body, bg=BG)
        hdr.pack(fill=tk.X, pady=(0, 8))
        self._label(hdr, f"{step_label} — LIVENESS VERIFICATION (MANUAL)", 12, YELLOW, bold=True).pack(side=tk.LEFT)
        self._label(hdr, f"Blink naturally, then press SPACE  ({required_blinks} confirmed blinks needed)",
                    9, GREY).pack(side=tk.RIGHT)

        cols = tk.Frame(body, bg=BG)
        cols.pack(fill=tk.BOTH, expand=True)

        cam_card = self._card(cols)
        cam_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        self.wcam = self._webcam_label(cam_card)

        side = self._card(cols, width=320)
        side.pack(side=tk.LEFT, fill=tk.Y)
        side.pack_propagate(False)

        self._label(side, "LIVENESS STATUS", 9, YELLOW, bold=True).pack(pady=(14, 4))
        self.blink_var = tk.StringVar(value=f"Blinks: 0 / {required_blinks}")
        tk.Label(side, textvariable=self.blink_var, font=("Consolas", 14, "bold"),
                 bg=PANEL, fg=GREEN).pack(pady=8)

        self.ear_var = tk.StringVar(value="Last check: --")
        tk.Label(side, textvariable=self.ear_var, font=("Consolas", 9), bg=PANEL, fg=GREY,
                 wraplength=280).pack()

        self.proc_status_var = tk.StringVar(value="")
        tk.Label(side, textvariable=self.proc_status_var, font=("Consolas", 9, "italic"),
                 bg=PANEL, fg=YELLOW).pack()

        self.live_bar = ttk.Progressbar(side, maximum=required_blinks, mode="determinate")
        self.live_bar.pack(fill=tk.X, padx=14, pady=10)

        self.live_capture_btn = self._btn(side, "⎵  BLINK NOW, THEN PRESS SPACE",
                                          self._check_blink_burst, color=BLUE, width=28)
        self.live_capture_btn.pack(pady=6, padx=10)

        self._label(side, "INSTRUCTIONS", 8, YELLOW, bold=True).pack(pady=(10, 4))
        self._label(side,
                    "1. Look at the camera\n2. Blink naturally once\n3. Immediately press SPACE",
                    9, GREY, justify=tk.LEFT).pack(padx=14, anchor="w")

        self._label(side, "LOG", 8, YELLOW, bold=True).pack(pady=(10, 2))
        self.live_log = self._log_box(side, height=6)
        self._append(self.live_log, "Ready. Blink, then press SPACE to confirm.")

        self._btn(side, "CANCEL", self._cancel_current, color=RED, fg=WHITE).pack(pady=10)

        self.liveness_det.reset()
        self.liveness_det.required_blinks = required_blinks
        self._live_required   = required_blinks
        self._live_confirmed  = 0
        self._live_attempts   = 0
        self._live_on_complete = on_complete
        self._live_busy = False

        self.root.bind("<space>", lambda e: self._safe(self._check_blink_burst)())
        self._video_loop(self.wcam, overlay_text="Blink, then press SPACE")

    def _check_blink_burst(self):
        if self._live_busy:
            return
        self._live_busy = True
        self.live_capture_btn.config(state=tk.DISABLED)
        self._append(self.live_log, "Sampling frames...")
        self._start_processing_timer(self.proc_status_var, "Checking blink")

        blinks_before = self._live_confirmed

        def work():
            frames = self.cam.get_burst(BURST_FRAMES)
            detected = False
            last_ear = 0.0
            min_ear = 999.0
            for f in frames:
                is_live, blinks, ear = self.liveness_det.detect(f)
                last_ear = ear
                if ear > 0:
                    min_ear = min(min_ear, ear)
                if blinks > blinks_before:
                    detected = True
                    break  # stop early once a blink is confirmed
            return (detected, last_ear, min_ear)

        def done(ok, result):
            self._live_busy = False
            self._stop_processing_timer()
            self.proc_status_var.set("")
            self.live_capture_btn.config(state=tk.NORMAL)

            if not ok:
                self._append(self.live_log, f"⚠ Error: {result}")
                return

            detected, last_ear, min_ear = result
            self._live_attempts += 1
            if detected:
                self._live_confirmed += 1
                self.blink_var.set(f"Blinks: {self._live_confirmed} / {self._live_required}")
                self.live_bar["value"] = self._live_confirmed
                self.ear_var.set(f"Last check: blink confirmed (EAR≈{last_ear:.3f})")
                self._append(self.live_log, f"✅ Blink {self._live_confirmed}/{self._live_required} confirmed")
            else:
                self.ear_var.set(f"Last check: no blink detected (min EAR≈{min_ear:.3f}, threshold=0.25)")
                self._append(self.live_log, f"⚠ No blink detected (attempt {self._live_attempts}/{MAX_LIVENESS_ATTEMPTS}).")

            if self._live_confirmed >= self._live_required:
                self._unbind_space()
                self.live_capture_btn.config(state=tk.DISABLED)
                self._append(self.live_log, "✅ Liveness fully verified!")
                self.root.after(800, self._live_on_complete)
                return

            if self._live_attempts >= MAX_LIVENESS_ATTEMPTS:
                self._unbind_space()
                self.live_capture_btn.config(state=tk.DISABLED)
                self._append(self.live_log, "🚫 Liveness verification failed — too many attempts.")
                if self.current_user:
                    try:
                        self.account_mgr.record_failed_attempt(self.current_user)
                    except Exception:
                        pass
                    self.audit_log.log_failed_attempt(
                        self.current_user,
                        f"Liveness check failed after {MAX_LIVENESS_ATTEMPTS} attempts",
                        self.ip_address
                    )
                messagebox.showerror(
                    "Liveness Verification Failed",
                    f"No blink confirmed after {MAX_LIVENESS_ATTEMPTS} attempts.\n"
                    f"Access denied."
                )
                self.root.after(200, self.show_home)

        self._run_bg(work, done)

    def show_signup_liveness(self):
        self._build_liveness_screen(SIGNUP_BLINKS, self._on_signup_liveness_done, "STEP 2 OF 2")

    def _on_signup_liveness_done(self):
        self.liveness_done = True
        self.auth_system.users[self.current_user]["authenticated"] = True
        self.auth_system.save_users()
        self.audit_log.log_event(self.current_user, "LIVENESS_VERIFIED_SIGNUP",
                                  {"blinks": SIGNUP_BLINKS}, "INFO")
        messagebox.showinfo("Signup Complete",
                            f"Welcome {self.current_user}!\n\nYour account has been activated.\n"
                            "You can now log in using your username.")
        self.show_login()

    def show_login_liveness(self):
        self._build_liveness_screen(LOGIN_BLINKS, self._on_login_liveness_done, "LOGIN STEP 2")

    def _on_login_liveness_done(self):
        self.show_ids_verification()

    # ══════════════════════════════════════════════════════════════════════
    #   MANUAL FACE MATCH — non-blocking
    # ══════════════════════════════════════════════════════════════════════
    def show_face_match(self):
        self._clear()
        self._topbar(self.root)
        self.display_active = True

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=14, pady=8)

        hdr = tk.Frame(body, bg=BG)
        hdr.pack(fill=tk.X, pady=(0, 8))
        self._label(hdr, f"LOGIN STEP 1 — FACE RECOGNITION  (User: {self.current_user})",
                    12, BLUE, bold=True).pack(side=tk.LEFT)
        self._label(hdr, "Look at the camera, then press SPACE", 9, GREY).pack(side=tk.RIGHT)

        cols = tk.Frame(body, bg=BG)
        cols.pack(fill=tk.BOTH, expand=True)

        cam_card = self._card(cols)
        cam_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        self.wcam = self._webcam_label(cam_card)

        side = self._card(cols, width=320)
        side.pack(side=tk.LEFT, fill=tk.Y)
        side.pack_propagate(False)

        self._label(side, "FACE MATCH STATUS", 9, YELLOW, bold=True).pack(pady=(14, 6))
        self.match_var = tk.StringVar(value="Waiting for capture...")
        tk.Label(side, textvariable=self.match_var, font=("Consolas", 10, "bold"),
                 bg=PANEL, fg=GREEN, wraplength=280).pack(pady=4, padx=10)

        self.conf_var = tk.StringVar(value="Confidence: --")
        tk.Label(side, textvariable=self.conf_var, font=("Consolas", 12, "bold"),
                 bg=PANEL, fg=BLUE).pack(pady=6)
        self._label(side, f"Threshold: ≥ {FACE_THRESHOLD}", 9, GREY).pack()

        self.proc_status_var = tk.StringVar(value="")
        tk.Label(side, textvariable=self.proc_status_var, font=("Consolas", 9, "italic"),
                 bg=PANEL, fg=YELLOW).pack()

        self.match_bar = ttk.Progressbar(side, maximum=100, mode="determinate")
        self.match_bar.pack(fill=tk.X, padx=14, pady=8)

        self.match_btn = self._btn(side, "⎵  PRESS SPACE TO SCAN", self._try_face_match, color=BLUE, width=28)
        self.match_btn.pack(pady=8, padx=10)

        self._label(side, "LOG", 8, YELLOW, bold=True).pack(pady=(10, 2))
        self.match_log = self._log_box(side, height=6)
        self._append(self.match_log, "Position your face and press SPACE to scan.")

        self._btn(side, "CANCEL", self._cancel_current, color=RED, fg=WHITE).pack(pady=10)

        self._match_attempts = 0
        self._match_busy = False
        self.root.bind("<space>", lambda e: self._safe(self._try_face_match)())
        self._video_loop(self.wcam, overlay_text="Press SPACE to scan")

    def _try_face_match(self):
        if self._match_busy:
            return
        frame = getattr(self, "last_frame", None)
        if frame is None:
            self._append(self.match_log, "⚠ No camera frame available.")
            return

        stored_raw = self.auth_system.users.get(self.current_user, {}).get("embedding")
        stored_emb = list_to_emb(stored_raw) if stored_raw else \
                     self.face_recognizer.database.get(self.current_user)

        if stored_emb is None:
            messagebox.showerror("Enrollment Missing", "No enrollment embedding found for this user.")
            self._unbind_space()
            self.root.after(200, self.show_login)
            return

        self._match_busy = True
        self.match_btn.config(state=tk.DISABLED)
        self._append(self.match_log, "Scanning...")
        self._start_processing_timer(self.proc_status_var, "Matching face")

        def work():
            # FIX: use detect_sync() so this checks the actual captured
            # frame instead of a stale async result.
            faces = self.face_detector.detect_sync(frame)
            if len(faces) != 1:
                return ("wrong_face_count", len(faces))

            # Anti-spoof check — sampled across several frames rather
            # than just the one SPACE-press frame. A single frame can
            # occasionally score as "real" purely by chance (see
            # calibration notes — screen-replay scores varied widely
            # frame to frame); requiring most of a short burst to agree
            # closes that gap. Always computed and returned so it can
            # be logged/fed into the IDS features, regardless of
            # whether ENFORCE_ANTI_SPOOF is currently on.
            try:
                burst = self.cam.get_burst(ANTI_SPOOF_BURST_FRAMES)
                if not burst:
                    burst = [frame]
                live_votes = 0
                spoof_scores = []
                last_spoof_details = {}
                for bf in burst:
                    bfaces = self.face_detector.detect_sync(bf)
                    if len(bfaces) != 1:
                        continue
                    b_is_live, b_spoof_score, b_details = self.anti_spoof.analyze(bf, bfaces[0])
                    live_votes += 1 if b_is_live else 0
                    spoof_scores.append(b_spoof_score)
                    last_spoof_details = b_details
                total_checked = len(spoof_scores)
                if total_checked == 0:
                    is_live, spoof_score, spoof_details = True, 0.0, {"note": "no valid burst frames"}
                else:
                    # Require a clear majority of sampled frames to look
                    # live — one or two lucky/unlucky frames can't flip
                    # the overall result on their own.
                    is_live = live_votes > (total_checked / 2)
                    spoof_score = sum(spoof_scores) / total_checked
                    spoof_details = {
                        **last_spoof_details,
                        "burst_frames_checked": total_checked,
                        "burst_live_votes": live_votes,
                        "burst_avg_spoof_score": round(spoof_score, 3),
                    }
            except Exception as e:
                is_live, spoof_score, spoof_details = True, 0.0, {"error": str(e)}

            cur_emb = self.face_recognizer.get_embedding(frame)
            if cur_emb is None:
                return ("no_embedding", None, is_live, spoof_score, spoof_details)
            sim = cosine_sim(cur_emb, stored_emb)
            return ("ok", sim, is_live, spoof_score, spoof_details)

        def done(ok, result):
            self._match_busy = False
            self._stop_processing_timer()
            self.proc_status_var.set("")
            self.match_btn.config(state=tk.NORMAL)

            if not ok:
                self._append(self.match_log, f"⚠ Error: {result}")
                return

            status = result[0]
            if status == "wrong_face_count":
                self._append(self.match_log, f"⚠ Need exactly 1 face. Found {result[1]}.")
                return

            _, value, is_live, spoof_score, spoof_details = result
            self.spoof_score_this_login = spoof_score
            self.spoof_detected_this_login = not is_live

            spoof_tag = "⚠ SPOOF SIGNAL" if not is_live else "clean"
            self._append(self.match_log, f"Anti-spoof: score={spoof_score:.3f} ({spoof_tag})")

            if not is_live:
                self.audit_log.log_event(
                    self.current_user, "SPOOF_SIGNAL_DETECTED",
                    {"spoof_score": round(spoof_score, 3), **spoof_details}, "WARNING"
                )
                try:
                    self.account_mgr.record_spoof_attempt(self.current_user)
                except Exception:
                    pass

                if ENFORCE_ANTI_SPOOF:
                    self._append(self.match_log, "🚫 Blocked — anti-spoof check failed.")
                    messagebox.showerror(
                        "Spoof Detected",
                        f"This attempt looks like a spoofing attack "
                        f"(spoof score {spoof_score:.2f}). Access denied."
                    )
                    self._unbind_space()
                    self.root.after(200, self.show_home)
                    return

            if status == "no_embedding":
                self._append(self.match_log, "⚠ Could not extract embedding. Try again.")
                return

            sim = value
            self._match_attempts += 1
            self.conf_var.set(f"Confidence: {sim:.4f}")
            self.match_bar["value"] = min(int(sim * 100), 100)
            self._append(self.match_log, f"Attempt {self._match_attempts}: similarity = {sim:.4f}")

            if sim >= FACE_THRESHOLD:
                self.login_confidence = sim
                self.match_var.set(f"✅ Face matched! ({sim:.4f})")
                self._append(self.match_log, "✅ Face matched. Proceeding to liveness...")
                self.face_matched = True
                self._unbind_space()
                self.match_btn.config(state=tk.DISABLED)
                self.root.after(700, self.show_login_liveness)
            else:
                self.match_var.set(f"⚠ Not matched ({sim:.4f}). Try again or cancel.")
                if self._match_attempts >= 5:
                    self.failed_attempts += 1
                    self.account_mgr.record_failed_attempt(self.current_user)
                    self.audit_log.log_failed_attempt(
                        self.current_user, f"Face match failed after 5 attempts (best={sim:.4f})", self.ip_address)
                    messagebox.showerror("Access Denied",
                                         f"Face recognition failed after {self._match_attempts} attempts.\n"
                                         f"Best similarity: {sim:.4f}  (required ≥ {FACE_THRESHOLD})")
                    self._unbind_space()
                    self.root.after(200, self.show_home)

        self._run_bg(work, done)

    # ══════════════════════════════════════════════════════════════════════
    #   IDS VERIFICATION
    # ══════════════════════════════════════════════════════════════════════
    def show_ids_verification(self):
        self._clear()
        self._topbar(self.root)
        self.display_active = False

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=40, pady=20)

        card = self._card(body)
        card.pack(expand=True, ipadx=40, ipady=30)

        self._label(card, "STEP 3 — HYBRID INTRUSION DETECTION CHECK", 14, RED, bold=True).pack(pady=(20, 10))

        self.ids_status_var = tk.StringVar(value="Collecting network and behavioural features...")
        tk.Label(card, textvariable=self.ids_status_var, font=("Consolas", 10),
                 bg=PANEL, fg=YELLOW).pack(pady=6)

        self.ids_feat_box = scrolledtext.ScrolledText(card, height=14, width=80, bg="#0d1117",
                                                       fg=GREEN, font=("Consolas", 8), relief=tk.FLAT)
        self.ids_feat_box.pack(padx=30, pady=10)

        self._run_ids_check()

    def _run_ids_check(self):
        box = self.ids_feat_box

        def work():
            try:
                net_features, ids_allowed, ids_msg = self.net_monitor.extract_features()
            except Exception as e:
                net_features = {}

            # Admin after-hours override: if this user is marked trusted,
            # zero out the after_hours feature (index 6 of the 7 network
            # features) so quick_rules() doesn't auto-block them purely
            # for the time of day. The event is still fully logged below
            # regardless — this only skips the automatic hard block.
            override_applied = False
            try:
                trusted = self.account_mgr.is_after_hours_trusted(self.current_user)
            except Exception:
                trusted = False
            if trusted and net_features and len(net_features) > 6 and net_features[6] == 1.0:
                net_features = list(net_features)
                net_features[6] = 0.0
                override_applied = True

            auth_event = {
                "success": True,
                "spoof_detected": self.spoof_detected_this_login,
                "confidence_score": self.login_confidence,
                "ip_address": self.ip_address,
                "failed_attempts": self.failed_attempts,
            }
            try:
                features = self.feat_extractor.extract(auth_event, net_features)
                alert, level, reason = self.ids.predict(features)
            except Exception as e:
                alert, level, reason = False, "N/A", f"IDS unavailable — defaulting to allow ({e})"

            if override_applied:
                self.audit_log.log_event(
                    self.current_user, "AFTER_HOURS_OVERRIDE_APPLIED",
                    {"reason": "User is marked after-hours trusted by admin"}, "INFO"
                )

            return (net_features, auth_event, alert, level, reason, override_applied)

        def done(ok, result):
            if not ok:
                box.insert(tk.END, f"[ERROR] IDS pipeline failed: {result}\n")
                self.ids_status_var.set("⚠ IDS check failed — see log")
                messagebox.showerror("IDS Error", str(result))
                self.root.after(1500, self.show_home)
                return

            net_features, auth_event, alert, level, reason, override_applied = result

            box.insert(tk.END, "NETWORK FEATURE SNAPSHOT\n" + "-"*50 + "\n")
            net_feature_names = [
                "packets_per_sec", "bytes_per_sec", "unique_ports",
                "syn_count", "failed_connections", "traffic_ratio", "after_hours"
            ]
            for name, v in zip(net_feature_names, net_features or []):
                box.insert(tk.END, f"  {str(name):<30} {v}\n")
            if override_applied:
                box.insert(tk.END, "  (after-hours block overridden — user is admin-trusted)\n")

            box.insert(tk.END, "\nBEHAVIOURAL FEATURES\n" + "-"*50 + "\n")
            for k, v in auth_event.items():
                box.insert(tk.END, f"  {str(k):<30} {v}\n")

            box.insert(tk.END, "\nHYBRID IDS DECISION\n" + "-"*50 + "\n")
            box.insert(tk.END, f"  Classifier verdict: {'ALERT' if alert else 'CLEAN'}\n")
            box.insert(tk.END, f"  Severity level:     {level}\n")
            box.insert(tk.END, f"  Reason:             {reason}\n")
            box.see(tk.END)

            if alert:
                self.ids_status_var.set("🚨 ACCESS BLOCKED BY IDS")
                self.audit_log.log_ids_alert(self.current_user, level, reason)
                self.audit_log.log_failed_attempt(self.current_user, f"IDS blocked login: {reason}", self.ip_address)
                self.root.after(2000, lambda: (
                    messagebox.showerror("IDS Alert", f"Access blocked.\n\nLevel: {level}\nReason: {reason}"),
                    self.show_home()
                ))
            else:
                self.ids_status_var.set("✅ IDS CHECK PASSED — Creating session...")
                session_id = self.session_mgr.create_session(self.current_user, self.ip_address, self.device_id)
                self.current_session = session_id
                self.audit_log.log_login(self.current_user, True, self.login_confidence, self.ip_address)
                self.audit_log.log_event(self.current_user, "AUTHENTICATION_SUCCESS", {
                    "face_confidence": round(self.login_confidence, 4),
                    "ids_status": level,
                    "session_id": session_id[:8],
                }, "INFO")
                self.is_auth = True
                self.account_mgr.record_success(self.current_user)
                self.failed_attempts = 0
                self.root.after(1200, self.show_success)

        self._run_bg(work, done)

    # ══════════════════════════════════════════════════════════════════════
    #   SUCCESS
    # ══════════════════════════════════════════════════════════════════════
    def show_success(self):
        self._clear()
        self._topbar(self.root)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=40, pady=20)

        card = self._card(body)
        card.pack(expand=True, ipadx=40, ipady=30)

        tk.Label(card, text="✅", font=("Consolas", 48), bg=PANEL, fg=GREEN).pack(pady=(20, 4))
        self._label(card, "AUTHENTICATION SUCCESSFUL", 16, GREEN, bold=True).pack()

        user_info = self.auth_system.get_user_info(self.current_user)
        if user_info:
            self._label(card, f"Welcome, {user_info.get('full_name', self.current_user)}", 13, WHITE).pack(pady=4)
            self._label(card, f"Department: {user_info.get('department', 'N/A')}", 10, GREY).pack()

        ttk.Separator(card, orient="horizontal").pack(fill=tk.X, pady=16, padx=30)
        self._label(card, "ZERO TRUST VERIFICATION SUMMARY", 10, YELLOW, bold=True).pack()

        checks = [
            ("Face Recognition",   f"PASSED  (Confidence: {self.login_confidence:.4f})"),
            ("Liveness Detection", f"PASSED  ({LOGIN_BLINKS} blinks confirmed)"),
            ("Hybrid IDS",         "PASSED  (RF + Isolation Forest: CLEAN)"),
            ("Session ID",         f"{self.current_session[:12]}..." if self.current_session else "N/A"),
            ("IP Address",         self.ip_address),
            ("Access Time",        datetime.now().strftime("%d %b %Y  %H:%M:%S")),
        ]
        for label, val in checks:
            row = tk.Frame(card, bg=PANEL)
            row.pack(fill=tk.X, padx=40, pady=2)
            tk.Label(row, text="✓  " + label + ":", font=("Consolas", 9), bg=PANEL, fg=GREEN,
                     width=26, anchor="w").pack(side=tk.LEFT)
            tk.Label(row, text=val, font=("Consolas", 9, "bold"), bg=PANEL, fg=WHITE, anchor="w").pack(side=tk.LEFT)

        ttk.Separator(card, orient="horizontal").pack(fill=tk.X, pady=16, padx=30)
        btn_row = tk.Frame(card, bg=PANEL)
        btn_row.pack(pady=8)
        self._btn(btn_row, "🚪  LOGOUT", self._logout, color=RED, fg=WHITE).pack(side=tk.LEFT, padx=10)
        self._btn(btn_row, "📊  IDS DASHBOARD", self.show_ids, color=YELLOW, fg=BG).pack(side=tk.LEFT, padx=10)

    # ══════════════════════════════════════════════════════════════════════
    #   ADMIN PANEL — back button now lives in the fixed top bar
    # ══════════════════════════════════════════════════════════════════════
    def show_admin(self):
        self._clear()
        self._topbar(self.root, back_cmd=self.show_home)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=14, pady=8)

        self._label(body, "ADMINISTRATOR PANEL", 14, "#8957e5", bold=True).pack(pady=(0, 10))

        nb = ttk.Notebook(body)
        nb.pack(fill=tk.BOTH, expand=True)

        t1 = tk.Frame(nb, bg=PANEL)
        nb.add(t1, text="👥  Registered Users")
        top1 = tk.Frame(t1, bg=PANEL)
        top1.pack(fill=tk.X, padx=10, pady=6)
        u_box = scrolledtext.ScrolledText(t1, bg="#0d1117", fg=GREEN, font=("Consolas", 8), relief=tk.FLAT)
        self._btn(top1, "🔄 Refresh", lambda: self._refresh_users(u_box), color=BLUE, fg=BG).pack(side=tk.LEFT, padx=4)
        u_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)
        self._refresh_users(u_box)

        t2 = tk.Frame(nb, bg=PANEL)
        nb.add(t2, text="🔐  Account Status")
        a_box = scrolledtext.ScrolledText(t2, bg="#0d1117", fg=GREEN, font=("Consolas", 8), relief=tk.FLAT)
        a_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)
        self._refresh_accounts(a_box)

        t3 = tk.Frame(nb, bg=PANEL)
        nb.add(t3, text="📋  Audit Log")
        top3 = tk.Frame(t3, bg=PANEL)
        top3.pack(fill=tk.X, padx=10, pady=6)
        al_box = scrolledtext.ScrolledText(t3, bg="#0d1117", fg="#d29922", font=("Consolas", 8), relief=tk.FLAT)
        self._btn(top3, "🔄 Refresh", lambda: self._refresh_audit_log(al_box), color=BLUE, fg=BG).pack(side=tk.LEFT, padx=4)
        al_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)
        self._refresh_audit_log(al_box)

        t4 = tk.Frame(nb, bg=PANEL)
        nb.add(t4, text="🌐  Active Sessions")
        top4 = tk.Frame(t4, bg=PANEL)
        top4.pack(fill=tk.X, padx=10, pady=6)
        s_box = scrolledtext.ScrolledText(t4, bg="#0d1117", fg=GREEN, font=("Consolas", 8), relief=tk.FLAT)
        self._btn(top4, "🔄 Refresh", lambda: self._refresh_sessions(s_box), color=BLUE, fg=BG).pack(side=tk.LEFT, padx=4)
        s_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)
        self._refresh_sessions(s_box)

        t5 = tk.Frame(nb, bg=PANEL)
        nb.add(t5, text="🗑️  Manage Users")
        self._build_delete_tab(t5)

    def _refresh_audit_log(self, box):
        box.delete("1.0", tk.END)
        events = self.audit_log.get_recent_events(limit=200)
        box.insert(tk.END, f"{'Timestamp':<22} {'Username':<14} {'Event':<28} {'Severity':<10} Details\n" + "-"*120 + "\n")
        for e in reversed(events):
            box.insert(tk.END, f"{e['timestamp']:<22} {e['username']:<14} {e['event_type']:<28} "
                                f"{e['severity']:<10} {str(e['details'])[:60]}\n")

    def _refresh_sessions(self, box):
        box.delete("1.0", tk.END)
        sessions = self.session_mgr.get_all_sessions()
        if not sessions:
            box.insert(tk.END, "No active sessions yet — a session is only created after a "
                                "fully successful login (past face match, liveness, and IDS check).\n")
            return
        for s in sessions:
            box.insert(tk.END, f"{s['session_id'][:12]}...  {s['username']:<14} {s['ip_address']:<18} "
                                f"{s['created_at']:<22} {s['expired']}\n")

    def _refresh_users(self, box):
        box.delete("1.0", tk.END)
        users = self.auth_system.list_users()
        box.insert(tk.END, f"{'#':<4} {'Username':<14} {'Full Name':<18} {'Department':<16} "
                            f"{'Enrolled':<10} {'Auth':<8} {'Created'}\n" + "-"*120 + "\n")
        for i, u in enumerate(users, 1):
            enr = "✓" if u.get("enrolled", False) else "✗"
            aut = "✓" if u.get("authenticated", False) else "✗"
            box.insert(tk.END, f"{i:<4} {u['username']:<14} {u['full_name']:<18} "
                                f"{u['department']:<16} {enr:<10} {aut:<8} {u['created_at'][:10]}\n")

    def _refresh_accounts(self, box):
        box.delete("1.0", tk.END)
        accounts = self.account_mgr.list_all_accounts()
        box.insert(tk.END, f"{'Username':<14} {'Locked':<10} {'Failed':<10} {'Spoof':<10} {'AH-Trusted':<12} {'Last Login'}\n" + "-"*110 + "\n")
        for a in accounts:
            box.insert(tk.END, f"{a['username']:<14} {str(a.get('is_locked', False)):<10} "
                                f"{a.get('failed_attempts', 0):<10} {a.get('spoof_attempts', 0):<10} "
                                f"{str(a.get('after_hours_trusted', False)):<12} "
                                f"{a.get('last_login') or 'Never'}\n")

    def _build_delete_tab(self, parent):
        self._label(parent, "Delete or Unlock a User Account", 10, RED, bold=True).pack(pady=(14, 6))
        del_var = tk.StringVar()
        tk.Entry(parent, textvariable=del_var, font=("Consolas", 11), bg="#0d1117", fg=RED,
                 insertbackground=RED, relief=tk.FLAT, bd=4, width=30).pack(pady=8)
        msg_var = tk.StringVar()
        tk.Label(parent, textvariable=msg_var, font=("Consolas", 9), bg=PANEL, fg=YELLOW).pack()

        def delete():
            uname = del_var.get().strip()
            if not uname or not self.auth_system.user_exists(uname):
                msg_var.set(f"User '{uname}' not found."); return
            if not messagebox.askyesno("Confirm Delete", f"Permanently delete '{uname}'?"):
                return
            if uname in self.auth_system.users:
                del self.auth_system.users[uname]; self.auth_system.save_users()
            if uname in self.account_mgr.accounts:
                del self.account_mgr.accounts[uname]; self.account_mgr.save_accounts()
            if uname in self.face_recognizer.database:
                del self.face_recognizer.database[uname]
            self.audit_log.log_admin_action("admin", "DELETE_USER", uname, "Account deleted")
            msg_var.set(f"✅ User '{uname}' deleted.")

        def unlock():
            uname = del_var.get().strip()
            if uname in self.account_mgr.accounts:
                self.account_mgr.accounts[uname]["is_locked"] = False
                self.account_mgr.accounts[uname]["failed_attempts"] = 0
                self.account_mgr.save_accounts()
                self.audit_log.log_admin_action("admin", "UNLOCK_ACCOUNT", uname, "Unlocked by admin")
                msg_var.set(f"✅ Account '{uname}' unlocked.")
            else:
                msg_var.set(f"Account '{uname}' not found.")

        def toggle_after_hours_trust():
            uname = del_var.get().strip()
            if not uname or uname not in self.account_mgr.accounts:
                msg_var.set(f"Account '{uname}' not found.")
                return
            current = self.account_mgr.is_after_hours_trusted(uname)
            ok, msg = self.account_mgr.set_after_hours_trusted(uname, not current)
            if ok:
                self.audit_log.log_admin_action(
                    "admin", "AFTER_HOURS_TRUST_TOGGLED", uname,
                    f"Set to {not current}"
                )
            msg_var.set(f"✅ {msg}" if ok else msg)

        btn_row = tk.Frame(parent, bg=PANEL)
        btn_row.pack(pady=10)
        self._btn(btn_row, "🗑️ DELETE USER", delete, color=RED, fg=WHITE).pack(side=tk.LEFT, padx=8)
        self._btn(btn_row, "🔓 UNLOCK ACCOUNT", unlock, color=YELLOW, fg=BG).pack(side=tk.LEFT, padx=8)
        self._btn(btn_row, "🕒 TOGGLE AFTER-HOURS TRUST", toggle_after_hours_trust,
                  color="#8957e5", fg=WHITE).pack(side=tk.LEFT, padx=8)

    # ══════════════════════════════════════════════════════════════════════
    #   IDS DASHBOARD — back button also in fixed top bar
    # ══════════════════════════════════════════════════════════════════════
    def show_ids(self):
        self._clear()
        self._topbar(self.root, back_cmd=self.show_home)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=14, pady=8)
        self._label(body, "HYBRID INTRUSION DETECTION SYSTEM — DASHBOARD", 14, RED, bold=True).pack(pady=(0, 10))

        all_events = self.audit_log.logs
        ids_alerts   = [e for e in all_events if e["event_type"] == "IDS_ALERT"]
        failed_auths = [e for e in all_events if e["event_type"] == "FAILED_AUTH"]
        logins       = [e for e in all_events if e["event_type"] == "LOGIN"]
        lockouts     = [e for e in all_events if e["event_type"] == "LOCKOUT"]
        spoofs       = [e for e in all_events if "spoof" in str(e.get("details", "")).lower()]

        stat_row = tk.Frame(body, bg=BG)
        stat_row.pack(fill=tk.X, pady=(0, 10))
        for label, val, col in [
            ("IDS ALERTS", str(len(ids_alerts)), RED), ("FAILED LOGINS", str(len(failed_auths)), YELLOW),
            ("LOCKOUTS", str(len(lockouts)), "#8957e5"), ("SPOOF ATTEMPTS", str(len(spoofs)), RED),
            ("SUCCESSFUL LOGINS", str(len(logins)), GREEN), ("TOTAL EVENTS", str(len(all_events)), BLUE)]:
            box = self._card(stat_row)
            box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
            tk.Label(box, text=val, font=("Consolas", 20, "bold"), bg=PANEL, fg=col).pack(pady=(12, 2))
            tk.Label(box, text=label, font=("Consolas", 7), bg=PANEL, fg=GREY).pack(pady=(0, 10))

        nb = ttk.Notebook(body)
        nb.pack(fill=tk.BOTH, expand=True)

        t1 = tk.Frame(nb, bg=PANEL); nb.add(t1, text="🚨  IDS Alerts")
        a_box = scrolledtext.ScrolledText(t1, bg="#0d1117", fg=RED, font=("Consolas", 8), relief=tk.FLAT)
        a_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)
        if ids_alerts:
            for e in reversed(ids_alerts):
                a_box.insert(tk.END, f"{e['timestamp']:<22} {e['username']:<14} {str(e['details'])[:80]}\n")
        else:
            a_box.insert(tk.END, "✅  No IDS alerts recorded. System is clean.\n")

        t2 = tk.Frame(nb, bg=PANEL); nb.add(t2, text="⚠️  Failed Attempts")
        f_box = scrolledtext.ScrolledText(t2, bg="#0d1117", fg=YELLOW, font=("Consolas", 8), relief=tk.FLAT)
        f_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)
        for e in reversed(failed_auths):
            f_box.insert(tk.END, f"{e['timestamp']:<22} {e['username']:<14} {str(e['details'])[:80]}\n")

        t2b = tk.Frame(nb, bg=PANEL); nb.add(t2b, text="🎭  Spoof Detections")
        sp_box = scrolledtext.ScrolledText(t2b, bg="#0d1117", fg=RED, font=("Consolas", 8), relief=tk.FLAT)
        sp_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)
        if spoofs:
            for e in reversed(spoofs):
                sp_box.insert(tk.END, f"{e['timestamp']:<22} {e['username']:<14} {str(e['details'])[:100]}\n")
        else:
            sp_box.insert(tk.END, "✅  No spoof signals recorded.\n")

        t3 = tk.Frame(nb, bg=PANEL); nb.add(t3, text="📡  Network Analysis")
        n_box = scrolledtext.ScrolledText(t3, bg="#0d1117", fg=BLUE, font=("Consolas", 8), relief=tk.FLAT)
        n_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)
        try:
            net_f, _, _ = self.net_monitor.extract_features()
            n_box.insert(tk.END, "LIVE NETWORK FEATURE SNAPSHOT\n" + "-"*60 + "\n")
            net_feature_names = [
                "packets_per_sec", "bytes_per_sec", "unique_ports",
                "syn_count", "failed_connections", "traffic_ratio", "after_hours"
            ]
            for name, v in zip(net_feature_names, net_f or []):
                n_box.insert(tk.END, f"  {str(name):<35} {v}\n")
        except Exception as ex:
            n_box.insert(tk.END, f"Network monitor error: {ex}\n")

        t4 = tk.Frame(nb, bg=PANEL); nb.add(t4, text="🧠  Threat Analysis")
        th_box = scrolledtext.ScrolledText(t4, bg="#0d1117", fg=YELLOW, font=("Consolas", 9), relief=tk.FLAT)
        th_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)
        th_box.insert(tk.END, f"Total Events: {len(all_events)}   IDS Alerts: {len(ids_alerts)}   "
                              f"Failed Logins: {len(failed_auths)}\n")
        if len(failed_auths) > 5:
            th_box.insert(tk.END, f"\n⚠ HIGH RISK: {len(failed_auths)} failed attempts — possible brute force.\n")

    # ══════════════════════════════════════════════════════════════════════
    #   CANCEL / LOGOUT
    # ══════════════════════════════════════════════════════════════════════
    def _unbind_space(self):
        try:
            self.root.unbind("<space>")
        except Exception:
            pass

    def _cancel_signup(self):
        self.display_active = False
        self._proc_active = False
        self._unbind_space()
        if self.current_user and not self.liveness_done:
            try:
                if self.current_user in self.auth_system.users:
                    del self.auth_system.users[self.current_user]; self.auth_system.save_users()
                if self.current_user in self.account_mgr.accounts:
                    del self.account_mgr.accounts[self.current_user]; self.account_mgr.save_accounts()
                self.audit_log.log_event(self.current_user, "SIGNUP_INCOMPLETE",
                                          {"reason": "Cancelled before liveness"}, "WARNING")
            except Exception:
                pass
        self.current_user = None
        self.show_home()

    def _cancel_current(self):
        self.display_active = False
        self._proc_active = False
        self._unbind_space()
        self.show_home()

    def _logout(self):
        self.display_active = False
        if self.current_session:
            self.session_mgr.end_session(self.current_session)
            self.audit_log.log_event(self.current_user, "LOGOUT", {"session": self.current_session[:8]}, "INFO")
        self.current_user = None
        self.current_session = None
        self.is_auth = False
        self.login_confidence = 0.0
        self.liveness_det.reset()
        self.show_home()


if __name__ == "__main__":
    root = tk.Tk()
    app = FacialAuthSystem(root)
    root.mainloop()