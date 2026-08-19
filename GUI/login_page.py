import tkinter as tk
from tkinter import messagebox
import cv2
from PIL import Image, ImageTk
from GUI.config import config
from GUI.styles import styles

class LoginPage(tk.Frame):
    """User login page with facial authentication"""
    
    def __init__(self, parent, app_instance):
        super().__init__(parent, bg=config.BACKGROUND)
        self.app = app_instance
        self.camera_running = False
        
        self.create_widgets()
    
    def create_widgets(self):
        """Create login page widgets"""
        
        # HEADER SECTION
        header = tk.Frame(self, bg=config.PRIMARY_COLOR, height=80)
        header.pack(fill="x")
        header.pack_propagate(False)
        
        title = tk.Label(
            header, text="🔐 Facial Authentication Login",
            font=config.FONT_TITLE, bg=config.PRIMARY_COLOR, fg="white"
        )
        title.pack(pady=20)
        
        # MAIN CONTENT
        content = tk.Frame(self, bg=config.BACKGROUND)
        content.pack(fill="both", expand=True, padx=20, pady=20)
        
        # LEFT: Camera Feed
        camera_frame = tk.Frame(content, bg="white", relief="flat", bd=1)
        camera_frame.pack(side="left", fill="both", expand=True, padx=10)
        
        camera_label = tk.Label(
            camera_frame, text="📹 Live Camera Feed",
            font=config.FONT_HEADING, bg="white", fg=config.TEXT_PRIMARY
        )
        camera_label.pack(anchor="w", padx=10, pady=10)
        
        self.camera_canvas = tk.Canvas(
            camera_frame, width=config.CAMERA_WIDTH, 
            height=config.CAMERA_HEIGHT, bg="black"
        )
        self.camera_canvas.pack(padx=10, pady=10)
        
        # RIGHT: Status Panel
        status_frame = tk.Frame(content, bg="white", relief="flat", bd=1, width=300)
        status_frame.pack(side="right", fill="both", padx=10)
        status_frame.pack_propagate(False)
        
        status_label = tk.Label(
            status_frame, text="Authentication Status",
            font=config.FONT_HEADING, bg="white", fg=config.TEXT_PRIMARY
        )
        status_label.pack(anchor="w", padx=10, pady=10)
        
        # Status items
        self.status_items = {}
        status_items = [
            ("Face Detection", "idle"),
            ("Liveness Check", "idle"),
            ("Recognition", "idle"),
            ("Spoof Check", "idle"),
            ("IDS Analysis", "idle")
        ]
        
        for name, status in status_items:
            badge = styles.create_status_badge(status_frame, name, status)
            badge.pack(fill="x", padx=10, pady=5)
            self.status_items[name] = badge
        
        # User info
        user_frame = tk.LabelFrame(
            status_frame, text="User Information",
            font=config.FONT_NORMAL, bg="white", padx=10, pady=10
        )
        user_frame.pack(fill="x", padx=10, pady=10)
        
        self.user_label = tk.Label(
            user_frame, text="Waiting for authentication...",
            font=config.FONT_NORMAL, bg="white", fg=config.TEXT_SECONDARY,
            wraplength=250, justify="left"
        )
        self.user_label.pack(anchor="w")
        
        # Buttons
        button_frame = tk.Frame(status_frame, bg="white")
        button_frame.pack(fill="x", padx=10, pady=10)
        
        start_btn = styles.create_button(
            button_frame, "Start Authentication", 
            self.start_authentication, bg_color=config.COLOR_SUCCESS
        )
        start_btn.pack(fill="x", pady=5)
        
        admin_btn = styles.create_button(
            button_frame, "Admin Panel", 
            lambda: self.app.show_page("admin"), 
            bg_color=config.PRIMARY_COLOR
        )
        admin_btn.pack(fill="x", pady=5)
        
        monitor_btn = styles.create_button(
            button_frame, "Monitoring", 
            lambda: self.app.show_page("monitoring"),
            bg_color=config.SECONDARY_COLOR
        )
        monitor_btn.pack(fill="x", pady=5)
    
    def start_auth(self):
    """Start authentication"""
    import time
    
    # Update message
    msg = tk.Label(
        self, 
        text="AUTHENTICATING...\nPlease wait",
        font=("Segoe UI", 16, "bold"),
        bg="#F5F5F5", fg="#0066CC"
    )
    msg.pack(pady=20)
    self.update_idletasks()
    
    # Simulate authentication steps
    steps = [
        "Face Detection...",
        "Liveness Check...",
        "Recognition...",
        "Spoof Check...",
        "IDS Analysis..."
    ]
    
    for step in steps:
        msg.config(text=step)
        self.update_idletasks()
        time.sleep(0.5)
    
    # Success
    msg.config(text="AUTHENTICATION SUCCESSFUL!\nAccess GRANTED", fg="#00AA44")
    self.update_idletasks()
    
    print("OK - Authentication completed successfully")