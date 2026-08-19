"""Login Page"""
import tkinter as tk

class LoginPage(tk.Frame):
    """User login page"""
    
    def __init__(self, parent, app_instance):
        super().__init__(parent, bg="#F5F5F5")
        self.app = app_instance
        self.create_widgets()
    
    def create_widgets(self):
        """Create login widgets"""
        
        # Header
        header = tk.Frame(self, bg="#0066CC", height=80)
        header.pack(fill="x")
        header.pack_propagate(False)
        
        title = tk.Label(
            header, text="[FACIAL AUTH LOGIN]",
            font=("Segoe UI", 18, "bold"), bg="#0066CC", fg="white"
        )
        title.pack(pady=20)
        
        # Content
        content = tk.Frame(self, bg="#F5F5F5")
        content.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Message
        msg = tk.Label(
            content, 
            text="Login Page - Phase 4 Implementation",
            font=("Segoe UI", 14),
            bg="#F5F5F5"
        )
        msg.pack(pady=20)
        
        # Buttons
        btn_frame = tk.Frame(content, bg="#F5F5F5")
        btn_frame.pack()
        
        start_btn = tk.Button(
            btn_frame, text="Start Authentication",
            bg="#00AA44", fg="white", padx=20, pady=10,
            command=self.start_auth
        )
        start_btn.pack(pady=5, fill="x")
        
        admin_btn = tk.Button(
            btn_frame, text="Admin Panel",
            bg="#0066CC", fg="white", padx=20, pady=10,
            command=lambda: self.app.show_page("admin")
        )
        admin_btn.pack(pady=5, fill="x")
        
        monitor_btn = tk.Button(
            btn_frame, text="Monitoring",
            bg="#00CC99", fg="white", padx=20, pady=10,
            command=lambda: self.app.show_page("monitoring")
        )
        monitor_btn.pack(pady=5, fill="x")
    
    def start_auth(self):
        """Start authentication"""
        print("OK - Authentication started")
    
    def update_stats(self):
        pass
