"""Admin Panel"""
import tkinter as tk

class AdminPanel(tk.Frame):
    """Administrator panel"""
    
    def __init__(self, parent, app_instance):
        super().__init__(parent, bg="#F5F5F5")
        self.app = app_instance
        self.create_widgets()
    
    def create_widgets(self):
        """Create admin widgets"""
        
        # Header
        header = tk.Frame(self, bg="#0066CC", height=80)
        header.pack(fill="x")
        header.pack_propagate(False)
        
        title = tk.Label(
            header, text="[ADMIN PANEL]",
            font=("Segoe UI", 18, "bold"), bg="#0066CC", fg="white"
        )
        title.pack(pady=20)
        
        # Content
        content = tk.Frame(self, bg="#F5F5F5")
        content.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Message
        msg = tk.Label(
            content,
            text="Admin Panel - Phase 4 Implementation",
            font=("Segoe UI", 14),
            bg="#F5F5F5"
        )
        msg.pack(pady=20)
        
        # Button
        back_btn = tk.Button(
            content, text="Back to Login",
            bg="#FF9900", fg="white", padx=20, pady=10,
            command=lambda: self.app.show_page("login")
        )
        back_btn.pack(pady=10)
    
    def update_stats(self):
        pass
