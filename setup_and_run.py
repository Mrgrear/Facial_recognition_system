"""
Phase 4 Complete Setup and Verification Script
Fixed for Windows - No Unicode Issues
"""

import os
from pathlib import Path

def create_file_with_content(filepath, content):
    """Create file with specific content"""
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    # Use UTF-8 encoding explicitly
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"OK - Created: {filepath}")

def setup_phase4():
    print("=" * 70)
    print("PHASE 4 SETUP - Creating all necessary files")
    print("=" * 70)
    print()
    
    # Create __init__.py for GUI
    create_file_with_content(
        "GUI/__init__.py",
        "# GUI Package\n"
    )
    
    # Create __init__.py for pages
    create_file_with_content(
        "GUI/pages/__init__.py",
        "# Pages Package\n"
    )
    
    # Create config.py
    create_file_with_content(
        "GUI/config.py",
        '''"""GUI Configuration"""

class GUIConfig:
    WINDOW_WIDTH = 1400
    WINDOW_HEIGHT = 900
    WINDOW_TITLE = "Enhanced Facial Authentication System v1.0"
    PRIMARY_COLOR = "#0066CC"
    BACKGROUND = "#F5F5F5"

config = GUIConfig()
'''
    )
    
    # Create styles.py
    create_file_with_content(
        "GUI/styles.py",
        '''"""GUI Styling"""

class Styles:
    @staticmethod
    def create_button(parent, text, command, bg_color="#0066CC"):
        import tkinter as tk
        button = tk.Button(
            parent, text=text, command=command,
            bg=bg_color, fg="white", padx=20, pady=10
        )
        return button

styles = Styles()
'''
    )
    
    # Create login_page.py
    create_file_with_content(
        "GUI/pages/login_page.py",
        '''"""Login Page"""
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
'''
    )
    
    # Create admin_panel.py
    create_file_with_content(
        "GUI/pages/admin_panel.py",
        '''"""Admin Panel"""
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
'''
    )
    
    # Create monitoring_page.py
    create_file_with_content(
        "GUI/pages/monitoring_page.py",
        '''"""Monitoring Page"""
import tkinter as tk

class MonitoringPage(tk.Frame):
    """Real-time monitoring page"""
    
    def __init__(self, parent, app_instance):
        super().__init__(parent, bg="#F5F5F5")
        self.app = app_instance
        self.create_widgets()
    
    def create_widgets(self):
        """Create monitoring widgets"""
        
        # Header
        header = tk.Frame(self, bg="#0066CC", height=80)
        header.pack(fill="x")
        header.pack_propagate(False)
        
        title = tk.Label(
            header, text="[MONITORING & ALERTS]",
            font=("Segoe UI", 18, "bold"), bg="#0066CC", fg="white"
        )
        title.pack(pady=20)
        
        # Content
        content = tk.Frame(self, bg="#F5F5F5")
        content.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Message
        msg = tk.Label(
            content,
            text="Monitoring Page - Phase 4 Implementation",
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
'''
    )
    
    # Create main_gui.py
    create_file_with_content(
        "GUI/main_gui.py",
        '''"""Main GUI Application"""
import tkinter as tk
from GUI.config import config
from GUI.pages.login_page import LoginPage
from GUI.pages.admin_panel import AdminPanel
from GUI.pages.monitoring_page import MonitoringPage

class MainApplication(tk.Tk):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        
        self.title(config.WINDOW_TITLE)
        self.geometry(f"{config.WINDOW_WIDTH}x{config.WINDOW_HEIGHT}")
        self.resizable(True, True)
        
        self.stats = {
            "Total Logins": 0,
            "Failed Attempts": 0,
            "Spoof Detections": 0,
            "IDS Alerts": 0,
            "Locked Accounts": 0,
            "Network Anomalies": 0
        }
        
        # Container
        container = tk.Frame(self, bg=config.BACKGROUND)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        
        # Create pages
        self.pages = {}
        
        self.pages["login"] = LoginPage(container, self)
        self.pages["admin"] = AdminPanel(container, self)
        self.pages["monitoring"] = MonitoringPage(container, self)
        
        for page in self.pages.values():
            page.grid(row=0, column=0, sticky="nsew")
        
        self.show_page("login")
        print("OK - Application initialized successfully")
    
    def show_page(self, page_name):
        """Show specific page"""
        if page_name in self.pages:
            self.pages[page_name].tkraise()
            print(f"OK - Switched to {page_name} page")
    
    def update_stat(self, stat_name, value):
        """Update statistics"""
        if stat_name in self.stats:
            self.stats[stat_name] = value

def run():
    """Run the application"""
    app = MainApplication()
    app.mainloop()

if __name__ == "__main__":
    run()
'''
    )
    
    # Create/update main.py
    create_file_with_content(
        "main.py",
        '''"""
Main Entry Point - Phase 4 System Integration
Enhanced Facial Authentication System with Hybrid IDS
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from GUI.main_gui import run

if __name__ == "__main__":
    print("=" * 70)
    print("ENHANCED FACIAL AUTHENTICATION SYSTEM v1.0")
    print("Phase 4: System Integration & GUI Development")
    print("Student: Omu John Efu (CYB/23U/3983)")
    print("=" * 70)
    print()
    
    try:
        run()
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
'''
    )
    
    print()
    print("=" * 70)
    print("SUCCESS - All Files Created!")
    print("=" * 70)
    print()
    print("Created Files:")
    print("   OK - GUI/")
    print("   OK - GUI/__init__.py")
    print("   OK - GUI/config.py")
    print("   OK - GUI/styles.py")
    print("   OK - GUI/main_gui.py")
    print("   OK - GUI/pages/")
    print("   OK - GUI/pages/__init__.py")
    print("   OK - GUI/pages/login_page.py")
    print("   OK - GUI/pages/admin_panel.py")
    print("   OK - GUI/pages/monitoring_page.py")
    print("   OK - main.py (updated)")
    print()
    print("Next Step:")
    print("   python main.py")
    print()

if __name__ == "__main__":
    setup_phase4()