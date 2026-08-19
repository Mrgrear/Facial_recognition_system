"""Main GUI Application"""
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
