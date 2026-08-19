"""GUI Styling"""

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
