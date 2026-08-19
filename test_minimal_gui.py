import tkinter as tk

root = tk.Tk()
root.title("Minimal GUI Test")
root.geometry("600x400")
root.configure(bg="#1e1e1e")

label = tk.Label(
    root,
    text="If you see this, GUI works!",
    font=("Arial", 20),
    bg="#1e1e1e",
    fg="#00ff00"
)
label.pack(pady=50)

button = tk.Button(
    root,
    text="Click Me",
    command=lambda: print("Button clicked!"),
    bg="#00ff00",
    fg="#000000",
    font=("Arial", 12),
    padx=20,
    pady=10
)
button.pack()

root.mainloop()