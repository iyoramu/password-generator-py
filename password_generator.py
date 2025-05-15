import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import secrets
import string

class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Fortress Password Generator")
        self.root.geometry("500x400")
        self.root.resizable(False, False)
        self.root.configure(bg="#f4f6f8")
        self.create_widgets()

    def create_widgets(self):
        # Title
        title_label = tk.Label(self.root, text="🔐 Fortress Password Generator", font=("Helvetica", 18, "bold"), bg="#f4f6f8", fg="#2c3e50")
        title_label.pack(pady=20)

        # Password Length
        length_frame = tk.Frame(self.root, bg="#f4f6f8")
        length_frame.pack(pady=10)
        tk.Label(length_frame, text="Password Length:", font=("Helvetica", 12), bg="#f4f6f8").pack(side="left", padx=5)
        self.length_var = tk.IntVar(value=16)
        self.length_spinbox = ttk.Spinbox(length_frame, from_=6, to=64, textvariable=self.length_var, width=5, font=("Helvetica", 12))
        self.length_spinbox.pack(side="left")

        # Checkboxes
        self.include_uppercase = tk.BooleanVar(value=True)
        self.include_lowercase = tk.BooleanVar(value=True)
        self.include_digits = tk.BooleanVar(value=True)
        self.include_symbols = tk.BooleanVar(value=True)

        check_frame = tk.Frame(self.root, bg="#f4f6f8")
        check_frame.pack(pady=10)

        tk.Checkbutton(check_frame, text="Uppercase (A-Z)", variable=self.include_uppercase, bg="#f4f6f8", font=("Helvetica", 11)).grid(row=0, column=0, padx=10, pady=5)
        tk.Checkbutton(check_frame, text="Lowercase (a-z)", variable=self.include_lowercase, bg="#f4f6f8", font=("Helvetica", 11)).grid(row=0, column=1, padx=10, pady=5)
        tk.Checkbutton(check_frame, text="Digits (0-9)", variable=self.include_digits, bg="#f4f6f8", font=("Helvetica", 11)).grid(row=1, column=0, padx=10, pady=5)
        tk.Checkbutton(check_frame, text="Symbols (!@#$)", variable=self.include_symbols, bg="#f4f6f8", font=("Helvetica", 11)).grid(row=1, column=1, padx=10, pady=5)

        # Generate Button
        self.generate_btn = ttk.Button(self.root, text="Generate Password", command=self.generate_password)
        self.generate_btn.pack(pady=20)

        # Output Field
        self.output_var = tk.StringVar()
        output_frame = tk.Frame(self.root, bg="#f4f6f8")
        output_frame.pack(pady=10)
        self.output_entry = ttk.Entry(output_frame, textvariable=self.output_var, font=("Courier", 12), width=35, justify="center")
        self.output_entry.grid(row=0, column=0, padx=5)
        ttk.Button(output_frame, text="📋 Copy", command=self.copy_to_clipboard).grid(row=0, column=1, padx=5)

    def generate_password(self):
        length = self.length_var.get()
        char_pool = ''

        if self.include_uppercase.get():
            char_pool += string.ascii_uppercase
        if self.include_lowercase.get():
            char_pool += string.ascii_lowercase
        if self.include_digits.get():
            char_pool += string.digits
        if self.include_symbols.get():
            char_pool += "!@#$%^&*()_+-=[]{}|;:,.<>?/"

        if not char_pool:
            messagebox.showerror("Error", "Please select at least one character set!")
            return

        password = ''.join(secrets.choice(char_pool) for _ in range(length))
        self.output_var.set(password)

    def copy_to_clipboard(self):
        password = self.output_var.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.root.update()
            messagebox.showinfo("Copied", "Password copied to clipboard!")

# Main App Runner
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()
