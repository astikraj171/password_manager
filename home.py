import tkinter as tk
from tkinter import messagebox, simpledialog
from PIL import Image, ImageTk
import os
import string
import random
import pyperclip
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
import base64

# Blowfish key (16 bytes, should be kept secret)
blowfish_key = b'my_secret_blowfish_key'  # 16 bytes key

# Function to encrypt data using Blowfish
def blowfish_encrypt(data):
    cipher = Blowfish.new(blowfish_key, Blowfish.MODE_ECB)
    padded_data = pad(data.encode(), Blowfish.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted_data).decode()

# Function to decrypt data using Blowfish
def blowfish_decrypt(data):
    cipher = Blowfish.new(blowfish_key, Blowfish.MODE_ECB)
    encrypted_data = base64.b64decode(data)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), Blowfish.block_size)
    return decrypted_data.decode()

# Create the main window
root = tk.Tk()
root.geometry("800x600")
root.title("Password Manager")

# Sidebar for options
sidebar_frame = tk.Frame(root, bg="#003366", width=200, padx=10, pady=10)
sidebar_frame.pack(side="left", fill="y")

# Function to add a password
def add_password():
    add_password_frame = tk.Frame(root)
    tk.Label(add_password_frame, text="Website:", font=("Arial", 12)).grid(row=0, column=0, padx=10, pady=10)
    website_entry = tk.Entry(add_password_frame, font=("Arial", 12), width=30)
    website_entry.grid(row=0, column=1, padx=10, pady=10)

    tk.Label(add_password_frame, text="Username:", font=("Arial", 12)).grid(row=1, column=0, padx=10, pady=10)
    username_entry = tk.Entry(add_password_frame, font=("Arial", 12), width=30)
    username_entry.grid(row=1, column=1, padx=10, pady=10)

    tk.Label(add_password_frame, text="Password:", font=("Arial", 12)).grid(row=2, column=0, padx=10, pady=10)
    password_entry = tk.Entry(add_password_frame, font=("Arial", 12), width=30, show="*")
    password_entry.grid(row=2, column=1, padx=10, pady=10)

    def save_password():
        encrypted_password = blowfish_encrypt(password_entry.get())
        with open(".m_pass", "a") as f:
            f.write(f"{website_entry.get()}|{username_entry.get()}|{encrypted_password}\n")
        messagebox.showinfo("Success", "Password saved successfully!")
        add_password_frame.destroy()

    save_button = tk.Button(add_password_frame, text="Save", command=save_password)
    save_button.grid(row=3, column=1, pady=10)

    add_password_frame.pack(pady=20)

# Function to generate a random password
def generate_password():
    chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(chars) for i in range(12))
    pyperclip.copy(password)
    messagebox.showinfo("Generated Password", f"Password: {password}\n(Copied to clipboard)")

# Function to show log of unauthorized access photos
def log_show():
    log_window = tk.Toplevel(root)
    log_window.geometry("600x400")
    log_window.title("Unauthorized Access Photos")

    photos_frame = tk.Frame(log_window)
    photos_frame.pack(fill="both", expand=True)

    # Check for unauthorized access photos
    for file in os.listdir():
        if file.endswith(".jpg"):
            try:
                img = Image.open(file)
                img = img.resize((200, 150), Image.LANCZOS)
                img_tk = ImageTk.PhotoImage(img)

                label = tk.Label(photos_frame, image=img_tk)
                label.image = img_tk  # Keep a reference to avoid garbage collection
                label.pack(padx=10, pady=10)
            except Exception as e:
                print(f"Error loading image {file}: {e}")

# Function to calculate password strength
def calculate_strength(password):
    length = len(password)
    has_digit = any(char.isdigit() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_special = any(char in string.punctuation for char in password)

    if length >= 8 and has_digit and has_upper and has_lower and has_special:
        return "Strong"
    elif length >= 6 and (has_digit or has_special):
        return "Moderate"
    else:
        return "Weak"

# Function to prompt for password and calculate its strength
def calculate_strength_prompt():
    password = simpledialog.askstring("Calculate Strength", "Enter a password to calculate its strength:")
    if password:
        strength = calculate_strength(password)
        messagebox.showinfo("Password Strength", f"The strength of the password is: {strength}")

# Function to clear all passwords
def clear_passwords():
    with open(".m_pass", "w") as f:
        f.write("")
    messagebox.showinfo("Success", "All passwords have been cleared.")

# Function to quit the application
def quit_app():
    root.quit()

# Function to show help
def show_help():
    help_message = (
        "M-Pass is a simple password manager.\n\n"
        "To add a new password, click 'Add Password' and enter the website, username, and password.\n"
        "To generate a random password, click 'Generate Password'.\n"
        "To retrieve the password log, click 'Log'.\n"
        "To clear all passwords, click 'Clear Passwords'.\n"
        "To calculate password strength, use 'Calculate Strength'.\n"
    )
    messagebox.showinfo("Help", help_message)

# Sidebar Buttons (Aligned)
add_password_button = tk.Button(sidebar_frame, text="Add Password", font=("Arial", 12), command=add_password)
add_password_button.pack(fill="x", pady=10)

generate_password_button = tk.Button(sidebar_frame, text="Generate Password", font=("Arial", 12), command=generate_password)
generate_password_button.pack(fill="x", pady=10)

log_show_button = tk.Button(sidebar_frame, text="Log", font=("Arial", 12), command=log_show)
log_show_button.pack(fill="x", pady=10)

calculate_strength_button = tk.Button(sidebar_frame, text="Calculate Strength", font=("Arial", 12), command=calculate_strength_prompt)
calculate_strength_button.pack(fill="x", pady=10)

clear_passwords_button = tk.Button(sidebar_frame, text="Clear Passwords", font=("Arial", 12), command=clear_passwords)
clear_passwords_button.pack(fill="x", pady=10)

help_button = tk.Button(sidebar_frame, text="Help", font=("Arial", 12), command=show_help)
help_button.pack(fill="x", pady=10)

quit_button = tk.Button(sidebar_frame, text="Quit", font=("Arial", 12), command=quit_app)
quit_button.pack(fill="x", pady=10)

root.mainloop()
