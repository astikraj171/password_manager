import tkinter as tk
from tkinter import messagebox
import cv2
import os
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import unpad
import base64

# Blowfish key (must be the same as in updated_home.py)
blowfish_key = b'my_secret_blowfish_key'  # 16 bytes key

# Function to decrypt data using Blowfish
def blowfish_decrypt(data):
    cipher = Blowfish.new(blowfish_key, Blowfish.MODE_ECB)
    encrypted_data = base64.b64decode(data)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), Blowfish.block_size)
    return decrypted_data.decode()

# Set variables to keep track of login attempts
login_attempts = 0
photo_taken = False

# Create the main window
window = tk.Tk()
window.geometry("800x600")
window.title("Password Manager - Login")

# Frame for login
login_frame = tk.Frame(window)
login_frame.pack(pady=50)

# Username and Password fields
tk.Label(login_frame, text="Username:").grid(row=0, column=0, padx=10, pady=10)
username_entry = tk.Entry(login_frame, width=30)
username_entry.grid(row=0, column=1, padx=10, pady=10)

tk.Label(login_frame, text="Password:").grid(row=1, column=0, padx=10, pady=10)
password_entry = tk.Entry(login_frame, show="*", width=30)
password_entry.grid(row=1, column=1, padx=10, pady=10)

# Login function to check credentials
def login():
    global login_attempts, photo_taken
    entered_username = username_entry.get()
    entered_password = password_entry.get()

    try:
        with open(".m_pass", "r") as f:
            for line in f:
                website, stored_username, stored_encrypted_password = line.strip().split("|")
                stored_password = blowfish_decrypt(stored_encrypted_password)

                if entered_username == stored_username and entered_password == stored_password:
                    messagebox.showinfo("Login Successful", "Welcome!")
                    return

            # Increment login attempts
            login_attempts += 1
            messagebox.showerror("Error", "Invalid username or password!")

            # Take a photo after 3 failed attempts
            if login_attempts >= 3 and not photo_taken:
                cap = cv2.VideoCapture(0)
                if cap.isOpened():
                    ret, frame = cap.read()
                    if ret:
                        cv2.imwrite("unauthorized_access.jpg", frame)
                        messagebox.showwarning("Warning", "Unauthorized access detected! A photo has been taken.")
                        photo_taken = True
                    cap.release()
                else:
                    messagebox.showerror("Error", "Webcam is not available!")
    except FileNotFoundError:
        messagebox.showerror("Error", "No passwords stored yet!")

# Login button
login_button = tk.Button(window, text="Log In", command=login)
login_button.pack(pady=20)

window.mainloop()
