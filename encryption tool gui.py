import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
import os
import hashlib

# Function to generate a symmetric key
def generate_symmetric_key():
    return Fernet.generate_key()

# Function for AES Encryption and Decryption
def aes_encrypt(key, plaintext):
    fernet = Fernet(key)
    return fernet.encrypt(plaintext.encode()).decode()

def aes_decrypt(key, ciphertext):
    fernet = Fernet(key)
    return fernet.decrypt(ciphertext.encode()).decode()

# Function for RSA Encryption and Decryption
def rsa_generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    # Save keys to files
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL
        ))
        
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def rsa_encrypt(public_key_path, plaintext):
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

def rsa_decrypt(private_key_path, ciphertext):
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    
    ciphertext = base64.b64decode(ciphertext)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# Function for Hashing
def hash_text(plaintext):
    return hashlib.sha256(plaintext.encode()).hexdigest()

# Button callbacks
def perform_aes():
    key = key_entry.get()
    if not key:
        key = generate_symmetric_key().decode()
        key_entry.insert(0, key)
    
    action = action_var.get()
    text = input_entry.get("1.0", tk.END).strip()

    if action == "Encrypt":
        result = aes_encrypt(key.encode(), text)
        output_entry.delete("1.0", tk.END)
        output_entry.insert(tk.END, result)
    else:
        try:
            result = aes_decrypt(key.encode(), text)
            output_entry.delete("1.0", tk.END)
            output_entry.insert(tk.END, result)
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

def perform_rsa():
    action = rsa_action_var.get()
    text = input_entry.get("1.0", tk.END).strip()

    if action == "Generate Keys":
        rsa_generate_keys()
        messagebox.showinfo("Success", "RSA keys generated and saved as 'private_key.pem' and 'public_key.pem'.")
    elif action == "Encrypt":
        result = rsa_encrypt("public_key.pem", text)
        output_entry.delete("1.0", tk.END)
        output_entry.insert(tk.END, result)
    elif action == "Decrypt":
        try:
            result = rsa_decrypt("private_key.pem", text)
            output_entry.delete("1.0", tk.END)
            output_entry.insert(tk.END, result)
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

def perform_hash():
    text = input_entry.get("1.0", tk.END).strip()
    result = hash_text(text)
    output_entry.delete("1.0", tk.END)
    output_entry.insert(tk.END, result)

# GUI creation
def create_gui():
    global input_entry, output_entry, key_entry, action_var, rsa_action_var

    # Main window
    root = tk.Tk()
    root.title("Multi-Type Encryption Tool")
    root.geometry("500x400")

    # Title
    title_label = tk.Label(root, text="Multi-Type Encryption Tool", font=("Arial", 14))
    title_label.pack(pady=10)

    # Input Textbox
    input_label = tk.Label(root, text="Enter your text:")
    input_label.pack()
    input_entry = tk.Text(root, height=4, width=50)
    input_entry.pack(pady=5)

    # AES Section
    key_label = tk.Label(root, text="Enter AES key (leave empty to generate a new key):")
    key_label.pack()
    key_entry = tk.Entry(root, width=50)
    key_entry.pack(pady=5)

    action_var = tk.StringVar(value="Encrypt")
    encrypt_radio = tk.Radiobutton(root, text="Encrypt", variable=action_var, value="Encrypt")
    decrypt_radio = tk.Radiobutton(root, text="Decrypt", variable=action_var, value="Decrypt")
    encrypt_radio.pack()
    decrypt_radio.pack()

    aes_button = tk.Button(root, text="Perform AES", command=perform_aes)
    aes_button.pack(pady=5)

    # RSA Section
    rsa_action_var = tk.StringVar(value="Encrypt")
    generate_keys_radio = tk.Radiobutton(root, text="Generate RSA Keys", variable=rsa_action_var, value="Generate Keys")
    encrypt_radio = tk.Radiobutton(root, text="Encrypt with RSA", variable=rsa_action_var, value="Encrypt")
    decrypt_radio = tk.Radiobutton(root, text="Decrypt with RSA", variable=rsa_action_var, value="Decrypt")
    
    generate_keys_radio.pack()
    encrypt_radio.pack()
    decrypt_radio.pack()

    rsa_button = tk.Button(root, text="Perform RSA", command=perform_rsa)
    rsa_button.pack(pady=5)

    # Hashing Section
    hash_button = tk.Button(root, text="Hash Text (SHA-256)", command=perform_hash)
    hash_button.pack(pady=5)

    # Output Textbox
    output_label = tk.Label(root, text="Output:")
    output_label.pack()
    output_entry = tk.Text(root, height=4, width=50)
    output_entry.pack(pady=5)

    # Start the main loop
    root.mainloop()

if __name__ == "__main__":
    create_gui()
