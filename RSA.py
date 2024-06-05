import os
import math
import time
import threading
import tkinter as tk
from tqdm import tqdm
import EncryptionApp as app
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

global encrypted_data
encrypted_data = None

global encrypted_file_path
encrypted_file_path = None

global decrypted_file_path
decrypted_file_path = None

global decrypted_data
decrypted_data = None

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()
    # print("private key: ", private_key)
    # print("public key: ", public_key)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_pem, private_pem

# def clean_pem(pem_data):
#     lines = pem_data.decode('utf-8').splitlines()
#     cleaned_data = ''.join(lines[1:-1])  # Menggabungkan semua baris kecuali yang pertama dan terakhir
#     return cleaned_data

def pem_to_public_key(public_pem):
    public_key = serialization.load_pem_public_key(
        public_pem,
        backend=default_backend()
    )
    return public_key

def pem_to_private_key(private_pem):
    private_key = serialization.load_pem_private_key(
        private_pem,
        password=None,
        backend=default_backend()
    )
    return private_key

def update_keys():
    public_pem, private_pem = generate_rsa_key_pair()
    
    # public_pem = clean_pem(public_pem)
    # private_pem = clean_pem(private_pem)

    text_public_key.config(state=tk.NORMAL)
    text_public_key.delete(1.0, tk.END)
    text_public_key.insert(tk.END, public_pem)
    text_public_key.config(state=tk.DISABLED)
    
    text_private_key.config(state=tk.NORMAL)
    text_private_key.delete(1.0, tk.END)
    text_private_key.insert(tk.END, private_pem)
    text_private_key.config(state=tk.DISABLED)

def copy_to_clipboard(root, text_widget):
    root.clipboard_clear()
    text = text_widget.get(1.0, tk.END)
    root.clipboard_append(text)
    messagebox.showinfo("Copy to Clipboard", "Text has been copied to clipboard.")

def save_to_txt(text_widget):
    file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        text = text_widget.get(1.0, tk.END)
        with open(file_path, 'w') as file:
            file.write(text)
        messagebox.showinfo("Save to TXT", f"Text has been saved to {file_path}")

def update_file_path(entry, new_path):
    entry.delete(0, tk.END)
    entry.config(state=tk.NORMAL)
    entry.delete(0, tk.END)
    entry.insert(0, new_path)
    entry.config(state=tk.DISABLED)

# def ensure_pem_format(pem_data, pem_type):
#     pem_header = f"-----BEGIN {pem_type}-----"
#     pem_footer = f"-----END {pem_type}-----"
#     if not pem_data.startswith(pem_header):
#         pem_data = f"{pem_header}\n{pem_data}\n{pem_footer}"
#     return pem_data

def encrypt_chunk(chunk, public_key):
    try:
        cipher_text = public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return cipher_text
    except Exception as e:
        print(f"Error encrypting chunk: {chunk}, {e}")
        return None
    
def encrypt_rsa(root):
    public_pem = text_public_key.get(1.0, tk.END).strip()
    # public_pem = ensure_pem_format(public_pem, pem_type="PUBLIC KEY")
    public_key = pem_to_public_key(public_pem.encode('utf-8'))
    global encrypted_data, encrypted_file_path

    # estimated_time_label.config(text=f"Loading...")

    try:
        file_path = entry_file_encrypt.get()

        with open(file_path, 'rb') as f:
            start_time = time.time()
            encrypted_chunks = []
            chunk_num = 0
            total_chunks = math.ceil(os.path.getsize(file_path) / 128)  # Kecilin dulu chunk size-nya sesuai key.
            encrypt_progress_bar["maximum"] = total_chunks
            # with tqdm(total=total_chunks) as pbar:
            while True:
                chunk = f.read(128)
                if not chunk:
                    break
                
                encrypted_chunk = encrypt_chunk(chunk, public_key)

                if encrypted_chunk:
                    encrypted_chunks.append(encrypted_chunk)
                    chunk_num += 1
                    encrypt_progress_bar["value"] = chunk_num
                    root.update_idletasks()  # Update the progress bar
                    # pbar.update()
                else:
                    messagebox.showerror("Error", "Failed to encrypt and save chunk.")
                    return

        elapsed_time = time.time() - start_time
        hours, remainder = divmod(elapsed_time, 3600)
        minutes, seconds = divmod(remainder, 60)
        encrypt_estimated_time_label.config(text=f"Waktu enkripsi: {int(hours)} jam {int(minutes)} menit {int(seconds)} detik / {elapsed_time:.5f} detik.")
        encrypted_data = b''.join(encrypted_chunks)
        # estimated_time_label.config(text=f"Waktu enkripsi: {elapsed_time:.5f} detik.")
        btn_save_encrypted.config(state='normal')
        messagebox.showinfo("Information", f"Enkripsi selesai!")
    except Exception as e:
        messagebox.showerror("Error", "Encryption failed for file.\nError message: " + str(e))
        
def save_encrypted_result_file():
    global encrypted_data, encrypted_file_path
    
    if encrypted_data:
        file_path = filedialog.asksaveasfilename(defaultextension="", filetypes=[("Encrypted Files", "*_rsa.encrypted")])
        if file_path:
            file_path_root, file_extension = os.path.splitext(file_path)
            if file_extension != ".encrypted":
                file_path += "_rsa.encrypted"
        if file_path:
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            messagebox.showinfo("Information", "File berhasil disimpan!")
            btn_save_encrypted.config(state='disabled')
            encrypt_estimated_time_label.config(text="")
            entry_file_encrypt.config(textvariable="")
            entry_file_encrypt.delete(0, tk.END)
            entry_pubkey.delete(1.0, tk.END)
            encrypt_progress_bar['value'] = 0
    else:
        messagebox.showwarning("Warning", "Tidak ada data yang akan disimpan.")

def decrypt_chunk(chunk, private_key):
    try:
        decrypted_text = private_key.decrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_text
    except Exception as e:
        print(f"Error decrypting chunk: {chunk}, {e}")
        return None

# def decrypt_rsa(root):
#     private_pem = entry_privkey.get(1.0, tk.END).strip()
#     private_key = pem_to_private_key(private_pem.encode('utf-8'))
#     global encrypted_data, encrypted_file_path

#     try:
#         file_path = entry_file_decrypt.get()

#         with open(file_path, 'rb') as f:
#             start_time = time.time()
#             decrypted_chunks = []
#             chunk_num = 0
#             total_chunks = math.ceil(os.path.getsize(file_path) / 256)  # Adjust chunk size accordingly
#             decrypt_progress_bar["maximum"] = total_chunks
#             # with tqdm(total=total_chunks) as pbar:
#             while True:
#                 chunk = f.read(256)  # Adjust chunk size accordingly
#                 if not chunk:
#                     break
                
#                 decrypted_chunk = decrypt_chunk(chunk, private_key)

#                 if decrypted_chunk:
#                     decrypted_chunks.append(decrypted_chunk)
#                     chunk_num += 1
#                     decrypt_progress_bar["value"] = chunk_num
#                     root.update_idletasks()  # Update the progress bar
#                 else:
#                     messagebox.showerror("Error", "Failed to decrypt and save chunk.")
#                     return

#         elapsed_time = time.time() - start_time
#         hours, remainder = divmod(elapsed_time, 3600)
#         minutes, seconds = divmod(remainder, 60)
#         decrypt_estimated_time_label.config(text=f"Waktu dekripsi: {int(hours)} jam {int(minutes)} menit {int(seconds)} detik / {elapsed_time:.5f} detik.")
#         decrypted_data = b''.join(decrypted_chunks)
#         btn_save_decrypted.config(state='normal')
#         messagebox.showinfo("Information", f"Dekripsi selesai!")
#     except Exception as e:
#         messagebox.showerror("Error", "Decryption failed for file.\nError message: " + str(e))
        
def decrypt_rsa(root):
    private_pem = entry_privkey.get(1.0, tk.END).strip()
    private_key = pem_to_private_key(private_pem.encode('utf-8'))
    global decrypted_data, decrypted_file_path

    try:
        file_path = entry_file_decrypt.get()

        with open(file_path, 'rb') as f:
            start_time = time.time()
            decrypted_chunks = []
            chunk_num = 0
            total_chunks = math.ceil(os.path.getsize(file_path) / 256)  # Adjust chunk size accordingly
            decrypt_progress_bar["maximum"] = total_chunks

            chunk_size = 256
            update_interval = 1  # Update progress bar every 1 seconds
            next_update = time.time() + update_interval

            while True:
                chunk = f.read(256)  # Adjust chunk size accordingly
                if not chunk:
                    break
                
                decrypted_chunk = decrypt_chunk(chunk, private_key)

                if decrypted_chunk:
                    decrypted_chunks.append(decrypted_chunk)
                    decrypt_progress_bar["value"] = f.tell() // chunk_size  # Update progress bar based on file position

                    # Update progress bar at regular intervals
                    if time.time() >= next_update:
                        root.update_idletasks()
                        next_update = time.time() + update_interval

                else:
                    messagebox.showerror("Error", "Failed to decrypt and save chunk.")
                    return

        elapsed_time = time.time() - start_time
        hours, remainder = divmod(elapsed_time, 3600)
        minutes, seconds = divmod(remainder, 60)
        decrypt_estimated_time_label.config(text=f"Waktu dekripsi: {int(hours)} jam {int(minutes)} menit {int(seconds)} detik / {elapsed_time:.5f} detik.")
        decrypted_data = b''.join(decrypted_chunks)
        btn_save_decrypted.config(state='normal')
        messagebox.showinfo("Information", f"Dekripsi selesai!")
    except Exception as e:
        messagebox.showerror("Error", "Decryption failed for file.\nError message: " + str(e))

def save_decrypted_result_file():
    global decrypted_data, encrypted_file_path
    
    if decrypted_data:
        file_path = filedialog.asksaveasfilename(defaultextension=".bak", filetypes=[("Backup Files", "*.bak"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'wb') as f:
                f.write(decrypted_data)
        if file_path:
            with open(file_path, 'wb') as f:
                f.write(decrypted_data)
            messagebox.showinfo("Information", "File berhasil disimpan!")
            btn_save_decrypted.config(state='disabled')
            decrypt_estimated_time_label.config(text="")
            entry_file_decrypt.config(textvariable="")
            entry_file_decrypt.delete(0, tk.END)
            entry_privkey.delete(1.0, tk.END)
            decrypt_progress_bar['value'] = 0
    else:
        messagebox.showwarning("Warning", "Tidak ada data yang akan disimpan.")

def show_window(root):
    for widget in root.winfo_children():
        widget.destroy()
    
    root.title("Enkripsi RSA")

    label_title = tk.Label(root, text="Generate Public Key dan Private Key", font=("Arial", 24))
    label_title.place(x=30, y=10)

    btn_start_generating = tk.Button(text="Start Generating", command=update_keys)
    btn_start_generating.place(x=30, y=50, width=150, height=40)

    # PUBLIC KEY
    label_public = tk.Label(root, text="Public Key:", font=("Arial", 18))
    label_public.place(x=30, y=90)

    global text_public_key
    text_public_key = tk.Text(root)
    text_public_key.place(x=30, y=120, width=350, height=80)
    text_public_key.config(state=tk.DISABLED)
                           
    public_scrollbar = tk.Scrollbar(root, command=text_public_key.yview)
    text_public_key.config(yscrollcommand=public_scrollbar.set)
    
    btn_copy_public = tk.Button(text="Copy", command=lambda: copy_to_clipboard(root, text_public_key))
    btn_copy_public.place(x=170, y=205, width=100, height=30)
    
    btn_save_public = tk.Button(text="Save to TXT", command=lambda: save_to_txt(text_public_key))
    btn_save_public.place(x=280, y=205, width=100, height=30)



    # PRIVATE KEY
    label_private = tk.Label(root, text="Private Key:", font=("Arial", 18))
    label_private.place(x=420, y=90)
    
    global text_private_key
    text_private_key = tk.Text(root)
    text_private_key.place(x=420, y=120, width=350, height=80)
    text_private_key.config(state=tk.DISABLED)
    
    private_scrollbar = tk.Scrollbar(root, command=text_private_key.yview)
    text_private_key.config(yscrollcommand=private_scrollbar.set)
    
    btn_copy_private = tk.Button(text="Copy", command=lambda: copy_to_clipboard(root, text_private_key))
    btn_copy_private.place(x=560, y=205, width=100, height=30)
    
    btn_save_private = tk.Button(text="Save to TXT", command=lambda: save_to_txt(text_private_key))
    btn_save_private.place(x=670, y=205, width=100, height=30)

    separator = ttk.Separator(root, orient='horizontal')
    separator.place(x=0, y=250, width=800, height=2)



    # ENCRYPT
    label_encrypt = tk.Label(root, text="Encrypt File", font=("Arial", 24))
    label_encrypt.place(x=30, y=260)

    label_pubkey_input = tk.Label(root, text="Input Public Key:", font=("Arial", 18))
    label_pubkey_input.place(x=30, y=300)
    
    global entry_pubkey
    entry_pubkey = tk.Text(root)
    entry_pubkey.place(x=30, y=330, width=350, height=100)
                           
    entry_pubkey_scrollbar = tk.Scrollbar(root, command=entry_pubkey.yview)
    entry_pubkey.config(yscrollcommand=entry_pubkey_scrollbar.set)

    label_bak_encrypt = tk.Label(root, text="Pilih file .bak:", font=("Arial", 18))
    label_bak_encrypt.place(x=30, y=440)
    
    global entry_file_encrypt
    entry_file_encrypt = tk.Entry(root)
    entry_file_encrypt.place(x=30, y=470, width=250)
    
    btn_browse_encrypt = tk.Button(root, text="Browse", command=lambda: update_file_path(entry_file_encrypt, filedialog.askopenfilename(filetypes=[("Backup Database Files", "*.bak")])))
    btn_browse_encrypt.place(x=300, y=470, height=30)
    
    btn_start_encrypt = tk.Button(root, text="Mulai Enkripsi", command=lambda: encrypt_rsa(root))
    btn_start_encrypt.place(x=30, y=510, height=40)

    global btn_save_encrypted
    btn_save_encrypted = tk.Button(root, text="Simpan Hasil Enkripsi", command=save_encrypted_result_file)
    btn_save_encrypted.place(x=180, y=510, height=40, width= 200)
    btn_save_encrypted.config(state='disabled')

    global encrypt_progress_bar
    encrypt_progress_bar = ttk.Progressbar(root, variable=100, maximum=100)
    encrypt_progress_bar.place(x=30, y=560, width=350, height=20)

    global encrypt_estimated_time_label
    encrypt_estimated_time_label = tk.Message(root, text="", font=("Arial", 14), width=350)
    encrypt_estimated_time_label.place(x=30, y=600, height=30, width=350)

    separator = ttk.Separator(root, orient='vertical')
    separator.place(x=400, y=251, width = 2, height= 430)



    # DECRYPT
    label_decrypt = tk.Label(root, text="Decrypt File", font=("Arial", 24))
    label_decrypt.place(x=420, y=260)

    label_privkey_input = tk.Label(root, text="Input Private Key:", font=("Arial", 18))
    label_privkey_input.place(x=420, y=300)
    
    global entry_privkey
    entry_privkey = tk.Text(root)
    entry_privkey.place(x=420, y=330, width=350, height=100)
                           
    entry_privkey_scrollbar = tk.Scrollbar(root, command=entry_privkey.yview)
    entry_privkey.config(yscrollcommand=entry_privkey_scrollbar.set)

    label_bak_decrypt = tk.Label(root, text="Pilih file hasil enkripsi:", font=("Arial", 18))
    label_bak_decrypt.place(x=420, y=440)

    global entry_file_decrypt
    entry_file_decrypt = tk.Entry(root)
    entry_file_decrypt.place(x=420, y=470, width=250)
    
    btn_browse_decrypt = tk.Button(root, text="Browse", command=lambda: update_file_path(entry_file_decrypt, filedialog.askopenfilename(filetypes=[("Encrypted Files", ".encrypted")])))
    btn_browse_decrypt.place(x=690, y=470, height=30)
    
    btn_start_decrypt = tk.Button(root, text="Mulai Dekripsi", command=lambda: decrypt_rsa(root))
    btn_start_decrypt.place(x=420, y=510, height=40)

    global btn_save_decrypted
    btn_save_decrypted = tk.Button(root, text="Simpan Hasil Dekripsi", command=save_decrypted_result_file)
    btn_save_decrypted.place(x=570, y=510, height=40, width= 200)
    btn_save_decrypted.config(state='disabled')

    global decrypt_progress_bar
    decrypt_progress_bar = ttk.Progressbar(root, variable=100, maximum=100)
    decrypt_progress_bar.place(x=420, width=350, y=560, height=20)

    global decrypt_estimated_time_label
    decrypt_estimated_time_label = tk.Message(root, text="", font=("Arial", 14), width=350)
    decrypt_estimated_time_label.place(x=420, y=600, height=30, width=350)



    # BACK
    btn_back = tk.Button(root, text="Kembali", command=lambda: app.show_main_page(root))
    btn_back.place(x=700, y=10, height=30)

