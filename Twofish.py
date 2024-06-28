import os
import time
import tkinter as tk
from tqdm import tqdm
import EncryptionApp as app
from twofish import Twofish
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

def encrypt_twofish(root):
    global encrypted_data, encrypted_file_path

    bak_file = entry_file_encrypt.get()

    password = entry_pubkey.get("1.0", "end-1c").encode()
    
    if len(password) < 16:
        messagebox.showerror("Error", "Password harus minimal 16 byte atau karakter.")
        return

    if len(password) > 16:
        password = password[:16]

    cipher = Twofish(password)

    with open(bak_file, 'rb') as f:
        data = f.read()
        original_size = len(data) # Ukuran file sebelum di enrkipsi
    
    encrypt_progress_bar['maximum'] = len(data)
    encrypt_progress_bar['value'] = 0
    ciphertext_blocks = []
    start_time = time.time()

    batch_size = 1024 * 10  # Batasi pembaruan progress bar setiap 10KB
    next_update = batch_size

    for i in range(0, len(data), 16):
        block = data[i:i+16]
        if len(block) < 16:
            padding_length = 16 - len(block)
            block += bytes([padding_length]) * padding_length

        ciphertext_block = cipher.encrypt(block)
        ciphertext_blocks.append(ciphertext_block)

        # Update progress bar dalam interval batch_size
        if encrypt_progress_bar['value'] + len(block) >= next_update:
            encrypt_progress_bar['value'] += len(block)
            root.update_idletasks()
            next_update += batch_size
        else:
            encrypt_progress_bar['value'] += len(block)

    elapsed_time = time.time() - start_time
    encrypted_data = b''.join(ciphertext_blocks)
    encrypted_size = len(encrypted_data)  # Ukuran file setelah enkripsi

    # Pastikan progress bar mencapai nilai maksimum
    encrypt_progress_bar['value'] = len(data)
    root.update()  # Pastikan GUI sepenuhnya diperbarui

    hours, remainder = divmod(elapsed_time, 3600)
    minutes, seconds = divmod(remainder, 60)
    encrypt_estimated_time_label.config(text=f"Waktu enkripsi: {int(hours)} jam {int(minutes)} menit {int(seconds)} detik / {elapsed_time:.2f} detik.")
    
    original_size_kb = int(original_size / 1024)
    encrypted_size_kb = int(encrypted_size / 1024)
    original_size_encrypt_label.config(text=f"Ukuran sebelum enkripsi: {original_size_kb:} KB")
    encrypted_size_label.config(text=f"Ukuran setelah enkripsi: {encrypted_size_kb:} KB")
    
    btn_save_encrypted.config(state='normal')
    messagebox.showinfo("Information", f"Enkripsi selesai!")

def save_encrypted_result_file():
    global encrypted_data, encrypted_file_path
    
    if encrypted_data:
        file_path = filedialog.asksaveasfilename(defaultextension="", filetypes=[("Encrypted Files", "*_tf.encrypted")])
        if file_path:
            file_path_root, file_extension = os.path.splitext(file_path)
            if file_extension != ".encrypted":
                file_path += "_rsa.encrypted"
        if file_path:
            with open(file_path, 'wb') as f:
                f.write(b"TF:" + entry_pubkey.get("1.0", "end-1c").encode()[:16] + b"\n")
                f.write(encrypted_data)
            messagebox.showinfo("Information", "File berhasil disimpan!")
            btn_save_encrypted.config(state='disabled')
            encrypt_estimated_time_label.config(text="")
            entry_file_encrypt.config(textvariable="")
            entry_file_encrypt.delete(0, tk.END)
            entry_pubkey.delete(1.0, tk.END)
            encrypt_progress_bar['value'] =  0
    else:
        messagebox.showwarning("Warning", "Tidak ada data yang akan disimpan.")

def decrypt_twofish(root):
    global decrypted_data, decrypted_file_path

    encrypted_file = entry_file_decrypt.get()

    password = entry_privkey.get("1.0", "end-1c").encode()

    if len(password) < 16:
        messagebox.showerror("Error", "Password harus minimal 16 byte atau karakter.")
        return

    if len(password) > 16:
        password = password[:16]

    cipher = Twofish(password)

    with open(encrypted_file, 'rb') as f:
        metadata_password = f.readline().strip().split(b"TF:")[1]

        if metadata_password != password:
            messagebox.showerror("Error", "Password tidak cocok dengan password enkripsi!")
            return
        
        data = f.read()
        original_size = len(data) # Ukuran file sebelum di enrkipsi

    decrypt_progress_bar['maximum'] = len(data)
    decrypt_progress_bar['value'] = 0

    decrypted_blocks = []
    start_time = time.time()

    # Batasi pembaruan progress bar setiap 10KB
    batch_size = 1024 * 10
    next_update = batch_size

    for i in range(0, len(data), 16):
        block = data[i:i+16]
        decrypted_block = cipher.decrypt(block)

        # Remove padding if last block
        if i + 16 >= len(data):
            padding_length = decrypted_block[-1]
            decrypted_block = decrypted_block[:-padding_length]

        decrypted_blocks.append(decrypted_block)

        # Update progress bar dalam interval batch_size
        if decrypt_progress_bar['value'] + len(block) >= next_update:
            decrypt_progress_bar['value'] += len(block)
            root.update_idletasks()
            next_update += batch_size
        else:
            decrypt_progress_bar['value'] += len(block)

    elapsed_time = time.time() - start_time
    decrypted_data = b''.join(decrypted_blocks)
    decrypted_size = len(decrypted_data)  # Ukuran file setelah enkripsi

    # Pastikan progress bar mencapai nilai maksimum
    decrypt_progress_bar['value'] = len(data)
    root.update()  # Pastikan GUI sepenuhnya diperbarui

    hours, remainder = divmod(elapsed_time, 3600)
    minutes, seconds = divmod(remainder, 60)
    decrypt_estimated_time_label.config(text=f"Waktu dekripsi: {int(hours)} jam {int(minutes)} menit {int(seconds)} detik / {elapsed_time:.2f} detik.")
    
    original_size_kb = int(original_size / 1024)
    decrypted_size_kb = int(decrypted_size / 1024)
    original_size_decrypt_label.config(text=f"Ukuran sebelum dekripsi: {original_size_kb:} KB")
    decrypted_size_label.config(text=f"Ukuran setelah dekripsi: {decrypted_size_kb:} KB")
    
    btn_save_decrypted.config(state='normal')
    messagebox.showinfo("Information", f"Dekripsi selesai!")

def save_decrypted_result_file():
    global decrypted_data, decrypted_file_path
    
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
    
    root.title("Enkripsi Twofish")

    # Enkripsi
    label_encrypt = tk.Label(root, text="Encrypt File", font=("Arial", 24))
    label_encrypt.place(x=30, y=160)

    label_pubkey_input = tk.Label(root, text="Input Password / Secure Key:", font=("Arial", 18))
    label_pubkey_input.place(x=30, y=200)
    
    global entry_pubkey
    entry_pubkey = tk.Text(root)
    entry_pubkey.place(x=30, y=230, width=350, height=100)
                           
    entry_pubkey_scrollbar = tk.Scrollbar(root, command=entry_pubkey.yview)
    entry_pubkey.config(yscrollcommand=entry_pubkey_scrollbar.set)

    label_bak_encrypt = tk.Label(root, text="Pilih file .bak:", font=("Arial", 18))
    label_bak_encrypt.place(x=30, y=340)
    
    global entry_file_encrypt
    entry_file_encrypt = tk.Entry(root)
    entry_file_encrypt.place(x=30, y=370, width=250)
    
    btn_browse_encrypt = tk.Button(root, text="Browse", command=lambda: update_file_path(entry_file_encrypt, filedialog.askopenfilename(filetypes=[("Backup Database Files", "*.bak")])))
    btn_browse_encrypt.place(x=300, y=370, height=30)
    
    btn_start_encrypt = tk.Button(root, text="Mulai Enkripsi", command=lambda: encrypt_twofish(root))
    btn_start_encrypt.place(x=30, y=410, height=40)

    global btn_save_encrypted
    btn_save_encrypted = tk.Button(root, text="Simpan Hasil Enkripsi", command=save_encrypted_result_file)
    btn_save_encrypted.place(x=180, y=410, height=40, width= 200)
    btn_save_encrypted.config(state='disabled')

    global encrypt_progress_bar
    encrypt_progress_bar = ttk.Progressbar(root, variable=100, maximum=100)
    encrypt_progress_bar.place(x=30, y=460, width=350, height=20)

    global encrypt_estimated_time_label
    encrypt_estimated_time_label = tk.Message(root, text="", font=("Arial", 14), width=350)
    encrypt_estimated_time_label.place(x=30, y=500, height=30, width=350)

    global original_size_encrypt_label
    original_size_encrypt_label = tk.Message(root, text="", font=("Arial", 14), width=350)
    original_size_encrypt_label.place(x=30, y=540, height=30, width=350)

    global encrypted_size_label
    encrypted_size_label = tk.Message(root, text="", font=("Arial", 14), width=350)
    encrypted_size_label.place(x=30, y=560, height=30, width=350)

    separator = ttk.Separator(root, orient='vertical')
    separator.place(x=400, y=0, width = 2, height= 650)

    # Dekripsi
    label_decrypt = tk.Label(root, text="Decrypt File", font=("Arial", 24))
    label_decrypt.place(x=420, y=160)

    label_privkey_input = tk.Label(root, text="Input Password / Secure Key:", font=("Arial", 18))
    label_privkey_input.place(x=420, y=200)
    
    global entry_privkey
    entry_privkey = tk.Text(root)
    entry_privkey.place(x=420, y=230, width=350, height=100)
                           
    entry_privkey_scrollbar = tk.Scrollbar(root, command=entry_privkey.yview)
    entry_privkey.config(yscrollcommand=entry_privkey_scrollbar.set)

    label_bak_decrypt = tk.Label(root, text="Pilih file hasil enkripsi:", font=("Arial", 18))
    label_bak_decrypt.place(x=420, y=340)

    global entry_file_decrypt
    entry_file_decrypt = tk.Entry(root)
    entry_file_decrypt.place(x=420, y=370, width=250)
    
    btn_browse_decrypt = tk.Button(root, text="Browse", command=lambda: update_file_path(entry_file_decrypt, filedialog.askopenfilename(filetypes=[("Encrypted Files", ".encrypted")])))
    btn_browse_decrypt.place(x=690, y=370, height=30)
    
    btn_start_decrypt = tk.Button(root, text="Mulai Dekripsi", command=lambda: decrypt_twofish(root))
    btn_start_decrypt.place(x=420, y=410, height=40)

    global btn_save_decrypted
    btn_save_decrypted = tk.Button(root, text="Simpan Hasil Dekripsi", command=save_decrypted_result_file)
    btn_save_decrypted.place(x=570, y=410, height=40, width= 200)
    btn_save_decrypted.config(state='disabled')

    global decrypt_progress_bar
    decrypt_progress_bar = ttk.Progressbar(root, variable=100, maximum=100)
    decrypt_progress_bar.place(x=420, width=350, y=460, height=20)

    global decrypt_estimated_time_label
    decrypt_estimated_time_label = tk.Message(root, text="", font=("Arial", 14), width=350)
    decrypt_estimated_time_label.place(x=420, y=500, height=30, width=350)

    global original_size_decrypt_label
    original_size_decrypt_label = tk.Message(root, text="", font=("Arial", 14), width=350)
    original_size_decrypt_label.place(x=420, y=540, height=30, width=350)

    global decrypted_size_label
    decrypted_size_label = tk.Message(root, text="", font=("Arial", 14), width=350)
    decrypted_size_label.place(x=420, y=560, height=30, width=350)

    # Button Back
    btn_back = tk.Button(root, text="Kembali", command=lambda: app.show_main_page(root))
    btn_back.place(x=700, y=10, height=30)
