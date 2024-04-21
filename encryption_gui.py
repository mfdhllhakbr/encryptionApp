import tkinter as tk
from tkinter import filedialog, messagebox
import time
import os
import rsa
from twofish import Twofish
from threading import Thread
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from tqdm import tqdm
from datetime import timedelta
import math

encrypted_data = None
encrypted_file_path = None

def open_encryption_page():
    # Menutup halaman awal
    root.withdraw()
    # Membuka halaman enkripsi
    encryption_page.deiconify()

def open_decryption_page():
    # Menutup halaman awal
    root.withdraw()
    # Membuka halaman dekripsi
    decryption_page.deiconify()

def open_compression_page():
    # Menutup halaman awal
    root.withdraw()
    # Membuka halaman dekripsi
    compression_page.deiconify()

def update_file_path(new_path):
    file_path_entry.delete(0, tk.END)
    file_path_entry.config(state=tk.NORMAL)
    file_path_entry.delete(0, tk.END)
    file_path_entry.insert(0, new_path)
    file_path_entry.config(state=tk.DISABLED)

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

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

def encrypt_rsa():
    global encrypted_data, encrypted_file_path

    estimated_time_label.config(text=f"Loading...")

    try:
        file_path = file_path_entry.get()

        with open(file_path, 'rb') as f:
            start_time = time.time()
            encrypted_chunks = []
            chunk_num = 0
            total_chunks = math.ceil(os.path.getsize(file_path) / 128)  # Kecilin dulu chunk size-nya sesuai key.
            with tqdm(total=total_chunks) as pbar:
                while True:
                    chunk = f.read(128)
                    if not chunk:
                        break
                    
                    encrypted_chunk = encrypt_chunk(chunk, public_key)

                    if encrypted_chunk:
                        encrypted_chunks.append(encrypted_chunk)
                        pbar.update()
                    else:
                        messagebox.showerror("Error", "Failed to encrypt and save chunk.")
                        return

        elapsed_time = time.time() - start_time
        hours, remainder = divmod(elapsed_time, 3600)
        minutes, seconds = divmod(remainder, 60)
        estimated_time_label.config(text=f"Waktu enkripsi: {int(hours)} jam {int(minutes)} menit {int(seconds)} detik / {elapsed_time:.5f} detik.")
        encrypted_data = b''.join(encrypted_chunks)
        # estimated_time_label.config(text=f"Waktu enkripsi: {elapsed_time:.5f} detik.")
        save_button.config(state='normal')
        messagebox.showinfo("Information", f"Enkripsi selesai!")
    except Exception as e:
        messagebox.showerror("Error", "Encryption failed for file.\nError message: " + str(e))

def encrypt_twofish():
    global encrypted_data, encrypted_file_path
    
    estimated_time_label.config(text=f"Loading...")

    bak_file = file_path_entry.get()
    key = b'your_secure_encryption_key_here'

    cipher = Twofish(key)

    with open(bak_file, 'rb') as f:
        # Baca lines
        data = f.read()
        
    # Use tqdm for progress bar
    with tqdm(total=len(data), unit='B', unit_scale=True, unit_divisor=1024, desc="Encrypting") as pbar:
        ciphertext_blocks = []
        start_time = time.time()

        for i in range(0, len(data), 16):
            block = data[i:i+16]
            if len(block) < 16:
                padding_length = 16 - len(block)
                block += bytes([padding_length]) * padding_length

            ciphertext_block = cipher.encrypt(block)
            ciphertext_blocks.append(ciphertext_block)
            pbar.update(len(block))  # Update progress bar for each block

    elapsed_time = time.time() - start_time
    encrypted_data = b''.join(ciphertext_blocks)

    hours, remainder = divmod(elapsed_time, 3600)
    minutes, seconds = divmod(remainder, 60)
    estimated_time_label.config(text=f"Waktu enkripsi: {int(hours)} jam {int(minutes)} menit {int(seconds)} detik / {elapsed_time:.5f} detik.")
    # estimated_time_label.config(text=f"Waktu enkripsi: {elapsed_time:.5f} detik.")
    save_button.config(state='normal')
    messagebox.showinfo("Information", f"Enkripsi selesai!")

def save_result_file():
    global encrypted_data, encrypted_file_path
    
    if encrypted_data:
        if encryption_method.get() == 1:
            file_path = filedialog.asksaveasfilename(defaultextension="", filetypes=[("Encrypted Files", "*_rsa.encrypted")])
            if file_path:
                file_path_root, file_extension = os.path.splitext(file_path)
                if file_extension != ".encrypted":
                    file_path += "_rsa.encrypted"
        else:
            file_path = filedialog.asksaveasfilename(defaultextension="", filetypes=[("Encrypted Files", "*_tf.encrypted")])
            if file_path:
                file_path_root, file_extension = os.path.splitext(file_path)
                if file_extension != ".encrypted":
                    file_path += "_tf.encrypted"
        if file_path:
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            messagebox.showinfo("Information", "File berhasil disimpan!")
            save_button.config(state='disabled')
            estimated_time_label.config(text="")
            file_path_entry.config(textvariable="")
            file_path_entry.delete(0, tk.END)
    else:
        messagebox.showwarning("Warning", "Tidak ada data yang akan disimpan.")

# Halaman awal
root = tk.Tk()
root.title("Aplikasi Enkripsi/Deskripsi File")

# Pilihan enkripsi atau dekripsi
label = tk.Label(root, text="Pilih operasi yang ingin dilakukan:", font=("Arial", 20))
label.pack(pady=20)

encryption_button = tk.Button(root, text="Enkripsi", font=("Arial", 16), command=open_encryption_page)
encryption_button.pack(pady=10)

decryption_button = tk.Button(root, text="Dekripsi", font=("Arial", 16), command=open_decryption_page)
decryption_button.pack(pady=10)

compression_button = tk.Button(root, text="Kompresi", font=("Arial", 16), command=open_compression_page)
compression_button.pack(pady=10)

# Halaman enkripsi
encryption_page = tk.Toplevel(root)
encryption_page.title("Aplikasi Enkripsi File Backup Database")

private_key, public_key = generate_rsa_key_pair()

file_label = tk.Label(encryption_page, text="Pilih file .bak:", font=("Arial, 20"))
file_label.place(x=20, y=30)

frame = tk.Frame(encryption_page, highlightthickness=1, highlightbackground="black", bd=0)
frame.place(x=20, y=65)
file_path_entry = tk.Entry(frame, width=58, font=("Arial", 15), state=tk.DISABLED)
file_path_entry.pack(fill="both")
file_path_entry.config(state=tk.DISABLED)

browse_file_button = tk.Button(encryption_page, text="Browse", font=("Arial, 20"), command=lambda: update_file_path(filedialog.askopenfilename(filetypes=[("Backup Database Files", "*.bak")])))
browse_file_button.place(x=560, y = 63)

# Bagian switching.
switch_label = tk.Label(encryption_page, text="Pilih metode enkripsi:", font=("Arial, 20"))
switch_label.place(x=20, y=120)

encryption_method = tk.IntVar()
encryption_method.set(1)  # Default = rsa. 
toggle_rsa = tk.Radiobutton(encryption_page, text="RSA", font=("Arial", 20), variable=encryption_method, value=1)
toggle_rsa.place(x=20, y=150)
toggle_twofish = tk.Radiobutton(encryption_page, text="Twofish", font=("Arial", 20), variable=encryption_method, value=2)
toggle_twofish.place(x=140, y=150)

encrypt_button = tk.Button(encryption_page, text="Mulai Enkripsi", font=("Arial", 20), command=lambda: encrypt_rsa() if encryption_method.get() == 1 else encrypt_twofish())
encrypt_button.place(x=20, y=180)

# Label waktu.
estimated_time_label = tk.Label(encryption_page, text="", font=("Arial", 15))
estimated_time_label.place(x=200, y=184)

save_button = tk.Button(encryption_page, text="Save", font=("Arial", 20), command=save_result_file, state=tk.DISABLED)
save_button.place(x=20, y=230)

width = 680
height = 300
screen_width = encryption_page.winfo_screenwidth()
screen_height = encryption_page.winfo_screenheight()

x_coordinate = (screen_width - width) // 2
y_coordinate = (screen_height - height) // 2

encryption_page.geometry(f"{width}x{height}+{x_coordinate}+{y_coordinate}")
encryption_page.protocol("WM_DELETE_WINDOW", lambda: [root.deiconify(), encryption_page.withdraw()])

# Halaman dekripsi
decryption_page = tk.Toplevel(root)
decryption_page.title("Halaman Dekripsi")
decryption_page.geometry("600x400")
decryption_page.protocol("WM_DELETE_WINDOW", lambda: [root.deiconify(), decryption_page.withdraw()])

# Halaman compression
compression_page = tk.Toplevel(root)
compression_page.title("Halaman Kompresi")
compression_page.geometry("600x400")
compression_page.protocol("WM_DELETE_WINDOW", lambda: [root.deiconify(), compression_page.withdraw()])

# Jangan lupa untuk menyembunyikan kedua halaman terkait
encryption_page.withdraw()
decryption_page.withdraw()
compression_page.withdraw()

root.mainloop()