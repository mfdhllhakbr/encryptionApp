import os
import zlib
import threading
import tkinter as tk
import EncryptionApp as app
from tkinter import ttk, filedialog, messagebox

compressed_data = None

def compress_file(input_file):
    global compressed_data
    compress_progress_bar['value'] = 0
    compress_progress_bar.update_idletasks()

    def compression_task():
        global compressed_data
        with open(input_file, 'rb') as f_in:
            data = f_in.read()
            total_size = len(data)
            compressed_data = b""
            chunk_size = 1024  # Adjust the chunk size as needed
            for i in range(0, total_size, chunk_size):
                compressed_data += zlib.compress(data[i:i + chunk_size], level=9)
                progress = int((i / total_size) * 100)
                compress_progress_bar['value'] = progress
                compress_progress_bar.update_idletasks()

            # Finalize compression
            compressed_data += zlib.compress(data[i:], level=9)

        original_size = os.path.getsize(input_file)
        compressed_size = len(compressed_data)
        # print(f'Original size: {original_size} bytes')
        # print(f'Compressed size: {compressed_size} bytes')

        compress_progress_bar['value'] = 100
        compress_progress_bar.update_idletasks()
        messagebox.showinfo("Info", "Kompresi selesai!")
        btn_save_compressed.config(state='normal')

    # Start the compression in a separate thread
    threading.Thread(target=compression_task).start()

# def compress_file(input_file):
#     global compressed_data
#     with open(input_file, 'rb') as f_in:
#         data = f_in.read()
#         compressed_data = zlib.compress(data, level=9)
    # original_size = os.path.getsize(input_file)
    # compressed_size = len(compressed_data)
    # print(f'Original size: {original_size} bytes')
    # print(f'Compressed size: {compressed_size} bytes')

def save_compressed_file():
    global compressed_data
    if compressed_data is not None:
        output_file = filedialog.asksaveasfilename()
        if output_file:
            with open(output_file, 'wb') as f_out:
                f_out.write(compressed_data)
            messagebox.showinfo("Info", f"Hasil kompresi disimpan di {output_file}")
            btn_save_compressed.config(state='disabled')
            entry_file_compress.config(textvariable="")
            entry_file_compress.delete(0, tk.END)
    else:
        messagebox.showwarning("Peringatan", "Tidak ada data kompresi untuk disimpan!")

def update_file_path(entry, new_path):
    entry.delete(0, tk.END)
    entry.config(state=tk.NORMAL)
    entry.delete(0, tk.END)
    entry.insert(0, new_path)
    entry.config(state=tk.DISABLED)

def start_compression():
    file_path = entry_file_compress.get()
    if file_path:
        compress_file(file_path)
    else:
        messagebox.showwarning("Peringatan", "Pilih file terlebih dahulu!")

def show_window(root):
    for widget in root.winfo_children():
        widget.destroy()
    
    root.title("Kompresi File")

    label_compress = tk.Label(root, text="Kompresi File dengan Metode Deflate", font=("Arial", 24))
    label_compress.place(x=0, y=200, width=800)

    label_file_compress = tk.Label(root, text="Pilih file:", font=("Arial", 18))
    label_file_compress.place(x=200, y=250)
    
    global entry_file_compress
    entry_file_compress = tk.Entry(root)
    entry_file_compress.place(x=200, y=300, width=300, height=50)
    
    btn_browse_compress = tk.Button(root, text="Browse", command=lambda: update_file_path(entry_file_compress, filedialog.askopenfilename()))
    btn_browse_compress.place(x=530, y=300, width=80, height=50)
    
    btn_start_compress = tk.Button(root, text="Mulai Kompresi", command=start_compression)
    btn_start_compress.place(x=270, y=400, height=50)

    global btn_save_compressed
    btn_save_compressed = tk.Button(root, text="Simpan Hasil Kompresi", command=save_compressed_file)
    btn_save_compressed.place(x=410, y=400, height=50, width= 200)
    btn_save_compressed.config(state='disabled')

    global compress_progress_bar
    compress_progress_bar = ttk.Progressbar(root, maximum=100)
    compress_progress_bar.place(x=200, y=480, width=400, height=30)


    btn_back = tk.Button(root, text="Kembali", command=lambda: app.show_main_page(root))
    btn_back.place(x=700, y=10, height=30)

    root.update_idletasks()