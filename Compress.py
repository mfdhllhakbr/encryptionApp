import zlib
import time
import threading
import tkinter as tk
import EncryptionApp as app
from tkinter import ttk, filedialog, messagebox

compressed_data = None

def compress_file(input_file):
    global compressed_data
    compress_progress_bar['value'] = 0
    compress_progress_bar.update_idletasks()

    compress_estimated_time_label.config(text="")

    # Validasi ekstensi file
    if not input_file.endswith('.bak'):
        messagebox.showerror("Error", "File harus berformat .bak")
        return

    def compression_task():
        global compressed_data
        with open(input_file, 'rb') as f_in:
            data = f_in.read()
            compress_progress_bar['maximum'] = len(data)
            compress_progress_bar['value'] = 0
            batch_size = 1024 * 10  # Batasi pembaruan progress bar setiap 10KB
            next_update = batch_size
            
            compressor = zlib.compressobj(level=9)
            compressed_data_chunks = []
            start_time = time.time()
            
            for i in range(0, len(data), 1024):
                chunk = data[i:i+1024]
                compressed_chunk = compressor.compress(chunk)
                compressed_data_chunks.append(compressed_chunk)

                if compress_progress_bar['value'] + len(chunk) >= next_update:
                    compress_progress_bar['value'] += len(chunk)
                    next_update += batch_size
                else:
                    compress_progress_bar['value'] += len(chunk)

            compressed_data_chunks.append(compressor.flush())
            compressed_data = b''.join(compressed_data_chunks)
            compress_progress_bar['value'] = len(data)

            elapsed_time = time.time() - start_time
            hours, remainder = divmod(elapsed_time, 3600)
            minutes, seconds = divmod(remainder, 60)
            compress_estimated_time_label.config(text=f"Waktu kompresi: {int(hours)} jam {int(minutes)} menit {int(seconds)} detik / {elapsed_time:.5f} detik.")
            messagebox.showinfo("Info", "Kompresi selesai!")
            btn_save_compressed.config(state='normal')

    threading.Thread(target=compression_task).start()

def save_compressed_file():
    global compressed_data
    if compressed_data is not None:
        output_file = filedialog.asksaveasfilename(defaultextension=".bak.deflate", filetypes=[("Deflate files", "*.bak.deflate")])
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
    
    btn_start_compress = tk.Button(root, text="Compress File", command=lambda: compress_file(entry_file_compress.get()))
    btn_start_compress.place(x=270, y=400, height=50)

    global btn_save_compressed
    btn_save_compressed = tk.Button(root, text="Simpan Hasil Kompresi", command=save_compressed_file)
    btn_save_compressed.place(x=410, y=400, height=50, width= 200)
    btn_save_compressed.config(state='disabled')

    global compress_progress_bar
    compress_progress_bar = ttk.Progressbar(root, maximum=100)
    compress_progress_bar.place(x=200, y=480, width=400, height=30)

    global compress_estimated_time_label
    compress_estimated_time_label = tk.Message(root, text="", font=("Arial", 14), width=350)
    compress_estimated_time_label.place(x=200, y=500, height=30, width=350)

    btn_back = tk.Button(root, text="Kembali", command=lambda: app.show_main_page(root))
    btn_back.place(x=700, y=10, height=30)

    root.update_idletasks()