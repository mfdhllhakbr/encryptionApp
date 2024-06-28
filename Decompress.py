import zlib
import time
import threading
import tkinter as tk
import EncryptionApp as app
from tkinter import ttk, filedialog, messagebox

decompressed_data = None

def decompress_file(input_file):
    global decompressed_data
    decompress_progress_bar['value'] = 0
    decompress_progress_bar.update_idletasks()

    decompress_estimated_time_label.config(text="")

    # Validasi ekstensi file
    if not input_file.endswith('.bak.deflate'):
        messagebox.showerror("Error", "File harus berformat .bak.deflate")
        return

    def decompression_task():
        global decompressed_data
        with open(input_file, 'rb') as f_in:
            data = f_in.read()
            original_size = len(data) # Ukuran file sebelum di kompresi
            decompress_progress_bar['maximum'] = len(data)
            decompress_progress_bar['value'] = 0
            batch_size = 1024 * 10  # Batasi pembaruan progress bar setiap 10KB
            next_update = batch_size
            
            decompressor = zlib.decompressobj()
            decompressed_data_chunks = []
            start_time = time.time()
            
            for i in range(0, len(data), 1024):
                chunk = data[i:i+1024]
                decompressed_chunk = decompressor.decompress(chunk)
                decompressed_data_chunks.append(decompressed_chunk)

                if decompress_progress_bar['value'] + len(chunk) >= next_update:
                    decompress_progress_bar['value'] += len(chunk)
                    next_update += batch_size
                else:
                    decompress_progress_bar['value'] += len(chunk)

            decompressed_data_chunks.append(decompressor.flush())
            decompressed_data = b''.join(decompressed_data_chunks)
            decompressed_size = len(decompressed_data)  # Ukuran file setelah kompresi
            decompress_progress_bar['value'] = len(data)

            elapsed_time = time.time() - start_time
            hours, remainder = divmod(elapsed_time, 3600)
            minutes, seconds = divmod(remainder, 60)
            decompress_estimated_time_label.config(text=f"Waktu dekompresi: {int(hours)} jam {int(minutes)} menit {int(seconds)} detik / {elapsed_time:.5f} detik.")
            
            original_size_kb = int(original_size / 1024)
            decompressed_size_kb = int(decompressed_size / 1024)
            original_size_label.config(text=f"Ukuran file kompresi: {original_size_kb:} KB")
            decompressed_size_label.config(text=f"Ukuran setelah dekompresi: {decompressed_size_kb:} KB")
            
            messagebox.showinfo("Info", "Dekompresi selesai!")
            btn_save_decompress.config(state='normal')

    threading.Thread(target=decompression_task).start()

def save_decompressed_file():
    global decompressed_data
    if decompressed_data is not None:
        output_file = filedialog.asksaveasfilename(defaultextension=".encrypted", filetypes=[("Encrypted Files", ".encrypted")])
        if output_file:
            with open(output_file, 'wb') as f_out:
                f_out.write(decompressed_data)
            messagebox.showinfo("Info", f"Hasil dekompresi disimpan di {output_file}")
            btn_save_decompress.config(state='disabled')
            entry_file_decompress.config(textvariable="")
            entry_file_decompress.delete(0, tk.END)
    else:
        messagebox.showwarning("Peringatan", "Tidak ada data dekompresi untuk disimpan!")

def update_file_path(entry, new_path):
    entry.delete(0, tk.END)
    entry.config(state=tk.NORMAL)
    entry.delete(0, tk.END)
    entry.insert(0, new_path)
    entry.config(state=tk.DISABLED)

def start_decompress():
    file_path = entry_file_decompress.get()
    if file_path.endswith('.deflate'):
        decompress_file(file_path)
    else:
        messagebox.showwarning("Peringatan", "Pilih file .deflate untuk didekompresi!")

def show_window(root):
    for widget in root.winfo_children():
        widget.destroy()
    
    root.title("Dekompresi File")

    label_decompress = tk.Label(root, text="Dekompresi File dengan Metode Deflate", font=("Arial", 24))
    label_decompress.place(x=0, y=200, width=800)

    label_file_decompress = tk.Label(root, text="Pilih file:", font=("Arial", 18))
    label_file_decompress.place(x=200, y=250)
    
    global entry_file_decompress
    entry_file_decompress = tk.Entry(root)
    entry_file_decompress.place(x=200, y=300, width=300, height=50)
    
    btn_browse_decompress = tk.Button(root, text="Browse", command=lambda: update_file_path(entry_file_decompress, filedialog.askopenfilename()))
    btn_browse_decompress.place(x=530, y=300, width=80, height=50)
    
    btn_start_decompress = tk.Button(root, text="Mulai Dekompresi", command=start_decompress)
    btn_start_decompress.place(x=260, y=400, height=50)

    global btn_save_decompress
    btn_save_decompress = tk.Button(root, text="Simpan Hasil Dekompresi", command=save_decompressed_file)
    btn_save_decompress.place(x=410, y=400, height=50, width= 200)
    btn_save_decompress.config(state='disabled')

    global decompress_progress_bar
    decompress_progress_bar = ttk.Progressbar(root, maximum=100)
    decompress_progress_bar.place(x=200, y=480, width=400, height=30)

    global decompress_estimated_time_label
    decompress_estimated_time_label = tk.Message(root, text="", font=("Arial", 14), width=350)
    decompress_estimated_time_label.place(x=200, y=500, height=30, width=350)

    global original_size_label
    original_size_label = tk.Message(root, text="", font=("Arial", 14), width=400)
    original_size_label.place(x=200, y=540, height=30, width=400)

    global decompressed_size_label
    decompressed_size_label = tk.Message(root, text="", font=("Arial", 14), width=400)
    decompressed_size_label.place(x=200, y=560, height=30, width=400)

    btn_back = tk.Button(root, text="Kembali", command=lambda: app.show_main_page(root))
    btn_back.place(x=700, y=10, height=30)

    root.update_idletasks()