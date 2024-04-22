import tkinter as tk
from tkinter import ttk

def close_splash_screen():
    splash_screen.destroy()
    root.deiconify()

# Membuat splash screen
splash_screen = tk.Tk()
splash_screen.title("Splash Screen")
splash_screen.geometry("400x300")

# Menampilkan gambar atau teks splash screen
splash_label = ttk.Label(splash_screen, text="Ini adalah splash screen", font=("Arial", 20))
splash_label.pack(pady=50)

# Menambahkan timer untuk menutup splash screen setelah beberapa detik (misalnya, 3 detik)
splash_screen.after(3000, close_splash_screen)

# Menjalankan splash screen
splash_screen.mainloop()

# Membuat halaman utama setelah splash screen ditutup
root = tk.Tk()
root.title("Halaman Utama")

# Tambahkan elemen GUI untuk halaman utama di sini...

root.mainloop()
