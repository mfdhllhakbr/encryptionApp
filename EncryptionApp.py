import RSA as rsa
import tkinter as tk
import Twofish as tf
import Compress as compress
import Decompress as decompress

def center_window(window, width, height):
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width // 2) - (width // 2)
    y = (screen_height // 2) - (height // 2)
    window.geometry(f'{width}x{height}+{x}+{y}')

def show_main_page(root):
    for widget in root.winfo_children():
        widget.destroy()

    root.title("Halaman Utama")
    
    # Membuat tombol-tombol untuk setiap fitur
    btn_feature1 = tk.Button(root, text="RSA", command=lambda: rsa.show_window(root))
    btn_feature1.place(x=150, y=225, width=200, height=50)
    
    btn_feature2 = tk.Button(root, text="Twofish", command=lambda: tf.show_window(root))
    btn_feature2.place(x=450, y=225, width=200, height=50)
    
    btn_feature3 = tk.Button(root, text="Kompresi\nDeflate", command=lambda: compress.show_window(root))
    btn_feature3.place(x=150, y=350, width=200, height=50)
    
    btn_feature4 = tk.Button(root, text="Dekompresi\nDeflate", command=lambda: decompress.show_window(root))
    btn_feature4.place(x=450, y=350, width=200, height=50)

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Halaman Utama")
    root.geometry("800x650")

    center_window(root, 800, 650)

    show_main_page(root)

    root.mainloop()
