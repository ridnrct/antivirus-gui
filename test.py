import tkinter as tk
# import ttkbootstrap as ttk
# from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox, scrolledtext, ttk
from PIL import Image, ImageTk
import requests
import json
import hashlib
import os
import subprocess
import threading 

#Scan File
# Fungsi untuk mengupload file ke VirusTotal dan mendapatkan hasilnya
def scan_with_virustotal(file_path):
    api_key = "93990b132eccaaa0480b85365d57f782d49dbc1f6901ed90cd356c04c8d9a845"  # Ganti dengan API key Anda
    url = "https://www.virustotal.com/api/v3/files"

    headers = {
        "x-apikey": api_key
    }

    file_path = os.path.normpath(file_path)

    try:
        with open(file_path, "rb") as file:
            response = requests.post(url, headers=headers, files={"file": file})

        if response.status_code == 200:
            data = response.json()
            analysis_url = data["data"]["links"]["self"]

            # Mendapatkan hasil analisis
            analysis_response = requests.get(analysis_url, headers=headers)

            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                return analysis_data
            else:
                messagebox.showerror("Error", "Gagal mendapatkan hasil analisis dari VirusTotal.")
                return None
        else:
            messagebox.showerror("Error", "Gagal menghubungi VirusTotal.")
            return None
    except Exception as e:
        messagebox.showerror("Error", f"Gagal membuka file: {e}")
        return None

# Fungsi untuk menganalisis file menggunakan CAPA
def analyze_with_capa(file_path):
    python_path = os.path.join(os.getcwd(), ".venv", "Scripts", "python.exe")

    if not os.path.exists(python_path):
        return "Python di .venv tidak ditemukan. Pastikan .venv telah diaktifkan."

    try:
        result = subprocess.run(
            [python_path, "./capa/main.py", file_path, "-r", "./capa/rules/"],
            capture_output=True,
            text=True,
            encoding="utf-8"
        )

        if result.returncode != 0:
            return f"CAPA gagal dijalankan: {result.stderr}"

        return result.stdout
    except Exception as e:
        return f"CAPA gagal dijalankan: {str(e)}"

# Fungsi untuk memproses file di background
def process_file(file_path):
    try:
        # Tampilkan loading
        start_loading()

        # Proses VirusTotal
        virustotal_result = scan_with_virustotal(file_path)
        if virustotal_result:
            # Menampilkan hasil VirusTotal dalam tabel
            display_virustotal_in_table(virustotal_result)

        # Proses CAPA
        capa_output = analyze_with_capa(file_path)
        if capa_output:
            capa_result_text.delete(1.0, tk.END)
            capa_result_text.insert(tk.END, capa_output)
    finally:
        # Hentikan loading
        stop_loading()

# Fungsi untuk menampilkan hasil VirusTotal dalam tabel
def display_virustotal_in_table(virustotal_result):
    try:
        # Mengambil data dari hasil analisis VirusTotal
        scan_results = virustotal_result["data"]["attributes"]["results"]

        # Menghapus data lama di tabel
        for row in virustotal_table.get_children():
            virustotal_table.delete(row)

        # Menambahkan baris ke tabel
        for scanner, result in scan_results.items():
            # Menyusun hasil untuk setiap scanner
            engine_name = result.get("engine_name", "N/A")
            category = result.get("category", "N/A")
            scan_result = result.get("result", "N/A")

            virustotal_table.insert("", "end", values=(engine_name, category, scan_result))

    except Exception as e:
        messagebox.showerror("Error", f"Error saat menampilkan tabel: {e}")

# Fungsi untuk upload file dan memulai proses di thread
def upload_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        threading.Thread(target=process_file, args=(file_path,), daemon=True).start()

#Scan Direktori
# Fungsi untuk mendapatkan hash dari file

API_KEY = '93990b132eccaaa0480b85365d57f782d49dbc1f6901ed90cd356c04c8d9a845'
URL = 'https://www.virustotal.com/api/v3/files/'

def get_file_hash(file_path, hash_algo='sha256'):
    hash_function = hashlib.new(hash_algo)
    with open(file_path, 'rb') as file:
        while chunk := file.read(4096):
            hash_function.update(chunk)
    return hash_function.hexdigest()

# Variabel untuk menyimpan file malware
malware_files = []

def delete_malware_files(output_text):
    global malware_files
    if malware_files:
        for file in malware_files:
            try:
                os.remove(file)
                output_text.insert(tk.END, f"File {file} berhasil dihapus.\n")
            except Exception as e:
                output_text.insert(tk.END, f"Gagal menghapus file {file}: {e}\n")
        malware_files = []  # Kosongkan daftar setelah penghapusan
        delete_button.config(state="disabled")  # Nonaktifkan tombol
    else:
        output_text.insert(tk.END, "Tidak ada file malware untuk dihapus.\n")
    output_text.yview(tk.END)

# Fungsi untuk memeriksa status file melalui API VirusTotal
def scan_file_with_virustotal(file_path, output_text):
    global malware_files
    file_hash = get_file_hash(file_path)
    headers = {
        "x-apikey": API_KEY
    }
    
    # Kirim permintaan GET ke VirusTotal
    response = requests.get(URL + file_hash, headers=headers)
    
    if response.status_code == 200:
        json_response = response.json()
        data = json_response.get('data', {})
        attributes = data.get('attributes', {})
        malicious = attributes.get('last_analysis_stats', {}).get('malicious', 0)
        
        # Tambahkan hasil path file
        result_text = f"{file_path}: "
        output_text.insert(tk.END, result_text)

        # Tambahkan status hasil
        if malicious > 0:
            alert_text = "ALERT! Terdeteksi malware.\n"
            output_text.insert(tk.END, alert_text, "alert")  # Tambahkan teks dengan tag "alert"
            malware_files.append(file_path)  # Tambahkan file ke daftar malware
        else:
            safe_text = "Aman.\n"
            output_text.insert(tk.END, safe_text)

        # Aktifkan tombol delete jika ada malware
        if malware_files:
            delete_button.config(state="normal")
        
        # Atur scrolling
        output_text.yview(tk.END)
    else:
        output_text.insert(tk.END, f"Gagal memindai {file_path}, status: {response.status_code}\n")
        output_text.yview(tk.END)

    # Konfigurasi tag untuk warna merah
    output_text.tag_config("alert", foreground="red")


# Fungsi untuk memindai semua file dalam sebuah direktori
def scan_directory(directory_path, output_text):
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            output_text.yview(tk.END)
            scan_file_with_virustotal(file_path, output_text)

# Fungsi untuk memilih direktori dan memulai pemindaian
def browse_directory(output_text):
    directory_path = filedialog.askdirectory()
    if directory_path:
        output_text.delete(1.0, tk.END)  # Hapus hasil sebelumnya
        output_text.insert(tk.END, f"Memulai pemindaian pada direktori: {directory_path}\n")
        try:
            start_loading()
            scan_directory(directory_path, output_text)
        finally:
            stop_loading()

# Fungsi untuk menampilkan loading
def start_loading():
    # loading_label.grid(row=4, column=1)
    progress_bar.grid(row=6, columnspan=2, pady=10)
    progress_bar.start()
    upload_button.config(state="disabled")
    browse_button.config(state="disabled")
    root.update()

# Fungsi untuk menghentikan loading
def stop_loading():
    progress_bar.stop()
    progress_bar.grid_forget()
    # loading_label.grid_forget()
    upload_button.config(state="normal")
    browse_button.config(state="normal")
    root.update()

# Palet Warna untuk Tema Gelap
DARK_BG = "#2E2E2E"  # Warna latar belakang utama
DARK_FG = "#FFFFFF"  # Warna teks terang
BTN_BG = "#3E3E3E"   # Warna tombol
BTN_FG = "#FFFFFF"   # Warna teks tombol
HIGHLIGHT_BG = "#5A5A5A"  # Warna aktif tombol
ENTRY_BG = "#3A3A3A"  # Warna latar belakang teks masukan
ENTRY_FG = "#FFFFFF"  # Warna teks masukan

# Root Window
root = tk.Tk()
root.title("Sapapan Antivirus")
root.configure(bg=DARK_BG)

root.rowconfigure(0, weight=1)
root.columnconfigure(1, weight=1)

# Menampilkan Gambar
image_path = "sapapan.png"
try:
    image = Image.open(image_path)
    resized_image = image.resize((200, 680))
    photo = ImageTk.PhotoImage(resized_image)

    image_label = tk.Label(root, image=photo, bg=DARK_BG)
    image_label.image = photo
    image_label.grid(row=0, column=0, sticky="ns")
except Exception as e:
    image_label = tk.Label(root, text="Gambar tidak ditemukan!", fg="red", bg=DARK_BG)
    image_label.grid(row=0, column=0, sticky="ns")

# Frame Kanan
frame_right = tk.Frame(root, bg=DARK_BG)
frame_right.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

# Tombol Upload
upload_button = tk.Button(frame_right, text="Upload File untuk Scan", command=upload_file,
                          bg=BTN_BG, fg=BTN_FG, activebackground=HIGHLIGHT_BG, activeforeground=DARK_FG, font=("Arial", 10, "bold"))
upload_button.grid(pady=10, row=0)

# Tombol Browse
browse_button = tk.Button(frame_right, text="Pilih Direktori", command=lambda: browse_directory(output_text),
                          bg=BTN_BG, fg=BTN_FG, activebackground=HIGHLIGHT_BG, activeforeground=DARK_FG, font=("Arial", 10, "bold"))
browse_button.grid(row=0, column=1, pady=10)

# Label Hasil Scan VirusTotal
virustotal_label = tk.Label(frame_right, text="Hasil Scan File VirusTotal:", fg=DARK_FG, bg=DARK_BG, font=("Arial", 10, "bold"))
virustotal_label.grid(pady=10, row=1, column=0)

virustotal_dir_label = tk.Label(frame_right, text="Hasil Scan Direktori VirusTotal:", fg=DARK_FG, bg=DARK_BG, font=("Arial", 10, "bold"))
virustotal_dir_label.grid(pady=10, row=1, column=1)

# Progress Bar
progress_bar = ttk.Progressbar(frame_right, mode="indeterminate")
progress_bar.style = ttk.Style()
progress_bar.style.theme_use("clam")  # Gunakan tema sederhana yang mendukung kostumisasi

# Tabel Hasil VirusTotal
# Konfigurasi Style untuk Treeview (Tabel)
style = ttk.Style()
style.theme_use("clam")  # Gunakan tema sederhana yang mendukung kustomisasi
style.configure("Dark.Treeview",
                background=DARK_BG,  # Latar belakang tabel
                foreground=DARK_FG,  # Warna teks
                fieldbackground=DARK_BG,  # Latar belakang bidang
                highlightthickness=0,  # Hilangkan border highlight
                font=("Arial", 10))  # Font tabel
style.configure("Dark.Treeview.Heading",
                background=BTN_BG,  # Latar belakang header
                foreground=BTN_FG,  # Warna teks header
                font=("Arial", 10))  # Font header
style.map("Dark.Treeview",
          background=[("selected", HIGHLIGHT_BG)],  # Warna baris yang dipilih
          foreground=[("selected", DARK_FG)])  # Warna teks baris yang dipilih

# Tabel Hasil VirusTotal
# columns = ("Engine Name", "Category", "Result")
virustotal_table = ttk.Treeview(frame_right, height=10, columns=("Engine Name", "Category", "Result"), show="headings", style="Dark.Treeview")
virustotal_table.heading("Engine Name", text="Engine Name", anchor="center")
virustotal_table.heading("Category", text="Category", anchor="center")
virustotal_table.heading("Result", text="Result", anchor="center")
virustotal_table.column("Engine Name", anchor="center", width=100)
virustotal_table.column("Category", anchor="center", width=100)
virustotal_table.column("Result", anchor="center", width=200)
virustotal_table.grid(row=2)

# Label Hasil CAPA
capa_label = tk.Label(frame_right, text="Hasil Scan CAPA (Teknik Serangan):", fg=DARK_FG, bg=DARK_BG, font=("Arial", 10, "bold"))
capa_label.grid(pady=10, row=3)

# Teks Hasil CAPA
capa_result_text = tk.Text(frame_right, height=15, width=102, bg=ENTRY_BG, fg=ENTRY_FG, insertbackground=DARK_FG)
capa_result_text.grid(row=5, columnspan=2, sticky="w")

# Teks Output
output_text = tk.Text(frame_right, width=50, height=14, bg=ENTRY_BG, fg=ENTRY_FG, insertbackground=DARK_FG)
output_text.grid(row=2, column=1, padx=10, pady=10)

delete_button = tk.Button(frame_right, text="Delete Malware", bg=BTN_BG, fg=BTN_FG, command=lambda: delete_malware_files(output_text))
delete_button.grid(row=3, column=1, pady=5)
delete_button.config(state="disabled")  # Nonaktifkan secara defaul

root.mainloop()

# # root = ttk.Window(themename="darkly")
# root = tk.Tk()
# root.title("Sapapan Antivirus")
# root.configure(bg="#2E2E2E")

# root.rowconfigure(0, weight=1)
# root.columnconfigure(1, weight=1)

# image_path = "sapapan.png"
# try:
#     image = Image.open(image_path)
#     resized_image = image.resize((200, 720))
#     photo = ImageTk.PhotoImage(resized_image)

#     image_label = tk.Label(root, image=photo, bg="#2E2E2E")
#     image_label.image = photo
#     image_label.grid(row=0, column=0, sticky="ns")
# except Exception as e:
#     image_label = tk.Label(root, text="Gambar tidak ditemukan!", fg="red", bootstyle="danger")
#     image_label.grid(row=0, column=0, sticky="ns")

# frame_right = ttk.Frame(root)
# frame_right.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
# frame_right.configure(style="Dark.TFrame")

# # Tema untuk Label dan tombol
# style = ttk.Style()
# style.theme_use("clam")  # Pastikan menggunakan tema yang mendukung custom style
# style.configure("Dark.TFrame", background="#2E2E2E")
# style.configure("Dark.TLabel", background="#2E2E2E", foreground="white", font=("Arial", 10))
# style.configure("Dark.TButton", background="#3A3A3A", foreground="white", font=("Arial", 10))
# style.map("Dark.TButton", background=[("active", "#5A5A5A")])

# upload_button = ttk.Button(frame_right, text="Upload File untuk Scan", command=upload_file,  style="Dark.TButton")
# upload_button.grid(pady=10, row=0)

# browse_button = ttk.Button(frame_right, text="Pilih Direktori", command=lambda: browse_directory(output_text), style="Dark.TButton")
# browse_button.grid(row=0, column=1, pady=10)

# virustotal_label = ttk.Label(frame_right, text="Hasil Scan File VirusTotal:")
# virustotal_label.grid(pady=10, row=1, column=0)
# virustotal_label = ttk.Label(frame_right, text="Hasil Scan Direktori VirusTotal:")
# virustotal_label.grid(pady=10, row=1, column=1)

# # loading_label = ttk.Label(frame_right, text="Sedang memproses, harap tunggu...", bootstyle="danger")
# progress_bar = ttk.Progressbar(frame_right, mode="indeterminate")

# virustotal_table = ttk.Treeview(frame_right, height=10, columns=("Engine Name", "Category", "Result"), show="headings")
# virustotal_table.heading("Engine Name", text="Engine Name")
# virustotal_table.heading("Category", text="Category")
# virustotal_table.heading("Result", text="Result")
# virustotal_table.grid(row=2)

# capa_label = ttk.Label(frame_right, text="Hasil Scan CAPA (Teknik Serangan):")
# capa_label.grid(pady=10, row=4)

# capa_result_text = tk.Text(frame_right, height=15, width=100)
# capa_result_text.grid(row=5, columnspan=2, sticky="w")

# output_text = tk.Text(frame_right, width=75, height=11)
# output_text.grid(row=2, column=1, padx=10, pady=10)

# root.mainloop()
