import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
import requests
import json
import os
import subprocess
import threading  # Untuk threading

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
        messagebox.showinfo("Info", f"File terpilih: {file_path}")
        threading.Thread(target=process_file, args=(file_path,), daemon=True).start()

# Fungsi untuk menampilkan loading
def start_loading():
    loading_label.pack()
    progress_bar.pack()
    progress_bar.start()
    upload_button.config(state="disabled")
    root.update()

# Fungsi untuk menghentikan loading
def stop_loading():
    progress_bar.stop()
    progress_bar.pack_forget()
    loading_label.pack_forget()
    upload_button.config(state="normal")
    root.update()

# Membuat antarmuka pengguna (GUI)
root = tk.Tk()
root.title("Sapapan Antivirus")

# Atur grid layout
root.rowconfigure(0, weight=1)
root.columnconfigure(1, weight=1)

# Menambahkan gambar di sisi kiri
image_path = "team.jpg"
try:
    image = Image.open(image_path)
    resized_image = image.resize((200, 640))
    photo = ImageTk.PhotoImage(resized_image)

    image_label = tk.Label(root, image=photo)
    image_label.image = photo
    image_label.grid(row=0, column=0, sticky="ns")
except Exception as e:
    image_label = tk.Label(root, text="Gambar tidak ditemukan!", fg="red")
    image_label.grid(row=0, column=0, sticky="ns")

# Frame kanan untuk elemen lainnya
frame_right = tk.Frame(root)
frame_right.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

# Tambahkan tombol untuk memilih file
upload_button = tk.Button(frame_right, text="Upload File untuk Scan", command=upload_file)
upload_button.pack(pady=20)

# Menambahkan indikator loading
loading_label = tk.Label(frame_right, text="Sedang memproses, harap tunggu...", fg="red")
progress_bar = ttk.Progressbar(frame_right, mode="indeterminate")

# Menambahkan area untuk menampilkan hasil VirusTotal
virustotal_label = tk.Label(frame_right, text="Hasil VirusTotal:")
virustotal_label.pack()

# Membuat tabel untuk menampilkan hasil VirusTotal
virustotal_table = ttk.Treeview(frame_right, columns=("Engine Name", "Category", "Result"), show="headings")
virustotal_table.heading("Engine Name", text="Engine Name")
virustotal_table.heading("Category", text="Category")
virustotal_table.heading("Result", text="Result")
virustotal_table.pack()

# Menambahkan area untuk menampilkan hasil CAPA
capa_label = tk.Label(frame_right, text="Hasil CAPA (Teknik Serangan):")
capa_label.pack()

capa_result_text = tk.Text(frame_right, height=15, width=85)
capa_result_text.pack()

# Menjalankan GUI
root.mainloop()
