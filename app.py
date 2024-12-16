import tkinter as tk
from tkinter import filedialog, messagebox
import requests
import json
import os
import subprocess

# Fungsi untuk mengupload file ke VirusTotal dan mendapatkan hasilnya
# Fungsi untuk mengupload file ke VirusTotal dan mendapatkan hasilnya
def scan_with_virustotal(file_path):
    api_key = "93990b132eccaaa0480b85365d57f782d49dbc1f6901ed90cd356c04c8d9a845"  # Ganti dengan API key Anda
    url = "https://www.virustotal.com/api/v3/files"

    headers = {
        "x-apikey": api_key
    }

    # Normalisasi jalur file
    file_path = os.path.normpath(file_path)

    # Baca file
    try:
        with open(file_path, "rb") as file:
            response = requests.post(url, headers=headers, files={"file": file})

        if response.status_code == 200:
            data = response.json()
            analysis_url = data["data"]["links"]["self"]  # Ambil URL analisis lengkap

            # Mendapatkan hasil analisis dengan permintaan GET
            analysis_response = requests.get(analysis_url, headers=headers)

            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                return analysis_data  # Mengembalikan hasil analisis lengkap
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
    # Tentukan path ke Python di .venv
    python_path = os.path.join(os.getcwd(), ".venv", "Scripts", "python.exe")

    # Periksa apakah path Python ada
    if not os.path.exists(python_path):
        return "Python di .venv tidak ditemukan. Pastikan .venv telah diaktifkan."

    try:
        result = subprocess.run(
            [python_path, "./capa/capa/main.py", file_path, "-r", "./capa/capa/rules/"],
            capture_output=True,
            text=True,  # Pastikan text=True, agar output adalah string
            encoding='utf-8'  # Tentukan encoding yang benar
        )

        # Logging hasil ke file
        with open("capa_log.txt", "w", encoding="utf-8") as log_file:
            log_file.write(f"STDOUT:\n{result.stdout}\n")
            log_file.write(f"STDERR:\n{result.stderr}\n")

        if result.returncode != 0:
            return f"CAPA gagal dijalankan: {result.stderr}"

        return result.stdout
    except Exception as e:
        with open("capa_error_log.txt", "w") as error_file:
            error_file.write(str(e))
        return "CAPA gagal dijalankan."

# Fungsi untuk menangani file upload dan scan
def upload_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        messagebox.showinfo("Info", f"File terpilih: {file_path}")

        # Proses VirusTotal
        virustotal_result = scan_with_virustotal(file_path)
        if virustotal_result:
            virustotal_output = json.dumps(virustotal_result, indent=4)
            virustotal_result_text.delete(1.0, tk.END)
            virustotal_result_text.insert(tk.END, virustotal_output)

        # Proses CAPA
        capa_output = analyze_with_capa(file_path)

        # Cek apakah capa_output adalah string yang valid sebelum memasukkannya ke Text widget
        if isinstance(capa_output, str):
            capa_result_text.delete(1.0, tk.END)
            capa_result_text.insert(tk.END, capa_output)
        else:
            messagebox.showerror("Error", "Output CAPA tidak valid.")

# Membuat antarmuka pengguna (GUI)
root = tk.Tk()
root.title("Antivirus GUI dengan VirusTotal dan CAPA")

# Menambahkan tombol untuk memilih file
upload_button = tk.Button(root, text="Upload File untuk Scan", command=upload_file)
upload_button.pack(pady=20)

# Menambahkan area untuk menampilkan hasil VirusTotal
virustotal_label = tk.Label(root, text="Hasil VirusTotal:")
virustotal_label.pack()

virustotal_result_text = tk.Text(root, height=15, width=100)
virustotal_result_text.pack()

# Menambahkan area untuk menampilkan hasil CAPA
capa_label = tk.Label(root, text="Hasil CAPA (Teknik Serangan):")
capa_label.pack()

capa_result_text = tk.Text(root, height=15, width=100)
capa_result_text.pack()

# Menjalankan GUI
root.mainloop()
