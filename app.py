import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from PIL import Image, ImageTk
import requests
import json
import hashlib
import os
import subprocess
import threading 

def scan_with_virustotal(file_path):
    api_key = "93990b132eccaaa0480b85365d57f782d49dbc1f6901ed90cd356c04c8d9a845"  
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
            analysis_response = requests.get(analysis_url, headers=headers)
            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                return analysis_data
            else:
                messagebox.showerror("Error", "Failed to get analysis results from VirusTotal.")
                return None
        else:
            messagebox.showerror("Error", "Failed to connect VirusTotal.")
            return None
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open file: {e}")
        return None
        
def analyze_with_capa(file_path):
    python_path = os.path.join(os.getcwd(), ".venv", "Scripts", "python.exe")
    if not os.path.exists(python_path):
        return "Python in .venv not found. Make sure .venv is enabled."
    try:
        result = subprocess.run(
            [python_path, "./capa/main.py", file_path, "-r", "./capa/rules/"],
            capture_output=True,
            text=True,
            encoding="utf-8"
        )
        if result.returncode != 0:
            return f"CAPA failed to run: {result.stderr}"

        return result.stdout
    except Exception as e:
        return f"CAPA failed to run: {str(e)}"
        
def process_file(file_path):
    try:
        start_loading()
        virustotal_result = scan_with_virustotal(file_path)
        if virustotal_result:
            display_virustotal_in_table(virustotal_result)
        capa_output = analyze_with_capa(file_path)
        if capa_output:
            capa_result_text.delete(1.0, tk.END)
            capa_result_text.insert(tk.END, capa_output)
    finally:
        stop_loading()

def display_virustotal_in_table(virustotal_result):
    try:
        scan_results = virustotal_result["data"]["attributes"]["results"]
        for row in virustotal_table.get_children():
            virustotal_table.delete(row)
        for scanner, result in scan_results.items():
            engine_name = result.get("engine_name", "N/A")
            category = result.get("category", "N/A")
            scan_result = result.get("result", "N/A")
            virustotal_table.insert("", "end", values=(engine_name, category, scan_result))
    except Exception as e:
        messagebox.showerror("Error", f"Error displaying the table: {e}")

def upload_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        threading.Thread(target=process_file, args=(file_path,), daemon=True).start()

API_KEY = '93990b132eccaaa0480b85365d57f782d49dbc1f6901ed90cd356c04c8d9a845'
URL = 'https://www.virustotal.com/api/v3/files/'

def get_file_hash(file_path, hash_algo='sha256'):
    hash_function = hashlib.new(hash_algo)
    with open(file_path, 'rb') as file:
        while chunk := file.read(4096):
            hash_function.update(chunk)
    return hash_function.hexdigest()

malware_files = []

def delete_malware_files(output_text):
    global malware_files
    if malware_files:
        for file in malware_files:
            try:
                os.remove(file)
                output_text.insert(tk.END, f"File {file} was successfully deleted.\n")
            except Exception as e:
                output_text.insert(tk.END, f"Failed to delete the file {file}: {e}\n")
        malware_files = []  
        delete_button.config(state="disabled")  
    else:
        output_text.insert(tk.END, "There is no malware file to delete.\n")
    output_text.yview(tk.END)

def scan_file_with_virustotal(file_path, output_text):
    global malware_files
    file_hash = get_file_hash(file_path)
    headers = {
        "x-apikey": API_KEY
    }
    response = requests.get(URL + file_hash, headers=headers)
    
    if response.status_code == 200:
        json_response = response.json()
        data = json_response.get('data', {})
        attributes = data.get('attributes', {})
        malicious = attributes.get('last_analysis_stats', {}).get('malicious', 0)
        result_text = f"{file_path}: "
        output_text.insert(tk.END, result_text)
        if malicious > 0:
            alert_text = "ALERT! Terdeteksi malware.\n"
            output_text.insert(tk.END, alert_text, "alert")  
            malware_files.append(file_path)  
        else:
            safe_text = "Aman.\n"
            output_text.insert(tk.END, safe_text)
        if malware_files:
            delete_button.config(state="normal")
        output_text.yview(tk.END)
    else:
        output_text.insert(tk.END, f"Failed to scan {file_path}, status: {response.status_code}\n")
        output_text.yview(tk.END)
    output_text.tag_config("alert", foreground="red")

def scan_directory(directory_path, output_text):
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            output_text.yview(tk.END)
            scan_file_with_virustotal(file_path, output_text)

def browse_directory(output_text):
    directory_path = filedialog.askdirectory()
    if directory_path:
        output_text.delete(1.0, tk.END)  
        output_text.insert(tk.END, f"Starting scan on the directory: {directory_path}\n")
        try:
            start_loading()
            scan_directory(directory_path, output_text)
        finally:
            stop_loading()

def start_loading():
    progress_bar.grid(row=6, columnspan=2, pady=10)
    progress_bar.start()
    upload_button.config(state="disabled")
    browse_button.config(state="disabled")
    root.update()

def stop_loading():
    progress_bar.stop()
    progress_bar.grid_forget()
    upload_button.config(state="normal")
    browse_button.config(state="normal")
    root.update()

DARK_BG = "#2E2E2E"  
DARK_FG = "#FFFFFF"  
BTN_BG = "#3E3E3E"   
BTN_FG = "#FFFFFF"   
HIGHLIGHT_BG = "#5A5A5A"  
ENTRY_BG = "#3A3A3A"  
ENTRY_FG = "#FFFFFF"  

root = tk.Tk()
root.title("Sapapan Antivirus")
root.configure(bg=DARK_BG)
root.rowconfigure(0, weight=1)
root.columnconfigure(1, weight=1)

image_path = "sapapan.png"
try:
    image = Image.open(image_path)
    resized_image = image.resize((200, 680))
    photo = ImageTk.PhotoImage(resized_image)

    image_label = tk.Label(root, image=photo, bg=DARK_BG)
    image_label.image = photo
    image_label.grid(row=0, column=0, sticky="ns")
except Exception as e:
    image_label = tk.Label(root, text="Image not found!", fg="red", bg=DARK_BG)
    image_label.grid(row=0, column=0, sticky="ns")

frame_right = tk.Frame(root, bg=DARK_BG)
frame_right.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

upload_button = tk.Button(frame_right, text="Upload file to scan", command=upload_file,
                          bg=BTN_BG, fg=BTN_FG, activebackground=HIGHLIGHT_BG, activeforeground=DARK_FG, font=("Arial", 10, "bold"))
upload_button.grid(pady=10, row=0)

browse_button = tk.Button(frame_right, text="Select directory", command=lambda: browse_directory(output_text),
                          bg=BTN_BG, fg=BTN_FG, activebackground=HIGHLIGHT_BG, activeforeground=DARK_FG, font=("Arial", 10, "bold"))
browse_button.grid(row=0, column=1, pady=10)

virustotal_label = tk.Label(frame_right, text="VirusTotal file scan results:", fg=DARK_FG, bg=DARK_BG, font=("Arial", 10, "bold"))
virustotal_label.grid(pady=10, row=1, column=0)

virustotal_dir_label = tk.Label(frame_right, text="VirusTotal directory scan results:", fg=DARK_FG, bg=DARK_BG, font=("Arial", 10, "bold"))
virustotal_dir_label.grid(pady=10, row=1, column=1)

progress_bar = ttk.Progressbar(frame_right, mode="indeterminate")
progress_bar.style = ttk.Style()
progress_bar.style.theme_use("clam")  

style = ttk.Style()
style.theme_use("clam")  
style.configure("Dark.Treeview",
                background=DARK_BG,  
                foreground=DARK_FG,  
                fieldbackground=DARK_BG,  
                highlightthickness=0,  
                font=("Arial", 10))  
style.configure("Dark.Treeview.Heading",
                background=BTN_BG,  
                foreground=BTN_FG,  
                font=("Arial", 10))  
style.map("Dark.Treeview",
          background=[("selected", HIGHLIGHT_BG)],  
          foreground=[("selected", DARK_FG)])  

virustotal_table = ttk.Treeview(frame_right, height=10, columns=("Engine Name", "Category", "Result"), show="headings", style="Dark.Treeview")
virustotal_table.heading("Engine Name", text="Engine Name", anchor="center")
virustotal_table.heading("Category", text="Category", anchor="center")
virustotal_table.heading("Result", text="Result", anchor="center")
virustotal_table.column("Engine Name", anchor="center", width=100)
virustotal_table.column("Category", anchor="center", width=100)
virustotal_table.column("Result", anchor="center", width=200)
virustotal_table.grid(row=2)

capa_label = tk.Label(frame_right, text="Hasil Scan CAPA (Teknik Serangan):", fg=DARK_FG, bg=DARK_BG, font=("Arial", 10, "bold"))
capa_label.grid(pady=10, row=3)

capa_result_text = tk.Text(frame_right, height=15, width=102, bg=ENTRY_BG, fg=ENTRY_FG, insertbackground=DARK_FG)
capa_result_text.grid(row=5, columnspan=2, sticky="w")

output_text = tk.Text(frame_right, width=50, height=14, bg=ENTRY_BG, fg=ENTRY_FG, insertbackground=DARK_FG)
output_text.grid(row=2, column=1, padx=10, pady=10)

delete_button = tk.Button(frame_right, text="Delete Malware", bg=BTN_BG, fg=BTN_FG, command=lambda: delete_malware_files(output_text))
delete_button.grid(row=3, column=1, pady=5)
delete_button.config(state="disabled")  

root.mainloop()
