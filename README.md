# Malware Scanning - VirusTotal & Capa

## Background
With the increasing threat of cyber attacks, the need for antivirus software capable of detecting and analyzing malware has become more urgent. Sapapan Antivirus was developed as a solution to help users detect malicious files using VirusTotal API-based analysis and static techniques from CAPA (Capability Analysis). This application is designed to provide analysis results that are easy for users to understand.

## Objectives
1. Provide an effective malware detection tool for individual users.
2. Integrate the VirusTotal API for security engine-based analysis.
3. Use CAPA to identify malware behavior patterns based on predefined rules.

## Components
Sapapan Antivirus consists of several main components:

1. **User Interface (GUI):**
   - Built using the Python Tkinter library, providing an intuitive interface for file uploads, directory selection, and displaying analysis results.

2. **VirusTotal Analysis:**
   - Utilizes the VirusTotal API to scan files and generate reports from multiple security engines.

3. **CAPA Analysis:**
   - Uses the CAPA framework to detect techniques or malicious behavior based on static rules.

4. **Malware File Management:**
   - A feature to delete detected malicious files directly from the user system.

## How It Works

1. **File Scanning:**
   - Users upload a file through the GUI.
   - The file is analyzed using the VirusTotal API.

2. **Directory Scanning:**
   - Users select a directory to scan all files within it.
   - Each file is analyzed by obtaining its hash and sending it to the VirusTotal API.

3. **CAPA Analysis:**
   - The scanned file is analyzed using CAPA to detect specific behavior patterns based on predefined rules.

4. **Reporting:**
   - VirusTotal analysis results are displayed in a table detailing detection engines, categories, and findings.
   - CAPA results are displayed in a text format containing descriptions of detected behaviors.

5. **Malware Removal:**
   - Detected malicious files can be deleted directly from the system through the automatic removal feature.

## Application Workflow

1. **Start Application:**
   - Users open the Sapapan Antivirus application.

2. **Upload File or Select Directory:**
   - Users select a file or directory for analysis.

3. **Analysis Process:**
   - Files are analyzed in parallel by the VirusTotal API and CAPA.
   - A loading bar provides progress information.

4. **Displaying Results:**
   - The VirusTotal results table shows detection details from each engine.
   - CAPA analysis results provide an overview of detected attack techniques.

5. **Follow-up Actions:**
   - If a file is detected as malware, users can choose to delete it directly through the application.
