# Supraja Project: Automated Recon Tool

**Automatic Reconnaissance with Python** is a GUI-based OSINT and penetration testing tool designed for cybersecurity enthusiasts, students, and professionals. It gathers information about a target domain using local recon methods and external APIs, generates detailed PDF reports, and can optionally send them via email.

---

## Features

- **GUI – Simulation Tool**
  - Interactive Tkinter interface.
  - Buttons for Start Recon, Clear Output, and Project Info.
  - Real-time log display of reconnaissance results.

- **Infogathering Using OSINT**
  - Domain IP & Geolocation
  - WHOIS information
  - DNS records (A, AAAA, MX, NS, TXT)
  - HTTP headers
  - SSL certificate information
  - Admin panel brute-force checking
  - HTML meta tag scraping
  - Technology stack detection

- **Tools API Integration**
  - Uses [HackerTarget APIs](https://hackertarget.com) for:
    - DNS Lookup
    - Reverse IP Lookup
    - Traceroute
    - Subdomain Enumeration

- **PDF Report Generation**
  - Generates detailed PDF reports of all reconnaissance activities.
  - Saved in `output/results/`.

- **Automatic Email Function**
  - Optionally send PDF reports via SMTP.

- **Installable EXE**
  - Can be converted into a standalone Windows executable using PyInstaller.

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/pavan3020/Supraja_project.git
   cd Supraja_project
Create and activate a virtual environment (optional but recommended):

bash
Copy code
python -m venv venv
venv\Scripts\activate   # Windows
source venv/bin/activate # Linux/Mac
Install dependencies:

bash
Copy code
pip install -r requirements.txt
Chrome WebDriver

Download ChromeDriver matching your Chrome version.

Place it in the project folder or add to your system PATH.

Usage
Run the GUI:

bash
Copy code
python automatic_recon_gui.py
Enter the target domain (e.g., example.com) and click Start Recon.

View logs in GUI.

PDF reports are saved in output/results/.

Screenshots are saved in output/screenshots/.

Configure email in the script to send reports automatically.

Folder Structure
bash
Copy code
Supraja_project/
│
├─ assets/                # GUI assets (icons, backgrounds)
├─ output/
│   ├─ results/           # PDF reports
│   └─ screenshots/       # Website screenshots
├─ automatic_recon_gui.py # Main GUI script
├─ requirements.txt       # Python dependencies
└─ README.md              # This file
