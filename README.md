1. Project Title & Description

Title: Automated Recon Tool

Description: A Python GUI-based OSINT and penetration testing tool for gathering information on a target domain, generating PDF reports, and optionally sending email reports.

2. Features / Enhancements

List the main functionalities clearly:

GUI – Interactive interface with Start/Clear/Project Info buttons.

OSINT Infogathering: IP, Geolocation, Whois, DNS, HTTP headers, SSL info, Admin panel paths, HTML meta tags, Tech stack.

HackerTarget API integration: DNS Lookup, Reverse IP, Traceroute, Subdomain enumeration.

Generate PDF reports with full reconnaissance details.

Optional email sending of PDF reports.

Can be packaged as a standalone EXE.

3. Installation Instructions

Clone the repo.

Create and activate a Python virtual environment (optional).

Install dependencies via pip install -r requirements.txt.

Download ChromeDriver for Selenium.

4. Usage

Run the Python GUI script: python automatic_recon_gui.py.

Enter the target domain and click Start Recon.

View results in GUI, screenshots in output/screenshots, and PDF reports in output/results.

Optionally, configure email to send PDF reports automatically.

5. Folder Structure
Recon_Tool/
│
├─ assets/                # GUI assets (icons, background)
├─ output/
│   ├─ results/           # PDF reports
│   └─ screenshots/       # Website screenshots
├─ automatic_recon_gui.py # Main Python GUI script
├─ requirements.txt       # Python dependencies
└─ README.md              # This file
