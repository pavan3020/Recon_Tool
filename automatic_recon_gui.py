import os
import threading
import socket
import ssl
import whois
import dns.resolver
import webbrowser
import requests
import builtwith
import datetime
import tempfile
import json
import smtplib
import configparser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from bs4 import BeautifulSoup
from tkinter import Tk, Entry, Button, Text, Scrollbar, Canvas, messagebox, Label, Toplevel, StringVar, BooleanVar, Checkbutton
from tkinter import simpledialog
from PIL import Image, ImageTk
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options
# Imports for enhanced PDF reports
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib import colors
from reportlab.lib.units import inch


# --- Constants & Directory Setup ---
BASE_DIR = os.path.dirname(os.path.abspath(file))
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
RESULTS_DIR = os.path.join(OUTPUT_DIR, "results")
SCREENSHOTS_DIR = os.path.join(OUTPUT_DIR, "screenshots")
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
CONFIG_PATH = os.path.join(BASE_DIR, 'config.ini')

# --- Subdomain list ---
COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'blog', 'dev', 'shop', 'api', 'cdn',
    'm', 'dev', 'stage', 'test', 'app', 'store', 'secure', 'support', 'status', 'docs', 'admin',
    'assets', 'static', 'images', 'img', 'files', 'download', 'media', 'video', 'audio',
    'careers', 'jobs', 'hr', 'news', 'press', 'events', 'partner', 'portal', 'client',
    'customer', 'user', 'users', 'login', 'signin', 'signup', 'register', 'account',
    'my', 'dashboard', 'console', 'panel', 'cpanel', 'billing', 'payment', 'payments',
    'checkout', 'cart', 'order', 'orders', 'help', 'faq', 'contact', 'about', 'info',
    'community', 'forum', 'forums', 'chat', 'feedback', 'search', 'go', 'links', 'ads',
    'analytics', 'metrics', 'stats', 'status', 'vpn', 'proxy', 'remote', 'cloud', 'db',
    'sql', 'mysql', 'mongo', 'redis', 'git', 'svn', 'code', 'developer', 'developers'
]

# --- Configuration Functions ---
def load_config():
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_PATH):
        config.read(CONFIG_PATH)
        return {
            'shodan_key': config.get('API_KEYS', 'SHODAN_API_KEY', fallback=''),
            'virustotal_key': config.get('API_KEYS', 'VT_API_KEY', fallback=''),
            'sender_email': config.get('EMAIL', 'SENDER_EMAIL', fallback=''),
            'smtp_server': config.get('EMAIL', 'SMTP_SERVER', fallback='smtp.gmail.com'),
            'smtp_port': config.get('EMAIL', 'SMTP_PORT', fallback='587')
        }
    return {'shodan_key': '', 'virustotal_key': '', 'sender_email': '', 'smtp_server': 'smtp.gmail.com', 'smtp_port': '587'}

def save_email_config(email, server, port):
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_PATH):
        config.read(CONFIG_PATH)
    if 'EMAIL' not in config:
        config.add_section('EMAIL')
    config.set('EMAIL', 'SENDER_EMAIL', email)
    config.set('EMAIL', 'SMTP_SERVER', server)
    config.set('EMAIL', 'SMTP_PORT', port)
    with open(CONFIG_PATH, 'w') as configfile:
        config.write(configfile)

# --- Reconnaissance Functions ---
def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def get_geolocation(ip):
    if not ip:
        return "N/A"
    try:
        # Suppress only the InsecureRequestWarning from urllib3
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        data = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5, verify=False).json()
        return f"{data.get('city', 'N/A')}, {data.get('region', 'N/A')}, {data.get('country', 'N/A')}"
    except Exception:
        return "N/A"

def get_whois_info(domain):
    try:
        return whois.whois(domain)
    except Exception:
        return None

def get_dns_records(domain):
    records = {}
    for t in ['A', 'MX', 'NS', 'TXT']:
        try:
            answers = dns.resolver.resolve(domain, t, lifetime=5)
            records[t] = [r.to_text() for r in answers]
        except Exception:
            records[t] = []
    return records

def detect_tech_stack(domain):
    try:
        return builtwith.parse(f"http://{domain}")
    except Exception:
        return {}

def take_screenshot(domain):
    screenshot_path = os.path.join(SCREENSHOTS_DIR, f"{domain}.png")
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--window-size=1280x720")
    options.add_argument("--disable-gpu")
    options.add_argument("--log-level=3")
    options.add_argument("--ignore-certificate-errors")
    driver = None
    try:
        service = ChromeService(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        driver.get(f"http://{domain}")
        driver.save_screenshot(screenshot_path)
        return screenshot_path
    except Exception:
        return None
    finally:
        if driver:
            driver.quit()

def find_subdomains(domain):
    subdomains = set()
    for sub in COMMON_SUBDOMAINS:
        try:
            full_domain = f"{sub}.{domain}"
            if socket.gethostbyname(full_domain):
                subdomains.add(full_domain)
        except socket.error:
            continue
    return list(subdomains)

def query_shodan(ip, api_key):
    if not ip or not api_key or "YOUR_API_KEY" in api_key:
        return {"Error": "IP or Shodan API Key is missing from config.ini"}
    try:
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        return requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}", verify=False).json()
    except Exception as e:
        return {"Error": f"Shodan query failed: {e}"}

def query_virustotal(domain, api_key):
    if not domain or not api_key or "YOUR_API_KEY" in api_key:
        return {"Error": "Domain or VirusTotal API Key is missing from config.ini"}
    try:
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        return requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers={'x-apikey': api_key}, verify=False).json()
    except Exception as e:
        return {"Error": f"VirusTotal query failed: {e}"}

# --- PDF Generation Functions ---
def generate_pdf_report(domain, data, report_path):
    doc = SimpleDocTemplate(report_path, pagesize=letter)
    styles = getSampleStyleSheet()

    if 'Title' not in styles:
        styles.add(ParagraphStyle(name='Title', parent=styles['h1'], alignment=TA_CENTER, spaceAfter=20))

    story = [Paragraph("Reconnaissance Report", styles['Title']),
             Paragraph(f"Target: {domain}", styles['h2'])]

    # --- 1. Executive Summary Section ---
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("Executive Summary", styles['h2']))
    ip = data.get('IP_Address', 'N/A')
    location = data.get('Geolocation', 'N/A')
    vt_data = data.get('VirusTotal', {}).get('data', {})
    vt_stats = vt_data.get('attributes', {}).get('last_analysis_stats', {}) if vt_data else {}
    vt_summary = f"{vt_stats.get('malicious', 0)} Malicious / {sum(vt_stats.values())} Scanners" if vt_stats else "N/A"
    shodan_data = data.get('Shodan', {})
    if "Error" in shodan_data:
        shodan_isp = f"Scan Failed: {shodan_data['Error']}"
    elif "error" in shodan_data:
        shodan_isp = f"Scan Failed: {shodan_data['error']}"
    else:
        shodan_isp = shodan_data.get('isp', 'N/A')

    summary_data = [
        ['IP Address:', ip], ['Geolocation:', location],
        ['VirusTotal Detections:', vt_summary], ['Hosting Provider (ISP):', shodan_isp]
    ]
    summary_table = Table(summary_data, colWidths=[2 * inch, 4.5 * inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey), ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.2 * inch))

    # --- 2. DNS Records Section ---
    dns_records = data.get('DNS_Records')
    if dns_records:
        story.append(Paragraph("DNS Records", styles['h2']))
        dns_data = []
        for rectype, recs in dns_records.items():
            if recs:
                formatted_recs = [Paragraph(r, styles['Normal']) for r in recs]
                dns_data.append([f"{rectype} Records:", formatted_recs])
        if dns_data:
            dns_table = Table(dns_data, colWidths=[1.5 * inch, 5 * inch])
            dns_table.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 1, colors.black), ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey), ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ]))
            story.append(dns_table)
            story.append(Spacer(1, 0.2 * inch))
            
    # --- 3. Technology Stack Section ---
    tech_stack = data.get('Tech_Stack')
    if tech_stack:
        story.append(Paragraph("Technology Stack", styles['h2']))
        tech_data = [[k.replace('-', ' ').title(), ', '.join(v)] for k, v in tech_stack.items()]
        if tech_data:
            tech_table = Table(tech_data, colWidths=[2 * inch, 4.5 * inch])
            tech_table.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 1, colors.black), ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey), ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ]))
            story.append(tech_table)
            story.append(Spacer(1, 0.2 * inch))

    # --- 4. WHOIS Data Section ---
    whois_text = data.get('WHOIS')
    if whois_text:
        story.append(PageBreak())
        story.append(Paragraph("WHOIS Raw Data", styles['h2']))
        p_style = ParagraphStyle('CodeSmall', parent=styles['Normal'], fontName='Courier', fontSize=8, leading=10)
        formatted_whois = []
        for line in whois_text.splitlines():
            if ':' in line:
                parts = line.split(':', 1)
                formatted_line = f"<b>{parts[0].strip()}:</b>{parts[1]}"
                formatted_whois.append(formatted_line)
            else:
                formatted_whois.append(line)
        story.append(Paragraph('<br/>'.join(formatted_whois), p_style))

    doc.build(story)

def generate_project_info_pdf(output_path):
    doc = SimpleDocTemplate(output_path, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
    styles = getSampleStyleSheet()
    
    table_style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a86e8')), ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'), ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12), ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
        ('GRID', (0, 0), (-1, -1), 1, colors.black), ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ])
    key_value_style = TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey), ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
    ])
    story = []
    story.append(Paragraph("Project Information", styles['h1'])); story.append(Spacer(1, 0.2 * inch))
    intro_text = """This project was developed by a team as part of a <b>Cyber Security Intership</b>. This project is designed to <b>Secure the Organizations in Real World from Cyber Frauds performed by Hackers.</b>"""
    story.append(Paragraph(intro_text, styles['Normal'])); story.append(Spacer(1, 0.3 * inch))
    project_details_data = [['Project Name', 'Automatic Reconnaissance with Python'], ['Project Description', Paragraph('Automated Python-based reconnaissance tool for efficient and comprehensive security information gathering.', styles['Normal'])], ['Project Start Date', '30-JULY-2025'], ['Project End Date', '02-AUG-2025'], ['Project Status', 'Completed']]
    project_table = Table(project_details_data, colWidths=[2*inch, 4.5*inch]); project_table.setStyle(key_value_style)
    story.append(project_table); story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph("Developer Details", styles['h2']))
    developer_data = [['Name', 'Employee ID', 'Email'], ['Palla Vaasanti', 'ST#IS#8140', '22691A3750@MITS.AC.IN'], ['G . Rama Pavan Kumar Reddy', 'ST#IS#8138', '22691A3730@MITS.AC.IN'], ['Tupakula Yeshwanth Kumar', 'ST#IS#8136', '22691A3759@MITS.AC.IN'], ['Sharon Rose Mallela', 'ST#IS#8141', '22691A3739@MITS.AC.IN']]
    developer_table = Table(developer_data, colWidths=[2.5*inch, 1.5*inch, 2.5*inch]); developer_table.setStyle(table_style)
    story.append(developer_table); story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph("Company Details", styles['h2']))
    company_data = [['Name', 'Supraja Technologies'], ['Email', 'contact@suprajatechnologies.com']]
    company_table = Table(company_data, colWidths=[2*inch, 4.5*inch]); company_table.setStyle(key_value_style)
    story.append(company_table)
    doc.build(story)

# --- Email Functions ---
def send_email_report(recipient, subject, body, attachment_path, sender_email, sender_password, smtp_server, smtp_port):
    if not all([sender_email, sender_password, smtp_server, smtp_port]):
        messagebox.showerror("Email Error", "Sender credentials or SMTP settings were not provided.")
        return
    msg = MIMEMultipart(); msg['From'] = sender_email; msg['To'] = recipient; msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    with open(attachment_path, "rb") as attachment:
        part = MIMEBase("application", "octet-stream"); part.set_payload(attachment.read())
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", f"attachment; filename= {os.path.basename(attachment_path)}")
    msg.attach(part)
    try:
        server = smtplib.SMTP(smtp_server, int(smtp_port)); server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient, msg.as_string()); server.quit()
        messagebox.showinfo("Success", "Email sent successfully!")
    except Exception as e: messagebox.showerror("Email Error", f"Failed to send email:\n{e}")

class EmailLoginWindow(Toplevel):
    def init(self, parent, saved_email="", saved_server="", saved_port=""):
        super().init(parent)
        self.title("Sender Email Details"); self.geometry("400x280"); self.transient(parent); self.grab_set()
        self.email = StringVar(value=saved_email); self.password = StringVar()
        self.server = StringVar(value=saved_server); self.port = StringVar(value=saved_port)
        self.save_email = BooleanVar(value=True)
        Label(self, text="Your Email:").pack(pady=5); Entry(self, textvariable=self.email, width=50).pack()
        Label(self, text="Your App Password:").pack(pady=5); Entry(self, textvariable=self.password, show="*", width=50).pack()
        Label(self, text="SMTP Server:").pack(pady=5); Entry(self, textvariable=self.server, width=50).pack()
        Label(self, text="SMTP Port:").pack(pady=5); Entry(self, textvariable=self.port, width=50).pack()
        Checkbutton(self, text="Save email & SMTP settings", variable=self.save_email).pack(pady=5)
        Button(self, text="Send Email", command=self.submit).pack(pady=5)
        self.wait_window(self)

    def submit(self):
        if self.save_email.get():
            save_email_config(self.email.get(), self.server.get(), self.port.get())
        self.destroy()

class ReconApp:
    def init(self, root):
        self.config = load_config()
        self.root = root
        self.root.title("AUTOMATED RECON TOOL")
        self.root.geometry("900x650")
        self.root.resizable(False, False)
        
        self.canvas = Canvas(self.root, width=900, height=650)
        self.canvas.pack(fill="both", expand=True)
        try:
            bg_img = Image.open(os.path.join(ASSETS_DIR, "background.jpg")).resize((900, 650))
            self.bg_photo = ImageTk.PhotoImage(bg_img)
            self.canvas.create_image(0, 0, image=self.bg_photo, anchor="nw")
        except: self.canvas.config(bg="#000")
            
        self.canvas.create_text(450, 30, text="AUTOMATED RECON TOOL", font=("Arial", 20, "bold"), fill="#EE1532")
        self.canvas.create_text(450, 70, text="Target Domain:", font=("Arial", 14), fill="#00FF00")
        self.entry = Entry(self.root, font=("Arial", 13), bg="#111", fg="#0f0", insertbackground="#0f0", width=50)
        self.canvas.create_window(450, 100, window=self.entry)
        self.start_btn = Button(self.root, text="Start Recon", font=("Arial", 12), bg="#00cc00", fg="black", command=self.start_recon_thread)
        self.canvas.create_window(370, 140, window=self.start_btn)
        self.clear_btn = Button(self.root, text="Clear Output", font=("Arial", 12), bg="#cc0000", fg="black", command=self.clear_output)
        self.canvas.create_window(530, 140, window=self.clear_btn)
        self.info_btn = Button(self.root, text="Project Info", font=("Arial", 12), bg="#007acc", fg="white", command=self.open_project_info)
        self.canvas.create_window(450, 180, window=self.info_btn)
        self.output_text = Text(self.root, font=("Consolas", 11), bg="#000", fg="#00FF00", state="disabled")
        self.canvas.create_window(450, 430, width=600, height=300, window=self.output_text)
        self.scrollbar = Scrollbar(self.root, command=self.output_text.yview)
        self.output_text.config(yscrollcommand=self.scrollbar.set)
        self.canvas.create_window(750, 430, height=300, window=self.scrollbar)

    def log(self, msg):
        self.root.after(0, self._log_thread_safe, msg)
        
    def _log_thread_safe(self, msg):
        self.output_text.config(state="normal")
        self.output_text.insert("end", msg + "\n")
        self.output_text.see("end")
        self.output_text.config(state="disabled")
        self.root.update_idletasks()

    def clear_output(self):
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.config(state="disabled")

    def open_project_info(self):
        self.log("[INFO] Generating Project Information PDF...")
        try:
            info_path = os.path.join(RESULTS_DIR, "Project_Information.pdf")
            generate_project_info_pdf(info_path)
            self.log(f"[SUCCESS] Project Information PDF saved to {info_path}")
            os.startfile(info_path) # Automatically opens the PDF
        except Exception as e:
            self.log(f"[ERROR] Could not generate or open Project Info PDF: {e}")
            messagebox.showerror("Error", f"Could not generate Project Info PDF: {e}")
    
    def start_recon_thread(self):
        domain = self.entry.get().strip()
        if not domain: messagebox.showwarning("Input Error", "Please enter a valid domain."); return
        
        if domain.startswith("https://"): domain = domain[8:]
        elif domain.startswith("http://"): domain = domain[7:]
        domain = domain.split('/')[0]

        self.clear_output()
        self.log(f"Starting reconnaissance on: {domain}\n")
        self.start_btn.config(state="disabled")
        threading.Thread(target=self.run_recon, args=(domain,), daemon=True).start()

    def run_recon(self, domain):
        recon_data = {}
        self.log("=== Basic Recon ===")
        ip = resolve_ip(domain); recon_data['IP_Address'] = ip
        self.log(f"[\u2713] IP Address: {ip or 'Not Found'}")
        geo = get_geolocation(ip); recon_data['Geolocation'] = geo
        self.log(f"[\u2713] Location: {geo}")
        
        self.log("\n=== DNS Records ===")
        dns_recs = get_dns_records(domain); recon_data['DNS_Records'] = dns_recs
        self.log(json.dumps(dns_recs, indent=2))
        
        self.log("\n=== Whois Info ===")
        w = get_whois_info(domain)
        if w and w.text:
            recon_data['WHOIS'] = w.text
            self.log(w.text)
        
        self.log("\n=== Subdomain OSINT ===")
        subs = find_subdomains(domain)
        if subs:
            recon_data['Subdomains'] = subs
            self.log('\n'.join(subs))
        
        self.log("\n=== Shodan API Info ===")
        shodan_info = query_shodan(ip, self.config['shodan_key'])
        if shodan_info:
            recon_data['Shodan'] = shodan_info
            self.log(json.dumps(shodan_info, indent=2))
            
        self.log("\n=== VirusTotal API Info ===")
        vt_info = query_virustotal(domain, self.config['virustotal_key'])
        if vt_info:
            recon_data['VirusTotal'] = vt_info
            self.log(json.dumps(vt_info, indent=2))
            
        self.log("\n=== Tech Stack ===")
        techs = detect_tech_stack(domain)
        if techs:
            recon_data['Tech_Stack'] = techs
            self.log(json.dumps(techs, indent=2))
        
        self.log("\n=== Screenshot ===")
        screenshot_path = take_screenshot(domain)
        if screenshot_path: self.log(f"Screenshot saved: {screenshot_path}")
            
        self.log("\n=== Generating Reports ===")
        pdf_report_path = os.path.join(RESULTS_DIR, f"{domain}_report.pdf")
        generate_pdf_report(domain, recon_data, pdf_report_path)
        self.log(f"PDF Report saved: {pdf_report_path}")
        self.log("\n[\u2713] Reconnaissance complete.")

        self.root.after(0, self.prompt_for_email, domain, pdf_report_path)

    def prompt_for_email(self, domain, pdf_report_path):
        self.log("\n=== Email Notification ===")
        recipient_email = simpledialog.askstring("Recipient Email", "Enter the recipient's email address:", parent=self.root)
        if recipient_email:
            # The original code had a separate popup class, but we need to pass SMTP settings
            login_popup = EmailLoginWindow(self.root,
                                           saved_email=self.config.get('sender_email', ''),
                                           saved_server=self.config.get('smtp_server', ''),
                                           saved_port=self.config.get('smtp_port', ''))
            
            sender_email = login_popup.email.get()
            sender_password = login_popup.password.get()
            smtp_server = login_popup.server.get()
            smtp_port = login_popup.port.get()

            if sender_email and sender_password:
                self.log(f"Attempting to send report to {recipient_email}...")
                threading.Thread(target=send_email_report, args=(
                    recipient_email,
                    f"Recon Report for {domain}",
                    "Please find attached the recon report.",
                    pdf_report_path,
                    sender_email,
                    sender_password,
                    smtp_server,
                    smtp_port
                ), daemon=True).start()
            else:
                self.log("Email sending cancelled.")
        self.start_btn.config(state="normal")


if name == "main":
    root = Tk()
    app = ReconApp(root)
    root.mainloop()
