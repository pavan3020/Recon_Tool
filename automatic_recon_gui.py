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
from bs4 import BeautifulSoup
from tkinter import Tk, Canvas, Entry, Button, Text, Scrollbar, messagebox
from fpdf import FPDF
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import smtplib
from email.message import EmailMessage
import logging

# --- Setup Logging ---
logging.basicConfig(
    filename="recon_tool.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# --- Directories ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
RESULTS_DIR = os.path.join(OUTPUT_DIR, "results")
SCREENSHOTS_DIR = os.path.join(OUTPUT_DIR, "screenshots")
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

ADMIN_PATHS = ['admin', 'login', 'cpanel', 'administrator', 'wp-admin', 'user', 'backend']

# --- Utility Functions ---

def resolve_ip(domain):
    """Resolve domain to IP address."""
    try:
        ip = socket.gethostbyname(domain)
        logging.info(f"Resolved {domain} to {ip}")
        return ip
    except Exception as e:
        logging.error(f"IP resolution failed for {domain}: {e}")
        return None

def get_geolocation(ip):
    """Return geolocation from ipinfo.io."""
    if not ip:
        return "N/A"
    try:
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = resp.json()
        return f"{data.get('city','N/A')}, {data.get('region','N/A')}, {data.get('country','N/A')}"
    except Exception as e:
        logging.error(f"Geolocation failed for {ip}: {e}")
        return "N/A"

def get_whois_info(domain):
    """Return WHOIS information for the domain."""
    try:
        return whois.whois(domain)
    except Exception as e:
        logging.error(f"WHOIS lookup failed for {domain}: {e}")
        return None

def get_dns_records(domain):
    """Fetch common DNS records."""
    records = {}
    for r_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
        try:
            answers = dns.resolver.resolve(domain, r_type)
            records[r_type] = [str(ans) for ans in answers]
        except Exception:
            records[r_type] = None
    return records

def get_http_headers(domain):
    """Return HTTP headers of domain."""
    try:
        resp = requests.get(f"http://{domain}", timeout=7, allow_redirects=True)
        return resp.headers
    except Exception as e:
        logging.warning(f"HTTP headers fetch failed for {domain}: {e}")
        return None

def get_ssl_info(domain):
    """Return SSL certificate info."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=7) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                issuer_name = issuer.get('organizationName','N/A')
                not_before = datetime.datetime.strptime(cert['notBefore'],"%b %d %H:%M:%S %Y %Z")
                not_after = datetime.datetime.strptime(cert['notAfter'],"%b %d %H:%M:%S %Y %Z")
                return issuer_name, not_before, not_after
    except Exception as e:
        logging.warning(f"SSL fetch failed for {domain}: {e}")
        return None, None, None

def brute_force_admin_panels(domain):
    """Check common admin paths."""
    found = []
    for path in ADMIN_PATHS:
        url = f"http://{domain}/{path}"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                found.append(url)
        except Exception:
            continue
    return found

def scrape_html_meta(domain):
    """Return HTML meta tags."""
    meta_data = {}
    try:
        resp = requests.get(f"http://{domain}", timeout=7)
        soup = BeautifulSoup(resp.text, 'html.parser')
        for tag in soup.find_all('meta'):
            if tag.get('name'):
                meta_data[tag.get('name')] = tag.get('content','N/A')
    except Exception as e:
        logging.warning(f"Meta scraping failed for {domain}: {e}")
    return meta_data

def detect_tech_stack(domain):
    """Return technologies used by website."""
    try:
        techs = builtwith.parse(f"http://{domain}")
        return techs if techs else {"Info":["No technologies detected"]}
    except Exception as e:
        logging.warning(f"Tech detection failed for {domain}: {e}")
        return {"Error":["Could not detect technologies"]}

def take_screenshot(domain):
    """Take homepage screenshot using Selenium."""
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--window-size=1920x1080")
        driver = webdriver.Chrome(options=chrome_options)
        driver.get(f"http://{domain}")
        path = os.path.join(SCREENSHOTS_DIR, f"{domain}.png")
        driver.save_screenshot(path)
        driver.quit()
        return path
    except Exception as e:
        logging.error(f"Screenshot failed for {domain}: {e}")
        return None

def write_pdf_report(domain, content):
    """Generate PDF report."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial","B",16)
    pdf.cell(0,10,f"Recon Report: {domain}",ln=True)
    pdf.set_font("Arial","",12)
    for line in content.split("\n"):
        pdf.multi_cell(0,7,line)
    path = os.path.join(RESULTS_DIR, f"{domain}_report.pdf")
    pdf.output(path)
    return path

def send_email_report(receiver_email, pdf_path, subject="Recon Report"):
    """Send PDF via email (optional)."""
    try:
        sender_email = "youremail@example.com"
        password = "yourpassword"
        msg = EmailMessage()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = subject
        msg.set_content("Please find the attached reconnaissance report.")
        with open(pdf_path,'rb') as f:
            msg.add_attachment(f.read(), maintype='application', subtype='pdf', filename=os.path.basename(pdf_path))
        with smtplib.SMTP_SSL('smtp.gmail.com',465) as server:
            server.login(sender_email,password)
            server.send_message(msg)
        logging.info(f"Email sent to {receiver_email}")
        return True
    except Exception as e:
        logging.error(f"Email sending failed: {e}")
        return False

# --- GUI Class ---

class ReconApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AUTOMATED RECON TOOL")
        self.root.geometry("900x650")
        self.root.resizable(False, False)

        self.canvas = Canvas(self.root, width=900, height=650)
        self.canvas.pack(fill="both", expand=True)

        self.canvas.create_text(450,40,text="AUTOMATED RECON TOOL",font=("Arial",24,"bold"),fill="#00FF00")
        self.canvas.create_text(450,80,text="Target Domain:",font=("Arial",14),fill="#FF0000")

        self.entry = Entry(self.root,font=("Arial",13),bg="#FFFFFF",fg="#FF0000",insertbackground="#FF0000",width=50)
        self.canvas.create_window(450,110,window=self.entry)

        self.start_btn = Button(self.root,text="Start Recon",font=("Arial",12),bg="#00CC00",fg="black",command=self.start_recon_thread)
        self.canvas.create_window(370,150,window=self.start_btn)

        self.clear_btn = Button(self.root,text="Clear Output",font=("Arial",12),bg="#CC0000",fg="black",command=self.clear_output)
        self.canvas.create_window(530,150,window=self.clear_btn)

        self.info_btn = Button(self.root,text="Project Info",font=("Arial",12),bg="#007ACC",fg="white",command=self.open_project_info)
        self.canvas.create_window(450,190,window=self.info_btn)

        self.output_text = Text(self.root,font=("Consolas",11),bg="#000000",fg="#00FF00",state="disabled")
        self.canvas.create_window(450,430,width=800,height=380,window=self.output_text)

        self.scrollbar = Scrollbar(self.root, command=self.output_text.yview)
        self.output_text.config(yscrollcommand=self.scrollbar.set)
        self.canvas.create_window(860,430,height=380,window=self.scrollbar)

    def log(self,msg):
        self.output_text.config(state="normal")
        self.output_text.insert("end",msg+"\n")
        self.output_text.see("end")
        self.output_text.config(state="disabled")
        logging.info(msg)

    def clear_output(self):
        self.output_text.config(state="normal")
        self.output_text.delete("1.0","end")
        self.output_text.config(state="disabled")

    def open_project_info(self):
        pdf_content = """
Project Information
This project is a Python-based automated reconnaissance tool.
It gathers OSINT information, generates PDF reports, and can send emails.

Developer Details:
1. Rama Pavan - Email: gangireddyrampavan@gmail.com, Employee ID: ST#IS#8138
2. Vaasanthi - Email: , Employee ID: ST#IS#8140
3. T. Yeswanth - Email: @gmail.com, Employee ID: ST#IS#8141
4. Sharone Rose - Email: @gmail.com, Employee ID: ST#IS#8136
"""
        temp_pdf_path = os.path.join(OUTPUT_DIR,"Project_Info.pdf")
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial","B",16)
        pdf.multi_cell(0,10,pdf_content)
        pdf.output(temp_pdf_path)
        webbrowser.open(f"file://{temp_pdf_path}")

    def start_recon_thread(self):
        domain = self.entry.get().strip()
        if not domain:
            messagebox.showwarning("Input Error","Please enter a valid domain or URL.")
            return
        domain = domain.replace("http://","").replace("https://","").split("/")[0]
        self.clear_output()
        self.log(f"Starting reconnaissance on: {domain}\n")
        self.start_btn.config(state="disabled")
        threading.Thread(target=self.run_recon,args=(domain,),daemon=True).start()

    def run_recon(self, domain):
        try:
            ip = resolve_ip(domain)
            self.log("=== Basic Recon ===")
            self.log(f"[✓] IP Address: {ip or 'Not Found'}")
            self.log(f"[✓] Location: {get_geolocation(ip)}\n")

            w = get_whois_info(domain)
            self.log("=== Whois Info ===")
            if w and w.domain_name:
                self.log(f"Domain: {w.domain_name}")
                self.log(f"Registrar: {w.registrar}")
                self.log(f"Created: {w.creation_date}")
                self.log(f"Expires: {w.expiration_date}\n")
            else:
                self.log("Whois data not found.\n")

            dns_records = get_dns_records(domain)
            self.log("=== DNS Records ===")
            for r_type, vals in dns_records.items():
                self.log(f"{r_type}: {', '.join(vals) if vals else 'None'}")
            self.log("")

            headers = get_http_headers(domain)
            self.log("=== HTTP Headers ===")
            if headers:
                for k,v in headers.items():
                    self.log(f"{k}: {v}")
            else:
                self.log("Could not fetch HTTP headers.")
            self.log("")

            issuer,start,end = get_ssl_info(domain)
            self.log("=== SSL Info ===")
            if issuer:
                self.log(f"Issuer: {issuer}")
                self.log(f"Valid From: {start.strftime('%Y-%m-%d')}")
                self.log(f"Valid Until: {end.strftime('%Y-%m-%d')}\n")
            else:
                self.log("No SSL info found.\n")

            panels = brute_force_admin_panels(domain)
            self.log("=== Admin Panels ===")
            if panels:
                for url in panels:
                    self.log(f"[+] Found: {url}")
            else:
                self.log("No admin panels found.")
            self.log("")

            meta = scrape_html_meta(domain)
            self.log("=== HTML Meta Data ===")
            if meta:
                for k,v in meta.items():
                    self.log(f"{k}: {v}")
            else:
                self.log("No meta data found.")
            self.log("")

            techs = detect_tech_stack(domain)
            self.log("=== Tech Stack ===")
            for category,apps in techs.items():
                self.log(f"{category}: {', '.join(apps)}")
            self.log("")

            screenshot = take_screenshot(domain)
            self.log("=== Screenshot ===")
            self.log(f"Saved at: {screenshot}" if screenshot else "Failed to take screenshot")
            self.log("")

            pdf_path = write_pdf_report(domain, self.output_text.get("1.0","end"))
            self.log(f"=== PDF Report Saved ===\n{pdf_path}\n")

            self.log("[✓] Recon complete.")

        except Exception as e:
            self.log(f"[!] An error occurred: {e}")
        finally:
            self.start_btn.config(state="normal")

# --- Main ---
if __name__ == "__main__":
    root = Tk()
    app = ReconApp(root)
    root.mainloop()
