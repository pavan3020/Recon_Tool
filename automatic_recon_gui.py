import os
import threading
import socket
import ssl
import whois
import dns.resolver
import requests
import builtwith
import datetime
import tempfile
from fpdf import FPDF
from bs4 import BeautifulSoup
from tkinter import Tk, Canvas, Entry, Button, Text, Scrollbar, messagebox, simpledialog
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import smtplib
from email.message import EmailMessage

# -------------------- DIRECTORIES --------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
RESULTS_DIR = os.path.join(OUTPUT_DIR, "results")
SCREENSHOTS_DIR = os.path.join(OUTPUT_DIR, "screenshots")
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

ADMIN_PATHS = ['admin', 'login', 'cpanel', 'administrator', 'wp-admin', 'user', 'backend']

# -------------------- UTILITIES --------------------

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def get_geolocation(ip):
    if not ip:
        return "N/A"
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        d = r.json()
        return f"{d.get('city','N/A')}, {d.get('region','N/A')}, {d.get('country','N/A')}"
    except:
        return "N/A"

def get_whois_info(domain):
    try:
        return whois.whois(domain)
    except:
        return None

def get_dns_records(domain):
    records = {}
    for t in ['A','AAAA','MX','NS','TXT']:
        try:
            r = dns.resolver.resolve(domain, t)
            records[t] = [x.to_text() for x in r]
        except:
            records[t] = None
    return records

def get_http_headers(domain):
    try:
        r = requests.get(f"http://{domain}", timeout=7, allow_redirects=True)
        return r.headers
    except:
        return None

def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain,443),timeout=7) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                issuer_name = issuer.get('organizationName','N/A')
                start = datetime.datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
                end = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                return issuer_name, start, end
    except:
        return None,None,None

def brute_force_admin_panels(domain):
    found = []
    for path in ADMIN_PATHS:
        try:
            url = f"http://{domain}/{path}"
            r = requests.get(url, timeout=5)
            if r.status_code==200: found.append(url)
        except: continue
    return found

def scrape_html_meta(domain):
    meta = {}
    try:
        r = requests.get(f"http://{domain}", timeout=7)
        soup = BeautifulSoup(r.text,'html.parser')
        for tag in soup.find_all('meta'):
            if tag.get('name'):
                meta[tag.get('name')] = tag.get('content','N/A')
    except: pass
    return meta

def detect_tech_stack(domain):
    try:
        techs = builtwith.parse(f"http://{domain}")
        return techs if techs else {"Info":["No tech detected"]}
    except:
        return {"Error":["Could not detect tech"]}

def take_screenshot(domain):
    try:
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--window-size=1920x1080")
        driver = webdriver.Chrome(options=options)
        driver.get(f"https://{domain}")  # HTTPS ensures better success
        path = os.path.join(SCREENSHOTS_DIR, f"{domain}.png")
        driver.save_screenshot(path)
        driver.quit()
        print(f"[+] Screenshot saved: {path}")
        return path
    except Exception as e:
        print(f"[!] Screenshot failed: {e}")
        return None

def hacker_target_api(domain, service="subnet"):
    try:
        r = requests.get(f"https://api.hackertarget.com/{service}/?q={domain}", timeout=10)
        if r.status_code==200: return r.text
        return "API limit or error."
    except: return "API call failed."

def write_report_pdf(domain, content, screenshot_path=None):
    pdf_path = os.path.join(RESULTS_DIR,f"{domain}_report.pdf")
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial","B",16)
    pdf.cell(0,10,f"Recon Report - {domain}",ln=True,align="C")
    pdf.set_font("Arial","",12)
    pdf.multi_cell(0,6,content)
    if screenshot_path and os.path.exists(screenshot_path):
        pdf.add_page()
        pdf.image(screenshot_path,x=10,y=20,w=180)
    pdf.output(pdf_path)
    return pdf_path

def send_email_with_report(pdf_path, recipient_email):
    try:
        smtp_server = simpledialog.askstring("SMTP Server","Enter SMTP server (e.g., smtp.gmail.com):")
        smtp_port = int(simpledialog.askstring("SMTP Port","Enter SMTP port (e.g., 465):"))
        sender_email = simpledialog.askstring("Sender Email","Enter your email address:")
        password = simpledialog.askstring("Password","Enter your email password or app-specific password:",show="*")
        msg = EmailMessage()
        msg['Subject'] = "Recon Report"
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg.set_content(f"Attached is the reconnaissance report for {os.path.basename(pdf_path)}")
        with open(pdf_path,'rb') as f:
            msg.add_attachment(f.read(), maintype='application',subtype='pdf',filename=os.path.basename(pdf_path))
        with smtplib.SMTP_SSL(smtp_server,smtp_port) as smtp:
            smtp.login(sender_email,password)
            smtp.send_message(msg)
        return True
    except Exception as e:
        print(f"[!] Email sending failed: {e}")
        return False

# -------------------- GUI --------------------
class ReconApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AUTOMATED RECON TOOL")
        self.root.geometry("900x650")
        self.root.resizable(False,False)
        self.canvas = Canvas(self.root,width=900,height=650,bg="black")
        self.canvas.pack(fill="both",expand=True)

        self.canvas.create_text(450,40,text="AUTOMATED RECON TOOL",font=("Arial",24,"bold"),fill="#00FF00")
        self.canvas.create_text(450,80,text="Target Domain:",font=("Arial",14),fill="#FFFFFF")
        self.entry = Entry(self.root,font=("Arial",13),bg="#111111",fg="#00FF00",insertbackground="#00FF00",width=50)
        self.canvas.create_window(450,110,window=self.entry)

        self.start_btn = Button(self.root,text="Start Recon",font=("Arial",12),bg="#00CC00",fg="black",command=self.start_recon_thread)
        self.canvas.create_window(370,150,window=self.start_btn)

        self.clear_btn = Button(self.root,text="Clear Output",font=("Arial",12),bg="#CC0000",fg="black",command=self.clear_output)
        self.canvas.create_window(530,150,window=self.clear_btn)

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

    def clear_output(self):
        self.output_text.config(state="normal")
        self.output_text.delete("1.0","end")
        self.output_text.config(state="disabled")

    def start_recon_thread(self):
        domain = self.entry.get().strip()
        if not domain:
            messagebox.showwarning("Input Error","Enter a valid domain.")
            return
        domain = domain.replace("http://","").replace("https://","").split("/")[0]
        self.clear_output()
        self.log(f"Starting reconnaissance on: {domain}\n")
        self.start_btn.config(state="disabled")
        threading.Thread(target=self.run_recon,args=(domain,),daemon=True).start()

    def run_recon(self,domain):
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
            else: self.log("Whois data not found.\n")

            self.log("=== DNS Records ===")
            dns_records = get_dns_records(domain)
            for r,v in dns_records.items():
                self.log(f"{r}: {', '.join(v) if v else 'None'}")
            self.log("")

            headers = get_http_headers(domain)
            self.log("=== HTTP Headers ===")
            if headers:
                for k,v in headers.items(): self.log(f"{k}: {v}")
            else: self.log("Could not fetch HTTP headers.")
            self.log("")

            issuer,start,end = get_ssl_info(domain)
            self.log("=== SSL Info ===")
            if issuer:
                self.log(f"Issuer: {issuer}")
                self.log(f"Valid From: {start.strftime('%Y-%m-%d')}")
                self.log(f"Valid Until: {end.strftime('%Y-%m-%d')}\n")
            else: self.log("No SSL info found.\n")

            panels = brute_force_admin_panels(domain)
            self.log("=== Admin Panel Finder ===")
            if panels:
                for url in panels: self.log(f"[+] Found: {url}")
            else: self.log("No admin panels found.")
            self.log("")

            meta = scrape_html_meta(domain)
            self.log("=== HTML Meta Data ===")
            if meta: 
                for k,v in meta.items(): self.log(f"{k}: {v}")
            else: self.log("No meta data found.")
            self.log("")

            techs = detect_tech_stack(domain)
            self.log("=== Tech Stack ===")
            for k,v in techs.items(): self.log(f"{k}: {', '.join(v)}")
            self.log("")

            self.log("=== HackerTarget API Data ===")
            for service in ["subnet","reverseiplookup","portscan"]:
                data = hacker_target_api(domain,service)
                self.log(f"--- {service} ---")
                self.log(data+"\n")

            self.log("=== Screenshot ===")
            screenshot = take_screenshot(domain)
            self.log(f"Screenshot saved: {screenshot}" if screenshot else "Screenshot failed.")
            self.log("")

            self.log("=== PDF Report ===")
            pdf_path = write_report_pdf(domain,self.output_text.get("1.0","end"),screenshot)
            self.log(f"PDF saved at: {pdf_path}\n")

            # Ask user if they want to send email
            if messagebox.askyesno("Email Report","Do you want to email the report?"):
                recipient = simpledialog.askstring("Recipient Email","Enter recipient email:")
                if recipient:
                    success = send_email_with_report(pdf_path, recipient)
                    self.log("[✓] Email sent successfully." if success else "[!] Email sending failed.")

            self.log("[✓] Recon complete.")

        except Exception as e:
            self.log(f"[!] Error occurred: {e}")
        finally:
            self.start_btn.config(state="normal")

# -------------------- MAIN --------------------
if __name__=="__main__":
    root = Tk()
    app = ReconApp(root)
    root.mainloop()
