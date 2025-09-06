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
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

# --- Constants & Directory Setup ---
BASE_DIR = os.path.dirname(os.path.abspath(_file_))
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
RESULTS_DIR = os.path.join(OUTPUT_DIR, "results")
SCREENSHOTS_DIR = os.path.join(OUTPUT_DIR, "screenshots")
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
CONFIG_PATH = os.path.join(BASE_DIR, 'config.ini')

# --- UPGRADE: Much larger subdomain list ---
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

# --- Function to load configuration from config.ini ---
def load_config():
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_PATH):
        config.read(CONFIG_PATH)
        return {
            'shodan_key': config.get('API_KEYS', 'SHODAN_API_KEY', fallback=''),
            'virustotal_key': config.get('API_KEYS', 'VT_API_KEY', fallback=''),
            'sender_email': config.get('EMAIL', 'SENDER_EMAIL', fallback='')
        }
    return {'shodan_key': '', 'virustotal_key': '', 'sender_email': ''}

# --- UPGRADE: Function to save email config ---
def save_email_config(email):
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_PATH):
        config.read(CONFIG_PATH)
    if 'EMAIL' not in config:
        config.add_section('EMAIL')
    config.set('EMAIL', 'SENDER_EMAIL', email)
    with open(CONFIG_PATH, 'w') as configfile:
        config.write(configfile)

# --- Utility & Enhancement Functions ---

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def get_geolocation(ip):
    if not ip:
        return "N/A"
    try:
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

def get_http_headers(url):
    try:
        return requests.get(url, timeout=7, allow_redirects=True, verify=False).headers
    except Exception:
        return None

def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=7) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer', []))
                return (issuer.get('organizationName') or issuer.get('commonName') or "N/A",
                        datetime.datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z"),
                        datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z"))
    except Exception:
        return None, None, None

def scrape_html_meta(domain):
    try:
        soup = BeautifulSoup(requests.get(f"http://{domain}", timeout=5, verify=False).text, 'html.parser')
        meta_data = {t.get('name') or t.get('property'): t.get('content') for t in soup.find_all('meta') if (t.get('name') or t.get('property')) and t.get('content')}
        return meta_data if meta_data else {}
    except Exception:
        return {}

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
        return requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}", verify=False).json()
    except Exception as e:
        return {"Error": f"Shodan query failed: {e}"}

def query_virustotal(domain, api_key):
    if not domain or not api_key or "YOUR_API_KEY" in api_key:
        return {"Error": "Domain or VirusTotal API Key is missing from config.ini"}
    try:
        return requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers={'x-apikey': api_key}, verify=False).json()
    except Exception as e:
        return {"Error": f"VirusTotal query failed: {e}"}

def generate_pdf_report(domain, data, report_path):
    doc = SimpleDocTemplate(report_path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = [Paragraph(f"Reconnaissance Report for: {domain}", styles['h1']), Spacer(1, 0.25*inch)]
    for key, value in data.items():
        if not value:
            continue
        story.append(Paragraph(key.replace('_', ' ').title(), styles['h2']))
        if isinstance(value, dict):
            for sub_key, sub_value in value.items():
                story.append(Paragraph(f"<b>{sub_key}:</b> {json.dumps(sub_value, indent=2)}", styles['Code']))
        elif isinstance(value, list):
            for item in value:
                story.append(Paragraph(str(item), styles['Normal']))
        else:
            story.append(Paragraph(str(value), styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
    doc.build(story)

def send_email_report(recipient, subject, body, attachment_path, sender_email, sender_password):
    if not sender_email or not sender_password:
        messagebox.showerror("Email Error", "Sender credentials were not provided.")
        return
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    with open(attachment_path, "rb") as attachment:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(attachment.read())
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", f"attachment; filename= {os.path.basename(attachment_path)}")
    msg.attach(part)
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient, msg.as_string())
        server.quit()
        messagebox.showinfo("Success", "Email sent successfully!")
    except Exception as e:
        messagebox.showerror("Email Error", f"Failed to send email:\n{e}")

class EmailLoginWindow(Toplevel):
    def _init_(self, parent, saved_email=""):
        super()._init_(parent)
        self.title("Sender Email Details")
        self.geometry("350x180")
        self.transient(parent)
        self.grab_set()
        self.email = StringVar(value=saved_email)
        self.password = StringVar()
        self.save_email = BooleanVar(value=True)
        
        Label(self, text="Your Email:").pack(pady=5)
        Entry(self, textvariable=self.email, width=40).pack()
        Label(self, text="Your Gmail App Password:").pack(pady=5)
        Entry(self, textvariable=self.password, show="*", width=40).pack()
        Checkbutton(self, text="Save email for next time", variable=self.save_email).pack(pady=5)
        Button(self, text="Send Email", command=self.submit).pack(pady=5)
        
        self.wait_window(self)

    def submit(self):
        if self.save_email.get():
            save_email_config(self.email.get())
        self.destroy()

class ReconApp:
    def _init_(self, root):
        self.config = load_config()
        self.root = root
        self.root.title("AUTOMATED RECON TOOL")
        self.root.geometry("900x650")
        self.root.resizable(False, False)
        try:
            self.root.iconbitmap(os.path.join(ASSETS_DIR, "app_icon.ico"))
        except:
            print("[!] Icon Load Failed")
        self.canvas = Canvas(self.root, width=900, height=650)
        self.canvas.pack(fill="both", expand=True)
        try:
            bg_img = Image.open(os.path.join(ASSETS_DIR, "background.jpg")).resize((900, 650))
            self.bg_photo = ImageTk.PhotoImage(bg_img)
            self.canvas.create_image(0, 0, image=self.bg_photo, anchor="nw")
        except:
            self.canvas.config(bg="#000")
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
        self.output_text = Text(self.root, font=("Consolas", 11), bg="#000", fg="#00FF00")
        self.output_text.config(state="disabled")
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
        logo_base64 = "/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD/2wBDAQMDAwQDBAgEBAgQCwkLEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBD/wAARCADhAOEDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD9U6KKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACmu6RqXdgqqMknoBXk3xm/aD8P/C5/7BsY01PxHNH5i2gbCWyHpJMR0B6hB8zf7I+avJLDwD8cvjnjWfEuqSWOlTjzIReu0UDKeR5VunUYOQzAZGPmNePjM2VCp9Xw8HUqdlsvV9DyMRm9OFV4fDxdSot0tl6vofS83j7wNbzfZ5/Gehxy9NjajCG/LdWtZajYalCLjTr2C6iPSSCRXU/iDivnyD9jyxWELceO52k7mPTwq/gPMP8OsTVP2bPiT4IkfWvh74s+2TxDdttnayuWA7D5ird+CwyO3auV5jmlL36uF93+7JN/d1Mvr2Y0/eqYfTykm/u6n1PRXzf8Pf2n7jTdaTwb8YbcabOrLB/akkfk+XKTgLcxnATOR84AAz8wA+avo8EEZBzXrYLHUcfT9pRfqnuvU9DBY+hj4uVF7brqvVC0UUV2HYFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQB41qP7PHwx0z4l6p8Z9dn227Rm+urW8k/0OO5Xl7pyxwQFUEIRtUgt6AcL4n/aS8WePdWPhv4LWFx5T5VLoWpe7mA6usbgiJPdhnGCSvSvpbUdOsdXsbjS9Ts4buzu4mhngmQOksbDDKwPBBBxiua+Hfwt8G/CzS5dK8IaaYI55nlkklcySsCxKoXPJVQcKPQZOSST5OMwNWt+7w0vZxk7ya+J+n9aHh1ssqxqezwTVOnJuU2vibfb1PBIfg7+0lqarqV74vube4b5jHPr029e/Gzco+gNV0+I3x5+Cl5DH46tLrU9Ld/8Al9fz0kHcJcruKt7MTj+7XN/ED/godPofjW90XwV8PrbVNF026a1e7vr54JbzYSrvGqowjXcMKW3FhzgdK+oPBXinwf8AHP4Z2PiW1sxd6L4gtmEltdKCyMrMkkT4JAZJFZcg9VyD0NePRy7D1JyWAxElUj3d0/XTVH0mdeG2c8OYSlmFdTpKp8MnJSV7XSkk7pta2duumjS8913wn8Lf2svC9rr+j6lLY39lPHb3csSr9qgQMDLazISVyVJKtzgkMpKllb2rRNH07w9o9loOj2/kWOnW8drbRb2fy4kUKq7mJJwAOSSaxPh78NvCfwx0Z9E8J6f5Ec0pnuJpDumuJD/FI+PmIGAOwAAFdRX0uGo+zXPNLnaXM11Z4+Bwnsv9orRiq0klJx62/r+tAooorpPQCiiigApKWvzj+NH7Q3x+/aH+PN58Cf2eddvNG0uxurjT1l0+5NpJctbkrcXdxdKPMigVwyqIyMgrw7OqjWlSdVu2iRy4rFRwsU2rt6JLdn6OUmcda/PQfsF/tbS7Zrn9pHMx5Y/8JJq789fvEZPPeuh8G/sj/treEfEel3q/tMPcaZDf20l7BJ4l1ScPbCVTMqxTRshYoGABxk4yR1Gjo07aVF9zMY4uvf3qLt6o+6qKz/EOrweH/D2p67cHEOm2c13IfRY0LHr7Cvh3/gm18RPiz8TPE/jPUPiD8QPEGv2mj6VYQxw6hevNEk9xJISwUnG7FuRnrhj6nOcaTnCU10N6mJjSqwotayv+B950UV86ft6/EPxH8OP2fbrU/CWv3ui6vf6vYWNveWcximT955rhWXkZjhdTjqCRUQi6klBdTStVVGnKo9krn0XSV4P+w/rHjHxL+zl4f8UeO/EGpazq2r3V/cNc6hcNNKYlupIohljwuyNSB7+9eK/8FMvi3408AQeBNA8FeMdc0CTUE1S+vn0m/ltJJY4hbrGrNGysQTLIQM9VrSFFzq+yTMamMjSw31lrSydvU+4s+1FfnrY/sS/tg6tYWupSftNX8TXUEc3lzeKNYLx7lB2tz1GcVzHxG+Cv7bv7N3h64+Jln8dNW1jTNK2yXjWniK8u/s6kgeZJa3imKRASMnDEA5IC5I0WHhJ8saiuc8sdWguadF29UfplRXh37H3x71D9oL4Rp4m8QQW8Wv6TeyaTqv2dCkUsyIkiyop+6HjkQkA4DbgOAK+ZP28/iP8AFCf9o3wj8JPh18QfEXh5NQ07Tbcx6ZqtzZRyXt5ezQq0nksCwAER78H2qIUJTqOm9LG1XGwp0FXWqex+hdLX59t+wv8AtguxeT9qC5LE9T4o1kk1xXxK8HftufsiWFt4+k+NN/rWh/aY4JZRrNxqVvFI2dqT216pCq5+XcmTkgZU7atYeE3aE1cyljqtNc1Si0vVM/TmivNf2dfi8nxz+D/h/wCJLWMdldahHJDfWsZJSG6hkaKUJnnYWQsuSTtZc85r0k1zSi4txfQ74TjUipx2eoZor4I/aB+Lnxj+Mv7U9n+z58AfHd94eg0WKS1v7yzungje7VDLcSTPGCxjiAjhA5xIXH8Qrov+Cfnxd+I3ibxh8SPhj8TvGOo+IL7QJYpLWW+uGmeNo5pre6VWYbtu5YSAehJ9a3eGlGHO3529Tjjj4TreySe7V+l0rs+1qQ8ilpDXOd58CfEb/gn78Rp/HF7cfDzXPD8nh6/uWmgOoTywz2SO2SjIsbCQLk4IYFgOQDX2P8HPhlp3wf8Ahzo/w/027e7XTY3M1yybDPPI7SSybcnaC7thcnAwMnGa+MvCHxa+KXjn/goZe+C7H4g68PCFjr1/FLpKXzi0WGzsnQr5Y+XabiIEjuWJOea/QKuanlVDAVHUprWSv6X6H0ma8f5vxZgqeBx0706LstEnJpWUm1vo7Lbd6XEoz3rh/jb8UtL+DHwt8Q/EjVVSUaRaFra3Ztv2m6chIIQe2+RkXPYEntX5kal48/a/g+C1n+0Ld/HDxKmk6v4gfRreJL6RGeUJIxuBEAIlg8yGSLaP4hjbtr0aOHlWV726HxuKx0cLLlabdr6dEfrfkdM0V8+eMfGnifx/8I/BPiTwvPfC78V6dol5aw2kcZ+0S3N3Zi6VhLG8RMdtLOwWRGQASSFT5IZO5+BWo6/feFoRrbTtKlpatdJOrK9rfkP9otdrY2+WBDuVQEDvIE2qAiZODSuzpjWUpKK7XPS6KKKg1Gvu2NsIDYOM+tflz/wTz8W+FfAXx8120+Jmq2uja7qOmXGkwTX8giT7aLqJp7cu3CyM0fAJGTGV5JAP6kV8tftEfsCfDr4161e+NfDmsTeEfE2oZe8kitxcWV9JjHmTQEqQ5xgsjrnksrmuihUhFShPRPqefjqNWcoVqKu4vbvc+pAQwBU5BGQRR1r8xpPht+3n+yRFJc+D9TvtY8L2I3lNKl/tbTxEOxs5V82HjljEigf3+9fTP7Hv7Ztv+0Q114O8WaPaaT4w0+1+2j7E7Gz1G2BVWliDEtGys67oyzcMrKzfMEJ4ZxjzwakvIKOYRnNUqkXGT6Pr6M9I/aw1o6B+zX8Sr5ZPLeTw5eWUbA4Ie4jMC4PrulFeAf8AwStoQt/hj408TNHibUPECWobH3o7e2jcfk1xJXdf8FGdcaU/Zi1TTg5V9c1fTbFecZ2Ti4I/75tzV/8A4J86A2h/sueG55Ytk2rXmo38mf4g13IiH/v3GlWvdwz82Zy9/MYr+WN/vdj6Pr4b/wCCqOupB4G8B+GTJhrvWbnUto7i3tzH/wC3Vfclfmx/wVCvrvxF8W/A/gPTZA11DokjwJkf66+uvKT3BJtlpYNXrK5eay5cJLzt+Z9t/szeH5PC/wCz18OdEmjEc8PhrT5J164mkgWST/x92r4g/wCCgko8cftW+CPhwsfmRtYaTpzLnOZL2/kRhj/dMdfpFp1jBpen2umWq7YbSFII19FVQoH5Cvyr/aD8a6+/7eGreJfC/hi48Taj4a1mxOnaTbQSzyXMllaxOVCQhnO2SORztBwFJPAJq8JedWU/JswzO1PDQpdG0vuP1bVVVQqKAo4AAxivFP21Nfs/D37L/wAQJ7yZI/t+mf2XFuP3pLmRYVA9T+8z+FfN8v7f37ScBCzfsvX0bE7dr6XqanPpgx15x491D9s/9tTUtO8M3nwxvNC0K0uRPHDJptxpmnRuQVE9xPc5aZkUsMR5IDHEZJzSpYWcZqU2kl5lV8xpVKcqdJNyatazPf8A/gmBolzp/wAD/EOs3CbY9X8UTvAf70cVtbxk/wDfayD/AIDXj/imX/hP/wDgqJp+nECaLTNctI4zkEKLHTRct+Ukb/jX3f8ABj4X6T8Gfhj4f+GujzefFo1r5ctzs2G5uHYvPMVydu+V3bGTjOM8V+XPhTWfjb4l/ap8aeOvgFobaz4oi1XWtRhUrbusVjJctDv/AH7qn3ZY1GDu+bjjNaUZe1qVJrsc+Ji8NRoUn0abtrtv+Z+vefavlH/gpT4q07SP2eB4YnlX7Z4l1qygt4wfm2wP9od8f3R5SKT2Mi+teUX3xF/4Kh2dvLNP8P5lWJdzNBpumzOB/sqkjFj7AE+1cJ+z/wCBLb9tb4lT6h+0B8ZNcv8AXPD8bSSeGXshavNaCQBvJmRgsUYYosqpEkoJGWHyuZpUPZS9pKSsu2prica68Pq9ODUpae8reu59c/sB+G77w3+y34V/tCPy5dVkvdVRT/zxmuZGhb6NHsYH0au//aI+L1n8D/hD4g+IU/lPd2kHkaZDJ0nvpTsgQgcld5DNjoise1eg2FhZaXY2+m6baxWtpaQpBBBEgSOKNAAqKo4CgAAAdAK/Nr/got8W7bx98WdD+CNp4gi07QvC80Umr3rI0scF/cBVMrKgLOLe3kJ2qCSZpFxkCs6UfrNe72erOjEVP7PwijHdJJev9anqX/BNX4T3dt4e8QfHzxOHuNW8W3EllY3MwBke2SUtcz5wDma4zu9fs6nvXFfCW5j+F/8AwUx8X+Ftwhg8S3OpW+Bwpa8t49UU/XcuB7n8K988IftjfsceBfCukeDPD/xQit9N0OxhsLWP+xtQyIo0Crn/AEfkkDJPckmvkb48/Gr4cax+2b4J+M3wx8Tx6npNvJoralcC1ng8uSO6eO4BWVEb/j2KcjjBxng1vBTqVJ8yaTT/AOAcNb2OHo0uSSbjJN2d/U/UwUMyopZiABySegFLXH/GPxJ/wh3wk8a+KwcNo/h7Ub5f96O3dlH5gV58Vd2PdlJRi5PofAP/AAT5jPjr9q7xr8RXAeI6fqupA8ErLe38bJz/ALhlGa/S6vgD/glJ4Za3tPiL4obmN20vSoDjlTEs8knPuJYvy+lfa/xO+IGi/CvwBr3xD8RMfsGg2Ul3IgOGmYDCRL/tO5VF92FdWM96tyryR5uVJQwinLS92/6+R8Q/t+eOta+Lnxc8I/sreA5fNuFvLebUNuSov7gYhV8EHbDA7zOP7soPG2vZP2uPhJo2gfsUan4F8MWwS18F2WnXFmW+9stZ4/OkY92aIzFm7lmJ618o/sf/ABY+Fmi/GTxR8e/2hfHtvZeILrzW06M2V3cbrm6ZjczL5cbiNVTEUa7uFkdcAAV9XfEv9sP9k3x78OfFHgh/ixFt8QaPeaZk6PqAwZoWQHPkccsDWtSM6coQgnaOu3U5qM6eIp1atSSUp3STey6F39grW7Lx1+ytoGkavBb3y6Nc3mj3EE8ayJtjnaSFSpyOIpIcDHYV9IW1rbWUEdrZ28cEEShI440CoijoABwB7V8I/wDBKnxV53h/4geCJVMbWt7Y60ilgcm4ieGQD/d+yx5P+0K+865sTHkrSR6GXVPa4WEvK33aBRRRWB2iZpa8n/aT0j48638P4bL9nfW7HSfEv9oxST3N1KiYswkm9Y/MikQuX8oYYAY3HIIFfJt5p/8AwVe0pykGsXd8ucB4B4ccEev7xAf0renR9or8yXqcdfFuhK3s5S80rn6EOyRozuyqqjJJOAB6mvzH/YrS18T/ALcPifxH4ZjQ6MsniPVYHgUeV9jmu9sIGOApE8ZA/wBnp6bWrfDP/gpv8VtPn8L+NNZvrLSr4GK5FzqelWMLoeGWQ2A8xkIJBXBBGQQa9d+A3g34I/sM6deW3xV+Kui/8Jz4lSFr3yw7fZ7dNxjhijUNII9zOTIyrvOOAFAFznSwVKTqTWum+hnhsJjM8xdKnhKE2462UW5P0SuyD/gqRBdy/BHwrLCjtBD4vhMxGcLmxvApPoMnGfUj1r2H9jLUtM1P9l/4dyaXMkiW+jpaTbSDtnido5VOO4kVq3fHfhT4a/tSfB/UPDUWvW2qaBrsYNvqWmTrIbe4jcPHKjDgOjqpKnryrDBIr4l039mf9vb9na7vbH4JeJxqWlXcvmZ0q9tPKlIGPMe01AeXHIQACU3HCqC5AFOlKGIoKCkk738mRiqVfAY2VSdNvSzVtU10a+R+kjukas7sFVRliTgAepr8xLvVYP2qP+Cg+m3ugMmoeHdH1W1aC4jO6NtO0vErS56NHLcBwrDgidOuednW/hL/AMFK/jRYTeFPiDrF7Z6RdjyrmO91PTLG2lQ9VlGnAvIhGcqVYHuK+p/2Uv2T9A/Zt0S7u7jU11vxbrKKmpakIjHFHEpytvboSSsYJyzE7nYAnACIlRUMNFvmTk9NDGbq5jOEeRxgnd30v5W/r/P3z8K/NL9jVm+IH7dfjDxlKTKlv/wAJFrUMhAIAlvFhjAPb93ckD2Br9I9W+3f2Xef2YivefZ5Ps6s20NLtO0E9ucc1yH+wj+yv8UPgH4j8Va/8ToNJWTUdOtLKxeyvftDMRI7zljtG3JEPrnn0rOhKMKc7vWx0YunOriKKSdk238tj7HooormPRMnxbrkPhjwprXiW4YLFpOn3N87EgALFGzknPstfAf8AwSm0GaXW/iF4pu8mSCx0ywVz3aV55Jf/AEVH+dfa3x58MeJfG3wX8a+C/B8UEmseINEu9LtVnl8qPM8ZiJZucAK7H8K8o/Ya/Z/8bfAHwH4j0r4hQafFq2sa39rRbK589BbLbxImW2j5twl49MV005RjRmr6ux51enKpjKUraRT16an0nX5pXjH4Mf8ABTRZkQWem65r8YAUBVmTVbVVbp2+1zEn3TNfpZXxb+2H+yr8Yfij8afDvxa+EMGjPPpenWiS/br82xW7tbqSaFxhTuz5ig/7ownYsoxk1J6NNBmVOc4RnTV3GSZ9O/Gf4naX8Hfhf4h+I+qiN00ezaSCF22/abpsJBCD2Lysi+2c9q+Cf2L/wMcNB/aSHjD4u/HKzvdYtL3UXitSt3NaG6vncy3dwWidWKguqgZ25Mgx8ox9Aftv8Awc+Pfx50zw74Q+Gmn6QuhWTPqWpfbdT+ztNeYKRR4CtlEVpCc8FnUj7te9fB/wCGukfCD4aeHvhxohD2+h2SQPNtwbic5aaZv9p5Gdz7tThUVGj7r95/gialGWKxX7yPuRXXq2eQ/wDDcZP9lL/oQdR/8KLUf/j9fK/7e37LPwt+CPhTwt4h+GWhXembfVL+50vUVl1C4uhI7Q+ZCZzO2zCxTdMZyM9BX6cV4b+2R8GfEvxz+C1x4P8Gw2cuuwanaahZLdz+TFso5WTL4OD5UkuOOuBRQxM41E5SdgxewUXQl7OC5raWWp6D8G/Fx8e/CTwZ41c5k1zQbC/lHdZJIEd1PumLA/SvNP26vEkfDf7LfjCQyASalFa6VGu4Av9ouYo3A9f3bSHjspgjwB4C/aR+Gv7H8Xw68Of2XH8TNJWW202YXUUsEcD3pdWDSocLJbuyqrrgsi545r5v8AEu/sx/t6/tA6zp2kfG3xFDDpNjMZI7q9vLH7NbkgqZUtbEL5ku0kAsqnDEb1GNmcTpw9pzOSsmLEV6vsFTjTblKPbRN9z3L/gmf4e/sn9nc61pkwfEHiO9u1bHJSJYrbH/fVu/wCdebf8FKfirqGu6v4Z/Zy8GpJeX15cW+oajbQtgz3Ej+XY2memWdjIQcYPkHvX2h8Nfh9ovwk+HWi/D3wvHNLY6BZLbQmVlEtw4yzyOeBvkcs7HgbmPQV8o/Av9kz4xSftM6l+0B8fodG8xprjVLOCxvzc/wCmviOBCNo/dwQ5Vc85SI9jThUi6sq0um36E1qNWOGhhILfRvsup2nhT/gnR+zlY+GdJs/Fnhm/1bW4LKFNRvk1u+gW5uQg82RY0lCopfJCgcDArW/4d5/spf8AQg6j/wCFFqP/AMfr6QorF4iq9eZ/edawGFSt7Nfcj82P2MYj8IP22vGPwoMxjsbhdY0a1hdyS/kXCz2rEnkn7PE/U5O8nnrX6T18X+K/2Wfi7b/tt2f7QXg210p/DbatZX12Zb8R3CRm0S1uwse07sp5jDkZLV9oVeJnGpJST3WvqZZdTnRhOnJWSk7egUUUVzHoBRRRQAhxivkb9mLW/gunhPW/id8VPEfhCHxb4t8Qak95da/e2qTiJJ3jjhTzmBWMKOFHGCB0AA9w/aVurqx+AHxBu7K5lt54vD160csTlHQ+UeQRyDX50/s1+F/h14z+IN9oXxK0vUb7Tk0DUNQhWyuDEyS26rIWJBBPyB8DON23IIzXiZjinRxVKEYptp7vS7t/k/vP1jgjhynmfDuYYytVnCMZQv7OKc3GKcmtZRVm5RbX9xH2H8Dx4R8LftR+PfB3wxuNOHhLWfDlj4hW10yVHsorwTeU7QiM7F3K/IHoo6KAPpa+vbPTLOfUdRuora1tY2mnmlcIkUajLMzHgAAEkmvyp/ZDury2/aL8AqtxLEZ7ueKcK+3zFNnOSrY4I3AHHTIHoK/VwjNa5NifrNCUrWtJ/jr+pweKORPIM3pUZVHUcqUG5NWbcbwu9Xdvkvc5XRfit8MfEmqDRPD3xC8OanqJkMQtLTU4Zpt4TzCuxWJzsIbGPunPStLxH4y8JeEFt38V+JtL0dbx2jtzfXccAlZRkhd5G4gcnFc/8Pf+Ru+J/wD2NVv/AOmPS6h8dweIbjx74Rj8M6pp1hd/ZtTLS39g93GY9sGVCJNEQ2dvzbsDBGDnI9Y/NjstI1nSPEGnRavoep2uoWM+7yrm2lWSJ8MVO1l4OCCPqDWTrPxG8AeHdRfSNe8aaJp97DGsssFzfRxvDG3CPICfkViCAWwCRxmtfSotVg0+GPXLy0u75QfOmtLZreJzngrG0khUYxwXb+lcb8GJbF/DGoxqw/taLXdUGtqx/erfG6kLeZn5gDGYjHn/AJYmHb8m2gDt72+stNtZL7ULuG2t4hmSWVwiIM45J4HJpLnULGzmtLe7vIYZb+Y29rHJIFaeURvIUQH7zBI5GwOdqMegNcl8ZlnPwv8ACBbSRccxtgImlQuitvXBZQylhnqAwz6jrXP+IrLx7b+N/hw/ibxJoF/af8JJcBYrHRJrSQP/AGNqWCXe6lGMZ4255HIxggHpOpavpWjpBJq2pWtkt1cRWkDXEyxiWeRtscSliMuzHCqOSTgU99S0+PUYdIkvYFvbmGW5htjIBLJFGyLI6r1Kq0sQJHAMi56iuM+Lmg6Z4o0/QfD2swedZ3+txQyqGKsB5MxDKykMjqQGV1IKsFYEECuX8Mazq1z8adC8L+KZvM1/w74X1yG5m2BBf20l3pX2e9VRgASrG4ZQAFljmQZVVZgD1PXvEWg+FtNfWPEutWOlWMbIjXN5OsMYdmCou5iBuZiAB1JIA5NR+H/FPhrxXbTXfhnXtP1SG2mNvO1pcLL5MoUMY32n5HCsp2nBwwOOa5TxYYo/jD4Cl1Zo103+z9ajtDOR5f8Aa7fZPs+zP/LY2o1IKRzsMw7nLh9nl+OSPpDxF4PDE0WveWQWDG6hbTRJ7hf7SKjqAznowyAdq+oWEd/DpUl5At7cQyXEVuZAJZIo2RZHVc5KqZIwSOAXXPUVY6VxGq/8lt8L/wDYq69/6V6VXWayuoPpF8ukMq3xtpRalugl2nYT/wACxQBjH4lfD0a6PDB8b6H/AGsbn7GLP7fF5v2nGfI27v8AW458v72OcYrpOPWvIPN8Gf8ADkcuzB/sc+FzbGPB+0fafJ2eXt+/9r+0fLt/1nn8ffrr/AconhUfCDXU0J5G8XDw3dCzaDG46l9lbyynbPm4xQBcf4l/DyPVf7Dk8b6Et/wDbF0/yDfxbhdswVbc/NxKWIAj+8SRxW7e39jplq17qF3DbW6FQ0srhEBYhVGTxySAPcivPJ/Flv4W8B+G9Y+GOk6BeeDCum2dvtvJISlvPcRQJ5KrGynasmcMVOVwccmtr4u/8iBqH/Xaz/wDSqKgDptV1XS9C0u71zW9QttP07T4Huru7uZViht4UUs8ju2AqqoJLHAABJrO8P+OPBviuaa28MeKtJ1aW3UPMlleRzNGCcAsFJwM1ifHEOfgt49EbKrnwzqe0sMgH7LJjIyM/nW34etPGltLcHxZr+iajGwX7Oun6RLZNGedxcyXM27PGAAuMHrngAd4g8aeEfCklvD4l8S6bpkl0skkEd1cpG0iJt8xwCclV3rubou5ckZFalpd2l/aw31hdRXNtcRrLDNC4dJEYZVlYcEEEEEcEGuQ8SeG/ENl4mufHvg3UtLW/l0yGwv7DVVZbe6ht3nlhxOmWtWDXE2ZNkqlSP3ZIBrb8FeJrbxr4O0PxjZWsttb67p1tqUUMpUvGk0SyBWKkgkBsZBIPYmgDZxS0UUAFFFFABRRRQBkeLvC2jeN/DGqeEPEVu0+maxaSWV3GkjRs0TqVYBlIIOD1FfLl9/wTr8JQ30l54U+LXi3RhIHQqUt5WEbgq0e9VQ7SpKkHOQSDnJr66ormr4OhiWnVjdo97J+J83yCMqeXV3CMt1o0/VSTX4Hzr8Hv2Jfhz8JvFNh43PiLXtd1nS3eS0a6eKKCJmjaMt5cagsdrsPmYjnpX0VRRV0MPSw0eSlGyOXN86zDPsR9azKq6k7Wu+i3sktErtuy7kEFlZ2stxPbWkMUl3IJrh0QK00gRUDuR95tiIuTztVR0ArP8ReD/CXi+KC38W+FtI1uK2cyQpqNlFcrE5GCyiRSFOOMjtWvRWx5ZS0bRNG8O6dFo/h/SLLTLC33eVa2cCQwx7mLNtRAFGWJJwOSSe9Zur+APAniDVI9b17wVoOpajEEVLu706GaZQh3KA7KWAB5HPB5Fb9FAEN3Z2d/bvZ31rDcwSDDxTIHRhnPIPB5Aoms7S5kt5ri1ilktJDNbu6BmikKMhdCeVbY7rkc4Zh0JqaigCKe0tboxG5topTBIJYi6BvLcAgMuehwSMjnk0xtO099Qj1Z7G3a+hhe3juTEplSJ2VnjD4yFZkQkZwSik9BViigClrGiaN4h0+bSNf0mz1OxuABLa3kCzRSAEEbkYEHBAPI6iotB8N+HfC1idM8MaDp2kWZkMpt7G1SCMuerbUAG44GT1OK0qKAMTxH4H8F+MGt38W+ENF1trQOLc6lYRXJhD7d+zzFO3dtXOOu0Z6CtHTdL03RtPg0nSNPtrGytkEUFtbRLFFEg6KqKAFHsBVqigDB/wCEC8Df8JD/AMJd/wAIZoX9ubt/9p/2dD9r3bdu7zdu/O3jOc44reoooA5xvhx8PH1hvEL+BPDzaq84umvjpkHnmYHIkMm3dvH97Ofet27s7S/t2tL61huYHILRyoHQ4IIyDwcEA/UVNRQBXv8AT7DVbG40vVLKC8s7uJ4Li3uIxJFNGwIZHVshlIJBB4INZfh7wL4I8IzT3PhTwdoeiy3KhZ5NP0+G2aVQcgMY1BYAk9fWtyigDn9f+H3gLxXex6l4o8E6DrF3FGIo7i/02G4kVAxYKGdSQASTjpkk1vgBQFUYA4AHalooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKAP/9k="

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Project Information</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f6f8; }}
                .container {{ max-width: 850px; margin: 50px auto; padding: 30px 40px; background-color: #fff; box-shadow: 0 4px 15px rgba(0,0,0,0.1); border-radius: 10px; position: relative; }}
                .logo {{ position: absolute; top: 30px; right: 40px; width: 100px; height: 100px; background-image: url('data:image/jpeg;base64,{logo_base64}'); background-size: contain; background-repeat: no-repeat; }}
                h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-bottom: 20px; }}
                h2 {{ color: #34495e; margin-top: 40px; border-left: 4px solid #3498db; padding-left: 10px; }}
                p {{ color: #555; line-height: 1.7; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                table td, table th {{ padding: 14px; text-align: left; border-bottom: 1px solid #e0e0e0; }}
                table th {{ background-color: #f9f9f9; font-weight: 600; color: #333; }}
                table tr:hover {{ background-color: #f2f8fc; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="logo"></div>
                <h1>Project Information</h1>
                <p>This project was developed by as part of a <strong>Cyber Security Internship</strong>. It is designed to secure organizations in the real world from cyber frauds performed by hackers.</p>
                <h2>Project Details</h2>
                <table>
                    <tr><th>Project Name</th><td>Automatic Reconnaissance with Python</td></tr>
                    <tr><th>Description</th><td>Automated Python-based tool for efficient and comprehensive security information gathering.</td></tr>
                    <tr><th>Start Date</th><td>22-SEP-2024</td></tr>
                    <tr><th>End Date</th><td>02-NOV-2024</td></tr>
                    <tr><th>Status</th><td>Completed</td></tr>
                </table>
                <h2>Developer Details</h2>
                <table>
                    <tr><th>Name</th><th>Employee ID</th><th>Email</th></tr>
                    <tr><td>Palla Vaasanti</td><td>ST#IS#8140</td><td>22691A3750@MITS.AC.IN</td></tr>
                    <tr><td>G . Rama Pavan Kumar Reddy</td><td>ST#IS#8138</td><td>22691A3730@MITS.AC.IN</td></tr>
                    <tr><td>Tupakula Yeshwanth Kumar</td><td>ST#IS#8136</td><td>22691A3759@MITS.AC.IN</td></tr>
                    <tr><td>Sharon Rose Mallela</td><td>ST#IS#8141</td><td>22691A3739@MITS.AC.IN</td></tr>
                </table>
                <h2>Company Details</h2>
                <table>
                     <tr><th>Name</th><td>Supraja Technologies</td></tr>
                     <tr><th>Email</th><td>contact@suprajatechnologies.com</td></tr>
                </table>
            </div>
        </body>
        </html>
        """
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".html", encoding='utf-8') as f:
            f.write(html_content)
        webbrowser.open(f"file://{os.path.abspath(f.name)}")
    
    def start_recon_thread(self):
        domain = self.entry.get().strip()
        if not domain: messagebox.showwarning("Input Error", "Please enter a valid domain."); return
        
        # FIX: Improved input sanitization
        if domain.startswith("https://"):
            domain = domain[8:]
        elif domain.startswith("http://"):
            domain = domain[7:]
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
        if shodan_info and "Error" not in shodan_info:
            recon_data['Shodan'] = shodan_info
            self.log(json.dumps(shodan_info, indent=2))
        elif shodan_info:
             self.log(f"Shodan Error: {shodan_info['Error']}")
        self.log("\n=== VirusTotal API Info ===")
        vt_info = query_virustotal(domain, self.config['virustotal_key'])
        if vt_info and "error" not in vt_info:
            recon_data['VirusTotal'] = vt_info
            self.log(json.dumps(vt_info, indent=2))
        elif vt_info:
             self.log(f"VirusTotal Error: {vt_info.get('error', {}).get('message', 'Unknown error')}")
        self.log("\n=== Tech Stack ===")
        techs = detect_tech_stack(domain)
        if techs:
            recon_data['Tech_Stack'] = techs
            self.log(json.dumps(techs, indent=2))
        self.log("\n=== Screenshot ===")
        screenshot_path = take_screenshot(domain)
        if screenshot_path:
            self.log(f"Screenshot saved: {screenshot_path}")
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
            login_popup = EmailLoginWindow(self.root, saved_email=self.config.get('sender_email', ''))
            sender_email = login_popup.email.get(); sender_password = login_popup.password.get()
            if sender_email and sender_password:
                self.log(f"Attempting to send report to {recipient_email}...")
                threading.Thread(target=send_email_report, args=(recipient_email, f"Recon Report for {domain}", "Please find attached the recon report.", pdf_report_path, sender_email, sender_password), daemon=True).start()
            else:
                self.log("Email sending cancelled.")
        self.start_btn.config(state="normal")


if _name_ == "_main_":
    root = Tk()
    app = ReconApp(root)
    root.mainloop()
