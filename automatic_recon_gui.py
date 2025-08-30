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
from tkinter import Tk, Canvas, Entry, Button, Text, Scrollbar, messagebox, PhotoImage
from PIL import Image, ImageTk
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# --- Constants ---
# Define the directory structure for the project
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
RESULTS_DIR = os.path.join(OUTPUT_DIR, "results")
SCREENSHOTS_DIR = os.path.join(OUTPUT_DIR, "screenshots")

# Create the output directories if they don't exist
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

ADMIN_PATHS = ['admin', 'login', 'cpanel', 'administrator', 'wp-admin', 'user', 'backend']

# --- Utility Functions ---

def resolve_ip(domain):
    """Resolves the domain name to an IP address."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def get_geolocation(ip):
    """Gets geolocation data for an IP address from ipinfo.io."""
    if not ip:
        return "N/A"
    try:
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = resp.json()
        city = data.get("city", "N/A")
        region = data.get("region", "N/A")
        country = data.get("country", "N/A")
        return f"{city}, {region}, {country}"
    except Exception:
        return "N/A"

def get_whois_info(domain):
    """Retrieves WHOIS information for a domain."""
    try:
        return whois.whois(domain)
    except Exception:
        return None

def get_dns_records(domain):
    """Gets common DNS records for a domain."""
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    for r_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, r_type)
            records[r_type] = [ans.to_text() for ans in answers]
        except Exception:
            records[r_type] = None
    return records

def get_http_headers(domain):
    """Fetches HTTP headers from the domain."""
    try:
        resp = requests.get(f"http://{domain}", timeout=7, allow_redirects=True)
        return resp.headers
    except Exception:
        return None

def get_ssl_info(domain):
    """Retrieves SSL certificate information."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=7) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                issuer_name = issuer.get('organizationName', 'N/A')
                not_before = datetime.datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
                not_after = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                return issuer_name, not_before, not_after
    except Exception:
        return None, None, None

def brute_force_admin_panels(domain):
    """Checks for common admin panel paths."""
    found_panels = []
    for path in ADMIN_PATHS:
        url = f"http://{domain}/{path}"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                found_panels.append(url)
        except Exception:
            continue
    return found_panels

def scrape_html_meta(domain):
    """Scrapes meta tags from the domain's homepage."""
    meta_data = {}
    try:
        resp = requests.get(f"http://{domain}", timeout=7)
        soup = BeautifulSoup(resp.text, 'html.parser')
        for tag in soup.find_all('meta'):
            if tag.get('name'):
                meta_data[tag.get('name')] = tag.get('content', 'N/A')
    except Exception:
        pass
    return meta_data

def detect_tech_stack(domain):
    """Detects the technology stack used by the website."""
    try:
        techs = builtwith.parse(f"http://{domain}")
        return techs if techs else {"Info": ["No technologies detected."]}
    except Exception:
        return {"Error": ["Could not analyze technology stack."]}

def take_screenshot(domain):
    """Takes a screenshot of the website's homepage using Selenium."""
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
        print(f"Screenshot failed: {e}")
        return None

def write_report(domain, content):
    """Writes the output content to a text file."""
    path = os.path.join(RESULTS_DIR, f"{domain}_report.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path

# --- GUI Class ---

class ReconApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AUTOMATED RECON TOOL")
        self.root.geometry("900x650")
        self.root.resizable(False, False)

        # Set icon
        try:
            icon_path = os.path.join(ASSETS_DIR, "app_icon.ico")
            self.root.iconbitmap(icon_path)
        except Exception as e:
            print(f"[!] Icon Load Failed: {e}")

        self.canvas = Canvas(self.root, width=900, height=650)
        self.canvas.pack(fill="both", expand=True)
        
        # Set background
        try:
            bg_path = os.path.join(ASSETS_DIR, "background.jpg")
            self.bg_image = Image.open(bg_path)
            self.bg_photo = ImageTk.PhotoImage(self.bg_image)
            self.canvas.create_image(0, 0, image=self.bg_photo, anchor="nw")
        except Exception as e:
            print(f"[!] Background Load Failed: {e}")
            # Fallback to a black background
            self.canvas.configure(bg="black")
        
        # --- Widgets ---
        self.canvas.create_text(450, 40, text="AUTOMATED RECON TOOL", font=("Arial", 24, "bold"), fill="#00FF00")
        self.canvas.create_text(450, 80, text="Target Domain:", font=("Arial", 14), fill="#FFFFFF")
        
        self.entry = Entry(self.root, font=("Arial", 13), bg="#111111", fg="#00FF00", insertbackground="#00FF00", width=50)
        self.canvas.create_window(450, 110, window=self.entry)

        self.start_btn = Button(self.root, text="Start Recon", font=("Arial", 12), bg="#00CC00", fg="black", command=self.start_recon_thread)
        self.canvas.create_window(370, 150, window=self.start_btn)

        self.clear_btn = Button(self.root, text="Clear Output", font=("Arial", 12), bg="#CC0000", fg="black", command=self.clear_output)
        self.canvas.create_window(530, 150, window=self.clear_btn)
        
        self.info_btn = Button(self.root, text="Project Info", font=("Arial", 12), bg="#007ACC", fg="white", command=self.open_project_info)
        self.canvas.create_window(450, 190, window=self.info_btn)
        
        # Output Text area
        self.output_text = Text(self.root, font=("Consolas", 11), bg="#000000", fg="#00FF00", state="disabled")
        self.canvas.create_window(450, 430, width=800, height=380, window=self.output_text)

        self.scrollbar = Scrollbar(self.root, command=self.output_text.yview)
        self.output_text.config(yscrollcommand=self.scrollbar.set)
        self.canvas.create_window(860, 430, height=380, window=self.scrollbar)

    def log(self, msg):
        """Logs a message to the output text area."""
        self.output_text.config(state="normal")
        self.output_text.insert("end", msg + "\n")
        self.output_text.see("end")
        self.output_text.config(state="disabled")

    def clear_output(self):
        """Clears the output text area."""
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.config(state="disabled")

    def open_project_info(self):
        """Creates and opens an HTML file with project information."""
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Project Information</title>
            <style>
                body { font-family: Arial, sans-serif; background-color: #f2f2f2; margin: 0; padding: 20px; }
                .container { max-width: 800px; margin: 0 auto; padding: 20px; background-color: #fff; box-shadow: 0 0 10px rgba(0,0,0,0.2); }
                h1 { color: #333; }
                table { width: 100%; border-collapse: collapse; }
                th, td { padding: 10px; text-align: left; border: 1px solid #ddd; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Project Information</h1>
                <p>This project was developed by <strong>Anonymous</strong>.</p>
                <table>
                    <thead><tr><th>Project Detail</th><th>Value</th></tr></thead>
                    <tbody>
                        <tr><td>Project Name</td><td>Automatic Reconnaissance with Python</td></tr>
                        <tr><td>Description</td><td>Automated Python-based reconnaissance tool for efficient information gathering.</td></tr>
                        <tr><td>Start Date</td><td>22-SEP-2024</td></tr>
                        <tr><td>Contact</td><td>contact@suprajatechnologies.com</td></tr>
                    </tbody>
                </table>
            </div>
        </body>
        </html>
        """
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".html") as f:
            f.write(html_content)
            temp_file_path = f.name
        webbrowser.open(f"file://{temp_file_path}")

    def start_recon_thread(self):
        """Starts the reconnaissance process in a background thread."""
        domain = self.entry.get().strip()
        if not domain:
            messagebox.showwarning("Input Error", "Please enter a valid domain or URL.")
            return
        
        # Sanitize the input domain
        domain = domain.replace("http://", "").replace("https://", "").split("/")[0]

        self.clear_output()
        self.log(f"Starting reconnaissance on: {domain}\n")
        self.start_btn.config(state="disabled")
        
        # Run the scan in a separate thread to keep the GUI responsive
        threading.Thread(target=self.run_recon, args=(domain,), daemon=True).start()

    def run_recon(self, domain):
        """The main worker function that performs all reconnaissance tasks."""
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
            
            self.log("=== DNS Records ===")
            dns_records = get_dns_records(domain)
            for r_type, vals in dns_records.items():
                self.log(f"{r_type}: {', '.join(vals) if vals else 'None'}")
            self.log("")

            headers = get_http_headers(domain)
            self.log("=== HTTP Headers ===")
            if headers:
                for k, v in headers.items():
                    self.log(f"{k}: {v}")
            else:
                self.log("Could not fetch HTTP headers.")
            self.log("")
            
            issuer, start, end = get_ssl_info(domain)
            self.log("=== SSL Info ===")
            if issuer:
                self.log(f"Issuer: {issuer}")
                self.log(f"Valid From: {start.strftime('%Y-%m-%d')}")
                self.log(f"Valid Until: {end.strftime('%Y-%m-%d')}\n")
            else:
                self.log("No SSL info found.\n")

            panels = brute_force_admin_panels(domain)
            self.log("=== Admin Panel Finder ===")
            if panels:
                for url in panels:
                    self.log(f"[+] Found: {url}")
            else:
                self.log("No admin panels found.")
            self.log("")

            meta = scrape_html_meta(domain)
            self.log("=== HTML Meta Data ===")
            if meta:
                for k, v in meta.items():
                    self.log(f"{k}: {v}")
            else:
                self.log("No meta data found.")
            self.log("")

            techs = detect_tech_stack(domain)
            self.log("=== Tech Stack ===")
            for category, apps in techs.items():
                self.log(f"{category}: {', '.join(apps)}")
            self.log("")

            self.log("=== Screenshot ===")
            screenshot = take_screenshot(domain)
            self.log(f"Screenshot saved: {screenshot}" if screenshot else "Screenshot failed.")
            self.log("")

            self.log("=== Report Saved ===")
            report = write_report(domain, self.output_text.get("1.0", "end"))
            self.log(f"Report path: {report}\n")

            self.log("[✓] Reconnaissance complete.")
        
        except Exception as e:
            self.log(f"\n[!] An error occurred: {e}")
        
        finally:
            # Re-enable the start button once the scan is complete or fails
            self.start_btn.config(state="normal")


# --- Main Execution Block ---

if __name__ == "__main__":
    root = Tk()
    app = ReconApp(root)
    root.mainloop()