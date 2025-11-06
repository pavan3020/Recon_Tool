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
from concurrent.futures import ThreadPoolExecutor, as_completed
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
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
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
            'securitytrails_key': config.get('API_KEYS', 'SECURITYTRAILS_API_KEY', fallback=''),
            'sender_email': config.get('EMAIL', 'SENDER_EMAIL', fallback='')
        }
    return {'shodan_key': '', 'virustotal_key': '', 'securitytrails_key': '', 'sender_email': ''}

def save_email_config(email):
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_PATH):
        config.read(CONFIG_PATH)
    if 'EMAIL' not in config:
        config.add_section('EMAIL')
    config.set('EMAIL', 'SENDER_EMAIL', email)
    with open(CONFIG_PATH, 'w') as configfile:
        config.write(configfile)

# --- Reconnaissance Functions ---
def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        print(f"IP resolution failed: {e}")
        return None

def get_geolocation(ip):
    if not ip:
        return "N/A"
    try:
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        data = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5, verify=False).json()
        return f"{data.get('city', 'N/A')}, {data.get('region', 'N/A')}, {data.get('country', 'N/A')}"
    except Exception as e:
        print(f"Geolocation lookup failed: {e}")
        return "N/A"

def get_whois_info(domain):
    """
    Enhanced WHOIS lookup with multiple fallback methods
    """
    # Method 1: Python whois library
    try:
        print(f"[DEBUG] Method 1: Python whois library for {domain}")
        w = whois.whois(domain)
        print(f"[DEBUG] WHOIS object type: {type(w)}")
        
        # Check if we got valid data
        if hasattr(w, 'text') and w.text:
            print(f"[DEBUG] ✓ Got WHOIS text data ({len(w.text)} chars)")
            return w
        elif hasattr(w, 'domain_name'):
            # Generate text representation from whois object
            print("[DEBUG] Converting whois object to text format...")
            class WhoisResult:
                def __init__(self, whois_obj):
                    self.text = self._format_whois(whois_obj)
                
                def _format_whois(self, w):
                    lines = []
                    # Handle both dict-like and object access
                    try:
                        items = w.items() if hasattr(w, 'items') else vars(w).items()
                    except:
                        items = []
                    
                    for key, value in items:
                        if value and not key.startswith('_'):
                            if isinstance(value, list):
                                value = ', '.join(str(v) for v in value)
                            elif isinstance(value, datetime.datetime):
                                value = value.strftime('%Y-%m-%d %H:%M:%S')
                            lines.append(f"{key.replace('_', ' ').title()}: {value}")
                    return '\n'.join(lines) if lines else "WHOIS data available but format unknown"
            
            result = WhoisResult(w)
            if result.text:
                print(f"[DEBUG] ✓ Formatted WHOIS data ({len(result.text)} chars)")
                return result
        
        print("[DEBUG] ✗ WHOIS returned but no readable data")
            
    except Exception as e:
        print(f"[DEBUG] ✗ Python WHOIS failed: {type(e).__name__}: {str(e)}")
    
    # Method 2: Direct socket connection to WHOIS server
    try:
        print("[DEBUG] Method 2: Direct socket connection to WHOIS server...")
        
        def socket_whois(domain):
            # Determine appropriate WHOIS server
            tld = domain.split('.')[-1]
            whois_servers = {
                'com': 'whois.verisign-grs.com',
                'net': 'whois.verisign-grs.com',
                'org': 'whois.pir.org',
                'info': 'whois.afilias.net',
                'biz': 'whois.biz',
                'io': 'whois.nic.io',
                'co': 'whois.nic.co',
                'uk': 'whois.nic.uk',
            }
            whois_server = whois_servers.get(tld, 'whois.iana.org')
            
            port = 43
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            
            try:
                sock.connect((whois_server, port))
                sock.send(f"{domain}\r\n".encode())
                
                response = b""
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                
                return response.decode('utf-8', errors='ignore')
            finally:
                sock.close()
        
        whois_data = socket_whois(domain)
        if whois_data and len(whois_data) > 50:
            class WhoisResult:
                def __init__(self, text):
                    self.text = text
            print(f"[DEBUG] ✓ Socket WHOIS successful ({len(whois_data)} chars)")
            return WhoisResult(whois_data)
        
    except Exception as e2:
        print(f"[DEBUG] ✗ Socket WHOIS failed: {e2}")
    
    # Method 3: System whois command
    try:
        import subprocess
        print("[DEBUG] Method 3: System whois command...")
        result = subprocess.run(['whois', domain], 
                                capture_output=True, 
                                text=True, 
                                timeout=15)
        if result.returncode == 0 and result.stdout:
            class WhoisResult:
                def __init__(self, text):
                    self.text = text
            print(f"[DEBUG] ✓ System whois successful ({len(result.stdout)} chars)")
            return WhoisResult(result.stdout)
    except Exception as e3:
        print(f"[DEBUG] ✗ System whois failed: {e3}")
    
    # Method 4: Online WHOIS service
    try:
        print("[DEBUG] Method 4: Online WHOIS service...")
        requests.packages.urllib3.disable_warnings()
        response = requests.get(f"https://www.whois.com/whois/{domain}", timeout=10, verify=False)
        if response.status_code == 200:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            pre_tag = soup.find('pre', class_='df-raw')
            if pre_tag:
                class WhoisResult:
                    def __init__(self, text):
                        self.text = text
                print(f"[DEBUG] ✓ Online whois successful")
                return WhoisResult(pre_tag.get_text())
    except Exception as e4:
        print(f"[DEBUG] ✗ Online whois failed: {e4}")
    
    print("[DEBUG] ✗ All WHOIS methods failed")
    return None

def get_dns_records(domain):
    records = {}
    for t in ['A', 'MX', 'NS', 'TXT']:
        try:
            answers = dns.resolver.resolve(domain, t, lifetime=5)
            records[t] = [r.to_text() for r in answers]
        except Exception as e:
            print(f"DNS {t} record lookup failed: {e}")
            records[t] = []
    return records

def detect_tech_stack(domain):
    """
    Detect technology stack using builtwith
    """
    try:
        print(f"[DEBUG] Detecting tech stack for {domain}")
        tech_data = builtwith.parse(f"http://{domain}")
        print(f"[DEBUG] Tech stack detection complete")
        return tech_data
    except Exception as e:
        print(f"[DEBUG] Tech stack detection failed: {e}")
        return {}

def analyze_website_with_bs4(domain):
    """
    Detailed website analysis using BeautifulSoup
    """
    try:
        print(f"[DEBUG] Analyzing website structure for {domain}")
        requests.packages.urllib3.disable_warnings()
        
        # Try both http and https
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{domain}"
                response = requests.get(url, timeout=10, verify=False, 
                                       headers={'User-Agent': 'Mozilla/5.0'})
                if response.status_code == 200:
                    break
            except:
                continue
        else:
            print("[DEBUG] Could not fetch website")
            return None
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        analysis = {
            'title': soup.title.string if soup.title else 'No title found',
            'meta_description': '',
            'meta_keywords': '',
            'headings': {'h1': [], 'h2': [], 'h3': []},
            'links_count': len(soup.find_all('a')),
            'images_count': len(soup.find_all('img')),
            'forms_count': len(soup.find_all('form')),
            'scripts_count': len(soup.find_all('script')),
            'external_scripts': [],
            'stylesheets_count': len(soup.find_all('link', rel='stylesheet')),
            'comments': len(soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--'))),
            'server': response.headers.get('Server', 'Unknown'),
            'content_type': response.headers.get('Content-Type', 'Unknown'),
            'cookies_count': len(response.cookies),
        }
        
        # Get meta tags
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc:
            analysis['meta_description'] = meta_desc.get('content', '')[:200]
        
        meta_keywords = soup.find('meta', attrs={'name': 'keywords'})
        if meta_keywords:
            analysis['meta_keywords'] = meta_keywords.get('content', '')[:200]
        
        # Get headings
        for tag in ['h1', 'h2', 'h3']:
            headings = soup.find_all(tag)
            analysis['headings'][tag] = [h.get_text().strip()[:100] for h in headings[:5]]
        
        # Get external scripts
        scripts = soup.find_all('script', src=True)
        for script in scripts[:10]:
            src = script.get('src', '')
            if src.startswith('http'):
                analysis['external_scripts'].append(src)
        
        print(f"[DEBUG] Website analysis complete")
        return analysis
        
    except Exception as e:
        print(f"[DEBUG] Website analysis failed: {e}")
        return None

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
    except Exception as e:
        print(f"Screenshot failed: {e}")
        return None
    finally:
        if driver:
            driver.quit()

def find_subdomains(domain):
    """
    Enhanced subdomain enumeration with multiple methods
    """
    print(f"[DEBUG] Starting subdomain enumeration for {domain}")
    subdomains = set()
    
    # Method 1: Direct DNS resolution with concurrent checks
    def check_subdomain(sub):
        try:
            full_domain = f"{sub}.{domain}"
            socket.setdefaulttimeout(2)
            ip = socket.gethostbyname(full_domain)
            print(f"[DEBUG] Found subdomain: {full_domain} -> {ip}")
            return full_domain
        except:
            return None
    
    print("[DEBUG] Method 1: Checking common subdomains...")
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_subdomain, sub): sub for sub in COMMON_SUBDOMAINS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                subdomains.add(result)
    
    print(f"[DEBUG] Method 1 found {len(subdomains)} subdomains")
    
    # Method 2: Certificate Transparency Logs (crt.sh)
    try:
        print("[DEBUG] Method 2: Checking Certificate Transparency logs...")
        requests.packages.urllib3.disable_warnings()
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=15, verify=False)
        if response.status_code == 200:
            data = response.json()
            ct_count = 0
            for entry in data:
                name = entry.get('name_value', '')
                if name:
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(domain) and '*' not in sub:
                            if sub not in subdomains:
                                ct_count += 1
                            subdomains.add(sub)
            print(f"[DEBUG] Method 2 found {ct_count} additional subdomains")
    except Exception as e:
        print(f"[DEBUG] Certificate transparency lookup failed: {e}")
    
    # Method 3: SecurityTrails API (if configured)
    # This would require an API key in config
    
    print(f"[DEBUG] Total subdomains found: {len(subdomains)}")
    return sorted(list(subdomains))

def find_subdomains_securitytrails(domain, api_key):
    """
    Use SecurityTrails API for comprehensive subdomain enumeration
    Get free API key from: https://securitytrails.com/
    """
    if not api_key or "YOUR_API_KEY" in api_key or not api_key.strip():
        print("[DEBUG] SecurityTrails API key not configured")
        return []
    
    try:
        print("[DEBUG] Querying SecurityTrails API...")
        requests.packages.urllib3.disable_warnings()
        headers = {'APIKEY': api_key}
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        
        if response.status_code == 200:
            data = response.json()
            subdomains = [f"{sub}.{domain}" for sub in data.get('subdomains', [])]
            print(f"[DEBUG] SecurityTrails found {len(subdomains)} subdomains")
            return subdomains
        else:
            print(f"[DEBUG] SecurityTrails returned status code: {response.status_code}")
    except Exception as e:
        print(f"[DEBUG] SecurityTrails lookup failed: {e}")
    
    return []

def query_shodan(ip, api_key):
    if not ip or not api_key or "YOUR_API_KEY" in api_key:
        return {"Error": "IP or Shodan API Key is missing from config.ini"}
    
    try:
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        
        # Try the full host endpoint first (requires membership)
        response = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}", 
                               verify=False, timeout=10)
        result = response.json()
        
        # Check if membership is required
        if 'error' in result and 'membership' in result['error'].lower():
            print("[DEBUG] Full Shodan API requires membership, trying alternative...")
            
            # Fallback: Use DNS resolve endpoint (free tier)
            dns_response = requests.get(f"https://api.shodan.io/dns/resolve?hostnames={ip}&key={api_key}",
                                       verify=False, timeout=10)
            
            # Use search API with limited info (free tier)
            search_response = requests.get(f"https://api.shodan.io/shodan/host/search?key={api_key}&query=ip:{ip}",
                                          verify=False, timeout=10)
            search_result = search_response.json()
            
            if search_result.get('matches'):
                match = search_result['matches'][0]
                return {
                    'ip_str': match.get('ip_str', ip),
                    'org': match.get('org', 'N/A'),
                    'isp': match.get('isp', 'N/A'),
                    'asn': match.get('asn', 'N/A'),
                    'ports': match.get('ports', []),
                    'hostnames': match.get('hostnames', []),
                    'country_name': match.get('location', {}).get('country_name', 'N/A'),
                    'city': match.get('location', {}).get('city', 'N/A'),
                    'note': 'Limited info - Free API tier used'
                }
            else:
                return {"Info": "No Shodan data available for this IP (Free tier limitation)"}
        
        return result
        
    except Exception as e:
        return {"Error": f"Shodan query failed: {e}"}

def query_alternative_ip_intel(ip):
    """
    Alternative IP intelligence using free services
    """
    intel_data = {}
    
    try:
        # 1. IPInfo.io (Free tier: 50k requests/month)
        print("[DEBUG] Querying IPInfo.io...")
        requests.packages.urllib3.disable_warnings()
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10, verify=False)
        if response.status_code == 200:
            data = response.json()
            intel_data['ipinfo'] = {
                'ip': data.get('ip'),
                'hostname': data.get('hostname', 'N/A'),
                'city': data.get('city', 'N/A'),
                'region': data.get('region', 'N/A'),
                'country': data.get('country', 'N/A'),
                'location': data.get('loc', 'N/A'),
                'org': data.get('org', 'N/A'),
                'postal': data.get('postal', 'N/A'),
                'timezone': data.get('timezone', 'N/A')
            }
    except Exception as e:
        print(f"[DEBUG] IPInfo failed: {e}")
    
    try:
        # 2. IP-API.com (Free, no key needed)
        print("[DEBUG] Querying IP-API.com...")
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                intel_data['ip-api'] = {
                    'isp': data.get('isp', 'N/A'),
                    'org': data.get('org', 'N/A'),
                    'as': data.get('as', 'N/A'),
                    'asname': data.get('asname', 'N/A'),
                    'mobile': data.get('mobile', False),
                    'proxy': data.get('proxy', False),
                    'hosting': data.get('hosting', False)
                }
    except Exception as e:
        print(f"[DEBUG] IP-API failed: {e}")
    
    try:
        # 3. AbuseIPDB Check (requires free API key)
        # You can get free key at: https://www.abuseipdb.com/api
        print("[DEBUG] Note: For AbuseIPDB data, get free API key at https://www.abuseipdb.com/api")
    except:
        pass
    
    return intel_data if intel_data else None

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
    
    # --- 2.5. Subdomains Section ---
    subdomains = data.get('Subdomains')
    if subdomains:
        story.append(Paragraph(f"Discovered Subdomains ({len(subdomains)} found)", styles['h2']))
        sub_chunks = [subdomains[i:i+3] for i in range(0, len(subdomains), 3)]
        sub_data = []
        for chunk in sub_chunks:
            row = [Paragraph(s, styles['Normal']) for s in chunk]
            while len(row) < 3:
                row.append('')
            sub_data.append(row)
        
        if sub_data:
            sub_table = Table(sub_data, colWidths=[2.2 * inch, 2.2 * inch, 2.2 * inch])
            sub_table.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BACKGROUND', (0, 0), (-1, -1), colors.beige),
            ]))
            story.append(sub_table)
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
    
    # --- 3.5. Website Analysis Section ---
    web_analysis = data.get('Website_Analysis')
    if web_analysis:
        story.append(Paragraph("Website Analysis (BeautifulSoup)", styles['h2']))
        
        web_data = [
            ['Page Title:', Paragraph(web_analysis.get('title', 'N/A'), styles['Normal'])],
            ['Server:', web_analysis.get('server', 'Unknown')],
            ['Content Type:', web_analysis.get('content_type', 'Unknown')],
            ['Links Count:', str(web_analysis.get('links_count', 0))],
            ['Images Count:', str(web_analysis.get('images_count', 0))],
            ['Forms Count:', str(web_analysis.get('forms_count', 0))],
            ['Scripts Count:', str(web_analysis.get('scripts_count', 0))],
            ['Stylesheets Count:', str(web_analysis.get('stylesheets_count', 0))],
            ['HTML Comments:', str(web_analysis.get('comments', 0))],
            ['Cookies:', str(web_analysis.get('cookies_count', 0))],
        ]
        
        if web_analysis.get('meta_description'):
            web_data.append(['Meta Description:', Paragraph(web_analysis['meta_description'], styles['Normal'])])
        
        # Add H1 headings
        h1_tags = web_analysis.get('headings', {}).get('h1', [])
        if h1_tags:
            web_data.append(['H1 Headings:', Paragraph('<br/>'.join(h1_tags), styles['Normal'])])
        
        web_table = Table(web_data, colWidths=[2 * inch, 4.5 * inch])
        web_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 1, colors.black), ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey), ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ]))
        story.append(web_table)
        
        # Add external scripts if any
        ext_scripts = web_analysis.get('external_scripts', [])
        if ext_scripts:
            story.append(Spacer(1, 0.1 * inch))
            story.append(Paragraph("External Scripts:", styles['h3']))
            script_data = [[Paragraph(script, styles['Normal'])] for script in ext_scripts[:15]]
            if script_data:
                script_table = Table(script_data, colWidths=[6.5 * inch])
                script_table.setStyle(TableStyle([
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('BACKGROUND', (0, 0), (-1, -1), colors.beige),
                ]))
                story.append(script_table)
        
        story.append(Spacer(1, 0.2 * inch))
    
    # --- 3.6. Alternative IP Intelligence Section ---
    alt_intel = data.get('Alternative_IP_Intel')
    if alt_intel:
        story.append(Paragraph("IP Intelligence (Alternative Sources)", styles['h2']))
        
        intel_data = []
        
        if 'ipinfo' in alt_intel:
            ipinfo = alt_intel['ipinfo']
            intel_data.extend([
                ['Source:', 'IPInfo.io'],
                ['Hostname:', ipinfo.get('hostname', 'N/A')],
                ['Organization:', ipinfo.get('org', 'N/A')],
                ['Location:', f"{ipinfo.get('city', 'N/A')}, {ipinfo.get('region', 'N/A')}, {ipinfo.get('country', 'N/A')}"],
                ['Coordinates:', ipinfo.get('location', 'N/A')],
                ['Timezone:', ipinfo.get('timezone', 'N/A')],
                ['', ''],  # Spacer
            ])
        
        if 'ip-api' in alt_intel:
            ipapi = alt_intel['ip-api']
            intel_data.extend([
                ['Source:', 'IP-API.com'],
                ['ISP:', ipapi.get('isp', 'N/A')],
                ['AS Number:', ipapi.get('as', 'N/A')],
                ['AS Name:', ipapi.get('asname', 'N/A')],
                ['Hosting Provider:', 'Yes' if ipapi.get('hosting') else 'No'],
                ['Proxy Detected:', 'Yes' if ipapi.get('proxy') else 'No'],
                ['Mobile Network:', 'Yes' if ipapi.get('mobile') else 'No'],
            ])
        
        if intel_data:
            intel_table = Table(intel_data, colWidths=[2 * inch, 4.5 * inch])
            intel_table.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ]))
            story.append(intel_table)
            story.append(Spacer(1, 0.2 * inch))

    # --- 4. WHOIS Data Section ---
    whois_text = data.get('WHOIS')
    if whois_text:
        story.append(PageBreak())
        story.append(Paragraph("WHOIS Information", styles['h2']))
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
    project_details_data = [['Project Name', 'Automatic Reconnaissance with Python'], ['Project Description', Paragraph('Automated Python-based reconnaissance tool for efficient and comprehensive security information gathering.', styles['Normal'])], ['Project Start Date', '30-jul-2025'], ['Project End Date', '30-aug-2025'], ['Project Status', 'Completed']]
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
    def __init__(self, parent, saved_email=""):
        super().__init__(parent)
        self.title("Sender Email Details")
        self.geometry("350x200")
        self.transient(parent)
        self.grab_set()
        
        self.email = StringVar(value=saved_email)
        self.password = StringVar()
        self.save_email = BooleanVar(value=True)
        
        Label(self, text="Your Email:").pack(pady=5)
        Entry(self, textvariable=self.email, width=40).pack()
        
        Label(self, text="Your App Password:").pack(pady=5)
        Entry(self, textvariable=self.password, show="*", width=40).pack()
        
        Checkbutton(self, text="Save email for next time", variable=self.save_email).pack(pady=10)
        
        Button(self, text="Send Email", command=self.submit).pack(pady=5)
        
        self.wait_window(self)

    def submit(self):
        if self.save_email.get():
            save_email_config(self.email.get())
        self.destroy()

class ReconApp:
    def __init__(self, root):
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
        # Add this as a new line in your GUI setup
        self.project_summary_btn = Button(self.root, text="Project Overview", font=("Arial", 12), bg="#007acc", fg="white", command=self.show_project_summary, width=20)
        self.canvas.create_window(450, 200, window=self.project_summary_btn)
        self.output_text = Text(self.root, font=("Consolas", 11), bg="#000", fg="#00FF00", state="disabled")
        self.canvas.create_window(450, 430, width=600, height=300, window=self.output_text)
        self.scrollbar = Scrollbar(self.root, command=self.output_text.yview)
        self.output_text.config(yscrollcommand=self.scrollbar.set)
        self.canvas.create_window(750, 430, height=300, window=self.scrollbar)

    def log(self, msg):
        self.root.after(0, self._log_thread_safe, msg)
    def show_project_summary(self):
        summary_text = (
            "Project Overview and Significance\n"
            "This project is an automated reconnaissance tool designed to perform comprehensive OSINT (Open Source Intelligence) gathering on target domains. "
            "It efficiently collects data from diverse sources, including WHOIS records, DNS entries, subdomains, IP intelligence, and technology stack detection. "
            "The tool produces detailed PDF reports that assist security teams in vulnerability assessments and penetration testing preparation.\n\n"
            "Manual reconnaissance can be tedious and prone to errors, often requiring gathering information from over ten different sources, taking hours to complete. "
            "This tool automates the entire process, reducing the time from several hours to 2-3 minutes and providing more thorough results. "
            "By doing so, it aids organizations in proactively identifying their attack surface before potential attackers do.\n\n"
            "Building on this foundation, the project focuses on accelerating and enhancing intelligence gathering for cybersecurity professionals, saving valuable time while increasing accuracy.\n\n"
            "Technology Stack\n"
            "- Languages & Frameworks:\n"
            "  Python for core programming, Tkinter for user-friendly GUI, and threading to maintain responsiveness during scanning operations.\n"
            "- Libraries and Tools:\n"
            "  Requests for web and API interactions, python-whois for domain data, dnspython for DNS queries, BeautifulSoup and Selenium for web scraping and automating browser tasks, ReportLab for generating professional PDF reports, and builtwith for detecting underlying technologies on websites.\n"
            "- Integrated APIs:\n"
            "  VirusTotal provides insights into domain reputations and malware detection; Shodan offers IP intelligence and open port data; SecurityTrails enables thorough subdomain enumeration; IPInfo supplies IP geolocation and related data.\n\n"
            "Future Enhancements\n"
            "- Addition of port scanning using tools like Nmap to detect open services.\n"
            "- Correlating technology detections with known vulnerabilities through CVE integration.\n"
            "- Implementing scheduled scans with alert notifications for changes detected.\n"
            "- Developing a web interface for wider accessibility and improved interaction.\n"
            "- Offering API endpoints to allow integration with other cybersecurity tools.\n"
            "- Enhancing security features such as PDF report encryption, audit logging, and role-based access controls.\n"
        )

        from tkinter import Toplevel, Text, Scrollbar, RIGHT, Y, LEFT, BOTH
        top = Toplevel(self.root)
        top.title("Project Summary")
        top.geometry("700x500")  # Adjust window size for better width/height
        txt = Text(top, wrap='word', width=80, height=30)
        scrollbar = Scrollbar(top, command=txt.yview)
        txt.configure(yscrollcommand=scrollbar.set)
        txt.insert('1.0', summary_text)
        txt.config(state='disabled')  # Make read-only
        txt.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)



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
            os.startfile(info_path)
        except Exception as e:
            self.log(f"[ERROR] Could not generate or open Project Info PDF: {e}")
            messagebox.showerror("Error", f"Could not generate Project Info PDF: {e}")
    
    def start_recon_thread(self):
        domain = self.entry.get().strip()
        if not domain: 
            messagebox.showwarning("Input Error", "Please enter a valid domain.")
            return
        
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
        ip = resolve_ip(domain)
        recon_data['IP_Address'] = ip
        self.log(f"[\u2713] IP Address: {ip or 'Not Found'}")
        
        geo = get_geolocation(ip)
        recon_data['Geolocation'] = geo
        self.log(f"[\u2713] Location: {geo}")
        
        self.log("\n=== DNS Records ===")
        dns_recs = get_dns_records(domain)
        recon_data['DNS_Records'] = dns_recs
        for record_type, records in dns_recs.items():
            if records:
                self.log(f"{record_type} Records:")
                for record in records:
                    self.log(f"  - {record}")
        
        self.log("\n=== WHOIS Information ===")
        w = get_whois_info(domain)
        if w and hasattr(w, 'text') and w.text:
            recon_data['WHOIS'] = w.text
            # Display first 20 lines of WHOIS in GUI
            whois_lines = w.text.splitlines()[:20]
            for line in whois_lines:
                self.log(line)
            if len(w.text.splitlines()) > 20:
                self.log(f"... ({len(w.text.splitlines()) - 20} more lines in PDF report)")
        else:
            self.log("WHOIS information not available")
        
        self.log("\n=== Subdomain Enumeration ===")
        
        # Try SecurityTrails first if API key is available
        subs = []
        if self.config.get('securitytrails_key') and self.config['securitytrails_key'].strip():
            self.log("Using SecurityTrails API...")
            subs = find_subdomains_securitytrails(domain, self.config['securitytrails_key'])
        
        # If SecurityTrails didn't work or no API key, use standard methods
        if not subs:
            self.log("Using DNS enumeration and Certificate Transparency...")
            subs = find_subdomains(domain)
        
        if subs:
            recon_data['Subdomains'] = subs
            self.log(f"Found {len(subs)} subdomains:")
            # Display first 15 subdomains in GUI
            for sub in subs[:15]:
                self.log(f"  - {sub}")
            if len(subs) > 15:
                self.log(f"  ... and {len(subs) - 15} more (see PDF report)")
        else:
            self.log("No subdomains found")
        
        self.log("\n=== Shodan API Info ===")
        shodan_info = query_shodan(ip, self.config['shodan_key'])
        if shodan_info:
            recon_data['Shodan'] = shodan_info
            if "Error" not in shodan_info and "error" not in shodan_info:
                if shodan_info.get('note'):
                    self.log(f"Note: {shodan_info['note']}")
                self.log(f"ISP: {shodan_info.get('isp', 'N/A')}")
                self.log(f"Organization: {shodan_info.get('org', 'N/A')}")
                self.log(f"ASN: {shodan_info.get('asn', 'N/A')}")
                self.log(f"Open Ports: {shodan_info.get('ports', [])}")
                if shodan_info.get('hostnames'):
                    self.log(f"Hostnames: {', '.join(shodan_info.get('hostnames', []))}")
            else:
                error_msg = shodan_info.get('Error', shodan_info.get('error', shodan_info.get('Info', 'Unknown error')))
                self.log(f"Shodan: {error_msg}")
                
                # Try alternative IP intelligence if Shodan fails
                self.log("\n=== Alternative IP Intelligence ===")
                alt_intel = query_alternative_ip_intel(ip)
                if alt_intel:
                    recon_data['Alternative_IP_Intel'] = alt_intel
                    
                    if 'ipinfo' in alt_intel:
                        self.log("IPInfo.io Data:")
                        ipinfo = alt_intel['ipinfo']
                        self.log(f"  Hostname: {ipinfo.get('hostname', 'N/A')}")
                        self.log(f"  Organization: {ipinfo.get('org', 'N/A')}")
                        self.log(f"  Location: {ipinfo.get('city', 'N/A')}, {ipinfo.get('region', 'N/A')}, {ipinfo.get('country', 'N/A')}")
                        self.log(f"  Timezone: {ipinfo.get('timezone', 'N/A')}")
                    
                    if 'ip-api' in alt_intel:
                        self.log("\nIP-API.com Data:")
                        ipapi = alt_intel['ip-api']
                        self.log(f"  ISP: {ipapi.get('isp', 'N/A')}")
                        self.log(f"  AS: {ipapi.get('as', 'N/A')}")
                        self.log(f"  AS Name: {ipapi.get('asname', 'N/A')}")
                        self.log(f"  Hosting: {ipapi.get('hosting', False)}")
                        self.log(f"  Proxy: {ipapi.get('proxy', False)}")
                else:
                    self.log("Alternative IP intelligence not available")
            
        self.log("\n=== VirusTotal API Info ===")
        vt_info = query_virustotal(domain, self.config['virustotal_key'])
        if vt_info:
            recon_data['VirusTotal'] = vt_info
            if "Error" not in vt_info:
                vt_data = vt_info.get('data', {})
                vt_stats = vt_data.get('attributes', {}).get('last_analysis_stats', {})
                if vt_stats:
                    self.log(f"Malicious: {vt_stats.get('malicious', 0)}")
                    self.log(f"Suspicious: {vt_stats.get('suspicious', 0)}")
                    self.log(f"Clean: {vt_stats.get('harmless', 0) + vt_stats.get('undetected', 0)}")
            else:
                self.log(f"VirusTotal query failed: {vt_info.get('Error', 'Unknown error')}")
            
        self.log("\n=== Technology Stack ===")
        techs = detect_tech_stack(domain)
        if techs:
            recon_data['Tech_Stack'] = techs
            for tech_type, tech_list in techs.items():
                self.log(f"{tech_type.replace('-', ' ').title()}: {', '.join(tech_list)}")
        else:
            self.log("No technology stack information available")
        
        self.log("\n=== Website Analysis (BeautifulSoup) ===")
        web_analysis = analyze_website_with_bs4(domain)
        if web_analysis:
            recon_data['Website_Analysis'] = web_analysis
            self.log(f"Page Title: {web_analysis.get('title', 'N/A')}")
            self.log(f"Server: {web_analysis.get('server', 'Unknown')}")
            self.log(f"Content Type: {web_analysis.get('content_type', 'Unknown')}")
            self.log(f"Links: {web_analysis.get('links_count', 0)}")
            self.log(f"Images: {web_analysis.get('images_count', 0)}")
            self.log(f"Forms: {web_analysis.get('forms_count', 0)}")
            self.log(f"Scripts: {web_analysis.get('scripts_count', 0)}")
            self.log(f"Stylesheets: {web_analysis.get('stylesheets_count', 0)}")
            self.log(f"HTML Comments: {web_analysis.get('comments', 0)}")
            self.log(f"Cookies: {web_analysis.get('cookies_count', 0)}")
            
            if web_analysis.get('meta_description'):
                self.log(f"Meta Description: {web_analysis['meta_description'][:100]}...")
            
            # Show main headings
            h1_tags = web_analysis.get('headings', {}).get('h1', [])
            if h1_tags:
                self.log(f"H1 Headings: {', '.join(h1_tags[:3])}")
            
            # Show external scripts
            ext_scripts = web_analysis.get('external_scripts', [])
            if ext_scripts:
                self.log(f"External Scripts ({len(ext_scripts)}):")
                for script in ext_scripts[:3]:
                    self.log(f"  - {script}")
                if len(ext_scripts) > 3:
                    self.log(f"  ... and {len(ext_scripts) - 3} more")
        else:
            self.log("Website analysis not available")
        
        self.log("\n=== Screenshot ===")
        screenshot_path = take_screenshot(domain)
        if screenshot_path: 
            self.log(f"Screenshot saved: {screenshot_path}")
        else:
            self.log("Screenshot capture failed")
            
        self.log("\n=== Generating PDF Report ===")
        pdf_report_path = os.path.join(RESULTS_DIR, f"{domain}_report.pdf")
        try:
            generate_pdf_report(domain, recon_data, pdf_report_path)
            self.log(f"[\u2713] PDF Report saved: {pdf_report_path}")
        except Exception as e:
            self.log(f"[ERROR] Failed to generate PDF: {e}")
            
        self.log("\n[\u2713] Reconnaissance complete!")
        self.log("\n" + "="*50)

        self.root.after(0, self.prompt_for_email, domain, pdf_report_path)

    def prompt_for_email(self, domain, pdf_report_path):
        self.log("\n=== Email Notification ===")
        recipient_email = simpledialog.askstring("Recipient Email", "Enter the recipient's email address:", parent=self.root)
        if recipient_email:
            login_popup = EmailLoginWindow(self.root, saved_email=self.config.get('sender_email', ''))
            
            sender_email = login_popup.email.get()
            sender_password = login_popup.password.get()
            
            smtp_server = "smtp.gmail.com"
            smtp_port = 587

            if sender_email and sender_password:
                self.log(f"Attempting to send report to {recipient_email}...")
                threading.Thread(target=send_email_report, args=(
                    recipient_email,
                    f"Recon Report for {domain}",
                    "Please find attached the reconnaissance report.",
                    pdf_report_path,
                    sender_email,
                    sender_password,
                    smtp_server,
                    smtp_port
                ), daemon=True).start()
            else:
                self.log("Email sending cancelled.")
        else:
            self.log("Email notification skipped.")
        
        self.start_btn.config(state="normal")


if __name__ == "__main__":
    root = Tk()
    app = ReconApp(root)
    root.mainloop()
