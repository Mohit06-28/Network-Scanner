from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory
from functools import wraps
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import hashlib
import secrets
import json
import os
import socket
import threading
import subprocess
import platform
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import time
from io import BytesIO

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'static', 'uploads', 'avatars')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
ALLOWED_AVATAR = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# Port → representative exposure / CVE-style hints (authorized testing only)
PORT_THREAT_INTEL = {
    21: ('FTP cleartext / weak auth', 'CRITICAL', 9.8, 'CVE-1999-0017', 'Disable anonymous FTP; use SFTP.', 'FTP'),
    23: ('Telnet cleartext credentials', 'CRITICAL', 9.8, 'CVE-1999-0619', 'Disable Telnet; use SSH.', 'Telnet'),
    25: ('Open SMTP relay / spam', 'HIGH', 7.5, 'CVE-1999-0512', 'Restrict relay; enable AUTH.', 'SMTP'),
    445: ('SMB / Windows sharing exposure', 'CRITICAL', 10.0, 'CVE-2017-0144', 'Patch MS17-010; restrict SMB to VPN.', 'SMB'),
    3389: ('RDP brute-force / BlueKeep class', 'CRITICAL', 9.8, 'CVE-2019-0708', 'Enable NLA; restrict by firewall/VPN.', 'RDP'),
    5900: ('VNC without encryption', 'HIGH', 8.2, 'CVE-2006-2369', 'Tunnel over SSH or VPN.', 'VNC'),
    22: ('SSH weak keys / brute force', 'MEDIUM', 5.3, 'CVE-2018-15473', 'Key-only auth; fail2ban.', 'SSH'),
    80: ('HTTP / outdated web stack', 'MEDIUM', 5.0, 'CVE-2021-44228', 'HTTPS redirect; patch apps.', 'HTTP'),
    443: ('TLS misconfiguration', 'MEDIUM', 5.0, 'N/A', 'Harden cipher suites.', 'HTTPS'),
    3306: ('MySQL exposed to network', 'HIGH', 8.0, 'N/A', 'Bind to localhost; strong passwords.', 'MySQL'),
    5432: ('PostgreSQL exposed', 'HIGH', 8.0, 'N/A', 'Use pg_hba.conf and firewall.', 'PostgreSQL'),
    6379: ('Redis unauthenticated', 'CRITICAL', 10.0, 'CVE-2015-4335', 'Require AUTH; bind localhost.', 'Redis'),
    27017: ('MongoDB exposed', 'CRITICAL', 10.0, 'CVE-2015-7886', 'Enable auth; network segmentation.', 'MongoDB'),
}

# Email configuration
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))
EMAIL_USER = os.getenv('EMAIL_USER', '')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD', '')
EMAIL_FROM = os.getenv('EMAIL_FROM', EMAIL_USER)

# Database setup
def get_db():
    conn = sqlite3.connect('network_scanner.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone TEXT,
                password_hash TEXT NOT NULL,
                is_verified BOOLEAN DEFAULT 0,
                otp_secret TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                api_key TEXT UNIQUE,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP
            )
        ''')
        
        # OTP codes table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS otp_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identifier TEXT NOT NULL,
                otp_code TEXT NOT NULL,
                purpose TEXT DEFAULT 'login',
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Scan history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                target TEXT NOT NULL,
                scan_type TEXT,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                open_ports INTEGER,
                total_ports INTEGER,
                high_risk_count INTEGER,
                status TEXT,
                result_json TEXT,
                alert_triggered BOOLEAN DEFAULT 0
            )
        ''')
        
        # Network maps table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_maps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                network TEXT NOT NULL,
                discovery_time TIMESTAMP,
                hosts_found INTEGER,
                devices_json TEXT,
                topology_json TEXT
            )
        ''')
        
        # Vulnerability reports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerability_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                host TEXT,
                port INTEGER,
                vulnerability TEXT,
                severity TEXT,
                cvss_score REAL,
                cve_id TEXT,
                description TEXT,
                recommendation TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                scan_id INTEGER,
                severity TEXT,
                message TEXT,
                is_read BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create default admin user (legacy SHA-256 hash for demo compatibility)
        admin_hash = hashlib.sha256('Admin@123'.encode()).hexdigest()
        cursor.execute('SELECT id FROM users WHERE username = ?', ('admin',))
        if not cursor.fetchone():
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, is_verified, api_key)
                VALUES (?, ?, ?, 1, ?)
            ''', ('admin', 'admin@localhost', admin_hash, secrets.token_urlsafe(32)))
        
        conn.commit()
    migrate_schema()

def migrate_schema():
    """Add columns / tables on existing databases."""
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    with get_db() as conn:
        cur = conn.cursor()
        try:
            cur.execute('ALTER TABLE users ADD COLUMN avatar_filename TEXT')
        except sqlite3.OperationalError:
            pass
        cur.execute('''
            CREATE TABLE IF NOT EXISTS app_ratings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                stars INTEGER NOT NULL,
                comment TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS enterprise_inquiries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                email TEXT,
                company TEXT,
                message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()

def insert_vulnerabilities_for_scan(cursor, scan_id, target, results):
    """Populate vulnerability_reports from open ports (heuristic / threat intel)."""
    if not results:
        return
    for port_key, info in results.items():
        if not info or not info.get('open'):
            continue
        try:
            port = int(port_key)
        except (TypeError, ValueError):
            continue
        tpl = PORT_THREAT_INTEL.get(port)
        if tpl:
            base, sev, cvss, cve, rec, _svc = tpl
            title = f"{base} (TCP/{port})"
        else:
            risk = (info.get('risk') or 'LOW').upper()
            if risk in ('CRITICAL', 'HIGH'):
                title = f"Exposed {info.get('service', 'service')} on port {port}"
                sev = risk
                cvss = 9.0 if risk == 'CRITICAL' else 7.0
                cve = 'N/A'
                rec = 'Restrict with firewall; disable if unused; keep patched.'
            elif risk == 'MEDIUM':
                title = f"Review {info.get('service', 'service')} on port {port}"
                sev = 'MEDIUM'
                cvss = 5.0
                cve = 'N/A'
                rec = 'Verify necessity and harden configuration.'
            else:
                continue
        cursor.execute('''
            INSERT INTO vulnerability_reports
            (scan_id, host, port, vulnerability, severity, cvss_score, cve_id, description, recommendation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id, target, port, title, sev, cvss, cve,
            f"Detected during scan of {target}. Service: {info.get('service', 'unknown')}.",
            rec
        ))

def send_email(to_email, subject, body):
    """Send email using SMTP"""
    try:
        if not EMAIL_USER or not EMAIL_PASSWORD:
            print(f"Email not configured. Would send: To={to_email}, Subject={subject}")
            return True
        
        msg = MIMEMultipart()
        msg['From'] = EMAIL_FROM
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))
        
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def generate_otp():
    """Generate 6-digit OTP"""
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

def hash_password(password: str) -> str:
    """Salted password hash (Werkzeug PBKDF2)."""
    return generate_password_hash(password)

def verify_password(stored_hash: str, password: str) -> bool:
    """Verify password; supports legacy SHA-256 hex hashes for existing accounts."""
    if not stored_hash:
        return False
    h = stored_hash.strip().lower()
    if len(h) == 64 and all(c in '0123456789abcdef' for c in h):
        return hashlib.sha256(password.encode()).hexdigest() == h
    try:
        return check_password_hash(stored_hash, password)
    except (ValueError, TypeError):
        return False

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ============ PORT SCANNER CLASS ============
class AdvancedPortScanner:
    SERVICES = {
        20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 67: 'DHCP', 68: 'DHCP', 80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC',
        139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS',
        995: 'POP3S', 1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP',
        5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt', 27017: 'MongoDB',
    }

    def __init__(self, target, ports, scan_type='tcp', threads=200, timeout=1):
        self.target = target
        self.ports = ports
        self.scan_type = scan_type
        self.threads = threads
        self.timeout = timeout
        self.results = {}
        self.high_risk_ports = [21, 23, 25, 110, 143, 445, 3389, 5900, 5800]
        
    @classmethod
    def get_service_name(cls, port):
        return cls.SERVICES.get(port, 'unknown')
    
    def get_risk_level(self, port):
        if port in [445, 3389, 23, 21]:
            return 'CRITICAL'
        elif port in [22, 3306, 5432, 5900]:
            return 'HIGH'
        elif port in [80, 443, 8080]:
            return 'MEDIUM'
        return 'LOW'
    
    def scan_tcp_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                return {
                    'port': port,
                    'open': True,
                    'service': self.get_service_name(port),
                    'risk': self.get_risk_level(port),
                    'protocol': 'tcp'
                }
            return {'port': port, 'open': False}
        except:
            return {'port': port, 'open': False}
    
    def scan_udp_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(b'', (self.target, port))
            try:
                data, addr = sock.recvfrom(1024)
                sock.close()
                return {
                    'port': port,
                    'open': True,
                    'service': self.get_service_name(port),
                    'risk': self.get_risk_level(port),
                    'protocol': 'udp'
                }
            except socket.timeout:
                sock.close()
                return {'port': port, 'open': 'filtered'}
        except:
            return {'port': port, 'open': False}
    
    def scan(self):
        print(f"Starting {self.scan_type.upper()} scan on {self.target}")
        
        if self.scan_type == 'all':
            return self._scan_all_protocols()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            if self.scan_type == 'udp':
                futures = {executor.submit(self.scan_udp_port, port): port for port in self.ports}
            else:
                futures = {executor.submit(self.scan_tcp_port, port): port for port in self.ports}
            
            for future in as_completed(futures):
                result = future.result()
                self.results[result['port']] = result
        
        return self.results

    def _scan_all_protocols(self):
        """TCP connect + UDP probe merged per port (composite 'all' scan type)."""
        tcp_s = AdvancedPortScanner(self.target, self.ports, 'tcp', self.threads, self.timeout)
        tcp_r = tcp_s.scan()
        udp_threads = min(self.threads, 300)
        udp_s = AdvancedPortScanner(self.target, self.ports, 'udp', udp_threads, min(self.timeout, 2))
        udp_r = udp_s.scan()
        for p in self.ports:
            t = tcp_r.get(p, {})
            u = udp_r.get(p, {})
            t_open = t.get('open') is True
            u_open = u.get('open') is True
            u_filt = u.get('open') == 'filtered'
            merged_open = t_open or u_open
            svc = t.get('service') if t_open else (u.get('service') if u_open else self.get_service_name(p))
            risk = self.get_risk_level(p) if merged_open else 'LOW'
            self.results[p] = {
                'port': p,
                'open': merged_open,
                'tcp_open': t_open,
                'udp_open': u_open,
                'udp_state': 'filtered' if u_filt and not u_open else ('open' if u_open else 'closed'),
                'service': svc,
                'risk': risk if merged_open else 'LOW',
                'protocol': 'tcp+udp',
            }
        return self.results

# ============ NETWORK MAPPER CLASS ============
class NetworkMapper:
    def __init__(self):
        self.mac_vendors = {
            '00:00:0C': 'Cisco', '00:01:5C': 'D-Link', '00:04:5A': 'Netgear',
            '00:0C:29': 'VMware', '00:14:22': 'Dell', '00:16:3E': 'Xen',
            '00:1A:11': 'Samsung', '00:1C:42': 'Intel', '00:1E:37': 'HP',
            '00:1F:5B': 'Raspberry Pi', '00:23:12': 'Apple', '00:25:9C': 'Huawei',
            '00:50:56': 'VMware', '08:00:27': 'Oracle', '28:C2:1F': 'Intel',
            '30:9C:23': 'Samsung', '34:17:EB': 'TP-Link', '44:32:C8': 'Apple',
            '50:2B:73': 'Xiaomi', '70:85:C2': 'Google', '80:86:F2': 'Amazon',
            '94:DE:80': 'Nest', 'B8:27:EB': 'Raspberry Pi', 'C0:25:06': 'Amazon',
            'E0:55:3D': 'Apple'
        }
    
    def get_vendor(self, mac):
        if not mac or mac == 'Unknown':
            return 'Unknown'
        mac_upper = mac.upper()
        for oui, vendor in self.mac_vendors.items():
            if mac_upper.startswith(oui):
                return vendor
        return 'Unknown'
    
    def get_mac_from_ip(self, ip):
        """Get MAC address from IP address using ARP"""
        try:
            if platform.system().lower() == 'windows':
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=5)
                for line in result.stdout.split('\n'):
                    if ip in line:
                        parts = line.split()
                        for part in parts:
                            if re.match(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', part):
                                return part.upper()
            else:
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=5)
                for line in result.stdout.split('\n'):
                    if ip in line:
                        parts = line.split()
                        for part in parts:
                            if re.match(r'([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})', part):
                                return part.upper()
        except:
            pass
        return 'Unknown'
    
    def ping_host(self, ip):
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        try:
            result = subprocess.run(['ping', param, '1', ip], 
                                  capture_output=True, timeout=2)
            if result.returncode == 0:
                mac = self.get_mac_from_ip(ip)
                return {
                    'ip': ip,
                    'alive': True,
                    'mac': mac,
                    'vendor': self.get_vendor(mac),
                    'hostname': self.get_hostname(ip)
                }
        except:
            pass
        return None
    
    def get_hostname(self, ip):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
    
    def discover_network(self, network_cidr):
        network_parts = network_cidr.split('/')[0].split('.')
        network_prefix = '.'.join(network_parts[:3])
        
        devices = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(self.ping_host, f"{network_prefix}.{i}") for i in range(1, 255)]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    devices.append(result)
        
        return devices

    def _normalize_mac(self, mac):
        if not mac or mac == 'Unknown':
            return ''
        h = re.sub(r'[^0-9a-fA-F]', '', mac)
        if len(h) != 12:
            return ''
        return ':'.join(h[i : i + 2].upper() for i in range(0, 12, 2))

    def parse_arp_table(self):
        rows = []
        try:
            if platform.system().lower() == 'windows':
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=20)
                for line in result.stdout.splitlines():
                    m = re.search(
                        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F:-]{17})\s+', line
                    )
                    if m:
                        ip, raw = m.group(1), m.group(2)
                        mac = raw.replace('-', ':').upper()
                        rows.append({'ip': ip.strip(), 'mac': mac})
            else:
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=20)
                for line in result.stdout.splitlines():
                    m = re.search(
                        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?([0-9a-fA-F:]{17})', line
                    )
                    if m:
                        ip, mac = m.group(1), m.group(2).upper()
                        rows.append({'ip': ip.strip(), 'mac': mac})
        except Exception:
            pass
        return rows

    def get_ip_from_mac(self, mac):
        target = self._normalize_mac(mac)
        if not target:
            return None
        for row in self.parse_arp_table():
            if self._normalize_mac(row['mac']) == target:
                return row['ip']
        return None

    def ping_ttl(self, ip):
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            result = subprocess.run(
                ['ping', param, '1', ip], capture_output=True, text=True, timeout=4
            )
            t = re.search(r'(?:TTL|ttl)[=<:]\s*(\d+)', result.stdout, re.I)
            if t:
                return int(t.group(1))
        except Exception:
            pass
        return None

    @staticmethod
    def guess_os_from_ttl(ttl):
        if ttl is None:
            return 'Unknown (no TTL — try ping first)'
        if ttl <= 64:
            return 'Likely Linux / Unix / macOS / Android (TTL≤64)'
        if ttl <= 128:
            return 'Likely Windows (TTL≈128)'
        return 'Likely router / IOS / network gear (TTL≈255)'

    def guess_device_category(self, vendor, hostname):
        v = (vendor or '').lower()
        h = (hostname or '').lower()
        if any(x in v for x in ('apple', 'samsung', 'xiaomi', 'google', 'huawei', 'oneplus')):
            return 'Phone / tablet / consumer'
        if 'raspberry' in v or 'raspberry' in h:
            return 'Embedded / IoT'
        if any(x in v for x in ('cisco', 'netgear', 'tp-link', 'd-link', 'ubiquiti', 'router')):
            return 'Network / Wi‑Fi infrastructure'
        if 'vmware' in v or 'virtual' in h or 'xen' in v:
            return 'Virtual machine'
        return 'PC / server / other'

    def enrich_endpoint(self, ip=None, mac=None):
        if mac and (not ip or ip == 'Unknown'):
            ip = self.get_ip_from_mac(mac) or ''
        if ip and (not mac or mac == 'Unknown'):
            mac = self.get_mac_from_ip(ip)
        mac = mac or 'Unknown'
        vendor = self.get_vendor(mac)
        hostname = self.get_hostname(ip) if ip else None
        ttl = self.ping_ttl(ip) if ip else None
        os_hint = self.guess_os_from_ttl(ttl)
        cat = self.guess_device_category(vendor, hostname)
        name = hostname or (f'{vendor} host' if vendor != 'Unknown' else 'Unknown device')
        return {
            'ip': ip or None,
            'mac': mac,
            'vendor': vendor,
            'operator_vendor': vendor,
            'hostname': hostname,
            'device_name': name,
            'os_guess': os_hint,
            'device_category': cat,
            'ttl': ttl,
        }


def get_local_lan_cidr():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        parts = ip.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24", ip
    except Exception:
        return '192.168.1.0/24', None


def parse_port_range_spec(port_range):
    """Return list of port ints. Supports 'all', 'scan all', '1-1000', comma lists."""
    pr = (port_range or '1-1000').strip().lower()
    if pr in ('all', 'full', 'scan all', '1-65535', '65535'):
        return list(range(1, 65536))
    if '-' in pr:
        a, b = pr.split('-', 1)
        start_port, end_port = int(a.strip()), int(b.strip())
        return list(range(start_port, min(end_port + 1, 65536)))
    if ',' in pr:
        return [int(p.strip()) for p in pr.split(',') if p.strip()]
    return [int(pr)]


def _ascii_safe(s):
    if s is None:
        return ''
    return str(s).encode('ascii', 'replace').decode('ascii')


def build_report_pdf_bytes(scan_id, scan, vulns):
    from fpdf import FPDF

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font('Helvetica', 'B', 16)
    pdf.cell(0, 10, _ascii_safe('Network Security Scan Report'), ln=True)
    pdf.set_font('Helvetica', '', 11)
    pdf.cell(0, 8, _ascii_safe(f'Report ID: {scan_id}'), ln=True)
    pdf.cell(0, 8, _ascii_safe(f"Target: {scan['target']}"), ln=True)
    pdf.cell(0, 8, _ascii_safe(f"Scan type: {scan['scan_type']}"), ln=True)
    pdf.cell(0, 8, _ascii_safe(f"Completed: {scan['end_time']}"), ln=True)
    pdf.cell(0, 8, _ascii_safe(f"Open ports: {scan['open_ports']} / {scan['total_ports']}"), ln=True)
    pdf.ln(4)
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, _ascii_safe('Vulnerabilities / exposures'), ln=True)
    pdf.set_font('Helvetica', '', 10)
    for v in vulns:
        line = f"[{v.get('severity')}] {v.get('host')}:{v.get('port')} — {v.get('vulnerability')}"
        pdf.multi_cell(0, 6, _ascii_safe(line))
        if v.get('recommendation'):
            pdf.set_font('Helvetica', 'I', 9)
            pdf.multi_cell(0, 5, _ascii_safe(f"  Remediation: {v['recommendation']}"))
            pdf.set_font('Helvetica', '', 10)
    data = pdf.output(dest='S')
    if isinstance(data, str):
        return data.encode('latin-1')
    return bytes(data)


def build_report_png_bytes(scan_id, scan, vulns):
    from PIL import Image, ImageDraw, ImageFont

    lines = [
        'NETWORK SCAN REPORT',
        f'ID: {scan_id}  Target: {scan["target"]}',
        f'Type: {scan["scan_type"]}  Open: {scan["open_ports"]}/{scan["total_ports"]}',
        '',
        'Vulnerabilities:',
    ]
    for v in vulns[:25]:
        lines.append(f"* [{v.get('severity')}] {v.get('host')}:{v.get('port')} {v.get('vulnerability', '')[:60]}")
    w, h = 920, min(120 + len(lines) * 22, 4000)
    img = Image.new('RGB', (w, h), color=(255, 255, 255))
    dr = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype('arial.ttf', 16)
        font_sm = ImageFont.truetype('arial.ttf', 14)
    except Exception:
        font = ImageFont.load_default()
        font_sm = font
    y = 20
    for i, line in enumerate(lines):
        fnt = font if i < 4 else font_sm
        dr.text((20, y), line[:120], fill=(20, 20, 40), font=fnt)
        y += 22
    buf = BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return buf.getvalue()


# ============ ROUTES ============
@app.route('/')
def index():
    return render_template('index.html')

def _normalize_phone(phone: str) -> str:
    if not phone:
        return ''
    return re.sub(r'\D', '', phone)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json() or {}
        username = (data.get('username') or '').strip()
        email = (data.get('email') or '').strip() or None
        phone = (data.get('phone') or '').strip() or None
        password = data.get('password')
        otp_method = (data.get('otp_method') or 'email').lower()
        
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        if otp_method == 'phone':
            if not phone:
                return jsonify({'error': 'Phone number is required for SMS verification'}), 400
            digits = _normalize_phone(phone)
            if len(digits) < 8:
                return jsonify({'error': 'Enter a valid phone number'}), 400
            if not email:
                email = f"{username}_{digits}@phone.scanner.local"
        else:
            if not email:
                return jsonify({'error': 'Email is required for email verification'}), 400
        
        password_hash = hash_password(password)
        otp_identifier = phone if otp_method == 'phone' else email
        
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (username, email, phone, password_hash, api_key)
                    VALUES (?, ?, ?, ?, ?)
                ''', (username, email, phone, password_hash, secrets.token_urlsafe(32)))
                conn.commit()
                
                otp = generate_otp()
                expires_at = datetime.now() + timedelta(minutes=10)
                cursor.execute('''
                    INSERT INTO otp_codes (identifier, otp_code, purpose, expires_at)
                    VALUES (?, ?, 'verification', ?)
                ''', (otp_identifier, otp, expires_at))
                conn.commit()
                
                if otp_method == 'phone':
                    print(f"[SMS OTP] To {phone}: Your verification code is {otp}")
                else:
                    email_body = f"""
                    <html>
                    <body>
                        <h2>Welcome to Network Security Scanner</h2>
                        <p>Your verification code is: <strong style="font-size: 24px;">{otp}</strong></p>
                        <p>This code expires in 10 minutes.</p>
                    </body>
                    </html>
                    """
                    send_email(email, 'Verify Your Account', email_body)
                
                return jsonify({
                    'success': True,
                    'message': 'OTP sent to your phone (see server log if SMS not configured)' if otp_method == 'phone' else 'OTP sent to your email',
                    'otp_method': otp_method,
                    'otp_identifier': otp_identifier
                })
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Username, email, or phone already exists'}), 400
    
    return render_template('register.html')

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    identifier = data.get('identifier')
    otp = data.get('otp')
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM otp_codes 
            WHERE identifier = ? AND otp_code = ? AND used = 0 
            AND expires_at > datetime('now')
            ORDER BY expires_at DESC LIMIT 1
        ''', (identifier, otp))
        
        otp_record = cursor.fetchone()
        
        if otp_record:
            cursor.execute('UPDATE otp_codes SET used = 1 WHERE id = ?', (otp_record['id'],))
            norm = _normalize_phone(identifier)
            cursor.execute('UPDATE users SET is_verified = 1 WHERE email = ?', (identifier,))
            if cursor.rowcount == 0:
                cursor.execute('UPDATE users SET is_verified = 1 WHERE phone = ?', (identifier,))
            if cursor.rowcount == 0 and norm:
                cursor.execute(
                    """UPDATE users SET is_verified = 1
                       WHERE REPLACE(REPLACE(REPLACE(REPLACE(COALESCE(phone,''),'+',''),'-',''),' ',''),'(','') = ?""",
                    (norm,)
                )
            conn.commit()
            return jsonify({'success': True})
    
    return jsonify({'error': 'Invalid or expired OTP'}), 400

@app.route('/send-otp', methods=['POST'])
def send_otp():
    data = request.get_json() or {}
    identifier = data.get('identifier')
    method = (data.get('method') or 'email').lower()
    purpose = data.get('purpose') or 'login'
    
    if not identifier:
        return jsonify({'error': 'identifier required'}), 400
    
    otp = generate_otp()
    expires_at = datetime.now() + timedelta(minutes=10)
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO otp_codes (identifier, otp_code, purpose, expires_at)
            VALUES (?, ?, ?, ?)
        ''', (identifier, otp, purpose, expires_at))
        conn.commit()
    
    if method == 'email':
        email_body = f"""
        <html>
        <body>
            <h2>Login Verification</h2>
            <p>Your OTP is: <strong style="font-size: 24px;">{otp}</strong></p>
            <p>Valid for 10 minutes.</p>
        </body>
        </html>
        """
        send_email(identifier, 'Your Login OTP', email_body)
    else:
        print(f"[SMS OTP] To {identifier}: Your OTP is {otp}")
    
    return jsonify({'success': True})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        identifier = data.get('identifier')
        password = data.get('password')
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT * FROM users WHERE email = ? OR username = ? OR phone = ? OR phone = ?',
                (identifier, identifier, identifier, _normalize_phone(identifier))
            )
            user = cursor.fetchone()
            
            if user:
                # Check if account is locked
                if user['locked_until'] and datetime.now() < datetime.fromisoformat(user['locked_until']):
                    return jsonify({'error': 'Account locked. Try again later.'}), 401
                
                if verify_password(user['password_hash'], password):
                    # Reset failed attempts
                    cursor.execute('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?', 
                                 (user['id'],))
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    
                    cursor.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', 
                                 (user['id'],))
                    conn.commit()
                    
                    return jsonify({
                        'success': True,
                        'username': user['username'],
                        'redirect': '/dashboard',
                        'api_key': user['api_key']
                    })
                else:
                    # Increment failed attempts
                    failed = user['failed_attempts'] + 1
                    if failed >= 5:
                        locked_until = datetime.now() + timedelta(minutes=15)
                        cursor.execute('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?',
                                     (failed, locked_until, user['id']))
                    else:
                        cursor.execute('UPDATE users SET failed_attempts = ? WHERE id = ?', (failed, user['id']))
                    conn.commit()
            
            return jsonify({'error': 'Invalid credentials'}), 401
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/scanner')
@login_required
def scanner():
    return render_template('scanner.html')

@app.route('/network-map')
@login_required
def network_map():
    return render_template('network_map.html')

@app.route('/reports')
@login_required
def reports():
    return render_template('reports.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/api/scan', methods=['POST'])
@login_required
def start_scan():
    data = request.get_json()
    target = data.get('target')
    port_range = data.get('port_range', '1-1000')
    scan_type = (data.get('scan_type') or 'tcp').strip().lower()
    if scan_type in ('all', 'all_types', 'all scan types', 'every'):
        scan_type = 'all'
    
    try:
        ports = parse_port_range_spec(port_range)
    except ValueError:
        return jsonify({'error': 'Invalid port range'}), 400
    
    # Run scan in background
    scanner = AdvancedPortScanner(target, ports, scan_type)
    results = scanner.scan()
    
    open_ports = [p for p, info in results.items() if info.get('open') is True]
    high_risk_ports = [p for p in open_ports if results[p].get('risk') in ['CRITICAL', 'HIGH']]
    
    # Trigger alert if high risk found
    alert_triggered = len(high_risk_ports) > 0
    
    # Store in database
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scan_history (user_id, target, scan_type, start_time, end_time, 
                                      open_ports, total_ports, high_risk_count, status, result_json, alert_triggered)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], target, scan_type, datetime.now(), datetime.now(),
              len(open_ports), len(ports), len(high_risk_ports), 'completed', 
              json.dumps(results), alert_triggered))
        scan_id = cursor.lastrowid
        
        # Store alerts
        for port in high_risk_ports:
            cursor.execute('''
                INSERT INTO alerts (user_id, scan_id, severity, message)
                VALUES (?, ?, ?, ?)
            ''', (session['user_id'], scan_id, results[port]['risk'], 
                  f"High risk port {port} ({results[port]['service']}) found on {target}"))
        
        insert_vulnerabilities_for_scan(cursor, scan_id, target, results)
        
        conn.commit()
    
    return jsonify({
        'success': True,
        'scan_id': scan_id,
        'results': results,
        'open_ports': open_ports,
        'high_risk_ports': high_risk_ports,
        'alert_triggered': alert_triggered
    })

@app.route('/api/scan-status/<int:scan_id>', methods=['GET'])
@login_required
def scan_status(scan_id):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM scan_history WHERE id = ? AND user_id = ?', 
                      (scan_id, session['user_id']))
        scan = cursor.fetchone()
        
        if scan:
            return jsonify({
                'id': scan['id'],
                'status': scan['status'],
                'target': scan['target'],
                'scan_type': scan['scan_type'],
                'start_time': scan['start_time'],
                'end_time': scan['end_time'],
                'open_ports': scan['open_ports'],
                'total_ports': scan['total_ports'],
                'high_risk_count': scan['high_risk_count'],
                'alert_triggered': bool(scan['alert_triggered']),
                'result': json.loads(scan['result_json']) if scan['result_json'] else None
            })
    
    return jsonify({'error': 'Scan not found'}), 404

@app.route('/api/network-map', methods=['POST'])
@login_required
def discover_network():
    data = request.get_json()
    network = data.get('network', '192.168.1.0/24')
    
    mapper = NetworkMapper()
    devices = mapper.discover_network(network)
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO network_maps (user_id, network, discovery_time, hosts_found, devices_json)
            VALUES (?, ?, ?, ?, ?)
        ''', (session['user_id'], network, datetime.now(), len(devices), json.dumps(devices)))
        conn.commit()
    
    return jsonify({
        'success': True,
        'network': network,
        'hosts_found': len(devices),
        'devices': devices
    })

@app.route('/api/reports', methods=['GET'])
@login_required
def get_reports():
    report_type = request.args.get('type', 'scans')
    
    with get_db() as conn:
        cursor = conn.cursor()
        
        if report_type == 'scans':
            cursor.execute('''
                SELECT * FROM scan_history WHERE user_id = ? 
                ORDER BY start_time DESC LIMIT 50
            ''', (session['user_id'],))
            reports = cursor.fetchall()
            return jsonify([dict(r) for r in reports])
        
        elif report_type == 'alerts':
            cursor.execute('''
                SELECT * FROM alerts WHERE user_id = ? 
                ORDER BY created_at DESC LIMIT 50
            ''', (session['user_id'],))
            alerts = cursor.fetchall()
            return jsonify([dict(a) for a in alerts])
        
        elif report_type == 'network':
            cursor.execute('''
                SELECT * FROM network_maps WHERE user_id = ? 
                ORDER BY discovery_time DESC LIMIT 20
            ''', (session['user_id'],))
            maps = cursor.fetchall()
            return jsonify([dict(m) for m in maps])
        
        elif report_type == 'vulnerabilities':
            cursor.execute('''
                SELECT v.* FROM vulnerability_reports v
                INNER JOIN scan_history s ON v.scan_id = s.id
                WHERE s.user_id = ?
                ORDER BY v.discovered_at DESC LIMIT 100
            ''', (session['user_id'],))
            rows = cursor.fetchall()
            return jsonify([dict(r) for r in rows])
    
    return jsonify([])

@app.route('/uploads/avatars/<path:filename>')
def avatar_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/profile', methods=['GET', 'PUT'])
@login_required
def api_user_profile():
    if request.method == 'GET':
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT id, username, email, phone, created_at, last_login, api_key, avatar_filename FROM users WHERE id = ?',
                (session['user_id'],)
            )
            user = cursor.fetchone()
            d = dict(user)
            if d.get('avatar_filename'):
                d['avatar_url'] = url_for('avatar_file', filename=d['avatar_filename'])
            else:
                d['avatar_url'] = None
            return jsonify(d)
    
    elif request.method == 'PUT':
        data = request.get_json() or {}
        new_key = None
        with get_db() as conn:
            cursor = conn.cursor()
            if 'password' in data:
                new_hash = hash_password(data['password'])
                cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', 
                             (new_hash, session['user_id']))
            if 'phone' in data:
                cursor.execute('UPDATE users SET phone = ? WHERE id = ?', 
                             (data['phone'], session['user_id']))
            if data.get('regenerate_api_key'):
                new_key = secrets.token_urlsafe(32)
                cursor.execute('UPDATE users SET api_key = ? WHERE id = ?', (new_key, session['user_id']))
            conn.commit()
        out = {'success': True}
        if new_key:
            out['api_key'] = new_key
        return jsonify(out)

@app.route('/api/profile/avatar', methods=['POST'])
@login_required
def upload_avatar():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    f = request.files['file']
    if not f or not f.filename:
        return jsonify({'error': 'Empty file'}), 400
    ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else ''
    if ext not in ALLOWED_AVATAR:
        return jsonify({'error': 'Allowed: png, jpg, gif, webp'}), 400
    fn = secure_filename(f"user_{session['user_id']}.{ext}")
    path = os.path.join(app.config['UPLOAD_FOLDER'], fn)
    f.save(path)
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET avatar_filename = ? WHERE id = ?', (fn, session['user_id']))
        conn.commit()
    return jsonify({'success': True, 'avatar_url': url_for('avatar_file', filename=fn)})

@app.route('/api/export-report/<int:scan_id>', methods=['GET'])
@login_required
def export_report(scan_id):
    fmt = (request.args.get('format') or 'json').lower()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'SELECT * FROM scan_history WHERE id = ? AND user_id = ?',
            (scan_id, session['user_id'])
        )
        scan = cursor.fetchone()
        if not scan:
            return jsonify({'error': 'Report not found'}), 404
        cursor.execute(
            'SELECT * FROM vulnerability_reports WHERE scan_id = ? ORDER BY severity DESC, cvss_score DESC',
            (scan_id,)
        )
        vulns = [dict(row) for row in cursor.fetchall()]
    payload = {
        'scan': dict(scan),
        'vulnerabilities': vulns,
        'exported_at': datetime.now().isoformat(),
    }
    if fmt == 'txt':
        from flask import Response
        lines = [
            'NETWORK SECURITY SCAN REPORT',
            f"Report ID: {scan_id}",
            f"Target: {scan['target']}",
            f"Scan type: {scan['scan_type']}",
            f"Completed: {scan['end_time']}",
            f"Open ports: {scan['open_ports']} / {scan['total_ports']} scanned",
            f"High-risk count: {scan['high_risk_count']}",
            '',
            '--- Vulnerabilities / exposures ---',
        ]
        for v in vulns:
            lines.append(f"[{v.get('severity')}] {v.get('host')}:{v.get('port')} — {v.get('vulnerability')}")
            if v.get('cve_id'):
                lines.append(f"    CVE: {v['cve_id']}  CVSS: {v.get('cvss_score')}")
            if v.get('recommendation'):
                lines.append(f"    Remediation: {v['recommendation']}")
            lines.append('')
        return Response(
            '\n'.join(lines),
            mimetype='text/plain',
            headers={'Content-Disposition': f'attachment; filename=scan_report_{scan_id}.txt'},
        )
    if fmt == 'pdf':
        from flask import Response
        try:
            raw = build_report_pdf_bytes(scan_id, scan, vulns)
        except Exception as e:
            return jsonify({'error': f'PDF build failed: {e}'}), 500
        return Response(
            raw,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename=scan_report_{scan_id}.pdf'},
        )
    if fmt == 'png':
        from flask import Response
        try:
            raw = build_report_png_bytes(scan_id, scan, vulns)
        except Exception as e:
            return jsonify({'error': f'PNG build failed: {e}'}), 500
        return Response(
            raw,
            mimetype='image/png',
            headers={'Content-Disposition': f'attachment; filename=scan_report_{scan_id}.png'},
        )
    return jsonify(payload)

@app.route('/api/public-stats', methods=['GET'])
def public_stats():
    """Aggregate stats for landing page (real-time from database)."""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM scan_history WHERE status = 'completed'")
        total_scans = c.fetchone()[0]
        c.execute('SELECT COALESCE(SUM(COALESCE(total_ports, 0)), 0) FROM scan_history')
        ports_scanned = int(c.fetchone()[0] or 0)
        c.execute('SELECT COUNT(*) FROM vulnerability_reports')
        vulns = c.fetchone()[0]
        c.execute('SELECT COUNT(*) FROM users')
        users = c.fetchone()[0]
    return jsonify({
        'scans_completed': total_scans,
        'ports_scanned': ports_scanned,
        'vulnerabilities_found': vulns,
        'happy_users': users,
    })

@app.route('/api/mac-from-ip', methods=['POST'])
@login_required
def mac_from_ip():
    data = request.get_json() or {}
    ip = (data.get('ip') or '').strip()
    if not ip:
        return jsonify({'error': 'ip required'}), 400
    mapper = NetworkMapper()
    mac = mapper.get_mac_from_ip(ip)
    enriched = mapper.enrich_endpoint(ip=ip, mac=mac)
    return jsonify({'success': True, **enriched})


@app.route('/api/device-resolve', methods=['POST'])
@login_required
def device_resolve():
    """Resolve MAC ↔ IP and enrich with vendor, hostname, OS guess, device category."""
    data = request.get_json() or {}
    ip = (data.get('ip') or '').strip() or None
    mac = (data.get('mac') or '').strip() or None
    if not ip and not mac:
        return jsonify({'error': 'Provide ip and/or mac'}), 400
    mapper = NetworkMapper()
    info = mapper.enrich_endpoint(ip=ip, mac=mac)
    info['success'] = True
    return jsonify(info)


@app.route('/api/nearby-devices', methods=['GET'])
@login_required
def nearby_devices():
    """
    Devices on the same LAN / Wi‑Fi segment (ARP + ping sweep).
    Physical “~100 m” is approximated by same access-point / subnet proximity.
    """
    mapper = NetworkMapper()
    cidr, my_ip = get_local_lan_cidr()
    arp = mapper.parse_arp_table()
    seen = {row['ip']: row for row in arp}
    discovered = mapper.discover_network(cidr)
    for d in discovered:
        if d['ip'] not in seen:
            seen[d['ip']] = {'ip': d['ip'], 'mac': d.get('mac')}
    devices = []
    for ip, row in seen.items():
        mac = row.get('mac') or mapper.get_mac_from_ip(ip)
        info = mapper.enrich_endpoint(ip=ip, mac=mac)
        devices.append(info)
    devices.sort(key=lambda x: x.get('ip') or '')
    return jsonify({
        'success': True,
        'network': cidr,
        'this_host_ip': my_ip,
        'device_count': len(devices),
        'devices': devices,
        'note': 'Nearby = same LAN/Wi‑Fi segment (ARP-visible). Typical indoor Wi‑Fi coverage is often within ~100 m of the access point; exact distance is not measured over IP.',
    })

@app.route('/api/rating', methods=['POST'])
def submit_rating():
    data = request.get_json() or {}
    try:
        stars = int(data.get('stars', 0))
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid stars'}), 400
    if stars < 1 or stars > 5:
        return jsonify({'error': 'Stars must be 1–5'}), 400
    comment = (data.get('comment') or '')[:500]
    uid = session.get('user_id')
    with get_db() as conn:
        c = conn.cursor()
        c.execute(
            'INSERT INTO app_ratings (user_id, stars, comment) VALUES (?, ?, ?)',
            (uid, stars, comment),
        )
        conn.commit()
    return jsonify({'success': True})

@app.route('/api/enterprise-inquiry', methods=['POST'])
def enterprise_inquiry():
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    email = (data.get('email') or '').strip()
    company = (data.get('company') or '').strip()
    message = (data.get('message') or '').strip()
    if not email:
        return jsonify({'error': 'Work email is required'}), 400
    with get_db() as conn:
        c = conn.cursor()
        c.execute(
            'INSERT INTO enterprise_inquiries (name, email, company, message) VALUES (?, ?, ?, ?)',
            (name, email, company, message),
        )
        conn.commit()
    return jsonify({'success': True, 'message': 'Thank you. Our team will reach out shortly.'})

@app.route('/api/alerts/<int:alert_id>/read', methods=['PUT'])
@login_required
def mark_alert_read(alert_id):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE alerts SET is_read = 1 WHERE id = ? AND user_id = ?', 
                      (alert_id, session['user_id']))
        conn.commit()
    return jsonify({'success': True})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    print("=" * 60)
    print("🔒 NETWORK SECURITY SCANNER - ADVANCED EDITION 🔒")
    print("=" * 60)
    print(f"📍 Access at: http://localhost:5000")
    print(f"👤 Default login: admin / Admin@123")
    print(f"⚠️  High-risk alerts will trigger visual and audio warnings")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)