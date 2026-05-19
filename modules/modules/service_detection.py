"""
MÓDULO 5: SERVICE DETECTION
Detección de servicios en puertos abiertos
"""


import socket
import re
from typing import List, Dict

COMMON_SERVICES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 
    80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC', 139: 'NetBIOS',
    143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP',
    5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Proxy',
    27017: 'MongoDB'
}

SERVICE_PROBES = {
    'HTTP': b'GET / HTTP/1.0\r\n\r\n',
    'SMTP': b'EHLO test\r\n',
}

class ServiceDetector:
    def __init__(self, target: str, ports: List[int]):
        self.target = target
        self.ports = ports
        self.results = {}
        
    def detect_all(self) -> Dict[int, Dict]:
        print(f"[*] Detectando servicios en {len(self.ports)} puertos...")
        
        for port in self.ports:
            service_info = self.detect_service(port)
            if service_info:
                self.results[port] = service_info
                print(f"[+] Puerto {port}: {service_info['service']} {service_info.get('version', '')}")
        
        return self.results
    
    def detect_service(self, port: int) -> Dict:
        try:
            service_name = COMMON_SERVICES.get(port, 'unknown')
            banner = self.grab_banner(port, service_name)
            version_info = self.parse_version(banner, service_name)
            
            service_data = {
                'service': service_name,
                'port': port,
                'protocol': 'TCP',
                'state': 'open',
                'banner': banner[:200] if banner else None,
            }
            
            if version_info:
                service_data.update(version_info)
            
            return service_data
        except:
            return None
    
    def grab_banner(self, port: int, service: str, timeout: int = 3) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((self.target, port))
            
            probe = SERVICE_PROBES.get(service.upper(), b'')
            if probe:
                sock.send(probe)
            
            banner = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            return banner.strip()
        except:
            return ""
    
    def parse_version(self, banner: str, service: str) -> Dict:
        version_info = {}
        if not banner:
            return version_info
        
        if 'HTTP' in service.upper():
            server_match = re.search(r'Server:\s*(.+)', banner, re.IGNORECASE)
            if server_match:
                version_info['version'] = server_match.group(1).strip()
        elif 'SSH' in service.upper():
            ssh_match = re.search(r'SSH-([0-9\.]+)-(.+)', banner)
            if ssh_match:
                version_info['protocol'] = f"SSH-{ssh_match.group(1)}"
                version_info['version'] = ssh_match.group(2).strip()
        elif 'FTP' in service.upper():
            ftp_match = re.search(r'220[- ](.+)', banner)
            if ftp_match:
                version_info['version'] = ftp_match.group(1).strip()
        
        return version_info

def detect(target: str, ports: List[int]) -> Dict:
    detector = ServiceDetector(target, ports)
    return detector.detect_all()