
import platform
import subprocess
import re
from typing import List, Dict

class ARPScanner:
    def __init__(self):
        self.devices = []
        
    def scan(self) -> List[Dict]:
        print("[*] Escaneando red local (ARP)...")
        
        try:
            # Usar arp -a en Windows/Linux
            if platform.system() == 'Windows':
                cmd = "arp -a"
            else:
                cmd = "arp -n"
            
            output = subprocess.check_output(cmd, shell=True).decode()
            
            # Parsear salida
            lines = output.split('\n')
            for line in lines:
                # Buscar IP y MAC
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+.*?([0-9a-fA-F:]{17}|[0-9a-fA-F-]{17})', line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2)
                    
                    device = {
                        'ip': ip,
                        'mac': mac,
                        'vendor': self.get_vendor(mac)
                    }
                    
                    self.devices.append(device)
                    print(f"[+] {ip} - {mac}")
            
            print(f"\n[+] Dispositivos encontrados: {len(self.devices)}")
            
        except Exception as e:
            print(f"[!] Error en ARP scan: {e}")
        
        return self.devices
    
    def get_vendor(self, mac: str) -> str:
        """Obtiene el vendor del MAC (requiere base de datos OUI)"""
        # Simplificado - en producción usar base de datos OUI
        return "Unknown"

def scan() -> List[Dict]:
    scanner = ARPScanner()
    return scanner.scan()