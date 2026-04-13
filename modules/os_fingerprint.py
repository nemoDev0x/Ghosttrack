# ═══════════════════════════════════════════════════════════════════
# ARCHIVO: modules/os_fingerprint.py - MÓDULO 7
# ═══════════════════════════════════════════════════════════════════

import platform
import subprocess

class OSFingerprinter:
    def __init__(self, target: str):
        self.target = target
        
    def detect_os(self) -> Dict:
        print(f"[*] Detectando sistema operativo de: {self.target}")
        
        results = {
            'target': target,
            'os_guess': 'Unknown',
            'confidence': 'Low',
            'details': {}
        }
        
        # Técnica 1: TTL Analysis
        ttl_os = self.ttl_fingerprint()
        if ttl_os:
            results['ttl_analysis'] = ttl_os
        
        # Técnica 2: TCP/IP Stack Fingerprinting
        tcp_os = self.tcp_fingerprint()
        if tcp_os:
            results['tcp_analysis'] = tcp_os
        
        # Técnica 3: Service Banners
        banner_os = self.banner_analysis()
        if banner_os:
            results['banner_analysis'] = banner_os
        
        # Determinar OS más probable
        os_guess = self.determine_os(results)
        results['os_guess'] = os_guess
        
        print(f"[+] OS detectado: {os_guess}")
        
        return results
    
    def ttl_fingerprint(self) -> Dict:
        """Detecta OS mediante análisis de TTL"""
        try:
            if platform.system() == 'Windows':
                cmd = f"ping -n 1 {self.target}"
            else:
                cmd = f"ping -c 1 {self.target}"
            
            output = subprocess.check_output(cmd, shell=True).decode()
            
            # Extraer TTL
            ttl_match = re.search(r'ttl=(\d+)', output, re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                
                # TTL típicos:
                # Windows: 128
                # Linux: 64
                # Cisco: 255
                
                if ttl <= 64:
                    return {'ttl': ttl, 'os_family': 'Linux/Unix', 'confidence': 'Medium'}
                elif ttl <= 128:
                    return {'ttl': ttl, 'os_family': 'Windows', 'confidence': 'Medium'}
                else:
                    return {'ttl': ttl, 'os_family': 'Cisco/Network Device', 'confidence': 'Medium'}
        except:
            pass
        
        return None
    
    def tcp_fingerprint(self) -> Dict:
        """TCP/IP Stack Fingerprinting"""
        # Implementación simplificada
        return {'method': 'TCP Stack Analysis', 'status': 'Not implemented'}
    
    def banner_analysis(self) -> Dict:
        """Análisis de banners para detectar OS"""
        banners = {}
        
        # Intentar conectar a puertos comunes
        for port in [22, 80, 443]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((self.target, port))
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                if banner:
                    banners[port] = banner
                    
                    # Detectar OS en banners
                    if 'Ubuntu' in banner or 'Debian' in banner:
                        return {'os': 'Linux (Ubuntu/Debian)', 'evidence': banner[:100]}
                    elif 'Microsoft' in banner or 'Windows' in banner:
                        return {'os': 'Windows', 'evidence': banner[:100]}
                    elif 'Unix' in banner:
                        return {'os': 'Unix', 'evidence': banner[:100]}
            except:
                pass
        
        return banners
    
    def determine_os(self, results: Dict) -> str:
        """Determina el OS más probable basado en todos los análisis"""
        # Lógica simple de votación
        votes = {}
        
        if 'ttl_analysis' in results:
            os_family = results['ttl_analysis'].get('os_family')
            votes[os_family] = votes.get(os_family, 0) + 1
        
        if 'banner_analysis' in results and 'os' in results['banner_analysis']:
            os_name = results['banner_analysis']['os']
            votes[os_name] = votes.get(os_name, 0) + 2  # Mayor peso a banners
        
        if votes:
            return max(votes, key=votes.get)
        
        return 'Unknown'

def detect(target: str) -> Dict:
    fingerprinter = OSFingerprinter(target)
    return fingerprinter.detect_os()
