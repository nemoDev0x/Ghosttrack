import json
import re
from typing import Dict, List

class VulnerabilityScanner:
    """Escáner de vulnerabilidades basado en servicios detectados"""
    
    # Base de datos simplificada de CVEs
    CVE_DATABASE = {
        'Apache/2.4.49': {
            'cve': 'CVE-2021-41773',
            'severity': 'CRITICAL',
            'description': 'Path Traversal and RCE in Apache HTTP Server 2.4.49',
            'cvss': 9.8
        },
        'OpenSSH/7.4': {
            'cve': 'CVE-2018-15473',
            'severity': 'MEDIUM',
            'description': 'Username enumeration vulnerability',
            'cvss': 5.3
        },
        'nginx/1.14': {
            'cve': 'CVE-2019-9511',
            'severity': 'HIGH',
            'description': 'HTTP/2 implementation vulnerabilities',
            'cvss': 7.5
        }
    }
    
    def __init__(self, target: str, services: Dict):
        self.target = target
        self.services = services
        self.vulnerabilities = []
        
    def scan(self) -> List[Dict]:
        print(f"[*] Escaneando vulnerabilidades en: {self.target}")
        
        # Escanear cada servicio
        for port, service_info in self.services.items():
            service = service_info.get('service', 'unknown')
            version = service_info.get('version', '')
            
            print(f"[*] Analizando: {service} {version} en puerto {port}")
            
            # Buscar CVEs conocidos
            vulns = self.check_cves(service, version)
            
            # Verificar configuraciones inseguras
            config_vulns = self.check_misconfigurations(port, service)
            
            self.vulnerabilities.extend(vulns)
            self.vulnerabilities.extend(config_vulns)
        
        # Mostrar resumen
        self.display_results()
        
        return self.vulnerabilities
    
    def check_cves(self, service: str, version: str) -> List[Dict]:
        """Verifica CVEs conocidos para un servicio"""
        vulns = []
        
        # Buscar en base de datos
        for key, cve_info in self.CVE_DATABASE.items():
            if service.lower() in key.lower():
                # Comparación simplificada de versiones
                if version and version in key:
                    vulns.append({
                        'type': 'CVE',
                        'service': service,
                        'version': version,
                        'cve_id': cve_info['cve'],
                        'severity': cve_info['severity'],
                        'description': cve_info['description'],
                        'cvss': cve_info['cvss']
                    })
                    print(f"[!] Vulnerabilidad encontrada: {cve_info['cve']}")
        
        return vulns
    
    def check_misconfigurations(self, port: int, service: str) -> List[Dict]:
        """Verifica configuraciones inseguras"""
        vulns = []
        
        # Puertos inseguros
        if port in [21, 23, 69]:  # FTP, Telnet, TFTP
            vulns.append({
                'type': 'MISCONFIGURATION',
                'service': service,
                'port': port,
                'severity': 'MEDIUM',
                'description': f'Protocolo inseguro en puerto {port} (sin cifrado)'
            })
        
        # SSL/TLS en puertos estándar
        if port == 80 and 'http' in service.lower():
            vulns.append({
                'type': 'MISCONFIGURATION',
                'service': service,
                'port': port,
                'severity': 'LOW',
                'description': 'HTTP sin cifrado (recomendado usar HTTPS)'
            })
        
        return vulns
    
    def display_results(self):
        """Muestra resultados de vulnerabilidades"""
        print(f"\n{'='*70}")
        print(f"Vulnerability Scan Results for: {self.target}")
        print(f"{'='*70}\n")
        
        if not self.vulnerabilities:
            print("[+] No se encontraron vulnerabilidades conocidas")
            return
        
        # Agrupar por severidad
        critical = [v for v in self.vulnerabilities if v.get('severity') == 'CRITICAL']
        high = [v for v in self.vulnerabilities if v.get('severity') == 'HIGH']
        medium = [v for v in self.vulnerabilities if v.get('severity') == 'MEDIUM']
        low = [v for v in self.vulnerabilities if v.get('severity') == 'LOW']
        
        print(f"[!] CRITICAL: {len(critical)}")
        print(f"[!] HIGH: {len(high)}")
        print(f"[!] MEDIUM: {len(medium)}")
        print(f"[!] LOW: {len(low)}")
        print(f"\nTotal: {len(self.vulnerabilities)} vulnerabilidades encontradas\n")
        
        # Mostrar detalles
        for vuln in self.vulnerabilities:
            severity_color = {
                'CRITICAL': '\033[91m',  # Rojo
                'HIGH': '\033[93m',      # Amarillo
                'MEDIUM': '\033[94m',    # Azul
                'LOW': '\033[92m'        # Verde
            }
            color = severity_color.get(vuln.get('severity', 'LOW'), '')
            reset = '\033[0m'
            
            print(f"{color}[{vuln.get('severity')}]{reset} {vuln.get('description')}")
            if 'cve_id' in vuln:
                print(f"    CVE: {vuln['cve_id']}")
                print(f"    CVSS: {vuln.get('cvss', 'N/A')}")
            print()

def scan(target: str, services: Dict) -> List[Dict]:
    scanner = VulnerabilityScanner(target, services)
    return scanner.scan()