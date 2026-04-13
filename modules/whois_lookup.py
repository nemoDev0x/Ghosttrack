"""
MÓDULO 2: WHOIS LOOKUP
Consulta información de registro de dominios e IPs
"""

import socket
import re
from typing import Dict, Optional
from datetime import datetime

class WHOISLookup:
    """Consultas WHOIS para dominios e IPs"""
    
    WHOIS_SERVERS = {
        'com': 'whois.verisign-grs.com',
        'net': 'whois.verisign-grs.com',
        'org': 'whois.pir.org',
        'info': 'whois.afilias.net',
        'biz': 'whois.biz',
        'us': 'whois.nic.us',
        'uk': 'whois.nic.uk',
        'ca': 'whois.cira.ca',
        'de': 'whois.denic.de',
        'es': 'whois.nic.es',
        'fr': 'whois.afnic.fr',
        'it': 'whois.nic.it',
        'ru': 'whois.tcinet.ru',
        'default': 'whois.iana.org'
    }
    
    def __init__(self, target: str):
        self.target = target
        self.whois_server = self._get_whois_server()
        
    def _get_whois_server(self) -> str:
        """Determina el servidor WHOIS apropiado"""
        if '.' in self.target:
            tld = self.target.split('.')[-1]
            return self.WHOIS_SERVERS.get(tld, self.WHOIS_SERVERS['default'])
        return self.WHOIS_SERVERS['default']
    
    def query(self) -> Dict:
        """Realiza la consulta WHOIS"""
        print(f"[*] Consultando WHOIS para: {self.target}")
        
        try:
            # Conectar al servidor WHOIS
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.whois_server, 43))
            
            # Enviar consulta
            query = f"{self.target}\r\n"
            sock.send(query.encode())
            
            # Recibir respuesta
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            
            sock.close()
            
            # Parsear respuesta
            whois_data = response.decode('utf-8', errors='ignore')
            parsed_data = self._parse_whois(whois_data)
            
            return {
                'target': self.target,
                'whois_server': self.whois_server,
                'raw_data': whois_data,
                'parsed_data': parsed_data,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'target': self.target,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def _parse_whois(self, raw_data: str) -> Dict:
        """Parsea los datos WHOIS"""
        parsed = {}
        
        # Registrar
        registrar = re.search(r'Registrar:\s*(.+)', raw_data, re.IGNORECASE)
        if registrar:
            parsed['registrar'] = registrar.group(1).strip()
        
        # Fecha de creación
        created = re.search(r'Creation Date:\s*(.+)', raw_data, re.IGNORECASE)
        if created:
            parsed['created_date'] = created.group(1).strip()
        
        # Fecha de expiración
        expires = re.search(r'Expir(?:ation|y) Date:\s*(.+)', raw_data, re.IGNORECASE)
        if expires:
            parsed['expiration_date'] = expires.group(1).strip()
        
        # Fecha de actualización
        updated = re.search(r'Updated Date:\s*(.+)', raw_data, re.IGNORECASE)
        if updated:
            parsed['updated_date'] = updated.group(1).strip()
        
        # Name servers
        nameservers = re.findall(r'Name Server:\s*(.+)', raw_data, re.IGNORECASE)
        if nameservers:
            parsed['nameservers'] = [ns.strip() for ns in nameservers]
        
        # Status
        status = re.findall(r'Status:\s*(.+)', raw_data, re.IGNORECASE)
        if status:
            parsed['status'] = [s.strip() for s in status]
        
        # Emails
        emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', raw_data)
        if emails:
            parsed['emails'] = list(set(emails))
        
        # Organization
        org = re.search(r'Organi[zs]ation:\s*(.+)', raw_data, re.IGNORECASE)
        if org:
            parsed['organization'] = org.group(1).strip()
        
        return parsed
    
    def display_results(self, results: Dict):
        """Muestra los resultados de forma legible"""
        print(f"\n{'='*60}")
        print(f"WHOIS Information for: {results['target']}")
        print(f"{'='*60}")
        
        if 'error' in results:
            print(f"[!] Error: {results['error']}")
            return
        
        parsed = results.get('parsed_data', {})
        
        if 'registrar' in parsed:
            print(f"[+] Registrar: {parsed['registrar']}")
        
        if 'created_date' in parsed:
            print(f"[+] Created: {parsed['created_date']}")
        
        if 'expiration_date' in parsed:
            print(f"[+] Expires: {parsed['expiration_date']}")
        
        if 'updated_date' in parsed:
            print(f"[+] Updated: {parsed['updated_date']}")
        
        if 'nameservers' in parsed:
            print(f"[+] Name Servers:")
            for ns in parsed['nameservers']:
                print(f"    - {ns}")
        
        if 'status' in parsed:
            print(f"[+] Status:")
            for s in parsed['status']:
                print(f"    - {s}")
        
        if 'organization' in parsed:
            print(f"[+] Organization: {parsed['organization']}")
        
        if 'emails' in parsed:
            print(f"[+] Emails found:")
            for email in parsed['emails']:
                print(f"    - {email}")

def lookup(target: str) -> Dict:
    """
    Función principal de consulta WHOIS
    
    Args:
        target: Dominio o IP a consultar
        
    Returns:
        Diccionario con información WHOIS
    """
    whois = WHOISLookup(target)
    results = whois.query()
    whois.display_results(results)
    return results

def bulk_lookup(targets: list) -> Dict[str, Dict]:
    """
    Consulta WHOIS para múltiples targets
    
    Args:
        targets: Lista de dominios/IPs
        
    Returns:
        Diccionario con resultados de todos los targets
    """
    results = {}
    
    for target in targets:
        print(f"\n[*] Processing: {target}")
        results[target] = lookup(target)
    
    return results

if __name__ == "__main__":
    # Test del módulo
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        lookup(target)
    else:
        print("Uso: python whois_lookup.py <domain>")
        print("Ejemplo: python whois_lookup.py google.com")