"""
MÓDULO 3: DNS ENUMERATION
Enumera todos los registros DNS de un dominio
"""
from typing import Dict, List, Optional, Tuple, Any
import socket
import subprocess
from typing import Dict, List
import re

class DNSEnumerator:
    """Enumeración completa de registros DNS"""
    
    RECORD_TYPES = [
        'A',      # IPv4
        'AAAA',   # IPv6
        'MX',     # Mail Exchange
        'NS',     # Name Server
        'TXT',    # Text records
        'CNAME',  # Canonical name
        'SOA',    # Start of Authority
        'PTR',    # Pointer
        'SRV',    # Service
        'CAA',    # Certification Authority Authorization
    ]
    
    def __init__(self, domain: str):
        self.domain = domain
        self.results = {}
        
    def enumerate_all(self) -> Dict:
        """Enumera todos los tipos de registros"""
        print(f"[*] Enumerando DNS para: {self.domain}")
        
        for record_type in self.RECORD_TYPES:
            print(f"[*] Consultando registros {record_type}...")
            records = self.query_record(record_type)
            if records:
                self.results[record_type] = records
                print(f"[+] Encontrados {len(records)} registros {record_type}")
        
        # Zone transfer attempt
        print(f"[*] Intentando transferencia de zona...")
        zone_transfer = self.attempt_zone_transfer()
        if zone_transfer:
            self.results['ZONE_TRANSFER'] = zone_transfer
        
        return self.results
    
    def query_record(self, record_type: str) -> List[str]:
        """Consulta un tipo específico de registro DNS"""
        records = []
        
        try:
            # Usar nslookup
            cmd = f"nslookup -type={record_type} {self.domain}"
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            output = output.decode('utf-8', errors='ignore')
            
            # Parsear resultados según el tipo
            if record_type == 'A':
                records = re.findall(r'Address:\s*(\d+\.\d+\.\d+\.\d+)', output)
            elif record_type == 'AAAA':
                records = re.findall(r'Address:\s*([0-9a-fA-F:]+)', output)
            elif record_type == 'MX':
                records = re.findall(r'mail exchanger = \d+ (.+)', output)
            elif record_type == 'NS':
                records = re.findall(r'nameserver = (.+)', output)
            elif record_type == 'TXT':
                records = re.findall(r'"([^"]+)"', output)
            elif record_type == 'CNAME':
                records = re.findall(r'canonical name = (.+)', output)
            elif record_type == 'SOA':
                soa_match = re.search(r'origin = (.+)', output)
                if soa_match:
                    records = [soa_match.group(1).strip()]
            
            # Limpiar resultados
            records = [r.strip() for r in records if r.strip()]
            
        except subprocess.CalledProcessError:
            pass
        except Exception as e:
            print(f"[!] Error consultando {record_type}: {e}")
        
        return records
    
    def attempt_zone_transfer(self) -> List[str]:
        """Intenta una transferencia de zona DNS (AXFR)"""
        zone_data = []
        
        try:
            # Obtener name servers
            ns_records = self.query_record('NS')
            
            for ns in ns_records:
                ns = ns.strip('.')
                print(f"[*] Intentando AXFR desde: {ns}")
                
                try:
                    cmd = f"dig @{ns} {self.domain} AXFR"
                    output = subprocess.check_output(cmd, shell=True, timeout=10, stderr=subprocess.STDOUT)
                    output = output.decode('utf-8', errors='ignore')
                    
                    # Si contiene registros, la transferencia tuvo éxito
                    if 'XFR size' in output or len(output.split('\n')) > 10:
                        print(f"[!] ¡Transferencia de zona exitosa desde {ns}!")
                        zone_data.append({
                            'nameserver': ns,
                            'data': output
                        })
                    else:
                        print(f"[-] Transferencia denegada desde {ns}")
                        
                except subprocess.TimeoutExpired:
                    print(f"[-] Timeout en transferencia desde {ns}")
                except subprocess.CalledProcessError:
                    print(f"[-] Transferencia denegada desde {ns}")
                    
        except Exception as e:
            print(f"[!] Error en transferencia de zona: {e}")
        
        return zone_data
    
    def reverse_lookup(self, ip: str) -> str:
        """Realiza reverse DNS lookup"""
        try:
            hostname = socket.gethostbyaddr(ip)
            return hostname[0]
        except:
            return None
    
    def display_results(self):
        """Muestra los resultados de forma legible"""
        print(f"\n{'='*60}")
        print(f"DNS Enumeration Results for: {self.domain}")
        print(f"{'='*60}\n")
        
        for record_type, records in self.results.items():
            if record_type == 'ZONE_TRANSFER':
                if records:
                    print(f"[!] ZONA TRANSFERIDA (Vulnerabilidad encontrada):")
                    for zt in records:
                        print(f"    Servidor: {zt['nameserver']}")
                continue
            
            print(f"\n[+] {record_type} Records:")
            for record in records:
                print(f"    - {record}")
                
                # Si es A record, hacer reverse lookup
                if record_type == 'A':
                    reverse = self.reverse_lookup(record)
                    if reverse:
                        print(f"      → Reverse: {reverse}")

def enumerate(domain: str) -> Dict:
    """
    Función principal de enumeración DNS
    
    Args:
        domain: Dominio a enumerar
        
    Returns:
        Diccionario con todos los registros DNS
    """
    enumerator = DNSEnumerator(domain)
    results = enumerator.enumerate_all()
    enumerator.display_results()
    return results

def check_dnssec(domain: str) -> bool:
    """Verifica si el dominio tiene DNSSEC habilitado"""
    try:
        cmd = f"dig {domain} +dnssec"
        output = subprocess.check_output(cmd, shell=True).decode()
        return 'RRSIG' in output
    except:
        return False

def find_subdomains_dns(domain: str, wordlist: List[str] = None) -> List[str]:
    """
    Encuentra subdominios mediante fuerza bruta DNS
    
    Args:
        domain: Dominio base
        wordlist: Lista de palabras para probar
        
    Returns:
        Lista de subdominios encontrados
    """
    if not wordlist:
        wordlist = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'portal']
    
    found_subdomains = []
    
    print(f"[*] Buscando subdominios de {domain}...")
    
    for word in wordlist:
        subdomain = f"{word}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            found_subdomains.append(subdomain)
            print(f"[+] Encontrado: {subdomain}")
        except:
            pass
    
    return found_subdomains

if __name__ == "__main__":
    # Test del módulo
    import sys
    
    if len(sys.argv) > 1:
        domain = sys.argv[1]
        enumerate(domain)
        
        # Verificar DNSSEC
        print(f"\n[*] Verificando DNSSEC...")
        dnssec = check_dnssec(domain)
        if dnssec:
            print("[+] DNSSEC está habilitado")
        else:
            print("[-] DNSSEC no está habilitado")
    else:
        print("Uso: python dns_enum.py <domain>")
        print("Ejemplo: python dns_enum.py google.com")
