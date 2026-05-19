"""
MÓDULO 4: SUBDOMAIN FINDER
Descubrimiento de subdominios mediante múltiples técnicas
"""

import socket
import requests
import dns.resolver
from typing import List, Set
import threading
from queue import Queue

class SubdomainFinder:
    """Descubrimiento de subdominios"""
    
    # Wordlist básica de subdominios comunes
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
        'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mx', 'email', 'cloud',
        'owa', 'www2', 'www1', 'test', 'portal', 'staging', 'dev', 'development',
        'admin', 'administrator', 'api', 'blog', 'shop', 'store', 'app', 'mobile',
        'vpn', 'remote', 'git', 'gitlab', 'jenkins', 'jira', 'confluence', 'wiki',
        'docs', 'support', 'help', 'status', 'monitor', 'monitoring', 'stats',
        'cdn', 'media', 'static', 'assets', 'images', 'img', 'video', 'videos',
        'download', 'downloads', 'ftp2', 'secure', 'ssl', 'web', 'backup', 'forum',
        'old', 'new', 'beta', 'alpha', 'demo', 'preview', 'prod', 'production',
        'uat', 'qa', 'testing', 'db', 'database', 'sql', 'mysql', 'postgres',
    ]
    
    def __init__(self, domain: str, wordlist: List[str] = None, threads: int = 20):
        self.domain = domain
        self.wordlist = wordlist if wordlist else self.COMMON_SUBDOMAINS
        self.threads = threads
        self.found_subdomains = set()
        self.queue = Queue()
        self.lock = threading.Lock()
        
    def find_all(self) -> Set[str]:
        """Encuentra subdominios usando todas las técnicas"""
        print(f"[*] Iniciando búsqueda de subdominios para: {self.domain}")
        
        # Técnica 1: Brute Force DNS
        print(f"[*] Técnica 1: Brute Force DNS ({len(self.wordlist)} palabras)")
        self.bruteforce_dns()
        
        # Técnica 2: Certificate Transparency
        print(f"[*] Técnica 2: Certificate Transparency")
        self.certificate_transparency()
        
        # Técnica 3: Search Engines
        print(f"[*] Técnica 3: Search Engines")
        self.search_engines()
        
        print(f"\n[+] Total de subdominios encontrados: {len(self.found_subdomains)}")
        
        return self.found_subdomains
    
    def bruteforce_dns(self):
        """Brute force DNS usando wordlist"""
        # Llenar la cola
        for word in self.wordlist:
            self.queue.put(word)
        
        # Crear threads
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self._dns_worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Esperar a que terminen
        for t in threads:
            t.join()
    
    def _dns_worker(self):
        """Worker thread para brute force DNS"""
        while not self.queue.empty():
            subdomain_word = self.queue.get()
            full_domain = f"{subdomain_word}.{self.domain}"
            
            try:
                # Intentar resolver
                socket.gethostbyname(full_domain)
                
                with self.lock:
                    self.found_subdomains.add(full_domain)
                    print(f"[+] Encontrado: {full_domain}")
                    
            except socket.gaierror:
                pass
            except Exception as e:
                pass
            
            self.queue.task_done()
    
    def certificate_transparency(self):
        """Búsqueda en Certificate Transparency Logs"""
        try:
            # Usar crt.sh API
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                for entry in data:
                    name = entry.get('name_value', '')
                    
                    # Procesar nombres (pueden tener múltiples líneas)
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip()
                        
                        # Validar que sea un subdominio válido
                        if subdomain and subdomain.endswith(self.domain):
                            # Eliminar wildcards
                            if not subdomain.startswith('*'):
                                with self.lock:
                                    if subdomain not in self.found_subdomains:
                                        self.found_subdomains.add(subdomain)
                                        print(f"[+] CT: {subdomain}")
        except Exception as e:
            print(f"[!] Error en Certificate Transparency: {e}")
    
    def search_engines(self):
        """Búsqueda en motores de búsqueda"""
        # Google dorking
        try:
            query = f"site:.{self.domain} -www"
            # Nota: En producción real, usar APIs oficiales
            print(f"[*] Google Dork: {query}")
            # Implementación básica (requeriría scraping o API)
        except Exception as e:
            print(f"[!] Error en búsqueda de motores: {e}")
    
    def dns_zone_walk(self):
        """DNSSEC zone walking (si está habilitado)"""
        try:
            resolver = dns.resolver.Resolver()
            # Intentar NSEC walking
            # Implementación avanzada de DNSSEC zone walking
            pass
        except Exception as e:
            print(f"[!] Error en zone walking: {e}")
    
    def display_results(self):
        """Muestra los resultados"""
        print(f"\n{'='*60}")
        print(f"Subdomain Discovery Results for: {self.domain}")
        print(f"{'='*60}\n")
        
        if not self.found_subdomains:
            print("[!] No se encontraron subdominios")
            return
        
        # Ordenar y mostrar
        sorted_subdomains = sorted(self.found_subdomains)
        
        for subdomain in sorted_subdomains:
            try:
                ip = socket.gethostbyname(subdomain)
                print(f"[+] {subdomain} → {ip}")
            except:
                print(f"[+] {subdomain}")

def find(domain: str, wordlist: List[str] = None, threads: int = 20) -> Set[str]:
    """
    Función principal de descubrimiento de subdominios
    
    Args:
        domain: Dominio base
        wordlist: Lista personalizada de palabras (opcional)
        threads: Número de threads para brute force
        
    Returns:
        Set de subdominios encontrados
    """
    finder = SubdomainFinder(domain, wordlist, threads)
    results = finder.find_all()
    finder.display_results()
    return results

def load_wordlist(file_path: str) -> List[str]:
    """
    Carga una wordlist desde un archivo
    
    Args:
        file_path: Ruta al archivo de wordlist
        
    Returns:
        Lista de palabras
    """
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Error cargando wordlist: {e}")
        return []

def export_results(subdomains: Set[str], output_file: str):
    """
    Exporta los resultados a un archivo
    
    Args:
        subdomains: Set de subdominios
        output_file: Archivo de salida
    """
    try:
        with open(output_file, 'w') as f:
            for subdomain in sorted(subdomains):
                f.write(f"{subdomain}\n")
        print(f"[+] Resultados guardados en: {output_file}")
    except Exception as e:
        print(f"[!] Error guardando resultados: {e}")

if __name__ == "__main__":
    # Test del módulo
    import sys
    
    if len(sys.argv) > 1:
        domain = sys.argv[1]
        
        # Cargar wordlist si se proporciona
        wordlist = None
        if len(sys.argv) > 2:
            wordlist = load_wordlist(sys.argv[2])
        
        # Encontrar subdominios
        results = find(domain, wordlist)
        
        # Exportar si se solicita
        if len(sys.argv) > 3:
            export_results(results, sys.argv[3])
    else:
        print("Uso: python subdomain_finder.py <domain> [wordlist] [output]")
        print("Ejemplo: python subdomain_finder.py example.com")
        print("Ejemplo: python subdomain_finder.py example.com wordlist.txt results.txt")