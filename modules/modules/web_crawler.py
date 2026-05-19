from typing import Dict, List, Optional, Tuple, Any

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import Set

class WebCrawler:
    def __init__(self, target: str, max_depth: int = 3, max_pages: int = 50):
        self.target = target
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited_urls = set()
        self.found_urls = set()
        self.emails = set()
        self.forms = []
        
    def crawl(self) -> Dict:
        print(f"[*] Crawling: {self.target}")
        
        # Asegurar que el target tenga protocolo
        if not self.target.startswith('http'):
            self.target = f"http://{self.target}"
        
        # Iniciar crawling
        self._crawl_recursive(self.target, 0)
        
        results = {
            'target': self.target,
            'total_urls': len(self.found_urls),
            'urls': list(self.found_urls),
            'emails': list(self.emails),
            'forms': self.forms,
            'visited': len(self.visited_urls)
        }
        
        self.display_results(results)
        
        return results
    
    def _crawl_recursive(self, url: str, depth: int):
        """Crawling recursivo"""
        # Verificar límites
        if depth > self.max_depth or len(self.visited_urls) >= self.max_pages:
            return
        
        if url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        
        try:
            print(f"[*] Crawling [{depth}]: {url}")
            
            response = requests.get(url, timeout=5, allow_redirects=True)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extraer enlaces
                links = self._extract_links(soup, url)
                
                # Extraer emails
                self._extract_emails(response.text)
                
                # Extraer formularios
                self._extract_forms(soup, url)
                
                # Crawlear enlaces encontrados
                for link in links:
                    if self._is_valid_url(link):
                        self.found_urls.add(link)
                        
                        # Crawlear recursivamente solo URLs del mismo dominio
                        if urlparse(link).netloc == urlparse(self.target).netloc:
                            self._crawl_recursive(link, depth + 1)
        
        except Exception as e:
            print(f"[!] Error crawling {url}: {e}")
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> Set[str]:
        """Extrae todos los enlaces de la página"""
        links = set()
        
        for tag in soup.find_all(['a', 'link']):
            href = tag.get('href')
            if href:
                absolute_url = urljoin(base_url, href)
                links.add(absolute_url)
        
        return links
    
    def _extract_emails(self, text: str):
        """Extrae direcciones de email del texto"""
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, text)
        
        for email in emails:
            self.emails.add(email)
            print(f"[+] Email encontrado: {email}")
    
    def _extract_forms(self, soup: BeautifulSoup, url: str):
        """Extrae información de formularios"""
        for form in soup.find_all('form'):
            form_info = {
                'url': url,
                'action': form.get('action'),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea']):
                form_info['inputs'].append({
                    'type': input_tag.get('type', 'text'),
                    'name': input_tag.get('name'),
                    'value': input_tag.get('value')
                })
            
            self.forms.append(form_info)
            print(f"[+] Formulario encontrado en: {url}")
    
    def _is_valid_url(self, url: str) -> bool:
        """Verifica si una URL es válida"""
        parsed = urlparse(url)
        return bool(parsed.netloc) and bool(parsed.scheme)
    
    def display_results(self, results: Dict):
        """Muestra los resultados del crawling"""
        print(f"\n{'='*70}")
        print(f"Web Crawling Results for: {results['target']}")
        print(f"{'='*70}\n")
        
        print(f"[+] URLs encontradas: {results['total_urls']}")
        print(f"[+] Emails encontrados: {len(results['emails'])}")
        print(f"[+] Formularios encontrados: {len(results['forms'])}")
        print(f"[+] Páginas visitadas: {results['visited']}")

def crawl(target: str, max_depth: int = 3, max_pages: int = 50) -> Dict:
    crawler = WebCrawler(target, max_depth, max_pages)
    return crawler.crawl()
