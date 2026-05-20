
import requests
from bs4 import BeautifulSoup
import re

class EmailHarvester:
    def __init__(self, target: str):
        self.target = target
        self.emails = set()
        
    def harvest(self) -> List[str]:
        print(f"[*] Buscando emails en: {self.target}")
        
        # Técnica 1: Scraping del sitio web
        self.harvest_from_website()
        
        # Técnica 2: Búsqueda en Google (limitada)
        self.harvest_from_search()
        
        print(f"[+] Emails encontrados: {len(self.emails)}")
        
        for email in self.emails:
            print(f"  - {email}")
        
        return list(self.emails)
    
    def harvest_from_website(self):
        """Extrae emails del sitio web"""
        try:
            url = f"http://{self.target}" if not self.target.startswith('http') else self.target
            response = requests.get(url, timeout=10)
            
            # Buscar emails con regex
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            emails = re.findall(email_pattern, response.text)
            
            for email in emails:
                self.emails.add(email.lower())
                
        except Exception as e:
            print(f"[!] Error: {e}")
    
    def harvest_from_search(self):
        """Búsqueda en motores (simulado)"""
        print("[*] Búsqueda en Google (limitada sin API)")

def harvest(target: str) -> List[str]:
    harvester = EmailHarvester(target)
    return harvester.harvest()