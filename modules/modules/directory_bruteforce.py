from typing import Dict, List, Optional, Tuple, Any
import requests
import threading
from queue import Queue

class DirectoryBruteforcer:
    # Wordlist básica de directorios comunes
    COMMON_DIRS = [
        'admin', 'administrator', 'login', 'dashboard', 'panel', 'cp', 'cpanel',
        'api', 'v1', 'v2', 'backup', 'backups', 'old', 'new', 'test', 'testing',
        'dev', 'development', 'prod', 'production', 'staging', 'demo',
        'wp-admin', 'wp-content', 'wp-includes', 'wordpress',
        'phpmyadmin', 'pma', 'mysql', 'database', 'db',
        'uploads', 'upload', 'files', 'images', 'img', 'assets', 'static',
        'js', 'css', 'fonts', 'media', 'downloads', 'download',
        'config', 'conf', 'configuration', 'settings',
        'includes', 'include', 'inc', 'lib', 'libraries',
        'server-status', 'server-info', '.git', '.svn', '.env',
        'robots.txt', 'sitemap.xml', '.htaccess', 'web.config'
    ]
    
    def __init__(self, target: str, wordlist: List[str] = None, threads: int = 10):
        self.target = target
        self.wordlist = wordlist if wordlist else self.COMMON_DIRS
        self.threads = threads
        self.found_dirs = []
        self.queue = Queue()
        self.lock = threading.Lock()
        
        # Asegurar que el target tenga protocolo
        if not self.target.startswith('http'):
            self.target = f"http://{self.target}"
    
    def bruteforce(self) -> List[Dict]:
        print(f"[*] Iniciando directory bruteforce en: {self.target}")
        print(f"[*] Testing {len(self.wordlist)} directorios...")
        
        # Llenar la cola
        for directory in self.wordlist:
            self.queue.put(directory)
        
        # Crear threads
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self._worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Esperar a que terminen
        for t in threads:
            t.join()
        
        print(f"\n[+] Directorios encontrados: {len(self.found_dirs)}")
        
        return self.found_dirs
    
    def _worker(self):
        """Worker thread para bruteforce"""
        while not self.queue.empty():
            directory = self.queue.get()
            
            url = f"{self.target.rstrip('/')}/{directory.lstrip('/')}"
            
            try:
                response = requests.get(url, timeout=5, allow_redirects=False)
                
                # Considerar encontrado si: 200, 301, 302, 403
                if response.status_code in [200, 301, 302, 401, 403]:
                    with self.lock:
                        self.found_dirs.append({
                            'url': url,
                            'status_code': response.status_code,
                            'size': len(response.content),
                            'redirect': response.headers.get('Location', None)
                        })
                        
                        status_emoji = {
                            200: '✓',
                            301: '→',
                            302: '→',
                            401: '🔒',
                            403: '⛔'
                        }
                        emoji = status_emoji.get(response.status_code, '?')
                        
                        print(f"[{emoji}] [{response.status_code}] {url} ({len(response.content)} bytes)")
                
            except requests.RequestException:
                pass
            
            self.queue.task_done()

def bruteforce(target: str, wordlist: List[str] = None, threads: int = 10) -> List[Dict]:
    bruteforcer = DirectoryBruteforcer(target, wordlist, threads)
    return bruteforcer.bruteforce()

def load_wordlist(file_path: str) -> List[str]:
    """Carga una wordlist desde un archivo"""
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Error cargando wordlist: {e}")
        return []
