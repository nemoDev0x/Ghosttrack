
import ssl as ssl_module
import threading
from queue import Queue

class BannerGrabber:
    SERVICE_PROBES = {
        21: b'',                           # FTP
        22: b'',                           # SSH
        25: b'EHLO banner\r\n',           # SMTP
        80: b'GET / HTTP/1.0\r\n\r\n',   # HTTP
        443: b'GET / HTTP/1.0\r\n\r\n',  # HTTPS
        3306: b'',                         # MySQL
        6379: b'INFO\r\n',                # Redis
    }
    
    def __init__(self, target: str, ports: List[int], timeout: int = 3, threads: int = 10):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.threads = threads
        self.results = {}
        self.queue = Queue()
        self.lock = threading.Lock()
        
    def grab_all(self) -> Dict[int, Dict]:
        print(f"[*] Capturando banners de {len(self.ports)} puertos...")
        
        for port in self.ports:
            self.queue.put(port)
        
        threads = []
        for _ in range(min(self.threads, len(self.ports))):
            t = threading.Thread(target=self._worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        return self.results
    
    def _worker(self):
        while not self.queue.empty():
            port = self.queue.get()
            banner = self.grab_banner(port)
            
            if banner:
                with self.lock:
                    self.results[port] = banner
                    print(f"[+] Puerto {port}: Banner capturado")
            
            self.queue.task_done()
    
    def grab_banner(self, port: int) -> Dict:
        use_ssl = port in [443, 8443, 993, 995]
        
        if use_ssl:
            return self._grab_ssl_banner(port)
        else:
            return self._grab_plain_banner(port)
    
    def _grab_plain_banner(self, port: int) -> Dict:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            
            probe = self.SERVICE_PROBES.get(port, b'')
            if probe:
                sock.send(probe)
            
            banner = sock.recv(4096)
            sock.close()
            
            if banner:
                return {
                    'port': port,
                    'ssl': False,
                    'banner': banner.decode('utf-8', errors='ignore').strip()
                }
        except:
            pass
        return None
    
    def _grab_ssl_banner(self, port: int) -> Dict:
        try:
            context = ssl_module.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl_module.CERT_NONE
            
            with socket.create_connection((self.target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    probe = self.SERVICE_PROBES.get(port, b'')
                    if probe:
                        ssock.send(probe)
                    
                    banner = ssock.recv(4096)
                    
                    return {
                        'port': port,
                        'ssl': True,
                        'ssl_version': ssock.version(),
                        'cipher': ssock.cipher(),
                        'banner': banner.decode('utf-8', errors='ignore').strip()
                    }
        except:
            pass
        return None

def grab(target: str, ports: List[int], timeout: int = 3) -> Dict:
    grabber = BannerGrabber(target, ports, timeout)
    return grabber.grab_all()