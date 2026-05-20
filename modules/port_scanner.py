"""
MÓDULO 5: PORT SCANNER
Escaneo rápido y eficiente de puertos TCP/UDP
"""

import socket
import threading
from queue import Queue
from typing import List, Dict
import time

# Puertos comunes a escanear
COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 3000, 5000, 5432, 6379, 27017,
    1433, 1521, 2049, 5601, 9200, 9300, 11211, 50000, 50070
]

class PortScanner:
    """Escáner de puertos multi-threaded"""
    
    def __init__(self, target: str, ports: List[int] = None, threads: int = 100, timeout: float = 1):
        self.target = target
        self.ports = ports if ports else COMMON_PORTS
        self.threads = threads
        self.timeout = timeout
        self.open_ports = []
        self.queue = Queue()
        self.lock = threading.Lock()
        self.start_time = None
        
    def scan_port(self, port: int) -> bool:
        """
        Escanea un puerto específico
        
        Args:
            port: Número de puerto
            
        Returns:
            True si el puerto está abierto
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                return True
            return False
        except:
            return False
    
    def worker(self):
        """Worker thread para escaneo paralelo"""
        while not self.queue.empty():
            port = self.queue.get()
            if self.scan_port(port):
                with self.lock:
                    self.open_ports.append(port)
                    service = self.get_service_name(port)
                    print(f"[+] Puerto {port}/tcp ABIERTO - {service}")
            self.queue.task_done()
    
    def scan(self) -> List[int]:
        """
        Ejecuta el escaneo de puertos
        
        Returns:
            Lista de puertos abiertos
        """
        self.start_time = time.time()
        
        print(f"[*] Iniciando escaneo de {len(self.ports)} puertos en {self.target}")
        print(f"[*] Usando {self.threads} threads con timeout de {self.timeout}s")
        
        # Llenar la cola
        for port in self.ports:
            self.queue.put(port)
        
        # Crear threads
        thread_list = []
        for _ in range(min(self.threads, len(self.ports))):
            thread = threading.Thread(target=self.worker)
            thread.daemon = True
            thread.start()
            thread_list.append(thread)
        
        # Esperar a que terminen
        for thread in thread_list:
            thread.join()
        
        elapsed_time = time.time() - self.start_time
        
        self.open_ports.sort()
        print(f"\n[+] Escaneo completo en {elapsed_time:.2f} segundos")
        print(f"[+] {len(self.open_ports)} puertos abiertos encontrados")
        
        return self.open_ports
    
    def get_service_name(self, port: int) -> str:
        """Obtiene el nombre del servicio para un puerto"""
        try:
            return socket.getservbyport(port)
        except:
            return "unknown"
    
    def scan_range(self, start_port: int, end_port: int) -> List[int]:
        """
        Escanea un rango de puertos
        
        Args:
            start_port: Puerto inicial
            end_port: Puerto final
            
        Returns:
            Lista de puertos abiertos
        """
        self.ports = list(range(start_port, end_port + 1))
        return self.scan()
    
    def quick_scan(self) -> List[int]:
        """Escaneo rápido de puertos más comunes"""
        self.ports = COMMON_PORTS[:20]  # Top 20 puertos
        return self.scan()
    
    def full_scan(self) -> List[int]:
        """Escaneo completo de todos los puertos"""
        self.ports = list(range(1, 65536))
        return self.scan()

def scan(target: str, port_range: str = None, threads: int = 100) -> List[int]:
    """
    Función principal de escaneo
    
    Args:
        target: IP o dominio objetivo
        port_range: Rango de puertos (ej: "1-1000" o "80,443,8080")
        threads: Número de threads
        
    Returns:
        Lista de puertos abiertos
    """
    ports = parse_port_range(port_range) if port_range else COMMON_PORTS
    
    scanner = PortScanner(target, ports, threads)
    return scanner.scan()

def parse_port_range(port_range: str) -> List[int]:
    """
    Parsea un rango de puertos
    
    Args:
        port_range: String con rango (ej: "1-100" o "80,443,8080")
        
    Returns:
        Lista de puertos
    """
    ports = []
    
    if '-' in port_range:
        # Rango: "1-1000"
        start, end = map(int, port_range.split('-'))
        ports = list(range(start, end + 1))
    elif ',' in port_range:
        # Lista: "80,443,8080"
        ports = [int(p.strip()) for p in port_range.split(',')]
    else:
        # Puerto único
        ports = [int(port_range)]
    
    return ports

def scan_udp(target: str, port: int, timeout: float = 2) -> bool:
    """
    Escanea un puerto UDP
    
    Args:
        target: IP objetivo
        port: Puerto a escanear
        timeout: Timeout en segundos
        
    Returns:
        True si el puerto está abierto/filtrado
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b'', (target, port))
        
        try:
            data, addr = sock.recvfrom(1024)
            sock.close()
            return True  # Puerto abierto
        except socket.timeout:
            sock.close()
            return True  # Puerto abierto/filtrado (no hay respuesta ICMP)
    except:
        return False

def stealth_scan(target: str, port: int) -> str:
    """
    SYN Stealth Scan (requiere privilegios root)
    
    Args:
        target: IP objetivo
        port: Puerto a escanear
        
    Returns:
        Estado del puerto
    """
    # Nota: Requiere scapy y privilegios root
    print("[!] SYN Stealth Scan requiere privilegios root y scapy")
    return "not_implemented"

def get_open_ports_summary(target: str, open_ports: List[int]) -> Dict:
    """
    Genera un resumen de puertos abiertos
    
    Args:
        target: Target escaneado
        open_ports: Lista de puertos abiertos
        
    Returns:
        Diccionario con resumen
    """
    summary = {
        'target': target,
        'total_open_ports': len(open_ports),
        'ports': {},
        'services': {}
    }
    
    for port in open_ports:
        try:
            service = socket.getservbyport(port)
            summary['ports'][port] = service
            
            if service in summary['services']:
                summary['services'][service].append(port)
            else:
                summary['services'][service] = [port]
        except:
            summary['ports'][port] = 'unknown'
    
    return summary

if __name__ == "__main__":
    # Test del módulo
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        
        if len(sys.argv) > 2:
            # Con rango de puertos
            port_range = sys.argv[2]
            open_ports = scan(target, port_range)
        else:
            # Escaneo de puertos comunes
            open_ports = scan(target)
        
        # Mostrar resumen
        summary = get_open_ports_summary(target, open_ports)
        print(f"\n{'='*60}")
        print(f"Resumen del escaneo:")
        print(f"Puertos abiertos: {summary['total_open_ports']}")
        print(f"Servicios detectados: {len(summary['services'])}")
        print(f"{'='*60}")
    else:
        print("Uso: python port_scanner.py <target> [port_range]")
        print("Ejemplos:")
        print("  python port_scanner.py 192.168.1.1")
        print("  python port_scanner.py scanme.nmap.org 1-1000")
        print("  python port_scanner.py example.com 80,443,8080")