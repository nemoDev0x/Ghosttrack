
import subprocess
import platform
import re

class Traceroute:
    def __init__(self, target: str, max_hops: int = 30):
        self.target = target
        self.max_hops = max_hops
        self.hops = []
        
    def trace(self) -> List[Dict]:
        print(f"[*] Trazando ruta a: {self.target}")
        
        try:
            # Comando según el SO
            if platform.system() == 'Windows':
                cmd = f"tracert -h {self.max_hops} {self.target}"
            else:
                cmd = f"traceroute -m {self.max_hops} {self.target}"
            
            # Ejecutar traceroute
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            output = output.decode('utf-8', errors='ignore')
            
            # Parsear salida
            self.hops = self.parse_output(output)
            
            # Mostrar resultados
            self.display_results()
            
        except subprocess.CalledProcessError as e:
            print(f"[!] Error ejecutando traceroute: {e}")
            return []
        
        return self.hops
    
    def parse_output(self, output: str) -> List[Dict]:
        """Parsea la salida del traceroute"""
        hops = []
        
        lines = output.split('\n')
        for line in lines:
            # Buscar líneas con información de saltos
            # Formato: número IP [hostname] tiempo
            hop_match = re.search(r'(\d+)\s+([0-9\.]+|\*)\s+(?:\[([^\]]+)\])?\s*(\d+\.?\d*)\s*ms', line)
            
            if hop_match:
                hop_num = int(hop_match.group(1))
                ip = hop_match.group(2)
                hostname = hop_match.group(3) if hop_match.group(3) else None
                rtt = float(hop_match.group(4))
                
                hops.append({
                    'hop': hop_num,
                    'ip': ip,
                    'hostname': hostname,
                    'rtt': rtt
                })
        
        return hops
    
    def display_results(self):
        """Muestra los resultados del traceroute"""
        print(f"\n{'='*70}")
        print(f"Traceroute to {self.target}")
        print(f"{'='*70}\n")
        
        for hop in self.hops:
            hostname_str = f" ({hop['hostname']})" if hop['hostname'] else ""
            print(f"{hop['hop']:2d}  {hop['ip']:15s}{hostname_str:30s}  {hop['rtt']:.2f} ms")

def trace(target: str, max_hops: int = 30) -> List[Dict]:
    tracer = Traceroute(target, max_hops)
    return tracer.trace()