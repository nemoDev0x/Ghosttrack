from typing import Dict, List, Optional, Tuple, Any

class NetworkSniffer:
    def __init__(self, interface: str = None):
        self.interface = interface
        self.packets = []
        
    def sniff(self, count: int = 100) -> List:
        print(f"[*] Capturando {count} paquetes...")
        print("[!] Nota: Requiere privilegios de administrador")
        
        try:
            from scapy.all import sniff as scapy_sniff
            
            packets = scapy_sniff(count=count, iface=self.interface)
            
            for pkt in packets:
                self.packets.append({
                    'summary': pkt.summary(),
                    'time': pkt.time
                })
                print(f"[+] {pkt.summary()}")
            
        except ImportError:
            print("[!] Scapy no está instalado: pip install scapy")
        except Exception as e:
            print(f"[!] Error: {e}")
        
        return self.packets

def sniff(interface: str = None, count: int = 100) -> List:
    sniffer = NetworkSniffer(interface)
    return sniffer.sniff(count)
