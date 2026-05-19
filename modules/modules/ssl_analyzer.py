from typing import Dict, List, Tuple, Optional, Any
import ssl
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class SSLAnalyzer:
    def __init__(self, target: str, port: int = 443):
        self.target = target
        self.port = port
        
    def analyze(self) -> Dict:
        print(f"[*] Analizando SSL/TLS de: {self.target}:{self.port}")
        
        results = {
            'target': self.target,
            'port': self.port,
            'timestamp': datetime.now().isoformat()
        }
        
        # Obtener certificado
        cert_info = self.get_certificate()
        if cert_info:
            results['certificate'] = cert_info
        
        # Probar versiones SSL/TLS
        protocols = self.test_protocols()
        results['supported_protocols'] = protocols
        
        # Probar ciphers
        ciphers = self.test_ciphers()
        results['ciphers'] = ciphers
        
        # Verificar vulnerabilidades conocidas
        vulns = self.check_vulnerabilities(results)
        results['vulnerabilities'] = vulns
        
        return results
    
    def get_certificate(self) -> Dict:
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((self.target, self.port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()
                    
                    # Parsear certificado
                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                    
                    return {
                        'subject': dict(x[0] for x in cert_dict.get('subject', [])),
                        'issuer': dict(x[0] for x in cert_dict.get('issuer', [])),
                        'version': cert_dict.get('version'),
                        'serial_number': cert.serial_number,
                        'not_before': cert.not_valid_before.isoformat(),
                        'not_after': cert.not_valid_after.isoformat(),
                        'signature_algorithm': cert.signature_algorithm_oid._name,
                        'is_expired': datetime.now() > cert.not_valid_after,
                        'days_until_expiry': (cert.not_valid_after - datetime.now()).days
                    }
        except Exception as e:
            return {'error': str(e)}
    
    def test_protocols(self) -> List[str]:
        """Prueba versiones de SSL/TLS soportadas"""
        protocols = []
        
        ssl_versions = [
            ('SSLv2', ssl.PROTOCOL_SSLv23),  # Deprecated
            ('SSLv3', ssl.PROTOCOL_SSLv23),  # Deprecated
            ('TLSv1.0', ssl.PROTOCOL_TLSv1),
            ('TLSv1.1', ssl.PROTOCOL_TLSv1_1),
            ('TLSv1.2', ssl.PROTOCOL_TLSv1_2),
        ]
        
        for name, protocol in ssl_versions:
            try:
                context = ssl.SSLContext(protocol)
                with socket.create_connection((self.target, self.port), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        protocols.append(name)
                        print(f"[+] {name}: Soportado")
            except:
                print(f"[-] {name}: No soportado")
        
        return protocols
    
    def test_ciphers(self) -> List[str]:
        """Prueba cipher suites soportadas"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, self.port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cipher = ssock.cipher()
                    return {
                        'name': cipher[0],
                        'protocol': cipher[1],
                        'bits': cipher[2]
                    }
        except:
            return {}
    
    def check_vulnerabilities(self, results: Dict) -> List[Dict]:
        """Verifica vulnerabilidades SSL/TLS conocidas"""
        vulns = []
        
        protocols = results.get('supported_protocols', [])
        
        # Heartbleed (requiere prueba específica)
        # POODLE
        if 'SSLv3' in protocols:
            vulns.append({
                'name': 'POODLE',
                'severity': 'HIGH',
                'description': 'SSLv3 es vulnerable a POODLE'
            })
        
        # BEAST
        if 'TLSv1.0' in protocols:
            vulns.append({
                'name': 'BEAST',
                'severity': 'MEDIUM',
                'description': 'TLSv1.0 puede ser vulnerable a BEAST'
            })
        
        # Certificado expirado
        cert = results.get('certificate', {})
        if cert.get('is_expired'):
            vulns.append({
                'name': 'Expired Certificate',
                'severity': 'HIGH',
                'description': 'El certificado SSL ha expirado'
            })
        
        return vulns

def analyze(target: str, port: int = 443) -> Dict:
    analyzer = SSLAnalyzer(target, port)
    results = analyzer.analyze()
    
    # Mostrar resumen
    print(f"\n{'='*60}")
    print(f"SSL/TLS Analysis Results for: {target}:{port}")
    print(f"{'='*60}")
    
    if 'certificate' in results and 'subject' in results['certificate']:
        cert = results['certificate']
        print(f"\n[+] Certificado:")
        print(f"    CN: {cert['subject'].get('commonName', 'N/A')}")
        print(f"    Emisor: {cert['issuer'].get('organizationName', 'N/A')}")
        print(f"    Válido hasta: {cert.get('not_after', 'N/A')}")
        print(f"    Días restantes: {cert.get('days_until_expiry', 'N/A')}")
    
    if 'supported_protocols' in results:
        print(f"\n[+] Protocolos soportados:")
        for proto in results['supported_protocols']:
            print(f"    - {proto}")
    
    if 'vulnerabilities' in results and results['vulnerabilities']:
        print(f"\n[!] Vulnerabilidades encontradas:")
        for vuln in results['vulnerabilities']:
            print(f"    - {vuln['name']} [{vuln['severity']}]: {vuln['description']}")
    
    return results
