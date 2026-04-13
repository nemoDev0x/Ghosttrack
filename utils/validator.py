import re
import socket
import ipaddress

class Validator:
    """Validación de inputs y datos"""
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Valida una dirección IP"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Valida un nombre de dominio"""
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))
    
    @staticmethod
    def validate_target(target: str) -> bool:
        """Valida un target (IP o dominio)"""
        if Validator.validate_ip(target):
            return True
        if Validator.validate_domain(target):
            return True
        
        # Intentar resolver como hostname
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            return False
    
    @staticmethod
    def validate_port(port: int) -> bool:
        """Valida un número de puerto"""
        return 1 <= port <= 65535
    
    @staticmethod
    def validate_port_range(port_range: str) -> bool:
        """Valida un rango de puertos"""
        try:
            if '-' in port_range:
                start, end = map(int, port_range.split('-'))
                return Validator.validate_port(start) and Validator.validate_port(end) and start <= end
            elif ',' in port_range:
                ports = [int(p.strip()) for p in port_range.split(',')]
                return all(Validator.validate_port(p) for p in ports)
            else:
                return Validator.validate_port(int(port_range))
        except ValueError:
            return False
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Valida una URL"""
        pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        return bool(re.match(pattern, url, re.IGNORECASE))
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Valida una dirección de email"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitiza un nombre de archivo"""
        # Remover caracteres peligrosos
        filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
        # Limitar longitud
        if len(filename) > 200:
            filename = filename[:200]
        return filename
    
    @staticmethod
    def validate_cidr(cidr: str) -> bool:
        """Valida notación CIDR"""
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False
