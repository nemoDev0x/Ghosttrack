"""
MÓDULO 1: GEOLOCALIZACIÓN IP
Obtiene información geográfica de una dirección IP
"""



"""
Si no funciona a esta parte es culpa del import requests
voy a omitirlo por el toc
"""

import requests
import socket
from typing import Dict, Optional

def get_location(target: str) -> Dict:
    """
    Obtiene la geolocalización de una IP o dominio
    
    Args:
        target: IP o dominio a geolocalizar
        
    Returns:
        Diccionario con información de geolocalización
    """
    print(f"[*] Geolocalizando: {target}")
    
    try:
        # Resolver a IP si es un dominio
        ip = resolve_to_ip(target)
        
        # Usar API gratuita de geolocalización
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            if data['status'] == 'success':
                result = {
                    'ip': ip,
                    'country': data.get('country', 'Unknown'),
                    'country_code': data.get('countryCode', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'zip': data.get('zip', 'Unknown'),
                    'lat': data.get('lat', 0),
                    'lon': data.get('lon', 0),
                    'timezone': data.get('timezone', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'as': data.get('as', 'Unknown'),
                }
                
                # Mostrar resultados
                print(f"[+] IP: {result['ip']}")
                print(f"[+] País: {result['country']} ({result['country_code']})")
                print(f"[+] Región: {result['region']}")
                print(f"[+] Ciudad: {result['city']}")
                print(f"[+] Coordenadas: {result['lat']}, {result['lon']}")
                print(f"[+] ISP: {result['isp']}")
                print(f"[+] Organización: {result['org']}")
                print(f"[+] ASN: {result['as']}")
                
                return result
            else:
                return {'error': 'No se pudo obtener información de geolocalización'}
        else:
            return {'error': f'Error en la petición: {response.status_code}'}
            
    except Exception as e:
        return {'error': str(e)}

def resolve_to_ip(target: str) -> str:
    """
    Resuelve un dominio a dirección IP
    
    Args:
        target: Dominio o IP
        
    Returns:
        Dirección IP
    """
    try:
        # Si ya es una IP, devolverla
        socket.inet_aton(target)
        return target
    except socket.error:
        # Es un dominio, resolver
        try:
            ip = socket.gethostbyname(target)
            print(f"[+] {target} resuelve a {ip}")
            return ip
        except socket.gaierror:
            raise ValueError(f"No se pudo resolver el dominio: {target}")

def get_reverse_dns(ip: str) -> Optional[str]:
    """
    Obtiene el reverse DNS de una IP
    
    Args:
        ip: Dirección IP
        
    Returns:
        Nombre de dominio o None
    """
    try:
        hostname = socket.gethostbyaddr(ip)
        return hostname[0]
    except socket.herror:
        return None

def get_asn_info(ip: str) -> Dict:
    """
    Obtiene información del ASN (Autonomous System Number)
    
    Args:
        ip: Dirección IP
        
    Returns:
        Información del ASN
    """
    try:
        response = requests.get(f"https://api.hackertarget.com/aslookup/?q={ip}", timeout=10)
        if response.status_code == 200:
            return {'asn': response.text.strip()}
        return {'error': 'No se pudo obtener información ASN'}
    except Exception as e:
        return {'error': str(e)}

def get_geolocation_alternative(ip: str) -> Dict:
    """
    API alternativa de geolocalización (ipapi.co)
    
    Args:
        ip: Dirección IP
        
    Returns:
        Información de geolocalización
    """
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10)
        if response.status_code == 200:
            return response.json()
        return {'error': 'API alternativa no disponible'}
    except Exception as e:
        return {'error': str(e)}

if __name__ == "__main__":
    # Test del módulo
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        print(f"Testing geolocalización para: {target}")
        result = get_location(target)
        print(f"\nResultado completo:\n{result}")
    else:
        # Test con IP pública de Google DNS
        test_target = "8.8.8.8"
        print(f"Testing geolocalización para: {test_target}")
        result = get_location(test_target)
        print(f"\nResultado completo:\n{result}")