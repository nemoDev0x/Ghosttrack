"""
═══════════════════════════════════════════════════════════════════
GhostTrack Red Team Modules Package
═══════════════════════════════════════════════════════════════════

Este paquete contiene 20 módulos avanzados de Red Team para pentesting:

ENUMERACIÓN Y RECONOCIMIENTO:
- SMBEnumerator: Enumeración de servicios SMB/CIFS
- LDAPEnumerator: Enumeración de Active Directory
- BloodHoundCollector: Recolección de datos AD

ATAQUES A CREDENCIALES:
- KerberosAttacker: Kerberoasting, AS-REP Roasting
- NTLMRelayAttacker: NTLM Relay y Pass-the-Hash
- CredentialDumper: Extracción de credenciales (LSASS, SAM, WiFi, etc)

POST-EXPLOTACIÓN:
- PrivilegeEscalationChecker: Vectores de escalada de privilegios
- LateralMovementDetector: Rutas de movimiento lateral
- TokenManipulator: Manipulación de tokens Windows
- ProcessInjector: Inyección de procesos (DLL, Hollowing, etc)

PERSISTENCIA Y EVASIÓN:
- DLLHijackingScanner: Búsqueda de DLL Hijacking
- PersistenceChecker: Mecanismos de persistencia
- FirewallEvasion: Evasión de firewalls
- AVEvasion: Evasión de antivirus

TÉCNICAS AVANZADAS:
- PayloadGenerator: Generación de payloads
- C2Communication: Comunicación Command & Control
- DataExfiltration: Exfiltración de datos
- WiFiAttacker: Ataques WiFi
- BluetoothScanner: Escaneo Bluetooth
- SocialEngineeringToolkit: Ingeniería social

═══════════════════════════════════════════════════════════════════
ADVERTENCIA LEGAL:
Estos módulos implementan técnicas ofensivas avanzadas que pueden ser
ILEGALES si se usan sin autorización explícita. Solo para fines
educativos y con permiso por escrito del propietario del sistema.
═══════════════════════════════════════════════════════════════════
"""

from .complete_redteam import (
    # Enumeración
    SMBEnumerator,
    LDAPEnumerator,
    BloodHoundCollector,
    
    # Ataques a Credenciales
    KerberosAttacker,
    NTLMRelayAttacker,
    CredentialDumper,
    
    # Post-Explotación
    PrivilegeEscalationChecker,
    LateralMovementDetector,
    TokenManipulator,
    ProcessInjector,
    
    # Persistencia y Evasión
    DLLHijackingScanner,
    PersistenceChecker,
    FirewallEvasion,
    AVEvasion,
    
    # Técnicas Avanzadas
    PayloadGenerator,
    C2Communication,
    DataExfiltration,
    WiFiAttacker,
    BluetoothScanner,
    SocialEngineeringToolkit,
    
    # Función principal
    run_full_redteam_assessment
)

__version__ = '2.0.0'
__author__ = 'Tu Nombre'

__all__ = [
    # Enumeración (3)
    'SMBEnumerator',
    'LDAPEnumerator',
    'BloodHoundCollector',
    
    # Ataques a Credenciales (3)
    'KerberosAttacker',
    'NTLMRelayAttacker',
    'CredentialDumper',
    
    # Post-Explotación (4)
    'PrivilegeEscalationChecker',
    'LateralMovementDetector',
    'TokenManipulator',
    'ProcessInjector',
    
    # Persistencia y Evasión (4)
    'DLLHijackingScanner',
    'PersistenceChecker',
    'FirewallEvasion',
    'AVEvasion',
    
    # Técnicas Avanzadas (6)
    'PayloadGenerator',
    'C2Communication',
    'DataExfiltration',
    'WiFiAttacker',
    'BluetoothScanner',
    'SocialEngineeringToolkit',
    
    # Función principal
    'run_full_redteam_assessment'
]

# Total: 20 clases + 1 función = 21 exportaciones

def get_available_modules():
    """
    Retorna la lista de todos los módulos Red Team disponibles
    
    Returns:
        Dict con información de cada módulo
    """
    modules = {
        'enumeration': {
            'SMBEnumerator': 'Enumeración SMB/CIFS (shares, usuarios, null sessions)',
            'LDAPEnumerator': 'Enumeración LDAP/Active Directory',
            'BloodHoundCollector': 'Recolección de datos para BloodHound'
        },
        'credential_attacks': {
            'KerberosAttacker': 'Kerberoasting y AS-REP Roasting',
            'NTLMRelayAttacker': 'NTLM Relay y Pass-the-Hash',
            'CredentialDumper': 'Extracción de credenciales (LSASS, SAM, WiFi, browsers)'
        },
        'post_exploitation': {
            'PrivilegeEscalationChecker': 'Detección de vectores de escalada de privilegios',
            'LateralMovementDetector': 'Rutas de movimiento lateral',
            'TokenManipulator': 'Manipulación de tokens Windows',
            'ProcessInjector': 'Inyección de procesos (DLL, Hollowing, etc)'
        },
        'persistence_evasion': {
            'DLLHijackingScanner': 'Búsqueda de DLL Hijacking',
            'PersistenceChecker': 'Mecanismos de persistencia',
            'FirewallEvasion': 'Evasión de firewalls',
            'AVEvasion': 'Evasión de antivirus'
        },
        'advanced': {
            'PayloadGenerator': 'Generación de payloads (Meterpreter, Empire, etc)',
            'C2Communication': 'Comunicación C2 (HTTPS, DNS, ICMP)',
            'DataExfiltration': 'Exfiltración de datos (DNS, Steganography)',
            'WiFiAttacker': 'Ataques WiFi (Handshake, Deauth)',
            'BluetoothScanner': 'Escaneo y ataques Bluetooth',
            'SocialEngineeringToolkit': 'Framework de ingeniería social'
        }
    }
    
    return modules

def print_modules_info():
    """Imprime información de todos los módulos Red Team"""
    modules = get_available_modules()
    
    print("\n" + "="*70)
    print("GHOSTTRACK RED TEAM MODULES - 20 MÓDULOS DISPONIBLES")
    print("="*70 + "\n")
    
    total = 0
    for category, mods in modules.items():
        category_name = category.replace('_', ' ').title()
        print(f"\n{category_name} ({len(mods)} módulos):")
        print("-" * 70)
        
        for module_name, description in mods.items():
            total += 1
            print(f"  {total:2d}. {module_name:30s} - {description}")
    
    print(f"\n{'='*70}")
    print(f"Total: {total} módulos Red Team")
    print(f"{'='*70}\n")

if __name__ == "__main__":
    print_modules_info()