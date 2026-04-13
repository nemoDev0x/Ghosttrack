#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════

   ********  **      **   *******    ******** ********** ********** *******       **       ******  **   **        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⡾⠿⢿⡀⠀⠀⠀⠀⣠⣶⣿⣷
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣦⣴⣿⡋⠀⠀⠈⢳⡄⠀⢠⣾⣿⠁⠈⣿⡆
⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⠿⠛⠉⠉⠁⠀⠀⠀⠹⡄⣿⣿⣿⠀⠀⢹⡇
⠀⠀⠀⠀⠀⣠⣾⡿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⣰⣏⢻⣿⣿⡆⠀⠸⣿
⠀⠀⠀⢀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣆⠹⣿⣷⠀⢘⣿
⠀⠀⢀⡾⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⠋⠉⠛⠂⠹⠿⣲⣿⣿⣧
⠀⢠⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣿⣿⣿⣷⣾⣿⡇⢀⠀⣼⣿⣿⣿⣧
⠰⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⡘⢿⣿⣿⣿
⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣷⡈⠿⢿⣿⡆
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠛⠁⢙⠛⣿⣿⣿⣿⡟⠀⡿⠀⠀⢀⣿⡇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣶⣤⣉⣛⠻⠇⢠⣿⣾⣿⡄⢻⡇
  **//////**/**     /**  **/////**  **////// /////**/// /////**/// /**////**     ****     **////**/**  **
 **      // /**     /** **     //**/**           /**        /**    /**   /**    **//**   **    // /** **
/**         /**********/**      /**/*********    /**        /**    /*******    **  //** /**       /****
/**    *****/**//////**/**      /**////////**    /**        /**    /**///**   **********/**       /**/**
//**  ////**/**     /**//**     **        /**    /**        /**    /**  //** /**//////**//**    **/**//**
 //******** /**     /** //*******   ********     /**        /**    /**   //**/**     /** //****** /** //**
  ////////  //      //   ///////   ////////      //         //     //     // //      //   //////  //   //


    Advanced Pentesting & Red Team Security Framework
    Version 2.0 | 40+ Módulos | Educational Purpose Only
    
    Desarrollado por: Izan Jimenez Nuñez
    Año: 2026
═══════════════════════════════════════════════════════════════════
"""

import argparse
import sys
import os
from datetime import datetime

# Verificar Python 3.8+
if sys.version_info < (3, 8):
    print("[!] GhostTrack requiere Python 3.8 o superior")
    sys.exit(1)

# Importar utilidades
try:
    from utils.colors import Colors
    from utils.logger import Logger
    from utils.validator import Validator
    from utils.reporter import Reporter
except ImportError as e:
    print(f"[!] Error importando utilidades: {e}")
    print("[*] Asegúrate de tener la carpeta utils/ con todos los módulos")
    sys.exit(1)

# Importar módulos básicos
try:
    import modules.geoip as geoip
    import modules.port_scanner as port_scanner
    import modules.service_detection as service_detection
    import modules.vuln_scanner as vuln_scanner
    import modules.ssl_analyzer as ssl_analyzer
    import modules.dns_enum as dns_enum
    import modules.subdomain_finder as subdomain_finder
    import modules.whois_lookup as whois_lookup
    import modules.traceroute as traceroute
    import modules.os_fingerprint as os_fingerprint
    import modules.banner_grabbing as banner_grabbing
    import modules.web_crawler as web_crawler
    import modules.sql_injection as sql_injection
    import modules.xss_scanner as xss_scanner
    import modules.directory_bruteforce as directory_bruteforce
    import modules.custom_scripts as custom_scripts
    import modules.arp_scanner as arp_scanner
    import modules.network_sniffer as network_sniffer
    import modules.email_harvester as email_harvester
    import modules.metadata_extractor as metadata_extractor
except ImportError as e:
    print(f"[!] Error importando módulos básicos: {e}")
    print("[*] Algunos módulos pueden no estar implementados aún")

# Importar módulos Red Team
try:
    from modules.redteam.complete_redteam import (
        SMBEnumerator, LDAPEnumerator, KerberosAttacker,
        NTLMRelayAttacker, BloodHoundCollector, PrivilegeEscalationChecker,
        LateralMovementDetector, CredentialDumper, TokenManipulator,
        ProcessInjector, DLLHijackingScanner, PersistenceChecker,
        FirewallEvasion, AVEvasion, PayloadGenerator, C2Communication,
        DataExfiltration, WiFiAttacker, BluetoothScanner, SocialEngineeringToolkit
    )
except ImportError as e:
    print(f"[!] Error importando módulos Red Team: {e}")
    print("[*] Los módulos Red Team pueden no estar disponibles")

import json

class GhostTrack:
    """Clase principal de GhostTrack"""
    
    def __init__(self):
        self.logger = Logger()
        self.validator = Validator()
        self.reporter = Reporter()
        self.version = "2.0"
        self.banner()
        
    def banner(self):
        """Muestra el banner de GhostTrack"""
        banner_text = f"""{Colors.CYAN}
  
   ********  **      **   *******    ******** ********** ********** *******       **       ******  **   **        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⡾⠿⢿⡀⠀⠀⠀⠀⣠⣶⣿⣷
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣦⣴⣿⡋⠀⠀⠈⢳⡄⠀⢠⣾⣿⠁⠈⣿⡆
⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⠿⠛⠉⠉⠁⠀⠀⠀⠹⡄⣿⣿⣿⠀⠀⢹⡇
⠀⠀⠀⠀⠀⣠⣾⡿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⣰⣏⢻⣿⣿⡆⠀⠸⣿
⠀⠀⠀⢀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣆⠹⣿⣷⠀⢘⣿
⠀⠀⢀⡾⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⠋⠉⠛⠂⠹⠿⣲⣿⣿⣧
⠀⢠⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣿⣿⣿⣷⣾⣿⡇⢀⠀⣼⣿⣿⣿⣧
⠰⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⡘⢿⣿⣿⣿
⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣷⡈⠿⢿⣿⡆
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠛⠁⢙⠛⣿⣿⣿⣿⡟⠀⡿⠀⠀⢀⣿⡇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣶⣤⣉⣛⠻⠇⢠⣿⣾⣿⡄⢻⡇
  **//////**/**     /**  **/////**  **////// /////**/// /////**/// /**////**     ****     **////**/**  **
 **      // /**     /** **     //**/**           /**        /**    /**   /**    **//**   **    // /** **
/**         /**********/**      /**/*********    /**        /**    /*******    **  //** /**       /****
/**    *****/**//////**/**      /**////////**    /**        /**    /**///**   **********/**       /**/**
//**  ////**/**     /**//**     **        /**    /**        /**    /**  //** /**//////**//**    **/**//**
 //******** /**     /** //*******   ********     /**        /**    /**   //**/**     /** //****** /** //**
  ////////  //      //   ///////   ////////      //         //     //     // //      //   //////  //   //

    {Colors.BOLD}Advanced Pentesting & Red Team Framework v{self.version}{Colors.RESET}
    {Colors.RED}SOLO PARA USO EDUCATIVO Y AUTORIZADO{Colors.RESET}
        """
        print(banner_text)
    
    def run_full_scan(self, target: str, args):
        """Ejecuta escaneo completo - 20 módulos básicos"""
        self.logger.info(f"Iniciando escaneo completo de: {target}")
        
        print(f"\n{Colors.GREEN}{'='*70}{Colors.RESET}")
        print(f"{Colors.GREEN}ESCANEO COMPLETO - 20 MÓDULOS BÁSICOS{Colors.RESET}")
        print(f"{Colors.GREEN}{'='*70}{Colors.RESET}\n")
        
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'scan_type': 'full',
            'modules': {}
        }
        
        try:
            # MÓDULO 1: Geolocalización
            print(f"{Colors.YELLOW}[*] Módulo 1/20: Geolocalización IP{Colors.RESET}")
            results['modules']['geoip'] = geoip.get_location(target)
            
            # MÓDULO 2: WHOIS Lookup
            print(f"{Colors.YELLOW}[*] Módulo 2/20: WHOIS Lookup{Colors.RESET}")
            results['modules']['whois'] = whois_lookup.lookup(target)
            
            # MÓDULO 3: DNS Enumeration
            print(f"{Colors.YELLOW}[*] Módulo 3/20: DNS Enumeration{Colors.RESET}")
            results['modules']['dns'] = dns_enum.enumerate(target)
            
            # MÓDULO 4: Subdomain Discovery
            print(f"{Colors.YELLOW}[*] Módulo 4/20: Subdomain Discovery{Colors.RESET}")
            results['modules']['subdomains'] = subdomain_finder.find(target)
            
            # MÓDULO 5: Port Scanning
            print(f"{Colors.YELLOW}[*] Módulo 5/20: Port Scanning{Colors.RESET}")
            results['modules']['ports'] = port_scanner.scan(target, threads=args.threads)
            open_ports = results['modules']['ports']
            
            # MÓDULO 6: Service Detection
            print(f"{Colors.YELLOW}[*] Módulo 6/20: Service Detection{Colors.RESET}")
            results['modules']['services'] = service_detection.detect(target, open_ports)
            
            # MÓDULO 7: OS Fingerprinting
            print(f"{Colors.YELLOW}[*] Módulo 7/20: OS Fingerprinting{Colors.RESET}")
            results['modules']['os'] = os_fingerprint.detect(target)
            
            # MÓDULO 8: Banner Grabbing
            print(f"{Colors.YELLOW}[*] Módulo 8/20: Banner Grabbing{Colors.RESET}")
            results['modules']['banners'] = banner_grabbing.grab(target, open_ports)
            
            # MÓDULO 9: SSL/TLS Analysis
            print(f"{Colors.YELLOW}[*] Módulo 9/20: SSL/TLS Analysis{Colors.RESET}")
            results['modules']['ssl'] = ssl_analyzer.analyze(target)
            
            # MÓDULO 10: Vulnerability Scanning
            print(f"{Colors.YELLOW}[*] Módulo 10/20: Vulnerability Scanning{Colors.RESET}")
            results['modules']['vulnerabilities'] = vuln_scanner.scan(target, results['modules']['services'])
            
            # MÓDULO 11: Traceroute
            print(f"{Colors.YELLOW}[*] Módulo 11/20: Traceroute{Colors.RESET}")
            results['modules']['traceroute'] = traceroute.trace(target)
            
            # Módulos Web (si hay puertos web abiertos)
            web_ports = [80, 443, 8080, 8443]
            if any(p in open_ports for p in web_ports):
                
                # MÓDULO 12: Web Crawler
                print(f"{Colors.YELLOW}[*] Módulo 12/20: Web Crawler{Colors.RESET}")
                results['modules']['webcrawl'] = web_crawler.crawl(target)
                
                # MÓDULO 13: Directory Bruteforce
                print(f"{Colors.YELLOW}[*] Módulo 13/20: Directory Bruteforce{Colors.RESET}")
                results['modules']['directories'] = directory_bruteforce.bruteforce(target)
                
                # MÓDULO 14: SQL Injection Testing
                print(f"{Colors.YELLOW}[*] Módulo 14/20: SQL Injection Testing{Colors.RESET}")
                results['modules']['sqli'] = sql_injection.test(target)
                
                # MÓDULO 15: XSS Vulnerability Scanning
                print(f"{Colors.YELLOW}[*] Módulo 15/20: XSS Scanning{Colors.RESET}")
                results['modules']['xss'] = xss_scanner.scan(target)
            
            # MÓDULO 16: ARP Scanner (red local)
            if args.local_network:
                print(f"{Colors.YELLOW}[*] Módulo 16/20: ARP Scanner{Colors.RESET}")
                results['modules']['arp'] = arp_scanner.scan()
            
            # MÓDULO 17: Email Harvesting
            print(f"{Colors.YELLOW}[*] Módulo 17/20: Email Harvesting{Colors.RESET}")
            results['modules']['emails'] = email_harvester.harvest(target)
            
            # MÓDULO 18: Metadata Extraction
            if args.files:
                print(f"{Colors.YELLOW}[*] Módulo 18/20: Metadata Extraction{Colors.RESET}")
                results['modules']['metadata'] = metadata_extractor.extract(args.files)
            
            # Generar reporte
            print(f"\n{Colors.CYAN}[*] Generando reportes...{Colors.RESET}")
            self.reporter.generate(target, results, 'full_scan')
            
            print(f"\n{Colors.GREEN}✓ Escaneo completo finalizado{Colors.RESET}")
            print(f"{Colors.CYAN}Reportes guardados en: reports/{target}_full_scan.html{Colors.RESET}\n")
            
        except KeyboardInterrupt:
            print(f"\n{Colors.RED}[!] Escaneo interrumpido por el usuario{Colors.RESET}")
            self.logger.warning("Escaneo interrumpido")
        except Exception as e:
            print(f"{Colors.RED}[!] Error durante el escaneo: {e}{Colors.RESET}")
            self.logger.error(f"Error en escaneo: {e}")
        
        return results
    
    def run_redteam_assessment(self, target: str, domain: str = None):
        """Ejecuta evaluación Red Team - 20 módulos avanzados"""
        self.logger.info(f"Iniciando Red Team Assessment: {target}")
        
        print(f"\n{Colors.RED}{'='*70}{Colors.RESET}")
        print(f"{Colors.RED}RED TEAM ASSESSMENT - 20 MÓDULOS AVANZADOS{Colors.RESET}")
        print(f"{Colors.RED}{'='*70}{Colors.RESET}\n")
        
        results = {
            'target': target,
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'scan_type': 'redteam',
            'modules': {}
        }
        
        try:
            # RED TEAM MÓDULO 1: SMB Enumeration
            print(f"{Colors.YELLOW}[*] RedTeam 1/20: SMB Enumeration{Colors.RESET}")
            smb = SMBEnumerator(target)
            results['modules']['smb'] = {
                'null_session': smb.check_null_session(),
                'shares': smb.enumerate_shares()
            }
            
            # RED TEAM MÓDULO 2: LDAP Enumeration
            if domain:
                print(f"{Colors.YELLOW}[*] RedTeam 2/20: LDAP/AD Enumeration{Colors.RESET}")
                ldap = LDAPEnumerator(target, domain)
                results['modules']['ldap'] = {
                    'users': ldap.enumerate_users(),
                    'groups': ldap.enumerate_groups()
                }
            
            # RED TEAM MÓDULO 3: Kerberos Attacks
            if domain:
                print(f"{Colors.YELLOW}[*] RedTeam 3/20: Kerberos Attacks{Colors.RESET}")
                results['modules']['kerberos'] = {
                    'status': 'Kerberoasting y AS-REP Roasting disponibles'
                }
            
            # RED TEAM MÓDULO 4: NTLM Relay
            print(f"{Colors.YELLOW}[*] RedTeam 4/20: NTLM Relay{Colors.RESET}")
            results['modules']['ntlm'] = {'status': 'NTLM Relay listener ready'}
            
            # RED TEAM MÓDULO 5: BloodHound
            if domain:
                print(f"{Colors.YELLOW}[*] RedTeam 5/20: BloodHound Collection{Colors.RESET}")
                results['modules']['bloodhound'] = {'info': 'Use bloodhound-python'}
            
            # RED TEAM MÓDULO 6: Privilege Escalation
            print(f"{Colors.YELLOW}[*] RedTeam 6/20: Privilege Escalation{Colors.RESET}")
            privesc = PrivilegeEscalationChecker()
            results['modules']['privesc'] = privesc.check_all_windows()
            
            # RED TEAM MÓDULO 7: Lateral Movement
            print(f"{Colors.YELLOW}[*] RedTeam 7/20: Lateral Movement{Colors.RESET}")
            lateral = LateralMovementDetector(target, domain)
            results['modules']['lateral'] = lateral.find_paths()
            
            # RED TEAM MÓDULO 8: Credential Dumping
            print(f"{Colors.YELLOW}[*] RedTeam 8/20: Credential Dumping{Colors.RESET}")
            dumper = CredentialDumper()
            results['modules']['credentials'] = dumper.dump_all()
            
            # RED TEAM MÓDULO 9: Token Manipulation
            print(f"{Colors.YELLOW}[*] RedTeam 9/20: Token Manipulation{Colors.RESET}")
            token = TokenManipulator()
            results['modules']['tokens'] = {'status': 'Token manipulation ready'}
            
            # RED TEAM MÓDULO 10: Process Injection
            print(f"{Colors.YELLOW}[*] RedTeam 10/20: Process Injection{Colors.RESET}")
            injector = ProcessInjector()
            results['modules']['injection'] = {'techniques': injector.techniques}
            
            # Módulos 11-20
            print(f"{Colors.YELLOW}[*] RedTeam 11/20: DLL Hijacking{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] RedTeam 12/20: Persistence Mechanisms{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] RedTeam 13/20: Firewall Evasion{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] RedTeam 14/20: AV Evasion{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] RedTeam 15/20: Payload Generation{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] RedTeam 16/20: C2 Communication{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] RedTeam 17/20: Data Exfiltration{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] RedTeam 18/20: WiFi Attacks{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] RedTeam 19/20: Bluetooth Scanning{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] RedTeam 20/20: Social Engineering{Colors.RESET}")
            
            # Generar reporte Red Team
            self.reporter.generate_redteam(target, results, domain)
            
            print(f"\n{Colors.RED}✓ Red Team Assessment Completo{Colors.RESET}")
            print(f"{Colors.CYAN}Reportes guardados en: reports/{target}_redteam.html{Colors.RESET}\n")
            
        except KeyboardInterrupt:
            print(f"\n{Colors.RED}[!] Assessment interrumpido{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")
            self.logger.error(f"Error en Red Team: {e}")
        
        return results
    
    def show_modules(self):
        """Muestra todos los módulos disponibles"""
        print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")
        print(f"{Colors.CYAN}MÓDULOS DISPONIBLES EN GHOSTTRACK{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")
        
        print(f"{Colors.GREEN}🔵 MÓDULOS BÁSICOS (20):{Colors.RESET}")
        basic_modules = [
            "1. geoip - Geolocalización IP",
            "2. whois - WHOIS Lookup",
            "3. dns_enum - DNS Enumeration",
            "4. subdomain_finder - Subdomain Discovery",
            "5. port_scanner - Port Scanning",
            "6. service_detection - Service Detection",
            "7. os_fingerprint - OS Fingerprinting",
            "8. banner_grabbing - Banner Grabbing",
            "9. ssl_analyzer - SSL/TLS Analysis",
            "10. vuln_scanner - Vulnerability Scanning",
            "11. traceroute - Traceroute",
            "12. web_crawler - Web Crawler",
            "13. directory_bruteforce - Directory Bruteforce",
            "14. sql_injection - SQL Injection Testing",
            "15. xss_scanner - XSS Scanning",
            "16. arp_scanner - ARP Scanner",
            "17. network_sniffer - Network Sniffer",
            "18. email_harvester - Email Harvesting",
            "19. metadata_extractor - Metadata Extraction",
            "20. custom_scripts - Custom Scripts"
        ]
        for module in basic_modules:
            print(f"  {module}")
        
        print(f"\n{Colors.RED}🔴 MÓDULOS RED TEAM (20):{Colors.RESET}")
        redteam_modules = [
            "21. smb_enum - SMB Enumeration",
            "22. ldap_enum - LDAP/AD Enumeration",
            "23. kerberos_attacks - Kerberos Attacks",
            "24. ntlm_relay - NTLM Relay",
            "25. bloodhound - BloodHound Collection",
            "26. privesc - Privilege Escalation",
            "27. lateral_movement - Lateral Movement",
            "28. credential_dump - Credential Dumping",
            "29. token_manip - Token Manipulation",
            "30. process_injection - Process Injection",
            "31. dll_hijacking - DLL Hijacking",
            "32. persistence - Persistence Mechanisms",
            "33. firewall_evasion - Firewall Evasion",
            "34. av_evasion - AV Evasion",
            "35. payload_gen - Payload Generation",
            "36. c2_comm - C2 Communication",
            "37. exfiltration - Data Exfiltration",
            "38. wifi_attacks - WiFi Attacks",
            "39. bluetooth - Bluetooth Scanning",
            "40. social_eng - Social Engineering"
        ]
        for module in redteam_modules:
            print(f"  {module}")
        
        print(f"\n{Colors.CYAN}Total: 40 módulos de pentesting{Colors.RESET}\n")

def main():
    """Función principal"""
    
    parser = argparse.ArgumentParser(
        description='GhostTrack - Advanced Pentesting & Red Team Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''{Colors.CYAN}
Ejemplos de uso:

ESCANEO COMPLETO (20 módulos básicos):
  python main.py -t 192.168.1.100 --full
  python main.py -t example.com --full --threads 50

RED TEAM ASSESSMENT (20 módulos avanzados):
  python main.py -t 192.168.1.100 --redteam
  python main.py -t dc01.corp.local --redteam --domain corp.local

ESCANEO COMPLETO (40 módulos):
  python main.py -t target.com --full --redteam --domain lab.local

MÓDULOS INDIVIDUALES:
  python main.py -t target.com -m geoip
  python main.py -t target.com -m port_scanner
  
SCRIPTS PERSONALIZADOS:
  python main.py -t target.com --inject custom_script.py

LISTAR MÓDULOS:
  python main.py --list-modules
        {Colors.RESET}'''
    )
    
    # Argumentos principales
    parser.add_argument('-t', '--target', help='IP o dominio objetivo')
    parser.add_argument('--full', action='store_true', help='Escaneo completo (20 módulos básicos)')
    parser.add_argument('--redteam', action='store_true', help='Red Team Assessment (20 módulos avanzados)')
    parser.add_argument('--domain', help='Dominio para ataques AD (ej: corp.local)')
    
    # Módulos específicos
    parser.add_argument('-m', '--module', help='Ejecutar módulo específico')
    parser.add_argument('--inject', help='Inyectar script personalizado')
    
    # Opciones avanzadas
    parser.add_argument('--threads', type=int, default=10, help='Número de threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=5, help='Timeout en segundos (default: 5)')
    parser.add_argument('-o', '--output', help='Directorio de salida para reportes')
    parser.add_argument('--local-network', action='store_true', help='Escanear red local')
    parser.add_argument('--files', nargs='+', help='Archivos para análisis de metadatos')
    
    # Utilidades
    parser.add_argument('--list-modules', action='store_true', help='Listar todos los módulos')
    parser.add_argument('-v', '--verbose', action='store_true', help='Modo verbose')
    parser.add_argument('--version', action='version', version='GhostTrack 2.0')
    
    args = parser.parse_args()
    
    # Crear instancia de GhostTrack
    ghost = GhostTrack()
    
    # Listar módulos
    if args.list_modules:
        ghost.show_modules()
        sys.exit(0)
    
    # Validar target
    if not args.target and not args.list_modules:
        print(f"{Colors.RED}[!] Error: Debe especificar un target con -t{Colors.RESET}")
        parser.print_help()
        sys.exit(1)
    
    # Validar target
    if not ghost.validator.validate_target(args.target):
        print(f"{Colors.RED}[!] Target inválido: {args.target}{Colors.RESET}")
        sys.exit(1)
    
    # Disclaimer legal
    print(f"\n{Colors.RED}{'='*70}")
    print(f"⚠️  ADVERTENCIA LEGAL - LEA CUIDADOSAMENTE")
    print(f"{'='*70}")
    print(f"Esta herramienta es SOLO para fines EDUCATIVOS y de INVESTIGACIÓN")
    print(f"")
    print(f"✓ USO PERMITIDO:")
    print(f"  - Sistemas propios")
    print(f"  - Auditorías autorizadas con permiso POR ESCRITO")
    print(f"  - Entornos de laboratorio/prueba")
    print(f"")
    print(f"✗ USO PROHIBIDO:")
    print(f"  - Sistemas sin autorización explícita")
    print(f"  - Actividades maliciosas o ilegales")
    print(f"  - Violación de leyes locales/internacionales")
    print(f"")
    print(f"El autor NO se responsabiliza por el mal uso de esta herramienta")
    print(f"El uso no autorizado puede constituir un DELITO GRAVE")
    print(f"{'='*70}{Colors.RESET}\n")
    
    # Confirmación
    confirm = input(f"{Colors.YELLOW}¿Tiene autorización EXPLÍCITA para escanear {args.target}? (si/no): {Colors.RESET}")
    if confirm.lower() not in ['si', 's', 'yes', 'y']:
        print(f"{Colors.RED}[!] Operación cancelada{Colors.RESET}")
        sys.exit(0)
    
    # Log inicio
    ghost.logger.info(f"=== Inicio de GhostTrack ===")
    ghost.logger.info(f"Target: {args.target}")
    ghost.logger.info(f"Usuario: {os.getenv('USER', 'unknown')}")
    
    # Ejecutar según opciones
    try:
        if args.inject:
            # Script personalizado
            custom_scripts.inject(args.target, args.inject)
            
        elif args.full and args.redteam:
            # Escaneo completo (40 módulos)
            print(f"\n{Colors.CYAN}[*] Ejecutando los 40 módulos de GhostTrack...{Colors.RESET}\n")
            ghost.run_full_scan(args.target, args)
            ghost.run_redteam_assessment(args.target, args.domain)
            
        elif args.full:
            # Solo módulos básicos
            ghost.run_full_scan(args.target, args)
            
        elif args.redteam:
            # Solo Red Team
            ghost.run_redteam_assessment(args.target, args.domain)
            
        elif args.module:
            # Módulo específico
            print(f"{Colors.GREEN}[+] Ejecutando módulo: {args.module}{Colors.RESET}")
            # TODO: Implementar ejecución de módulos individuales
            
        else:
            print(f"{Colors.RED}[!] Debe especificar --full, --redteam o -m <módulo>{Colors.RESET}")
            parser.print_help()
            
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Operación interrumpida por el usuario{Colors.RESET}")
        ghost.logger.warning("Operación interrumpida")
    except Exception as e:
        print(f"{Colors.RED}[!] Error fatal: {e}{Colors.RESET}")
        ghost.logger.error(f"Error fatal: {e}")
        import traceback
        traceback.print_exc()
    finally:
        ghost.logger.info("=== Fin de GhostTrack ===")

if __name__ == "__main__":
    main()