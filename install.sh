#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# GhostTrack — Script de instalación automática para Kali Linux
# Uso: chmod +x install.sh && sudo bash install.sh
# ═══════════════════════════════════════════════════════════════════

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════╗"
echo "║         GhostTrack — Instalador Automático       ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Verificar que se ejecuta en Linux ──────────────────────────────
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo -e "${RED}[!] Este script es para Linux/Kali. En Windows usa install_windows.bat${NC}"
    exit 1
fi

echo -e "${YELLOW}[*] Paso 1: Actualizando repositorios apt...${NC}"
sudo apt-get update -qq

echo -e "${YELLOW}[*] Paso 2: Instalando dependencias del sistema...${NC}"
sudo apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    libxml2-dev \
    libxslt1-dev \
    libssl-dev \
    libffi-dev \
    build-essential \
    aircrack-ng \
    bluez \
    bluetooth \
    nmap \
    net-tools \
    curl \
    wget 2>/dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] Dependencias del sistema instaladas correctamente${NC}"
else
    echo -e "${RED}[!] Error instalando dependencias del sistema${NC}"
fi

echo -e "${YELLOW}[*] Paso 3: Creando entorno virtual Python...${NC}"
python3 -m venv ghosttrack_env

if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Error creando entorno virtual${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Entorno virtual creado: ghosttrack_env/${NC}"

echo -e "${YELLOW}[*] Paso 4: Activando entorno virtual...${NC}"
source ghosttrack_env/bin/activate

echo -e "${YELLOW}[*] Paso 5: Actualizando pip...${NC}"
pip install --upgrade pip --quiet

echo -e "${YELLOW}[*] Paso 6: Instalando dependencias Python...${NC}"
echo ""

# Instalar una por una para mostrar progreso y manejar errores
PACKAGES=(
    "requests>=2.31.0"
    "beautifulsoup4>=4.12.2"
    "lxml>=5.1.0"
    "dnspython>=2.4.2"
    "cryptography>=42.0.0"
    "pyOpenSSL>=24.0.0"
    "Pillow>=10.2.0"
    "pypdf>=4.0.0"
    "Jinja2>=3.1.2"
    "colorama>=0.4.6"
    "tqdm>=4.66.1"
    "python-dotenv>=1.0.0"
    "click>=8.1.7"
    "impacket>=0.12.0"
    "ldap3>=2.9.1"
    "pycryptodome>=3.20.0"
    "scapy>=2.5.0"
    "pytest>=7.4.3"
    "pytest-cov>=4.1.0"
)

FAILED=()

for package in "${PACKAGES[@]}"; do
    echo -ne "  Instalando ${package}... "
    pip install "$package" --quiet 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗ ERROR${NC}"
        FAILED+=("$package")
    fi
done

echo ""

# ── Resumen de instalación ─────────────────────────────────────────
if [ ${#FAILED[@]} -eq 0 ]; then
    echo -e "${GREEN}[+] Todos los paquetes instalados correctamente${NC}"
else
    echo -e "${YELLOW}[!] Los siguientes paquetes fallaron:${NC}"
    for pkg in "${FAILED[@]}"; do
        echo -e "    ${RED}✗ $pkg${NC}"
    done
    echo ""
    echo -e "${YELLOW}[*] Intentando instalar los fallidos con --no-binary...${NC}"
    for pkg in "${FAILED[@]}"; do
        pip install "$pkg" --no-binary :all: --quiet 2>/dev/null && \
            echo -e "    ${GREEN}✓ $pkg instalado${NC}" || \
            echo -e "    ${RED}✗ $pkg sigue fallando — instala manualmente${NC}"
    done
fi

echo ""
echo -e "${YELLOW}[*] Paso 7: Verificando instalación...${NC}"
echo ""

python3 -c "
import sys
packages = [
    ('requests',      'requests'),
    ('bs4',           'beautifulsoup4'),
    ('lxml',          'lxml'),
    ('dns',           'dnspython'),
    ('cryptography',  'cryptography'),
    ('OpenSSL',       'pyOpenSSL'),
    ('PIL',           'Pillow'),
    ('pypdf',         'pypdf'),
    ('jinja2',        'Jinja2'),
    ('colorama',      'colorama'),
    ('tqdm',          'tqdm'),
    ('dotenv',        'python-dotenv'),
    ('click',         'click'),
    ('impacket',      'impacket'),
    ('ldap3',         'ldap3'),
    ('Crypto',        'pycryptodome'),
    ('scapy',         'scapy'),
]
ok = 0
fail = 0
for mod, pkg in packages:
    try:
        __import__(mod)
        print(f'  \033[92m✓\033[0m {pkg}')
        ok += 1
    except ImportError:
        print(f'  \033[91m✗\033[0m {pkg} — pip install {pkg}')
        fail += 1
print()
print(f'  Resultado: {ok} instalados, {fail} fallidos')
sys.exit(0 if fail == 0 else 1)
"

echo ""
echo -e "${YELLOW}[*] Paso 8: Verificando herramientas del sistema...${NC}"
TOOLS=("aircrack-ng" "airodump-ng" "aireplay-ng" "hcitool" "bluetoothctl" "nmap")
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $tool"
    else
        echo -e "  ${RED}✗${NC} $tool — sudo apt-get install ${tool%%-*}"
    fi
done

echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                  INSTALACIÓN COMPLETA                  ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Para usar GhostTrack:${NC}"
echo ""
echo -e "  ${YELLOW}# Activar entorno virtual (cada vez que abras terminal):${NC}"
echo -e "  source ghosttrack_env/bin/activate"
echo ""
echo -e "  ${YELLOW}# Escaneo básico:${NC}"
echo -e "  python main.py -t objetivo.com --full"
echo ""
echo -e "  ${YELLOW}# Escaneo Red Team (requiere root):${NC}"
echo -e "  sudo python main.py -t 192.168.1.1 --redteam"
echo ""
echo -e "  ${YELLOW}# Desactivar entorno virtual cuando termines:${NC}"
echo -e "  deactivate"
echo ""
