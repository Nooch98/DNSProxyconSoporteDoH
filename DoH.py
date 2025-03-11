# -----------------------------------------------------------------------------------------#
# ESTE SCRIPT IMPLEMENTA UN SERVIDOR DNS PERSONALIZADO Y CONFIGURABLE CON FUNCIONALIDADES
# COMO PROTECCION CONTRA ATAQUE DDoS, DNS TUNNELING, BLOQUEO DE DOMINIOS, BLOQUEOS DE IP,
# BLOQUEOS DE URLS, USO DE STUNNEL PARA CIFRAR AUN MAS LA CONEXION Y UNA INTERFAZ WEB
# PARA MONITORIZAR EL SERVIDOR CON ESTADISTICAS, LOGS Y LA CONFIGURACION
# AUTOR: Nooch98
# FECHA DE CREACION: 2025-02-21
# ULTIMA MODIFICACION: 2025-03-10
# LICENCIA: MIT
# -----------------------------------------------------------------------------------------#

# IMPORTS
import os
import re
import sys
import json
import time
import base64
import signal
import random
import socket
import shutil
import psutil
import dnslib
import logging
import platform
import requests
import ipaddress
import threading
import subprocess
import dns.dnssec
import dns.message
import dns.resolver
import configparser
import socketserver
import cryptography
import urllib.request
from functools import wraps
from cachetools import TTLCache
from dns.dnssec import validate
from dns.message import from_wire
from urllib.parse import urlparse
from dnslib import DNSRecord, QTYPE
from collections import defaultdict
from socketserver import ThreadingUDPServer
from flask import Flask, render_template, jsonify, request, send_file, send_from_directory, abort

# COLORES
COLOR = {
    "INFO": "\033[94m", "SUCCESS": "\033[92m", "WARNING": "\033[93m", "ERROR": "\033[91m",
    "BOLD": "\033[1m", "UNDERLINE": "\033[4m", "CYAN": "\033[96m", "MAGENTA": "\033[95m",
    "GRAY": "\033[90m", "WHITE": "\033[97m", "BLACK": "\033[30m", "RED": "\033[31m",
    "GREEN": "\033[32m", "YELLOW": "\033[33m", "BLUE": "\033[34m", "PURPLE": "\033[35m",
    "LIGHT_GRAY": "\033[37m", "DARK_GRAY": "\033[90m", "LIGHT_RED": "\033[91m",
    "LIGHT_GREEN": "\033[92m", "LIGHT_YELLOW": "\033[93m", "LIGHT_BLUE": "\033[94m",
    "LIGHT_MAGENTA": "\033[95m", "LIGHT_CYAN": "\033[96m", "BG_BLACK": "\033[40m",
    "BG_RED": "\033[41m", "BG_GREEN": "\033[42m", "BG_YELLOW": "\033[43m",
    "BG_BLUE": "\033[44m", "BG_MAGENTA": "\033[45m", "BG_CYAN": "\033[46m",
    "BG_WHITE": "\033[47m", "RESET": "\033[0m", "BG_GRAY": "\033[48;2;169;169;169m",
    "BG_LIGHT_GRAY": "\033[107m"
}

# VARIABLES GLOBALES
query_count = defaultdict(int)
blocked_domains = set()
blocked_urls_domains = set()
ad_block_domains = set()
connected_ips = set()
threat_domains = set()
success_count = 0
error_count = 0
total_query_time = 0
server_index = 0
dns_cache = TTLCache(maxsize=1000, ttl=3600)
latency_lock = threading.Lock()
server = None
server_thread = None
flask_app_running = True
global_request = []
config = configparser.ConfigParser()

config.read('config.ini')

DOH_SERVERS = config['DNS']['Servers'].split(',')
if not DOH_SERVERS or not DOH_SERVERS[0]:
    DOH_SERVERS = ["https://8.8.8.8/dns-query", "https://1.1.1.1/dns-query"]
server_latencies = {server: float('inf') for server in DOH_SERVERS}
ALLOWED_QTYPES = config['DNS']['AllowedQtypes'].split(',')
IP = config['Server']['IP']
PORT = int(config['Server']['Port'])
RATE_LIMIT = int(config['Security']['RateLimit'])
BLACKLIST_FILE = config['Security']['Blacklist']
BLOCKED_URLS_FILE = "blocked_urls.txt"
THREAT_LIST_URLS = [
    "https://openphish.com/feed.txt",  # Lista de phishing
    "https://www.malwaredomainlist.com/hostslist/hosts.txt",  # Malware
    "https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt"  # Ransomware
]
THREAT_UPDATE_INTERVAL = config.getint('Security', 'ThreatUpdateInterval', fallback=86400)
ALLOWED_NETWORKS = config.get('Security', 'AllowedNetworks', fallback='').split(',')
ALLOWED_NETWORKS = [ipaddress.ip_network(net.strip()) for net in ALLOWED_NETWORKS if net.strip()] if ALLOWED_NETWORKS[0] else []
MAX_RESPONSE_SIZE = config.getint('Security', 'MaxResponseSize', fallback=512)
ENABLE_ANTI_AMPLIFICATION = config.getboolean('Security', 'EnableAntiAmplification', fallback=True)
ENABLE_AD_BLOCKING = config.getboolean('AdBlocking', 'EnableAdBlocking', fallback=False)
AD_BLOCK_LISTS = config.get('AdBlocking', 'AdBlockLists', fallback='https://easylist.to/easylist/easylist.txt').split(',')
AD_BLOCK_UPDATE_INTERVAL = config.getint('AdBlocking', 'UpdateInterval', fallback=86400)
STEALTH_MODE = config.getboolean('Security', 'StealthMode')
BLOCKED_IPS_FILE = "blocked_ips.txt"
ALLOW_PRIVATE_IPS = config.getboolean('Security', 'AllowPrivateIPs', fallback=False)
ENABLE_URL_BLOCKING = config.getboolean('Security', 'EnableURLBlocking', fallback=False)
CLIENT_REQUEST = defaultdict(list)
MAX_REQUEST_PER_SECOND = config.getint('Security', 'MaxRequestPerSecond', fallback=500)
GLOBAL_RATE_LIMIT = config.getint('Security', 'GlobalRateLimit', fallback=5000)
CONTROL_PORT = config.getint('Security', 'ControlPanelConect', fallback=5000)
SUCCESS_LEVEL = 25

logging.addLevelName(SUCCESS_LEVEL, "SUCCESS")
logging.basicConfig(filename=config['Logging']['LogFile'], level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")

# ESTADISTICAS PARA LA INTERFAZ WEB
stats = {
    "total_queries": 0,
    "total_resolved": 0,
    "total_failed": 0,
    "blocked_domains_count": len(blocked_domains),
    "blocked_urls_count": len(blocked_urls_domains),
}

logs = []

# FUNCION LOG PARA MUESTRA DE INFORMACION EN LA TERMINAL
def log(message, level="INFO"):
    global stats, success_count, error_count

    # Actualizar estadísticas
    if "consultas exitosas" in message:
        stats["total_resolved"] += 1
        success_count += 1
    elif "consultas fallidas" in message:
        stats["total_failed"] += 1
        error_count += 1
    stats["total_queries"] += 1
    stats["blocked_domains_count"] = len(blocked_domains)

    # Obtener el timestamp y color según el nivel de log
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    
    # Mapeo de colores según nivel de log
    level_colors = {
        "INFO": COLOR["INFO"],
        "WARNING": COLOR["WARNING"],
        "ERROR": COLOR["ERROR"],
        "SUCCESS": COLOR["SUCCESS"],
        "DEBUG": COLOR["LIGHT_GRAY"],
        "CRITICAL": COLOR["BG_RED"]
    }
    
    # Determinar el color del mensaje
    color = level_colors.get(level.upper(), COLOR["RESET"])
    
    log_entry = f"[{timestamp}] [{level.upper()}] {message}"

    logs.append(log_entry)
    
    # Mostrar el mensaje en la terminal con formato mejorado
    print(f"{color}[{timestamp}] [{level.upper()}] {message}{COLOR['RESET']}")

    # Registrar en el log con el método adecuado según el nivel
    level = level.lower()
    if level == "info":
        logging.info(message)
    elif level == "warning":
        logging.warning(message)
    elif level == "error":
        logging.error(message)
    elif level == "success":
        logging.info(f"SUCCESS: {message}")  # 'SUCCESS' se registra como INFO
    elif level == "debug":
        logging.debug(message)
    elif level == "critical":
        logging.critical(message)

# MENSAJE DE AYUDA
def show_help():
    help_text = f"""
{COLOR['BG_BLUE']}{COLOR['WHITE']}{COLOR['BOLD']}═══════════════════════════════════════════════════════════════════════════════════════{COLOR['RESET']}
          🔹 {COLOR['BOLD']}DNS Proxy con soporte para DoH (DNS over HTTPS) - Guía de Uso 🔹
{COLOR['BG_BLUE']}{COLOR['WHITE']}{COLOR['BOLD']}═══════════════════════════════════════════════════════════════════════════════════════{COLOR['RESET']}

{COLOR['BOLD']}{COLOR['INFO']}📌 Descripción:{COLOR['RESET']}
  {COLOR['CYAN']}Este script actúa como un servidor DNS Proxy que redirige consultas a servidores DoH (DNS sobre HTTPS).{COLOR['RESET']}
  {COLOR['CYAN']}Ofrece mayor privacidad, evita bloqueos de ISP y protege contra amenazas en la red.{COLOR['RESET']}

{COLOR['BOLD']}⚙️ Características principales:{COLOR['RESET']}
  {COLOR['LIGHT_GREEN']}✅ Soporte para múltiples tipos de registros DNS (A, AAAA, CNAME, MX, TXT, etc.).{COLOR['RESET']}
  {COLOR['LIGHT_GREEN']}✅ Validación DNSSEC para mayor seguridad.{COLOR['RESET']}
  {COLOR['LIGHT_GREEN']}✅ Caché local para respuestas más rápidas.{COLOR['RESET']}
  {COLOR['LIGHT_GREEN']}✅ Bloqueo de anuncios y dominios maliciosos.{COLOR['RESET']}
  {COLOR['LIGHT_GREEN']}✅ Protección contra ataques de amplificación DNS.{COLOR['RESET']}
  {COLOR['LIGHT_GREEN']}✅ Registro de actividad en dns_proxy.log.{COLOR['RESET']}
  {COLOR['LIGHT_GREEN']}✅ Configuración dinámica sin necesidad de reinicio.{COLOR['RESET']}

{COLOR['BOLD']}🛠️ Funcionamiento:{COLOR['RESET']}
  {COLOR['INFO']}📡 Recibe consultas DNS en {COLOR['UNDERLINE']}{COLOR['YELLOW']}{IP}:{PORT}{COLOR['RESET']}.
  {COLOR['INFO']}🔄 Convierte las consultas a DoH y valida las respuestas con DNSSEC.{COLOR['RESET']}
  {COLOR['INFO']}⚡ Usa caché local para mejorar el rendimiento.{COLOR['RESET']}
  {COLOR['INFO']}🛑 Bloquea dominios maliciosos y anuncios según listas configuradas.{COLOR['RESET']}
  {COLOR['INFO']}📝 Registra actividad en dns_proxy.log para auditoría y depuración.{COLOR['RESET']}
  {COLOR['INFO']}🔧 Configura automáticamente el DNS en Windows para usar el servidor proxy.{COLOR['RESET']}

{COLOR['BOLD']}🔧 Configuración avanzada:{COLOR['RESET']}
  {COLOR['GRAY']}📄 Edita {COLOR['BOLD']}config.ini{COLOR['RESET']}{COLOR['GRAY']} para personalizar el servidor:{COLOR['RESET']}
  {COLOR['MAGENTA']}🌍 Interfaz de red: {COLOR['BOLD']}[Network] InterfaceName=Ethernet{COLOR['RESET']}
  {COLOR['MAGENTA']}🔗 Servidores DoH: {COLOR['BOLD']}[DNS] Servers=https://1.1.1.1/dns-query,https://8.8.8.8/dns-query{COLOR['RESET']}
  {COLOR['MAGENTA']}📌 Tipos de consultas permitidas: {COLOR['BOLD']}[DNS] AllowedQtypes=A,AAAA,CNAME,MX,TXT,NS,SOA,HTTPS{COLOR['RESET']}
  {COLOR['MAGENTA']}📡 IP y puerto del servidor: {COLOR['BOLD']}[Server] IP=0.0.0.0 Port=53{COLOR['RESET']}
  {COLOR['MAGENTA']}🔒 Seguridad y filtrado: {COLOR['BOLD']}[Security] RateLimit=10 Blacklist=blocked_domains.txt{COLOR['RESET']}
  {COLOR['MAGENTA']}🚫 Bloqueo de URLs: {COLOR['BOLD']}[Security] EnableURLBlocking=True (usa blocked_urls.txt){COLOR['RESET']}
  {COLOR['MAGENTA']}🔄 Anti-amplificación: {COLOR['BOLD']}[Security] MaxResponseSize=512 EnableAntiAmplification=True{COLOR['RESET']}

  {COLOR['WARNING']}⚠️ Si config.ini no existe, se generará automáticamente con valores predeterminados.{COLOR['RESET']}
  {COLOR['WARNING']}⚠️ Para bloqueo por URL, edita blocked_urls.txt con las URLs específicas.{COLOR['RESET']}
  {COLOR['SUCCESS']}✅ Cambios aplicados en tiempo real sin necesidad de reinicio.{COLOR['RESET']}

{COLOR['BOLD']}📝 Comandos disponibles:{COLOR['RESET']}
  {COLOR['INFO']}💡 Iniciar el servidor DNS Proxy:{COLOR['RESET']}  
      {COLOR['BOLD']}{COLOR['CYAN']}python DoH.py{COLOR['RESET']}

  {COLOR['INFO']}ℹ️ Mostrar esta ayuda:{COLOR['RESET']}  
      {COLOR['BOLD']}{COLOR['CYAN']}python DoH.py --help (-h){COLOR['RESET']}

  {COLOR['INFO']}🛠️ Probar la configuración actual:{COLOR['RESET']}  
      {COLOR['BOLD']}{COLOR['CYAN']}python DoH.py --test (-t){COLOR['RESET']}

  {COLOR['INFO']}🧹 Limpiar la caché DNS del navegador:{COLOR['RESET']}  
      {COLOR['BOLD']}{COLOR['CYAN']}python DoH.py --flush-dns (-fd){COLOR['RESET']}

  {COLOR['INFO']}🌐 Listar interfaces de red disponibles:{COLOR['RESET']}  
      {COLOR['BOLD']}{COLOR['CYAN']}python DoH.py --interface (-i){COLOR['RESET']}

{COLOR['BG_BLUE']}{COLOR['WHITE']}{COLOR['BOLD']}═══════════════════════════════════════════════════════════════════════════════════════{COLOR['RESET']}
"""
    print(help_text)
    
def clean_dns_cache_webbrowser_help():
    help_text = f"""
{COLOR['BOLD']}{COLOR['UNDERLINE']}{COLOR['CYAN']}═══════════════════════════════════════════════════════
📌 Instrucciones para limpiar la caché DNS del navegador
═══════════════════════════════════════════════════════{COLOR['RESET']}

{COLOR['BOLD']}{COLOR['BG_BLUE']}{COLOR['WHITE']} 🌐 Google Chrome: {COLOR['RESET']}  
   {COLOR['INFO']}1️⃣ Abre {COLOR['BOLD']}chrome://net-internals/#dns{COLOR['RESET']}{COLOR['INFO']} en la barra de direcciones.  
   2️⃣ Haz clic en {COLOR['BOLD']}'Clear host cache'.{COLOR['RESET']}

{COLOR['BOLD']}{COLOR['BG_MAGENTA']}{COLOR['WHITE']} 🦊 Mozilla Firefox: {COLOR['RESET']}  
   {COLOR['INFO']}1️⃣ Abre {COLOR['BOLD']}about:config{COLOR['RESET']}{COLOR['INFO']}.  
   2️⃣ Busca {COLOR['BOLD']}'network.dnsCacheExpiration'{COLOR['RESET']}{COLOR['INFO']}.  
   3️⃣ Establece un valor bajo (como 1) y reinicia el navegador.{COLOR['RESET']}

{COLOR['BOLD']}{COLOR['BG_CYAN']}{COLOR['BLACK']} 🔵 Microsoft Edge: {COLOR['RESET']}  
   {COLOR['INFO']}1️⃣ Abre {COLOR['BOLD']}edge://net-internals/#dns{COLOR['RESET']}{COLOR['INFO']}.  
   2️⃣ Haz clic en {COLOR['BOLD']}'Clear host cache'.{COLOR['RESET']}

{COLOR['BOLD']}{COLOR['BG_YELLOW']}{COLOR['BLACK']} 💡 Alternativa General: {COLOR['RESET']}  
   {COLOR['SUCCESS']}✔️ Cierra y vuelve a abrir tu navegador.  
   ✔️ Usa una ventana de incógnito para evitar caché persistente.{COLOR['RESET']}

{COLOR['BOLD']}{COLOR['UNDERLINE']}{COLOR['CYAN']}═══════════════════════════════════════════════════════{COLOR['RESET']}
"""
    print(help_text)

def show_update():
    update_text = f"""
{COLOR['BOLD']}{COLOR['UNDERLINE']}{COLOR['RED']}═════════════════════════════════════════════════════════{COLOR['RESET']}
{COLOR['BOLD']}{COLOR['UNDERLINE']}{COLOR['RED']}    🛠️ CAMBIOS Y ARREGLOS DE LA ACTUALIZACION    {COLOR['RESET']}
{COLOR['BOLD']}{COLOR['UNDERLINE']}{COLOR['RED']}═════════════════════════════════════════════════════════{COLOR['RESET']}

{COLOR['INFO']}- Se ha Agregado la funcion Control_server para conectar el panel de control con el servidor.{COLOR['RESET']}

{COLOR['INFO']}- Se ha agregado un panel de control nuevo apartado del servidor la idea es que una vez todo 
mas o menos implementado todo se haga desde la interfaz de panel de control tanto levantar el servidor, pararlo
configurarlo etc etc{COLOR['RESET']}

{COLOR['BOLD']}{COLOR['UNDERLINE']}{COLOR['CYAN']}═════════════════════════════════════════════════════════{COLOR['RESET']}
"""
    print(update_text)

# CONFIGURACION, TEST Y ASISTENCIA A LA CONFIGURACION
def create_default_config():
    config['Network'] = {'InterfaceName': 'Ethernet'}
    config['DNS'] = {
        'Servers': 'https://1.1.1.1/dns-query,https://8.8.8.8/dns-query',
        'AllowedQtypes': 'A,AAAA,CNAME,MX,TXT,NS,SOA,HTTPS'
    }
    config['Server'] = {'IP': '127.0.0.1', 'Port': '53'}
    config['Security'] = {'RateLimit': '10', 'Blacklist': 'blocked_domains.txt', 'StealthMode': 'True', "ThreatUpdateInterval": "86400", 'AllowedNetworks': '', 'MaxResponseSize': '512', 'EnableAntiAmplification': 'True', 'EnableURLBlocking': 'False', 'AllowPrivateIPs': 'False', 'MaxRequestPerSecond': '500', 'GlobalRateLimit': '5000', 'ControlPanelConect': '5001'}
    config['AdBlocking'] = {'EnableAdBlocking': 'False', 'AdBlockLists': 'https://easylist.to/easylist/easylist.txt', 'UpdateInterval': '86400'}
    config['Logging'] = {'LogFile': 'dns_proxy.log'}

    with open('config.ini', 'w') as configfile:
        config.write(configfile)
        
if not os.path.exists('config.ini'):
    create_default_config()

def show_config():
    if not os.path.exists('config.ini'):
        print(f"{COLOR['ERROR']}El archivo config.ini no existe.{COLOR['RESET']}")
        return
    try:
        if not config.read('config.ini'):
            print(f"{COLOR['ERROR']}No se pudo leer el archivo config.ini correctamente.{COLOR['RESET']}")
            return
    except configparser.Error as e:
        print(f"{COLOR['ERROR']}Error al leer config.ini: {e}{COLOR['RESET']}")
        return
    print(f"{COLOR['BOLD']}{COLOR['INFO']}Configuración del script (config.ini):{COLOR['RESET']}")
    for section in config.sections():
        print(f"\n{COLOR['BOLD']}{COLOR['CYAN']}[{section}]{COLOR['RESET']}")
        for key, value in config.items(section):
            print(f"  {COLOR['GREEN']}{key}{COLOR['RESET']}: {COLOR['LIGHT_GRAY']}{value}{COLOR['RESET']}")
    
    print(f"\n{COLOR['BOLD']}{COLOR['SUCCESS']}Configuración mostrada correctamente.{COLOR['RESET']}")
    
def configure_script():
    if os.path.exists('config.ini'):
        config.read('config.ini')
        print(f"{COLOR['INFO']}Configuración cargada desde 'config.ini'.{COLOR['RESET']}")
    else:
        print(f"{COLOR['WARNING']}No se encontró 'config.ini'. Se creará uno nuevo.{COLOR['RESET']}")

    sections = {
        'Network': ['interface_name'],
        'DNS': ['servers', 'allowedqtypes'],
        'Server': ['ip', 'port'],
        'Security': ['ratelimit', 'blacklist', 'stealthmode', 'ThreatUpdateInterval', 'AllowedNetworks', 'MaxResponseSize', 'EnableAntiAmplification', 'AllowPrivateIPs', 'EnableURLBlocking', 'MaxRequestPerSecond', 'GlobalRateLimit'],
        'AdBlocking': ['EnableAdBlocking', 'AdBlockLists', 'UpdateInterval'],
        'Logging': ['logfile']
    }

    for section, keys in sections.items():
        if not config.has_section(section):
            config.add_section(section)

        print(f"\n{COLOR['BOLD']}{COLOR['CYAN']}Configuración de la sección [{section}]:{COLOR['RESET']}")
        
        for key in keys:
            current_value = config.get(section, key, fallback=None)
            if current_value:
                print(f"  {COLOR['GREEN']}Valor actual para {key}: {current_value}{COLOR['RESET']}")
            new_value = input(f"{COLOR['YELLOW']}Ingrese el nuevo valor para '{key}' (deje en blanco para mantener el valor actual): {COLOR['RESET']}")

            if new_value:
                config.set(section, key, new_value)

    with open('config.ini', 'w') as configfile:
        config.write(configfile)

    print(f"\n{COLOR['SUCCESS']}Configuración guardada en 'config.ini'.{COLOR['RESET']}")
    
def show_interfaces():
    available_interfaces = psutil.net_if_addrs().keys()
    print(f"{COLOR['BOLD']}{COLOR['INFO']}Interfaces de red disponibles:{COLOR['RESET']}")

    if available_interfaces:
        for interface in available_interfaces:
            print(f"  {COLOR['CYAN']}- {interface}{COLOR['RESET']}")
    else:
        print(f"{COLOR['YELLOW']}  No se encontraron interfaces de red.{COLOR['RESET']}")

def is_valid_interface(interface_name):
    available_interfaces = psutil.net_if_addrs().keys()
    return interface_name in available_interfaces

def run_tests():
    log(f"{COLOR['INFO']}Verificando configuración...{COLOR['RESET']}", "INFO")

    # 1. Verificar si el archivo config.ini existe
    if not os.path.exists('config.ini'):
        log(f"{COLOR['ERROR']}[❌ ERROR] El archivo config.ini no existe.{COLOR['RESET']}", "ERROR")
        sys.exit(1)

    # 2. Leer el archivo config.ini
    try:
        config.read('config.ini')
    except configparser.Error as e:
        log(f"{COLOR['ERROR']}[❌ ERROR] Error al leer config.ini: {e}{COLOR['RESET']}", "ERROR")
        sys.exit(1)

    # 3. Verificar secciones obligatorias
    required_sections = ['DNS', 'Server', 'Security']
    for section in required_sections:
        if section not in config:
            log(f"{COLOR['ERROR']}[❌ ERROR] Falta la sección obligatoria '{section}' en config.ini.{COLOR['RESET']}", "ERROR")
            sys.exit(1)

    # 4. Validar sección [DNS]
    if 'Servers' not in config['DNS']:
        log(f"{COLOR['ERROR']}[❌ ERROR] Falta clave 'Servers' en sección [DNS].{COLOR['RESET']}", "ERROR")
        sys.exit(1)
    doh_servers = config['DNS']['Servers'].split(',')
    for server in doh_servers:
        parsed_url = urlparse(server.strip())
        if not (parsed_url.scheme in ['http', 'https'] and parsed_url.netloc):
            log(f"{COLOR['ERROR']}[❌ ERROR] URL de servidor DoH inválida: {server}{COLOR['RESET']}", "ERROR")
            sys.exit(1)
    log(f"{COLOR['SUCCESS']}[✅ OK] Servidores DoH configurados válidos: {doh_servers}.{COLOR['RESET']}", "INFO")

    if 'AllowedQtypes' not in config['DNS']:
        log(f"{COLOR['ERROR']}[❌ ERROR] Falta clave 'AllowedQtypes' en sección [DNS].{COLOR['RESET']}", "ERROR")
        sys.exit(1)
    allowed_qtypes = config['DNS']['AllowedQtypes'].split(',')
    valid_qtypes = {'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'HTTPS'}
    for qtype in allowed_qtypes:
        if qtype.strip() not in valid_qtypes:
            log(f"{COLOR['ERROR']}[❌ ERROR] Tipo de consulta inválido en AllowedQtypes: {qtype}{COLOR['RESET']}", "ERROR")
            sys.exit(1)
    log(f"{COLOR['SUCCESS']}[✅ OK] Tipos de consulta válidos: {allowed_qtypes}{COLOR['RESET']}", "INFO")

    # 5. Validar sección [Server]
    if 'IP' not in config['Server']:
        log(f"{COLOR['ERROR']}[❌ ERROR] Falta clave 'IP' en sección [Server].{COLOR['RESET']}", "ERROR")
        sys.exit(1)
    ip = config['Server']['IP']
    if ip != '0.0.0.0' and ip != '::':
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            log(f"{COLOR['ERROR']}[❌ ERROR] Dirección IP inválida: {ip}{COLOR['RESET']}", "ERROR")
            sys.exit(1)
    log(f"{COLOR['SUCCESS']}[✅ OK] IP del servidor válida: {ip}{COLOR['RESET']}", "INFO")

    if 'Port' not in config['Server']:
        log(f"{COLOR['ERROR']}[❌ ERROR] Falta clave 'Port' en sección [Server].{COLOR['RESET']}", "ERROR")
        sys.exit(1)
    try:
        port = int(config['Server']['Port'])
        if not (0 <= port <= 65535):
            raise ValueError("Fuera de rango")
    except ValueError:
        log(f"{COLOR['ERROR']}[❌ ERROR] Puerto inválido: {config['Server']['Port']}{COLOR['RESET']}", "ERROR")
        sys.exit(1)
    log(f"{COLOR['SUCCESS']}[✅ OK] Puerto válido: {port}{COLOR['RESET']}", "INFO")

    # 6. Validar sección [Security]
    if 'RateLimit' not in config['Security']:
        log(f"{COLOR['ERROR']}[❌ ERROR] Falta clave 'RateLimit' en sección [Security].{COLOR['RESET']}", "ERROR")
        sys.exit(1)
    try:
        rate_limit = int(config['Security']['RateLimit'])
        if rate_limit < 0:
            raise ValueError("Negativo")
    except ValueError:
        log(f"{COLOR['ERROR']}[❌ ERROR] RateLimit inválido: {config['Security']['RateLimit']}{COLOR['RESET']}", "ERROR")
        sys.exit(1)
    log(f"{COLOR['SUCCESS']}[✅ OK] RateLimit válido: {rate_limit}{COLOR['RESET']}", "INFO")

    if 'Blacklist' not in config['Security']:
        log(f"{COLOR['ERROR']}[❌ ERROR] Falta clave 'Blacklist' en sección [Security].{COLOR['RESET']}", "ERROR")
        sys.exit(1)
    blacklist_file = config['Security']['Blacklist']
    if not os.path.exists(blacklist_file):
        log(f"{COLOR['WARNING']}[⚠️ WARNING] El archivo de lista negra {blacklist_file} no existe.{COLOR['RESET']}", "WARNING")
    else:
        log(f"{COLOR['SUCCESS']}[✅ OK] Archivo de lista negra encontrado: {blacklist_file}{COLOR['RESET']}", "INFO")

    # 7. Validar opciones booleanas en [Security]
    # StealthMode
    if 'StealthMode' not in config['Security']:
        log(f"{COLOR['ERROR']}[❌ ERROR] Falta clave 'StealthMode' en sección [Security].{COLOR['RESET']}", "ERROR")
        sys.exit(1)
    try:
        stealth_mode = config.getboolean('Security', 'StealthMode')
        log(f"{COLOR['SUCCESS']}[✅ OK] StealthMode configurado como: {stealth_mode}{COLOR['RESET']}", "INFO")
    except ValueError:
        log(f"{COLOR['ERROR']}[❌ ERROR] Valor inválido para StealthMode: {config['Security']['StealthMode']}{COLOR['RESET']}", "ERROR")
        sys.exit(1)

    # AllowPrivateIPs
    if 'AllowPrivateIPs' not in config['Security']:
        log(f"{COLOR['ERROR']}[❌ ERROR] Falta clave 'AllowPrivateIPs' en sección [Security].{COLOR['RESET']}", "ERROR")
        sys.exit(1)
    try:
        allow_private_ips = config.getboolean('Security', 'AllowPrivateIPs')
        log(f"{COLOR['SUCCESS']}[✅ OK] AllowPrivateIPs configurado como: {allow_private_ips}{COLOR['RESET']}", "INFO")
        if allow_private_ips:
            log(f"{COLOR['WARNING']}[⚠️ WARNING] AllowPrivateIPs está habilitado, esto puede permitir DNS Rebinding.{COLOR['RESET']}", "WARNING")
    except ValueError:
        log(f"{COLOR['ERROR']}[❌ ERROR] Valor inválido para AllowPrivateIPs: {config['Security']['AllowPrivateIPs']}{COLOR['RESET']}", "ERROR")
        sys.exit(1)

    # EnableURLBlocking (nueva validación)
    if 'EnableURLBlocking' not in config['Security']:
        log(f"{COLOR['ERROR']}[❌ ERROR] Falta clave 'EnableURLBlocking' en sección [Security].{COLOR['RESET']}", "ERROR")
        sys.exit(1)
    try:
        enable_url_blocking = config.getboolean('Security', 'EnableURLBlocking')
        log(f"{COLOR['SUCCESS']}[✅ OK] EnableURLBlocking configurado como: {enable_url_blocking}{COLOR['RESET']}", "INFO")
        if enable_url_blocking:
            blocked_urls_file = 'blocked_urls.txt'
            if not os.path.exists(blocked_urls_file):
                log(f"{COLOR['WARNING']}[⚠️ WARNING] El archivo de URLs bloqueadas {blocked_urls_file} no existe.{COLOR['RESET']}", "WARNING")
            else:
                log(f"{COLOR['SUCCESS']}[✅ OK] Archivo de URLs bloqueadas encontrado: {blocked_urls_file}{COLOR['RESET']}", "INFO")
    except ValueError:
        log(f"{COLOR['ERROR']}[❌ ERROR] Valor inválido para EnableURLBlocking: {config['Security']['EnableURLBlocking']}{COLOR['RESET']}", "ERROR")
        sys.exit(1)

    # 8. Validar AllowedNetworks (opcional)
    allowed_networks = config.get('Security', 'AllowedNetworks', fallback='').split(',')
    if allowed_networks and allowed_networks[0]:
        for net in allowed_networks:
            try:
                ipaddress.ip_network(net.strip())
            except ValueError:
                log(f"{COLOR['ERROR']}[❌ ERROR] Red inválida en AllowedNetworks: {net}{COLOR['RESET']}", "ERROR")
                sys.exit(1)
        log(f"{COLOR['SUCCESS']}[✅ OK] Redes permitidas válidas: {allowed_networks}{COLOR['RESET']}", "INFO")
    else:
        log(f"{COLOR['WARNING']}[⚠️ WARNING] AllowedNetworks vacío, acceso público permitido.{COLOR['RESET']}", "WARNING")

    # 9. Validar sección [AdBlocking] y EnableAdBlocking
    if 'AdBlocking' in config:
        if 'EnableAdBlocking' not in config['AdBlocking']:
            log(f"{COLOR['ERROR']}[❌ ERROR] Falta clave 'EnableAdBlocking' en sección [AdBlocking].{COLOR['RESET']}", "ERROR")
            sys.exit(1)
        try:
            enable_ad_blocking = config.getboolean('AdBlocking', 'EnableAdBlocking')
            log(f"{COLOR['SUCCESS']}[✅ OK] EnableAdBlocking configurado como: {enable_ad_blocking}{COLOR['RESET']}", "INFO")
        except ValueError:
            log(f"{COLOR['ERROR']}[❌ ERROR] Valor inválido para EnableAdBlocking: {config['AdBlocking']['EnableAdBlocking']}{COLOR['RESET']}", "ERROR")
            sys.exit(1)

        if enable_ad_blocking:
            if 'AdBlockLists' not in config['AdBlocking']:
                log(f"{COLOR['ERROR']}[❌ ERROR] Falta clave 'AdBlockLists' en sección [AdBlocking] cuando EnableAdBlocking es True.{COLOR['RESET']}", "ERROR")
                sys.exit(1)
            adblock_lists = config.get('AdBlocking', 'AdBlockLists', fallback='').split(',')
            for url in adblock_lists:
                parsed_url = urlparse(url.strip())
                if not (parsed_url.scheme in ['http', 'https'] and parsed_url.netloc):
                    log(f"{COLOR['ERROR']}[❌ ERROR] URL de lista de AdBlocking inválida: {url}{COLOR['RESET']}", "ERROR")
                    sys.exit(1)
            log(f"{COLOR['SUCCESS']}[✅ OK] Listas de AdBlocking válidas: {adblock_lists}{COLOR['RESET']}", "INFO")
    else:
        log(f"{COLOR['WARNING']}[⚠️ WARNING] Sección [AdBlocking] no encontrada, asumiendo AdBlocking desactivado.{COLOR['RESET']}", "WARNING")
        
    if 'interface_name' not in config['Network']:
        log(f"{COLOR['ERROR']}[❌ ERROR] Falta clave 'interface_name' en sección [Network].{COLOR['RESET']}", "ERROR")
    else:
        interface_name = config['Network']['interface_name']
        
        if is_valid_interface(interface_name):
            log(f"{COLOR['SUCCESS']}[✅ OK] Nombre de interfaz válido: {interface_name}{COLOR['RESET']}", "INFO")
        else:
            log(f"{COLOR['ERROR']}[❌ ERROR] Nombre de interfaz inválido: {interface_name}{COLOR['RESET']}", "ERROR")
            sys.exit(1)
        
    # 10. Éxito si no hay errores
    log(f"{COLOR['SUCCESS']}Configuración verificada correctamente.{COLOR['RESET']}", "SUCCESS")
    sys.exit(0)

def set_windows_dns(ip, port):
    try:
        interface = config.get('Network', 'interface_name', fallback=None)
        if not interface:
            log("No se especificó una interfaz en config.ini bajo [Network] 'interface_name'.", "ERROR")
            return False
        
        cmd = f"netsh interface ip set dnsservers name=\"{interface}\" source=static {ip} primary"
        subprocess.run(cmd, shell=True, check=True, text=True)
        log(f"DNS de Windows configurado a {ip} en la interfaz '{interface}'.", "SUCCESS")
        return True
    except configparser.NoSectionError:
        log("Falta la sección [Network] en config.ini.", "ERROR")
        return False
    except configparser.NoOptionError:
        log("Falta 'interface_name' en la sección [Network] de config.ini.", "ERROR")
        return False
    except subprocess.CalledProcessError as e:
        log(f"Error al configurar DNS en Windows para la interfaz '{interface}': {e}", "ERROR")
        return False

def reset_windows_dns():
    try:
        interface = config.get('Network', 'interface_name', fallback=None)
        if not interface:
            log("No se especificó una interfaz en config.ini bajo [Network] 'interface_name'.", "ERROR")
            return False
        
        cmd = f"netsh interface ip set dnsservers name=\"{interface}\" source=dhcp"
        subprocess.run(cmd, shell=True, check=True, text=True)
        log(f"DNS de Windows restaurado a automático en la interfaz '{interface}'.", "SUCCESS")
        return True
    except configparser.NoSectionError:
        log("Falta la sección [Network] en config.ini.", "ERROR")
        return False
    except configparser.NoOptionError:
        log("Falta 'interface_name' en la sección [Network] de config.ini.", "ERROR")
        return False
    except subprocess.CalledProcessError as e:
        log(f"Error al restaurar DNS en Windows para la interfaz '{interface}': {e}", "ERROR")
        return False

def reload_config(signal, frame):
    """Recarga la configuración al recibir SIGHUP sin detener el servidor."""
    global DOH_SERVERS, ALLOWED_QTYPES, RATE_LIMIT, blocked_domains
    config.read('config.ini')
    DOH_SERVERS = config['DNS']['Servers'].split(',')
    ALLOWED_QTYPES = config['DNS']['AllowedQtypes'].split(',')
    RATE_LIMIT = int(config['Security']['RateLimit'])
    ENABLE_URL_BLOCKING = config.getboolean('Security', 'EnableURLBlocking', fallback=False)

    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE) as f:
            blocked_domains.clear()
            blocked_domains.update(line.strip() for line in f if line.strip())

    load_blocked_urls()
    log("🔄 Configuración recargada.", "SUCCESS")
  
# FUNCIONES SERVIDOR
def log_connected_ip(ip):
    if ip not in connected_ips:
        connected_ips.add(ip)
        with open('connected_ips.txt', 'a') as f:
            f.write(ip + "\n")
        log(f"[📡 NUEVA CONEXIÓN] IP registrada: {ip}", "INFO")

def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def update_threat_list():
    global threat_domains
    while True:
        try:
            new_threats = set()
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            for url in THREAT_LIST_URLS:
                try:
                    req = urllib.request.Request(url, headers=headers)
                    with urllib.request.urlopen(req) as response:
                        lines = response.read().decode('utf-8').splitlines()
                        for line in lines:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                domain = re.sub(r'^(127\.0\.0\.1|0\.0\.0\.0)\s+', '', line).strip()
                                if domain:
                                    new_threats.add(domain)
                except urllib.error.HTTPError as e:
                    log(f"[❌ THREAT] Error HTTP al obtener {url}: {e}", "ERROR")
                except Exception as e:
                    log(f"[❌ THREAT] Error al procesar {url}: {e}", "ERROR")
            threat_domains = new_threats
            log(f"[🔒 THREAT] Lista de amenazas actualizada: {len(threat_domains)} dominios cargados", "SUCCESS")
        except Exception as e:
            log(f"[❌ THREAT] Error general al actualizar lista de amenazas: {e}", "ERROR")
        time.sleep(THREAT_UPDATE_INTERVAL)

def update_adblock_list():
    global ad_block_domains, ENABLE_AD_BLOCKING, AD_BLOCK_LISTS, AD_BLOCK_UPDATE_INTERVAL
    while True:
        if not ENABLE_AD_BLOCKING:  # Respetar el estado dinámico
            time.sleep(60)  # Dormir si está desactivado, revisando cada minuto
            continue
        
        try:
            new_adblocks = set()
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            for url in AD_BLOCK_LISTS:
                try:
                    req = urllib.request.Request(url, headers=headers)
                    with urllib.request.urlopen(req) as response:
                        lines = response.read().decode("utf-8").splitlines()
                        for line in lines:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                domain = re.sub(r'^(127\.0\.0\.1|0\.0\.0\.0)\s+', '', line).strip()
                                if domain and re.match(r'^[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', domain):
                                    new_adblocks.add(domain)
                except urllib.error.HTTPError as e:
                    log(f"[❌ ADBLOCK] Error HTTP al obtener {url}: {e}", "ERROR")
                except Exception as e:
                    log(f"[❌ ADBLOCK] Error al procesar {url}: {e}", "ERROR")
            ad_block_domains = new_adblocks  # Asignar fuera del bucle
            log(f"[🔒 ADBLOCK] Lista de anuncios/rastreadores actualizada: {len(ad_block_domains)} dominios cargados", "SUCCESS")
        except Exception as e:
            log(f"[❌ ADBLOCK] Error general al actualizar lista de anuncios: {e}", "ERROR")
        time.sleep(AD_BLOCK_UPDATE_INTERVAL)

def load_blocked_urls():
    global blocked_urls_domains
    blocked_urls_domains.clear()
    if os.path.exists(BLOCKED_URLS_FILE):
        with open(BLOCKED_URLS_FILE, 'r') as f:
            for line in f:
                url = line.strip()
                if url:
                    parsed_url = urlparse(url)
                    domain = parsed_url.hostname
                    if domain:
                        blocked_urls_domains.add(domain.lower())
        log(f"[🔒 URL BLOCK] Cargados {len(blocked_urls_domains)} dominios desde {BLOCKED_URLS_FILE}", "SUCCESS")
    else:
        log(f"[⚠️ URL BLOCK] Archivo {BLOCKED_URLS_FILE} no encontrado, creando uno vacío", "WARNING")
        open(BLOCKED_URLS_FILE, 'a').close()
        
def measure_latency(server):
    try:
        start_time = time.time()
        response = requests.get(server, timeout=2)  # Prueba simple con GET
        latency = time.time() - start_time
        with latency_lock:
            server_latencies[server] = latency
    except requests.RequestException:
        with latency_lock:
            server_latencies[server] = float('inf')  # Marca como inalcanzable
            
def update_server_latencies():
    while True:
        for server in DOH_SERVERS:
            threading.Thread(target=measure_latency, args=(server,), daemon=True).start()
        time.sleep(60)

def get_best_doh_server():
    with latency_lock:
        return min(server_latencies, key=server_latencies.get)

def cargar_ips_bloqueadas():
    if os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE) as f:
            return set(f.read().splitlines())
    return set()

def validar_dnssec(dns_response, request, qname):
    try:
        request_message = dns.message.from_wire(request.pack())
        dns.dnssec.validate(dns_response, request_message)
        log(f"[🔒 DNSSEC] Respuesta validada correctamente para {qname}", "SUCCESS")
        return True
    except Exception as e:
        log(f"[⚠️ DNSSEC] Validación fallida para {qname}: {str(e)}", "WARNING")
        return False

def send_doh_request(doh_query, headers, retries=3, delay=2, verify=True):
    global success_count, error_count, total_query_time
    
    for server in DOH_SERVERS:
        for attempt in range(retries):
            try:
                start_time = time.time()
                response = requests.post(server, data=doh_query, headers=headers, timeout=5)
                elapsed_time = time.time() - start_time
                total_query_time += elapsed_time
                server_latencies[server] = elapsed_time
                if response.status_code == 200:
                    success_count += 1
                    log(f"[🔍 DoH] Respuesta exitosa desde {server}", "INFO")
                    return response.content
                else:
                    log(f"[⚠️ DoH] Respuesta no válida desde {server} (código: {response.status_code})", "WARNING")
            except requests.RequestException as e:
                log(f"[❌ DoH] Error al conectar a {server} (intento {attempt + 1}/{retries}): {e}", "ERROR")
                server_latencies[server] = float('inf')
            time.sleep(delay)
        log(f"[❌ DoH] Fallo con {server} tras todos los intentos", "WARNING")
    
    error_count += 1
    log("[❌ DoH] Fallo tras intentar todos los servidores. Posible fuga DNS al ISP.", "ERROR")
    return None

def bloquear_ip(ip):
    blocked_ips.add(ip)
    with open(BLOCKED_IPS_FILE, "a") as f:
        f.write(ip + "\n")
    log(f"[⛔ BLOQUEADO] IP {ip} detectada por posible DNS Tunneling", "WARNING")
    
def is_ddos_attack(client_ip):
    now = time.time()
    CLIENT_REQUEST[client_ip] = [ts for ts in CLIENT_REQUEST[client_ip] if now - ts < 1]
    CLIENT_REQUEST[client_ip].append(now)
    return len(CLIENT_REQUEST[client_ip]) > MAX_REQUEST_PER_SECOND

global_request = []
def is_global_ddos_attack():
    now = time.time()
    global global_request
    global_request = [t for t in global_request if now - t < 1]
    if len(global_request) >= GLOBAL_RATE_LIMIT:
        return True
    global_request.append(now)
    return False

def block_ddos_attack(client_ip):
    if not is_ip_blocked(client_ip, BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, "a") as f:
            f.write(client_ip + "\n")
        log(f"[ DDoS] IP {client_ip} bloqueada por posible ataque DDoS", "WARNING")
    else:
        log(f"[ DDoS] IP {client_ip} ya estaba bloqueada", "INFO")

def is_ip_blocked(client_ip, BLOCKED_IPS_FILE):
    if not os.path.exists(BLOCKED_IPS_FILE):
        return False
    try:
        with open(BLOCKED_IPS_FILE, "r") as f:
            for line in f:
                if line.strip() == client_ip:
                    return True 
        return False
    except FileNotFoundError:
        return False 

def handle_blocked_domain(request, sock):
    # Crear la respuesta para el dominio bloqueado
    reply = request.reply()

    # Redirigir a una página de bloqueo usando un registro A
    # Asegúrate de tener un servidor web en la IP especificada (por ejemplo, 127.0.0.1)
    blocked_ip = "127.0.0.1"  # Cambia esta IP a la dirección donde está tu página de bloqueo
    reply.add_answer(request.q.qname, QTYPE.A, rdata=(blocked_ip,), ttl=300)

    # Simular una respuesta adicional (por ejemplo, un mensaje sobre el motivo del bloqueo)
    blocked_message = "Este dominio ha sido bloqueado por razones de seguridad."
    reply.add_answer(request.q.qname, QTYPE.TXT, rdata=(blocked_message,), ttl=300)

    # Enviar la respuesta al cliente
    try:
        sock.sendto(reply.pack(), request.peer)
        log(f"[🚫 BLOQUEADO] Consulta para {request.q.qname} redirigida a {blocked_ip}", "WARNING")
    except Exception as e:
        log(f"[❌ ERROR] No se pudo enviar respuesta para {request.q.qname}: {e}", "ERROR")
        
def handle_blocked_ip(client_ip):
    try:
        logging.warning(f"[ BLOQUEADO] IP {client_ip} bloqueada")
    except Exception as e:
        logging.error(f"[❌ ERROR] No se pudo enviar respuesta para IP bloqueada: {e}")

class DNSProxy(socketserver.BaseRequestHandler):
    def handle(self):
        client_ip = self.client_address[0]
        query_count[client_ip] += 1
        log_connected_ip(client_ip)
        
        if is_global_ddos_attack():
            log("[🌊💥 DDoS] Límite global excedido", "WARNING")
            block_ddos_attack(client_ip)
        
        if is_ddos_attack(client_ip):
            log(f"[🌊💥 DDoS] Posible ataque detectado desde {client_ip}", "WARNING")
            block_ddos_attack(client_ip)
            return
        
        if ALLOWED_NETWORKS:
            client_ip_obj = ipaddress.ip_address(client_ip)
            if not any(client_ip_obj in net for net in ALLOWED_NETWORKS):
                log(f"[🚫 SEGURIDAD] Consulta rechazada desde IP no autorizada: {client_ip}", "WARNING")
                return
        
        if client_ip in blocked_ips:
            log(f"[⛔ BLOQUEADO] {client_ip} intentó conectarse", "WARNING")
            handle_blocked_ip(client_ip)
            return

        if RATE_LIMIT != 0 and query_count[client_ip] > RATE_LIMIT:
            log(f"[🚫 BLOQUEADO] {client_ip} superó el límite de {RATE_LIMIT} consultas", "WARNING")
            return

        data, sock = self.request
        try:
            request = DNSRecord.parse(data)
        except Exception as e:
            log(f"[❌ ERROR] No se pudo parsear solicitud DNS desde {client_ip}: {e}", "ERROR")
            return
        
        qname = str(request.q.qname).rstrip('.')  # Eliminar el punto final para consistencia
        qtype = QTYPE.get(request.q.qtype, "UNKNOWN")
        
        log(f"[🔍 CONSULTA] {qname} ({qtype}) desde {client_ip}", "INFO")
        
        # Bloqueo por URL
        if ENABLE_URL_BLOCKING and any(qname.endswith(blocked_domain) for blocked_domain in blocked_urls_domains):
            log(f"[🚫 URL BLOCK] Consulta bloqueada para {qname} (URL restringida)")
            reply = request.reply()
            reply.header.rcode = 3  # NXDOMAIN: dominio no existe
            sock.sendto(reply.pack(), self.client_address)
            return
        
        # Bloqueo de anuncios
        if ENABLE_AD_BLOCKING and qname in ad_block_domains:
            log(f"[🚫 ADBLOCK] Consulta bloqueada para {qname} (anuncio/rastreador)", "WARNING")
            reply = request.reply()
            reply.header.rcode = 3  # NXDOMAIN
            response_data = reply.pack()
            try:
                sock.sendto(response_data, self.client_address)
            except Exception as e:
                log(f"[❌ ERROR] Fallo al enviar NXDOMAIN para {qname}: {e}", "ERROR")
            return
        
        # Bloqueo de dominios amenazantes o PTR
        if qtype == 'PTR' or qname in blocked_domains or qname in threat_domains:
            log(f"[🚫 BLOQUEADO] Consulta denegada para {qname} (amenaza detectada)", "WARNING")
            reply = request.reply()
            reply.header.rcode = 3  # NXDOMAIN
            sock.sendto(reply.pack(), self.client_address)
            return
        
        if qname in blocked_domains:
            log(f"[🚫 BLOQUEADO] Dominio {qname} está bloqueado, redirigiendo a la página de bloqueo", "WARNING")
            handle_blocked_domain(request, sock)  # Llamamos a la función que maneja la redirección
            return

        if qtype not in ALLOWED_QTYPES:
            log(f"[🚫 IGNORADO] Tipo {qtype} no permitido para {qname}", "WARNING")
            reply = request.reply()
            reply.header.rcode = 3  # NXDOMAIN
            sock.sendto(reply.pack(), self.client_address)
            return
        
        if qtype == 'TXT' and len(data) > 300:
            bloquear_ip(client_ip)
            return

        cache_key = f"{qname}:{qtype}"
        cached_response = dns_cache.get(cache_key)
        
        if cached_response:
            log(f"[🔍 CACHÉ] {qname} ({qtype}) servido desde caché", "SUCCESS")
            sock.sendto(cached_response, self.client_address)
            return
        
        start_time = time.time()
        log(f"[🔍 CONSULTA] {qname} ({qtype}) de {client_ip}", "INFO")

        doh_query = request.pack()
        headers = {"Accept": "application/dns-message", "Content-Type": "application/dns-message"}
        response = send_doh_request(doh_query, headers, retries=3, verify=True)
        
        if response:
            try:
                dns_response = dns.message.from_wire(response)
                end_time = time.time()
                query_duration = end_time - start_time
                ttl = min(rr.ttl for rr in dns_response.answer) if dns_response.answer else 3600
                
                has_dnssec = any(rr.rdtype in [dns.rdatatype.RRSIG, dns.rdatatype.DNSKEY] for rr in dns_response.answer)
                if has_dnssec:
                    if not validar_dnssec(dns_response, request, qname):
                        log(f"[⚠️ DNSSEC] Rechazando respuesta no válida para {qname}", "WARNING")
                        reply = request.reply()
                        reply.header.rcode = 2  # SERVFAIL
                        sock.sendto(reply.pack(), self.client_address)
                        return
                else:
                    log(f"[ℹ️ DNSSEC] No se encontraron registros DNSSEC para {qname}, omitiendo validación", "INFO")
                
                resolved_ip = None
                if qtype == 'A':
                    for rrset in dns_response.answer:
                        if rrset.rdtype == dns.rdatatype.A:
                            resolved_ip = str(rrset[0].address)
                            break
                elif qtype == 'AAAA':
                    for rrset in dns_response.answer:
                        if rrset.rdtype == dns.rdatatype.AAAA:
                            resolved_ip = str(rrset[0].address)
                            break
                elif qtype == 'HTTPS':
                    for rrset in dns_response.answer:
                        if rrset.rdtype == dns.rdatatype.HTTPS:
                            resolved_ip = "HTTPS Record"
                            break
                if resolved_ip is None:
                    resolved_ip = "No IP"
                    
                response_ip = resolved_ip if resolved_ip else "No IP"
                log(f"[✅ RESPUESTA] {qname} ({qtype}) → Resolución: {response_ip} - Tiempo: {query_duration:.4f}s", "SUCCESS")
                response_data = dns_response.to_wire()
                
                if qtype in ['A', 'AAAA']:
                    for rrset in dns_response.answer:
                        if rrset.rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
                            ip = str(rrset[0].address)
                            if is_private_ip(ip) and not ALLOW_PRIVATE_IPS:
                                log(f"[🚫 SEGURIDAD] Bloqueado DNS Rebinding para {qname} -> {ip}", "WARNING")
                                reply = request.reply()
                                reply.header.rcode = 3  # NXDOMAIN
                                sock.sendto(reply.pack(), self.client_address)
                                return
                
                if ENABLE_ANTI_AMPLIFICATION and len(response_data) > MAX_RESPONSE_SIZE:
                    log(f"[⚠️ SEGURIDAD] Respuesta para {qname} truncada (tamaño: {len(response_data)} > {MAX_RESPONSE_SIZE})", "WARNING")
                    response_data = response_data[:MAX_RESPONSE_SIZE]
                
                dns_cache[cache_key] = response_data
                sock.sendto(response_data, self.client_address)
            except Exception as e:
                log(f"[❌ ERROR] No se pudo parsear respuesta DoH para {qname}: {e}", "ERROR")
                if isinstance(response, bytes) and len(response) > 12:
                    log(f"[⚠️ FALLBACK] Enviando respuesta cruda para {qname}", "WARNING")
                    sock.sendto(response, self.client_address)
                else:
                    reply = request.reply()
                    reply.header.rcode = 2
                    sock.sendto(reply.pack(), self.client_address)
                if response:
                    sock.sendto(response[:MAX_RESPONSE_SIZE] if ENABLE_ANTI_AMPLIFICATION else response, self.client_address)
                else:
                    reply = request.reply()
                    reply.header.rcode = 3  # NXDOMAIN
                    sock.sendto(reply.pack(), self.client_address)
            return

        end_time = time.time()
        query_duration = end_time - start_time
        log(f"[❌ FALLÓ] No se pudo resolver {qname} - Tiempo: {query_duration:.4f}s", "ERROR")
        reply = request.reply()
        reply.header.rcode = 3  # NXDOMAIN
        sock.sendto(reply.pack(), self.client_address)

def iniciar_stunnel():
    # Determinar la ruta del ejecutable según el sistema operativo
    if platform.system() == "Windows":
        # Obtener la ruta de LOCALAPPDATA
        local_app_data = os.environ.get("LOCALAPPDATA")
        stunnel_executable = os.path.join(local_app_data, "Programs", "stunnel", "bin", "stunnel.exe")
    else:
        stunnel_executable = "stunnel"
    
    # Verificar si el ejecutable existe
    if (platform.system() == "Windows" and not os.path.exists(stunnel_executable)) or \
       (platform.system() != "Windows" and shutil.which(stunnel_executable) is None):
        user_input = input(
            "stunnel no está instalado o no se encontró en la ruta estándar.\n"
            "stunnel se utiliza para crear un túnel seguro que ofusque el tráfico DNS y mitigue bloqueos del ISP.\n"
            "¿Desea obtener instrucciones para instalarlo? (s/n): "
        )
        if user_input.lower() in ['s', 'si']:
            print("\nInstrucciones de instalación:")
            if platform.system() == "Windows":
                print("  - Visita https://www.stunnel.org/downloads.html y descarga la versión para Windows.")
                print("  - Instálalo y asegúrate de que se encuentre en '%LOCALAPPDATA%\\Programs\\stunnel\\bin\\stunnel.exe'")
            elif platform.system() == "Linux":
                print("  - En distribuciones basadas en Debian/Ubuntu, ejecuta: sudo apt install stunnel4")
                print("  - En otras distribuciones, usa el gestor de paquetes correspondiente.")
            else:
                print("  - Consulta la documentación de stunnel en https://www.stunnel.org/")
            proceed = input("\n¿Deseas continuar sin stunnel? (s/n): ")
            if proceed.lower() not in ['s', 'si']:
                sys.exit("Por favor, instala stunnel y reinicia el programa.")
            else:
                print("Continuando sin stunnel.")
                return None
        else:
            print("Continuando sin stunnel.")
            return None

    # La ruta del archivo de configuración se toma desde el directorio de la aplicación
    stunnel_config_path = os.path.join(os.path.dirname(__file__), 'stunnel.conf')
    
    try:
        stunnel_proc = subprocess.Popen([stunnel_executable, stunnel_config_path])
        log("stunnel iniciado correctamente.", "SUCCESS")
        time.sleep(2)  # Esperar a que stunnel se inicie
        return stunnel_proc
    except Exception as e:
        log(f"Error al iniciar stunnel: {e}", "ERROR")
        return None

# Servidor de control (socket TCP)
def control_server():
    global server, server_thread
    
    control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    control_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        control_socket.bind(('0.0.0.0', CONTROL_PORT))
        control_socket.listen(1)
        log(f"🔧 Servidor de control escuchando en 0.0.0.0:{CONTROL_PORT}", "INFO")
    except Exception as e:
        log(f"[❌ CONTROL] Error al iniciar servidor de control: {e}", "ERROR")
        return

    while True:
        try:
            client, addr = control_socket.accept()
            log(f"[🔧 CONTROL] Conexión desde {addr}", "INFO")
            data = client.recv(1024).decode('utf-8')
            log(f"[🔧 CONTROL] Comando recibido: {data}", "INFO")
            
            if data == "start":
                if not server:
                    threading.Thread(target=start_dns_server, daemon=True).start()
                    response = "Servidor iniciado"
                else:
                    response = "Servidor ya está corriendo"
            
            elif data == "stop":
                if server:
                    server.shutdown()
                    server.server_close()
                    if server_thread:
                        server_thread.join(timeout=2)
                    server = None
                    server_thread = None
                    response = "Servidor detenido"
                else:
                    response = "Servidor ya está detenido"
            
            elif data == "stats":
                status = "Corriendo" if server else "Detenido"
                stats_data = {
                    "status": status,
                    "queries": sum(query_count.values()),
                    "connected_ips": len(connected_ips),
                    "success_count": success_count,
                    "error_count": error_count,
                    "blocked_domains_count": len(blocked_domains),
                    "total_query_time": total_query_time,  # Añadido para avg_time
                    "logs": logs[-10:],
                    "ip": IP,
                    "port": PORT
                }
                response = json.dumps(stats_data)
            
            elif data == "reload_config":
                reload_config(None, None)
                response = "Configuración recargada"
            
            elif data.startswith("blacklist_add:"):
                domain = data.split(":", 1)[1]
                if domain not in blocked_domains:
                    blocked_domains.add(domain)
                    with open(BLACKLIST_FILE, 'a') as f:
                        f.write(f"{domain}\n")
                    response = f"Dominio {domain} añadido"
                else:
                    response = "Dominio ya está en la lista"
            
            elif data.startswith("blacklist_remove:"):
                domain = data.split(":", 1)[1]
                if domain in blocked_domains:
                    blocked_domains.remove(domain)
                    with open(BLACKLIST_FILE, 'w') as f:
                        f.writelines(f"{d}\n" for d in blocked_domains)
                    response = f"Dominio {domain} eliminado"
                else:
                    response = "Dominio no encontrado"
            
            elif data == "get_blacklist":
                response = json.dumps(list(blocked_domains))
            
            else:
                response = "Comando desconocido"
            
            client.send(response.encode('utf-8'))
        
        except Exception as e:
            log(f"[❌ CONTROL] Error en servidor de control: {e}", "ERROR")
            client.send("Error interno".encode('utf-8'))
        
        finally:
            client.close()
    
def print_stats():
    avg_time = total_query_time / success_count if success_count else 0
    log(f"{COLOR['BOLD']}{COLOR['INFO']}🔹 Estadísticas de rendimiento:{COLOR['RESET']}", "INFO")
    log(f"  {COLOR['GREEN']} - Consultas exitosas:{COLOR['RESET']} {COLOR['CYAN']}{success_count}{COLOR['RESET']}", "INFO")
    log(f"  {COLOR['RED']} - Consultas fallidas:{COLOR['RESET']} {COLOR['MAGENTA']}{error_count}{COLOR['RESET']}", "INFO")
    log(f"  {COLOR['BOLD']}🔹 Consultas totales:{COLOR['RESET']} {COLOR['CYAN']}{stats['total_queries']}{COLOR['RESET']}", "INFO")
    log(f"  {COLOR['YELLOW']} - Tiempo promedio por consulta:{COLOR['RESET']} {COLOR['LIGHT_BLUE']}{avg_time:.4f}s{COLOR['RESET']}", "INFO")
    
def start_dns_server():
    global server, server_thread
    if IP == '0.0.0.0' and not ALLOWED_NETWORKS:
        log("[⚠️ SEGURIDAD] El servidor está escuchando en 0.0.0.0 sin restricciones de red. Considera configurar AllowedNetworks en config.ini para mayor seguridad.", "WARNING")
    server = socketserver.ThreadingUDPServer((IP, PORT), DNSProxy)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    log(f"🔐 Servidor DNS Proxy corriendo en {IP}:{PORT}...", "SUCCESS")

def flush_dns_cache():
    subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True, check=True)
    log("DNS Cache de Windows limpiada.", "INFO")
    
def is_admin():
    import ctypes
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

# SERVIDOR FLASK
app = Flask(__name__, template_folder=os.path.abspath('./'))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Configurar logging
logging.basicConfig(filename=config['Logging']['LogFile'], level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

# Credenciales de autenticación
WEB_USERNAME = config.get('Web', 'Username', fallback='admin')
WEB_PASSWORD = config.get('Web', 'Password', fallback='secret')

# Función de autenticación básica
def check_auth(username, password):
    return username == WEB_USERNAME and password == WEB_PASSWORD

def authenticate():
    return jsonify({"error": "Autenticación requerida"}), 401, {'WWW-Authenticate': 'Basic realm="Login Required"'}

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

@app.route('/restart', methods=['POST'])
@requires_auth
def restart_server():
    global server, server_thread
    try:
        if server:
            server.shutdown()
            server.server_close()
            if server_thread:
                server_thread.join(timeout=2)  # Esperar a que el hilo termine
            log("Servidor DNS detenido para reinicio.", "INFO")
        
        # Reiniciar el servidor en un nuevo hilo
        server = socketserver.ThreadingUDPServer((IP, PORT), DNSProxy)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        
        set_windows_dns(IP, PORT)
        log(f"Servidor DNS reiniciado en {IP}:{PORT}.", "SUCCESS")
        return jsonify({"message": "Servidor reiniciado correctamente"}), 200
    except Exception as e:
        log(f"Error al reiniciar el servidor: {e}", "ERROR")
        return jsonify({"error": f"Error al reiniciar: {str(e)}"}), 500
    
@app.route('/stop', methods=['POST'])
@requires_auth
def stop_server():
    global server, server_thread, flask_app_running
    try:
        if server:
            server.shutdown()
            server.server_close()
            if server_thread:
                server_thread.join(timeout=2)
            log("Servidor DNS detenido.", "INFO")
            
        if stunnel_proc:
            stunnel_proc.terminate()
            log("stunnel detenido.", "INFO")
        
        reset_windows_dns()
        log("Aplicación Flask preparada para detenerse.", "INFO")
        flask_app_running = False  # Señal para detener Flask
        
        # Terminar el proceso completo
        threading.Thread(target=lambda: os._exit(0), daemon=True).start()
        return jsonify({"message": "Servidor y aplicación detenidos"}), 200
    except Exception as e:
        log(f"Error al detener el servidor: {e}", "ERROR")
        return jsonify({"error": f"Error al detener: {str(e)}"}), 500

# Ruta principal
@app.route('/')
@requires_auth
def index():
    return render_template('index.html')

# Ruta para estadísticas
@app.route('/stats')
@requires_auth
def get_stats():
    stats_data = {
        "total_queries": sum(query_count.values()),
        "success_count": success_count,
        "error_count": error_count,
        "avg_time": total_query_time / success_count if success_count else 0,
        "blocked_domains_count": len(blocked_domains),
        "enabled": ENABLE_AD_BLOCKING,
        "blocked_ad_domains": len(ad_block_domains),
        "last_update": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - AD_BLOCK_UPDATE_INTERVAL))
    }
    return jsonify(stats_data)

# Ruta para configuración
@app.route('/config_ini', methods=['GET', 'PATCH'])
def config_json():
    if request.method == 'GET':
        config_data = {key: value for section in config.sections() for key, value in config[section].items()}
        return jsonify(config_data)
    
    elif request.method == 'PATCH':
        data = request.json
        for key, value in data.items():
            for section in config.sections():
                if key in config[section]:
                    config[section][key] = str(value)
        
        with open('config.ini', 'w') as configfile:
            config.write(configfile)
        return jsonify({"message": "Configuración actualizada"}), 200

@app.route('/system_stats')
@requires_auth
def system_stats():
    """Devuelve estadísticas del sistema y latencias de servidores DoH."""
    return jsonify({
        "cpu_usage": psutil.cpu_percent(interval=1),
        "memory_usage": psutil.virtual_memory().percent,
    })


# Ruta para logs
@app.route('/logs')
@requires_auth
def get_logs():
    log_file = 'dns_proxy.log'
    logs = []
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r') as file:
                logs = file.readlines()
            logs = logs[-50:]
        except Exception as e:
            return jsonify({"error": f"Error al leer el archivo de logs: {str(e)}"}), 500
    else:
        return jsonify({"error": "El archivo de logs no existe."}), 404
    return jsonify({'logs': logs})

# Rutas para lista negra
@app.route('/blacklist', methods=['GET'])
@requires_auth
def get_blacklist():
    return jsonify(list(blocked_domains))

@app.route('/blacklist/add', methods=['POST'])
@requires_auth
def add_to_blacklist():
    domain = request.json.get('domain')
    if domain and domain not in blocked_domains:
        blocked_domains.add(domain)
        with open(config['Security']['Blacklist'], 'a') as f:
            f.write(f"{domain}\n")
        log(f"[🔒 BLACKLIST] Dominio {domain} añadido.", "SUCCESS")
        return jsonify({"message": f"{domain} añadido a la lista negra"}), 200
    return jsonify({"error": "Dominio no válido o ya existe"}), 400

@app.route('/blacklist/remove', methods=['POST'])
@requires_auth
def remove_from_blacklist():
    domain = request.json.get('domain')
    if domain in blocked_domains:
        blocked_domains.remove(domain)
        with open(config['Security']['Blacklist'], 'w') as f:
            f.writelines(f"{d}\n" for d in blocked_domains)
        log(f"[🔓 BLACKLIST] Dominio {domain} eliminado.", "SUCCESS")
        return jsonify({"message": f"{domain} eliminado de la lista negra"}), 200
    return jsonify({"error": "Dominio no encontrado"}), 404

@app.route('/blocked_urls', methods=['GET'])
@requires_auth
def get_blocked_urls():
    with open(BLOCKED_URLS_FILE, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
    return jsonify(urls)

@app.route('/blocked_urls/add', methods=['POST'])
@requires_auth
def add_blocked_url():
    url = request.json.get('url')
    if url:
        parsed_url = urlparse(url)
        domain = parsed_url.hostname
        if domain:
            with open(BLOCKED_URLS_FILE, 'a') as f:
                f.write(f"{url}\n")
            blocked_urls_domains.add(domain.lower())
            log(f"[🔒 URL BLOCK] URL {url} añadida (dominio: {domain})", "SUCCESS")
            return jsonify({"message": f"URL {url} añadida"}), 200
    return jsonify({"error": "URL inválida"}), 400

@app.route('/blocked_urls/remove', methods=['POST'])
@requires_auth
def remove_blocked_url():
    url = request.json.get('url')
    if url:
        parsed_url = urlparse(url)
        domain = parsed_url.hostname
        if domain and domain.lower() in blocked_urls_domains:
            blocked_urls_domains.remove(domain.lower())
            with open(BLOCKED_URLS_FILE, 'r') as f:
                urls = [line.strip() for line in f if line.strip() != url]
            with open(BLOCKED_URLS_FILE, 'w') as f:
                f.writelines(f"{u}\n" for u in urls)
            log(f"[🔓 URL BLOCK] URL {url} eliminada (dominio: {domain})", "SUCCESS")
            return jsonify({"message": f"URL {url} eliminada"}), 200
    return jsonify({"error": "URL no encontrada"}), 404

@app.route('/config_ini', methods=['PATCH'])
@requires_auth
def update_config():
    global config
    data = request.json
    for key, value in data.items():
        if key in ['doh_servers', 'allowed_qtypes']:
            config['DNS'][key.replace('_', '')] = ','.join(value) if isinstance(value, list) else value
        elif key in ['server_ip', 'server_port']:
            config['Server'][key.replace('server_', '').capitalize()] = str(value)
        elif key == 'rate_limit':
            config['Security']['RateLimit'] = str(value)
        elif key == 'blacklist_file':
            config['Security']['Blacklist'] = value
    
    with open('config.ini', 'w') as configfile:
        config.write(configfile)

    return jsonify({"message": "Configuración guardada, pero no aplicada aún"}), 200

@app.route('/apply_config', methods=['POST'])
@requires_auth
def apply_config():
    reload_config(None, None)  # Recarga la configuración manualmente
    return jsonify({"message": "Configuración aplicada correctamente"}), 200

@app.route('/threat_stats', methods=['GET'])
@requires_auth
def get_threat_stats():
    return jsonify({
        "blocked_threats": len(threat_domains),
        "last_update": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - THREAT_UPDATE_INTERVAL))
    })

dns_servers = config.get('DNS', 'servers', fallback='').split(',')
@app.route('/dns_leak_test', methods=['GET'])
@requires_auth
def dns_leak_test():
    try:
        # Lista de servidores DoH configurados
        dns_servers = [
            {"url": "https://8.8.8.8/dns-query", "type": "google"},
            {"url": "https://1.1.1.1/dns-query", "type": "cloudflare"},
            {"url": "https://9.9.9.9/dns-query", "type": "quad9"}
        ]
        
        # Dominio de prueba
        domain = "example.com"
        
        # Construir la consulta DNS utilizando dnspython
        query = dns.message.make_query(domain, dns.rdatatype.A)
        query_bytes = query.to_wire()  # Convertir la consulta en bytes (binario)
        
        # Resultados
        results = []

        for server in dns_servers:
            try:
                # Determinar el tipo de contenido según el servidor
                headers = {"Content-Type": "application/dns-message"}
                payload = query_bytes  # Enviar la consulta como un paquete binario

                # Realizar la consulta DNS usando POST
                response = requests.post(server['url'], data=payload, headers=headers)

                # Verificar el código de estado
                if response.status_code == 200:
                    try:
                        # Intentar interpretar la respuesta como un mensaje DNS
                        data = response.content
                        
                        # Convertir la respuesta a un formato legible (hexadecimal dividido en líneas)
                        hex_response = data.hex()
                        formatted_response = "\n".join([hex_response[i:i+64] for i in range(0, len(hex_response), 64)])  # Dividir en líneas de 64 caracteres
                        
                        results.append({
                            'server': server['url'],
                            'response': formatted_response  # Respuesta legible
                        })
                    except ValueError:
                        results.append({
                            'server': server['url'],
                            'error': 'Respuesta no es un formato válido.'
                        })
                elif response.status_code == 400:
                    results.append({
                        'server': server['url'],
                        'error': f"Error 400 - Solicitud incorrecta: El formato de la consulta puede ser inválido."
                    })
                elif response.status_code == 415:
                    results.append({
                        'server': server['url'],
                        'error': f"Error 415 - Tipo de medio no soportado: Verifica el tipo de contenido de la solicitud."
                    })
                else:
                    results.append({
                        'server': server['url'],
                        'error': f"Error en la consulta DNS, código de estado: {response.status_code}"
                    })

            except requests.exceptions.RequestException as e:
                results.append({
                    'server': server['url'],
                    'error': f"Error en la solicitud: {str(e)}"
                })

        return jsonify({
            "message": "Prueba de fuga DNS realizada con los servidores configurados.",
            "configured_servers": [server['url'] for server in dns_servers],
            "results": results,
            "recommendation": "Si observas que la respuesta proviene de un servidor no deseado, puede haber una fuga de DNS."
        })
    
    except Exception as e:
        return jsonify({"error": f"Error al generar prueba: {str(e)}"}), 500
    
@app.route('/docs')
def serve_docs():
    return send_file(os.path.join(BASE_DIR, "docs.html"))

@app.route('/<path:filename>')
def serve_files(filename):
    file_path = os.path.join(BASE_DIR, filename)

    if not os.path.exists(file_path):  # Si el archivo no existe, devuelve un error 404
        abort(404, description="Archivo no encontrado")

    return send_from_directory(BASE_DIR, filename)

# Función para iniciar Flask
def run_flask():
    while flask_app_running:
        app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)
        if not flask_app_running:
            break

if __name__ == "__main__":
    if "--help" in sys.argv or "-h" in sys.argv:
        show_help()
        sys.exit(0)
    
    if "--test" in sys.argv or "-t" in sys.argv:
        run_tests()
        sys.exit(0)
    
    if "--flush-dns" in sys.argv or "-f" in sys.argv:
        clean_dns_cache_webbrowser_help()
        sys.exit(0)
        
    if "--interface" in sys.argv or "-i" in sys.argv:
        show_interfaces()
        sys.exit(0)
        
    if "--show-config" in sys.argv or "-sc" in sys.argv:
        show_config()
        sys.exit(0)
        
    if "--config" in sys.argv or "-c" in sys.argv:
        configure_script()
        sys.exit(0)
        
    if "--updates" in sys.argv or "-u" in sys.argv:
        show_update()
        sys.exit(0)
    
    if "--start" in sys.argv or "-s" in sys.argv:
        if not is_admin():
            print(f"{COLOR['ERROR']}Para modificar la configuración DNS de Windows, se necesitan privilegios de administrador. Por favor, ejecute el script como administrador.{COLOR['RESET']}")
        log("Iniciando servidor DNS...", "INFO")
        
        if ENABLE_AD_BLOCKING:
            threading.Thread(target=update_adblock_list, daemon=True).start()
        
        load_blocked_urls()
        
        threading.Thread(target=update_server_latencies, daemon=True).start()
        
        blocked_ips = cargar_ips_bloqueadas()
        
        # Iniciar Flask en un hilo separado
        flask_thread = threading.Thread(target=run_flask)
        flask_thread.daemon = True
        flask_thread.start()
        
        # Verificar si el sistema operativo soporta SIGHUP antes de intentar registrar la señal
        if platform.system() != "Windows":
            signal.signal(signal.SIGHUP, reload_config)
        else:
            log("[⚠️ ERROR] SIGHUP no disponible en este sistema.", "ERROR")
    
        flush_dns_cache()
        stunnel_proc = iniciar_stunnel()
        
        if set_windows_dns(IP, PORT):
            log(f"Proxy DNS configurado en {IP}:{PORT} y DNS de Windows actualizado.", "SUCCESS")
        else:
            log("No se pudo configurar el DNS de Windows. Continuando sin cambios.", "WARNING")
            
        start_dns_server()
        
        threading.Thread(target=control_server, daemon=True).start()  # Iniciar servidor de control
        threading.Thread(target=update_threat_list, daemon=True).start()

        try:
            while flask_app_running:
                time.sleep(1)
        except KeyboardInterrupt:
            log("🔴 Servidor detenido por el usuario.", "INFO")
            print_stats()
            if server:
                server.shutdown()
                server.server_close()
                server_thread.join(timeout=2)
            if stunnel_proc:
                stunnel_proc.terminate()
                log("stunnel detenido", "INFO")
            reset_windows_dns()
        finally:
            if stunnel_proc:
                stunnel_proc.terminate()
                log("stunnel detenido", "INFO")
            reset_windows_dns()
