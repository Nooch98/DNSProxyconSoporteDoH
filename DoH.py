import requests
import socketserver
import logging
import time
import sys
import os
import re
import platform
import psutil
import signal
import configparser
import threading
import socket
import shutil
import subprocess
import urllib.request
from flask import Flask, render_template, jsonify, request
from functools import wraps
from socketserver import ThreadingUDPServer
from collections import defaultdict
from dnslib import DNSRecord, QTYPE
from cachetools import TTLCache
from dns.dnssec import validate

# 🎨 Colores para la salida en terminal
COLOR = {
    "INFO": "\033[94m", "SUCCESS": "\033[92m", "WARNING": "\033[93m",
    "ERROR": "\033[91m", "BOLD": "\033[1m", "UNDERLINE": "\033[4m",
    "CYAN": "\033[96m", "MAGENTA": "\033[95m", "GRAY": "\033[90m", "RESET": "\033[0m"
}

# Variables globales
query_count = defaultdict(int)  # Contador de consultas por IP
blocked_domains = set()  # Lista negra de dominios
success_count = 0
error_count = 0
total_query_time = 0
server_index = 0
dns_cache = TTLCache(maxsize=1000, ttl=3600)
config = configparser.ConfigParser()

# Estadísticas para la interfaz web
stats = {
    "total_queries": 0,
    "total_resolved": 0,
    "total_failed": 0,
    "blocked_domains_count": len(blocked_domains),
}

def show_help():
    help_text = f"""
{COLOR['SUCCESS']}═══════════════════════════════════════════════════════════════════════════════════════
          🔹 {COLOR['BOLD']}DNS Proxy con soporte para DoH (DNS over HTTPS) - Guía de Uso 🔹{COLOR['RESET']}{COLOR['SUCCESS']}
═══════════════════════════════════════════════════════════════════════════════════════{COLOR['RESET']}

{COLOR['BOLD']}{COLOR['INFO']}📌 ¿Qué hace este script?{COLOR['RESET']}
  - {COLOR['CYAN']}Este servidor DNS Proxy intercepta consultas DNS y las redirige a servidores DoH (DNS sobre HTTPS).{COLOR['RESET']}
  - {COLOR['CYAN']}El objetivo es mejorar la privacidad y evitar bloqueos de los ISP.{COLOR['RESET']}

{COLOR['BOLD']}🛠️ ¿Cómo funciona?{COLOR['RESET']}
  {COLOR['INFO']}✔ Recibe consultas DNS en {COLOR['UNDERLINE']}{IP}:{PORT}{COLOR['RESET']}.
  {COLOR['INFO']}✔ Convierte las consultas a DNS sobre HTTPS (DoH).
  {COLOR['INFO']}✔ Envía las consultas a los servidores DoH configurados en config.ini.
  {COLOR['INFO']}✔ Responde con la IP resuelta al cliente que hizo la consulta.

{COLOR['BOLD']}🔧 Configuración:{COLOR['RESET']}
  {COLOR['GRAY']}🛠️ Para personalizar el servidor, edita el archivo {COLOR['BOLD']}config.ini{COLOR['RESET']}{COLOR['GRAY']}:{COLOR['RESET']}
    - Servidores DoH → [DNS] Servers=https://dns.google/dns-query,https://cloudflare-dns.com/dns-query
    - Tipos de consultas permitidos → [DNS] AllowedQtypes=A,AAAA,CNAME,MX,TXT,NS,SOA,HTTPS
    - IP y puerto del proxy → [Server] IP=127.0.0.1  Port=53
  {COLOR['WARNING']}⚠️ Si no existe config.ini, se genera automáticamente con valores predeterminados.{COLOR['RESET']}

{COLOR['BOLD']}📊 Características:{COLOR['RESET']}
  {COLOR['MAGENTA']}✅ Soporta consultas A, AAAA, CNAME, MX, TXT, NS, SOA, HTTPS.{COLOR['RESET']}
  {COLOR['MAGENTA']}✅ Registro detallado de logs en dns_proxy.log.{COLOR['RESET']}
  {COLOR['MAGENTA']}✅ Intentos de reenvío automáticos en caso de fallo.{COLOR['RESET']}
  {COLOR['MAGENTA']}✅ Protección contra consultas DNS maliciosas o bloqueadas.{COLOR['RESET']}

{COLOR['BOLD']}📝 Comandos disponibles:{COLOR['RESET']}
  {COLOR['INFO']}💡 Iniciar el servidor DNS Proxy:{COLOR['RESET']}  
      {COLOR['BOLD']}{COLOR['CYAN']}python script.py{COLOR['RESET']}
  
  {COLOR['INFO']}ℹ️ Mostrar esta ayuda:{COLOR['RESET']}  
      {COLOR['BOLD']}{COLOR['CYAN']}python script.py --help{COLOR['RESET']}

{COLOR['SUCCESS']}═══════════════════════════════════════════════════════════════════════════════════════{COLOR['RESET']}
"""
    print(help_text)


def create_default_config():
    config['DNS'] = {
        'Servers': 'https://1.1.1.1/dns-query,https://8.8.8.8/dns-query',
        'AllowedQtypes': 'A,AAAA,CNAME,MX,TXT,NS,SOA,HTTPS'
    }
    config['Server'] = {'IP': '127.0.0.1', 'Port': '53'}
    config['Security'] = {'RateLimit': '10', 'Blacklist': 'blocked_domains.txt', 'StealthMode': 'True', "ThreatUpdateInterval": "86400"}
    config['Logging'] = {'LogFile': 'dns_proxy.log'}
    config['Web'] = {'Username': 'admin', 'Password': 'secret'}

    with open('config.ini', 'w') as configfile:
        config.write(configfile)


if not os.path.exists('config.ini'):
    create_default_config()

config.read('config.ini')

DOH_SERVERS = config['DNS']['Servers'].split(',')
if not DOH_SERVERS or not DOH_SERVERS[0]:
    DOH_SERVERS = ["https://8.8.8.8/dns-query", "https://1.1.1.1/dns-query"]
ALLOWED_QTYPES = config['DNS']['AllowedQtypes'].split(',')
IP = config['Server']['IP']
PORT = int(config['Server']['Port'])
RATE_LIMIT = int(config['Security']['RateLimit'])
BLACKLIST_FILE = config['Security']['Blacklist']
THREAT_LIST_URLS = [
    "https://openphish.com/feed.txt",  # Lista de phishing
    "https://www.malwaredomainlist.com/hostslist/hosts.txt",  # Malware
    "https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt"  # Ransomware
]
THREAT_UPDATE_INTERVAL = config.getint('Security', 'ThreatUpdateInterval', fallback=86400)  # 24 horas en segundos
threat_domains = set()

if os.path.exists(BLACKLIST_FILE):
    with open(BLACKLIST_FILE) as f:
        blocked_domains.update(line.strip() for line in f if line.strip())
        
SUCCESS_LEVEL = 25
logging.addLevelName(SUCCESS_LEVEL, "SUCCESS")
logging.basicConfig(filename=config['Logging']['LogFile'], level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")


STEALTH_MODE = config.getboolean('Security', 'StealthMode')
BLOCKED_IPS_FILE = "blocked_ips.txt"
server_latencies = {server: float('inf') for server in DOH_SERVERS}
latency_lock = threading.Lock()
server = None
server_thread = None
flask_app_running = True

def get_active_interface():
    """Obtiene el nombre de la interfaz de red activa en Windows."""
    try:
        output = subprocess.check_output("netsh interface show interface", shell=True, text=True)
        for line in output.splitlines()[2:]:  # Saltar encabezados
            if "Connected" in line:
                match = re.search(r"\s+(\S+)$", line)
                if match:
                    return match.group(1)
        return None
    except subprocess.CalledProcessError as e:
        log(f"Error al obtener interfaz activa: {e}", "ERROR")
        return None

def update_threat_list():
    global threat_domains
    while True:
        try:
            new_threats = set()
            for url in THREAT_LIST_URLS:
                with urllib.request.urlopen(url) as response:
                    lines = response.read().decode('utf-8').splitlines()
                    for line in lines:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Extraer dominio (ignorar prefijos como "127.0.0.1" en algunas listas)
                            domain = re.sub(r'^(127\.0\.0\.1|0\.0\.0\.0)\s+', '', line).strip()
                            if domain:
                                new_threats.add(domain)
            threat_domains = new_threats
            log(f"[🔒 THREAT] Lista de amenazas actualizada: {len(threat_domains)} dominios cargados", "SUCCESS")
        except Exception as e:
            log(f"[❌ THREAT] Error al actualizar lista de amenazas: {e}", "ERROR")
        time.sleep(THREAT_UPDATE_INTERVAL)

threading.Thread(target=update_threat_list, daemon=True).start()

def set_windows_dns(ip, port):
    interface = get_active_interface()
    if not interface:
        log("No se pudo determinar la interfaz de red activa.", "ERROR")
        return False
    
    try:
        cmd = f"netsh interface ip set dns name=\"{interface}\" source=static addr={ip}"
        subprocess.run(cmd, shell=True, check=True, text=True)
        log(f"DNS de Windows configurado a {ip} en la interfaz '{interface}'.", "SUCCESS")
        return True
    except subprocess.CalledProcessError as e:
        log(f"Error al configurar DNS en Windows: {e}", "ERROR")
        return False
    
def reset_windows_dns():
    interface = get_active_interface()
    if not interface:
        log("No se pudo determinar la interfaz de red activa.", "ERROR")
        return False
    
    try:
        cmd = f"netsh interface ip set dns name=\"{interface}\" source=dhcp"
        subprocess.run(cmd, shell=True, check=True, text=True)
        log(f"DNS de Windows restaurado a automático en la interfaz '{interface}'.", "SUCCESS")
        return True
    except subprocess.CalledProcessError as e:
        log(f"Error al restaurar DNS en Windows: {e}", "ERROR")
        return False

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

threading.Thread(target=update_server_latencies, daemon=True).start()

def get_best_doh_server():
    with latency_lock:
        return min(server_latencies, key=server_latencies.get)

def log(message, level="INFO"):
    global stats

    # Actualizar estadísticas
    if "consultas exitosas" in message:
        stats["total_resolved"] += 1
    elif "consultas fallidas" in message:
        stats["total_failed"] += 1
    stats["total_queries"] += 1
    
    # Obtener el timestamp y color según el nivel de log
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    color = COLOR[level] if level in COLOR else ""
    
    # Mostrar el mensaje en la terminal con el color correspondiente
    print(f"{color}[{timestamp}] {message}{COLOR['RESET']}")

    # Usar el método de logging adecuado para el nivel
    if level.lower() == "info":
        logging.info(message)
    elif level.lower() == "warning":
        logging.warning(message)
    elif level.lower() == "error":
        logging.error(message)
    elif level.lower() == "success":
        # Usamos info() para 'success' porque no existe un método específico
        logging.info(message)

def cargar_ips_bloqueadas():
    if os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE) as f:
            return set(f.read().splitlines())
    return set()

def send_doh_request(doh_query, headers, retries=3, delay=2):
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
                    return response.content
                elif response.status_code == 403 and STEALTH_MODE:
                    log(f"[🚨 STEALTH] {server} bloqueado, eliminando...", "WARNING")
                    with latency_lock:
                        DOH_SERVERS.remove(server)
                        del server_latencies[server]
                    if not DOH_SERVERS:
                        log("[⛔ ERROR] No quedan servidores DoH disponibles.", "ERROR")
                        return None
            except requests.RequestException as e:
                log(f"[❌ DoH] Error al conectar a {server} (intento {attempt + 1}/{retries}): {e}", "ERROR")
                server_latencies[server] = float('inf')

        time.sleep(delay)
    
    error_count += 1
    return None

blocked_ips = cargar_ips_bloqueadas()

def bloquear_ip(ip):
    blocked_ips.add(ip)
    with open(BLOCKED_IPS_FILE, "a") as f:
        f.write(ip + "\n")
    log(f"[⛔ BLOQUEADO] IP {ip} detectada por posible DNS Tunneling", "WARNING")

class DNSProxy(socketserver.BaseRequestHandler):
    def handle(self):
        client_ip = self.client_address[0]
        query_count[client_ip] += 1
        
        if client_ip in blocked_ips:
            log(f"[⛔ BLOQUEADO] {client_ip} intentó conectarse", "WARNING")
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
        
        qname = str(request.q.qname)
        qtype = QTYPE.get(request.q.qtype, "UNKNOWN")
        
        cache_key = f"{qname}:{qtype}"
        cached_response = dns_cache.get(cache_key)
        
        if cached_response:
            log(f"[🔍 CACHÉ] {qname} ({qtype}) servido desde caché", "SUCCESS")
            sock.sendto(cached_response, self.client_address)
            return
        
        if qtype == 'PTR' or qname in blocked_domains or qname in threat_domains:
            log(f"[🚫 BLOQUEADO] Consulta denegada para {qname} (amenaza detectada)", "WARNING")
            reply = request.reply()
            reply.header.rcode = 3  # NXDOMAIN
            sock.sendto(reply.pack(), self.client_address)
            return

        if qtype not in ALLOWED_QTYPES:
            log(f"[🚫 IGNORADO] Tipo {qtype} no permitido para {qname}", "WARNING")
            return
        
        if qtype == 'TXT' and len(data) > 300:
            bloquear_ip(client_ip)
            return

        start_time = time.time()
        log(f"[🔍 CONSULTA] {qname} ({qtype}) de {client_ip}", "INFO")

        doh_query = request.pack()
        headers = {"Accept": "application/dns-message", "Content-Type": "application/dns-message"}

        response = send_doh_request(doh_query, headers, retries=3)
        if response:
            try:
                dns_response = DNSRecord.parse(response)
                end_time = time.time()
                query_duration = end_time - start_time
                ttl = min(rr.ttl for rr in dns_response.rr) if dns_response.rr else 3600
                try:
                    validate(dns_response, request)
                    log("[🔒 DNSSEC] Respuesta validada", "SUCCESS")
                except Exception as e:
                    log(f"[⚠️ DNSSEC] Validación fallida para {qname}: {e}", "WARNING")
                # Manejar diferentes tipos de respuesta
                if qtype == 'A' and dns_response.get_a():
                    resolved_ip = str(dns_response.get_a().rdata)
                elif qtype == 'AAAA' and any(r.rtype == QTYPE.AAAA for r in dns_response.rr):
                    resolved_ip = str(next(r.rdata for r in dns_response.rr if r.rtype == QTYPE.AAAA))
                elif qtype == 'HTTPS' and any(r.rtype == QTYPE.HTTPS for r in dns_response.rr):
                    resolved_ip = "HTTPS Record"
                else:
                    resolved_ip = "No IP"
                log(f"[✅ RESPUESTA] {qname} ({qtype}) → Resolución: {resolved_ip} - Tiempo: {query_duration:.4f}s", "SUCCESS")
                dns_cache[cache_key] = response
                sock.sendto(response, self.client_address)
            except Exception as e:
                log(f"[❌ ERROR] No se pudo parsear respuesta DoH para {qname}: {e}", "ERROR")
                # Enviar la respuesta tal cual si es válida, o NXDOMAIN si falla
                if response:
                    sock.sendto(response, self.client_address)
                else:
                    reply = request.reply()
                    reply.header.rcode = 3  # NXDOMAIN
                    sock.sendto(reply.pack(), self.client_address)
            return

        end_time = time.time()
        query_duration = end_time - start_time
        log(f"[❌ FALLÓ] No se pudo resolver {qname} - Tiempo: {query_duration:.4f}s", "ERROR")
        # Enviar NXDOMAIN como fallback si falla DoH
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

# Inicializar Flask
app = Flask(__name__, template_folder=os.path.abspath('./'))

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

# Función log sin dependencia de Flask
def log(message, level="INFO"):
    global stats, success_count, error_count
    if "consultas exitosas" in message:
        stats["total_resolved"] += 1
        success_count += 1
    elif "consultas fallidas" in message:
        stats["total_failed"] += 1
        error_count += 1
    stats["total_queries"] += 1
    stats["blocked_domains_count"] = len(blocked_domains)

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print(f"[{timestamp}] {message}")
    if level.lower() == "info":
        logging.info(message)
    elif level.lower() == "warning":
        logging.warning(message)
    elif level.lower() == "error":
        logging.error(message)
    elif level.lower() == "success":
        logging.info(message)

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
    }
    return jsonify(stats_data)

# Ruta para configuración
@app.route('/config_ini', methods=['GET', 'PATCH'])
@requires_auth
def config_json():
    global config
    if request.method == 'GET':
        config_data = {
            'doh_servers': config['DNS']['Servers'].split(','),
            'allowed_qtypes': config['DNS']['AllowedQtypes'].split(','),
            'server_ip': config['Server']['IP'],
            'server_port': int(config['Server']['Port']),
            'rate_limit': int(config['Security']['RateLimit']),
            'blacklist_file': config['Security']['Blacklist'],
        }
        return jsonify(config_data)
    
    elif request.method == 'PATCH':
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
        reload_config(None, None)
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

# Función para iniciar Flask
def run_flask():
    while flask_app_running:
        app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)
        if not flask_app_running:
            break

# Iniciar Flask en un hilo separado
flask_thread = threading.Thread(target=run_flask)
flask_thread.daemon = True
flask_thread.start()


def print_stats():
    """Imprime estadísticas de rendimiento."""
    avg_time = total_query_time / success_count if success_count else 0
    log("🔹 Estadísticas de rendimiento:", "INFO")
    log(f"  - Consultas exitosas: {success_count}", "INFO")
    log(f"  - Consultas fallidas: {error_count}", "INFO")
    log(f"  - Tiempo promedio por consulta: {avg_time:.4f}s", "INFO")


def reload_config(signal, frame):
    """Recarga la configuración al recibir SIGHUP sin detener el servidor."""
    global DOH_SERVERS, ALLOWED_QTYPES, RATE_LIMIT, blocked_domains
    config.read('config.ini')
    DOH_SERVERS = config['DNS']['Servers'].split(',')
    ALLOWED_QTYPES = config['DNS']['AllowedQtypes'].split(',')
    RATE_LIMIT = int(config['Security']['RateLimit'])

    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE) as f:
            blocked_domains.clear()
            blocked_domains.update(line.strip() for line in f if line.strip())

    log("🔄 Configuración recargada.", "SUCCESS")
    
def start_dns_server():
    global server, server_thread
    server = socketserver.ThreadingUDPServer((IP, PORT), DNSProxy)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    log(f"🔐 Servidor DNS Proxy corriendo en {IP}:{PORT}...", "SUCCESS")

# Verificar si el sistema operativo soporta SIGHUP antes de intentar registrar la señal
if platform.system() != "Windows":
    signal.signal(signal.SIGHUP, reload_config)
else:
    log("[⚠️ ERROR] SIGHUP no disponible en este sistema.", "ERROR")

if __name__ == "__main__":
    if "--help" in sys.argv:
        show_help()
        sys.exit(0)
        
    stunnel_proc = iniciar_stunnel()
    
    if set_windows_dns(IP, PORT):
        log(f"Proxy DNS configurado en {IP}:{PORT} y DNS de Windows actualizado.", "SUCCESS")
    else:
        log("No se pudo configurar el DNS de Windows. Continuando sin cambios.", "WARNING")
        
    start_dns_server()

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
