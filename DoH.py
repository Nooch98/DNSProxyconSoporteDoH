import requests
import socketserver
import logging
import time
import sys
import os
import platform
import signal
import configparser
import threading
import socket
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
from collections import defaultdict
from dnslib import DNSRecord, QTYPE

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
    """Crea un archivo config.ini con valores predeterminados si no existe."""
    config['DNS'] = {
        'Servers': 'https://cloudflare-dns.com/dns-query,https://dns.google/dns-query',
        'AllowedQtypes': 'A,AAAA,CNAME,MX,TXT,NS,SOA,HTTPS'
    }
    config['Server'] = {'IP': '127.0.0.1', 'Port': '53'}
    config['Security'] = {'RateLimit': '10', 'Blacklist': 'blocked_domains.txt'}
    config['Logging'] = {'LogFile': 'dns_proxy.log'}

    with open('config.ini', 'w') as configfile:
        config.write(configfile)


if not os.path.exists('config.ini'):
    create_default_config()

config.read('config.ini')

DOH_SERVERS = config['DNS']['Servers'].split(',')
ALLOWED_QTYPES = config['DNS']['AllowedQtypes'].split(',')
IP = config['Server']['IP']
PORT = int(config['Server']['Port'])
RATE_LIMIT = int(config['Security']['RateLimit'])
BLACKLIST_FILE = config['Security']['Blacklist']

if os.path.exists(BLACKLIST_FILE):
    with open(BLACKLIST_FILE) as f:
        blocked_domains.update(line.strip() for line in f if line.strip())
        
SUCCESS_LEVEL = 25
logging.addLevelName(SUCCESS_LEVEL, "SUCCESS")
logging.basicConfig(filename=config['Logging']['LogFile'], level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")


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


def send_doh_request(server, doh_query, headers, retries=3, delay=2):
    """Intenta resolver una consulta DNS usando DoH con reintentos."""
    global success_count, error_count, total_query_time

    for attempt in range(retries):
        try:
            start_time = time.time()
            response = requests.post(server, data=doh_query, headers=headers, timeout=3)
            elapsed_time = time.time() - start_time
            total_query_time += elapsed_time

            if response.status_code == 200:
                success_count += 1
                return response.content
            else:
                log(f"[⚠️ ERROR] {server} respondió {response.status_code}", "ERROR")
        except requests.RequestException:
            log(f"[⛔ ERROR] Intento {attempt+1}/{retries}: No se pudo conectar a {server}", "ERROR")

        time.sleep(delay)
    
    error_count += 1
    return None


class DNSProxy(socketserver.BaseRequestHandler):
    def handle(self):
        client_ip = self.client_address[0]
        query_count[client_ip] += 1

        # Verifica si RATE_LIMIT es 0 (sin límite) o si se supera el límite de consultas
        if RATE_LIMIT != 0 and query_count[client_ip] > RATE_LIMIT:
            log(f"[🚫 BLOQUEADO] {client_ip} superó el límite de {RATE_LIMIT} consultas", "WARNING")
            return

        data, sock = self.request
        request = DNSRecord.parse(data)
        qname = str(request.q.qname)
        qtype = QTYPE.get(request.q.qtype, "UNKNOWN")

        # Resolución de la IP del dominio
        try:
            resolved_ip = socket.gethostbyname(qname)  # Resuelve el dominio a una IP
        except socket.gaierror:
            resolved_ip = "No se pudo resolver"

        if qtype == 'PTR' or qname in blocked_domains:
            log(f"[🚫 BLOQUEADO] Consulta denegada para {qname}", "WARNING")
            return

        if qtype not in ALLOWED_QTYPES:
            log(f"[🚫 IGNORADO] Tipo {qtype} no permitido ({qname})", "WARNING")
            return

        # Log mejorado con más detalles, incluyendo el tiempo de la consulta
        start_time = time.time()  # Inicio de la consulta
        log(f"[🔍 CONSULTA] {qname} ({qtype}) de {client_ip} → Resolución: {resolved_ip}", "INFO")

        doh_query = request.pack()
        headers = {"Accept": "application/dns-message", "Content-Type": "application/dns-message"}

        for server in DOH_SERVERS:
            response = send_doh_request(server, doh_query, headers)
            if response:
                end_time = time.time()  # Fin de la consulta
                query_duration = end_time - start_time  # Duración total
                log(f"[✅ RESPUESTA] {qname} ({qtype}) desde {server} → Resolución: {resolved_ip} - Tiempo: {query_duration:.4f}s", "SUCCESS")
                sock.sendto(response, self.client_address)
                return

        end_time = time.time()  # Fin en caso de fallo
        query_duration = end_time - start_time
        log(f"[❌ FALLÓ] No se pudo resolver {qname} ({resolved_ip}) - Tiempo: {query_duration:.4f}s", "ERROR")

# Inicializar la aplicación Flask
app = Flask(__name__, template_folder=os.path.abspath('./'))

# Configuración de SocketIO
socketio = SocketIO(app)

# Cargar configuración desde config.ini
config = configparser.ConfigParser()
config.read('config.ini')

# Ruta principal
@app.route('/')
def index():
    return render_template('index.html')

# Ruta para obtener las estadísticas en formato JSON
@app.route('/stats')
def get_stats():
    stats = {
        "total_queries": sum(query_count.values()),
        "success_count": success_count,
        "error_count": error_count,
        "avg_time": total_query_time / success_count if success_count else 0,
        "blocked_domains_count": len(blocked_domains),
    }
    return jsonify(stats)

# Ruta para obtener la configuración en formato JSON (opcional)
@app.route('/config_ini')
def config_json():
    config_data = {
        'doh_servers': config['DNS']['Servers'].split(','),
        'allowed_qtypes': config['DNS']['AllowedQtypes'].split(','),
        'server_ip': config['Server']['IP'],
        'server_port': int(config['Server']['Port']),
        'rate_limit': int(config['Security']['RateLimit']),
        'blacklist_file': config['Security']['Blacklist'],
    }
    return jsonify(config_data)

@app.route('/logs')
def get_logs():
    log_file = 'dns_proxy.log'
    logs = []
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r') as file:
                logs = file.readlines()
            # Limitar la cantidad de líneas si el archivo es muy grande
            logs = logs[-50:]  # Solo mostrar las últimas 50 líneas de los logs
        except Exception as e:
            return jsonify({"error": f"Error al leer el archivo de logs: {str(e)}"}), 500
    else:
        return jsonify({"error": "El archivo de logs no existe."}), 404
    
    return jsonify({'logs': logs})

# Función para iniciar el servidor Flask en un hilo separado
def run_flask():
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)

# Iniciar el servidor Flask en un hilo separado
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

# Verificar si el sistema operativo soporta SIGHUP antes de intentar registrar la señal
if platform.system() != "Windows":
    signal.signal(signal.SIGHUP, reload_config)
else:
    log("[⚠️ ERROR] SIGHUP no disponible en este sistema.", "ERROR")

if __name__ == "__main__":
    if "--help" in sys.argv:
        show_help()
        sys.exit(0)
    if "--stats" in sys.argv:
        print_stats()
        sys.exit(0)

    try:
        with socketserver.UDPServer((IP, PORT), DNSProxy) as server:
            log(f"🔐 Servidor DNS Proxy con TLS corriendo en {IP}:{PORT}...", "SUCCESS")
            server.serve_forever()
    except KeyboardInterrupt:
        log("🔴 Servidor detenido por el usuario.", "INFO")
        print_stats()
