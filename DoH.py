import requests
import socketserver
import logging
import time
import os
import configparser
from dnslib import DNSRecord, QTYPE
import socket  # Asegúrate de que el módulo socket está importado

def create_default_config():
    config = configparser.ConfigParser()

    config['DNS'] = {
        'Servers': 'https://cloudflare-dns.com/dns-query,https://dns.google/dns-query',  # Servidores DoH predeterminados
        'AllowedQtypes': 'A,AAAA,CNAME,MX,TXT,NS,SOA,HTTPS'  # Tipos de consulta permitidos
    }
    config['Server'] = {
        'IP': '127.0.0.1',  # IP local predeterminada (todas las interfaces)
        'Port': '53'  # Puerto predeterminado
    }
    config['Logging'] = {
        'LogFile': 'dns_proxy.log'  # Archivo de log predeterminado
    }

    with open('config.ini', 'w') as configfile:
        config.write(configfile)


# 🔹 Leer configuración desde el archivo .ini
config = configparser.ConfigParser()
config.read('config.ini')

DOH_SERVERS = config['DNS']['Servers'].split(',')
ALLOWED_QTYPES = config['DNS']['AllowedQtypes'].split(',')
IP = config['Server']['IP']
PORT = int(config['Server']['Port'])

# 🔹 Configuración de logging
logging.basicConfig(filename=config['Logging']['LogFile'], level=logging.INFO, 
                    format="%(asctime)s - %(levelname)s - %(message)s")

# Variables de estadísticas
success_count = 0
error_count = 0
total_query_time = 0
query_count = 0

def log_info(message):
    """Función para logear y mostrar mensajes de info en la terminal con colores."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())  # Timestamp detallado
    print(f"{COLOR['INFO']}[{timestamp}] {message}{COLOR['RESET']}")
    logging.info(f"{timestamp} - {message}")

def log_error(message):
    """Función para logear y mostrar mensajes de error en la terminal con colores."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print(f"{COLOR['ERROR']}[{timestamp}] {message}{COLOR['RESET']}")
    logging.error(f"{timestamp} - {message}")

def log_success(message):
    """Función para logear y mostrar mensajes de éxito en la terminal con colores."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print(f"{COLOR['SUCCESS']}[{timestamp}] {message}{COLOR['RESET']}")
    logging.info(f"{timestamp} - {message}")

def log_warning(message):
    """Función para logear y mostrar mensajes de advertencia en la terminal con colores."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print(f"{COLOR['WARNING']}[{timestamp}] {message}{COLOR['RESET']}")
    logging.warning(f"{timestamp} - {message}")

# 🎨 Colores para la salida en terminal (para hacerla más legible)
COLOR = {
    "INFO": "\033[94m",  # Azul
    "SUCCESS": "\033[92m",  # Verde
    "WARNING": "\033[93m",  # Amarillo
    "ERROR": "\033[91m",  # Rojo
    "RESET": "\033[0m"  # Reset de color
}

# Leer configuración desde el archivo .ini
if not os.path.exists('config.ini'):
    print(f"{COLOR['WARNING']}El archivo config.ini no encontrado, creando uno por defecto...{COLOR['RESET']}")
    create_default_config()

def send_doh_request_with_retries(server, doh_query, headers, retries=3, delay=2):
    """Función para intentar enviar la consulta DoH con reintentos."""
    global success_count, error_count, total_query_time, query_count  # Usamos variables globales para estadísticas
    for attempt in range(retries):
        try:
            start_time = time.time()
            response = requests.post(server, data=doh_query, headers=headers, timeout=3)
            elapsed_time = time.time() - start_time
            query_count += 1
            total_query_time += elapsed_time  # Acumulamos el tiempo total de consultas exitosas

            if response.status_code == 200:
                success_count += 1  # Incrementamos el contador de éxitos
                return response, elapsed_time
            else:
                log_error(f"[⚠️ ERROR] {server} respondió {response.status_code} - {response.text}")
        except requests.RequestException as e:
            log_error(f"[⛔ ERROR] Intento {attempt+1} de {retries}: No se pudo conectar a {server}: {e}")
        
        if attempt < retries - 1:
            time.sleep(delay)
    
    error_count += 1  # Incrementamos el contador de errores
    return None, None

def print_stats():
    """Imprime las estadísticas de desempeño."""
    if query_count > 0:
        avg_time = total_query_time / query_count
        log_info(f"🔹 Estadísticas de rendimiento:")
        log_info(f"  - Consultas exitosas: {success_count}")
        log_info(f"  - Consultas fallidas: {error_count}")
        log_info(f"  - Tiempo promedio por consulta: {avg_time:.4f}s")
    else:
        log_info("🔹 No se han procesado consultas aún.")

class DNSProxy(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request  # Cambié 'socket' a 'sock' aquí
        request = DNSRecord.parse(data)

        qname = str(request.q.qname)
        qtype = QTYPE.get(request.q.qtype, "UNKNOWN")

        # 🛑 Ignorar PTR (evita consultas reversas de IPs locales)
        if qtype == 'PTR':
            log_warning(f"[IGNORADO] Consulta PTR para {qname}")
            return

        # Solo permitir tipos de consulta específicos
        if qtype not in ALLOWED_QTYPES:
            log_warning(f"[IGNORADO] Consulta {qtype} no permitida ({qname})")
            return

        log_info(f"[🔍 CONSULTA] Dominio: {qname} | Tipo: {qtype}")

        doh_query = request.pack()

        # 🔁 Intentar cada servidor DoH disponible
        for server in DOH_SERVERS:
            response, elapsed_time = send_doh_request_with_retries(server, doh_query, {
                "Accept": "application/dns-message",
                "Content-Type": "application/dns-message"
            })
            
            if response:
                # Obtener la IP de destino
                ip_destino = socket.gethostbyname(qname) if qtype in ['A', 'AAAA'] else "N/A"
                log_success(f"[✅ RESPUESTA] Dominio: {qname} | Tipo: {qtype} | IP Destino: {ip_destino} | "
                            f"Servidor DoH: {server} | Tiempo: {elapsed_time:.3f}s")  # Más precisión en el tiempo
                log_info(f"[HEX] {response.content.hex()[:100]}...")  # Muestra solo los primeros 100 bytes del resultado
                sock.sendto(response.content, self.client_address)  # Enviar la respuesta al cliente
                return
            else:
                log_error(f"[❌ FALLÓ] No se pudo resolver {qname}")

# 🔥 Iniciar el servidor DNS local en la IP y puerto configurados
try:
    with socketserver.UDPServer((IP, PORT), DNSProxy) as server:
        log_success(f"🔐 Servidor DNS Proxy con TLS corriendo en {IP}:{PORT}...\n{'-'*50}")
        server.serve_forever()
except KeyboardInterrupt:
    log_info("🔴 Servidor detenido por el usuario.")
    print_stats()
