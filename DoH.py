import requests
import socketserver
import logging
import time
import configparser
from dnslib import DNSRecord, QTYPE
import socket  # Asegúrate de que el módulo socket está importado

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

def log_info(message):
    """Función para logear y mostrar mensajes de info en la terminal con colores."""
    print(f"{COLOR['INFO']}{message}{COLOR['RESET']}")
    logging.info(message)

def log_error(message):
    """Función para logear y mostrar mensajes de error en la terminal con colores."""
    print(f"{COLOR['ERROR']}{message}{COLOR['RESET']}")
    logging.error(message)

def log_success(message):
    """Función para logear y mostrar mensajes de éxito en la terminal con colores."""
    print(f"{COLOR['SUCCESS']}{message}{COLOR['RESET']}")
    logging.info(message)

def log_warning(message):
    """Función para logear y mostrar mensajes de advertencia en la terminal con colores."""
    print(f"{COLOR['WARNING']}{message}{COLOR['RESET']}")
    logging.warning(message)

# 🎨 Colores para la salida en terminal (para hacerla más legible)
COLOR = {
    "INFO": "\033[94m",  # Azul
    "SUCCESS": "\033[92m",  # Verde
    "WARNING": "\033[93m",  # Amarillo
    "ERROR": "\033[91m",  # Rojo
    "RESET": "\033[0m"  # Reset de color
}

def send_doh_request_with_retries(server, doh_query, headers, retries=3, delay=2):
    """Función para intentar enviar la consulta DoH con reintentos."""
    for attempt in range(retries):
        try:
            start_time = time.time()
            response = requests.post(server, data=doh_query, headers=headers, timeout=3)
            elapsed_time = time.time() - start_time
            if response.status_code == 200:
                return response, elapsed_time
            else:
                log_error(f"[⚠️ ERROR] {server} respondió {response.status_code} - {response.text}")
        except requests.RequestException as e:
            log_error(f"[⛔ ERROR] Intento {attempt+1} de {retries}: No se pudo conectar a {server}: {e}")
        
        if attempt < retries - 1:
            time.sleep(delay)
    return None, None

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
                            f"Servidor DoH: {server} | Tiempo: {elapsed_time:.2f}s")
                log_info(f"[HEX] {response.content.hex()[:100]}...")  # Muestra solo los primeros 100 bytes del resultado
                sock.sendto(response.content, self.client_address)  # Enviar la respuesta al cliente
                return
            else:
                log_error(f"[❌ FALLÓ] No se pudo resolver {qname}")

# 🔥 Iniciar el servidor DNS local en la IP y puerto configurados
try:
    with socketserver.UDPServer((IP, PORT), DNSProxy) as server:
        log_success(f"🔐 Servidor DNS Proxy con TLS corriendo en {IP}:{PORT}...")
        server.serve_forever()
except KeyboardInterrupt:
    log_info("🔴 Servidor detenido por el usuario.")
