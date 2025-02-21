import requests
import socketserver
import logging
import time
import configparser
from dnslib import DNSRecord, QTYPE

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
    print(f"{COLOR['INFO']}{message}{COLOR['RESET']}")
    logging.info(message)

def log_error(message):
    print(f"{COLOR['ERROR']}{message}{COLOR['RESET']}")
    logging.error(message)

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
            response = requests.post(server, data=doh_query, headers=headers, timeout=3)
            if response.status_code == 200:
                return response
            else:
                log_error(f"[⚠️ ERROR] {server} respondió {response.status_code} - {response.text}")
        except requests.RequestException as e:
            log_error(f"[⛔ ERROR] Intento {attempt+1} de {retries}: No se pudo conectar a {server}: {e}")
        
        if attempt < retries - 1:
            time.sleep(delay)
    return None

class DNSProxy(socketserver.BaseRequestHandler):
    def handle(self):
        data, socket = self.request
        request = DNSRecord.parse(data)

        qname = str(request.q.qname)
        qtype = QTYPE.get(request.q.qtype, "UNKNOWN")

        # 🛑 Ignorar PTR (evita consultas reversas de IPs locales)
        if qtype == 'PTR':
            log_info(f"[IGNORADO] Consulta PTR para {qname}")
            return

        # Solo permitir tipos de consulta específicos
        if qtype not in ALLOWED_QTYPES:
            log_info(f"[IGNORADO] Consulta {qtype} no permitida ({qname})")
            return

        log_info(f"[🔍 CONSULTA] {qname} ({qtype})")

        doh_query = request.pack()

        # 🔁 Intentar cada servidor DoH disponible
        for server in DOH_SERVERS:
            response = send_doh_request_with_retries(server, doh_query, {
                "Accept": "application/dns-message",
                "Content-Type": "application/dns-message"
            })
            
            if response:
                log_info(f"[✅ RESPUESTA] {qname} ({qtype}) desde {server}")
                log_info(f"[HEX] {response.content.hex()[:100]}...")
                socket.sendto(response.content, self.client_address)
                return
            else:
                log_error(f"[❌ FALLÓ] No se pudo resolver {qname}")

# 🔥 Iniciar el servidor DNS local en la IP y puerto configurados
try:
    with socketserver.UDPServer((IP, PORT), DNSProxy) as server:
        log_info(f"🔐 Servidor DNS Proxy con TLS corriendo en {IP}:{PORT}...")
        server.serve_forever()
except KeyboardInterrupt:
    log_info("🔴 Servidor detenido por el usuario.")
