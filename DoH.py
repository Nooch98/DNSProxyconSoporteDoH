from dnslib import DNSRecord, QTYPE
import requests
import socketserver
import time

# Colores para terminal (solo si la terminal soporta ANSI)
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Configuración del servidor DoH
DOH_SERVER = "https://dns.google/dns-query"

class DNSProxy(socketserver.BaseRequestHandler):
    def handle(self):
        data, socket = self.request
        request = DNSRecord.parse(data)

        # Convertir la consulta en formato DoH
        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]

        # Ignorar consultas de tipo PTR (que son típicas para direcciones como 127.0.0.1)
        if qtype == 'PTR':
            print(f"{bcolors.WARNING}[INFO] Consulta ignorada: tipo PTR no permitido{bcolors.ENDC}")
            return

        # Solo permitir consultas de tipo A y AAAA (direcciones IPv4 e IPv6)
        if qtype not in ['A', 'AAAA']:
            print(f"{bcolors.WARNING}[INFO] Consulta ignorada: tipo {qtype} no permitido{bcolors.ENDC}")
            return

        # Mostrar la consulta que se recibió
        print(f"\n{bcolors.OKBLUE}[INFO] Consulta recibida:{bcolors.ENDC}")
        print(f"{bcolors.OKGREEN}  Nombre de dominio: {qname}{bcolors.ENDC}")
        print(f"{bcolors.OKGREEN}  Tipo de consulta: {qtype}{bcolors.ENDC}")

        # Crear la consulta DNS en formato binario
        doh_query = request.pack()

        # Enviar la consulta al servidor DoH usando POST
        try:
            start_time = time.time()  # Medir el tiempo de la solicitud

            headers = {
                "Accept": "application/dns-message",
                "Content-Type": "application/dns-message"
            }
            response = requests.post(DOH_SERVER, data=doh_query, headers=headers)

            # Medir tiempo de respuesta
            elapsed_time = time.time() - start_time

            if response.status_code == 200:
                print(f"\n{bcolors.OKGREEN}[INFO] Respuesta recibida desde {DOH_SERVER}: OK{bcolors.ENDC}")
                print(f"{bcolors.OKGREEN}[INFO] Tiempo de respuesta: {elapsed_time:.2f} segundos{bcolors.ENDC}")
                print(f"{bcolors.OKGREEN}[INFO] Respuesta DoH (primeros 100 bytes): {response.content.hex()[:100]}...{bcolors.ENDC}")

                # Enviar la respuesta al cliente
                socket.sendto(response.content, self.client_address)
            else:
                print(f"\n{bcolors.FAIL}[ERROR] Error al obtener la respuesta DoH: {response.status_code} - {response.text}{bcolors.ENDC}")

        except requests.RequestException as e:
            print(f"\n{bcolors.FAIL}[ERROR] Error de conexión con el servidor DoH: {e}{bcolors.ENDC}")


# Iniciar servidor DNS local en el puerto 53
with socketserver.UDPServer(("127.0.0.1", 53), DNSProxy) as server:
    print(f"\n{bcolors.OKBLUE}[INFO] Servidor DNS Proxy corriendo en 127.0.0.1:53...{bcolors.ENDC}")
    print(f"{bcolors.OKBLUE}[INFO] Esperando consultas DNS...{bcolors.ENDC}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{bcolors.OKGREEN}[INFO] Servidor detenido por el usuario.{bcolors.ENDC}")
