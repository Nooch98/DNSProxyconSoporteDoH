from dnslib import DNSRecord, QTYPE
import requests
import socketserver

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
            print(f"Consulta ignorada: tipo PTR no permitido")
            return

        # Solo permitir consultas de tipo A y AAAA (direcciones IPv4 e IPv6)
        if qtype not in ['A', 'AAAA']:
            print(f"Consulta ignorada: tipo {qtype} no permitido")
            return

        print(f"Consulta hacia {qname} tipo {qtype}")

        # Crear la consulta DNS en formato binario
        doh_query = request.pack()

        # Enviar la consulta al servidor DoH usando POST
        try:
            headers = {
                "Accept": "application/dns-message",
                "Content-Type": "application/dns-message"
            }
            response = requests.post(DOH_SERVER, data=doh_query, headers=headers)

            if response.status_code == 200:
                print(f"Respuesta recibida desde {DOH_SERVER}: OK")
                print(f"Respuesta DoH (primeros 100 bytes): {response.content.hex()[:100]}...") 
                socket.sendto(response.content, self.client_address)
            else:
                print(f"Error al obtener la respuesta DoH: {response.status_code} - {response.text}")
        except requests.RequestException as e:
            print(f"Error de conexión con el servidor DoH: {e}")

# Iniciar servidor DNS local en el puerto 53
with socketserver.UDPServer(("127.0.0.1", 53), DNSProxy) as server:
    print("Servidor DNS Proxy corriendo en 127.0.0.1:53...")
    server.serve_forever()
