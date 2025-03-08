# DNS Proxy con Soporte DoH

[![Python](https://img.shields.io/badge/Python-3.12+-green.svg)](https://www.python.org/)

Un servidor proxy DNS avanzado que convierte consultas DNS locales en solicitudes DNS over HTTPS (DoH) para mejorar la privacidad y evitar bloqueos de ISP. Incluye una interfaz web interactiva para monitoreo y gestión, soporte para ofuscación con `stunnel`, y la capacidad de configurar automáticamente los DNS de Windows.

## Propósito
Un servidor proxy DNS diseñado para evitar bloqueos de ISP, como el de Movistar a Cloudflare, y mejorar la privacidad del usuario mediante DNS over HTTPS (DoH). Ofrece una alternativa segura frente a proxies maliciosos o DNS fraudulentos, garantizando un acceso confiable y protegido a internet. **Nota**: Este no es un VPN ni cifra todo el tráfico de red; solo redirige consultas DNS para evitar bloqueos específicos y proteger la privacidad de las resoluciones DNS.

## Características

- **DNS over HTTPS (DoH)**: Convierte consultas DNS tradicionales (UDP/53) en solicitudes HTTPS cifradas.
- **Evitar Bloqueos de ISP**: Soporte para múltiples servidores DoH (Cloudflare, Google, etc.), rotación de IPs alternativas(En Proceso), y túneles TLS con `stunnel`.
- **Bloqueador de anuncios**: Bloquea dominios de anuncios conocidos para evitar anuncios.
- **Interfaz Web**: Dashboard en tiempo real con estadísticas, configuración editable(En Proceso), logs, y gestión de lista negra.
- **Configuración Automática de DNS**: Configura los DNS de Windows para usar el proxy local y los restaura al cerrar.
- **Seguridad**: Protección contra DNS tunneling, límites de tasa, y lista negra de dominios.
- **Multiplataforma**: Diseñado para Windows, con posibilidad de expansión a Linux/macOS.
- **Gestión Remota**: Opciones para reiniciar o detener el servidor desde la web.

![Captura de pantalla 2025-02-22 044426](https://github.com/user-attachments/assets/59a8563a-e64a-49b5-8242-4bf07abce65a)

## Requisitos

- **Python 3.12+**
- **Dependencias**:
  - `requests`
  - `dnslib`
  - `pythondns`
  - `flask`
  - `psutil`
  - `cachetools` (opcional, para caché DNS)
- **stunnel**: Opcional, para ofuscación del tráfico (requiere instalación manual en Windows).
- **Windows**: Requiere privilegios de administrador para configurar DNS.

Instala las dependencias con:
```bash
pip install requests dnslib pythondns flask psutil cachetools
```

# Instalación

### 1. Clonar o Descargar el Repositorio

```bash
git clone https://github.com/Nooch98/bloqueo-a-cloudflare-bypass.git
```

### 2. Configurar `stunnel` (opcional)

- Descargar e instalar [stunell](https://www.stunnel.org/downloads.html)

- Asegurate de que `stunnel.exe` este en `%LOCALAPPDATA%\Programs\stunnel\bin\`

- Crea un archivo `stunnel.conf` (Ver sección de Configuración)

### 3. Ejecutar el Script

```bash
python DoH.py
```

- Usa privilegios de administrador en windows para permitir la configuración de DNS.

### 4. Empaquetar como .exe (opcional)

```bash
pyinstaller --onefile --add-data "stunnel.conf" DoH.py
```

- Ejecuta el .exe resultante como administrador.

# USO

* **Iniciar el servidor**: Ejecuta el script o el `.exe`. El proxy DNS escucha en `127.0.0.1:53` (configurable).

* **Acceder a la interfaz web**: Abre `http://127.0.0.1:5000` en tu navegador (credenciales predeterminadas: `admin`/`secret`).

![Captura de pantalla 2025-02-24 210435](https://github.com/user-attachments/assets/cc73667c-1eed-4f45-956f-6818deecbcca)

* **Terminal**: Los logs se muestran en la terminal y se guardan en `dns_proxy.log`.

![Captura de pantalla 2025-02-24 210357](https://github.com/user-attachments/assets/69b377c1-feb8-4e80-a8cc-dbaa85c1abd1)

* **Comandos de Línea**:
  - `--help`: Muestra Info y Ayuda.

# Configuración

El archivo `config.ini` permite personalizar el comportamiento del proxy. Si no existe, se genera uno predeterminado al iniciar el script.

## Ejemplo de `config.ini`

```ini
[DNS]
Servers=[https://cloudflare-dns.com/dns-query,https://dns.google/dns-query](https://8.8.8.8/dns-query,https://1.1.1.1/dns-query,https://9.9.9.9/dns-query)
AllowedQtypes=A,AAAA,CNAME,MX,TXT,NS,SOA,HTTPS

[Server]
IP=127.0.0.1
Port=53

[Security]
ratelimit = 0
blacklist = blocked_domains.txt
stealthmode = True
ThreatUpdateInterval = 86400
AllowedNetworks=
MaxResponseSize=512
EnableAntiAmplification=True

[AdBlocking]
EnableAdBlocking=True
AdBlockLists=https://easylist.to/easylist/easylist.txt,https://adaway.org/hosts.txt
UpdateInterval=86400

[Logging]
logfile = dns_proxy.log
```

## Ejemplo de `stunnel.conf`

Para ofuscar el trafico DNS:

```conf
; stunnel.conf para DNS sobre HTTPS (DoH)
; Este archivo configura stunnel en modo cliente para crear un túnel TLS.
; Se acepta tráfico DNS en 127.0.0.1:53 y se redirige hacia un servidor DoH (en este ejemplo, dns.google:443).

; Opciones globales
output = stunnel.log

; Modo cliente: se usará para cifrar las consultas DNS
[doh]
client = yes

; Puerto local donde stunnel escuchará las consultas DNS (puedes ajustar este puerto según tu configuración)
accept = 127.0.0.1:53

; Conexión remota al servidor DoH; en este ejemplo se usa Google DNS sobre HTTPS.
connect = dns.google:443

; Opciones de seguridad (ajusta según sea necesario)
verifyChain = yes
; CAfile: ruta al archivo con certificados de autoridades certificadoras. 
; Descarga el paquete de certificados (por ejemplo, "cacert.pem") y colócalo en el directorio de tu aplicación.
CAfile = ca-certs.pem

; Opciones adicionales para reforzar la seguridad
options = NO_SSLv2
options = NO_SSLv3

; Tiempo de espera para cerrar la conexión (puedes ajustar si es necesario)
TIMEOUTclose = 0
```

# Funcionalidades de la Interfaz Web

* **Estadísticas**: Consultas totales, exitosas, fallidas, tiempo promedio, uso de CPU/memoria.

* **Configuración**: Muestra la configuración actual del servidor.

* **Logs**: Muestra los últimos 50 registros del archivo de logs.

* **Lista Negra**: Agrega o elimina dominios bloqueados.

* **Controles**: Reiniciar o detener el servidor.

# Evitar Bloqueos de ISP

* **DoH**: Cifra consultas DNS en HTTPS (puerto 443).

* **stunnel**:  Ofusca el tráfico a través de un túnel TLS en un puerto no estándar (8443).


# Notas

* **Privilegios**: Ejecuta como administrador en Windows para configurar DNS.

* **stunnel**: Requiere configuración manual y un servidor remoto para máxima efectividad contra DPI.

* **Empaquetado**: Incluye el archivo `stunnel.conf` para ofuscar el tráfico DNS.

# LICENCIA

> MIT License
>
> Copyright (c) 2025 Nooch98
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

# CONTACTO

Si tienes alguna sugerencia de mejora, o encontraste algún error, por favor abre un issue.
