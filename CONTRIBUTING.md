# Guía de Contribución

[![Python](https://img.shields.io/badge/Python-3.12+-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/github/license/Nooch98/bloqueo-a-cloudflare-bypass)](https://github.com/Nooch98/bloqueo-a-cloudflare-bypass)

¡Gracias por tu interés en contribuir al **DNS Proxy con Soporte DoH**! Este proyecto está diseñado para evitar bloqueos de ISP y mejorar la privacidad mediante DNS over HTTPS (DoH). Aprecio cualquier ayuda, ya sea reportando problemas, proponiendo mejoras, o enviando código. A continuación, encontrarás las pautas para participar.

## Cómo Contribuir

### 1. Reportar Problemas
Si encuentras un error o tienes una idea para mejorar el proyecto:
- Abre un [issue](https://github.com/Nooch98/bloqueo-a-cloudflare-bypass/issues) en el repositorio.
- Proporciona:
  - Una descripción clara del problema o la sugerencia.
  - Pasos para reproducir el error (si aplica).
  - Información del sistema (versión de Python, Windows, etc.).
  - Capturas de pantalla o logs relevantes (si es posible).

### 2. Proponer Mejoras
- Usa los [issues](https://github.com/Nooch98/bloqueo-a-cloudflare-bypass/issues) para discutir nuevas funcionalidades antes de implementarlas.
- Describe el propósito de la mejora y cómo beneficiará al proyecto.

### 3. Enviar Pull Requests
Sigue estos pasos para contribuir con código:

#### a. Hacer un Fork
1. Haz un fork del repositorio desde la página principal en GitHub.
2. Clona tu fork localmente:
   ```bash
   git clone https://github.com/tu-usuario/bloqueo-a-cloudflare-bypass.git
   cd bloqueo-a-cloudflare-bypass
   ```

#### b. Crea una Rama
* Crea una rama nueva:
  ```bash
  git checkout -b <nombre-de-la-rama>
  ```
* Usa nombres descriptivos (por ejemplo, `fix/bug-resolucion-dns` o `feature/nueva-funcionalidad`).

#### c. Hacer Cambios
* Realiza tus modificaciones en el codigo o documentación.
* Manten el estilo de codigo existente.
* Si añades Funcionalidades:
  - Actualiza `README.md` con las nuevas características o instrucciones.
  - Incluye cualquier archivo nuevo(como imagenes, archivos de configuración, etc.)necesarios para tu cambio.

#### d. Probar los cambios
* Asegurate de que el script funciona como esperas y que no haya errores.
* Verifica que las dependencias requeridas esten actualizadas y que el empaquetado funciona correctamente.

#### e. Commit y Pull Request
* Haz commits con mensajes claros:
  ```bash
  git commit -m "feat: Añadir soporte para DNSSEC"
  ```
* Sube tu rama a tu fork:
  ```bash
  git push origin <nombre-de-la-rama>
  ```
* Abre un Pull Request desde tu fork hacia la rama `main` del repositorio.
* Describe tus cambios y vincula cualquier issue relacionada.

### 4. Cambios en configuraciones
- Si modificas `config.ini`o `stunnel.conf`, incluye ejemplos actualizados en el README.

### 5. Areas de mejora
- Soporte para MacOS, Linux(Adaptar configuracion DNS).
- Añadir Cache con TTL(`cachetools` ya esta como dependencia opcional)
- Mejorar la interfaz web con nuevas funcionalidades(por ejemplo: Configuracion en ejecucion, graficos dinamicos, etc etc)
- Documentar casos de uso específicos (por ejemplo: bloqueos de otros ISP)

## Contacto
Si tienes alguna pregunta o necesitas ayuda, no dudes en contactarme, abre un [issue](https://github.com/Nooch98/bloqueo-a-cloudflare-bypass/issues)
