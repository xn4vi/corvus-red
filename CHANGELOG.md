# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y versionado [SemVer](https://semver.org/lang/es/).

## [1.2.0] — 2026-11-25

### Cambiado
- **Identidad visual propia de CORVUS Red**: logo nuevo (cuervo geométrico con pico en dos facetas verdes y ojo píxel neón), banner y lema propios («Auditoría de seguridad web con método: cada hallazgo, verificado.»).
- Paleta clara con verde `#166534`, trama de puntos y colores de severidad; tipografías Inter, Mona Sans y Chakra Petch incluidas e incrustadas en los informes.
- Informe rediseñado: portada clara, cuadrado y filete verdes en los títulos, severidades con cuadrado de color y etiqueta técnica.
- Los informes ya no llevan autor por defecto: si `auditor`, `web` o `email` están vacíos en `brand.json`, no aparecen. Cada auditor firma con su `brand.local.json`.
- `brand.json` admite `tipografias`, `severidad_texto` y cualquier color en `colores`, que llegan al CSS como variables.
- Banner «retícula»: cuervo heráldico con las alas abiertas (facetas oscuras, contorno verde, pico verde y ojo neón) en el centro de un radar, con «CORVUS RED» en Chakra Petch y esquinas de visor. Lleva las fuentes incrustadas y sirve también como vista previa social: `assets/social-preview.png` (1280×640).

## [1.1.0] — 2026-11-24

### Añadido
- Ficha nueva `xssi` (inclusión de scripts entre sitios: JSONP, JavaScript dinámico, condiciones de SameSite).
- `xss` §4.14: inyección HTML sin JavaScript (suplantación, formularios falsos, `<base>`, correos transaccionales).
- `authentication` §4.11: variantes de teléfono (RFC 3966) y de códigos OTP para saltarse los límites de intentos.
- `01-reconocimiento` §1.1: dorking en Google, Bing, GitHub, Shodan y Censys.
- `config-exposure` §4.14: método para CVE de productos perimetrales y CMS (CISA KEV y plantillas de nuclei).
- `payloads/upload/`: kit de ficheros PoC inocuos (SVG, HTML y políglotas con magic bytes) y guía de variantes de nombre.

## [1.0.0] — 2026-11-24

### Añadido
- `SKILL.md` con 10 reglas innegociables, flujo de encargo de 7 fases y 7 modos de trabajo (caja negra, caja gris, API, IA/LLM, caja blanca, híbrido y consulta).
- 7 guías de fase: alcance y ROE, reconocimiento, cobertura OWASP WSTG, caza, validación en 7 puertas, informe y herramientas.
- 32 fichas de vulnerabilidad con plantilla común de 13 secciones, y 3 guías de caja blanca (metodología, sumideros por lenguaje, secretos y dependencias).
- `scripts/corvus.py`: `init`, `scope-check`, `http`, `jwt`, `redact`, `status`, `cvss` y `report` (Markdown, HTML y PDF con la marca, en ES/EN).
- Informe de ejemplo contra OWASP Juice Shop (`examples/juice-shop/`).

### Validado
- Prueba de punta a punta contra OWASP Juice Shop 20.4: 11 hallazgos validados en dos rondas por un subagente validador independiente.
