# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y versionado [SemVer](https://semver.org/lang/es/).

## [1.2.0] — 2026-11-25

### Cambiado
- Identidad visual de **CORVUS Red by Iván Pérez** ([ivanperezf.es](https://ivanperezf.es)): escudo con el píxel verde, verde corporativo `#166534`, fondo claro con trama de puntos y colores de severidad de la web.
- Informe rediseñado: portada clara, cuadrado y filete verdes en los títulos, severidades con cuadrado de color y etiqueta técnica, y web y correo de contacto en la portada.
- `brand.json` admite `tipografias`, `severidad_texto` y cualquier color en `colores`; todos llegan al CSS como variables.
- `corvus.py report` incrusta las fuentes `.woff2` que haya en `assets/fonts/`.
- README, banner y LICENSE con la autoría de Iván Pérez.

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
