# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y versionado [SemVer](https://semver.org/lang/es/).

## [1.0.0] — 2026-11-24

### Añadido
- `SKILL.md` con 10 reglas innegociables, flujo de encargo de 7 fases y 7 modos de trabajo (caja negra, caja gris, API, IA/LLM, caja blanca, híbrido y consulta).
- 7 guías de fase: alcance y ROE, reconocimiento, cobertura OWASP WSTG, caza, validación en 7 puertas, informe y herramientas.
- 32 fichas de vulnerabilidad con plantilla común de 13 secciones, y 3 guías de caja blanca (metodología, sumideros por lenguaje, secretos y dependencias).
- `scripts/corvus.py`: `init`, `scope-check`, `http`, `jwt`, `redact`, `status`, `cvss` y `report` (Markdown, HTML y PDF con la marca, en ES/EN).
- Informe de ejemplo contra OWASP Juice Shop (`examples/juice-shop/`).

### Validado
- Prueba de punta a punta contra OWASP Juice Shop 20.4: 11 hallazgos validados en dos rondas por un subagente validador independiente.
