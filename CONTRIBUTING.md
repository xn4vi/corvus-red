# Cómo contribuir

¡Gracias por querer mejorar CORVUS Red! Las contribuciones más útiles son fichas nuevas, mejoras de payloads, correcciones técnicas y mejoras de `corvus.py`.

## Reglas de contenido

1. **Idioma:** castellano claro. Define cada término técnico la primera vez y evita el spanglish innecesario. Las herramientas, cabeceras, payloads y el código se quedan en su forma original.
2. **Plantilla:** cada ficha de `references/vulns/` sigue las 13 secciones de las existentes (clasificación → qué es → dónde buscar → detección segura → explotación → evasión → escalada → caja blanca → falsos positivos → evidencia → severidad → remediación → herramientas → referencias).
3. **Seguridad primero:** marca con ⚠️ y «requiere confirmación explícita del cliente» todo payload con efectos reales (modificar datos, DoS, persistencia, shells). Prioriza las pruebas de solo lectura.
4. **Nada inventado:** no cites CVE, parámetros de herramientas ni puntuaciones CVSS que no puedas verificar. Si dudas, márcalo («verificar versión»).
5. **Licencias:** no copies texto de fuentes sin licencia compatible. Los payloads y hechos técnicos son reutilizables; la prosa, no.

## Flujo

```bash
git checkout -b feat/mi-mejora
python -m unittest discover -s tests -v      # tests del script
python tools/check_refs.py                   # enlaces internos entre fichas
git commit -m "feat(vulns): añade ficha de XS-Leaks"
```

Abre un pull request describiendo qué cambia y cómo lo has probado (idealmente contra un laboratorio: Juice Shop, DVWA, PortSwigger Academy…).
