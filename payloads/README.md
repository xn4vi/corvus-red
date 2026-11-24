# Kit de ficheros PoC inocuos

Ficheros listos para probar subidas, renderizadores y parsers **sin causar daño**. Ninguno ejecuta órdenes, abre shells ni roba datos. Lo único que hacen es escribir un marcador en la consola, hacer una petición OAST o imprimir `CORVUS-9359` (`1337 × 7`).

## Antes de usarlos

1. **Sustituye `OAST_DOMAIN`** por tu dominio de interactsh o de Burp Collaborator:

   ```bash
   sed -i 's/OAST_DOMAIN/abc123.oast.fun/g' payloads/upload/*.svg payloads/upload/*.html
   ```

2. **Haz una copia por prueba** y renómbrala según la variante (ver la tabla de abajo). No subas el original.
3. Registra cada subida con `corvus.py http … --save` o en `payload-log.md`, y **borra los ficheros** al terminar (`00-alcance-roe.md` §5).

## Ficheros

| Fichero | Para qué | Señal de éxito |
|---|---|---|
| `upload/corvus-xss.svg` | XSS al servir un SVG subido desde el origen de la aplicación | Consola: `CORVUS-XSS-SVG-<dominio>` |
| `upload/corvus-xss.html` | XSS al servir un HTML subido | Consola: `CORVUS-XSS-HTML-<dominio>-cookie_len=N` |
| `upload/corvus-blind-xss.svg` | XSS ciego en paneles internos que abren los ficheros | Petición OAST `/corvus-bxss?d=…&p=…` (sin cookies) |
| `upload/corvus-ssrf.svg` | SSRF en conversiones de SVG a imagen o PDF | Petición OAST `/corvus-ssrf-svg-*` desde una IP del servidor |
| `upload/corvus-xxe.svg` | XXE en parsers de SVG | Petición OAST `/corvus-xxe-svg` |
| `upload/corvus-redirect.html` | Redirección abierta desde un HTML alojado en el dominio | Navegación a `example.com/?corvus=upload-redirect` |
| `upload/corvus-html-injection.html` | Inyección HTML sin JavaScript | Marcador visible y baliza OAST |
| `upload/corvus-marker.php.{gif,jpg,png,pdf}` | Ejecución en el servidor con magic bytes válidos (políglotas) | Al pedir el fichero, la respuesta contiene `CORVUS-9359` |

⚠️ Subir ficheros que el servidor podría **ejecutar** (`corvus-marker.*`, aunque sean inocuos) y los ficheros que verían usuarios reales requieren la confirmación explícita del cliente (`SKILL.md`, regla 4).

## Variantes de nombre que conviene probar

Pruébalas sobre el marcador correspondiente, de una en una y registrando cada intento:

| Técnica | Ejemplos |
|---|---|
| Extensión alternativa | `.php3` `.php4` `.php5` `.php7` `.phtml` `.phar` `.pht` `.pgif` · `.asp` `.aspx` `.ashx` `.asmx` `.cer` · `.jsp` `.jspx` `.jspf` |
| Mayúsculas y minúsculas | `.PhP` `.pHtMl` `.SVG` |
| Doble extensión | `corvus.php.jpg` · `corvus.jpg.php` |
| Triple extensión | `corvus.jpg.php.png` · `corvus.php.jpg.php` |
| Byte nulo y separadores | `corvus.php%00.jpg` · `corvus.php%2500.jpg` · `corvus.php;.jpg` · `corvus.php%0a.jpg` · `corvus.php%20` |
| Punto y espacio finales (Windows) | `corvus.php.` · `corvus.php ` · `corvus.php::$DATA` |
| Tipo declarado | Extensión de imagen con `Content-Type: image/png` y contenido políglota |

Más técnicas, el porqué de cada una y cómo validarlas: `references/vulns/file-upload.md`.

## Lo que este kit no incluye a propósito

- **Shells inversas o webshells funcionales:** si una prueba las requiere, se construyen para ese encargo con autorización expresa.
- **Bombas de píxeles o de descompresión** (denegación de servicio): solo se describen en la ficha y nunca se prueban sin permiso.
