# Secretos, dependencias, cadena de suministro e IaC

> Parte de la revisión white-box ([metodologia.md](metodologia.md)). Cubre: secretos expuestos, análisis de dependencias (SCA) y su triaje, riesgos de cadena de suministro y comprobaciones rápidas de infraestructura como código relevantes para auditar una aplicación web.
> Mapeo principal OWASP Top 10:2025: **A03** Software Supply Chain Failures, **A08** Software or Data Integrity Failures, **A02** Security Misconfiguration, **A04** Cryptographic Failures (secretos).

## Contenido

1. Detección de secretos: dónde buscar y regex
2. Historial de git, CI, capas Docker, bundles y source maps
3. Validación y reporte de secretos (sin salirse del alcance)
4. SCA: ejecutar y, sobre todo, triar
5. Cadena de suministro: confusión de dependencias, typosquatting, scripts de instalación, CI/CD
6. Comprobaciones rápidas de IaC, Docker y Kubernetes
7. Checklist

---

## 1. Detección de secretos

Un **secreto** es cualquier valor que da acceso por sí mismo: claves de API, contraseñas, tokens, claves privadas, cadenas de conexión, claves de firma (JWT, cookies, `secret_key_base`), webhooks con token en la URL.

### 1.1 Herramientas

```bash
# gitleaks (v8.19+: subcomandos git/dir; en versiones anteriores: gitleaks detect --source . / --no-git)
gitleaks git -v --report-format json --report-path out/gitleaks-hist.json .      # historial completo
gitleaks dir -v --report-format json --report-path out/gitleaks-tree.json .      # árbol actual sin git

# trufflehog: muchos detectores; con verificación contacta con el proveedor real
trufflehog git file://. --no-verification --json > out/th-git.json
trufflehog filesystem . --no-verification --json > out/th-fs.json
trufflehog docker --image registro/app:tag --no-verification --json > out/th-img.json

# Semgrep y Trivy como segunda opinión
semgrep scan --config p/secrets --json -o out/semgrep-secrets.json
trivy fs --scanners secret .
```

`--no-verification` evita que la herramienta pruebe las credenciales contra servicios de terceros. Activa la verificación solo si el alcance lo permite (ver §3).

### 1.2 Regex de formatos comunes (para `rg -n -P`)

| Secreto | Regex |
|---|---|
| AWS Access Key ID | `\b(AKIA\|ASIA\|ABIA\|ACCA)[0-9A-Z]{16}\b` |
| AWS Secret Key (con contexto) | `(?i)aws.{0,30}(secret\|sk).{0,20}['"][A-Za-z0-9/+]{40}['"]` |
| GitHub tokens | `\bgh[pousr]_[A-Za-z0-9]{36,}\b` · `\bgithub_pat_[A-Za-z0-9_]{22,}\b` |
| GitLab PAT | `\bglpat-[A-Za-z0-9_-]{20,}\b` |
| Slack token / webhook | `\bxox[abprs]-[A-Za-z0-9-]{10,}` · `https://hooks\.slack\.com/services/[A-Za-z0-9/]+` |
| Stripe | `\b(sk\|rk)_(live\|test)_[A-Za-z0-9]{20,}\b` |
| Google API key | `\bAIza[0-9A-Za-z_-]{35}\b` |
| Google OAuth client secret | `\bGOCSPX-[A-Za-z0-9_-]{20,}` |
| Cuenta de servicio GCP | `"type"\s*:\s*"service_account"` |
| Azure Storage | `AccountKey=[A-Za-z0-9+/=]{80,}` · `(?i)sig=[A-Za-z0-9%]{30,}` (SAS) |
| Clave privada | `-----BEGIN ([A-Z]+ )?PRIVATE KEY( BLOCK)?-----` |
| JWT | `\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}` |
| SendGrid | `\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b` |
| Twilio | `\b(AC\|SK)[0-9a-f]{32}\b` |
| npm / PyPI | `\bnpm_[A-Za-z0-9]{36}\b` · `\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}` |
| Docker Hub PAT | `\bdckr_pat_[A-Za-z0-9_-]{20,}` |
| HashiCorp Vault | `\bhv[sbr]\.[A-Za-z0-9_-]{20,}` |
| LLM APIs | `\bsk-ant-[A-Za-z0-9_-]{20,}` · `\bsk-(proj-)?[A-Za-z0-9_-]{20,}` |
| URL con credenciales | `[a-z][a-z0-9+.-]*://[^/\s:@'"]+:[^/\s:@'"]+@[^/\s'"]+` |
| Asignación genérica | `(?i)(password\|passwd\|pwd\|secret\|token\|api[_-]?key\|client[_-]?secret\|private[_-]?key)\s*[:=]\s*['"][^'"\s]{8,}['"]` |
| Claves de framework | `(?i)(SECRET_KEY\|secret_key_base\|APP_KEY\|JWT_SECRET\|SESSION_SECRET\|NEXTAUTH_SECRET)\s*[:=]` |

En tablas los `\|` son escapes de Markdown: al pegar en la terminal usa `|`. Ejemplo:

```bash
rg -n -P --hidden -g '!.git' '\b(AKIA|ASIA)[0-9A-Z]{16}\b|-----BEGIN ([A-Z]+ )?PRIVATE KEY|\bgh[pousr]_[A-Za-z0-9]{36,}|\bAIza[0-9A-Za-z_-]{35}\b|\bxox[abprs]-'
```

### 1.3 Ficheros que hay que mirar siempre

```bash
fd -H -I -t f '(^\.env(\..*)?$|\.pem$|\.key$|\.p12$|\.pfx$|\.jks$|\.keystore$|id_rsa|\.npmrc$|\.pypirc$|\.netrc$|\.git-credentials$|credentials(\.json)?$|secrets?\.(ya?ml|json)$|terraform\.tfstate(\.backup)?$|\.tfvars$|kubeconfig|\.dockercfg$|config\.json$)' 
rg -n --hidden -g 'appsettings*.json' -g 'application*.{yml,yaml,properties}' -g 'settings*.py' -g '.env*' -g 'wp-config.php' -g 'config/*.{yml,rb,php,js,ts}' -i 'password|secret|key|token|connectionstring'
```

Ojo con: `.env.example` con valores reales, ficheros de test con credenciales de entornos compartidos, `docker-compose.yml` con contraseñas de BD, `terraform.tfstate` (guarda en claro los valores de recursos y salidas), `config/master.key` y `credentials.yml.enc` (Rails), `appsettings.Development.json`, notebooks `.ipynb` con salidas.

---

## 2. Historial, CI, capas Docker, bundles y source maps

### 2.1 Historial de git

Un secreto borrado en un commit posterior **sigue** en el historial y en los clones. Se considera expuesto y debe rotarse.

```bash
git log --all --oneline | wc -l
git log -p --all -S 'AKIA' --source                     # commits que añaden o quitan la cadena
git log -p --all -G '(?i)(password|secret|api_key)\s*='  # por regex en diffs
git log --all --diff-filter=D --name-only --format='%h %s' | rg -i '\.env|\.pem|key|secret|credential'
git rev-list --all | xargs -n 200 git grep -I -n -E 'BEGIN (RSA|EC|OPENSSH) PRIVATE KEY' 2>/dev/null | head
git fsck --lost-found 2>/dev/null | head              # objetos colgantes (commits reescritos)
git stash list; git for-each-ref                        # stashes, ramas y tags olvidados
```

Si el cliente da acceso a la plataforma (GitHub/GitLab), revisa también: PR cerradas, forks, wikis, issues, releases con artefactos, logs de ejecuciones de CI.

### 2.2 Ficheros de CI/CD

```bash
rg -n --hidden -g '.github/workflows/*' -g '.gitlab-ci.yml' -g 'Jenkinsfile' -g 'azure-pipelines.yml' -g 'bitbucket-pipelines.yml' -g '.circleci/*' \
  -i 'password|token|secret|key|AKIA|echo \$|set -x|curl .*-u '
```

Busca: secretos literales en `env:`; `set -x` o `echo $SECRET` (los imprimen en logs; el enmascarado de la plataforma se salta con codificación); secretos pasados como argumentos de línea de comandos (visibles en `ps`); artefactos de build que incluyen `.env`.

### 2.3 Capas de imágenes Docker

Un `RUN rm secreto` en una capa posterior no borra el secreto de la capa anterior.

```bash
docker history --no-trunc registro/app:tag              # ARG/ENV y comandos con secretos
docker save registro/app:tag -o out/app.tar && mkdir out/app && tar -xf out/app.tar -C out/app
# Cada capa es un tar: extraer y buscar
find out/app -name '*.tar' -o -name 'layer.tar' | while read l; do tar -tf "$l" | rg -i '\.env|\.pem|id_rsa|credentials|\.npmrc' | sed "s|^|$l: |"; done
dive registro/app:tag                                   # explorador interactivo de capas
trufflehog docker --image registro/app:tag --no-verification
```

### 2.4 Bundles de front-end y source maps

El JavaScript servido al navegador es público: cualquier clave que esté en él está expuesta. Variables con prefijo `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `NUXT_PUBLIC_` o `environment.ts` de Angular acaban en el bundle.

```bash
# En el repo: qué se inyecta en build
rg -n '(NEXT_PUBLIC|VITE|REACT_APP|NUXT_PUBLIC|PUBLIC)_\w+' -g '!node_modules'
# En el build o en la instancia
rg -n -P -o '(AIza[0-9A-Za-z_-]{35}|sk_live_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|https?://[^"'\''\s]*(internal|staging|dev|admin)[^"'\''\s]*)' dist/ build/ .next/static/ 2>/dev/null | sort -u
# Source maps: ¿se publican? (revelan el código original, comentarios y rutas internas)
curl -s https://objetivo/static/js/main.js | tail -c 300 | rg sourceMappingURL
```

Reconstruir el código fuente desde un `.map` (los mapas suelen traer `sourcesContent`):

```bash
python3 - main.js.map out/src <<'PY'
import json, os, sys
m = json.load(open(sys.argv[1])); base = sys.argv[2]
for name, content in zip(m.get("sources", []), m.get("sourcesContent") or []):
    if content is None: continue
    safe = os.path.normpath(name.replace("webpack://", "").lstrip("./")).replace("..", "_")
    path = os.path.join(base, safe); os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "w", encoding="utf-8").write(content)
PY
```

Después aplica sobre `out/src` las regex de secretos y las de sumideros front-end de [sinks-por-lenguaje.md §8](sinks-por-lenguaje.md#8-front-end-dom-react-angular-vue). Hallazgo: [config-exposure](../vulns/config-exposure.md).

---

## 3. Validación y reporte de secretos

- **Clasifica** antes de probar: ¿producción, staging, test?, ¿revocado?, ¿de un tercero (Stripe, AWS) o propio de la app (clave JWT, `APP_KEY`)?
- **Usar una credencial encontrada contra un servicio de terceros puede estar fuera del alcance** aunque el encargo sea autorizado. Pide confirmación explícita al cliente antes de verificarla; si se aprueba, usa solo llamadas de identidad de solo lectura (p. ej. `aws sts get-caller-identity`) y nunca accedas a datos.
- Las claves propias de la app sí se pueden demostrar en el entorno de pruebas: con la clave de firma JWT o `secret_key_base` se forjan tokens/cookies ([jwt](../vulns/jwt.md), [session](../vulns/session.md), [deserialization](../vulns/deserialization.md) para cookies serializadas).
- **En el informe nunca pegues el secreto completo**: muestra prefijo y sufijo (`AKIA…7Q2X`), fichero, commit (`sha`), fecha y autor del commit.
- **Recomendación siempre**: rotar/revocar (borrar del repo no basta), limpiar historial si procede (`git filter-repo`), activar *push protection*/escaneo de secretos, mover a un gestor de secretos.

---

## 4. SCA: ejecutar y triar

**SCA** (Software Composition Analysis) compara las versiones de las librerías de terceros con bases de vulnerabilidades conocidas (OSV, GitHub Advisory, NVD). El ruido es enorme; el valor está en el triaje.

### 4.1 Ejecución por ecosistema

```bash
osv-scanner scan source -r . --format json > out/osv.json   # v2; v1: osv-scanner -r . / --lockfile=<fichero>
trivy fs --scanners vuln --format json -o out/trivy-vuln.json .
syft dir:. -o cyclonedx-json > out/sbom.json && grype sbom:out/sbom.json -o json > out/grype.json
dependency-check.sh --scan . --format JSON --out out/dc        # OWASP Dependency-Check (Java/.NET; lento)

npm audit --omit=dev --json > out/npm-audit.json               # pnpm audit / yarn npm audit
pip-audit -r requirements.txt -f json -o out/pip-audit.json    # o en el venv del proyecto: pip-audit
composer audit --format=json > out/composer-audit.json
bundle-audit check --update                                    # Ruby (gem bundler-audit)
govulncheck ./...                                              # Go: informa solo si se llama a la función vulnerable
dotnet list package --vulnerable --include-transitive          # .NET
mvn -q dependency:tree -DoutputFile=out/deptree.txt ; gradle dependencies > out/gradle-deps.txt
cargo audit                                                    # Rust
```

### 4.2 Triaje: ¿importa de verdad?

Para cada aviso, responde en orden:

1. **¿La versión vulnerable es la que se despliega?**
   - Manda el **lockfile** (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `Pipfile.lock`, `composer.lock`, `Gemfile.lock`, `go.sum`, `packages.lock.json`), no el manifiesto. Un manifiesto con `^1.2.0` no dice qué versión se instaló.
   - Sin lockfile (p. ej. `requirements.txt` sin versiones fijas) la versión depende del día del build: hallazgo en sí mismo (builds no reproducibles, A03/A08).
   - Compara con lo desplegado: SBOM de la imagen (`syft registro/app:tag`), `npm ls paquete`, `pip show paquete`, `go version -m binario`, cabeceras/ficheros de versión en la instancia.
   - Dependencias de desarrollo (`devDependencies`, grupos `dev`/`test`) normalmente no llegan a producción, salvo en SSR/bundles o si la imagen instala todo.
2. **¿Es alcanzable la función vulnerable?** Lee el aviso: identifica la función o característica afectada (p. ej. "solo si se usa `merge` con datos del usuario", "solo al parsear YAML no confiable").
   ```bash
   rg -n "from 'lodash'|require\('lodash'\)|lodash\.(merge|set|zipObjectDeep)" -g '!node_modules'
   rg -n 'yaml\.load\(|Yaml\(\)\.load' ; rg -n 'import .*paquete_vulnerable'
   ```
   `govulncheck` hace este análisis automáticamente en Go; CodeQL o una regla Semgrep pueden comprobarlo en otros lenguajes. Si es una dependencia transitiva, identifica qué dependencia directa la usa y si esa ruta se ejecuta con datos del atacante.
3. **¿Es explotable en este contexto?** ¿La entrada del atacante llega a esa función? ¿Configuración que lo impide? ¿Requiere autenticación?
4. **Prioriza** con contexto: severidad del aviso + alcanzabilidad + exposición. Las listas de explotación activa (CISA KEV) y la probabilidad de explotación (EPSS) ayudan a ordenar; no sustituyen el análisis de alcanzabilidad.
5. **Reporta** como hallazgo solo lo alcanzable o de severidad crítica con exposición plausible; el resto, agrupado en un anexo "dependencias desactualizadas" con la acción recomendada (actualizar a la versión X, que corrige el aviso).

No cites un CVE sin comprobar su identificador y versiones afectadas en la fuente (OSV/GHSA/NVD). Si la herramienta da un GHSA sin CVE, cita el GHSA.

### 4.3 Otros problemas de dependencias

- Librerías **abandonadas** o sin mantenimiento (último release hace años, repositorio archivado), por ejemplo `vm2`, `request`.
- Código **vendorizado o copiado** (`vendor/`, `third_party/`, `static/js/jquery-1.x.min.js`): el SCA basado en manifiestos no lo ve. Busca cabeceras de versión: `rg -n -o 'jQuery v[0-9.]+|Bootstrap v[0-9.]+|lodash [0-9.]+|AngularJS v[0-9.]+' static/ public/`.
- Dependencias desde **URL o git** sin hash (`"pkg": "git+https://..."`, `pip install git+https://...@main`).
- Integridad del lockfile: URLs `resolved` que apuntan a hosts inesperados, `integrity` ausentes. `npx lockfile-lint --path package-lock.json --allowed-hosts npm --validate-https`.

---

## 5. Cadena de suministro

### 5.1 Confusión de dependencias (dependency confusion)

Si la empresa usa paquetes internos con nombres que **no existen** en el registro público y el gestor consulta ambos registros, un atacante puede publicar ese nombre en el registro público con una versión mayor y conseguir que se instale.

Qué revisar en el código:

```bash
# Nombres de paquetes internos
jq -r '.dependencies,.devDependencies|keys[]' package.json | rg -v '^@' ; rg -n 'extra-index-url|index-url' -g '*.txt' -g '*.cfg' -g '*.toml' -g 'pip.conf' -g 'Dockerfile*'
cat .npmrc .yarnrc.yml 2>/dev/null ; rg -n '<repository>|<mirror>' -g 'pom.xml' -g 'settings.xml' ; rg -n 'packageSource' -g 'NuGet.config'
# ¿Existe el nombre en el registro público? (solo consulta)
npm view nombre-interno version 2>&1 | head -1
curl -s -o /dev/null -w '%{http_code}\n' https://pypi.org/pypi/nombre-interno/json
```

Indicadores de riesgo: paquetes sin *scope* (`@empresa/`) y sin publicar en npm; pip con `--extra-index-url` (pip elige la versión más alta entre todos los índices) en vez de un único índice proxy; Maven/Gradle con repositorios públicos antes que el interno sin filtros de grupo; NuGet con varias fuentes y sin *package source mapping*. Corrección: scopes reservados en el registro público, un único registro proxy, mapeo de fuentes, versiones fijadas con hash. Herramienta de apoyo: `confused` (comprueba nombres de manifiestos contra el registro público).

### 5.2 Typosquatting y paquetes maliciosos

Nombres casi idénticos a paquetes populares (`reqeusts`, `crossenv`, `electorn`), paquetes con pocas descargas y recién publicados, mantenedores cambiados recientemente. Revisa las dependencias **directas** una a una en proyectos pequeños; en grandes, las añadidas en el último periodo (`git log -p -- package.json`).

### 5.3 Scripts de instalación

```bash
# npm: scripts que se ejecutan al instalar
jq -r '.scripts | to_entries[] | select(.key|test("^(pre|post)?install$|^prepare$")) | "\(.key): \(.value)"' package.json
rg -l '"(pre|post)?install"\s*:' node_modules/*/package.json node_modules/@*/*/package.json 2>/dev/null | head -50
# Python: setup.py con código arbitrario; Ruby: extconf.rb; Composer: "scripts" en composer.json
```

Recomienda `npm ci --ignore-scripts` en CI cuando sea posible, `pip install --require-hashes` con lockfile con hashes, y construir en entornos sin secretos.

### 5.4 GitHub Actions y otros CI

```bash
rg -n 'uses:\s*[^@]+@(v?[0-9.]+|main|master|latest)\s*$' .github/workflows/     # acciones no fijadas a SHA
rg -n 'pull_request_target|workflow_run' .github/workflows/
rg -n '\$\{\{\s*github\.event\.(issue|pull_request|comment|review|head_commit|commits)|github\.head_ref' .github/workflows/
rg -n '^permissions:|write-all|contents:\s*write|id-token:\s*write' .github/workflows/
rg -n 'runs-on:\s*\[?self-hosted' .github/workflows/
zizmor .github/workflows/          # analizador de seguridad de workflows
actionlint                         # linter (incluye detección de inyección en run:)
```

| Problema | Por qué es grave | Corrección |
|---|---|---|
| `uses: tercero/accion@v1` | El tag es mutable; si comprometen la acción, se ejecuta código ajeno con tus secretos | fijar a SHA completo de commit + Dependabot |
| `pull_request_target` + `actions/checkout` de `github.event.pull_request.head.sha` y build | Código de un fork se ejecuta con secretos y token con escritura | usar `pull_request`; separar workflows privilegiados |
| `run: echo "${{ github.event.issue.title }}"` | Inyección de comandos: el título lo escribe cualquiera | pasar a `env:` y usar `"$VAR"` |
| Sin `permissions:` o `write-all` | `GITHUB_TOKEN` con más permisos de los necesarios | `permissions: contents: read` por defecto |
| Runners self-hosted en repos públicos | Persistencia en la máquina del runner, acceso a red interna | runners efímeros, solo repos privados |
| OIDC con política de confianza amplia (`sub` con comodines de toda la organización) | Cualquier repo/rama de la organización asume el rol cloud | restringir `sub` a repo + rama/entorno |
| Caché/artefactos compartidos entre workflows de distinta confianza | Envenenamiento de caché | claves de caché separadas, no restaurar caché en jobs privilegiados |

Para otros CI: GitLab (`rules` que ejecutan jobs con variables protegidas en ramas no protegidas, `include:` remotos sin `ref` fijo), Jenkins (`Jenkinsfile` de PR ejecutado con credenciales, `sh "... ${params.X}"`), Azure DevOps (variables secretas en pipelines de PR de forks). Detalle ofensivo en [config-exposure](../vulns/config-exposure.md). Mapeo: A03/A08.

### 5.5 Integridad de artefactos y actualizaciones

- Descargas en build o en runtime sin verificar hash/firma (`curl … | sh`, `ADD https://…` en Dockerfile, `wget` de binarios).
- Actualizaciones automáticas de la app o plugins sin firma.
- Deserialización de datos "propios" que viajan por el cliente (cookies, campos ocultos, ViewState) sin MAC ([deserialization](../vulns/deserialization.md)). Mapeo: A08.

---

## 6. Comprobaciones rápidas de IaC, Docker y Kubernetes

**IaC** (infraestructura como código): Terraform, CloudFormation, Bicep, Helm, manifiestos de Kubernetes, Compose. No es una auditoría cloud completa: se mira lo que afecta a la aplicación web.

```bash
checkov -d . --compact --quiet            # Terraform, CFN, K8s, Helm, Dockerfile, GH Actions
trivy config .                            # misconfig IaC/Dockerfile/K8s
hadolint Dockerfile
semgrep scan --config p/dockerfile --config p/terraform --config p/kubernetes
```

### 6.1 Dockerfile y Compose

```bash
rg -n -i '^(ARG|ENV)\s+\w*(PASS|SECRET|TOKEN|KEY)' -g 'Dockerfile*'
rg -n '^USER|^FROM .*:latest|^FROM [^:@]+$|^ADD https?://|curl[^|]*\|\s*(ba)?sh|COPY \. ' -g 'Dockerfile*'
ls -a .dockerignore 2>/dev/null || echo "SIN .dockerignore (COPY . . puede meter .env y .git)"
rg -n 'privileged:\s*true|/var/run/docker\.sock|network_mode:\s*host|cap_add|"?0\.0\.0\.0:?(3306|5432|6379|27017|9200)|POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD' -g 'docker-compose*.y*ml' -g 'compose*.y*ml'
```

Fallos típicos: contenedor como root (sin `USER`), secretos en `ARG`/`ENV` (quedan en la imagen; usar `RUN --mount=type=secret`), imagen base sin fijar o enorme, `COPY . .` sin `.dockerignore`, BD/Redis/Elasticsearch publicados en todas las interfaces sin auth, `docker.sock` montado (control total del host), modo debug activado por variables de entorno.

### 6.2 Kubernetes / Helm

```bash
rg -n 'privileged:\s*true|allowPrivilegeEscalation:\s*true|runAsUser:\s*0|hostNetwork:\s*true|hostPID:\s*true|hostPath:|automountServiceAccountToken:\s*true|readOnlyRootFilesystem:\s*false' -g '*.y*ml'
rg -n 'kind:\s*(ClusterRole|Role)' -A 15 -g '*.y*ml' | rg '"\*"|\*\]|verbs:.*\*'
rg -n 'kind:\s*ConfigMap' -A 20 -g '*.y*ml' | rg -i 'password|secret|token|key'
rg -n 'kind:\s*Secret' -A 10 -g '*.y*ml' | rg 'data:|stringData:'        # secretos (base64 no es cifrado) en el repo
rg -n 'nginx\.ingress\.kubernetes\.io/(configuration-snippet|server-snippet|auth-url)|type:\s*(NodePort|LoadBalancer)' -g '*.y*ml'
```

Fallos típicos: pods privilegiados o con `hostPath` (escape al nodo), token de service account montado sin necesidad + RBAC amplio (SSRF en la app → API de Kubernetes), `Secret` versionado en el repo, ConfigMaps con contraseñas, servicios internos (admin, métricas, Redis) expuestos con `LoadBalancer`, falta de `NetworkPolicy` (la app puede alcanzar todo el clúster en caso de SSRF: ver [ssrf](../vulns/ssrf.md)).

### 6.3 Terraform / cloud relevante para la app

```bash
rg -n 'acl\s*=\s*"public-read|block_public_(acls|policy)\s*=\s*false|publicly_accessible\s*=\s*true|cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]|"Action"\s*:\s*"\*"|"Resource"\s*:\s*"\*"|http_tokens\s*=\s*"optional"|encrypted\s*=\s*false|skip_final_snapshot' -g '*.tf' -g '*.tf.json'
git ls-files | rg 'tfstate|\.tfvars$'
```

Lo más relevante para una app web: buckets públicos con subidas de usuarios o backups, BD accesible desde Internet, grupos de seguridad abiertos a `0.0.0.0/0` en puertos de administración, IMDSv1 permitido (`http_tokens = "optional"`: un SSRF obtiene credenciales del rol), roles IAM de la app con `*`, `terraform.tfstate` versionado (contiene secretos en claro), CORS de buckets con `*`. Mapeo: A02 (y A01 si permite acceso a datos).

---

## 7. Checklist

- [ ] gitleaks/trufflehog sobre árbol actual **e** historial completo (todas las ramas y tags).
- [ ] Ficheros sensibles (`.env*`, claves, `tfstate`, `kubeconfig`, `.npmrc`, notebooks) revisados.
- [ ] CI/CD: secretos literales, impresión en logs, `pull_request_target`, inyección `${{ github.event.* }}`, acciones sin fijar a SHA, `permissions`, runners self-hosted, OIDC.
- [ ] Imagen Docker: `docker history`, capas extraídas, `.dockerignore`.
- [ ] Bundle front-end y source maps: claves públicas/privadas, endpoints internos, código fuente reconstruido.
- [ ] Secretos clasificados; verificación con terceros **solo con autorización explícita**; secretos enmascarados en el informe; rotación recomendada.
- [ ] SCA sobre lockfiles + SBOM de la imagen desplegada; versiones contrastadas con producción.
- [ ] Cada aviso relevante triado: versión desplegada, alcanzabilidad de la función, explotabilidad, exposición.
- [ ] Código vendorizado/copiado y librerías abandonadas identificados.
- [ ] Riesgo de confusión de dependencias (nombres internos, registros, `--extra-index-url`, scopes).
- [ ] Scripts de instalación y dependencias por URL/git revisados.
- [ ] Dockerfile/Compose, Kubernetes/Helm, Terraform: lo que afecta a la app (exposición, privilegios, secretos, IMDS, buckets).
- [ ] Hallazgos mapeados a A03/A08/A02/A04 con CWE (798 credenciales embebidas, 1104 componentes sin mantener, 1395 dependencia vulnerable, 829 inclusión de funcionalidad no confiable, 494 descarga sin integridad).
