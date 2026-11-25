#!/usr/bin/env python3
"""CORVUS Red — utilidades del encargo (solo biblioteca estándar).

Subcomandos:
  init <objetivo> [--nombre N] [--cliente C] [--idioma es|en] [--base engagements]
  scope-check <engagement> <url> [<url> ...]
  redact [<fichero>] [--in-place] [--check]
  status <engagement>
  cvss "<vector CVSS:3.1/...>"
  report <engagement> [--lang es|en] [--finding F-001] [--retest] [--no-pdf] [--force]
"""
from __future__ import annotations

import argparse
import datetime as _dt
import fnmatch
import html
import ipaddress
import json
import math
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

SKILL_DIR = Path(__file__).resolve().parent.parent
TEMPLATES = SKILL_DIR / "templates"

try:  # consola de Windows con acentos
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# --------------------------------------------------------------------------- utilidades


def read(p: Path) -> str:
    return p.read_text(encoding="utf-8") if p.exists() else ""


def write(p: Path, s: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(s, encoding="utf-8", newline="\n")


def slugify(target: str) -> str:
    t = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", target.strip())
    t = t.rstrip("/")
    return re.sub(r"[^A-Za-z0-9.-]+", "_", t).strip("_") or "objetivo"


def today() -> str:
    return _dt.date.today().isoformat()


def parse_frontmatter(text: str) -> tuple[dict, str]:
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", text, re.S)
    if not m:
        return {}, text
    meta = {}
    for line in m.group(1).splitlines():
        if ":" in line and not line.lstrip().startswith("#"):
            k, v = line.split(":", 1)
            meta[k.strip().lower()] = v.strip()
    return meta, m.group(2)


def md_sections(text: str, level: int = 2) -> dict:
    """Devuelve {titulo_en_minusculas: contenido} para encabezados del nivel dado."""
    out, cur, buf = {}, None, []
    prefix = "#" * level + " "
    for line in text.splitlines():
        if line.startswith(prefix) and not line.startswith(prefix + "#"):
            if cur is not None:
                out[cur] = "\n".join(buf).strip()
            cur, buf = line[len(prefix):].strip().lower(), []
        elif cur is not None:
            buf.append(line)
    if cur is not None:
        out[cur] = "\n".join(buf).strip()
    return out


def bold_fields(text: str) -> dict:
    out = {}
    for m in re.finditer(r"^\*\*([^*]+?):\*\*[ \t]*(.*)$", text, re.M):
        out[m.group(1).strip().lower()] = m.group(2).strip()
    return out


def bullets(section: str) -> list[str]:
    items = []
    for line in section.splitlines():
        m = re.match(r"^\s*[-*]\s+(.*)$", line)
        if not m:
            continue
        val = m.group(1).strip()
        val = re.split(r"\s+[—–]\s+|\s+-\s+", val, maxsplit=1)[0].strip()
        val = val.strip("`").strip()
        if val and val not in ("-",):
            items.append(val)
    return items


def resolve_engagement(arg: str) -> Path:
    p = Path(arg)
    if (p / "scope.md").exists():
        return p
    alt = Path("engagements") / arg
    if (alt / "scope.md").exists():
        return alt
    alt2 = Path("engagements") / slugify(arg)
    if (alt2 / "scope.md").exists():
        return alt2
    sys.exit(f"[!] No encuentro el encargo '{arg}' (busqué {p}, {alt}, {alt2}).")


# --------------------------------------------------------------------------- init


def cmd_init(a) -> None:
    slug = slugify(a.objetivo)
    base = Path(a.base) / slug
    if (base / "scope.md").exists():
        sys.exit(f"[!] Ya existe {base}/scope.md — no sobrescribo nada.")
    subs = {
        "{{OBJETIVO}}": a.objetivo,
        "{{NOMBRE}}": a.nombre or slug,
        "{{CLIENTE}}": a.cliente or "",
        "{{FECHA}}": today(),
        "{{IDIOMA}}": a.idioma,
    }
    for name in ("scope.md", "tech-stack.md", "coverage.md", "payload-log.md", "notes.md"):
        t = read(TEMPLATES / name)
        for k, v in subs.items():
            t = t.replace(k, v)
        write(base / name, t)
    for d in ("findings/en", "evidence", "report"):
        (base / d).mkdir(parents=True, exist_ok=True)
    write(base / "findings.md", f"# Hallazgos — {a.objetivo}\n\n_Sin hallazgos todavía._\n")
    # .gitignore si estamos en un repo
    gi_note = ""
    if Path(".git").exists():
        gi = Path(".gitignore")
        content = read(gi)
        if not re.search(rf"^/?{re.escape(a.base)}/?\s*$", content, re.M):
            write(gi, content + ("" if content.endswith("\n") or not content else "\n") + f"{a.base}/\n")
            gi_note = f"\n[+] Añadido '{a.base}/' a .gitignore (contiene datos del cliente)."
    print(f"[+] Encargo creado en {base}/")
    print("    scope.md · tech-stack.md · coverage.md · payload-log.md · notes.md · findings/ · evidence/ · report/")
    print("[!] Autorización: PENDIENTE — completa scope.md y confirma la autorización antes de enviar tráfico." + gi_note)


# --------------------------------------------------------------------------- scope-check


def _target(t: str):
    t = t.strip()
    if "://" not in t:
        t = "//" + t
    u = urlparse(t)
    host = (u.hostname or "").lower().rstrip(".")
    return (u.scheme or "").lower(), host, u.port, u.path or "/"


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _host_match(pat: str, host: str) -> bool:
    pat = pat.lower().rstrip(".")
    if pat.startswith("*."):
        root = pat[2:]
        return host.endswith("." + root)
    return fnmatch.fnmatchcase(host, pat)


def scope_match(pattern: str, target: str) -> bool:
    scheme, host, port, path = _target(target)
    p = pattern.strip().strip("`")
    # IP / CIDR
    if "/" in p and "://" not in p:
        try:
            net = ipaddress.ip_network(p, strict=False)
            return _is_ip(host) and ipaddress.ip_address(host) in net
        except ValueError:
            pass
    if _is_ip(p):
        return host == p
    if "://" not in p:
        p = "//" + p
    pu = urlparse(p)
    phost = (pu.hostname or "").lower()
    if not phost or not _host_match(phost, host):
        return False
    if pu.scheme and pu.scheme != "*" and scheme and pu.scheme.lower() != scheme:
        return False
    if pu.port and port and pu.port != port:
        return False
    if pu.port and not port:
        default = {"http": 80, "https": 443}.get(scheme)
        if default != pu.port:
            return False
    ppath = pu.path or ""
    if ppath in ("", "/", "/*", "*"):
        return True
    if any(c in ppath for c in "*?["):
        return fnmatch.fnmatchcase(path, ppath) or fnmatch.fnmatchcase(path + "/", ppath)
    base = ppath.rstrip("/")
    return path == base or path.startswith(base + "/")


def scope_load(eng: Path) -> dict:
    text = read(eng / "scope.md")
    secs = md_sections(text)
    clean = lambda xs: [x for x in xs if not x.startswith("(")]  # noqa: E731  — viñetas de comentario
    inc = clean(bullets(secs.get("en alcance", "") or secs.get("in scope", "")))
    exc = clean(bullets(secs.get("fuera de alcance", "") or secs.get("out of scope", "")))
    if any(x in ("*", "*.*", "http://*", "https://*") for x in exc):
        print("[!] scope.md: se ignora la exclusión comodín '*' (excluiría también lo que está en alcance). "
              "No hace falta: lo que no está en 'En alcance' ya sale DUDOSO.", file=sys.stderr)
        exc = [x for x in exc if x not in ("*", "*.*", "http://*", "https://*")]
    return {"text": text, "fields": bold_fields(text), "sections": secs, "in": inc, "out": exc}


def cmd_scope_check(a) -> None:
    eng = resolve_engagement(a.engagement)
    sc = scope_load(eng)
    auth = sc["fields"].get("autorización", sc["fields"].get("autorizacion", ""))
    worst = 0
    if not auth.upper().startswith("CONFIRMADA"):
        print(f"SIN AUTORIZACIÓN  — scope.md: Autorización = '{auth or 'vacío'}'. No envíes tráfico.")
        sys.exit(3)
    for t in a.urls:
        out_hit = next((p for p in sc["out"] if scope_match(p, t)), None)
        in_hit = next((p for p in sc["in"] if scope_match(p, t)), None)
        if out_hit:
            print(f"FUERA    {t}   (exclusión: {out_hit})")
            worst = max(worst, 1)
        elif in_hit:
            print(f"DENTRO   {t}   (patrón: {in_hit})")
        else:
            print(f"DUDOSO   {t}   (no aparece en ninguna lista — pregunta al auditor)")
            worst = max(worst, 2) if worst != 1 else 1
    sys.exit(worst)


# --------------------------------------------------------------------------- redact

SECRET_HEADERS = (
    "authorization|proxy-authorization|x-api-key|api-key|apikey|x-auth-token|x-access-token|"
    "x-csrf-token|x-xsrf-token|csrf-token|x-amz-security-token|x-session-token|x-goog-api-key|"
    "ocp-apim-subscription-key|private-token|x-vault-token"
)
SECRET_FIELDS = (
    "password|passwd|pwd|pass|secret|client_secret|token|access_token|refresh_token|id_token|"
    "api_key|apikey|api-key|session|sessionid|session_id|otp|totp|mfa_code|code_verifier|private_key|"
    "authorization|auth|credentials|jwt|csrf|csrf_token|_token|xsrf|"
    "current|current_password|old_password|oldpassword|new|new_password|newpassword|repeat|password_confirmation|"
    "passwordrepeat|confirm_password|pin|cvv|cvc"
)
SECRET_SUBSTR = (
    "password|passwd|pwd|secret|token|api_?key|apikey|session_?id|totp|otp_?code|credential|jwt|csrf|xsrf|"
    "private_?key|bearer|code_verifier|refresh|access_?key"
)
KEY_PATTERNS = [
    ("AWS-KEY", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b"),
    ("STRIPE", r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{10,}\b"),
    ("GITHUB", r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{30,}\b|\bgithub_pat_[0-9A-Za-z_]{40,}\b"),
    ("GITLAB", r"\bglpat-[0-9A-Za-z_-]{20,}\b"),
    ("SLACK", r"\bxox[abposr]-[0-9A-Za-z-]{10,}\b"),
    ("GOOGLE", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("ANTHROPIC", r"\bsk-ant-[0-9A-Za-z_-]{20,}\b"),
    ("OPENAI", r"\bsk-(?:proj-)?[0-9A-Za-z_-]{32,}\b"),
    ("JWT", r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"),
]
PRIVKEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)


def _mask(v: str, kind: str = "") -> str:
    v = v.strip()
    if not v or v.startswith("[REDACTED"):
        return v
    if kind == "" and re.match(r"^eyJ[A-Za-z0-9_-]+\.", v):
        kind = "JWT"
    tag = f"REDACTED-{kind}" if kind else "REDACTED"
    return f"[{tag} len={len(v)}]"


def redact_text(s: str) -> tuple[str, int]:
    n = 0

    def bump(x):
        nonlocal n
        n += 1
        return x

    # claves privadas
    s, k = PRIVKEY.subn("[REDACTED-PRIVATE-KEY]", s)
    n += k

    # cabeceras con secreto
    def hdr(m):
        name, val = m.group(1), m.group(2)
        if "[REDACTED" in val:
            return m.group(0)
        parts = val.split(None, 1)
        if name.lower() in ("authorization", "proxy-authorization") and len(parts) == 2:
            return bump(f"{name}: {parts[0]} {_mask(parts[1])}")
        return bump(f"{name}: {_mask(val)}")

    s = re.sub(rf"^({SECRET_HEADERS})[ \t]*:[ \t]*(.+)$", hdr, s, flags=re.I | re.M)

    # cookies
    def cookie(m):
        name, val = m.group(1), m.group(2)
        segs = [x.strip() for x in val.split(";")]
        out = []
        for i, seg in enumerate(segs):
            if "=" in seg and (name.lower() == "cookie" or i == 0):
                ck, cv = seg.split("=", 1)
                if cv and "[REDACTED" not in cv:
                    cv = _mask(cv)
                    bump(None)
                out.append(f"{ck}={cv}")
            else:
                out.append(seg)
        return f"{name}: " + "; ".join(x for x in out if x)

    s = re.sub(r"^(cookie|set-cookie)[ \t]*:[ \t]*(.+)$", cookie, s, flags=re.I | re.M)

    # campos JSON  "password": "valor"
    def jfield(m):
        if "[REDACTED" in m.group(3) or not m.group(3):
            return m.group(0)
        return bump(f'{m.group(1)}{m.group(2)}"{_mask(m.group(3))}"')

    s = re.sub(rf'("(?:{SECRET_FIELDS})")(\s*:\s*)"([^"]*)"', jfield, s, flags=re.I)
    # claves que CONTIENEN una palabra sensible (passwordRepeat, deluxeToken, totpSecret, x_api_key…)
    s = re.sub(rf'("[A-Za-z0-9_-]*(?:{SECRET_SUBSTR})[A-Za-z0-9_-]*")(\s*:\s*)"([^"]*)"', jfield, s, flags=re.I)

    # formularios y query strings  password=valor
    def ffield(m):
        if m.group(3).startswith("[REDACTED") or not m.group(3):
            return m.group(0)
        return bump(f"{m.group(1)}{m.group(2)}={_mask(m.group(3))}")

    s = re.sub(rf"(^|[?&\s])((?:{SECRET_FIELDS}))=([^&\s\"'<>]+)", ffield, s, flags=re.I | re.M)

    # formatos de clave conocidos y JWT sueltos
    for kind, pat in KEY_PATTERNS:
        s = re.sub(pat, lambda m, k=kind: bump(_mask(m.group(0), k)), s)
    return s, n


def cmd_redact(a) -> None:
    if a.file:
        p = Path(a.file)
        src = read(p)
    else:
        src = sys.stdin.read()
    out, n = redact_text(src)
    if a.check:
        print(f"{n} posibles secretos sin tachar" + (f" en {a.file}" if a.file else ""))
        sys.exit(1 if n else 0)
    if a.in_place and a.file:
        write(Path(a.file), out)
        print(f"[+] {n} valores tachados en {a.file}", file=sys.stderr)
    else:
        sys.stdout.write(out)
        print(f"[+] {n} valores tachados", file=sys.stderr)


# --------------------------------------------------------------------------- CVSS 3.1

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss31(vector: str) -> float:
    v = vector.strip()
    if not v.upper().startswith("CVSS:3."):
        raise ValueError("solo se calcula CVSS 3.x (para 4.0 usa la calculadora de FIRST)")
    m = dict(part.split(":", 1) for part in v.split("/")[1:] if ":" in part)
    for k in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
        if k not in m:
            raise ValueError(f"falta la métrica {k}")
    iss = 1 - (1 - _W["CIA"][m["C"]]) * (1 - _W["CIA"][m["I"]]) * (1 - _W["CIA"][m["A"]])
    if m["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * _PR[m["S"]][m["PR"]] * _W["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    if m["S"] == "U":
        return _roundup(min(impact + expl, 10))
    return _roundup(min(1.08 * (impact + expl), 10))


def sev_from_score(s: float) -> str:
    if s >= 9.0:
        return "Crítica"
    if s >= 7.0:
        return "Alta"
    if s >= 4.0:
        return "Media"
    if s > 0:
        return "Baja"
    return "Informativa"


def cmd_cvss(a) -> None:
    try:
        s = cvss31(a.vector)
    except (ValueError, KeyError) as e:
        sys.exit(f"[!] Vector no válido: {e}")
    print(f"{s:.1f}  {sev_from_score(s)}  {a.vector}")


# --------------------------------------------------------------------------- hallazgos

SEV_ORDER = ["Crítica", "Alta", "Media", "Baja", "Informativa"]
SEV_ALIASES = {
    "critica": "Crítica", "crítica": "Crítica", "critical": "Crítica",
    "alta": "Alta", "high": "Alta",
    "media": "Media", "medium": "Media", "moderate": "Media",
    "baja": "Baja", "low": "Baja",
    "informativa": "Informativa", "info": "Informativa", "informational": "Informativa", "none": "Informativa",
}
SEV_EN = {"Crítica": "Critical", "Alta": "High", "Media": "Medium", "Baja": "Low", "Informativa": "Informational"}
EST_ALIASES = {
    "sin validar": "SIN VALIDAR", "unvalidated": "SIN VALIDAR",
    "validado": "VALIDADO", "validated": "VALIDADO",
    "rechazado": "RECHAZADO", "rejected": "RECHAZADO",
    "requiere trabajo": "REQUIERE TRABAJO", "needs-work": "REQUIERE TRABAJO", "needs work": "REQUIERE TRABAJO",
    "corregido": "CORREGIDO", "fixed": "CORREGIDO",
}
EST_EN = {"SIN VALIDAR": "UNVALIDATED", "VALIDADO": "Open", "RECHAZADO": "REJECTED",
          "REQUIERE TRABAJO": "NEEDS WORK", "CORREGIDO": "Fixed"}
EST_ES_REPORT = {"VALIDADO": "Abierto", "CORREGIDO": "Corregido"}


def norm_sev(s: str) -> str:
    return SEV_ALIASES.get((s or "").strip().lower(), (s or "Informativa").strip() or "Informativa")


def norm_est(s: str) -> str:
    return EST_ALIASES.get((s or "").strip().lower(), (s or "SIN VALIDAR").strip().upper())


def _score(meta: dict) -> float:
    try:
        return float((meta.get("cvss_score") or "0").replace(",", "."))
    except ValueError:
        return 0.0


def load_findings(eng: Path, lang: str = "es") -> list[dict]:
    res = []
    for p in sorted((eng / "findings").glob("F-*.md")):
        meta, body = parse_frontmatter(read(p))
        if not meta:
            continue
        item = {"path": p, "meta": meta, "body": body, "lang_src": "es"}
        if lang == "en":
            pe = eng / "findings" / "en" / p.name
            if pe.exists():
                m2, b2 = parse_frontmatter(read(pe))
                merged = dict(meta)
                merged.update({k: v for k, v in m2.items() if v})
                item.update(meta=merged, body=b2, lang_src="en")
        item["sev"] = norm_sev(item["meta"].get("severidad", ""))
        item["est"] = norm_est(item["meta"].get("estado", ""))
        item["id"] = item["meta"].get("id", p.stem)
        res.append(item)
    res.sort(key=lambda f: (SEV_ORDER.index(f["sev"]) if f["sev"] in SEV_ORDER else 9, -_score(f["meta"]), f["id"]))
    return res


def table_rows(text: str, header_regex: str) -> int:
    rows, in_table = 0, False
    for line in text.splitlines():
        if re.match(header_regex, line):
            in_table = True
            continue
        if in_table:
            if line.startswith("|---") or line.startswith("| ---"):
                continue
            if line.startswith("|"):
                rows += 1
            elif line.strip():
                in_table = False
    return rows


def cmd_status(a) -> None:
    eng = resolve_engagement(a.engagement)
    sc = scope_load(eng)
    fs = load_findings(eng)
    auth = sc["fields"].get("autorización", "—")
    print(f"=== CORVUS Red · {sc['fields'].get('encargo', eng.name)} ({eng}) ===")
    print(f"Autorización: {auth}")
    print(f"Alcance: {len(sc['in'])} patrones · Exclusiones: {len(sc['out'])}")
    by_est, by_sev = {}, {}
    for f in fs:
        by_est[f["est"]] = by_est.get(f["est"], 0) + 1
        if f["est"] in ("VALIDADO", "CORREGIDO"):
            by_sev[f["sev"]] = by_sev.get(f["sev"], 0) + 1
    print(f"\nHallazgos: {len(fs)}  " + "  ".join(f"{k}: {v}" for k, v in by_est.items()))
    print("Validados por severidad: " + "  ".join(f"{s}: {by_sev.get(s, 0)}" for s in SEV_ORDER))
    plog = read(eng / "payload-log.md")
    n_payloads = table_rows(plog, r"^\| Fecha-hora")
    print(f"Payloads registrados: {n_payloads}")
    cov = read(eng / "coverage.md")
    wstg = re.findall(r"^\|\s*([^|]+?)\s*\|\s*WSTG-[A-Z]+-[^|]*\|\s*([^|]+?)\s*\|", cov, re.M)
    if wstg:
        done = sum(1 for _, st in wstg if st.lower() in ("sí", "si", "yes", "parcial", "partial", "n/a"))
        print(f"Categorías WSTG cubiertas: {done}/{len(wstg)}")
        pend = [c for c, st in wstg if st.lower() in ("no", "")]
        if pend:
            print("  Pendientes: " + ", ".join(pend))
    n_endpoints = table_rows(cov, r"^\| Endpoint")
    print(f"Endpoints en cobertura: {n_endpoints}")
    # findings.md
    lines = [f"# Hallazgos — {sc['fields'].get('objetivo', eng.name)}", "",
             "> Generado por `corvus.py status`. La fuente son los ficheros de `findings/`.", "",
             "| ID | Título | Severidad | CVSS | Endpoint | Clase | Estado | Fecha |",
             "|---|---|---|---|---|---|---|---|"]
    for f in fs:
        m = f["meta"]
        lines.append(f"| [{f['id']}](findings/{f['path'].name}) | {m.get('titulo','')} | {f['sev']} | "
                     f"{m.get('cvss_score','')} | `{m.get('endpoint','')}` | {m.get('clase','')} | {f['est']} | {m.get('fecha','')} |")
    write(eng / "findings.md", "\n".join(lines) + "\n")
    print(f"\n[+] {eng / 'findings.md'} regenerado.")
    for f in fs:
        if f["est"] in ("SIN VALIDAR", "REQUIERE TRABAJO"):
            print(f"  · {f['id']} {f['est']}: {f['meta'].get('titulo','')}")


# --------------------------------------------------------------------------- Markdown → HTML mínimo


def _inline(t: str) -> str:
    codes = []

    def keep(m):
        codes.append(m.group(1))
        return f"\x00{len(codes) - 1}\x00"

    t = re.sub(r"`([^`]+)`", keep, t)
    t = html.escape(t, quote=False)
    t = re.sub(r"\[([^\]]+)\]\((https?://[^)\s]+|#[^)\s]*|[^)\s]+\.(?:md|html|png|jpg|http|txt))\)",
               lambda m: f'<a href="{html.escape(m.group(2), quote=True)}">{m.group(1)}</a>', t)
    t = re.sub(r"&lt;(https?://[^\s&]+)&gt;", r'<a href="\1">\1</a>', t)
    t = re.sub(r'(?<![">=/])(https?://[^\s<]+[^\s<.,;:)\]])', r'<a href="\1">\1</a>', t)
    t = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"<em>\1</em>", t)
    t = re.sub(r"\x00(\d+)\x00", lambda m: f"<code>{html.escape(codes[int(m.group(1))], quote=False)}</code>", t)
    return t


def md_to_html(md: str) -> str:
    lines = md.splitlines()
    out, i, para = [], 0, []

    def flush():
        if para:
            out.append("<p>" + _inline(" ".join(x.strip() for x in para)) + "</p>")
            para.clear()

    while i < len(lines):
        line = lines[i]
        fence = re.match(r"^\s*(```+|~~~+)\s*([\w+-]*)", line)
        if fence:
            flush()
            mark, lang = fence.group(1), fence.group(2)
            i += 1
            buf = []
            while i < len(lines) and not lines[i].strip().startswith(mark[:3]):
                buf.append(lines[i])
                i += 1
            i += 1
            cls = f' class="language-{lang}"' if lang else ""
            out.append(f"<pre><code{cls}>" + html.escape("\n".join(buf), quote=False) + "</code></pre>")
            continue
        h = re.match(r"^(#{1,6})\s+(.*?)\s*#*$", line)
        if h:
            flush()
            lvl = len(h.group(1))
            txt = h.group(2)
            anchor = re.sub(r"[^a-z0-9]+", "-", txt.lower()).strip("-")
            out.append(f'<h{lvl} id="{anchor}">{_inline(txt)}</h{lvl}>')
            i += 1
            continue
        if line.strip().startswith("|") and i + 1 < len(lines) and re.match(r"^\s*\|?\s*:?-{3,}", lines[i + 1]):
            flush()
            hdr = [c.strip() for c in line.strip().strip("|").split("|")]
            i += 2
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            t = ["<table><thead><tr>" + "".join(f"<th>{_inline(c)}</th>" for c in hdr) + "</tr></thead><tbody>"]
            for r in rows:
                t.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in r) + "</tr>")
            t.append("</tbody></table>")
            out.append("".join(t))
            continue
        if re.match(r"^\s*(-{3,}|\*{3,})\s*$", line):
            flush()
            out.append("<hr>")
            i += 1
            continue
        if line.startswith(">"):
            flush()
            buf = []
            while i < len(lines) and lines[i].startswith(">"):
                buf.append(lines[i][1:].strip())
                i += 1
            out.append("<blockquote>" + md_to_html("\n".join(buf)) + "</blockquote>")
            continue
        lm = re.match(r"^(\s*)([-*]|\d+[.)])\s+(.*)$", line)
        if lm:
            flush()
            ordered = lm.group(2)[0].isdigit()
            tag = "ol" if ordered else "ul"
            items = []
            while i < len(lines):
                m2 = re.match(r"^(\s*)([-*]|\d+[.)])\s+(.*)$", lines[i])
                if m2 and len(m2.group(1)) < 2:
                    items.append(m2.group(3))
                elif m2 or (lines[i].startswith("   ") and items):
                    items[-1] = items[-1] + "\x01" + lines[i].strip()
                else:
                    break
                i += 1
            rendered = []
            for it in items:
                parts = it.split("\x01")
                head = _inline(parts[0])
                rest = "".join("<br>" + _inline(p) for p in parts[1:])
                rendered.append(f"<li>{head}{rest}</li>")
            out.append(f"<{tag}>" + "".join(rendered) + f"</{tag}>")
            continue
        if not line.strip():
            flush()
            i += 1
            continue
        para.append(line)
        i += 1
    flush()
    return "\n".join(out)


# --------------------------------------------------------------------------- informe

TXT = {
    "es": {
        "title": "Informe de prueba de intrusión", "retest": "Informe de verificación (retest)",
        "client": "Cliente", "engagement": "Encargo", "period": "Periodo de pruebas", "version": "Versión",
        "author": "Auditor", "date": "Fecha del informe", "type": "Tipo de prueba", "env": "Entorno",
        "exec": "Resumen ejecutivo", "scope": "Alcance y metodología", "in": "En alcance", "out": "Fuera de alcance",
        "restr": "Restricciones", "method": "Metodología", "summary": "Resumen de hallazgos",
        "details": "Hallazgos detallados", "concl": "Conclusiones, limitaciones y supuestos",
        "prio": "Priorización de la remediación", "annexA": "Anexo A — Cobertura de endpoints",
        "annexB": "Anexo B — Aviso legal", "sev": "Severidad", "count": "Hallazgos", "id": "ID",
        "ftitle": "Título", "status": "Estado", "endpoint": "Endpoint", "affected": "Afectados",
        "risk": "Nivel de riesgo global", "priority": "Prioridad", "effort": "Esfuerzo estimado",
        "nofind": "No se identificaron vulnerabilidades validadas dentro del alcance y periodo indicados.",
        "missing": "_Pendiente de redactar._",
        "method_txt": ("Las pruebas siguieron la **OWASP Web Security Testing Guide (WSTG)** y se apoyaron en "
                        "OWASP Top 10:2025, OWASP API Security Top 10:2023, OWASP Top 10 para aplicaciones LLM (2025) "
                        "y OWASP ASVS 5.0 cuando procedía. Cada hallazgo se verificó manualmente y superó un proceso "
                        "de validación de siete puntos (prueba de concepto reproducible, evidencia HTTP, impacto "
                        "demostrado, pertenencia al alcance, vulnerabilidad real, reproducibilidad por el cliente y "
                        "severidad justificada). La severidad se expresa con CVSS v3.1"
                        " (y CVSS v4.0 cuando se indica)."),
        "wstg": "Cobertura por categoría OWASP WSTG",
        "prio_map": {"Crítica": "1 — Inmediata", "Alta": "2 — Corto plazo (≤ 30 días)",
                     "Media": "3 — Medio plazo (≤ 90 días)", "Baja": "4 — Largo plazo",
                     "Informativa": "5 — Según criterio"},
        "body_secs": ["descripción", "prueba de concepto", "pasos para reproducir", "impacto", "remediación"],
    },
    "en": {
        "title": "Penetration Test Report", "retest": "Retest Report",
        "client": "Client", "engagement": "Engagement", "period": "Testing window", "version": "Version",
        "author": "Consultant", "date": "Report date", "type": "Test type", "env": "Environment",
        "exec": "Executive Summary", "scope": "Scope and Methodology", "in": "In scope", "out": "Out of scope",
        "restr": "Constraints", "method": "Methodology", "summary": "Findings Summary",
        "details": "Detailed Findings", "concl": "Conclusions, Limitations and Assumptions",
        "prio": "Remediation Priority", "annexA": "Appendix A — Endpoint Coverage",
        "annexB": "Appendix B — Legal Notice", "sev": "Severity", "count": "Findings", "id": "ID",
        "ftitle": "Title", "status": "Status", "endpoint": "Endpoint", "affected": "Affected",
        "risk": "Overall risk level", "priority": "Priority", "effort": "Estimated effort",
        "nofind": "No validated vulnerabilities were identified within the stated scope and testing window.",
        "missing": "_To be written._",
        "method_txt": ("Testing followed the **OWASP Web Security Testing Guide (WSTG)**, supported by the OWASP Top 10:2025, "
                        "the OWASP API Security Top 10:2023, the OWASP Top 10 for LLM Applications (2025) and OWASP ASVS 5.0 "
                        "where relevant. Every finding was manually verified and passed a seven-point validation process "
                        "(reproducible proof of concept, HTTP evidence, demonstrated impact, in-scope, real vulnerability, "
                        "client-reproducible, justified severity). Severity is expressed using CVSS v3.1 "
                        "(and CVSS v4.0 where stated)."),
        "wstg": "Coverage by OWASP WSTG category",
        "prio_map": {"Crítica": "1 — Immediate", "Alta": "2 — Short term (≤ 30 days)",
                     "Media": "3 — Medium term (≤ 90 days)", "Baja": "4 — Long term",
                     "Informativa": "5 — At discretion"},
        "body_secs": ["description", "proof of concept", "steps to reproduce", "impact", "remediation"],
    },
}


def _sevlabel(sev: str, lang: str) -> str:
    return SEV_EN.get(sev, sev) if lang == "en" else sev


def _strip_validation(body: str) -> str:
    return re.split(r"^##\s+(Validación|Validation)\b.*$", body, maxsplit=1, flags=re.M)[0].rstrip()


def _demote(body: str, by: int = 2) -> str:
    out, fence = [], False
    for line in body.splitlines():
        if line.strip().startswith("```") or line.strip().startswith("~~~"):
            fence = not fence
        if not fence and re.match(r"^#{1,4}\s", line):
            line = "#" * by + line
        out.append(line)
    return "\n".join(out)


def _wstg_table(cov: str) -> str:
    secs = md_sections(cov)
    for k, v in secs.items():
        if "wstg" in k:
            return v
    return ""


def _endpoint_table(cov: str) -> str:
    return md_sections(cov).get("endpoints", "")


def build_markdown(eng: Path, lang: str, findings: list[dict], brand: dict, retest: bool) -> tuple[str, list[str]]:
    T = TXT[lang]
    warns = []
    sc = scope_load(eng)
    f = sc["fields"]
    cov = read(eng / "coverage.md")
    exec_md = read(eng / "report" / f"resumen-ejecutivo.{lang}.md").strip()
    concl_md = read(eng / "report" / f"conclusiones.{lang}.md").strip()
    if not exec_md:
        warns.append(f"Falta report/resumen-ejecutivo.{lang}.md")
    if not concl_md:
        warns.append(f"Falta report/conclusiones.{lang}.md")
    title = T["retest"] if retest else T["title"]
    period = f"{f.get('fecha de inicio', '')} — {f.get('fecha de fin', '') or '…'}"
    L = []
    L.append(f"# {title} — {f.get('encargo', eng.name)}")
    L.append("")
    L.append("| | |\n|---|---|")
    L.append(f"| **{T['client']}** | {f.get('cliente', '') or '—'} |")
    L.append(f"| **{T['engagement']}** | {f.get('encargo', eng.name)} |")
    L.append(f"| **{T['period']}** | {period} |")
    L.append(f"| **{T['type']}** | {f.get('tipo de prueba', '—')} · {T['env']}: {f.get('entorno', '—')} |")
    if brand.get("auditor"):
        L.append(f"| **{T['author']}** | {brand['auditor']} — {brand.get('marca', '')} |")
    L.append(f"| **{T['date']}** | {today()} |")
    L.append(f"| **{T['version']}** | {f.get('versión del informe', '1.0')} |")
    L.append("")
    # 1 resumen ejecutivo
    counts = {s: 0 for s in SEV_ORDER}
    for x in findings:
        counts[x["sev"]] = counts.get(x["sev"], 0) + 1
    worst = next((s for s in SEV_ORDER if counts.get(s)), None)
    L.append(f"## 1. {T['exec']}\n")
    L.append(exec_md or T["missing"])
    L.append("")
    L.append(f"| {T['sev']} | {T['count']} |\n|---|---|")
    for s in SEV_ORDER:
        L.append(f"| {_sevlabel(s, lang)} | {counts.get(s, 0)} |")
    L.append("")
    if worst and worst != "Informativa":
        L.append(f"**{T['risk']}:** {_sevlabel(worst, lang)}\n")
    # 2 alcance y metodología
    L.append(f"## 2. {T['scope']}\n")
    L.append(f"### {T['in']}\n")
    L += [f"- `{x}`" for x in sc["in"]] or ["- —"]
    L.append(f"\n### {T['out']}\n")
    L += [f"- `{x}`" for x in sc["out"]] or ["- —"]
    restr = sc["sections"].get("restricciones", "")
    if restr:
        L.append(f"\n### {T['restr']}\n\n{restr}")
    L.append(f"\n### {T['method']}\n\n{T['method_txt']}\n")
    wt = _wstg_table(cov)
    if wt:
        L.append(f"#### {T['wstg']}\n\n{wt}\n")
    # 3 resumen de hallazgos
    L.append(f"## 3. {T['summary']}\n")
    if findings:
        L.append(f"| {T['id']} | {T['ftitle']} | {T['sev']} | CVSS | {T['status']} |\n|---|---|---|---|---|")
        for x in findings:
            m = x["meta"]
            t = (m.get("title_en") if lang == "en" and m.get("title_en") else m.get("titulo", ""))
            st = EST_EN.get(x["est"], x["est"]) if lang == "en" else EST_ES_REPORT.get(x["est"], x["est"])
            L.append(f"| {x['id']} | {t} | {_sevlabel(x['sev'], lang)} | {m.get('cvss_score', '')} | {st} |")
    else:
        L.append(T["nofind"])
    L.append("")
    # 4 detalle
    L.append(f"## 4. {T['details']}\n")
    for x in findings:
        m = x["meta"]
        t = (m.get("title_en") if lang == "en" and m.get("title_en") else m.get("titulo", ""))
        L.append(f'<div class="finding sev-{x["sev"]}"></div>\n')
        L.append(f"### {x['id']} — {t}\n")
        L.append("| | |\n|---|---|")
        L.append(f"| **{T['sev']}** | {_sevlabel(x['sev'], lang)} |")
        if m.get("cvss_vector"):
            L.append(f"| **CVSS v3.1** | {m.get('cvss_score', '')} — `{m.get('cvss_vector')}` |")
        if m.get("cvss4_vector"):
            L.append(f"| **CVSS v4.0** | {m.get('cvss4_score', '')} — `{m.get('cvss4_vector')}` |")
        for key, lab in (("cwe", "CWE"), ("owasp", "OWASP"), ("wstg", "WSTG")):
            if m.get(key):
                L.append(f"| **{lab}** | {m[key]} |")
        if m.get("endpoint"):
            L.append(f"| **{T['endpoint']}** | `{m['endpoint']}` |")
        if m.get("afectados"):
            L.append(f"| **{T['affected']}** | {m['afectados']} |")
        st = EST_EN.get(x["est"], x["est"]) if lang == "en" else EST_ES_REPORT.get(x["est"], x["est"])
        L.append(f"| **{T['status']}** | {st} |\n")
        body = _strip_validation(x["body"])
        L.append(_demote(body, 2))
        L.append("")
        # comprobaciones
        heads = [h.lower() for h in re.findall(r"^##\s+(.+?)\s*$", body, re.M)]
        for need in T["body_secs"]:
            if not any(h.startswith(need) for h in heads):
                warns.append(f"{x['id']}: falta la sección '{need}'")
        if lang == "en" and x["lang_src"] != "en":
            warns.append(f"{x['id']}: no existe findings/en/{x['path'].name}; se usa el texto en español")
        vec = m.get("cvss_vector", "")
        if vec.upper().startswith("CVSS:3"):
            try:
                calc = cvss31(vec)
                if abs(calc - _score(m)) > 0.05:
                    warns.append(f"{x['id']}: cvss_score={m.get('cvss_score')} pero el vector da {calc}")
                adjusted = re.search(r"ajuste por impacto de negocio|business impact adjustment", body, re.I)
                if sev_from_score(calc) != x["sev"] and not adjusted:
                    warns.append(f"{x['id']}: severidad '{x['sev']}' ≠ banda CVSS '{sev_from_score(calc)}' "
                                 "(válido solo con ajuste de negocio explicado)")
            except (ValueError, KeyError) as e:
                warns.append(f"{x['id']}: vector CVSS no válido ({e})")
        _, nsec = redact_text(body)
        if nsec:
            warns.append(f"{x['id']}: {nsec} posibles secretos sin tachar (usa corvus.py redact)")
    if not findings:
        L.append(T["nofind"] + "\n")
    # 5 conclusiones
    L.append(f"## 5. {T['concl']}\n")
    L.append(concl_md or T["missing"])
    L.append("")
    # 6 priorización
    if findings:
        L.append(f"## 6. {T['prio']}\n")
        L.append(f"| {T['priority']} | {T['id']} | {T['ftitle']} | {T['effort']} |\n|---|---|---|---|")
        for x in findings:
            m = x["meta"]
            t = (m.get("title_en") if lang == "en" and m.get("title_en") else m.get("titulo", ""))
            L.append(f"| {T['prio_map'].get(x['sev'], '')} | {x['id']} | {t} | {m.get('esfuerzo', '—')} |")
        L.append("")
    et = _endpoint_table(cov)
    if et:
        L.append(f"## {T['annexA']}\n\n{et}\n")
    L.append(f"## {T['annexB']}\n")
    L.append(brand.get("aviso_legal", {}).get(lang, ""))
    L.append("")
    return "\n".join(L), warns


def _embedded_fonts() -> str:
    """Incrusta como @font-face las .woff2 de assets/fonts/ (Familia-Peso.woff2 o Familia[wght].woff2)."""
    import base64

    weights = {"thin": 100, "extralight": 200, "light": 300, "regular": 400, "medium": 500,
               "semibold": 600, "bold": 700, "extrabold": 800, "black": 900}
    out = []
    for f in sorted((SKILL_DIR / "assets" / "fonts").glob("*.woff2")):
        stem = f.stem
        family = re.split(r"[-\[]", stem)[0]
        family = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", family)  # MonaSans → Mona Sans
        low = stem.lower()
        if "[" in stem or "variable" in low:
            weight = "100 900"
        else:
            weight = next((str(v) for k, v in sorted(weights.items(), key=lambda x: -len(x[0])) if k in low), "400")
        style = "italic" if "italic" in low else "normal"
        data = base64.b64encode(f.read_bytes()).decode()
        out.append(f"@font-face{{font-family:'{family}';font-weight:{weight};font-style:{style};font-display:swap;"
                   f"src:url(data:font/woff2;base64,{data}) format('woff2')}}")
    return "\n".join(out) + ("\n" if out else "")


def build_html(md: str, brand: dict, lang: str, eng_name: str, title: str) -> str:
    css = read(SKILL_DIR / "assets" / "report.css")
    logo = read(SKILL_DIR / brand.get("logo", "assets/logo.svg"))
    col = brand.get("colores", {})
    sevc = brand.get("severidad_colores", {})
    sevt = brand.get("severidad_texto", {})
    fonts = brand.get("tipografias", {})
    stack = {"texto": "system-ui, -apple-system, 'Segoe UI', Roboto, Arial, sans-serif",
             "titulos": "'Segoe UI', system-ui, Arial, sans-serif",
             "tecnica": "'Segoe UI Semibold', 'Segoe UI', system-ui, sans-serif"}
    vars_css = ":root{" + ";".join(
        [f"--{k.replace('_', '-')}:{v}" for k, v in col.items()]
        + [f"--font-{k}:{(chr(39) + fonts[k] + chr(39) + ', ') if fonts.get(k) else ''}{stack[k]}" for k in stack]
        + [f"--sev-{i}:{sevc.get(s, '#666')}" for i, s in enumerate(SEV_ORDER)]
        + [f"--sevt-{i}:{sevt.get(s, sevc.get(s, '#333'))}" for i, s in enumerate(SEV_ORDER)]) + "}"
    vars_css = _embedded_fonts() + vars_css
    body = md_to_html(md)
    # insignias de severidad en celdas
    labels = {**{s: i for i, s in enumerate(SEV_ORDER)}, **{SEV_EN[s]: i for i, s in enumerate(SEV_ORDER)}}
    body = re.sub(r"<td>(" + "|".join(map(re.escape, labels)) + r")</td>",
                  lambda m: f'<td><span class="sev sev-{labels[m.group(1)]}">{m.group(1)}</span></td>', body)
    body = body.replace("&lt;div class=&quot;finding", "<div class=\"finding").replace("&quot;&gt;&lt;/div&gt;", "\"></div>")
    body = re.sub(r'<p>&lt;div class="finding sev-[^"]*"&gt;&lt;/div&gt;</p>', '<div class="pb"></div>', body)
    body = re.sub(r"<p>&lt;div class=\"finding[^<]*</p>", '<div class="pb"></div>', body)
    lema = brand.get("lema", {}).get(lang, "")
    clasif = brand.get("clasificacion", {}).get(lang, "")
    rol = brand.get("rol_auditor", {}).get(lang, "")
    web, mail = brand.get("web", ""), brand.get("email", "")
    contacto = " · ".join(html.escape(x.replace("https://", "")) for x in (web, mail) if x)
    contacto = f'<span class="cover-contact">{contacto}</span><br>' if contacto else ""
    autor = " · ".join(html.escape(x) for x in (brand.get("auditor", ""), rol) if x)
    autor = f"{autor}<br>" if autor else ""
    cover = f"""
<section class="cover">
  <div class="cover-logo">{logo}</div>
  <div class="cover-brand">{html.escape(brand.get('marca', ''))}<span>{html.escape(brand.get('submarca', ''))}</span></div>
  <div class="cover-tag">{html.escape(lema)}</div>
  <h1 class="cover-title">{html.escape(title)}</h1>
  <div class="cover-eng">{html.escape(eng_name)}</div>
  <div class="cover-meta">{autor}{contacto}{today()}</div>
  <div class="cover-class">{html.escape(clasif)}</div>
</section>"""
    return f"""<!doctype html>
<html lang="{lang}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)} — {html.escape(eng_name)}</title>
<style>{vars_css}
{css}</style></head>
<body>
{cover}
<header class="run-head">{html.escape(brand.get('marca', ''))} · {html.escape(clasif)}</header>
<main class="doc">
{body}
</main>
</body></html>"""


def _deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        out[k] = _deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def load_brand() -> dict:
    """brand.json (público) + brand.local.json (privado, fuera de git), con prioridad del local."""
    brand = json.loads(read(SKILL_DIR / "brand.json") or "{}")
    local = SKILL_DIR / "brand.local.json"
    if local.exists():
        brand = _deep_merge(brand, json.loads(read(local) or "{}"))
    return brand


def find_browsers() -> list[str]:
    cands = [
        os.environ.get("CORVUS_BROWSER", ""),
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    ]
    found = [c for c in cands if c and Path(c).exists()]
    for n in ("google-chrome", "chromium", "chromium-browser", "chrome", "msedge"):
        w = shutil.which(n)
        if w and w not in found:
            found.append(w)
    return found


def to_pdf(html_path: Path, pdf_path: Path) -> str:
    import tempfile

    browsers = find_browsers()
    if not browsers:
        return "no se encontró Chrome/Edge: abre el HTML y usa Imprimir → Guardar como PDF"
    uri = html_path.resolve().as_uri()
    if pdf_path.exists():
        pdf_path.unlink()
    for b in browsers:
        with tempfile.TemporaryDirectory(prefix="corvus-pdf-") as prof:
            cmd = [b, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
                   f"--user-data-dir={prof}", "--no-pdf-header-footer", "--print-to-pdf-no-header",
                   f"--print-to-pdf={pdf_path.resolve()}", uri]
            try:
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
            except Exception:  # noqa: BLE001
                continue
        if pdf_path.exists() and pdf_path.stat().st_size > 0:
            return "ok"
    return "ningún navegador generó el PDF (abre el HTML y usa Imprimir → Guardar como PDF)"


def cmd_report(a) -> None:
    eng = resolve_engagement(a.engagement)
    lang = a.lang
    brand = load_brand()
    fs = load_findings(eng, lang)
    if a.finding:
        sel = [x for x in fs if x["id"].upper() == a.finding.upper()]
        if not sel:
            sys.exit(f"[!] No existe {a.finding}")
        if sel[0]["est"] not in ("VALIDADO", "CORREGIDO") and not a.force:
            sys.exit(f"[!] {a.finding} está '{sel[0]['est']}'. Valídalo antes o usa --force para un borrador.")
        fs = sel
    elif a.retest:
        fs = [x for x in fs if x["est"] in ("VALIDADO", "CORREGIDO")]
    else:
        skipped = [x["id"] for x in fs if x["est"] != "VALIDADO"]
        fs = [x for x in fs if x["est"] == "VALIDADO"]
        if skipped:
            print(f"[i] No entran (no VALIDADO): {', '.join(skipped)}")
    sc = scope_load(eng)
    md, warns = build_markdown(eng, lang, fs, brand, a.retest)
    suffix = f"-{a.finding.upper()}" if a.finding else ("-retest" if a.retest else "")
    stem = f"{eng.name}-{'informe' if lang == 'es' else 'report'}-{lang}{suffix}"
    out_md, out_html, out_pdf = (eng / "report" / (stem + ext) for ext in (".md", ".html", ".pdf"))
    write(out_md, md)
    title = (TXT[lang]["retest"] if a.retest else TXT[lang]["title"])
    write(out_html, build_html(md, brand, lang, sc["fields"].get("encargo", eng.name), title))
    print(f"[+] {out_md}")
    print(f"[+] {out_html}")
    if not a.no_pdf:
        r = to_pdf(out_html, out_pdf)
        print(f"[+] {out_pdf}" if r == "ok" else f"[i] PDF: {r}")
    if warns:
        print("\n[!] Revisa antes de entregar:")
        for w in warns:
            print(f"    - {w}")
    else:
        print("[+] Sin avisos de coherencia.")


# --------------------------------------------------------------------------- http (petición registrada)


class _NoRedirect(__import__("urllib.request").request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # noqa: D401
        return None


def _token_identity(text: str) -> str:
    """Resume la identidad de un JWT presente en las cabeceras sin revelar secretos (alg, firma, id, email, rol)."""
    m = re.search(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", text)
    if not m:
        return ""
    try:
        h, p, sig = m.group(0).split(".")
        hd = json.loads(_b64d(h))
        pl = json.loads(_b64d(p))
    except Exception:  # noqa: BLE001
        return ""
    src = pl.get("data", pl) if isinstance(pl, dict) else {}
    keys = ("id", "sub", "user_id", "uid", "email", "username", "role", "roles", "scope")
    who = ", ".join(f"{k}={src.get(k)}" for k in keys if isinstance(src, dict) and src.get(k) not in (None, ""))
    times = []
    for k in ("iat", "exp"):
        v = pl.get(k) if isinstance(pl, dict) else None
        if isinstance(v, (int, float)):
            times.append(f"{k}={_dt.datetime.fromtimestamp(v, _dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    if isinstance(pl, dict) and "exp" not in pl:
        times.append("exp=ausente")
    return (f"alg={hd.get('alg')}, firma={'vacía' if not sig else f'{len(sig)} car.'}, "
            f"{who or 'sin claims de identidad'}" + (", " + ", ".join(times) if times else ""))


def _rate_wait(eng: Path, min_interval: float) -> None:
    import time

    stamp = eng / "evidence" / ".last_request"
    try:
        last = float(read(stamp) or 0)
    except ValueError:
        last = 0.0
    delta = time.time() - last
    if delta < min_interval:
        time.sleep(min_interval - delta)
    write(stamp, str(time.time()))


def _rate_from_scope(sc: dict) -> float:
    m = re.search(r"Ritmo máximo:\*\*\s*([\d.,]+)", sc["text"])
    try:
        rps = float(m.group(1).replace(",", ".")) if m else 5.0
    except ValueError:
        rps = 5.0
    return 1.0 / rps if rps > 0 else 0.2


def cmd_http(a) -> None:
    import time
    import urllib.error
    import urllib.request

    eng = resolve_engagement(a.engagement)
    sc = scope_load(eng)
    auth = sc["fields"].get("autorización", "")
    if not auth.upper().startswith("CONFIRMADA"):
        sys.exit("SIN AUTORIZACIÓN — no se envía la petición.")
    if any(scope_match(p, a.url) for p in sc["out"]):
        sys.exit(f"FUERA de alcance — no se envía: {a.url}")
    if not any(scope_match(p, a.url) for p in sc["in"]):
        sys.exit(f"DUDOSO — {a.url} no está en 'En alcance'. Pregunta al auditor antes de enviar.")
    headers = {"User-Agent": "CORVUS-Red/1.0 (auditoria autorizada)"}
    for h in a.header or []:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()
    data = None
    if a.json is not None:
        data = a.json.encode("utf-8")
        headers.setdefault("Content-Type", "application/json")
    elif a.data is not None:
        data = a.data.encode("utf-8")
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    method = a.method.upper()
    u = urlparse(a.url)
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    req_txt = f"{method} {path} HTTP/1.1\nHost: {u.netloc}\n" + "".join(f"{k}: {v}\n" for k, v in headers.items())
    if data is not None:
        req_txt += "\n" + data.decode("utf-8", "replace")
    # 1) registrar ANTES de mirar la respuesta
    payload = a.payload or (a.json or a.data or u.query or path)
    red_payload, _ = redact_text(payload)
    red_payload = red_payload.replace("|", "\\|").replace("\n", " ")[:300]
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _rate_wait(eng, _rate_from_scope(sc))
    opener = urllib.request.build_opener(_NoRedirect())
    rq = urllib.request.Request(a.url, data=data, method=method, headers=headers)
    t0 = time.time()
    import http.client

    def _read(r):
        try:
            return r.read()
        except http.client.IncompleteRead as ir:  # respuesta truncada: quedarse con lo recibido
            return ir.partial

    try:
        resp = opener.open(rq, timeout=a.timeout)
        status, rh, body = resp.status, resp.headers, _read(resp)
    except urllib.error.HTTPError as e:
        status, rh, body = e.code, e.headers, _read(e)
    except Exception as e:  # noqa: BLE001
        status, rh, body = 0, {}, str(e).encode()
    ms = int((time.time() - t0) * 1000)
    observed = f"HTTP {status} · {len(body)} B · {ms} ms"
    with open(eng / "payload-log.md", "a", encoding="utf-8") as fh:
        # la columna Endpoint lleva solo la ruta: la query va (tachada) en la columna Payload
        fh.write(f"| {ts} | {method} {(u.path or '/')[:80].replace('|', '%7C')} | {a.clase} | `{red_payload}` | {observed} | {a.nota or ''} |\n")
    # 2) mostrar y guardar evidencia tachada
    text = body.decode("utf-8", "replace")
    resp_txt = f"HTTP/1.1 {status}\n" + "".join(f"{k}: {v}\n" for k, v in (rh.items() if rh else [])) + "\n" + text
    if a.save:
        ev = eng / "evidence" / f"{a.save}.http"
        ident = _token_identity(" ".join(headers.values()))
        full, n = redact_text(f"### Petición ({ts})\n{req_txt}\n\n### Respuesta ({observed})\n{resp_txt}")
        if ident:
            full = full.replace("\n\n### Respuesta", f"\n# Identidad del token enviado (no secreta): {ident}\n\n### Respuesta", 1)
        write(ev, full)
        print(f"[evidencia] {ev} ({n} valores tachados)", file=sys.stderr)
    print(f"[{observed}]")
    if a.show_headers and rh:
        for k, v in rh.items():
            print(f"{k}: {v}")
    shown = text if a.raw else redact_text(text)[0]  # tachar ANTES de recortar
    out = shown if a.max <= 0 else shown[: a.max] + (f"… [+{len(shown) - a.max} car.]" if len(shown) > a.max else "")
    print(out)


# --------------------------------------------------------------------------- jwt


def _b64d(s: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _set_path(obj: dict, path: str, value) -> None:
    keys = path.split(".")
    for k in keys[:-1]:
        obj = obj.setdefault(k, {})
    obj[keys[-1]] = value


def cmd_jwt(a) -> None:
    parts = a.token.strip().split(".")
    if len(parts) < 2:
        sys.exit("[!] No parece un JWT (cabecera.payload.firma).")
    header = json.loads(_b64d(parts[0]))
    payload = json.loads(_b64d(parts[1]))
    if not (a.set or a.alg or a.hs256_secret):
        print("Cabecera:", json.dumps(header, ensure_ascii=False))
        shown = json.dumps(payload, ensure_ascii=False, indent=1)
        print("Payload:", shown if a.raw else redact_text(shown)[0])
        claims = payload if isinstance(payload, dict) else {}
        flat = json.dumps(claims).lower()
        notes = []
        if "exp" not in claims:
            notes.append("sin 'exp' (no caduca)")
        for k in ("password", "totpsecret", "secret", "hash", "ssn", "card"):
            if f'"{k}' in flat:
                notes.append(f"contiene '{k}'")
        if header.get("alg", "").lower() == "none":
            notes.append("alg none")
        for k in ("kid", "jku", "x5u", "jwk"):
            if k in header:
                notes.append(f"cabecera con '{k}' (ver vulns/jwt.md)")
        print("Observaciones:", "; ".join(notes) or "—")
        return
    for s in a.set or []:
        k, _, v = s.partition("=")
        try:
            val = json.loads(v)
        except ValueError:
            val = v
        _set_path(payload, k, val)
    alg = a.alg or ("HS256" if a.hs256_secret else header.get("alg", "none"))
    header["alg"] = alg
    h = _b64e(json.dumps(header, separators=(",", ":")).encode())
    p = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    if alg.lower() == "none":
        print(f"{h}.{p}.")
    elif alg == "HS256" and a.hs256_secret is not None:
        import hashlib
        import hmac

        sig = hmac.new(a.hs256_secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
        print(f"{h}.{p}.{_b64e(sig)}")
    else:
        sys.exit("[!] Solo se forja con alg none o HS256 (--hs256-secret). Para RS→HS usa jwt_tool (vulns/jwt.md).")


# --------------------------------------------------------------------------- main


def main() -> None:
    ap = argparse.ArgumentParser(prog="corvus", description="CORVUS Red — utilidades del encargo")
    sp = ap.add_subparsers(dest="cmd", required=True)

    p = sp.add_parser("init", help="crea engagements/<slug>/ desde las plantillas")
    p.add_argument("objetivo")
    p.add_argument("--nombre")
    p.add_argument("--cliente")
    p.add_argument("--idioma", default="es", choices=["es", "en"])
    p.add_argument("--base", default="engagements")
    p.set_defaults(fn=cmd_init)

    p = sp.add_parser("scope-check", help="comprueba URLs contra scope.md (0 dentro, 1 fuera, 2 dudoso, 3 sin autorización)")
    p.add_argument("engagement")
    p.add_argument("urls", nargs="+")
    p.set_defaults(fn=cmd_scope_check)

    p = sp.add_parser("redact", help="tacha credenciales, tokens y claves (fichero o stdin)")
    p.add_argument("file", nargs="?")
    p.add_argument("--in-place", action="store_true")
    p.add_argument("--check", action="store_true", help="solo cuenta posibles secretos (código 1 si hay)")
    p.set_defaults(fn=cmd_redact)

    p = sp.add_parser("status", help="panel del encargo y regenera findings.md")
    p.add_argument("engagement")
    p.set_defaults(fn=cmd_status)

    p = sp.add_parser("cvss", help="calcula la puntuación base CVSS 3.1")
    p.add_argument("vector")
    p.set_defaults(fn=cmd_cvss)

    p = sp.add_parser("http", help="envía una petición: comprueba el alcance, registra en payload-log ANTES, respeta el ritmo y guarda evidencia tachada")
    p.add_argument("engagement")
    p.add_argument("method")
    p.add_argument("url")
    p.add_argument("-H", "--header", action="append", help="'Nombre: valor' (repetible)")
    p.add_argument("--json", help="cuerpo JSON (texto)")
    p.add_argument("--data", help="cuerpo x-www-form-urlencoded o crudo")
    p.add_argument("--clase", default="recon", help="clase de vulnerabilidad para el registro")
    p.add_argument("--payload", help="payload a registrar (por defecto, el cuerpo o la query)")
    p.add_argument("--nota", help="nota para el registro")
    p.add_argument("--save", help="nombre del fichero de evidencia (evidence/<nombre>.http)")
    p.add_argument("--max", type=int, default=1500, help="caracteres del cuerpo a mostrar (0 = todo)")
    p.add_argument("--timeout", type=float, default=30)
    p.add_argument("-i", "--show-headers", action="store_true")
    p.add_argument("--raw", action="store_true", help="no tachar la salida por pantalla")
    p.set_defaults(fn=cmd_http)

    p = sp.add_parser("jwt", help="decodifica un JWT (tachado) o forja uno con alg none / HS256")
    p.add_argument("token")
    p.add_argument("--set", action="append", help="claim a cambiar: ruta.con.puntos=valor (valor JSON o texto)")
    p.add_argument("--alg", help="algoritmo del token forjado (none)")
    p.add_argument("--hs256-secret", help="firma con HS256 usando este secreto (p. ej. tras crackearlo)")
    p.add_argument("--raw", action="store_true", help="no tachar el payload al decodificar")
    p.set_defaults(fn=cmd_jwt)

    p = sp.add_parser("report", help="genera el informe con la marca (MD + HTML + PDF)")
    p.add_argument("engagement")
    p.add_argument("--lang", default="es", choices=["es", "en"])
    p.add_argument("--finding")
    p.add_argument("--retest", action="store_true")
    p.add_argument("--no-pdf", action="store_true")
    p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_report)

    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
