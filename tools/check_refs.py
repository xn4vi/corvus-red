"""Comprueba que las fichas existen, siguen la plantilla y que los enlaces internos no están rotos."""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
REQUIRED = {1, 2, 3, 8, 9, 10, 11, 12, 13}
errors = []

for p in sorted((ROOT / "references").rglob("*.md")):
    t = p.read_text(encoding="utf-8")
    if p.parent.name == "vulns" and p.stem != "waf-bypass":
        nums = {int(n) for n in re.findall(r"^## (\d+)", t, re.M)}
        if not REQUIRED <= nums:
            errors.append(f"{p.relative_to(ROOT)}: faltan secciones {sorted(REQUIRED - nums)}")
    for link in set(re.findall(r"`?((?:\.\./)?(?:vulns|whitebox)/[a-z0-9-]+\.md)`?", t)):
        if not any(c.exists() for c in (p.parent / link, ROOT / "references" / link.replace("../", ""))):
            errors.append(f"{p.relative_to(ROOT)}: enlace roto {link}")

skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
for name in re.findall(r"`references/([\w/.-]+\.md)`", skill):
    if not (ROOT / "references" / name).exists():
        errors.append(f"SKILL.md: referencia inexistente references/{name}")

n_vulns = len(list((ROOT / "references" / "vulns").glob("*.md")))
print(f"{n_vulns} fichas de vulnerabilidad · {len(errors)} errores")
for e in errors:
    print("  -", e)
sys.exit(1 if errors else 0)
