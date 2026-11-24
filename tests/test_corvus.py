"""Tests de scripts/corvus.py (solo biblioteca estándar). Ejecutar: python -m unittest discover -s tests -v"""
import base64
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "corvus.py"
spec = importlib.util.spec_from_file_location("corvus", SCRIPT)
corvus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corvus)


def run(*args, cwd=None):
    return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=cwd, capture_output=True, text=True, encoding="utf-8")


def b64(o):
    return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()


class TestCvss(unittest.TestCase):
    CASES = {
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N": 8.6,
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 6.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N": 4.7,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N": 3.7,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
    }

    def test_scores(self):
        for vec, score in self.CASES.items():
            self.assertEqual(corvus.cvss31(vec), score, vec)

    def test_bands(self):
        self.assertEqual(corvus.sev_from_score(9.0), "Crítica")
        self.assertEqual(corvus.sev_from_score(7.5), "Alta")
        self.assertEqual(corvus.sev_from_score(4.0), "Media")
        self.assertEqual(corvus.sev_from_score(3.9), "Baja")
        self.assertEqual(corvus.sev_from_score(0.0), "Informativa")


class TestRedact(unittest.TestCase):
    def check(self, text, must_vanish):
        out, n = corvus.redact_text(text)
        self.assertGreater(n, 0, text)
        for s in must_vanish:
            self.assertNotIn(s, out)
        return out

    def test_headers_and_cookies(self):
        out = self.check("Authorization: Bearer abc.def.ghi123\nCookie: session=deadbeef; theme=dark\n"
                         "Set-Cookie: sid=xyz789; Path=/; HttpOnly", ["abc.def.ghi123", "deadbeef", "xyz789"])
        self.assertIn("Authorization: Bearer [REDACTED", out)
        self.assertIn("Path=/; HttpOnly", out)

    def test_json_fields_including_substrings(self):
        self.check('{"password":"p4ss","passwordRepeat":"p4ss2","deluxeToken":"tok","totpSecret":"ABC"}',
                   ["p4ss", "p4ss2", "\"tok\"", "ABC"])

    def test_query_params(self):
        self.check("GET /rest/user/change-password?current=old1&new=new2&repeat=new2&page=2",
                   ["old1", "new2"])

    def test_jwt_and_keys(self):
        jwt = b64({"alg": "HS256"}) + "." + b64({"sub": "1"}) + ".sig"
        self.check(f"token {jwt} y AKIAABCDEFGHIJKLMNOP", [jwt, "AKIAABCDEFGHIJKLMNOP"])

    def test_no_false_positive(self):
        out, n = corvus.redact_text('{"description":"ok","authentication":{"x":1}}')
        self.assertEqual(n, 0)


class TestScope(unittest.TestCase):
    def test_matching(self):
        m = corvus.scope_match
        self.assertTrue(m("https://app.x.test/*", "https://app.x.test/login"))
        self.assertFalse(m("https://app.x.test/*", "http://app.x.test/login"))
        self.assertTrue(m("*.api.x.test", "v2.api.x.test"))
        self.assertFalse(m("*.api.x.test", "api.x.test"))
        self.assertTrue(m("10.0.0.0/24", "10.0.0.7"))
        self.assertTrue(m("https://app.x.test/checkout/*", "https://app.x.test/checkout/pay"))
        self.assertTrue(m("app.x.test:8443", "https://app.x.test:8443/"))
        self.assertFalse(m("app.x.test:8443", "https://app.x.test/"))

    def test_cli_exit_codes_and_wildcard_exclusion(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d) / "engagements" / "x"
            eng.mkdir(parents=True)
            (eng / "scope.md").write_text(textwrap.dedent("""\
                **Autorización:** CONFIRMADA — test
                ## En alcance
                - `https://app.x.test/*`
                ## Fuera de alcance
                - `https://app.x.test/admin/*`
                - `*`
                - (comentario)
                """), encoding="utf-8")
            self.assertEqual(run("scope-check", str(eng), "https://app.x.test/a").returncode, 0)
            self.assertEqual(run("scope-check", str(eng), "https://app.x.test/admin/x").returncode, 1)
            self.assertEqual(run("scope-check", str(eng), "https://otro.test/").returncode, 2)
            (eng / "scope.md").write_text("**Autorización:** PENDIENTE\n## En alcance\n- `a.test`\n", encoding="utf-8")
            self.assertEqual(run("scope-check", str(eng), "https://a.test/").returncode, 3)


class TestJwt(unittest.TestCase):
    def test_forge_none_and_identity(self):
        tok = b64({"alg": "RS256", "typ": "JWT"}) + "." + b64({"data": {"id": 1, "email": "a@x.test", "role": "customer"}, "iat": 1}) + ".sig"
        r = run("jwt", tok, "--alg", "none", "--set", "data.id=2", "--set", "data.role=admin")
        forged = r.stdout.strip()
        self.assertTrue(forged.endswith("."))
        ident = corvus._token_identity("Bearer " + forged)
        self.assertIn("alg=none", ident)
        self.assertIn("firma=vacía", ident)
        self.assertIn("id=2", ident)
        self.assertIn("role=admin", ident)
        self.assertIn("exp=ausente", ident)


class TestReport(unittest.TestCase):
    def test_report_escapes_and_filters(self):
        with tempfile.TemporaryDirectory() as d:
            r = run("init", "https://app.x.test", "--nombre", "Demo", cwd=d)
            self.assertEqual(r.returncode, 0, r.stderr)
            eng = pathlib.Path(d) / "engagements" / "app.x.test"
            tpl = (ROOT / "templates" / "hallazgo.md").read_text(encoding="utf-8")
            ok = (tpl.replace("id: F-000", "id: F-001").replace("estado: SIN VALIDAR", "estado: VALIDADO")
                  .replace("cvss_vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "cvss_vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
                  .replace("cvss_score: 0.0", "cvss_score: 6.1")
                  + "\n<script>alert('no-ejecutar')</script>\n")
            (eng / "findings" / "F-001.md").write_text(ok, encoding="utf-8")
            (eng / "findings" / "F-002.md").write_text(tpl.replace("id: F-000", "id: F-002"), encoding="utf-8")
            r = run("report", str(eng), "--lang", "es", "--no-pdf")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("F-002", r.stdout)  # avisado como no VALIDADO
            html = (eng / "report" / "app.x.test-informe-es.html").read_text(encoding="utf-8")
            self.assertNotIn("<script>alert", html)
            self.assertIn("&lt;script&gt;alert", html)
            self.assertIn("F-001", html)
            self.assertNotIn("id=\"f-002", html)


if __name__ == "__main__":
    unittest.main()
