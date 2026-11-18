"""Safe diagnostics for Semgrep JSON variants, without code or credential disclosure."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from sast_sentinel.scanners import _diagnosticos_semgrep, rodar_semgrep


class SemgrepDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "src").mkdir()
        (self.root / "src/app.py").write_text("synthetic fixture")
        (self.root / "other.py").write_text("synthetic fixture")

    def diagnostic(self, **error):
        return _diagnosticos_semgrep(error, self.root)

    def test_string_type_and_span(self):
        for kind, expected in (("Syntax error", "ParseError"), ("ParseError", "ParseError"),
                               ("Timeout", "Timeout"), ("Rule parse error", "RuleParseError")):
            with self.subTest(kind=kind):
                result = self.diagnostic(type=kind, code=3, path="src/app.py",
                    spans=[{"file": str(self.root/"src/app.py"), "start":{"line":12}}])
                self.assertEqual(result, [{"type":expected,"code":3,"path":"src/app.py","line":12}])

    def test_partial_parsing_multiple_locations_and_no_payload_leak(self):
        result = self.diagnostic(type=["PartialParsing", [
            {"path":"src/app.py","start":{"line":4},"source":"PRIVATE_SOURCE"},
            {"path":"other.py","start":{"line":9}}]], code=3,
            message="PRIVATE_MESSAGE", long_msg="PRIVATE_LONG_MESSAGE")
        self.assertEqual([(d["path"],d["line"]) for d in result], [("src/app.py",4),("other.py",9)])
        self.assertNotIn("PRIVATE",json.dumps(result))

    def test_missing_locations_are_explicit_not_guessed_from_message(self):
        result = self.diagnostic(type=["PatternParseError", ["PRIVATE_PAYLOAD"]], code=4,
                                 message="src/app.py:99 PRIVATE_MESSAGE")
        self.assertEqual(result, [{"type":"PatternParseError","code":4,"path":None,"line":None}])
        self.assertEqual(self.diagnostic(type="Timeout",path="src/app.py")[0]["line"],None)

    def test_untrusted_types_and_numeric_fields_do_not_leak(self):
        for kind in ("PRIVATE_SECRET", {"PRIVATE_SECRET":1}, ["PRIVATE_SECRET", "payload"], [], None):
            with self.subTest(kind=kind):
                result = self.diagnostic(type=kind, code="PRIVATE_SECRET", spans=[
                    {"file":"src/app.py","start":{"line":"PRIVATE_SECRET"}}])
                self.assertEqual(result,[{"type":"Unspecified","code":None,"path":"src/app.py","line":None}])
        for number in (True, 0, -1, 2**40, "9", None):
            self.assertIsNone(self.diagnostic(type="Timeout", spans=[
                {"file":"src/app.py","start":{"line":number}}])[0]["line"])

    def test_external_missing_url_traversal_and_control_paths_are_hidden(self):
        for path in ("../PRIVATE_SECRET", "/etc/passwd", "https://host/PRIVATE_SECRET", "missing.py",
                     "src/app.py\nPRIVATE_SECRET", "src/app.py\x1b[31m", "bad\x00path"):
            with self.subTest(path=path):
                result = self.diagnostic(type="Timeout",path=path)
                self.assertIsNone(result[0]["path"])
                self.assertNotIn("PRIVATE_SECRET", json.dumps(result))

    def test_credentials_in_real_filenames_are_redacted(self):
        secret = "FAKE_PRIVATE_VALUE_987654"
        name = "src/"+secret+".py"
        (self.root/name).write_text("fixture")
        with patch.dict(os.environ, {"ASPM_PAT":secret}):
            result = self.diagnostic(type="Timeout",path=name)
        self.assertNotIn(secret,json.dumps(result))
        self.assertIn("REDIGIDO", result[0]["path"])
        name = "src/glpat-"+"a"*24+".py"
        (self.root/name).write_text("fixture")
        self.assertNotIn("a"*24,json.dumps(self.diagnostic(type="Timeout",path=name)))

    def test_missing_report_does_not_publish_stderr_or_stdout(self):
        cfg=SimpleNamespace(semgrep_bin="semgrep",semgrep_configs=[],skip_paths=[],semgrep_timeout=10,run_pipeline=False)
        process=SimpleNamespace(returncode=2,stdout="PRIVATE_STDOUT",stderr="PRIVATE_STDERR")
        with patch("sast_sentinel.scanners.subprocess.run",return_value=process):
            result=rodar_semgrep(cfg,self.root,self.root/"missing.json")
        self.assertFalse(result.ok)
        self.assertTrue(result.erros)
        self.assertNotIn("PRIVATE",json.dumps(result.erros))

    def test_malformed_errors_and_locations_remain_diagnostics(self):
        for error in (None, "PRIVATE_SECRET", [], 42):
            self.assertEqual(_diagnosticos_semgrep(error,self.root),
                [{"type":"Unspecified","code":None,"path":None,"line":None}])
        result=self.diagnostic(type=["PartialParsing", [None, 3, {"path":[]}]], spans=[None], code=True)
        self.assertEqual(result,[{"type":"PartialParsing","code":None,"path":None,"line":None}])


if __name__ == "__main__":
    unittest.main()
