"""Testes offline: checkout Git temporário, executáveis falsos, notificações simuladas."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from sast_sentinel import cli, pipeline, scanners
from sast_sentinel.config import Config, ConfigError
from sast_sentinel.aspm import ResultadoEnvio
from sast_sentinel.triage import redigir

FAKE = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
if name == "trivy" and "convert" in sys.argv:
    out = pathlib.Path(sys.argv[sys.argv.index("--output") + 1])
    out.write_text(json.dumps({"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy"}},"results":[]}]}))
    sys.exit(0)
out = pathlib.Path(sys.argv[sys.argv.index("--output") + 1])
mode_file = pathlib.Path(__file__).parent / "mode"
mode = mode_file.read_text() if mode_file.exists() else "clean"
if name == "semgrep":
    doc = {"results": [], "errors": [], "paths": {"scanned": ["app.py"]}}
    if mode in ("high", "critical", "medium", "unknown"):
        sev = {"high":"ERROR", "critical":"CRITICAL", "medium":"WARNING", "unknown":"CUSTOM"}[mode]
        doc["results"] = [{"check_id":"test.rule", "path":"app.py", "start":{"line":1},
          "extra":{"severity":sev,"message":"synthetic finding","metadata":{},"lines":"sensitive snippet"}}]
    if mode == "no-targets": doc["paths"]["scanned"] = []
    if mode == "scan-error": doc["errors"] = [{"message":"ASPM_PAT=aspm_pat_FAKE_SECRET_123456"}]
    if mode == "partial-parsing":
        source = sys.argv[sys.argv.index("scan")+1]
        location = {"path":str(pathlib.Path(source)/"app.py"),"start":{"line":7},"end":{"line":8}}
        doc["errors"] = [{"code":3,"type":["PartialParsing",[location]],
          "path":location["path"],"spans":[{"file":location["path"],"start":{"line":7}}],
          "message":"ASPM_PAT=aspm_pat_FAKE_SECRET_123456", "long_msg":"PRIVATE_SOURCE_SNIPPET"}]

elif name == "bearer":
    doc = {"critical":[], "high":[], "medium":[], "low":[], "warning":[]}
    if mode == "bearer-critical":
        doc["critical"] = [{"id":"test.secret", "title":"synthetic", "description":"synthetic", "filename":"app.py", "line_number":1}]
else:
    doc = {"SchemaVersion":2,"Results":[]}
    if sys.argv[sys.argv.index("--scanners")+1] != "misconfig":
        sys.exit(99)  # o gate deve passar o modo aprovado no comando real
    if mode in ("trivy-high", "trivy-critical"):
        doc["Results"] = [{"Target":"Dockerfile","Misconfigurations":[{"ID":"DS-TEST-1",
          "Severity":"CRITICAL" if mode == "trivy-critical" else "HIGH",
          "Title":"synthetic IaC finding","Message":"synthetic misconfiguration",
          "CauseMetadata":{"StartLine":1}}]}]
if mode == "blank" and name == "bearer":
    out.write_text("")
elif mode == "invalid" and name == "trivy":
    out.write_text("not-json")
elif mode == "malformed" and name == "semgrep":
    out.write_text("{}")
else:
    out.write_text(json.dumps(doc))
if mode == "exit-error" and name == "bearer":
    print("ASPM_PAT=aspm_pat_FAKE_SECRET_123456",file=sys.stderr)
    sys.exit(3)
'''


class GateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="sentinel-gate-tests-")
        cls.base = Path(cls.tmp.name)
        cls.repo = cls.base / "checkout"
        cls.repo.mkdir()
        (cls.repo / "app.py").write_text("print('fixture')\n")
        def git(*args):
            return subprocess.run(["git", "-C", str(cls.repo), *args], capture_output=True,
                                  text=True, check=True).stdout.strip()
        git("init", "-q")
        git("add", "app.py")
        git("-c", "user.name=Sentinel Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture")
        cls.sha = git("rev-parse", "HEAD")
        cls.bin = cls.base / "bin"
        cls.bin.mkdir()
        for name in ("semgrep", "bearer", "trivy"):
            f = cls.bin / name
            f.write_text(FAKE)
            f.chmod(0o755)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.env = patch.dict(os.environ, {
            "PATH": os.environ["PATH"], "HOME": str(self.base), "PYTHONDONTWRITEBYTECODE":"1",
            "CI_PROJECT_DIR": str(self.repo), "CI_PROJECT_PATH":"test/project", "CI_COMMIT_SHA":self.sha,
            "CI_COMMIT_BRANCH":"main", "CI_PIPELINE_ID":"123", "RUN_PIPELINE":"true",
            "SEMGREP_BIN":str(self.bin/"semgrep"), "BEARER_BIN":str(self.bin/"bearer"),
            "TRIVY_BIN":str(self.bin/"trivy"), "TRIVY_ENABLED":"true",
            # Destino de teste: sem credenciais reais e sem chamadas HTTP.
            "ASPM_WORKSPACE":"empresa-teste", "ASPM_BUSINESS_PRODUCT":"sistema-teste",
            "CI_SERVER_HOST":"gitlab.example.invalid",
            "ASPM_BASE_URL":"https://aspm.example.invalid", "ASPM_PAT":"aspm_pat_FAKE_SECRET_123456",
            "SLACK_WEBHOOK_URL":"https://hooks.slack.com/services/FAKE/ONLY/TEST",
            "PIPELINE_SUMMARY_PATH":str(self.base/"summary.json"),
        }, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        from sast_sentinel import pipeline_security as security
        self.policy_file = self.base / "trusted-test-policy.json"
        policy = json.loads(Path(security.POLICY_PATH).read_text())
        policy.update(require_root_owned=False, require_cached_rules=False,
                      aspm_allowed_hosts=["aspm.example.invalid"])
        policy["executables"].update(Semgrep=str(self.bin/"semgrep"),
            Bearer=str(self.bin/"bearer"), Trivy=str(self.bin/"trivy"))
        self.policy_file.write_text(json.dumps(policy))
        self.policy_patch = patch.object(security,"POLICY_PATH",self.policy_file)
        self.policy_patch.start()
        self.addCleanup(self.policy_patch.stop)
        (self.bin/"mode").write_text("clean")
        self.network = patch("requests.sessions.Session.request", side_effect=AssertionError("real network prohibited"))
        self.network.start()
        self.addCleanup(self.network.stop)
        self.out = io.StringIO()
        self.stdout = contextlib.redirect_stdout(self.out)
        self.stdout.__enter__()
        self.addCleanup(self.stdout.__exit__, None, None, None)

    def config(self, dry=True):
        return Config.load(self.base/"missing.env", pipeline=True, dry_run=dry)

    def run_gate(self, mode="clean", dry=True):
        (self.bin/"mode").write_text(mode)
        return pipeline.executar_pipeline(self.config(dry))

    def summary(self):
        return json.loads((self.base/"summary.json").read_text())

    def test_clean_passes(self):
        self.assertEqual(self.run_gate(), 0)
        self.assertFalse(self.summary()["uses_state"])
        self.assertTrue(all(x["complete"] for x in self.summary()["scanners"]))

    def test_high_blocks(self):
        self.assertEqual(self.run_gate("high"), 1)
        self.assertEqual(self.summary()["blocking_count"], 1)

    def test_critical_blocks(self):
        self.assertEqual(self.run_gate("critical"), 1)

    def test_medium_passes(self):
        self.assertEqual(self.run_gate("medium"), 0)

    def test_bearer_critical_blocks(self):
        self.assertEqual(self.run_gate("bearer-critical"), 1)

    def test_trivy_high_blocks(self):
        self.assertEqual(self.run_gate("trivy-high"), 1)

    def test_invalid_json_fails_closed(self):
        self.assertEqual(self.run_gate("invalid"), 2)

    def test_missing_schema_fails_closed(self):
        self.assertEqual(self.run_gate("malformed"), 2)

    def test_blank_report_fails_closed(self):
        self.assertEqual(self.run_gate("blank"), 2)

    def test_nonzero_with_valid_json_fails_closed(self):
        self.assertEqual(self.run_gate("exit-error"), 2)
        self.assertNotIn("aspm_pat_FAKE_SECRET_123456", json.dumps(self.summary()))

    def test_scanner_errors_fail_closed(self):
        self.assertEqual(self.run_gate("scan-error"), 2)
        self.assertNotIn("aspm_pat_FAKE_SECRET_123456", json.dumps(self.summary()))

    def test_partial_parsing_diagnostic_reaches_logs_slack_summary_and_blocks(self):
        client = self.deliveries()
        with patch.object(pipeline, "ASPMClient", return_value=client), \
             patch.object(pipeline, "enviar_slack", return_value=(True, "ok")) as slack, \
             self.assertLogs("sentinel.pipeline", level="INFO") as logs:
            self.assertEqual(self.run_gate("partial-parsing", dry=False), 2)
        summary = self.summary()
        semgrep = next(s for s in summary["scanners"] if s["name"] == "Semgrep")
        self.assertFalse(semgrep["complete"])
        self.assertEqual(semgrep["diagnostics"][-1],
                         {"type":"PartialParsing", "code":3, "path":"app.py", "line":7})
        self.assertEqual(len(semgrep["diagnostics"]), 2)  # process_exit + deduplicated location
        for published in (json.dumps(summary), json.dumps(slack.call_args.args[1]), "\n".join(logs.output)):
            self.assertIn("PartialParsing", published)
            self.assertIn("app.py", published)
            self.assertIn("linha: 7", published)
            for private in ("aspm_pat_FAKE_SECRET_123456", "PRIVATE_SOURCE_SNIPPET", "sentinel-pipeline-"):
                self.assertNotIn(private, published)
        self.assertEqual({call.kwargs["ferramenta"] for call in client.enviar.call_args_list},
                         {"Bearer", "Trivy"})

    def test_unknown_severity_fails_closed(self):
        self.assertEqual(self.run_gate("unknown"), 2)

    def test_no_semgrep_targets_is_incomplete(self):
        self.assertEqual(self.run_gate("no-targets"), 2)

    def test_missing_bearer_fails_closed(self):
        os.environ["BEARER_BIN"] = "/nonexistent/bearer"
        with self.assertRaises(ConfigError):
            self.run_gate()

    def test_disabled_trivy_is_explicit_policy(self):
        os.environ["TRIVY_ENABLED"] = "false"
        with self.assertRaises(ConfigError):
            self.run_gate()

    def test_sha_mismatch_fails_before_scans(self):
        os.environ["CI_COMMIT_SHA"] = "f" * 40
        with patch.object(pipeline, "rodar_semgrep") as scan:
            with self.assertRaises(ConfigError):
                self.run_gate()
            scan.assert_not_called()

    def test_missing_metadata_fails(self):
        del os.environ["CI_PROJECT_PATH"]
        with self.assertRaises(ConfigError):
            self.run_gate()

    def test_non_git_source_rejected(self):
        os.environ["CI_PROJECT_DIR"] = str(self.bin)
        with self.assertRaises(ConfigError):
            self.run_gate()

    def test_no_gitlab_or_s3_even_through_cli(self):
        with patch.object(cli,"State",side_effect=AssertionError("State accessed")), \
             patch.object(cli,"backend_de",side_effect=AssertionError("S3 accessed")), \
             patch.object(cli,"GitLabClient",side_effect=AssertionError("GitLab accessed")):
            self.assertEqual(cli.main(["--env",str(self.base/"missing.env"),"executar","--dry-run"]), 0)

    def test_explicit_pipeline_command_overrides_false_env(self):
        os.environ["RUN_PIPELINE"] = "false"
        self.assertEqual(cli.main(["--env",str(self.base/"missing.env"),"pipeline","--dry-run"]), 0)

    def test_pipeline_verificar_does_not_access_state(self):
        with patch.object(cli,"State",side_effect=AssertionError("State accessed")):
            self.assertEqual(cli.main(["--env",str(self.base/"missing.env"),"verificar"]), 0)

    def test_bad_config_returns_two(self):
        os.environ["PIPELINE_BLOCK_SEVERITIES"] = "HGIH"
        self.assertEqual(cli.main(["--env",str(self.base/"missing.env"),"executar"]), 2)

    def test_parent_default_still_dispatches_to_auditor(self):
        os.environ.update(RUN_PIPELINE="false", STATE_BACKEND="local",
                          GITLAB_URL="https://gitlab.example.invalid", GITLAB_API_TOKEN="fake-token")
        with patch.object(cli,"executar",return_value=0) as auditor:
            self.assertEqual(cli.main(["--env",str(self.base/"missing.env"),"executar"]), 0)
            self.assertFalse(auditor.call_args.args[0].run_pipeline)
            auditor.assert_called_once()

    def test_parent_errors_keep_zero_exit(self):
        os.environ.update(RUN_PIPELINE="false", STATE_BACKEND="local",
                          GITLAB_URL="https://gitlab.example.invalid", GITLAB_API_TOKEN="fake-token")
        with patch.object(cli,"executar",side_effect=RuntimeError("synthetic failure")):
            self.assertEqual(cli.main(["--env",str(self.base/"missing.env"),"executar"]), 0)

    def test_pipeline_requires_notifications_outside_dry_run(self):
        del os.environ["SLACK_WEBHOOK_URL"]
        with self.assertRaises(ConfigError):
            self.config(dry=False)
        self.config(dry=True)

    def test_parent_rejects_removed_s3_backend(self):
        os.environ.update(RUN_PIPELINE="false", STATE_BACKEND="s3",
                          GITLAB_URL="https://gitlab.example.invalid", GITLAB_API_TOKEN="fake-token")
        with self.assertRaises(ConfigError):
            Config.load(self.base/"missing.env")

    def deliveries(self):
        client = MagicMock()
        client.enviar.side_effect = lambda **kw: ResultadoEnvio(
            kw["ferramenta"], True, test_id="11111111-1111-4111-8111-111111111111", url="https://aspm.example.invalid/test/42")
        return client

    def test_notifies_aspm_before_block(self):
        client = self.deliveries()
        with patch.object(pipeline,"ASPMClient",return_value=client), \
             patch.object(pipeline,"enviar_slack",return_value=(True,"ok")) as slack:
            self.assertEqual(self.run_gate("high",dry=False), 1)
        self.assertEqual(client.enviar.call_count, 3)
        for call in client.enviar.call_args_list:
            self.assertFalse(call.kwargs["scan_complete"])
            self.assertIn("pipeline-", call.kwargs["run_id"])
            self.assertIn("gitlab-example-invalid__test__project", call.kwargs["projeto"])
        slack.assert_called_once()
        self.assertIn("BLOQUEADA",slack.call_args.args[1]["text"])

    def test_aspm_failure_still_notifies_slack(self):
        client = self.deliveries()
        client.enviar.side_effect = RuntimeError("aspm_pat_FAKE_SECRET_123456")
        with patch.object(pipeline,"ASPMClient",return_value=client), \
             patch.object(pipeline,"enviar_slack",return_value=(True,"ok")) as slack:
            self.assertEqual(self.run_gate("high",dry=False), 2)
            slack.assert_called_once()
        self.assertNotIn("aspm_pat_FAKE_SECRET_123456",json.dumps(self.summary()))

    def test_slack_failure_is_technical(self):
        with patch.object(pipeline,"ASPMClient",return_value=self.deliveries()), \
             patch.object(pipeline,"enviar_slack",return_value=(False,"fake error")):
            self.assertEqual(self.run_gate(dry=False), 2)

    def test_medium_notifies_result_even_without_severe_findings(self):
        with patch.object(pipeline,"ASPMClient",return_value=self.deliveries()), \
             patch.object(pipeline,"enviar_slack",return_value=(True,"ok")) as slack:
            self.assertEqual(self.run_gate("medium",dry=False), 0)
            self.assertIn("APROVADA",slack.call_args.args[1]["text"])

    def test_mr_context_is_stable(self):
        os.environ["CI_MERGE_REQUEST_IID"] = "19"
        client = self.deliveries()
        with patch.object(pipeline,"ASPMClient",return_value=client), \
             patch.object(pipeline,"enviar_slack",return_value=(True,"ok")):
            self.assertEqual(self.run_gate(dry=False), 0)
        self.assertTrue(all(c.kwargs["branch"] == "main" for c in client.enviar.call_args_list))

    def test_checkout_is_not_rewritten(self):
        before = (self.repo/"app.py").read_bytes()
        self.run_gate("high")
        self.assertEqual(before,(self.repo/"app.py").read_bytes())

    def test_retries_do_not_skip_commit(self):
        self.assertEqual(self.run_gate("high"), 1)
        self.assertEqual(self.run_gate("high"), 1)

    def test_cli_process_preserves_exit_one(self):
        os.environ["FAKE_MODE"] = "high"
        (self.bin/"mode").write_text("high")
        code = ("from pathlib import Path; from sast_sentinel import pipeline_security as s; "
                f"s.POLICY_PATH=Path({str(self.policy_file)!r}); "
                "from sast_sentinel.cli import main; "
                f"raise SystemExit(main(['--env',{str(self.base/'missing.env')!r},'pipeline','--dry-run']))")
        result = subprocess.run([sys.executable,"-c",code], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_report_not_reused_after_failure(self):
        cfg = self.config()
        file = self.base/"semgrep-old.json"
        file.write_text('{"results": []}')
        # O gate usa diretório temporário novo; um arquivo antigo fora dele não serve.
        os.environ["SEMGREP_BIN"] = "/does/not/exist"
        with self.assertRaises(ConfigError):
            pipeline.executar_pipeline(cfg.__class__.load(self.base/"missing.env",pipeline=True,dry_run=True))

    def test_custom_policy_can_block_medium(self):
        os.environ["PIPELINE_BLOCK_SEVERITIES"] = "MEDIUM,HIGH,CRITICAL"
        self.assertEqual(self.run_gate("medium"), 1)

    def test_notifications_opt_out_does_not_unblock_vulnerabilities(self):
        os.environ["PIPELINE_FAIL_ON_NOTIFICATION_ERROR"] = "false"
        with self.assertRaises(ConfigError):
            self.run_gate("high", dry=False)

    def test_partial_scan_opt_out_is_explicit(self):
        os.environ["PIPELINE_FAIL_ON_SCAN_ERROR"] = "false"
        with self.assertRaises(ConfigError):
            self.run_gate("exit-error")

    def test_client_initialization_failure_still_attempts_slack(self):
        with patch.object(pipeline,"ASPMClient",side_effect=RuntimeError("synthetic")), \
             patch.object(pipeline,"enviar_slack",return_value=(True,"ok")) as slack:
            self.assertEqual(self.run_gate(dry=False), 2)
            slack.assert_called_once()
            self.assertIn("ERRO TÉCNICO",slack.call_args.args[1]["text"])

    def test_debug_formatter_redacts_http_credentials(self):
        import logging
        record = logging.LogRecord("urllib3", logging.DEBUG, "", 0,
            "request %s key=%s", (os.environ["SLACK_WEBHOOK_URL"], os.environ["ASPM_PAT"]), None)
        text = pipeline.PipelineLogFormatter("%(message)s").format(record)
        self.assertNotIn("aspm_pat_FAKE_SECRET_123456", text)
        self.assertNotIn("FAKE/ONLY/TEST", text)

    def _novo_checkout(self, files):
        fixture = tempfile.TemporaryDirectory(prefix="sentinel-security-checkout-")
        self.addCleanup(fixture.cleanup)
        root = Path(fixture.name)
        for name, content in {"app.py": "print('safe')\n", **files}.items():
            file = root / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(content)
        def git(*args):
            return subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                                  text=True, check=True).stdout.strip()
        git("init", "-q"); git("add", "-f", ".")
        git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture")
        os.environ["CI_PROJECT_DIR"] = str(root)
        os.environ["CI_COMMIT_SHA"] = git("rev-parse", "HEAD")
        return root, git

    def test_cannot_remove_high_from_blocking_policy(self):
        os.environ["PIPELINE_BLOCK_SEVERITIES"] = "CRITICAL"
        with self.assertRaises(ConfigError): self.config()

    def test_cannot_remove_critical_from_blocking_policy(self):
        os.environ["PIPELINE_BLOCK_SEVERITIES"] = "HIGH"
        with self.assertRaises(ConfigError): self.config()

    def test_cannot_exclude_application_directory(self):
        os.environ["SCAN_SKIP_PATHS"] = "src"
        with self.assertRaises(ConfigError): self.config()

    def test_pipeline_default_comes_from_trusted_policy(self):
        os.environ.pop("TRIVY_SCANNERS", None)
        self.assertEqual(self.config().trivy_scanners, "misconfig")
        self.assertEqual(self.run_gate(), 0)
        self.assertEqual(self.summary()["policy"]["trivy_required_scanners"], ["misconfig"])

    def test_explicit_misconfig_accepted(self):
        os.environ["TRIVY_SCANNERS"] = "misconfig"
        self.assertEqual(self.run_gate(), 0)

    def test_original_trivy_modes_rejected_by_new_policy(self):
        for value in ("vuln,misconfig,secret", "misconfig,secret", "secret", "misconfig,", "misconfig,misconfig"):
            with self.subTest(value=value):
                os.environ["TRIVY_SCANNERS"] = value
                with self.assertRaises(ConfigError): self.config()

    def test_invalid_trivy_policy_fails_closed(self):
        initial = json.loads(self.policy_file.read_text())
        for value in ([], "misconfig", ["unknown"], ["misconfig", "misconfig"], [None]):
            with self.subTest(value=value):
                data = dict(initial); data["trivy_required_scanners"] = value
                self.policy_file.write_text(json.dumps(data))
                with self.assertRaises(ConfigError): self.config()
        initial.pop("trivy_required_scanners")
        self.policy_file.write_text(json.dumps(initial))
        with self.assertRaises(ConfigError): self.config()

    def test_trivy_critical_misconfig_blocks(self):
        self.assertEqual(self.run_gate("trivy-critical"), 1)
        self.assertEqual(self.summary()["findings"]["CRITICAL"], 1)

    def test_cannot_lower_trivy_scanners(self):
        os.environ["TRIVY_SCANNERS"] = "vuln"
        with self.assertRaises(ConfigError): self.config()

    def test_cannot_hide_unfixed_vulnerabilities(self):
        os.environ["TRIVY_IGNORE_UNFIXED"] = "true"
        with self.assertRaises(ConfigError): self.config()

    def test_cannot_disable_bearer_secrets(self):
        os.environ["BEARER_SCANNERS"] = "sast"
        with self.assertRaises(ConfigError): self.config()

    def test_cannot_remove_required_rulesets(self):
        os.environ["SEMGREP_CONFIGS"] = "p/secrets"
        with self.assertRaises(ConfigError): self.config()

    def test_cannot_use_repository_ruleset(self):
        os.environ["SEMGREP_CONFIGS"] = "p/default p/owasp-top-ten p/secrets /workspace/fake.yml"
        with self.assertRaises(ConfigError): self.config()

    def test_cannot_disable_tls(self):
        os.environ["ASPM_BASE_URL"] = "http://aspm.example.invalid"
        with self.assertRaises(ConfigError): self.config()

    def test_cannot_redirect_aspm_credentials_to_other_host(self):
        os.environ["ASPM_BASE_URL"] = "https://other.example.invalid"
        with self.assertRaises(ConfigError): self.config(dry=False)

    def test_dry_run_forbidden_in_gitlab(self):
        os.environ["GITLAB_CI"] = "true"
        with self.assertRaises(ConfigError): self.config(dry=True)

    def test_approved_language_pack_can_be_added(self):
        os.environ["SEMGREP_CONFIGS"] = "p/default p/owasp-top-ten p/secrets p/java"
        self.assertEqual(self.run_gate(), 0)

    def test_dirty_checkout_rejected_and_not_scanned(self):
        root, _ = self._novo_checkout({})
        (root / "app.py").write_text("print('different')\n")
        with patch.object(pipeline, "rodar_semgrep") as scan:
            self.assertEqual(self.run_gate(), 2)
            scan.assert_not_called()
        self.assertIn("Checkout modificado", " ".join(self.summary()["errors"]))

    def test_export_ignore_cannot_hide_committed_code(self):
        from sast_sentinel import pipeline_security as security
        root, _ = self._novo_checkout({".gitattributes":"hidden.py export-ignore\n", "hidden.py":"eval('unsafe')\n"})
        with tempfile.TemporaryDirectory() as tmp:
            info = security.snapshot_commit(pipeline.ContextoPipeline.carregar(), Path(tmp)/"snapshot",
                                            security.carregar_politica())
            self.assertEqual((Path(tmp)/"snapshot/hidden.py").read_text(), "eval('unsafe')\n")
            self.assertEqual(info["files"], 3)

    def test_gitignore_cannot_hide_tracked_code(self):
        from sast_sentinel import pipeline_security as security
        self._novo_checkout({".gitignore":"app.py\n"})
        with tempfile.TemporaryDirectory() as tmp:
            security.snapshot_commit(pipeline.ContextoPipeline.carregar(), Path(tmp)/"snapshot",
                                      security.carregar_politica())
            self.assertTrue((Path(tmp)/"snapshot/app.py").exists())

    def test_local_semgrep_ignore_rejected(self):
        self._novo_checkout({".semgrepignore":"app.py\n"})
        self.assertEqual(self.run_gate(), 2)

    def test_local_bearer_config_rejected(self):
        self._novo_checkout({"bearer.yml":"scan: {disable-default-rules: true}\n"})
        self.assertEqual(self.run_gate(), 2)

    def test_local_trivy_ignore_rejected(self):
        self._novo_checkout({".trivyignore":"CVE-TEST-123\n"})
        self.assertEqual(self.run_gate(), 2)

    def test_inline_trivy_suppression_rejected(self):
        self._novo_checkout({"app.py":"# trivy:ignore:secret-rule\nprint('safe')\n"})
        self.assertEqual(self.run_gate(), 2)

    def test_untracked_file_not_in_snapshot(self):
        from sast_sentinel import pipeline_security as security
        root, _ = self._novo_checkout({})
        (root/"untracked.py").write_text("print('not committed')")
        with tempfile.TemporaryDirectory() as tmp:
            security.snapshot_commit(pipeline.ContextoPipeline.carregar(), Path(tmp)/"snapshot",
                                      security.carregar_politica())
            self.assertFalse((Path(tmp)/"snapshot/untracked.py").exists())

    def test_symlink_cannot_point_outside_checkout(self):
        root, git = self._novo_checkout({})
        (root/"outside.py").symlink_to("/etc/passwd")
        git("add", "outside.py")
        git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "symlink")
        os.environ["CI_COMMIT_SHA"] = git("rev-parse", "HEAD")
        self.assertEqual(self.run_gate(), 2)

    def test_scanner_environment_drops_secrets_and_overrides(self):
        os.environ.update(BEARER_SKIP_RULE="all", TRIVY_SKIP_DB_UPDATE="true", AWS_SECRET_ACCESS_KEY="synthetic")
        cfg = self.config()
        env = scanners._ambiente_scanner(cfg, self.repo)
        for key in ("ASPM_PAT", "SLACK_WEBHOOK_URL", "AWS_SECRET_ACCESS_KEY", "BEARER_SKIP_RULE", "TRIVY_SKIP_DB_UPDATE"):
            self.assertNotIn(key, env)

    def test_semgrep_disables_inline_suppression(self):
        from types import SimpleNamespace
        cfg = self.config()
        file = self.base/"semgrep-flags.json"
        file.write_text(json.dumps({"results":[],"paths":{"scanned":["app.py"]}}))
        with patch.object(scanners.subprocess, "run", return_value=SimpleNamespace(returncode=0,stdout="",stderr="")) as run:
            scanners.rodar_semgrep(cfg, self.repo, file)
        self.assertIn("--disable-nosem", run.call_args.args[0])
        self.assertIn("--no-git-ignore", run.call_args.args[0])

    def test_central_exception_is_audited_and_keeps_finding(self):
        from datetime import date, timedelta
        data = json.loads(self.policy_file.read_text())
        data["exceptions"] = [{"scanner":"Semgrep","rule":"test.rule","project":"test/project","path":"app.py",
            "expires":(date.today()+timedelta(days=7)).isoformat(),"reason":"Test approved risk","approved_by":"Security",
            "ticket":"SEC-TEST"}]
        self.policy_file.write_text(json.dumps(data))
        self.assertEqual(self.run_gate("high"), 0)
        self.assertEqual(self.summary()["findings"]["HIGH"], 1)
        self.assertEqual(self.summary()["accepted_risks"][0]["ticket"], "SEC-TEST")

    def test_expired_exception_fails_closed(self):
        data = json.loads(self.policy_file.read_text())
        data["exceptions"] = [{"scanner":"Semgrep","rule":"test.rule","project":"test/project","path":"app.py",
            "expires":"2000-01-01","reason":"expired","approved_by":"Security","ticket":"SEC-TEST"}]
        self.policy_file.write_text(json.dumps(data))
        with self.assertRaises(ConfigError): self.config()

    def test_rules_manifest_detects_tampering(self):
        import hashlib
        from sast_sentinel import pipeline_security as security
        cfg = self.config()
        with tempfile.TemporaryDirectory() as tmp:
            assets = Path(tmp)
            for name in ("bearer.yml", "trivy.yml", "empty.ignore", "bearer.ignore"):
                (assets/name).write_text("")
            rule = assets/"rules.yml"; rule.write_text("rules: []")
            manifest = {pack:{"file":"rules.yml","sha256":hashlib.sha256(rule.read_bytes()).hexdigest()}
                        for pack in cfg.semgrep_configs}
            (assets/"rules-manifest.json").write_text(json.dumps(manifest))
            data = json.loads(self.policy_file.read_text()); data["require_cached_rules"]=True
            self.policy_file.write_text(json.dumps(data))
            with patch.object(security,"ASSETS",assets):
                security.validar_config(cfg)
                rule.write_text("rules: tampered")
                with self.assertRaises(ConfigError): security.validar_config(cfg)

    def test_secret_redaction_recognizes_prefixed_names(self):
        self.assertNotIn("123456abcdef",redigir("ASPM_PAT=123456abcdef"))
        self.assertNotIn("FAKE/ONLY/TEST",redigir("https://hooks.slack.com/services/FAKE/ONLY/TEST"))

    def test_validated_full_pipeline_can_close_only_after_explicit_opt_in(self):
        os.environ["ASPM_SCAN_COMPLETE"]="true"
        client=self.deliveries()
        with patch.object(pipeline,"ASPMClient",return_value=client), \
             patch.object(pipeline,"enviar_slack",return_value=(True,"ok")):
            self.assertEqual(self.run_gate("high",dry=False),1)
        self.assertTrue(all(c.kwargs["scan_complete"] for c in client.enviar.call_args_list))

    def test_partial_pipeline_never_closes_other_scanners(self):
        os.environ["ASPM_SCAN_COMPLETE"]="true"
        client=self.deliveries()
        with patch.object(pipeline,"ASPMClient",return_value=client), \
             patch.object(pipeline,"enviar_slack",return_value=(True,"ok")):
            self.assertEqual(self.run_gate("scan-error",dry=False),2)
        self.assertEqual(client.enviar.call_count,2)
        self.assertTrue(all(not c.kwargs["scan_complete"] for c in client.enviar.call_args_list))

    def test_synthetic_merge_never_closes_branch_findings(self):
        os.environ.update(ASPM_SCAN_COMPLETE="true",CI_MERGE_REQUEST_EVENT_TYPE="merged_result")
        client=self.deliveries()
        with patch.object(pipeline,"ASPMClient",return_value=client), \
             patch.object(pipeline,"enviar_slack",return_value=(True,"ok")):
            self.assertEqual(self.run_gate(dry=False),0)
        self.assertTrue(all(not c.kwargs["scan_complete"] for c in client.enviar.call_args_list))

    def test_conversion_failure_blocks_but_still_notifies_slack(self):
        actual=pipeline.preparar_relatorio
        def prepare(cfg,tool,*args):
            if tool=="Trivy": raise RuntimeError("PRIVATE_CONVERTER_PAYLOAD")
            return actual(cfg,tool,*args)
        with patch.object(pipeline,"ASPMClient",return_value=self.deliveries()), \
             patch.object(pipeline,"preparar_relatorio",side_effect=prepare), \
             patch.object(pipeline,"enviar_slack",return_value=(True,"ok")) as slack:
            self.assertEqual(self.run_gate(dry=False),2)
            slack.assert_called_once()
        self.assertNotIn("PRIVATE_CONVERTER_PAYLOAD",json.dumps(self.summary()))

    def test_historical_full_scan_uploads_to_aspm_without_closing_findings(self):
        cfg=self.config(False)
        cfg.run_pipeline=False
        cfg.scan_scope="full"
        cfg.aspm_scan_complete=True
        cfg.gitlab_url="https://gitlab.example.invalid"
        client=self.deliveries()
        gl=MagicMock()
        gl.baixar_codigo.return_value=self.repo
        with tempfile.TemporaryDirectory() as tmp:
            result=cli.processar_push(pipeline.ContextoPipeline.carregar().push(),gl,cfg,client,Path(tmp))
        self.assertFalse(result.erros)
        self.assertEqual(len(result.envios_aspm),3)
        self.assertTrue(all(not c.kwargs["scan_complete"] for c in client.enviar.call_args_list))

    def test_known_pat_is_redacted_without_redacting_project_path(self):
        self.assertEqual(pipeline.texto_seguro("test/project"),"test/project")
        self.assertNotIn(os.environ["ASPM_PAT"],pipeline.texto_seguro(os.environ["ASPM_PAT"]))


if __name__ == "__main__":
    unittest.main()