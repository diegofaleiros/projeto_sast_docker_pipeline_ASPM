"""Contrato ASPM offline: nenhum token, GitLab, Slack ou ASPM real é utilizado."""
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch
import requests
from sast_sentinel.aspm import ASPMClient, ASPMError, preparar_relatorio, repo_id, validar_destino
from sast_sentinel.config import ConfigError
from sast_sentinel.storage import BackendLocal, backend_de
from sast_sentinel.state import State

TEST_ID = "11111111-1111-4111-8111-111111111111"
JOB_ID = "22222222-2222-4222-8222-222222222222"
RECEIPT = dict(created=1, suppressed=0, closed=0, reactivated=0, unchanged=0, total=1)

def response(code=201, **body):
    r = Mock(status_code=code, headers={})
    r.json.return_value = body or dict(test_id=TEST_ID, engagement="sast", branch="main", receipt=RECEIPT)
    return r

class ASPMTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root/"semgrep.json"
        self.path.write_text('{"results": []}')
        self.cfg = SimpleNamespace(aspm_base_url="https://aspm.example.invalid", aspm_pat="aspm_pat_FAKE_ONLY",
            aspm_workspace="empresa", aspm_business_product="produto", aspm_poll_timeout=15,
            trivy_bin="trivy", trivy_timeout=10, run_pipeline=False, state_dir=self.root)
        self.client = ASPMClient(self.cfg)
        self.client.session = Mock()
        self.client.session.post.return_value = response()
        self.client.sleep = lambda n: None

    def send(self, **extra):
        args = dict(ferramenta="Semgrep", relatorio=self.path, projeto="gitlab__grupo__repo", branch="main",
                    commit="a"*40, run_id="pipeline-123", scan_complete=False)
        args.update(extra)
        return self.client.enviar(**args)

    def test_sync_requires_receipt_and_native_type(self):
        result = self.send()
        self.assertTrue(result.ok)
        self.assertEqual(result.test_id, TEST_ID)
        self.assertEqual(result.receipt, RECEIPT)
        kw = self.client.session.post.call_args.kwargs
        self.assertFalse(kw["allow_redirects"])
        self.assertEqual(kw["data"]["scan_type"], "semgrep")
        self.assertEqual(kw["data"]["product_slug"], "gitlab__grupo__repo")
        self.assertEqual(kw["data"]["business_product"], "produto")
        self.assertEqual(kw["data"]["auto_create"], "true")
        self.assertEqual(kw["data"]["scan_complete"], "false")

    def test_complete_is_explicit(self):
        self.assertTrue(self.send(scan_complete=True).ok)
        self.assertEqual(self.client.session.post.call_args.kwargs["data"]["scan_complete"], "true")

    def test_idempotency_stable_and_sensitive_to_run_and_content(self):
        self.send()
        first = self.client.session.post.call_args.kwargs["headers"]["Idempotency-Key"]
        self.send()
        self.assertEqual(first,self.client.session.post.call_args.kwargs["headers"]["Idempotency-Key"])
        self.send(run_id="pipeline-124")
        self.assertNotEqual(first,self.client.session.post.call_args.kwargs["headers"]["Idempotency-Key"])
        self.path.write_text('{"results": [], "version":"new"}')
        self.send()
        self.assertNotEqual(first,self.client.session.post.call_args.kwargs["headers"]["Idempotency-Key"])

    def test_async_waits_for_completed_and_never_follows_status_url(self):
        self.client.session.post.return_value = response(202, job_id=JOB_ID, status_url="https://evil.invalid/token")
        self.client.session.get.side_effect = [response(200,status="pending"),
            response(200,status="completed",test_id=TEST_ID,receipt=RECEIPT)]
        self.client.monotonic = lambda: 0
        result = self.send()
        self.assertTrue(result.ok)
        self.assertEqual(result.job_id, JOB_ID)
        for call in self.client.session.get.call_args_list:
            self.assertEqual(call.args[0],"https://aspm.example.invalid/api/v1/scans/jobs/"+JOB_ID+"/")
            self.assertFalse(call.kwargs["allow_redirects"])

    def test_async_failed_preserves_job_id_and_does_not_retry_post(self):
        self.client.session.post.return_value = response(202,job_id=JOB_ID)
        self.client.session.get.return_value = response(200,status="failed",error="aspm_pat_PRIVATE")
        self.client.monotonic = lambda: 0
        result = self.send()
        self.assertFalse(result.ok)
        self.assertEqual(result.job_id,JOB_ID)
        self.assertNotIn("PRIVATE",result.mensagem)
        self.client.session.post.assert_called_once()

    def test_async_timeout_is_not_success(self):
        self.client.session.post.return_value = response(202,job_id=JOB_ID)
        self.client.monotonic = Mock(side_effect=[0,16])
        result = self.send()
        self.assertFalse(result.ok)
        self.assertEqual(result.job_id,JOB_ID)
        self.assertIn("antes de reenviar",result.mensagem)

    def test_invalid_job_uuid_rejected_before_get(self):
        self.client.session.post.return_value = response(202,job_id="../evil")
        self.assertFalse(self.send().ok)
        self.client.session.get.assert_not_called()

    def test_replay_does_not_invent_original_receipt(self):
        r=response(200,test_id=TEST_ID)
        r.headers={"Idempotency-Replayed":"true"}
        self.client.session.post.return_value=r
        result=self.send()
        self.assertTrue(result.ok)
        self.assertTrue(result.replayed)
        self.assertEqual(result.receipt,{})

    def test_http_errors_and_redirects_fail_without_logging_response(self):
        for code in (301,302,307,308,401,403,409,413,422,429,503):
            with self.subTest(code=code):
                self.client.session.post.return_value=response(code,error="PRIVATE_RESPONSE")
                result=self.send()
                self.assertFalse(result.ok)
                self.assertNotIn("PRIVATE",result.mensagem)

    def test_malformed_success_is_not_delivery(self):
        for body in ({}, {"test_id":42}, {"test_id":TEST_ID,"receipt":RECEIPT},
                     {"test_id":TEST_ID,"engagement":"x","branch":"main","receipt":{"total":0}}):
            self.client.session.post.return_value=response(201,placeholder=1)
            self.client.session.post.return_value.json.return_value=body
            self.assertFalse(self.send().ok)

    def test_network_failure_never_retries_post(self):
        self.client.session.post.side_effect=requests.Timeout("PRIVATE_TOKEN")
        result=self.send()
        self.assertFalse(result.ok)
        self.assertNotIn("PRIVATE",result.mensagem)
        self.client.session.post.assert_called_once()

    def test_invalid_report_is_not_uploaded(self):
        self.path.write_text('{"wrong":[]}')
        self.assertFalse(self.send().ok)
        self.client.session.post.assert_not_called()

    def test_bearer_empty_native_security_report_is_valid(self):
        self.path.write_text('{}')
        self.assertTrue(self.send(ferramenta="Bearer").ok)
        self.assertEqual(self.client.session.post.call_args.kwargs["data"]["scan_type"],"bearer-cli")

    def test_trivy_json_is_not_sent_as_iac(self):
        self.path.write_text('{"SchemaVersion":2,"Results":[]}')
        self.assertFalse(self.send(ferramenta="Trivy").ok)
        self.client.session.post.assert_not_called()

    def test_tls_and_root_url_required(self):
        for base in ("http://aspm.invalid","https://user:pass@aspm.invalid","https://aspm.invalid/api",
                     "https://aspm.invalid?next=evil","https://aspm.invalid:8080"):
            with self.assertRaises(ConfigError):
                validar_destino(base,"aspm_pat_fake","empresa","produto")

    def test_repository_identity_distinguishes_projects_and_hosts(self):
        a=repo_id("gitlab.example","grupo/repo")
        self.assertEqual(a,repo_id("gitlab.example","grupo/repo"))
        for host,project in (("other.example","grupo/repo"),("gitlab.example","grupo/re.po"),
                             ("gitlab.example","grupo/re-po"),("gitlab.example","grupo/Repo")):
            self.assertNotEqual(a,repo_id(host,project))
        self.assertLessEqual(len(repo_id("a"*300,"b"*300)),255)

    def test_token_auth_is_preserved_without_netrc(self):
        client=ASPMClient(self.cfg)
        request=requests.Request("POST",client.base,auth=client.session.auth).prepare()
        self.assertEqual(request.headers["Authorization"],"Token aspm_pat_FAKE_ONLY")

    def test_sanitization_removes_snippets_and_pat_but_preserves_paths(self):
        doc={"results":[{"path":"src/app.py","extra":{"lines":"PRIVATE_SNIPPET","message":"aspm_pat_TEST_PRIVATE","metavars":{"$X":{"abstract_content":"PRIVATE_CAPTURE"}},"dataflow_trace":{"source":"PRIVATE_FLOW"}}}]}
        with patch.dict(os.environ,{"ASPM_PAT":"aspm_pat_TEST_PRIVATE","CI_PROJECT_PATH":"grupo/projeto"}):
            path=preparar_relatorio(self.cfg,"Semgrep",doc,self.root)
        data=path.read_text()
        self.assertNotIn("PRIVATE",data)
        self.assertIn("src/app.py",data)

    def test_state_local_roundtrip_without_cloud(self):
        state=State(backend_de(self.cfg))
        self.assertIsInstance(state.backend,BackendLocal)
        state.marcar_auditado(1,"a"*40)
        state.salvar()
        self.assertTrue(State(backend_de(self.cfg)).ja_auditado(1,"a"*40))

if __name__ == "__main__": unittest.main()
