"""ASPM Wake: relatórios nativos, PAT de serviço, recibos e jobs assíncronos.
Contrato: guia v0.431.0 fornecido pelo usuário. Nenhum POST é repetido automaticamente.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.parse import urlsplit
from uuid import UUID
import requests
from .config import ConfigError

log = logging.getLogger(__name__)
SCAN_TYPES = {"Semgrep": "semgrep", "Bearer": "bearer-cli", "Trivy": "trivy-iac"}
COUNTERS = ("created", "suppressed", "closed", "reactivated", "unchanged", "total")


class ASPMError(Exception):
    pass


def validar_destino(base, token, workspace, product):
    try:
        target = urlsplit(base)
        valid = (target.scheme == "https" and target.hostname and not target.path
                 and not target.query and not target.fragment and not target.username
                 and not target.password and target.port in (None, 443))
    except ValueError:
        valid = False
    if not valid:
        raise ConfigError("ASPM_BASE_URL deve ser a raiz HTTPS canônica, sem caminho ou credenciais.")
    if not re.fullmatch(r"aspm_pat_\S+", token):
        raise ConfigError("ASPM_PAT deve conter o PAT de serviço aspm_pat_..., sem espaços.")
    if not re.fullmatch(r"[a-z0-9-]{1,63}", workspace):
        raise ConfigError("ASPM_WORKSPACE deve conter o slug real da Empresa.")
    if not re.fullmatch(r"[a-z0-9_-]{1,100}", product):
        raise ConfigError("ASPM_BUSINESS_PRODUCT deve conter o slug do Produto existente na Empresa.")


def repo_id(host, project):
    if not host or not project:
        raise ConfigError("Informe CI_SERVER_HOST (pipeline) ou GITLAB_URL (auditoria) para identificar o repositório ASPM.")
    identity = host.lower() + "/" + project
    slug = re.sub(r"[^a-z0-9_-]", "-", identity.lower().replace("/", "__"))
    slug = re.sub(r"-+", "-", slug).strip("-_")[:238].rstrip("-_")
    # O sufixo evita colisões de caminhos que viram o mesmo slug após normalização.
    return slug + "-" + hashlib.sha256(identity.encode()).hexdigest()[:12]


def _uuid(value):
    try:
        return isinstance(value, str) and str(UUID(value)) == value.lower()
    except ValueError:
        return False


def _response(response, statuses):
    if response.status_code not in statuses:
        # Nunca devolver texto do servidor: ele pode refletir conteúdo/credenciais.
        raise ASPMError(f"ASPM: HTTP {response.status_code}; consulte a documentação da API.")
    try:
        data = response.json()
    except ValueError as exc:
        raise ASPMError("ASPM: resposta sem JSON válido.") from exc
    if not isinstance(data, dict):
        raise ASPMError("ASPM: resposta não é objeto JSON.")
    return data


def _completed(body, sync=True):
    if not _uuid(body.get("test_id")):
        raise ASPMError("ASPM: sucesso sem test_id válido.")
    if sync and not (body.get("engagement") and body.get("branch")):
        raise ASPMError("ASPM: sucesso sem engagement/branch.")
    receipt = body.get("receipt")
    if not isinstance(receipt, dict) or not all(type(receipt.get(k)) is int and receipt[k] >= 0 for k in COUNTERS):
        raise ASPMError("ASPM: sucesso sem recibo válido.")
    return {k: receipt[k] for k in COUNTERS}


@dataclass
class ResultadoEnvio:
    ferramenta: str
    ok: bool
    test_id: str | None = None
    job_id: str | None = None
    url: str = ""
    mensagem: str = ""
    produto: str = ""
    workspace: str = ""
    receipt: dict = field(default_factory=dict)
    replayed: bool = False


class _TokenAuth(requests.auth.AuthBase):
    def __init__(self, token): self.token = token
    def __call__(self, request):
        request.headers["Authorization"] = "Token " + self.token
        return request


class ASPMClient:
    def __init__(self, cfg):
        validar_destino(cfg.aspm_base_url, cfg.aspm_pat, cfg.aspm_workspace, cfg.aspm_business_product)
        self.base = cfg.aspm_base_url
        self.workspace = cfg.aspm_workspace
        self.product = cfg.aspm_business_product
        self.poll_timeout = cfg.aspm_poll_timeout
        self.session = requests.Session()
        self.session.auth = _TokenAuth(cfg.aspm_pat)  # impede substituição por ~/.netrc
        self.session.headers.update({"X-ASPM-Workspace": self.workspace})
        self.sleep = time.sleep
        self.monotonic = time.monotonic

    def enviar(self, *, ferramenta, relatorio, projeto, branch, commit, run_id, scan_complete=False):
        result = ResultadoEnvio(ferramenta, False, produto=projeto, workspace=self.workspace)
        try:
            if ferramenta not in SCAN_TYPES or not re.fullmatch(r"[a-z0-9_-]{1,255}", projeto) or not branch:
                raise ASPMError("ASPM: scanner, repositório ou branch inválidos.")
            if not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
                raise ASPMError("ASPM: commit_sha deve ter 40 caracteres hexadecimais.")
            path = Path(relatorio)
            content = path.read_bytes()
            doc = json.loads(content)
            validar_relatorio(ferramenta, doc)
            identity = [self.base, self.workspace, projeto, branch, SCAN_TYPES[ferramenta], run_id,
                        hashlib.sha256(content).hexdigest(), bool(scan_complete), commit]
            key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
            fields = {"scan_type": SCAN_TYPES[ferramenta], "branch": branch, "product_slug": projeto,
                      "business_product": self.product, "auto_create": "true",
                      "scan_complete": "true" if scan_complete else "false", "commit_sha": commit}
            with path.open("rb") as handle:
                response = self.session.post(self.base + "/api/v1/scans/import/", data=fields,
                    files={"file": (path.name, handle, "application/json")},
                    headers={"Idempotency-Key": key}, timeout=(10, 180), allow_redirects=False)
            body = _response(response, {200, 201, 202})
            sync = True
            if response.status_code == 202:
                job = body.get("job_id")
                if not _uuid(job): raise ASPMError("ASPM: resposta 202 sem job_id válido.")
                result.job_id = job
                log.info("ASPM: %s aceito; job_id=%s; aguardando processamento", ferramenta, job)
                deadline = self.monotonic() + self.poll_timeout
                while self.monotonic() < deadline:
                    self.sleep(min(5, max(0, deadline - self.monotonic())))
                    if self.monotonic() >= deadline: break
                    # Ignora status_url remoto: consulta apenas endpoint canônico da mesma origem.
                    body = _response(self.session.get(self.base + f"/api/v1/scans/jobs/{job}/",
                        timeout=(10, 60), allow_redirects=False), {200})
                    if body.get("status") == "completed":
                        sync = False
                        break
                    if body.get("status") not in {"pending", "processing"}:
                        raise ASPMError("ASPM: job falhou ou retornou status inválido; consulte job_id.")
                else:
                    body = {}
                if body.get("status") != "completed":
                    raise ASPMError("ASPM: espera encerrada; job pode continuar. Consulte job_id antes de reenviar.")
            if response.status_code == 200 and response.headers.get("Idempotency-Replayed") == "true":
                if not _uuid(body.get("test_id")): raise ASPMError("ASPM: replay sem test_id válido.")
                result.replayed = True
            else:
                result.receipt = _completed(body, sync=sync)
            result.test_id = body["test_id"]
            result.ok = True
            result.mensagem = "replay confirmado" if result.replayed else "processamento concluído"
        except ASPMError as exc:
            result.mensagem = str(exc)
        except (requests.RequestException, OSError, ValueError, TypeError, KeyError):
            result.mensagem = "ASPM: falha de rede/TLS ou relatório inválido; consulte jobs antes de reenviar."
        return result


def validar_relatorio(tool, doc):
    if not isinstance(doc, dict): raise ASPMError("Relatório nativo inválido.")
    if tool == "Semgrep" and not isinstance(doc.get("results"), list):
        raise ASPMError("Semgrep: results ausente.")
    if tool == "Bearer" and (doc and not any(k in doc for k in ("critical", "high", "medium", "low", "warning"))):
        raise ASPMError("Bearer: esperado JSON security por severidade.")
    if tool == "Trivy":
        runs = doc.get("runs")
        if doc.get("version") != "2.1.0" or not isinstance(runs, list) or not runs:
            raise ASPMError("Trivy IaC: esperado SARIF 2.1.0.")
        if any("trivy" not in r.get("tool", {}).get("driver", {}).get("name", "").lower() for r in runs):
            raise ASPMError("Trivy IaC: driver SARIF inválido.")


def preparar_relatorio(cfg, tool, doc, trabalho, raiz=None):
    from .scanners import gravar, limpar_trechos
    from .pipeline_security import ambiente_scanner, ASSETS
    from .triage import redigir
    # Remover snippets e valores conhecidos mantendo os formatos nativos dos parsers.
    values = [v for k, v in os.environ.items() if len(v) >= 6 and
              (k.upper().endswith("_PAT") or any(part in k.upper() for part in ("TOKEN", "SECRET", "PASSWORD", "API_KEY", "WEBHOOK")))]
    def clean(value):
        if isinstance(value, str):
            if raiz: value = value.replace(str(raiz) + "/", "")
            for secret in sorted(values, key=len, reverse=True): value = value.replace(secret, "[REDIGIDO]")
            return redigir(value, max(2, len(value) + 1))
        if isinstance(value, list): return [clean(v) for v in value]
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                # Conteúdo derivado do código pode aparecer também em metavariáveis
                # Semgrep e em CauseMetadata.Code do Trivy, além dos snippets comuns.
                if key in {"abstract_content", "code_extract", "snippet"}:
                    result[key] = "[trecho removido pelo SAST Sentinel]"
                elif key == "Code" and isinstance(item, dict) and "Lines" in item:
                    continue
                elif key == "dataflow_trace":
                    continue
                else:
                    result[key] = clean(item)
            return result
        return value
    path = gravar(clean(limpar_trechos(doc, tool)), Path(trabalho) / f"aspm-{tool.lower()}.json")
    if tool == "Trivy":
        if any(r.get("Vulnerabilities") or r.get("Secrets") for r in doc.get("Results") or []):
            raise ASPMError("Contrato trivy-iac não aceita relatórios mistos de CVEs/secrets.")
        output = Path(trabalho) / "trivy-iac.sarif"
        command = [cfg.trivy_bin, "convert", "--format", "sarif", "--output", str(output), str(path)]
        env = ambiente_scanner(cfg, trabalho)
        env["TRIVY_CONFIG"] = str(ASSETS / "trivy.yml")
        converted = subprocess.run(command, capture_output=True, timeout=cfg.trivy_timeout,
                                   env=env, cwd=trabalho, check=False)
        if converted.returncode: raise ASPMError("Trivy: falha ao converter JSON para SARIF.")
        data = json.loads(output.read_text())
        validar_relatorio(tool, data)
        path = gravar(clean(data), output)
    return path
