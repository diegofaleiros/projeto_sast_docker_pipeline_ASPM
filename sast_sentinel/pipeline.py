"""Gate do checkout GitLab: sem coleta de pushes, State ou histórico.

0: aprovado; 1: severidade bloqueadora; 2: falha técnica/integração.
Os relatórios brutos são temporários; apenas o resumo sanitizado é persistido.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .config import Config, ConfigError
from .pipeline_security import (
    validar_config, snapshot_commit, git_command, evidencia_politica, separar_excecoes,
)
from .aspm import ASPMClient, repo_id, preparar_relatorio
from .gitlab import Push
from .scanners import (
    BUCKETS, gravar, inventariar_arvore, limpar_trechos,
    rodar_bearer, rodar_semgrep, rodar_trivy, formatar_diagnostico,
)
from .slack import enviar as enviar_slack, montar_payload
from .triage import (
    normalizar_bearer, normalizar_semgrep, normalizar_trivy, ordenar, redigir,
)

log = logging.getLogger("sentinel.pipeline")


def texto_seguro(value: object, limite: int = 1000) -> str:
    text = str(value or "")
    # Substituir valores conhecidos antes de truncar, inclusive chaves sem prefixo.
    values = [v for k, v in os.environ.items() if len(v) >= 6 and (k.upper().endswith("_PAT") or any(
        part in k.upper() for part in ("TOKEN", "SECRET", "PASSWORD", "API_KEY", "WEBHOOK")))]
    for value in sorted(values, key=len, reverse=True):
        text = text.replace(value, "[REDIGIDO]")
    return redigir(text, limite)


class PipelineLogFormatter(logging.Formatter):
    """Redige também logs de bibliotecas HTTP quando DEBUG está habilitado."""
    def format(self, record):
        text = super().format(record)
        return texto_seguro(text, max(2, len(text) + 1))


def proteger_logs():
    for handler in logging.getLogger().handlers:
        handler.setFormatter(PipelineLogFormatter("%(asctime)s  %(message)s", datefmt="%H:%M:%S"))


def _sanitizar(value):
    if isinstance(value, str):
        return texto_seguro(value, max(2, len(value) + 1))
    if isinstance(value, list):
        return [_sanitizar(v) for v in value]
    if isinstance(value, dict):
        return {k: _sanitizar(v) for k, v in value.items()}
    return value


@dataclass
class ContextoPipeline:
    raiz: Path
    projeto: str
    sha: str
    branch: str
    mr: str
    pipeline_id: str
    pipeline_url: str
    project_url: str
    autor: str

    @classmethod
    def carregar(cls, source: str | None = None):
        raw = source or os.environ.get("PIPELINE_SOURCE_DIR") or os.environ.get("CI_PROJECT_DIR")
        if not raw or not Path(raw).is_dir():
            raise ConfigError("Defina CI_PROJECT_DIR, PIPELINE_SOURCE_DIR ou --source com o checkout.")
        raiz = Path(raw).resolve()
        projeto = os.environ.get("CI_PROJECT_PATH", "").strip()
        sha = os.environ.get("CI_COMMIT_SHA", "").strip().lower()
        branch = (os.environ.get("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME")
                  or os.environ.get("CI_COMMIT_BRANCH") or os.environ.get("CI_COMMIT_REF_NAME", "")).strip()
        if not projeto or not branch or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha):
            raise ConfigError("Pipeline exige CI_PROJECT_PATH, CI_COMMIT_SHA completo e branch/ref de CI.")
        # Só leitura: não altera checkout/configuração Git, não consulta rede nem hooks.
        command = git_command(raiz, "rev-parse")
        try:
            top = subprocess.run(command + ["--show-toplevel"], capture_output=True,
                                 text=True, timeout=15, check=False)
            head = subprocess.run(command + ["HEAD"], capture_output=True,
                                  text=True, timeout=15, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ConfigError("Não foi possível validar o checkout com git.") from exc
        if top.returncode or head.returncode or Path(top.stdout.strip()).resolve() != raiz:
            raise ConfigError("O diretório de análise deve ser a raiz de um checkout Git válido.")
        if head.stdout.strip().lower() != sha:
            raise ConfigError("HEAD difere de CI_COMMIT_SHA; o gate não analisará um commit diferente.")
        mr = os.environ.get("CI_MERGE_REQUEST_IID", "").strip()
        if mr and not mr.isdigit():
            raise ConfigError("CI_MERGE_REQUEST_IID inválido.")
        return cls(raiz, projeto, sha, branch, mr, os.environ.get("CI_PIPELINE_ID", "local"),
                   os.environ.get("CI_PIPELINE_URL", ""), os.environ.get("CI_PROJECT_URL", ""),
                   os.environ.get("GITLAB_USER_NAME") or os.environ.get("GITLAB_USER_LOGIN", "GitLab CI"))

    def push(self):
        return Push(
            event_id=None, criado_em=datetime.now(timezone.utc).isoformat(), projeto_id=0,
            projeto_caminho=texto_seguro(self.projeto), projeto_web_url=self.project_url,
            branch_default=self.branch, autor_username=texto_seguro(self.autor),
            autor_nome=texto_seguro(self.autor), ref=f"refs/heads/{texto_seguro(self.branch)}",
            acao="pipeline", commit_de=None, commit_para=self.sha, qtd_commits=1,
            titulo_commit=texto_seguro(os.environ.get("CI_COMMIT_TITLE", "Pipeline SAST")),
            origem="pipeline")


def verificar_pipeline(cfg: Config, source: str | None = None) -> int:
    policy = validar_config(cfg)
    ctx = ContextoPipeline.carregar(source)
    print(f"Modo pipeline: {texto_seguro(ctx.projeto)} @ {ctx.sha}")
    print("Checkout validado; Histórico local e API GitLab não são acessados. Verificar não executa scanners.")
    return 0


def _validar_resultado(result, arquivos: int) -> list[str]:
    errors = []
    if not result.ok:
        errors.append(f"{result.ferramenta}: execução sem relatório válido")
    # Não reproduzir stderr/stdout: podem conter trechos do repositório e credenciais.
    if result.erros:
        errors.append(f"{result.ferramenta}: {len(result.erros)} erro(s) de execução/cobertura")
        # Publicar somente os campos estruturados sanitizados; nunca mensagens livres.
        errors.extend(formatar_diagnostico(result.ferramenta, d)
                      for d in getattr(result, "diagnosticos", []) if d.get("code") or d["type"] != "process_exit")
    doc = result.documento
    if not isinstance(doc, dict):
        return errors + [f"{result.ferramenta}: estrutura de relatório inválida"]
    if result.ferramenta == "Semgrep":
        if not isinstance(doc.get("results"), list) or not isinstance(doc.get("paths"), dict):
            errors.append("Semgrep: relatório sem results/paths válidos")
        elif not isinstance(doc["paths"].get("scanned"), list):
            errors.append("Semgrep: cobertura de arquivos não informada")
        elif arquivos and not doc["paths"]["scanned"]:
            errors.append("Semgrep: nenhum arquivo analisado; confira linguagem e rulesets")
        if doc.get("errors") and not result.erros:
            errors.append("Semgrep: relatório contém erros de análise")
        for entry in doc.get("results", []) if isinstance(doc.get("results"), list) else []:
            if not isinstance(entry, dict) or not isinstance(entry.get("extra"), dict):
                errors.append("Semgrep: finding com estrutura inválida")
    elif result.ferramenta == "Bearer":
        # {} é o relatório security vazio emitido por versões do Bearer.
        if doc and not any(key in doc for key in BUCKETS):
            errors.append("Bearer: esperado relatório security por severidade")
        if any(doc.get(key) is not None and not isinstance(doc[key], list) for key in BUCKETS):
            errors.append("Bearer: buckets com estrutura inválida")
        if doc.get("errors"):
            errors.append("Bearer: relatório contém erros")
    elif result.ferramenta == "Trivy":
        if not isinstance(doc.get("SchemaVersion"), int):
            errors.append("Trivy: SchemaVersion ausente/inválido")
        if doc.get("Results") is not None and not isinstance(doc["Results"], list):
            errors.append("Trivy: Results inválido")
        for entry in doc.get("Results") or []:
            if not isinstance(entry, dict):
                errors.append("Trivy: resultado com estrutura inválida")
                break
            if entry.get("MisconfSummary", {}).get("Exceptions", 0):
                errors.append("Trivy: exceções na avaliação de configurações")
    return errors


def _notificar(cfg, ctx, findings, docs, scan_errors, blocked, trabalho):
    delivery_errors, deliveries = [], []
    if cfg.dry_run:
        return delivery_errors, {"aspm": "dry-run", "slack": "dry-run"}
    try:
        client = ASPMClient(cfg)
        host = os.environ.get("CI_SERVER_HOST") or __import__("urllib.parse", fromlist=["urlsplit"]).urlsplit(cfg.gitlab_url).hostname
        repository = repo_id(host, ctx.projeto)
    except Exception as exc:
        client = None
        delivery_errors.append(f"ASPM: inicialização falhou ({type(exc).__name__})")
    complete = cfg.aspm_scan_complete and not scan_errors and len(docs) == 3
    # Snapshots sintéticos de merge e tags não representam o HEAD de uma branch.
    complete = complete and not os.environ.get("CI_COMMIT_TAG") and os.environ.get(
        "CI_MERGE_REQUEST_EVENT_TYPE", "") not in {"merged_result", "merge_train"}
    for tool, doc in (docs.items() if client is not None else []):
        try:
            file = preparar_relatorio(cfg, tool, doc, trabalho, trabalho / "source")
            envio = client.enviar(ferramenta=tool, relatorio=file, projeto=repository,
                branch=ctx.branch, commit=ctx.sha, run_id=f"pipeline-{ctx.pipeline_id}",
                scan_complete=bool(complete))
            deliveries.append(envio)
            if not envio.ok:
                delivery_errors.append(f"ASPM: falha no envio de {tool}: {envio.mensagem}")
        except Exception as exc:
            delivery_errors.append(f"ASPM: envio de {tool} falhou ({type(exc).__name__})")
    selected = [a for a in findings if a.severidade in set(cfg.slack_severities + cfg.pipeline_block_severities)]
    try:
        payload = montar_payload(ctx.push(), selected, cfg, deliveries, scan_errors + delivery_errors)
        status = "ERRO TÉCNICO" if scan_errors or delivery_errors else "BLOQUEADA" if blocked else "APROVADA"
        counts = Counter(a.severidade for a in findings)
        payload["text"] = (f"SAST pipeline {status}: {ctx.projeto} @ {ctx.sha[:10]} · "
                           f"HIGH={counts['HIGH']} CRITICAL={counts['CRITICAL']}")
        payload["blocks"][0]["text"]["text"] = f"SAST — pipeline {status}"
        payload["blocks"][1]["text"]["text"] = (
            f"Checkout completo do commit `{ctx.sha[:10]}`. Resultado: *{status}*. "
            "Este modo não consulta nem grava o histórico da auditoria.")
        # Corrige o rodapé do payload do modo auditor: o gate altera o resultado do job.
        payload["blocks"][-1] = {"type": "context", "elements": [{"type": "mrkdwn", "text":
            f"GitLab pipeline {ctx.pipeline_id} · {ctx.pipeline_url}"}]}
        ok, _ = enviar_slack(cfg.slack_webhook, _sanitizar(payload))
        if not ok:
            delivery_errors.append("Slack: falha no envio")
    except Exception as exc:
        delivery_errors.append(f"Slack: notificação falhou ({type(exc).__name__})")
    return delivery_errors, {
        "aspm": [{"scanner": e.ferramenta, "ok": e.ok, "test_id": e.test_id, "job_id": e.job_id, "receipt": e.receipt, "replayed": e.replayed} for e in deliveries],
        "slack": "failed" if any(e.startswith("Slack:") for e in delivery_errors) else "sent"}


def executar_pipeline(cfg: Config, source: str | None = None) -> int:
    # Nenhum State/backend_de/cliente GitLab é instanciado neste módulo.
    policy = validar_config(cfg)
    ctx = ContextoPipeline.carregar(source)
    log.info("Pipeline: %s · commit %s · checkout completo; histórico desativado",
             texto_seguro(ctx.projeto), ctx.sha)
    errors, findings, docs, scanners = [], [], {}, []
    skip = list(cfg.skip_paths)
    # Nunca incluir artifacts gerados por uma tentativa anterior da pipeline.
    cfg.skip_paths = list(dict.fromkeys(skip + ["sentinel-artifacts"]))
    runners = [("Semgrep", rodar_semgrep, normalizar_semgrep),
               ("Bearer", rodar_bearer, normalizar_bearer)]
    if cfg.trivy_enabled:
        runners.append(("Trivy", rodar_trivy, normalizar_trivy))
    try:
        with tempfile.TemporaryDirectory(prefix="sentinel-pipeline-") as tmp:
            trabalho = Path(tmp)
            scan_root = trabalho / "source"
            cfg._pipeline_home = trabalho / "home"
            snapshot_info = {}
            try:
                snapshot_info = snapshot_commit(ctx, scan_root, policy)
                # Arquivo aprovado vazio impede defaults locais de exclusão do Semgrep.
                (scan_root / ".semgrepignore").write_text("")
            except (ConfigError, OSError, subprocess.SubprocessError) as exc:
                errors.append(texto_seguro(exc) if isinstance(exc, ConfigError)
                              else "Falha ao validar/extrair o snapshot do commit")
            arquivos = snapshot_info.get("files", 0)
            for name, runner, normalizer in runners:
                if not snapshot_info:
                    scanners.append({"name": name, "complete": False})
                    continue
                tool_errors, diagnostics = [], []
                try:
                    result = runner(cfg, scan_root, trabalho / f"{name.lower()}.json")
                    tool_errors = _validar_resultado(result, arquivos)
                    diagnostics = result.diagnosticos
                    if isinstance(result.documento, dict):
                        # Não aprovar por falha técnica, mas preservar achados que já foram obtidos.
                        new = (normalizer(result.documento, scan_root, cfg.escalate_high_impact)
                               if name == "Semgrep" else normalizer(result.documento, scan_root))
                        findings.extend(new)
                        if any(a.severidade == "UNKNOWN" for a in new):
                            tool_errors.append(f"{name}: finding com severidade desconhecida")
                        if not tool_errors:
                            docs[name] = result.documento
                except Exception as exc:
                    tool_errors.append(f"{name}: falha técnica ({type(exc).__name__})")
                errors.extend(tool_errors)
                scanners.append({"name": name, "complete": not tool_errors, "diagnostics": diagnostics})
            findings = ordenar(findings)
            actionable, accepted = separar_excecoes(findings, ctx, policy)
            blocked = [a for a in actionable if a.severidade in cfg.pipeline_block_severities]
            delivery_errors, deliveries = _notificar(cfg, ctx, findings, docs, errors, blocked, trabalho)
            technical = ((bool(errors) and cfg.pipeline_fail_on_scan_error)
                         or (bool(delivery_errors) and cfg.pipeline_fail_on_notification_error))
            code = 2 if technical else 1 if blocked else 0
            summary = {
                "schema_version": 1, "mode": "pipeline", "project": ctx.projeto,
                "commit_sha": ctx.sha, "branch": ctx.branch, "pipeline_id": ctx.pipeline_id,
                "scope": "full", "uses_state": False, "dry_run": cfg.dry_run,
                "status": "technical_error" if code == 2 else "blocked" if code == 1 else "passed",
                "exit_code": code, "findings": dict(Counter(a.severidade for a in findings)),
                "blocking_severities": cfg.pipeline_block_severities, "blocking_count": len(blocked),
                "scanners": scanners, "errors": errors + delivery_errors, "notifications": deliveries,
                "policy": evidencia_politica(policy), "snapshot": snapshot_info,
                "accepted_risks": accepted}
            output = Path(os.environ.get("PIPELINE_SUMMARY_PATH") or ctx.raiz / "sentinel-artifacts/summary.json")
            if not output.is_absolute():
                output = ctx.raiz / output
            # Apenas o resumo; nunca exportar JSON bruto dos scanners como artifact.
            gravar(_sanitizar(summary), output)
            log.info("Gate %s · HIGH=%d CRITICAL=%d · bloqueadores=%d · saída=%d",
                     summary["status"], summary["findings"].get("HIGH", 0),
                     summary["findings"].get("CRITICAL", 0), len(blocked), code)
            for error in errors + delivery_errors:
                log.warning("%s", texto_seguro(error))
            print(f"Resumo da pipeline: {texto_seguro(output)}")
            return code
    finally:
        cfg.skip_paths = skip
        if hasattr(cfg, "_pipeline_home"):
            del cfg._pipeline_home
