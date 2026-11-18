"""Carregamento e validação da configuração vinda do .env / ambiente."""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None


class ConfigError(Exception):
    """Configuração faltando ou inválida — a mensagem diz exatamente o quê."""


def _bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in ("1", "true", "yes", "y", "sim", "on"):
        return True
    if raw in ("0", "false", "no", "n", "nao", "não", "off"):
        return False
    raise ConfigError(f"{name}={raw!r} não é booleano. Use true ou false.")


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name}={raw!r} não é um número inteiro.") from exc


def _str(name: str, default: str = "") -> str:
    return os.environ.get(name, "").strip() or default


def _list(name: str, default: tuple[str, ...] = ()) -> list[str]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return list(default)
    return [p.strip() for p in raw.replace("\n", ",").split(",") if p.strip()]


@dataclass
class Config:
    # --- GitLab
    gitlab_url: str
    gitlab_token: str = field(repr=False)
    gitlab_projects: list[str]
    gitlab_membership_only: bool
    gitlab_branches: list[str]

    # --- ASPM: contrato v0.429+/v0.431 do guia Wake
    aspm_base_url: str
    aspm_pat: str = field(repr=False)
    aspm_workspace: str
    aspm_business_product: str
    aspm_scan_complete: bool
    aspm_poll_timeout: int

    # --- Slack
    slack_webhook: str = field(repr=False)
    slack_mentions: list[str]
    slack_severities: list[str]
    slack_max_findings: int

    # --- escopo
    scan_scope: str
    first_run_lookback_days: int
    max_projects: int
    max_pushes: int
    baseline_on_first_run: bool
    baseline_commits: int
    history_fallback: bool

    # --- scanners
    semgrep_bin: str
    bearer_bin: str
    semgrep_configs: list[str]
    semgrep_timeout: int
    bearer_scanners: str
    skip_paths: list[str]
    escalate_high_impact: bool

    # --- saídas
    state_dir: Path
    report_dir: Path
    report_xlsx: bool

    # --- operação
    dry_run: bool
    log_level: str
    allow_insecure_http: bool
    gitlab_verify_tls: bool

    # --- Trivy
    trivy_enabled: bool = True
    trivy_bin: str = ""
    trivy_scanners: str = "misconfig"
    trivy_timeout: int = 600
    trivy_ignore_unfixed: bool = False

    # --- gate local do GitLab Runner; nunca acessa estado/GitLab API
    run_pipeline: bool = False
    pipeline_block_severities: list[str] = field(default_factory=lambda: ["HIGH", "CRITICAL"])
    pipeline_fail_on_scan_error: bool = True
    pipeline_fail_on_notification_error: bool = True

    # --- diagnóstico do próprio .env
    env_path: Path | None = None
    avisos_env: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------ construção
    @classmethod
    def load(cls, env_file: str | os.PathLike[str] | None = None, require_all: bool = True,
             pipeline: bool | None = None, dry_run: bool = False) -> "Config":
        root = Path(__file__).resolve().parent.parent
        path = Path(env_file) if env_file else root / ".env"
        if load_dotenv and path.exists():
            load_dotenv(path, override=False)
        pipeline_mode = _bool("RUN_PIPELINE") if pipeline is None else pipeline
        if not path.exists() and require_all and not pipeline_mode and not (
                _str("GITLAB_URL") and _str("GITLAB_API_TOKEN")):
            # Em container não há .env: tudo vem de variável de ambiente real. Só é erro
            # quando falta configuração de fato (validate() cobre o restante).
            raise ConfigError(
                f"arquivo de configuração não encontrado: {path}\n"
                f"    Crie a partir do template:  cp .env.example .env && chmod 600 .env"
            )

        # O padrão de CI vem da política embarcada, não de uma escolha livre do projeto.
        trivy_default = "misconfig"  # auditor fora do container mantém seu padrão
        if pipeline_mode:
            from .pipeline_security import carregar_politica
            trivy_default = ",".join(carregar_politica()["trivy_required_scanners"])

        scope = _str("SCAN_SCOPE", "changed").lower()
        if scope not in ("changed", "full"):
            raise ConfigError(f"SCAN_SCOPE={scope!r} inválido. Use 'changed' ou 'full'.")

        cfg = cls(
            gitlab_url=_str("GITLAB_URL").rstrip("/"),
            gitlab_token=_str("GITLAB_API_TOKEN"),
            gitlab_projects=_list("GITLAB_PROJECTS"),
            gitlab_membership_only=_bool("GITLAB_MEMBERSHIP_ONLY"),
            gitlab_branches=_list("GITLAB_BRANCHES"),
            aspm_base_url=_str("ASPM_BASE_URL").rstrip("/"),
            aspm_pat=_str("ASPM_PAT"),
            aspm_workspace=_str("ASPM_WORKSPACE"),
            aspm_business_product=_str("ASPM_BUSINESS_PRODUCT"),
            aspm_scan_complete=_bool("ASPM_SCAN_COMPLETE", False),
            aspm_poll_timeout=_int("ASPM_POLL_TIMEOUT", 900),
            slack_webhook=_str("SLACK_WEBHOOK_URL"),
            slack_mentions=_str("SLACK_MENTIONS").split(),
            slack_severities=[s.upper() for s in _list("SLACK_SEVERITIES", ("CRITICAL", "HIGH"))],
            slack_max_findings=_int("SLACK_MAX_FINDINGS", 10),
            scan_scope=scope,
            first_run_lookback_days=_int("FIRST_RUN_LOOKBACK_DAYS", 7),
            max_projects=_int("MAX_PROJECTS", 2000),
            max_pushes=_int("MAX_PUSHES", 50),
            baseline_on_first_run=_bool("BASELINE_ON_FIRST_RUN", True),
            baseline_commits=_int("BASELINE_COMMITS", 1),
            history_fallback=_bool("HISTORY_FALLBACK", True),
            semgrep_bin=_str("SEMGREP_BIN"),
            bearer_bin=_str("BEARER_BIN"),
            semgrep_configs=_str("SEMGREP_CONFIGS", "p/default p/owasp-top-ten p/secrets").split(),
            semgrep_timeout=_int("SEMGREP_TIMEOUT", 120),
            bearer_scanners=_str("BEARER_SCANNERS", "sast,secrets"),
            skip_paths=_list("SCAN_SKIP_PATHS", (".git", "sentinel-artifacts") if pipeline_mode else
                             (".git", "node_modules", "vendor", "dist", "build", ".venv", "target")),
            escalate_high_impact=_bool("ESCALATE_HIGH_IMPACT", True),
            state_dir=(root / _str("STATE_DIR", ".state-aspm")).resolve(),
            report_dir=(root / _str("REPORT_DIR", "relatorios")).resolve(),
            report_xlsx=_bool("REPORT_XLSX", True),
            dry_run=dry_run or _bool("DRY_RUN", False),
            log_level=_str("LOG_LEVEL", "INFO").upper(),
            allow_insecure_http=_bool("ALLOW_INSECURE_HTTP", False),
            gitlab_verify_tls=_bool("GITLAB_VERIFY_TLS", True),
            trivy_enabled=_bool("TRIVY_ENABLED", True),
            trivy_bin=_str("TRIVY_BIN"),
            trivy_scanners=_str("TRIVY_SCANNERS", trivy_default),
            trivy_timeout=_int("TRIVY_TIMEOUT", 600),
            trivy_ignore_unfixed=_bool("TRIVY_IGNORE_UNFIXED", False),
            run_pipeline=pipeline_mode,
            pipeline_block_severities=[s.upper() for s in _list(
                "PIPELINE_BLOCK_SEVERITIES", ("HIGH", "CRITICAL"))],
            pipeline_fail_on_scan_error=_bool("PIPELINE_FAIL_ON_SCAN_ERROR", True),
            pipeline_fail_on_notification_error=_bool("PIPELINE_FAIL_ON_NOTIFICATION_ERROR", True),
        )
        cfg.env_path = path
        cfg.avisos_env = auditar_env(path)
        cfg._resolve_scanners()
        if require_all:
            cfg.validate()
        return cfg

    # ------------------------------------------------------------------ validação
    def _resolve_scanners(self) -> None:
        if not self.semgrep_bin:
            # Preferência ao semgrep do próprio venv, que é o que o requirements instala.
            venv_bin = Path(sys.executable).parent / "semgrep"
            self.semgrep_bin = str(venv_bin) if venv_bin.exists() else (shutil.which("semgrep") or "")
        if not self.bearer_bin:
            self.bearer_bin = shutil.which("bearer") or ""
        if not self.trivy_bin:
            self.trivy_bin = shutil.which("trivy") or ""

    def validate(self) -> None:
        faltando: list[str] = []
        if not self.run_pipeline and not self.gitlab_url:
            faltando.append("GITLAB_URL")
        if not self.run_pipeline and not self.gitlab_token:
            faltando.append("GITLAB_API_TOKEN")
        if not self.dry_run:
            for name in ("ASPM_BASE_URL", "ASPM_PAT", "ASPM_WORKSPACE", "ASPM_BUSINESS_PRODUCT"):
                if not getattr(self, name.lower()):
                    faltando.append(name)
        if self.run_pipeline and not self.dry_run and not self.slack_webhook:
            faltando.append("SLACK_WEBHOOK_URL (obrigatório no modo pipeline, exceto dry-run)")
        # SLACK_WEBHOOK_URL é opcional de propósito: rodar só contra o ASPM é um
        # uso legítimo. A ausência vira aviso na execução, não erro de configuração.
        if faltando:
            msg = ("variáveis obrigatórias não preenchidas no .env: " + ", ".join(faltando)
                   + "\n    (em DRY_RUN=true só GITLAB_URL e GITLAB_API_TOKEN são exigidas)")
            # Se o valor existe mas sob outro nome, dizer isso vale mais que a lista.
            pistas = [a for a in self.avisos_env if any(f in a for f in faltando)]
            if pistas:
                msg += "\n\n    Possível causa — nomes de variável no seu .env:"
                for pista in pistas:
                    msg += f"\n      · {pista}"
            raise ConfigError(msg)

        from .aspm import validar_destino
        if not self.dry_run:
            validar_destino(self.aspm_base_url, self.aspm_pat, self.aspm_workspace,
                            self.aspm_business_product)
        if not 1 <= self.aspm_poll_timeout <= 3600:
            raise ConfigError("ASPM_POLL_TIMEOUT deve ficar entre 1 e 3600 segundos.")
        if set(self.trivy_scanners.split(",")) != {"misconfig"}:
            raise ConfigError("O contrato ASPM aceita Trivy IaC; use TRIVY_SCANNERS=misconfig.")
        if os.environ.get("STATE_BACKEND", "local").lower() != "local":
            raise ConfigError("Esta edição usa somente estado local. Remova STATE_BACKEND e variáveis AWS/STATE_S3.")

        self._checar_esquema("GITLAB_URL", self.gitlab_url, "o token do GitLab")
        if self.slack_webhook and not self.slack_webhook.startswith("https://hooks.slack.com/"):
            raise ConfigError(
                "SLACK_WEBHOOK_URL precisa começar com https://hooks.slack.com/ — "
                "envio para outro destino é recusado por segurança."
            )
        if not self.semgrep_bin and not self.bearer_bin:
            raise ConfigError(
                "nenhum scanner encontrado. Rode `bash setup.sh`, ou aponte SEMGREP_BIN / BEARER_BIN."
            )

        if self.run_pipeline:
            validas = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
            if not self.pipeline_block_severities or set(self.pipeline_block_severities) - validas:
                raise ConfigError("PIPELINE_BLOCK_SEVERITIES exige uma lista de severidades válidas.")
            if not self.semgrep_configs:
                raise ConfigError("SEMGREP_CONFIGS não pode ser vazio no modo pipeline.")

        if self.run_pipeline:
            from .pipeline_security import validar_config
            validar_config(self)

        for m in self.slack_mentions:
            if m.startswith("@"):
                raise ConfigError(
                    f"SLACK_MENTIONS contém {m!r} como texto puro, que NÃO notifica ninguém no Slack. "
                    "Use a sintaxe de user group: <!subteam^S01ABCDEF|@nome>"
                )

    def _checar_esquema(self, nome: str, url: str, o_que_vaza: str) -> None:
        """Exige https, com duas exceções explícitas: loopback e ALLOW_INSECURE_HTTP."""
        if not url or url.startswith("https://"):
            return
        if not url.startswith("http://"):
            raise ConfigError(f"{nome}={url!r} não tem esquema válido. Use https:// (ou http:// em teste).")
        # Loopback nunca sai da máquina — liberado sem precisar de flag.
        if _host_privado(url) == "loopback":
            return
        if self.allow_insecure_http:
            return
        raise ConfigError(
            f"{nome} está em http:// — sem TLS, {o_que_vaza} trafega em claro e qualquer\n"
            f"    um no caminho de rede pode capturá-lo.\n"
            f"\n"
            f"    Se for ambiente de teste e você aceita esse risco, libere no .env:\n"
            f"        ALLOW_INSECURE_HTTP=true\n"
            f"\n"
            f"    Use um token dedicado ao teste, nunca o de produção.\n"
            f"    Se o servidor tem TLS mas com certificado autoassinado, prefira manter\n"
            f"    https:// e desligar só a validação:  GITLAB_VERIFY_TLS=false"
        )

    def avisos_de_seguranca(self) -> list[str]:
        """Avisos repetidos em toda execução — configuração insegura não vira rotina calada."""
        avisos: list[str] = []
        for nome, url in (("GITLAB_URL", self.gitlab_url),):
            if url.startswith("http://") and _host_privado(url) != "loopback":
                alcance = _host_privado(url)
                extra = ("o host NÃO parece ser de rede privada — o tráfego pode atravessar a internet"
                         if alcance == "publico" else "host de rede privada")
                avisos.append(f"{nome} em http:// sem TLS ({extra}); credencial trafega em claro")
        if not self.gitlab_verify_tls:
            avisos.append("GITLAB_VERIFY_TLS=false: certificado do GitLab não é validado")
        return avisos

    # ------------------------------------------------------------------ diagnóstico
    def resumo(self) -> str:
        def marca(v: object) -> str:
            return "definido" if v else "VAZIO"

        def tls(url: str, verifica: bool) -> str:
            if url.startswith("http://"):
                return "  ⚠ SEM TLS"
            return "" if verifica else "  ⚠ certificado não validado"

        linhas = [
            f"GitLab            {self.gitlab_url}  (token: {marca(self.gitlab_token)})"
            f"{tls(self.gitlab_url, self.gitlab_verify_tls)}",
            f"ASPM              {self.aspm_base_url or '—'}  (PAT: {marca(self.aspm_pat)})",
            f"Empresa/Produto   {self.aspm_workspace or '—'} / {self.aspm_business_product or '—'}",
            f"Slack             {'webhook definido' if self.slack_webhook else 'VAZIO'}"
            f"  · menções: {len(self.slack_mentions)}",
            f"Escopo            {self.scan_scope}  ·  projetos: "
            f"{', '.join(self.gitlab_projects) if self.gitlab_projects else 'instância inteira'}",
            f"Branches          {', '.join(self.gitlab_branches) if self.gitlab_branches else 'todas'}",
            f"Semgrep           {self.semgrep_bin or 'AUSENTE'}",
            f"Bearer            {self.bearer_bin or 'AUSENTE'}  (scanners: {self.bearer_scanners})",
            f"Tetos             {self.max_pushes} pushes · {self.max_projects} projetos",
            f"Modo              {'DRY-RUN (nada é enviado)' if self.dry_run else 'produção'}",
        ]
        return "\n".join("  " + linha for linha in linhas)


# Diagnóstico sem exibir valores de credenciais.
VARIAVEIS_CONHECIDAS = {
    "ASPM_BASE_URL", "ASPM_PAT", "ASPM_WORKSPACE", "ASPM_BUSINESS_PRODUCT",
    "ASPM_SCAN_COMPLETE", "ASPM_POLL_TIMEOUT",
    "GITLAB_URL", "GITLAB_API_TOKEN", "GITLAB_PROJECTS", "GITLAB_MEMBERSHIP_ONLY",
    "GITLAB_BRANCHES", "GITLAB_VERIFY_TLS", "SLACK_WEBHOOK_URL", "SLACK_MENTIONS",
    "SLACK_SEVERITIES", "SLACK_MAX_FINDINGS", "SCAN_SCOPE", "FIRST_RUN_LOOKBACK_DAYS",
    "MAX_PROJECTS", "MAX_PUSHES", "BASELINE_ON_FIRST_RUN", "BASELINE_COMMITS", "HISTORY_FALLBACK",
    "SEMGREP_BIN", "BEARER_BIN", "SEMGREP_CONFIGS", "SEMGREP_TIMEOUT", "BEARER_SCANNERS",
    "SCAN_SKIP_PATHS", "ESCALATE_HIGH_IMPACT", "STATE_DIR", "REPORT_DIR", "REPORT_XLSX",
    "DRY_RUN", "LOG_LEVEL", "ALLOW_INSECURE_HTTP", "TRIVY_ENABLED", "TRIVY_BIN",
    "TRIVY_SCANNERS", "TRIVY_TIMEOUT", "TRIVY_IGNORE_UNFIXED", "RUN_PIPELINE",
    "PIPELINE_BLOCK_SEVERITIES", "PIPELINE_FAIL_ON_SCAN_ERROR", "PIPELINE_FAIL_ON_NOTIFICATION_ERROR",
    "PIPELINE_SOURCE_DIR", "PIPELINE_SUMMARY_PATH",
}
APELIDOS = {}


def auditar_env(caminho: Path) -> list[str]:
    """Lê o .env como texto e aponta variáveis que o Sentinel não usa.

    Olha o ARQUIVO, não o ambiente já carregado, porque o objetivo é justamente pegar a
    linha que o dotenv carregou e o código nunca consultou.
    """
    problemas: list[str] = []
    if not caminho.exists():
        return problemas
    definidas: dict[str, str] = {}
    comentadas: set[str] = set()
    try:
        texto = caminho.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return problemas

    for linha in texto.splitlines():
        crua = linha.strip()
        if not crua or "=" not in crua:
            continue
        comentada = crua.startswith("#")
        nome = crua.lstrip("#").split("=", 1)[0].strip()
        valor = crua.split("=", 1)[1].strip().strip("'\"")
        if not nome or " " in nome:
            continue
        if comentada:
            comentadas.add(nome)
        else:
            definidas[nome] = valor

    for nome, valor in definidas.items():
        if nome in VARIAVEIS_CONHECIDAS:
            continue
        certo = APELIDOS.get(nome)
        if certo:
            detalhe = f"{nome} não é lida pelo Sentinel — o nome correto é {certo}"
            if certo in definidas and definidas[certo]:
                detalhe += f" (que já está preenchida; {nome} é redundante)"
            elif certo in comentadas:
                detalhe += f". {certo} está COMENTADA no arquivo: descomente e mova o valor para ela"
            elif certo not in definidas:
                detalhe += f". {certo} não existe no arquivo: renomeie esta linha"
            problemas.append(detalhe)
        else:
            parecidas = [v for v in VARIAVEIS_CONHECIDAS if _parecido(nome, v)]
            sugestao = f" — você quis dizer {parecidas[0]}?" if parecidas else " — ignorada"
            problemas.append(f"{nome} não é reconhecida{sugestao}")
    return problemas


def _parecido(a: str, b: str) -> bool:
    import difflib

    return difflib.SequenceMatcher(None, a, b).ratio() > 0.82


def _host_privado(url: str) -> str:
    """Classifica o alcance do host: 'loopback', 'privado' ou 'publico'.

    Serve para graduar o aviso: http:// num IP de rede interna é bem menos grave que
    http:// num host que pode estar atravessando a internet.
    """
    import ipaddress
    from urllib.parse import urlsplit

    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return "publico"
    if not host:
        return "publico"
    if host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost"):
        return "loopback"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Nome de host: heurística por sufixo e por ausência de domínio público.
        if host.endswith((".local", ".internal", ".lan", ".intranet", ".test", ".localdomain")):
            return "privado"
        return "privado" if "." not in host else "publico"
    if ip.is_loopback:
        return "loopback"
    return "privado" if (ip.is_private or ip.is_link_local) else "publico"


def _loopback(url: str) -> bool:
    """Mantido para os mocks de teste, que sobem em 127.0.0.1."""
    return _host_privado(url) == "loopback" and url.startswith("http://")
