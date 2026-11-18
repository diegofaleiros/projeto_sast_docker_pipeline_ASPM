"""Política do gate, controlada pelo build da imagem; não aceita caminho via ENV.

O job central continua obrigatório: quem controla o comando do job pode deixar de
executar o gate. Estes controles protegem a execução, não substituem o GitLab.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
from datetime import date
from urllib.parse import urlparse

from .config import ConfigError

POLICY_PATH = Path(__file__).with_name("pipeline-policy.json")
ASSETS = Path(__file__).with_name("pipeline_assets")


def carregar_politica():
    try:
        data = json.loads(POLICY_PATH.read_text())
        if data.get("schema_version") != 1:
            raise ValueError("schema")
        for key in ("executables", "semgrep_required", "semgrep_allowed", "block_severities", "exceptions", "trivy_required_scanners"):
            if key not in data:
                raise ValueError(key)
        trivy = data["trivy_required_scanners"]
        if (not isinstance(trivy, list) or not trivy
                or any(not isinstance(s, str) or s not in {"vuln", "misconfig", "secret"} for s in trivy)
                or len(set(trivy)) != len(trivy)):
            raise ValueError("scanners Trivy inválidos na política")
        for item in data["exceptions"]:
            required = ("scanner", "rule", "project", "path", "expires", "reason", "approved_by", "ticket")
            if any(not isinstance(item.get(k), str) or not item[k].strip() for k in required):
                raise ValueError("exceção sem rastreabilidade")
            if date.fromisoformat(item["expires"]) < date.today():
                raise ValueError("exceção expirada")
            if any(c in item["path"] for c in "*?[") or ".." in PurePosixPath(item["path"]).parts:
                raise ValueError("exceção exige caminho exato")
        return data
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise ConfigError("Política do gate ausente/inválida ou com exceção expirada; revisar imagem.") from exc


def _protegido(path, policy, executavel=False):
    p = Path(path)
    if not p.is_file() or (executavel and not os.access(p, os.X_OK)):
        raise ConfigError("Executável/arquivo aprovado da política não está instalado na imagem.")
    if policy.get("require_root_owned", True):
        info = p.stat()
        if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ConfigError("Arquivos aprovados devem pertencer a root e não permitir escrita por grupo/outros.")


def validar_config(cfg):
    policy = carregar_politica()
    _protegido(POLICY_PATH, policy)
    if not set(policy["block_severities"]).issubset(cfg.pipeline_block_severities):
        raise ConfigError("O gate não permite remover HIGH/CRITICAL da política bloqueadora.")
    if not cfg.pipeline_fail_on_scan_error or not cfg.pipeline_fail_on_notification_error:
        raise ConfigError("O gate exige reprovação em falha de scanner e de notificação.")
    if not cfg.trivy_enabled or cfg.trivy_ignore_unfixed or not cfg.escalate_high_impact:
        raise ConfigError("O gate exige Trivy ativo, CVEs sem correção visíveis e triagem de alto impacto.")
    configured = [s.strip() for s in cfg.trivy_scanners.split(",")]
    required = policy["trivy_required_scanners"]
    if (not all(configured) or len(set(configured)) != len(configured)
            or set(configured) != set(required)):
        raise ConfigError("TRIVY_SCANNERS difere da política aprovada na imagem: " + ",".join(required))
    cfg.trivy_scanners = ",".join(configured)
    if set(cfg.bearer_scanners.split(",")) != {"sast", "secrets"}:
        raise ConfigError("BEARER_SCANNERS deve conter sast,secrets no gate obrigatório.")
    if (not set(policy["semgrep_required"]).issubset(cfg.semgrep_configs)
            or set(cfg.semgrep_configs) - set(policy["semgrep_allowed"])):
        raise ConfigError("SEMGREP_CONFIGS deve preservar os packs obrigatórios e usar só packs aprovados na imagem.")
    if set(cfg.skip_paths) - set(policy["allowed_skip_paths"]):
        raise ConfigError("SCAN_SKIP_PATHS contém exclusão não aprovada para pipeline.")
    if cfg.aspm_base_url and urlparse(cfg.aspm_base_url).scheme != "https":
        raise ConfigError("O gate exige HTTPS e validação TLS do ASPM.")
    if not cfg.dry_run and urlparse(cfg.aspm_base_url).hostname not in policy["aspm_allowed_hosts"]:
        raise ConfigError("Host do ASPM não aprovado na política da imagem.")
    if cfg.dry_run and os.environ.get("GITLAB_CI", "").lower() == "true":
        raise ConfigError("Dry-run não é permitido no gate obrigatório do GitLab CI.")
    for name, attr in (("Semgrep", "semgrep_bin"), ("Bearer", "bearer_bin"), ("Trivy", "trivy_bin")):
        expected = policy["executables"][name]
        if str(Path(getattr(cfg, attr)).absolute()) != str(Path(expected).absolute()):
            raise ConfigError(f"{name}: executável fora do caminho aprovado pela imagem.")
        _protegido(expected, policy, True)
    # Assegura material de regras íntegro, quando empacotado na imagem.
    manifest_file = ASSETS / "rules-manifest.json"
    if policy.get("require_cached_rules", True):
        _protegido(manifest_file, policy)
        try:
            manifest = json.loads(manifest_file.read_text())
            for pack in cfg.semgrep_configs:
                item = manifest[pack]
                file = ASSETS / item["file"]
                if file.parent != ASSETS or hashlib.sha256(file.read_bytes()).hexdigest() != item["sha256"]:
                    raise ValueError("hash")
                _protegido(file, policy)
        except (KeyError, ValueError, OSError, TypeError) as exc:
            raise ConfigError("Ruleset Semgrep não corresponde ao manifesto da imagem.") from exc
    for name in ("bearer.yml", "trivy.yml", "empty.ignore", "bearer.ignore"):
        _protegido(ASSETS / name, policy)
    cfg._pipeline_policy = policy
    return policy


def regras_semgrep(cfg):
    if not getattr(cfg, "run_pipeline", False):
        return cfg.semgrep_configs
    manifest = ASSETS / "rules-manifest.json"
    if not manifest.exists():
        return cfg.semgrep_configs  # somente harness de teste; política de produção exige manifesto
    data = json.loads(manifest.read_text())
    return [str(ASSETS / data[pack]["file"]) for pack in cfg.semgrep_configs]


def ambiente_scanner(cfg, origem):
    # Não repassa chaves ASPM, Slack, tokens CI ou opções nativas manipuláveis.
    safe = ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
            "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR")
    env = {key: os.environ[key] for key in safe if key in os.environ}
    env.update(PATH="/opt/venv/bin:/usr/local/bin:/usr/bin:/bin", LANG="C.UTF-8",
               HOME=str(getattr(cfg, "_pipeline_home", Path(origem).parent / "home")),
               GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_COUNT="2",
               GIT_CONFIG_KEY_0="safe.directory", GIT_CONFIG_VALUE_0=str(Path(origem).resolve()),
               GIT_CONFIG_KEY_1="core.fsmonitor", GIT_CONFIG_VALUE_1="false",
               SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")
    Path(env["HOME"]).mkdir(parents=True, exist_ok=True)
    return env


def git_command(raiz, *args):
    policy = carregar_politica()
    return [policy["executables"]["Git"], "--no-optional-locks", "-c", f"safe.directory={raiz}",
            "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", str(raiz), *args]


FORBIDDEN = {".semgrepignore", ".semgrepignore-v2", "bearer.yml", "bearer.yaml", ".bearer.yml",
             ".bearer.yaml", "bearer.ignore", ".bearerignore", "trivy.yaml", "trivy.yml",
             "trivy-secret.yaml", "trivy-secret.yml", ".trivyignore", ".trivyignore.yaml",
             ".trivyignore.yml", ".trivyignore.rego"}
INLINE = re.compile(rb"(?i)(?:#|//|/\*|<!--)\s*(?:bearer\s*[:\-]\s*(?:disable|ignore|skip)|trivy\s*:\s*ignore|tfsec\s*:\s*ignore|checkov\s*:\s*skip)")
CODE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".cs", ".php", ".rb",
            ".kt", ".scala", ".tf", ".yaml", ".yml", ".json", ".sh", ".html"}


def snapshot_commit(ctx, destino, policy):
    """Extrai blobs por OID, sem export-ignore, filtros Git ou arquivos não versionados."""
    destino = Path(destino)
    destino.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
    tree = subprocess.run(git_command(ctx.raiz, "ls-tree", "-rz", "--full-tree", ctx.sha),
                          capture_output=True, timeout=60, env=env, check=True).stdout
    records = [r for r in tree.split(b"\0") if r]
    if not records or len(records) > policy["max_files"]:
        raise ConfigError("Snapshot vazio ou acima do limite de arquivos da política.")
    digest = hashlib.sha256()
    total = 0
    proc = subprocess.Popen(git_command(ctx.raiz, "cat-file", "--batch"), stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
    try:
        for record in records:
            attrs, raw_name = record.split(b"\t", 1)
            mode, kind, oid = attrs.split()
            name = os.fsdecode(raw_name)
            relative = PurePosixPath(name)
            if (kind != b"blob" or mode not in (b"100644", b"100755")
                    or relative.is_absolute() or ".." in relative.parts
                    or any(part in (".git", "sentinel-artifacts") for part in relative.parts)):
                raise ConfigError("Snapshot contém symlink, submódulo ou caminho não suportado pelo gate.")
            if relative.name.lower() in FORBIDDEN:
                raise ConfigError(f"Configuração/supressão local não permitida: {name}; usar política central.")
            assert proc.stdin is not None and proc.stdout is not None
            proc.stdin.write(oid + b"\n"); proc.stdin.flush()
            header = proc.stdout.readline().split()
            if len(header) != 3 or header[0] != oid or header[1] != b"blob":
                raise ConfigError("Não foi possível ler um blob do commit.")
            size = int(header[2]); total += size
            if size > policy["max_blob_bytes"] or total > policy["max_snapshot_bytes"]:
                raise ConfigError("Snapshot excede limite de tamanho; não será aprovado parcialmente.")
            content = proc.stdout.read(size)
            if len(content) != size or proc.stdout.read(1) != b"\n":
                raise ConfigError("Objeto Git incompleto.")
            if (relative.suffix.lower() in CODE_EXT or relative.name.lower().startswith("dockerfile")):
                if size > policy["max_code_bytes"]:
                    raise ConfigError("Arquivo de código excede o limite de cobertura do Semgrep.")
                if INLINE.search(content):
                    raise ConfigError(f"Supressão inline não aprovada: {name}; usar exceção central.")
            local = ctx.raiz / name
            if local.is_symlink() or not local.is_file() or not local.resolve().is_relative_to(ctx.raiz):
                raise ConfigError("Checkout difere do commit: arquivo ausente ou redirecionado.")
            if local.read_bytes() != content:
                raise ConfigError(f"Checkout modificado em relação a CI_COMMIT_SHA: {name}")
            target = destino / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            target.chmod(0o755 if mode == b"100755" else 0o644)
            digest.update(record + b"\0")
        return {"files": len(records), "bytes": total, "tree_manifest_sha256": digest.hexdigest()}
    finally:
        if proc.stdin:
            proc.stdin.close()
        if proc.stdout:
            proc.stdout.close()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait()


def separar_excecoes(findings, ctx, policy):
    accepted, remaining = [], []
    for finding in findings:
        match = next((e for e in policy["exceptions"] if
                      e["project"] == ctx.projeto and e["scanner"] == finding.ferramenta
                      and e["rule"] == finding.regra and e["path"] == finding.arquivo), None)
        if match:
            accepted.append({"scanner": finding.ferramenta, "rule": finding.regra,
                             "path": finding.arquivo, "ticket": match["ticket"], "expires": match["expires"],
                             "approved_by": match["approved_by"], "reason": match["reason"]})
        else:
            remaining.append(finding)
    return remaining, accepted


def evidencia_politica(policy):
    manifest = ASSETS / "rules-manifest.json"
    return {"id": policy["id"], "sha256": hashlib.sha256(POLICY_PATH.read_bytes()).hexdigest(),
            "rules": json.loads(manifest.read_text()) if manifest.exists() else {},
            "required_scanners": ["Semgrep", "Bearer", "Trivy"],
            "trivy_required_scanners": list(policy["trivy_required_scanners"])}


def cache_regras():
    """Somente no build; nenhuma credencial de integração é usada."""
    import requests
    policy = carregar_politica()
    manifest = {}
    ASSETS.mkdir(exist_ok=True)
    for pack in policy["semgrep_allowed"]:
        response = requests.get(f"https://semgrep.dev/c/{pack}", timeout=90)
        response.raise_for_status()
        name = pack.replace("/", "-") + ".yaml"
        content = response.content
        from ruamel.yaml import YAML
        parsed = YAML(typ="safe").load(content)
        if (not isinstance(parsed, dict) or not isinstance(parsed.get("rules"), list)
                or not parsed["rules"]):
            raise RuntimeError("Resposta inesperada do registry Semgrep")
        (ASSETS / name).write_bytes(content)
        manifest[pack] = {"file": name, "sha256": hashlib.sha256(content).hexdigest()}
    (ASSETS / "rules-manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"Rulesets aprovados empacotados: {len(manifest)}")


if __name__ == "__main__":
    cache_regras()