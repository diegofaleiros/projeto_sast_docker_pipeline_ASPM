"""Execução do Semgrep e do Bearer, e recorte dos relatórios ao código novo do push.

Por que a ANÁLISE roda sobre a árvore inteira mesmo quando você quer só o código novo
-------------------------------------------------------------------------------------
O pedido é "SAST sobre o código novo alterado", e é isso que sai no relatório. Mas o
scanner precisa ver a árvore toda:

  * o Bearer não tem `--only-path` — só `--skip-path`;
  * SQL injection normalmente atravessa arquivos: a entrada não sanitizada entra num
    `handler.py` que o push não tocou e desemboca no `db.py` que ele tocou. Rodando só
    sobre o diff, o rastreio de fluxo de dados perde a origem e o achado desaparece.

Então: analisa tudo, reporta o que o push tocou (`SCAN_SCOPE=changed`). O recorte é
feito sobre o JSON bruto, preservando o formato — assim os parsers do ASPM
continuam funcionando normalmente.
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ResultadoScanner:
    ferramenta: str
    ok: bool
    caminho_json: Path | None = None
    documento: dict | None = None
    erros: list[str] = field(default_factory=list)
    segundos: float = 0.0
    diagnosticos: list[dict] = field(default_factory=list)
    # Quantos arquivos a ferramenta realmente abriu. Sem isto, "0 achados" é ambíguo:
    # pode ser código limpo ou pode ser que nada tenha sido analisado.
    arquivos_varridos: int = -1
    arquivos_ignorados: int = 0


def _normalizar(caminho: str) -> str:
    return str(caminho or "").replace("\\", "/").lstrip("./").lower()


def _relativo(caminho: str, raiz: Path) -> str:
    try:
        return str(Path(caminho).resolve().relative_to(raiz.resolve())).replace("\\", "/")
    except (ValueError, OSError):
        texto = str(caminho).replace("\\", "/")
        marca = str(raiz).replace("\\", "/").rstrip("/") + "/"
        return texto[len(marca):] if texto.startswith(marca) else texto.lstrip("./")


def _ambiente_scanner(cfg, origem: Path):
    if not getattr(cfg, "run_pipeline", False):
        return None  # auditor mantém o ambiente anterior
    from .pipeline_security import ambiente_scanner
    return ambiente_scanner(cfg, origem)


# Only schema-defined labels are publishable; variant payloads can contain source code.
_SEMGREP_ERROR_TYPES = {name: name for name in (
    "ParseError", "Timeout", "PartialParsing", "RuleParseError", "PatternParseError",
    "LexicalError", "SemgrepError", "SemgrepWarning", "InvalidRuleSchemaError",
    "InvalidLanguage", "UnknownLanguageError", "TooManyMatches", "OtherParseError",
    "AstBuilderError", "InvalidYaml", "MatchingError", "SemgrepMatchFound", "FatalError",
    "OutOfMemory", "FixpointTimeout", "StackOverflow", "TimeoutDuringInterfile",
    "OutOfMemoryDuringInterfile", "MissingPlugin", "IncompatibleRule", "DependencyResolutionError",
)}
_SEMGREP_ERROR_TYPES.update(dict(zip((
    "Syntax error", "Lexical error", "Other syntax error", "AST builder error",
    "Rule parse error", "Pattern parse error", "Invalid YAML", "Internal matching error",
    "Semgrep match found", "Too many matches", "Fatal error", "Out of memory",
    "Fixpoint timeout", "Stack overflow", "Timeout during interfile analysis",
    "OOM during interfile analysis", "Missing plugin", "Incompatible rule",
), (
    "ParseError", "LexicalError", "OtherParseError", "AstBuilderError",
    "RuleParseError", "PatternParseError", "InvalidYaml", "MatchingError",
    "SemgrepMatchFound", "TooManyMatches", "FatalError", "OutOfMemory",
    "FixpointTimeout", "StackOverflow", "TimeoutDuringInterfile",
    "OutOfMemoryDuringInterfile", "MissingPlugin", "IncompatibleRule",
))))


def _caminho_diagnostico(value, origem: Path) -> str | None:
    # Accept only existing files inside the snapshot. No URLs, outside paths or controls.
    if not isinstance(value, str) or not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        return None
    try:
        root = origem.resolve()
        path = Path(value)
        path = (path if path.is_absolute() else root / path).resolve(strict=True)
        relative = path.relative_to(root).as_posix()
        if not path.is_file():
            return None
    except (OSError, ValueError, RuntimeError):
        return None
    from .triage import redigir
    # Filenames are untrusted too: mask known credential values even without prefixes.
    for key, secret in sorted(os.environ.items(), key=lambda item: len(item[1]), reverse=True):
        if len(secret) >= 6 and (key.upper().endswith("_PAT") or any(word in key.upper() for word in (
                "TOKEN", "SECRET", "PASSWORD", "API_KEY", "WEBHOOK", "ACCESS_KEY", "CREDENTIAL"))):
            relative = relative.replace(secret, "[REDIGIDO]")
    return redigir(relative, 600)


def _diagnosticos_semgrep(error, origem: Path) -> list[dict]:
    error = error if isinstance(error, dict) else {}
    variant = error.get("type")
    tag = variant[0] if isinstance(variant, list) and variant else variant
    kind = _SEMGREP_ERROR_TYPES.get(tag, "Unspecified") if isinstance(tag, str) else "Unspecified"
    code = error.get("code")
    code = code if type(code) is int and 0 <= code <= 255 else None
    # spans uses file; PartialParsing's payload uses path. Never stringify payloads.
    locations = error.get("spans") if isinstance(error.get("spans"), list) else []
    if kind == "PartialParsing" and isinstance(variant, list) and len(variant) == 2 and isinstance(variant[1], list):
        locations = locations + variant[1]
    diagnostics = []
    for location in locations:
        if not isinstance(location, dict):
            continue
        path = _caminho_diagnostico(location.get("file") or location.get("path"), origem)
        if path is None:
            continue
        start = location.get("start")
        line = start.get("line") if isinstance(start, dict) else None
        line = line if type(line) is int and 0 < line <= 2147483647 else None
        item = {"type": kind, "code": code, "path": path, "line": line}
        if item not in diagnostics:
            diagnostics.append(item)
    # Top-level path has no line; avoid adding a duplicate without a line.
    path = _caminho_diagnostico(error.get("path"), origem)
    if path and not any(item["path"] == path for item in diagnostics):
        diagnostics.append({"type": kind, "code": code, "path": path, "line": None})
    return diagnostics or [{"type": kind, "code": code, "path": None, "line": None}]


def formatar_diagnostico(ferramenta: str, diagnostic: dict) -> str:
    text = f"{ferramenta}: {diagnostic['type']} (código {diagnostic.get('code')})"
    if diagnostic["type"] != "process_exit":
        text += f" · arquivo: {diagnostic.get('path') or 'não informado'}"
        text += f" · linha: {diagnostic.get('line') or 'não informada'}"
    return text


# --------------------------------------------------------------------------- Semgrep

def rodar_semgrep(cfg, origem: Path, saida: Path) -> ResultadoScanner:
    import time

    res = ResultadoScanner("Semgrep", ok=False, caminho_json=saida)
    if not cfg.semgrep_bin:
        res.erros.append("Semgrep indisponível — cobertura parcial")
        return res

    comando = [cfg.semgrep_bin, "scan", str(origem)]
    from .pipeline_security import regras_semgrep
    for c in regras_semgrep(cfg):
        comando += ["--config", c]
    for p in cfg.skip_paths:
        comando += ["--exclude", p]
    comando += [
        "--json", "--output", str(saida),
        "--metrics=off", "--quiet", "--disable-version-check",
        "--timeout", str(cfg.semgrep_timeout),
        "--timeout-threshold", "3",
        "--max-target-bytes", "2000000",
    ]
    if getattr(cfg, "run_pipeline", False):
        comando += ["--disable-nosem", "--no-git-ignore"]
    # O gate decide pelo JSON normalizado; não usa `--error`: faria o Semgrep sair com código != 0 ao achar vulnerabilidade,
    # e um pipeline que chame o Sentinel reprovaria o build. Achado nunca vira falha.

    inicio = time.monotonic()
    try:
        proc = subprocess.run(
            comando, capture_output=True, text=True, env=_ambiente_scanner(cfg, origem),
            timeout=max(600, cfg.semgrep_timeout * 10), check=False,
        )
    except subprocess.TimeoutExpired:
        res.erros.append("Semgrep estourou o tempo limite global")
        return res
    except OSError as exc:
        res.erros.append(f"Semgrep não executou ({type(exc).__name__})")
        return res
    res.segundos = time.monotonic() - inicio
    res.diagnosticos.append({"type": "process_exit", "code": proc.returncode})
    if getattr(cfg, "run_pipeline", False) and proc.returncode != 0:
        res.erros.append("Semgrep terminou com erro técnico (código %s)" % proc.returncode)

    if not saida.exists():
        res.erros.append(f"Semgrep não produziu relatório (código {proc.returncode})")
        return res

    try:
        with open(saida, encoding="utf-8", errors="replace") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        res.erros.append(f"relatório do Semgrep ilegível ({type(exc).__name__})")
        return res

    for err in doc.get("errors") or []:
        diagnostics = _diagnosticos_semgrep(err, origem)
        res.diagnosticos.extend(diagnostics)
        # No free-form message, snippets, rules or variant payloads in published errors.
        res.erros.append(formatar_diagnostico("Semgrep", diagnostics[0]))

    # O Semgrep informa o que abriu em `paths.scanned`. É a diferença entre
    # "olhei 400 arquivos e está limpo" e "não encontrei nada para olhar".
    caminhos = doc.get("paths") or {}
    if isinstance(caminhos, dict):
        varridos = caminhos.get("scanned")
        if isinstance(varridos, list):
            res.arquivos_varridos = len(varridos)
        ignorados = caminhos.get("skipped")
        if isinstance(ignorados, list):
            res.arquivos_ignorados = len(ignorados)

    res.documento, res.ok = doc, True
    return res


def recortar_semgrep(doc: dict, arquivos: set[str], raiz: Path) -> tuple[dict, int]:
    novo = copy.deepcopy(doc)
    mantidos = []
    for r in doc.get("results") or []:
        if _normalizar(_relativo(r.get("path", ""), raiz)) in arquivos:
            mantidos.append(r)
    removidos = len(doc.get("results") or []) - len(mantidos)
    novo["results"] = mantidos
    return novo, removidos


# ---------------------------------------------------------------------------- Bearer

BUCKETS = ("critical", "high", "medium", "low", "warning")


def rodar_bearer(cfg, origem: Path, saida: Path) -> ResultadoScanner:
    import time

    res = ResultadoScanner("Bearer", ok=False, caminho_json=saida)
    if not cfg.bearer_bin:
        res.erros.append("Bearer indisponível — cobertura parcial")
        return res

    globs = ",".join(f"{p}/**" for p in cfg.skip_paths if p)
    comando = [
        cfg.bearer_bin, "scan", str(origem),
        "--format", "json", "--output", str(saida),
        # O padrão do Bearer é SÓ `sast`. Sem `secrets`, credencial hardcoded não é
        # detectada — foi medido: uma chave AWS em código passava invisível.
        "--scanner", cfg.bearer_scanners,
        # O scanner sai 0 por achados; o gate aplica o bloqueio após as notificações.
        "--exit-code", "0",
        "--quiet", "--disable-version-check",
    ]
    if getattr(cfg, "run_pipeline", False):
        from .pipeline_security import ASSETS
        comando += ["--report", "security", "--config-file", str(ASSETS / "bearer.yml"),
                    "--ignore-file", str(ASSETS / "bearer.ignore"), "--skip-git-ignore", "--skip-test=false"]
    if globs:
        comando += ["--skip-path", globs]

    inicio = time.monotonic()
    try:
        proc = subprocess.run(comando, capture_output=True, text=True, env=_ambiente_scanner(cfg, origem), timeout=1800, check=False)
    except subprocess.TimeoutExpired:
        res.erros.append("Bearer estourou o tempo limite global")
        return res
    except OSError as exc:
        res.erros.append(f"Bearer não executou: {exc}")
        return res
    res.segundos = time.monotonic() - inicio
    res.diagnosticos.append({"type": "process_exit", "code": proc.returncode})
    if getattr(cfg, "run_pipeline", False) and proc.returncode != 0:
        res.erros.append("Bearer terminou com erro técnico (código %s)" % proc.returncode)

    if not saida.exists():
        cauda = (proc.stderr or proc.stdout or "").strip()[-300:]
        res.erros.append(f"Bearer não produziu relatório (código {proc.returncode}): {cauda}")
        return res

    try:
        with open(saida, encoding="utf-8", errors="replace") as fh:
            conteudo = fh.read().strip()
        if not conteudo and getattr(cfg, "run_pipeline", False):
            res.erros.append("relatório vazio: não comprova análise concluída")
            return res
        doc = json.loads(conteudo) if conteudo else {}
    except (OSError, json.JSONDecodeError) as exc:
        res.erros.append(f"relatório do Bearer ilegível: {exc}")
        return res

    res.documento, res.ok = (doc if isinstance(doc, dict) else {}), True
    return res


# ----------------------------------------------------------------------------- Trivy

def rodar_trivy(cfg, origem: Path, saida: Path) -> ResultadoScanner:
    """`trivy fs` sobre a árvore: dependências vulneráveis, IaC e segredos.

    Cobre o que Semgrep e Bearer não veem:
      * `vuln`     CVE em dependência declarada (lockfile, go.mod, package-lock, pom…)
      * `misconfig` Dockerfile, Kubernetes, Terraform, CloudFormation, Helm
      * `secret`   credencial hardcoded (segunda opinião sobre o gitleaks do Bearer)

    Usamos `fs` e não `image` de propósito: do repositório temos o Dockerfile, não a
    imagem construída. Varrer a imagem exigiria buildar — fora do mandato somente-leitura
    e inviável sem daemon de container. O `misconfig` já avalia o Dockerfile em si.
    """
    import time

    res = ResultadoScanner("Trivy", ok=False, caminho_json=saida)
    if not cfg.trivy_bin:
        res.erros.append("Trivy indisponível — cobertura parcial (sem CVE de dependência nem IaC)")
        return res

    comando = [
        cfg.trivy_bin, "fs", str(origem),
        "--format", "json", "--output", str(saida),
        "--scanners", cfg.trivy_scanners,
        "--timeout", f"{cfg.trivy_timeout}s",
        # Sem isto, uma falha ao atualizar a base de CVE derruba a varredura inteira.
        "--skip-db-update" if os.environ.get("TRIVY_SKIP_DB_UPDATE") and not getattr(cfg, "run_pipeline", False) else "--quiet",
        # Achado nunca pode virar falha de processo.
        "--exit-code", "0",
    ]
    for p in cfg.skip_paths:
        if p.strip():
            comando += ["--skip-dirs", p.strip()]
    if getattr(cfg, "run_pipeline", False):
        from .pipeline_security import ASSETS
        comando += ["--config", str(ASSETS / "trivy.yml"),
                    "--ignorefile", str(ASSETS / "empty.ignore"), "--secret-config", ""]
    if cfg.trivy_ignore_unfixed:
        comando.append("--ignore-unfixed")

    inicio = time.monotonic()
    try:
        proc = subprocess.run(
            comando, capture_output=True, text=True, env=_ambiente_scanner(cfg, origem),
            timeout=cfg.trivy_timeout + 300, check=False,
        )
    except subprocess.TimeoutExpired:
        res.erros.append("Trivy estourou o tempo limite global")
        return res
    except OSError as exc:
        res.erros.append(f"Trivy não executou: {exc}")
        return res
    res.segundos = time.monotonic() - inicio
    res.diagnosticos.append({"type": "process_exit", "code": proc.returncode})
    if getattr(cfg, "run_pipeline", False) and proc.returncode != 0:
        res.erros.append("Trivy terminou com erro técnico (código %s)" % proc.returncode)

    if not saida.exists():
        cauda = (proc.stderr or proc.stdout or "").strip()[-300:]
        dica = ""
        if "DB" in cauda or "db" in cauda:
            dica = " (falha ao baixar a base de vulnerabilidades — precisa de rede na 1ª execução)"
        res.erros.append(f"Trivy não produziu relatório (código {proc.returncode}){dica}: {cauda}")
        return res

    try:
        with open(saida, encoding="utf-8", errors="replace") as fh:
            conteudo = fh.read().strip()
        if not conteudo and getattr(cfg, "run_pipeline", False):
            res.erros.append("relatório vazio: não comprova análise concluída")
            return res
        doc = json.loads(conteudo) if conteudo else {}
    except (OSError, json.JSONDecodeError) as exc:
        res.erros.append(f"relatório do Trivy ilegível: {exc}")
        return res

    if not isinstance(doc, dict):
        res.erros.append("relatório do Trivy com estrutura inesperada")
        return res

    res.arquivos_varridos = len(doc.get("Results") or [])
    res.documento, res.ok = doc, True
    return res


def recortar_trivy(doc: dict, arquivos: set[str], raiz: Path) -> tuple[dict, int]:
    """Mantém só os Results cujo Target é um arquivo tocado pelo push.

    O Target do Trivy já vem relativo à raiz varrida, então não há prefixo a remover —
    mas normalizamos mesmo assim porque lockfile às vezes vem com caminho absoluto.
    """
    novo = copy.deepcopy(doc)
    mantidos = []
    removidos = 0
    for resultado in doc.get("Results") or []:
        alvo = resultado.get("Target") or ""
        # "app/Dockerfile" ou "go.mod (gomod)" — o Trivy anexa o tipo entre parênteses.
        limpo = alvo.split(" (")[0].strip()
        if _normalizar(_relativo(limpo, raiz)) in arquivos or _normalizar(limpo) in arquivos:
            mantidos.append(resultado)
        else:
            removidos += 1
    novo["Results"] = mantidos
    return novo, removidos


def recortar_bearer(doc: dict, arquivos: set[str], raiz: Path) -> tuple[dict, int]:
    novo = copy.deepcopy(doc)
    removidos = 0
    for bucket in BUCKETS:
        itens = doc.get(bucket) or []
        mantidos = []
        for item in itens:
            caminho = item.get("filename") or item.get("full_filename") or ""
            if _normalizar(_relativo(caminho, raiz)) in arquivos:
                mantidos.append(item)
        removidos += len(itens) - len(mantidos)
        if bucket in novo:
            novo[bucket] = mantidos
    return novo, removidos


# ------------------------------------------------------------------------- utilidades

def limpar_trechos(doc: dict, ferramenta: str) -> dict:
    """Remove o trecho de código bruto antes de subir a terceiros.

    O trecho pode conter o valor literal do segredo detectado. Um relatório sobre chave
    vazada que carrega a chave é um segundo vazamento.
    """
    limpo = copy.deepcopy(doc)
    if ferramenta == "Trivy":
        for resultado in limpo.get("Results") or []:
            for s_ in resultado.get("Secrets") or []:
                for chave in ("Match", "Code"):
                    if chave in s_:
                        s_[chave] = "[trecho removido pelo SAST Sentinel]"
        return limpo
    if ferramenta == "Semgrep":
        for r in limpo.get("results") or []:
            extra = r.get("extra") or {}
            if "lines" in extra:
                extra["lines"] = "[trecho removido pelo SAST Sentinel]"
    else:
        for bucket in BUCKETS:
            for item in limpo.get(bucket) or []:
                for chave in ("code_extract", "snippet"):
                    if chave in item:
                        item[chave] = "[trecho removido pelo SAST Sentinel]"
    return limpo


def gravar(doc: dict, destino: Path) -> Path:
    destino.parent.mkdir(parents=True, exist_ok=True)
    with open(destino, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False)
    return destino


def conjunto_de_arquivos(caminhos: list[str]) -> set[str]:
    return {_normalizar(c) for c in caminhos if c}


def inventariar_arvore(raiz: Path, pular: list[str], teto: int = 50_000) -> tuple[int, dict[str, int]]:
    """Conta os arquivos do código baixado e as extensões mais comuns.

    Serve para distinguir "repositório limpo" de "não havia o que analisar" — árvore
    vazia, repositório só com documentação, ou linguagem que as regras não cobrem. Sem
    essa contagem, os três casos produzem o mesmo "0 achados".
    """
    pular_set = {p.strip("/") for p in pular if p.strip()}
    total = 0
    extensoes: dict[str, int] = {}
    for caminho in raiz.rglob("*"):
        if total >= teto:
            break
        if not caminho.is_file():
            continue
        if any(parte in pular_set for parte in caminho.parts):
            continue
        total += 1
        ext = caminho.suffix.lower() or "(sem extensão)"
        extensoes[ext] = extensoes.get(ext, 0) + 1
    principais = dict(sorted(extensoes.items(), key=lambda kv: -kv[1])[:8])
    return total, principais
