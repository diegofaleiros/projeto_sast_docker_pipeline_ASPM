"""Normalização, mapa de severidade e redação de segredos.

Consome os JSON brutos do Semgrep e do Bearer e devolve uma lista única de achados.
Serve ao Slack e à planilha; o ASPM recebe os relatórios brutos, porque os
parsers dele já entendem cada formato nativamente.

Tudo que vem do repositório — descrição de regra, trecho de código, mensagem de commit —
é DADO, nunca instrução. Texto que tente se dirigir ao agente é sinalizado e o achado
correspondente é preservado com a severidade intacta.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

ALERTAVEIS = ("CRITICAL", "HIGH")
ORDEM = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
EM_PT = {
    "CRITICAL": "CRÍTICA", "HIGH": "ALTA", "MEDIUM": "MÉDIA",
    "LOW": "BAIXA", "INFO": "INFORMATIVA", "UNKNOWN": "INDEFINIDA",
}

# Semgrep clássico usa ERROR/WARNING/INFO; regras novas trazem CRITICAL/HIGH em metadata.
SEV_SEMGREP = {
    "CRITICAL": "CRITICAL", "ERROR": "HIGH", "HIGH": "HIGH",
    "WARNING": "MEDIUM", "MEDIUM": "MEDIUM", "INFO": "LOW", "LOW": "LOW",
    "INVENTORY": "INFO", "EXPERIMENT": "INFO",
}
BUCKETS_BEARER = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
    "low": "LOW", "warning": "INFO",
}

PADROES_SEGREDO: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"https://hooks\.slack\.com/services/[^\s\"\'<>]+"), "[SLACK_WEBHOOK_REDIGIDO]"),
    (re.compile(r"-----BEGIN[^-\n]{0,40}PRIVATE KEY-----[\s\S]*?(-----END[^-\n]{0,40}PRIVATE KEY-----)?"),
     "[CHAVE_PRIVADA_REDIGIDA]"),
    (re.compile(r"\baspm_pat_[A-Za-z0-9_\-]+"), "[ASPM_PAT_REDIGIDO]"),
    (re.compile(r"\bglpat-[A-Za-z0-9_\-]{16,}"), "[GITLAB_PAT_REDIGIDO]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}"), "[GITHUB_TOKEN_REDIGIDO]"),
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}"), "[SLACK_TOKEN_REDIGIDO]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[AWS_ACCESS_KEY_REDIGIDA]"),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}"), "[API_KEY_REDIGIDA]"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"), "[JWT_REDIGIDO]"),
    (re.compile(r"https?://[^/\s:@]{1,64}:[^/\s@]{1,64}@"), "[URL_COM_CREDENCIAL_REDIGIDA]@"),
    # O lookahead evita redigir de novo um marcador já inserido por outra regra.
    (re.compile(r"(?i)\b([a-z0-9_-]*(?:pass(?:word)?|senha|secret|token|api[_-]?key|authorization|pat|private[_-]?key)[a-z0-9_-]*)\b"
                r"\s*[:=]\s*[\"']?(?!\[[A-Z_]*REDIGID)[^\s\"',;)}\]]{6,}"), r"\1=[REDIGIDO]"),
]

PARECE_SEGREDO = re.compile(r"(?i)secret|credential|password|token|api[_-]?key|hardcoded|private[_-]?key|gitleaks")

INJECAO = re.compile(
    r"(?i)(ignore\s+(all\s+)?previous|ignore\s+as\s+instru|desconsidere\s+as\s+instru|"
    r"disregard\s+(all\s+)?prior|system\s*prompt|you\s+are\s+now|a\s+partir\s+de\s+agora\s+voc|"
    r"n(ã|a)o\s+alerte|do\s+not\s+alert|skip\s+the\s+scan|n(ã|a)o\s+execute\s+a\s+varredura|"
    r"</?(system|assistant|user)>|\[\[\s*system\s*\]\])"
)


def redigir(texto: object, limite: int = 400) -> str:
    if texto is None:
        return ""
    s = str(texto)
    for padrao, troca in PADROES_SEGREDO:
        s = padrao.sub(troca, s)
        s = padrao.sub(troca, s)  # segunda passada estabiliza sobreposições
    s = re.sub(r"\s+", " ", s).strip()
    return s[: limite - 1] + "…" if len(s) > limite else s


def marcar_injecao(*textos: object) -> list[str]:
    """Trechos que parecem tentativa de injeção de prompt, com janelas fundidas."""
    achados: dict[str, None] = {}
    for t in textos:
        if not t:
            continue
        s = str(t)
        janelas: list[list[int]] = []
        for m in INJECAO.finditer(s):
            ini, fim = max(0, m.start() - 40), min(len(s), m.end() + 40)
            if janelas and ini <= janelas[-1][1]:
                janelas[-1][1] = max(janelas[-1][1], fim)
            else:
                janelas.append([ini, fim])
        for ini, fim in janelas:
            achados.setdefault(redigir(s[ini:fim], 240), None)
    return list(achados)


def _impressao(*partes: object) -> str:
    return hashlib.sha256("|".join("" if p is None else str(p) for p in partes).encode()).hexdigest()[:24]


def _inteiro(v: object) -> int:
    try:
        return int(v)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _relativo(caminho: object, raiz: Path | None) -> str:
    p = str(caminho or "").replace("\\", "/")
    if raiz:
        marca = str(raiz).replace("\\", "/").rstrip("/") + "/"
        if p.startswith(marca):
            p = p[len(marca):]
    return p.lstrip("./") or "(desconhecido)"


@dataclass
class Achado:
    ferramenta: str
    severidade: str
    severidade_declarada: str
    elevada_por: str
    regra: str
    titulo: str
    descricao: str
    arquivo: str
    linha: int
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    categorias: list[str] = field(default_factory=list)
    referencia: str = ""
    trecho: str = ""
    impressao: str = ""
    injecao_suspeita: bool = False

    @property
    def alertavel(self) -> bool:
        return self.severidade in ALERTAVEIS

    @property
    def local(self) -> str:
        return f"{self.arquivo}:{self.linha}" if self.linha else self.arquivo

    @property
    def severidade_pt(self) -> str:
        return EM_PT.get(self.severidade, self.severidade)


def normalizar_semgrep(doc: dict | None, raiz: Path | None, escalar: bool) -> list[Achado]:
    if not isinstance(doc, dict):
        return []
    saida: list[Achado] = []
    for r in doc.get("results") or []:
        if not isinstance(r, dict):
            continue
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}

        declarada = str(meta.get("severity") or extra.get("severity") or "").upper()
        sev = SEV_SEMGREP.get(declarada, "UNKNOWN")
        impacto = str(meta.get("impact") or "").upper()
        confianca = str(meta.get("confidence") or "").upper()
        validacao = str(extra.get("validation_state") or "").upper()

        elevada = ""
        if sev == "HIGH" and impacto == "HIGH" and confianca == "HIGH":
            sev, elevada = "CRITICAL", "impacto=ALTO e confiança=ALTA"
        elif validacao == "CONFIRMED_VALID":
            sev, elevada = "CRITICAL", "segredo validado como ATIVO pelo Semgrep"
        elif escalar and sev == "MEDIUM" and impacto == "HIGH" and confianca in ("HIGH", "MEDIUM"):
            # O Semgrep marca como WARNING várias regras de impacto alto — SQL injection
            # por cursor, vazamento de credencial em log. Sem esta escalada, o corte
            # estrito em CRÍTICA/ALTA as descartaria em silêncio.
            sev, elevada = "HIGH", f"WARNING com impacto=ALTO e confiança={confianca}"

        regra = str(r.get("check_id") or "regra-desconhecida")
        arquivo = _relativo(r.get("path"), raiz)
        linha = _inteiro((r.get("start") or {}).get("line"))
        cwe = meta.get("cwe") or []
        cwe = [cwe] if isinstance(cwe, str) else [str(c) for c in cwe]
        owasp = meta.get("owasp") or []
        owasp = [owasp] if isinstance(owasp, str) else [str(o) for o in owasp]
        refs = meta.get("references") or []

        e_segredo = bool(PARECE_SEGREDO.search(regra)) or "798" in " ".join(cwe) or bool(validacao)
        descricao = redigir(extra.get("message") or "", 400)
        trecho = "" if e_segredo else redigir(extra.get("lines"), 240)

        saida.append(
            Achado(
                ferramenta="Semgrep",
                severidade=sev,
                severidade_declarada=declarada or "(ausente)",
                elevada_por=elevada,
                regra=regra,
                titulo=redigir(regra.split(".")[-1].replace("-", " ").replace("_", " ") or regra, 120),
                descricao=descricao,
                arquivo=arquivo,
                linha=linha,
                cwe=cwe,
                owasp=owasp,
                referencia=str(refs[0]) if isinstance(refs, list) and refs else "",
                trecho=trecho,
                impressao=str(extra.get("fingerprint") or "") or _impressao("semgrep", regra, arquivo, linha),
                injecao_suspeita=bool(marcar_injecao(descricao, trecho)),
            )
        )
    return saida


def normalizar_bearer(doc: dict | None, raiz: Path | None) -> list[Achado]:
    if not isinstance(doc, dict):
        return []
    saida: list[Achado] = []
    for bucket, sev in BUCKETS_BEARER.items():
        for item in doc.get(bucket) or []:
            if not isinstance(item, dict):
                continue
            regra = str(item.get("id") or "regra-desconhecida")
            arquivo = _relativo(item.get("filename") or item.get("full_filename"), raiz)
            linha = _inteiro(item.get("line_number")) or _inteiro((item.get("source") or {}).get("start"))
            cwe = item.get("cwe_ids") or []
            cwe = [cwe] if isinstance(cwe, str) else [str(c) for c in cwe]
            grupos = item.get("category_groups") or []
            grupos = [grupos] if isinstance(grupos, str) else [str(g) for g in grupos]

            e_segredo = bool(PARECE_SEGREDO.search(regra)) or "798" in " ".join(cwe)
            descricao = redigir(item.get("description") or item.get("title") or "", 400)
            trecho = "" if e_segredo else redigir(item.get("code_extract") or item.get("snippet"), 240)

            saida.append(
                Achado(
                    ferramenta="Bearer",
                    severidade=sev,
                    severidade_declarada=bucket.upper(),
                    elevada_por="",
                    regra=regra,
                    titulo=redigir(item.get("title") or regra, 120),
                    descricao=descricao,
                    arquivo=arquivo,
                    linha=linha,
                    cwe=cwe,
                    categorias=grupos,
                    referencia=str(item.get("documentation_url") or ""),
                    trecho=trecho,
                    impressao=str(item.get("fingerprint") or "") or _impressao("bearer", regra, arquivo, linha),
                    injecao_suspeita=bool(marcar_injecao(descricao, trecho)),
                )
            )
    return saida


# O Trivy já usa CRITICAL/HIGH/MEDIUM/LOW, então o mapa é quase identidade.
SEV_TRIVY = {
    "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
    "LOW": "LOW", "UNKNOWN": "INFO", "": "UNKNOWN",
}


def normalizar_trivy(doc: dict | None, raiz: Path | None) -> list[Achado]:
    """Converte o relatório do Trivy nos três tipos que ele produz.

    Cada `Result` traz um `Target` (arquivo ou pacote) e pode conter
    `Vulnerabilities` (CVE em dependência), `Misconfigurations` (Dockerfile, K8s,
    Terraform) e `Secrets`. São naturezas diferentes e viram achados distintos.
    """
    if not isinstance(doc, dict):
        return []
    saida: list[Achado] = []

    for resultado in doc.get("Results") or []:
        if not isinstance(resultado, dict):
            continue
        alvo = str(resultado.get("Target") or "")
        arquivo = _relativo(alvo.split(" (")[0].strip(), raiz)
        classe = str(resultado.get("Class") or "")
        tipo = str(resultado.get("Type") or "")

        # --- CVE em dependência declarada
        for v in resultado.get("Vulnerabilities") or []:
            if not isinstance(v, dict):
                continue
            cve = str(v.get("VulnerabilityID") or "")
            pacote = str(v.get("PkgName") or "")
            instalada = str(v.get("InstalledVersion") or "")
            corrigida = str(v.get("FixedVersion") or "")
            sev = SEV_TRIVY.get(str(v.get("Severity") or "").upper(), "UNKNOWN")
            remediacao = (f" Corrigido em {corrigida}." if corrigida
                          else " Sem versão corrigida publicada.")
            cwe = v.get("CweIDs") or []
            cwe = [cwe] if isinstance(cwe, str) else [str(c) for c in cwe]
            saida.append(
                Achado(
                    ferramenta="Trivy",
                    severidade=sev,
                    severidade_declarada=str(v.get("Severity") or "").upper() or "(ausente)",
                    elevada_por="",
                    regra=cve or "vulnerabilidade-sem-id",
                    titulo=redigir(f"{cve} em {pacote} {instalada}".strip(), 120),
                    descricao=redigir((v.get("Title") or v.get("Description") or "") + remediacao, 400),
                    arquivo=arquivo,
                    linha=0,
                    cwe=cwe,
                    categorias=[c for c in ("dependência", tipo) if c],
                    referencia=str(v.get("PrimaryURL") or ""),
                    impressao=_impressao("trivy-vuln", cve, arquivo, pacote, instalada),
                )
            )

        # --- IaC: Dockerfile, Kubernetes, Terraform, Helm…
        for m in resultado.get("Misconfigurations") or []:
            if not isinstance(m, dict):
                continue
            ident = str(m.get("ID") or m.get("AVDID") or "")
            sev = SEV_TRIVY.get(str(m.get("Severity") or "").upper(), "UNKNOWN")
            linha = _inteiro((m.get("CauseMetadata") or {}).get("StartLine"))
            resolucao = str(m.get("Resolution") or "")
            descricao = str(m.get("Message") or m.get("Description") or "")
            if resolucao:
                descricao += f" Como corrigir: {resolucao}"
            saida.append(
                Achado(
                    ferramenta="Trivy",
                    severidade=sev,
                    severidade_declarada=str(m.get("Severity") or "").upper() or "(ausente)",
                    elevada_por="",
                    regra=ident or "misconfig-sem-id",
                    titulo=redigir(m.get("Title") or ident, 120),
                    descricao=redigir(descricao, 400),
                    arquivo=arquivo,
                    linha=linha,
                    categorias=[c for c in ("infraestrutura como código", tipo) if c],
                    referencia=str(m.get("PrimaryURL") or ""),
                    impressao=_impressao("trivy-misconf", ident, arquivo, linha),
                )
            )

        # --- segredos: nunca carregam o valor encontrado
        for s in resultado.get("Secrets") or []:
            if not isinstance(s, dict):
                continue
            regra = str(s.get("RuleID") or "segredo")
            sev = SEV_TRIVY.get(str(s.get("Severity") or "").upper(), "UNKNOWN")
            saida.append(
                Achado(
                    ferramenta="Trivy",
                    severidade=sev,
                    severidade_declarada=str(s.get("Severity") or "").upper() or "(ausente)",
                    elevada_por="",
                    regra=regra,
                    titulo=redigir(s.get("Title") or regra, 120),
                    descricao=redigir(
                        f"Segredo do tipo {s.get('Category') or 'desconhecido'} detectado. "
                        "O valor não é reproduzido aqui.", 400),
                    arquivo=arquivo,
                    linha=_inteiro(s.get("StartLine")),
                    cwe=["CWE-798"],
                    categorias=["segredo", classe or "secret"],
                    trecho="",  # o Match do Trivy é o próprio segredo: nunca sai daqui
                    impressao=_impressao("trivy-secret", regra, arquivo, s.get("StartLine")),
                )
            )
    return saida


def ordenar(achados: list[Achado]) -> list[Achado]:
    return sorted(achados, key=lambda a: (ORDEM.get(a.severidade, 9), a.ferramenta, a.arquivo, a.linha))


def contar(achados: list[Achado]) -> dict[str, int]:
    contagem = {s: 0 for s in ORDEM}
    for a in achados:
        contagem[a.severidade] = contagem.get(a.severidade, 0) + 1
    return contagem
