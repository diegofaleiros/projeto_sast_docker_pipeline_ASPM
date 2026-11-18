"""Planilha de conformidade — saída local, complementar ao ASPM.

O ASPM é o sistema de registro. A planilha existe para o que ele não resolve bem:
levar o resultado de uma janela de auditoria para quem não tem acesso ao ASPM, e
provar cobertura — o que NÃO foi analisado e por quê.

Abas: Resumo · Todos os achados · Severos · Pushes · Autores · Cobertura.

"Todos os achados" lista TODAS as severidades — crítica, alta, média, baixa e
informativa. O corte em crítica/alta existe só para decidir o que vira alerta no Slack;
ele nunca decide o que entra no relatório nem o que vai para o ASPM.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path

from .triage import EM_PT, ORDEM
from .xlsx import (
    S_CRITICAL, S_DEFAULT, S_HIGH, S_MONO, S_MUTED, S_OK, S_WRAP,
    Sheet, hyperlink, write_xlsx,
)

COLUNAS = [
    ("#", 5), ("Data do push", 19), ("Projeto", 32), ("Branch", 20), ("Commit", 12),
    ("Autor", 20), ("Nome", 22), ("Origem da autoria", 16), ("Ferramenta", 11), ("Severidade", 12),
    ("Elevada por", 28), ("Arquivo", 38), ("Linha", 7),
    ("Regra", 42), ("Título", 42), ("CWE", 22), ("OWASP", 20), ("Categoria (PII)", 18),
    ("Descrição", 58), ("Trecho (redigido)", 40), ("Documentação", 15), ("Commit (link)", 14),
    ("No ASPM", 15), ("Injeção suspeita", 10), ("Impressão", 24),
    ("Status conformidade", 20), ("Responsável", 18), ("Prazo", 12), ("Observações", 32),
]


def _defuse(valor):
    """Mesmo antídoto do xlsx: `=`, `+`, `@`, `-` iniciais viram texto no CSV."""
    if valor is None or (isinstance(valor, (int, float)) and not isinstance(valor, bool)):
        return valor
    s = str(valor)
    if not s:
        return s
    if s[0] in ("=", "+", "@", "\t", "\r"):
        return "'" + s
    if s[0] == "-":
        try:
            float(s)
        except ValueError:
            return "'" + s
    return s


def _contagem(achados: list) -> dict[str, int]:
    c = {k: 0 for k in ORDEM}
    for a in achados:
        c[a.severidade] = c.get(a.severidade, 0) + 1
    return c


def _estilo(sev: str) -> int:
    return {"CRITICAL": S_CRITICAL, "HIGH": S_HIGH}.get(sev, S_DEFAULT)


def _linhas(resultados: list) -> list[tuple]:
    saida = []
    for r in resultados:
        p = r.push
        aspm = " · ".join(e.url for e in r.envios_aspm if e.ok and e.url)
        for a in r.achados:
            saida.append((p, a, aspm))
    saida.sort(key=lambda t: (ORDEM.get(t[1].severidade, 9), t[0].projeto_caminho, t[1].arquivo, t[1].linha))
    return saida


def gerar(resultados: list, contexto: dict, destino_dir: Path) -> dict:
    destino_dir.mkdir(parents=True, exist_ok=True)
    carimbo = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    xlsx_path = destino_dir / f"sast_conformidade_{carimbo}.xlsx"
    csv_path = destino_dir / f"sast_conformidade_{carimbo}.csv"

    linhas = _linhas(resultados)
    severos = [t for t in linhas if t[1].alertavel]

    abas = [
        _aba_resumo(resultados, linhas, severos, contexto),
        _aba_achados(linhas, "Todos os achados"),
        _aba_achados(severos, "Severos (Slack)"),
        _aba_pushes(resultados),
        _aba_autores(resultados),
        _aba_cobertura(resultados, contexto),
    ]
    write_xlsx(str(xlsx_path), abas)
    # O CSV é o export legível por máquina: leva todas as severidades, não só as severas.
    _csv(csv_path, linhas)
    return {"xlsx": str(xlsx_path), "csv": str(csv_path),
            "achados_total": len(linhas), "achados_severos": len(severos)}


def _aba_achados(linhas: list[tuple], titulo: str) -> Sheet:
    sh = Sheet(titulo, [c[0] for c in COLUNAS], [c[1] for c in COLUNAS])
    for i, (p, a, aspm) in enumerate(linhas, 1):
        sh.add_row(
            [
                i, p.criado_em[:19].replace("T", " "), p.projeto_caminho, p.branch, p.commit_curto,
                p.autor_username, p.autor_nome,
                "push" if p.origem == "evento-de-push" else "histórico git",
                a.ferramenta, a.severidade_pt, a.elevada_por,
                a.arquivo, a.linha or "", a.regra, a.titulo,
                ", ".join(a.cwe), ", ".join(a.owasp), ", ".join(a.categorias),
                a.descricao, a.trecho,
                hyperlink(a.referencia, "regra") if a.referencia else "",
                hyperlink(p.commit_url, p.commit_curto) if p.commit_url else "",
                hyperlink(aspm.split(" · ")[0], "abrir") if aspm else "",
                "SIM" if a.injecao_suspeita else "", a.impressao,
                "", "", "", "",
            ],
            style=[
                S_DEFAULT, S_DEFAULT, S_DEFAULT, S_DEFAULT, S_MONO,
                S_DEFAULT, S_DEFAULT, S_DEFAULT, S_DEFAULT, _estilo(a.severidade), S_WRAP,
                S_MONO, S_DEFAULT, S_WRAP, S_WRAP,
                S_WRAP, S_WRAP, S_WRAP, S_WRAP, S_MONO,
                S_DEFAULT, S_DEFAULT, S_DEFAULT, S_DEFAULT, S_MONO,
                S_DEFAULT, S_DEFAULT, S_DEFAULT, S_WRAP,
            ],
        )
    if not linhas:
        sh.add_row(["—", "nenhum achado nesta categoria"], style=S_MUTED)
    return sh


def _aba_pushes(resultados: list) -> Sheet:
    cols = [("#", 5), ("Data", 19), ("Projeto", 32), ("Branch", 20), ("Commit", 12),
            ("Autor", 20), ("Origem", 14), ("Commits", 8), ("Arquivos alterados", 10),
            ("Semgrep", 9), ("Bearer", 9), ("Trivy", 9),
            ("Arquivos no commit", 11), ("Varridos", 9),
            ("CRÍTICAS", 9), ("ALTAS", 8), ("MÉDIAS", 8), ("BAIXAS", 8), ("INFO", 7),
            ("TOTAL", 8),
            ("Cobertura", 11), ("ASPM", 12), ("Slack", 10), ("Erros", 46)]
    sh = Sheet("Pushes", [c[0] for c in cols], [c[1] for c in cols])
    for i, r in enumerate(resultados, 1):
        p = r.push
        c = _contagem(r.achados)
        crit, alta = c["CRITICAL"], c["HIGH"]
        aspm_ok = sum(1 for e in r.envios_aspm if e.ok)
        sh.add_row(
            [i, p.criado_em[:19].replace("T", " "), p.projeto_caminho, p.branch, p.commit_curto,
             p.autor_username, "push" if p.origem == "evento-de-push" else "histórico git",
             p.qtd_commits or "", len(p.arquivos_alterados) or ("n/d" if p.diff_indisponivel else 0),
             sum(1 for a in r.achados if a.ferramenta == "Semgrep"),
             sum(1 for a in r.achados if a.ferramenta == "Bearer"),
             sum(1 for a in r.achados if a.ferramenta == "Trivy"),
             getattr(r, "arquivos_no_commit", 0),
             getattr(r, "arquivos_varridos", -1) if getattr(r, "arquivos_varridos", -1) >= 0 else "?",
             crit, alta, c["MEDIUM"], c["LOW"], c["INFO"], len(r.achados),
             "PARCIAL" if r.erros else "OK",
             f"{aspm_ok}/{len(r.envios_aspm)}" if r.envios_aspm else "—",
             r.slack, "; ".join(r.erros)],
            style=[S_DEFAULT, S_DEFAULT, S_DEFAULT, S_DEFAULT, S_MONO,
                   S_DEFAULT, S_DEFAULT, S_DEFAULT, S_DEFAULT,
                   S_DEFAULT, S_DEFAULT, S_DEFAULT, S_DEFAULT, S_DEFAULT,
                   S_CRITICAL if crit else S_DEFAULT, S_HIGH if alta else S_DEFAULT,
                   S_DEFAULT, S_DEFAULT, S_DEFAULT, S_DEFAULT,
                   S_HIGH if r.erros else S_OK, S_DEFAULT, S_DEFAULT, S_WRAP],
        )
    if not resultados:
        sh.add_row(["—", "nenhum push analisado nesta janela"], style=S_MUTED)
    return sh


def _aba_autores(resultados: list) -> Sheet:
    agg: dict[str, dict] = {}
    for r in resultados:
        p = r.push
        e = agg.setdefault(p.autor_username, {"nome": p.autor_nome, "pushes": 0, "proj": set(), "c": 0, "h": 0})
        e["pushes"] += 1
        e["proj"].add(p.projeto_caminho)
        for a in r.achados:
            if a.severidade == "CRITICAL":
                e["c"] += 1
            elif a.severidade == "HIGH":
                e["h"] += 1

    cols = [("Autor", 22), ("Nome", 26), ("Commits/pushes", 12), ("Projetos", 9),
            ("CRÍTICAS", 10), ("ALTAS", 9), ("Severas por push", 14)]
    sh = Sheet("Autores", [c[0] for c in cols], [c[1] for c in cols])
    for user, e in sorted(agg.items(), key=lambda kv: (-(kv[1]["c"] + kv[1]["h"]), kv[0])):
        total = e["c"] + e["h"]
        sh.add_row([user, e["nome"], e["pushes"], len(e["proj"]), e["c"], e["h"],
                    round(total / e["pushes"], 2) if e["pushes"] else ""],
                   style=[S_DEFAULT, S_DEFAULT, S_DEFAULT, S_DEFAULT,
                          S_CRITICAL if e["c"] else S_DEFAULT, S_HIGH if e["h"] else S_DEFAULT, S_DEFAULT])
    if not agg:
        sh.add_row(["—", "nenhum autor com push na janela"], style=S_MUTED)
    return sh


def _aba_cobertura(resultados: list, contexto: dict) -> Sheet:
    cols = [("Tipo", 26), ("Alvo", 44), ("Detalhe", 88)]
    sh = Sheet("Cobertura", [c[0] for c in cols], [c[1] for c in cols])
    n = 0
    for item in contexto.get("projetos_ignorados", []):
        sh.add_row(["Projeto ignorado", item.get("projeto", ""), item.get("motivo", "")], style=S_WRAP)
        n += 1
    for item in contexto.get("pushes_ignorados", []):
        sh.add_row(["Push sem código", item.get("alvo", ""), item.get("motivo", "")], style=S_WRAP)
        n += 1
    for r in resultados:
        p = r.push
        alvo = f"{p.projeto_caminho} · {p.commit_curto}"
        for e in r.erros:
            sh.add_row(["Cobertura parcial", alvo, e], style=S_WRAP)
            n += 1
        if p.diff_indisponivel:
            sh.add_row(["Diff indisponível", alvo, p.diff_indisponivel], style=S_WRAP)
            n += 1
        for envio in r.envios_aspm:
            if not envio.ok:
                sh.add_row(["Falha no ASPM", f"{alvo} · {envio.ferramenta}", envio.mensagem], style=S_WRAP)
                n += 1
        if r.slack.startswith("falhou"):
            sh.add_row(["Falha no Slack", alvo, r.slack], style=S_WRAP)
            n += 1
        if any(a.injecao_suspeita for a in r.achados):
            sh.add_row(["Injeção de prompt suspeita", alvo,
                        "texto tentando se dirigir ao agente; tratado como dado inerte"], style=S_WRAP)
            n += 1
    if contexto.get("teto_atingido"):
        sh.add_row(["Teto atingido", "MAX_PUSHES", contexto["teto_atingido"]], style=S_WRAP)
        n += 1
    if not n:
        sh.add_row(["—", "", "Nenhuma lacuna de cobertura registrada nesta execução."], style=S_MUTED)
    return sh


def _aba_resumo(resultados: list, linhas: list, severos: list, contexto: dict) -> Sheet:
    sh = Sheet("Resumo", headers=None, widths=[40, 34, 20, 14, 14], freeze_header=False, autofilter=False)
    sh.add_banner("Relatório de conformidade — SAST Security Sentinel")
    sh.add_row([])
    for k, v in [
        ("Gerado em (UTC)", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")),
        ("Instância GitLab", contexto.get("gitlab", "—")),
        ("ASPM", contexto.get("aspm", "—")),
        ("Janela", f"de {contexto.get('desde', '—')} até {contexto.get('ate', 'agora')}"),
        ("Primeira execução", "sim" if contexto.get("primeira_execucao") else "não"),
        ("Escopo da varredura", contexto.get("escopo", "—")),
        ("Chamadas à API do GitLab", contexto.get("chamadas_api", "—")),
        ("Modo", "DRY-RUN (nada enviado)" if contexto.get("dry_run") else "produção"),
    ]:
        sh.add_row([k, v], style=[S_MUTED, S_DEFAULT])

    todos_achados = [a for _, a, _ in linhas]
    c = _contagem(todos_achados)
    crit, alta = c["CRITICAL"], c["HIGH"]
    sh.add_row([])
    sh.add_row(["COBERTURA", "", "", "", ""], style=S_MUTED)
    for k, v in [
        ("Projetos considerados", contexto.get("projetos_considerados", "—")),
        ("Projetos ignorados", len(contexto.get("projetos_ignorados", []))),
        ("Pushes encontrados", contexto.get("pushes_encontrados", "—")),
        ("Pushes já auditados antes", contexto.get("pushes_ja_auditados", "—")),
        ("Pushes sem código", len(contexto.get("pushes_ignorados", []))),
        ("Pushes analisados", len(resultados)),
        ("  … com cobertura total", sum(1 for r in resultados if not r.erros)),
        ("  … com cobertura parcial", sum(1 for r in resultados if r.erros)),
        ("Autores distintos", len({r.push.autor_username for r in resultados})),
    ]:
        sh.add_row([k, v], style=[S_MUTED, S_DEFAULT])

    sh.add_row([])
    sh.add_row(["ACHADOS — TODAS AS SEVERIDADES", "", "", "", ""], style=S_MUTED)
    sh.add_row(["CRÍTICA", crit], style=[S_CRITICAL, S_DEFAULT])
    sh.add_row(["ALTA", alta], style=[S_HIGH, S_DEFAULT])
    sh.add_row(["MÉDIA", c["MEDIUM"]], style=[S_MUTED, S_DEFAULT])
    sh.add_row(["BAIXA", c["LOW"]], style=[S_MUTED, S_DEFAULT])
    sh.add_row(["INFORMATIVA", c["INFO"]], style=[S_MUTED, S_DEFAULT])
    if c.get("UNKNOWN"):
        sh.add_row(["INDEFINIDA", c["UNKNOWN"]], style=[S_MUTED, S_DEFAULT])
    sh.add_row(["TOTAL", len(linhas)], style=[S_MUTED, S_DEFAULT])
    por_ferramenta: dict[str, int] = {}
    for a in todos_achados:
        por_ferramenta[a.ferramenta] = por_ferramenta.get(a.ferramenta, 0) + 1
    if por_ferramenta:
        sh.add_row([])
        sh.add_row(["Por ferramenta", "Achados"], style=S_MUTED)
        for nome, qtd in sorted(por_ferramenta.items()):
            sh.add_row([nome, qtd])
    sh.add_row(["  destes, alertados no Slack", len(severos)], style=[S_MUTED, S_DEFAULT])
    sh.add_row([])
    sh.add_row(["COBERTURA DE CÓDIGO", "", "", "", ""], style=S_MUTED)
    sh.add_row(["Arquivos nos commits analisados",
                sum(getattr(r, "arquivos_no_commit", 0) for r in resultados)],
               style=[S_MUTED, S_DEFAULT])
    sh.add_row(["Arquivos varridos pelo Semgrep",
                sum(getattr(r, "arquivos_varridos", 0) for r in resultados
                    if getattr(r, "arquivos_varridos", -1) > 0)],
               style=[S_MUTED, S_DEFAULT])

    por_proj: dict[str, list[int]] = {}
    for p, a, _ in severos:
        e = por_proj.setdefault(p.projeto_caminho, [0, 0])
        e[0 if a.severidade == "CRITICAL" else 1] += 1
    if por_proj:
        sh.add_row([])
        sh.add_row(["Projeto", "CRÍTICAS", "ALTAS"], style=S_MUTED)
        for nome, (c, h) in sorted(por_proj.items(), key=lambda kv: (-kv[1][0], -kv[1][1], kv[0]))[:40]:
            sh.add_row([nome, c, h])

    sh.add_row([])
    sh.add_row(["Nota", "A aba 'Todos os achados' lista TODAS as severidades. O corte em "
                        "crítica/alta vale só para o alerta do Slack — o ASPM e esta "
                        "planilha recebem tudo. Cobertura parcial significa que uma ferramenta "
                        "falhou naquele push: consulte a aba Cobertura antes de declarar um "
                        "projeto conforme."],
               style=[S_MUTED, S_WRAP])
    return sh


def _csv(caminho: Path, severos: list[tuple]) -> None:
    with open(caminho, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow([c[0] for c in COLUNAS])
        for i, (p, a, aspm) in enumerate(severos, 1):
            w.writerow([_defuse(v) for v in [
                i, p.criado_em[:19].replace("T", " "), p.projeto_caminho, p.branch, p.commit_curto,
                p.autor_username, p.autor_nome,
                "push" if p.origem == "evento-de-push" else "historico git",
                a.ferramenta, EM_PT.get(a.severidade, a.severidade),
                a.elevada_por, a.arquivo, a.linha or "", a.regra, a.titulo,
                ", ".join(a.cwe), ", ".join(a.owasp), ", ".join(a.categorias),
                a.descricao, a.trecho, a.referencia, p.commit_url, aspm,
                "SIM" if a.injecao_suspeita else "", a.impressao, "", "", "", "",
            ]])
