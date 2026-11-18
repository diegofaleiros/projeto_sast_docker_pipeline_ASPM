"""Orquestração e interface de linha de comando.

Ciclo de uma execução:
    1. Descobre os projetos (instância inteira, ou a lista de GITLAB_PROJECTS).
    2. Lê os eventos de push de cada projeto desde a última execução.
    3. Para cada push: baixa o código do commit, roda Semgrep e Bearer, recorta os
       relatórios para os arquivos que o push alterou.
    4. Envia os relatórios ao ASPM (reimport, cria contexto sozinho).
    5. Alerta no Slack quando houver achado CRÍTICO ou ALTO.
    6. Só então avança o carimbo da última execução.

O passo 6 vir por último é deliberado: se o processo morrer no meio, a próxima
execução recobre a mesma janela em vez de pular pushes em silêncio.

A auditoria recorrente termina com código 0 — nem quando há 50 achados críticos, nem quando uma
ferramenta falha. Um pipeline que chame o Sentinel não pode quebrar por causa dele.
"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config import Config, ConfigError
from .aspm import ASPMClient, ResultadoEnvio, repo_id, preparar_relatorio
from .gitlab import GitLabClient, GitLabError, Projeto, Push
from .report import gerar as gerar_planilha
from .scanners import (
    conjunto_de_arquivos, gravar, inventariar_arvore, limpar_trechos, recortar_bearer,
    recortar_semgrep, recortar_trivy, rodar_bearer, rodar_semgrep, rodar_trivy,
)
from .slack import enviar as enviar_slack
from .slack import montar_payload
from .state import State, agora, de_iso, para_iso
from .storage import backend_de
from .triage import (
    EM_PT, Achado, contar, normalizar_bearer, normalizar_semgrep, normalizar_trivy, ordenar,
)

log = logging.getLogger("sentinel")


def ResultadoScannerVazio(nome: str):
    """Placeholder para scanner desligado por configuração: não é falha, é escolha."""
    from .scanners import ResultadoScanner

    return ResultadoScanner(nome, ok=False, erros=[f"{nome} desligado por configuração"])


@dataclass
class ResultadoPush:
    push: Push
    achados: list[Achado] = field(default_factory=list)
    envios_aspm: list[ResultadoEnvio] = field(default_factory=list)
    slack: str = "—"
    erros: list[str] = field(default_factory=list)
    recortados: int = 0
    envios_simulados: list[str] = field(default_factory=list)
    arquivos_no_commit: int = 0
    arquivos_varridos: int = -1
    extensoes: dict = field(default_factory=dict)
    fechamento_suprimido: str = ""

    def por_severidade(self) -> dict[str, int]:
        return contar(self.achados)


# --------------------------------------------------------------------------- descoberta

def descobrir_projetos(
    gl: GitLabClient, cfg: Config, desde: datetime | None, ignorados: list[dict], contexto: dict
) -> list[Projeto]:
    if cfg.gitlab_projects:
        projetos = []
        for ident in cfg.gitlab_projects:
            try:
                projetos.append(gl.projeto(ident))
            except GitLabError as exc:
                ignorados.append({"projeto": ident, "motivo": str(exc)})
        return projetos

    # `last_activity_after` é uma otimização: projeto sem atividade na janela não pode
    # ter push nela, e pular a leitura de eventos dele economiza uma chamada por projeto
    # numa instância grande. Mas no modo baseline (ou sem janela) ele é EXATAMENTE o
    # filtro errado: um repositório cujo último commit é de meses atrás é justamente o
    # que queremos avaliar.
    ativos_desde = desde.strftime("%Y-%m-%dT%H:%M:%SZ") if desde else None
    log.info(
        "enumerando projetos da instância (keyset)%s…",
        f", com atividade desde {ativos_desde}" if ativos_desde else ", sem filtro de atividade",
    )
    try:
        projetos = gl.listar_projetos(
            membership=cfg.gitlab_membership_only,
            ativos_desde=ativos_desde,
            teto=cfg.max_projects,
        )
    except GitLabError as exc:
        ignorados.append({"projeto": "(enumeração)", "motivo": str(exc)})
        return []

    # Vazio com filtro de data é ambíguo: pode ser "não há projeto" ou "há projeto, mas
    # nenhum mexido na janela". Uma chamada extra transforma o zero num diagnóstico.
    if not projetos and ativos_desde:
        try:
            amostra = gl.listar_projetos(membership=cfg.gitlab_membership_only, ativos_desde=None, teto=200)
        except GitLabError:
            amostra = []
        if amostra:
            recentes = sorted((p.ultima_atividade or "") for p in amostra if p.ultima_atividade)
            contexto["diagnostico_vazio"] = (
                f"a instância tem pelo menos {len(amostra)} projeto(s), mas nenhum com atividade "
                f"desde {ativos_desde}. Atividade mais recente encontrada: "
                f"{recentes[-1][:10] if recentes else 'desconhecida'}."
            )
            log.warning("nenhum projeto com atividade na janela — %s", contexto["diagnostico_vazio"])
            log.warning("Para avaliar o estado atual do código independente da data, use --baseline.")
    return projetos


def coletar_baseline(
    gl: GitLabClient, cfg: Config, projetos: list[Projeto], estado: State,
    ignorados: list[dict], pulados: list[dict], reprocessar: bool = False,
) -> tuple[list[Push], int, int, str]:
    """Baseline: os últimos commits de cada branch monitorada, sem limite de data.

    É o modo de partida e o modo para repositório parado: lê o HISTÓRICO DO GIT
    (`GET /repository/commits`), que existe sempre, em vez de depender do feed de
    eventos — que não existe em repo importado e é podado com o tempo.
    """
    fila: list[Push] = []
    encontrados = 0
    ja_auditados = 0
    teto = ""

    for i, proj in enumerate(projetos, 1):
        refs = cfg.gitlab_branches or [proj.branch_default]
        for ref in refs:
            if not ref:
                continue
            try:
                commits = gl.ultimos_commits(proj.id, ref, cfg.baseline_commits)
            except GitLabError as exc:
                detalhe = str(exc)
                if "404" in detalhe:
                    detalhe += f" — a branch {ref!r} não existe neste projeto, ou o repositório está vazio"
                elif "403" in detalhe or "401" in detalhe:
                    detalhe += " — o token não tem acesso ao repositório"
                ignorados.append({"projeto": f"{proj.caminho} ({ref})", "motivo": detalhe})
                continue

            if not commits:
                pulados.append({"alvo": f"{proj.caminho} · {ref}", "motivo": "repositório sem commits"})
                continue

            for commit in commits:
                encontrados += 1
                push = gl.push_do_commit(proj, commit, ref)
                if not push.commit_para:
                    continue
                if not reprocessar and estado.ja_auditado(push.projeto_id, push.commit_para):
                    ja_auditados += 1
                    continue
                if any(f.chave == push.chave for f in fila):
                    continue
                fila.append(push)

        if i % 25 == 0:
            log.info("  %d/%d projetos lidos · %d commit(s) na fila", i, len(projetos), len(fila))
        if len(fila) >= cfg.max_pushes:
            teto = (f"a coleta parou em MAX_PUSHES={cfg.max_pushes}; "
                    f"projetos {i}..{len(projetos)} não foram lidos nesta execução")
            log.warning(teto)
            break

    fila.sort(key=lambda p: p.criado_em, reverse=True)
    return fila[: cfg.max_pushes], encontrados, ja_auditados, teto


def coletar_pushes(gl: GitLabClient, cfg: Config, projetos: list[Projeto], desde: datetime,
                   estado: State, ignorados: list[dict], pulados: list[dict],
                   reprocessar: bool = False) -> tuple[list[Push], int, int, str]:
    encontrados = 0
    ja_auditados = 0
    fila: list[Push] = []
    teto = ""

    for i, proj in enumerate(projetos, 1):
        try:
            pushes = gl.pushes_do_projeto(proj, desde)
        except GitLabError as exc:
            detalhe = str(exc)
            if "403" in detalhe or "404" in detalhe or "401" in detalhe:
                detalhe += " — o token não tem acesso a este projeto"
            ignorados.append({"projeto": proj.caminho, "motivo": detalhe})
            continue

        # O feed de eventos não é infalível: repositório importado não gera evento de
        # push, e o GitLab poda eventos antigos. Se o projeto teve atividade DENTRO da
        # janela mas nenhum evento apareceu, o feed está furado para ele — recorremos ao
        # histórico do git, que é a fonte de verdade.
        if not pushes and cfg.history_fallback:
            atividade = de_iso(proj.ultima_atividade)
            if atividade and atividade > desde:
                log.info("  %s teve atividade mas nenhum evento de push — lendo o histórico do git",
                         proj.caminho)
                for ref in (cfg.gitlab_branches or [proj.branch_default]):
                    try:
                        for commit in gl.ultimos_commits(proj.id, ref, cfg.baseline_commits):
                            criado = de_iso(commit.get("committed_date") or commit.get("created_at"))
                            if criado and criado > desde:
                                pushes.append(gl.push_do_commit(proj, commit, ref))
                    except GitLabError as exc:
                        ignorados.append({"projeto": f"{proj.caminho} ({ref})", "motivo": str(exc)})

        for p in pushes:
            encontrados += 1
            if p.motivo_ignorado:
                pulados.append({"alvo": f"{p.projeto_caminho} · {p.ref}", "motivo": p.motivo_ignorado})
                continue
            if cfg.gitlab_branches and p.branch not in cfg.gitlab_branches:
                continue
            if not reprocessar and estado.ja_auditado(p.projeto_id, p.commit_para or ""):
                ja_auditados += 1
                continue
            if any(f.chave == p.chave for f in fila):
                continue
            fila.append(p)

        if i % 25 == 0:
            log.info("  %d/%d projetos lidos · %d push(es) na fila", i, len(projetos), len(fila))
        if len(fila) >= cfg.max_pushes:
            teto = (f"a coleta parou em MAX_PUSHES={cfg.max_pushes}; "
                    f"projetos {i}..{len(projetos)} não foram lidos nesta execução")
            log.warning(teto)
            break

    fila.sort(key=lambda p: p.criado_em)
    return fila[: cfg.max_pushes], encontrados, ja_auditados, teto


# ------------------------------------------------------------------------- um push

def processar_push(push: Push, gl: GitLabClient, cfg: Config, aspm: ASPMClient | None,
                   area: Path) -> ResultadoPush:
    res = ResultadoPush(push=push)
    trabalho = area / f"{push.projeto_id}-{push.commit_curto}"
    trabalho.mkdir(parents=True, exist_ok=True)

    try:
        raiz = gl.baixar_codigo(push.projeto_id, push.commit_para or "", trabalho / "src")
    except GitLabError as exc:
        res.erros.append(f"não foi possível obter o código: {exc}")
        return res

    # Antes de varrer: o que existe de fato na árvore? "0 achados" sem esta contagem é
    # ambíguo — pode ser código limpo, árvore vazia, ou linguagem não coberta.
    res.arquivos_no_commit, res.extensoes = inventariar_arvore(raiz, cfg.skip_paths)
    if res.arquivos_no_commit == 0:
        res.erros.append(
            "o código baixado não tem nenhum arquivo analisável — repositório vazio, "
            "ou tudo caiu em SCAN_SKIP_PATHS"
        )
        return res

    semgrep = rodar_semgrep(cfg, raiz, trabalho / "semgrep.json")
    bearer = rodar_bearer(cfg, raiz, trabalho / "bearer.json")
    trivy = (rodar_trivy(cfg, raiz, trabalho / "trivy.json") if cfg.trivy_enabled
             else ResultadoScannerVazio("Trivy"))
    res.erros.extend(semgrep.erros + bearer.erros + trivy.erros)
    res.arquivos_varridos = semgrep.arquivos_varridos

    if not semgrep.ok and not bearer.ok and not trivy.ok:
        res.erros.append("nenhuma ferramenta produziu resultado — este push ficou sem análise")
        return res

    # Semgrep abriu o repositório e não encontrou alvo: quase sempre é linguagem fora do
    # ruleset. Silenciar isso faria o relatório afirmar "limpo" sobre código não analisado.
    if semgrep.ok and semgrep.arquivos_varridos == 0 and res.arquivos_no_commit > 0:
        amostra = ", ".join(f"{e} ({n})" for e, n in list(res.extensoes.items())[:5])
        res.erros.append(
            f"o Semgrep não encontrou arquivo analisável entre os {res.arquivos_no_commit} "
            f"do commit — as regras de SEMGREP_CONFIGS podem não cobrir estas linguagens "
            f"[{amostra}]"
        )

    # Recorte para o código novo do push. A análise já rodou sobre a árvore inteira;
    # aqui decidimos o que é reportado.
    alterados = conjunto_de_arquivos(push.arquivos_alterados)
    recortar = cfg.scan_scope == "changed" and bool(alterados)
    if cfg.scan_scope == "changed" and not alterados:
        res.erros.append(
            "sem lista de arquivos alterados (diff indisponível) — reportando a árvore inteira deste commit"
        )

    docs: dict[str, dict] = {}
    if semgrep.ok and semgrep.documento is not None:
        doc = semgrep.documento
        if recortar:
            doc, fora = recortar_semgrep(doc, alterados, raiz)
            res.recortados += fora
        docs["Semgrep"] = doc
    if bearer.ok and bearer.documento is not None:
        doc = bearer.documento
        if recortar:
            doc, fora = recortar_bearer(doc, alterados, raiz)
            res.recortados += fora
        docs["Bearer"] = doc
    if trivy.ok and trivy.documento is not None:
        doc = trivy.documento
        if recortar:
            doc, fora = recortar_trivy(doc, alterados, raiz)
            res.recortados += fora
        docs["Trivy"] = doc

    achados = normalizar_semgrep(docs.get("Semgrep"), raiz, cfg.escalate_high_impact)
    achados += normalizar_bearer(docs.get("Bearer"), raiz)
    achados += normalizar_trivy(docs.get("Trivy"), raiz)
    res.achados = ordenar(achados)

    # Auditoria histórica nunca fecha achados ausentes: commits antigos podem
    # reintroduzir/fechar findings incorretamente mesmo com SCAN_SCOPE=full.
    if aspm:
        from urllib.parse import urlsplit
        repository = repo_id(urlsplit(cfg.gitlab_url).hostname, push.projeto_caminho)
        for ferramenta, doc in docs.items():
            try:
                arquivo = preparar_relatorio(cfg, ferramenta, doc, trabalho, raiz)
                envio = aspm.enviar(ferramenta=ferramenta, relatorio=arquivo, projeto=repository,
                    branch=push.branch, commit=push.commit_para or "",
                    run_id=f"audit-{push.projeto_id}-{push.commit_para}", scan_complete=False)
                res.envios_aspm.append(envio)
            except Exception as exc:
                res.envios_aspm.append(ResultadoEnvio(ferramenta, False,
                    mensagem=f"Preparação do relatório falhou ({type(exc).__name__})"))
        res.fechamento_suprimido = "auditoria de commits históricos (scan_complete=false)"
    elif cfg.dry_run:
        res.envios_simulados.extend(docs)

    return res


def alertar(res: ResultadoPush, cfg: Config) -> None:
    severos = [a for a in res.achados if a.severidade in cfg.slack_severities]
    if not severos:
        res.slack = "sem achado severo"
        return
    payload = montar_payload(res.push, severos, cfg, res.envios_aspm, res.erros)
    if not cfg.slack_webhook:
        res.slack = "Slack não configurado"
        log.warning("    %d achado(s) severo(s) sem destino: SLACK_WEBHOOK_URL está vazio", len(severos))
        return
    if cfg.dry_run:
        res.slack = "DRY-RUN"
        log.info("    [DRY-RUN] Slack não enviado. Prévia: %s", payload["text"][:160])
        return
    ok, detalhe = enviar_slack(cfg.slack_webhook, payload)
    res.slack = "enviado" if ok else f"falhou: {detalhe}"
    if not ok:
        log.warning("    envio ao Slack falhou: %s", detalhe)


# ----------------------------------------------------------------------------- ciclo

def executar(cfg: Config, args) -> int:
    inicio = agora()
    estado = State(backend_de(cfg))
    if estado.dados.get("estado_corrompido"):
        log.warning("estado anterior ilegível — recomeçando a janela pelo lookback inicial")

    desde, primeira = estado.inicio_da_janela(cfg.first_run_lookback_days)
    if args.desde:
        forcado = de_iso(args.desde if "T" in args.desde else f"{args.desde}T00:00:00Z")
        if not forcado:
            log.error("--desde inválido: use AAAA-MM-DD ou ISO-8601")
            return 0
        desde, primeira = forcado, True

    for aviso in cfg.avisos_env:
        log.error("PROBLEMA NO .ENV: %s", aviso)
    for aviso in cfg.avisos_de_seguranca():
        log.warning("INSEGURO: %s", aviso)

    # Baseline: avalia o estado atual do código sem limite de data. É o certo na primeira
    # execução e em instância com repositório parado — o modo incremental, por definição,
    # só olha o que mudou desde a última vez, e num repo sem push recente isso é nada.
    baseline = bool(args.baseline) or (primeira and cfg.baseline_on_first_run and not args.desde)
    escopo_efetivo = cfg.scan_scope
    if baseline:
        log.info("modo BASELINE: últimos %d commit(s) por branch, sem limite de data",
                 cfg.baseline_commits)
        if cfg.scan_scope == "changed" and not args.escopo:
            # Recortar um baseline pelos arquivos do último commit reportaria quase nada:
            # num repo parado o commit mais recente costuma mexer em um ou dois arquivos.
            # O propósito do baseline é avaliar a árvore inteira.
            escopo_efetivo = "full"
            log.info("escopo ajustado para 'full' neste baseline "
                     "(use --escopo changed para forçar o recorte)")
    if args.escopo:
        escopo_efetivo = args.escopo
    cfg.scan_scope = escopo_efetivo

    for aviso in cfg.avisos_env:
        log.error("PROBLEMA NO .ENV: %s", aviso)
    for aviso in cfg.avisos_de_seguranca():
        log.warning("INSEGURO: %s", aviso)

    if baseline:
        log.info("janela: sem limite de data (baseline)")
    else:
        log.info("janela: desde %s", para_iso(desde))

    gl = GitLabClient(cfg.gitlab_url, cfg.gitlab_token, verify_tls=cfg.gitlab_verify_tls)
    aspm = ASPMClient(cfg) if not cfg.dry_run else None

    ignorados: list[dict] = []
    pulados: list[dict] = []
    diagnostico: dict = {}
    projetos = descobrir_projetos(gl, cfg, None if baseline else desde, ignorados, diagnostico)
    log.info("%d projeto(s) candidatos", len(projetos))

    if baseline:
        log.info("lendo o histórico do git de cada projeto…")
        fila, encontrados, ja_auditados, teto = coletar_baseline(
            gl, cfg, projetos, estado, ignorados, pulados, args.reprocessar
        )
    else:
        fila, encontrados, ja_auditados, teto = coletar_pushes(
            gl, cfg, projetos, desde, estado, ignorados, pulados, args.reprocessar
        )
    log.info("%d commit(s)/push(es) a analisar (%d já auditados antes, %d sem código)",
             len(fila), ja_auditados, len(pulados))

    if not fila:
        if diagnostico.get("diagnostico_vazio"):
            log.warning("nada a analisar: %s", diagnostico["diagnostico_vazio"])
        elif ja_auditados:
            log.info("nada novo: os %d commit(s) encontrados já foram auditados. "
                     "Use --reprocessar ou --desde para reavaliar.", ja_auditados)
        elif not projetos:
            log.warning("nada a analisar: nenhum projeto visível. Com token sem permissão de "
                        "administrador, use GITLAB_PROJECTS ou GITLAB_MEMBERSHIP_ONLY=true.")
        else:
            log.warning("nada a analisar: %d projeto(s) visíveis, nenhum commit elegível. "
                        "Tente --baseline para avaliar o estado atual do código.", len(projetos))

    if fila and cfg.scan_scope == "changed":
        log.info("buscando os arquivos alterados de cada push…")
        for p in fila:
            gl.arquivos_alterados(p)

    resultados: list[ResultadoPush] = []
    area = Path(tempfile.mkdtemp(prefix="sast-sentinel-"))
    try:
        for i, push in enumerate(fila, 1):
            log.info("[%d/%d] %s · %s · %s · @%s", i, len(fila), push.projeto_caminho,
                     push.branch, push.commit_curto, push.autor_username)
            try:
                res = processar_push(push, gl, cfg, aspm, area)
            except Exception as exc:  # noqa: BLE001 — um push ruim não derruba o ciclo
                log.error("    erro inesperado neste push (%s)", type(exc).__name__)
                res = ResultadoPush(push=push, erros=[f"erro inesperado: {type(exc).__name__}"])

            alertar(res, cfg)
            resultados.append(res)

            c = res.por_severidade()
            log.info(
                "    %d arquivo(s) no commit, %s varrido(s) pelo Semgrep",
                res.arquivos_no_commit,
                res.arquivos_varridos if res.arquivos_varridos >= 0 else "?",
            )
            log.info(
                "    achados: %d crítica(s) · %d alta(s) · %d média(s) · %d baixa(s) · "
                "%d info · %d TOTAL",
                c["CRITICAL"], c["HIGH"], c["MEDIUM"], c["LOW"], c["INFO"], len(res.achados),
            )
            for envio in res.envios_aspm:
                log.info("    ASPM %s %s · repo=%s · test_id=%s · job_id=%s · %s",
                         "OK" if envio.ok else "FALHOU", envio.ferramenta, envio.produto,
                         envio.test_id, envio.job_id, envio.mensagem)
            log.info("    Slack %s", res.slack)
            for erro in res.erros:
                log.warning("    cobertura: %s", erro)

            # Marca como auditado só se houve análise de verdade. Um push que falhou
            # ao baixar o código deve voltar na próxima execução.
            # Marca e PERSISTE a cada push. Antes o estado só era salvo no fim: uma
            # interrupção no meio perdia tudo e o próximo ciclo reanalisava — que é o
            # caminho pelo qual commits são reanalisados.
            houve_analise = "não foi possível obter o código" not in " ".join(res.erros)
            envio_ok = bool(res.envios_aspm) and all(e.ok for e in res.envios_aspm) and not res.erros
            if not cfg.dry_run and houve_analise and envio_ok:
                estado.marcar_auditado(push.projeto_id, push.commit_para or "",
                                       {"projeto": push.projeto_caminho, "branch": push.branch,
                                        "achados": len(res.achados)})
                try:
                    estado.salvar()
                except OSError as exc:
                    log.warning("    não foi possível gravar o estado: %s", exc)
            elif not cfg.dry_run and not envio_ok:
                log.warning("    NÃO marcado como auditado: nenhum envio ao ASPM "
                            "funcionou, então este commit volta na próxima execução")
            shutil.rmtree(area / f"{push.projeto_id}-{push.commit_curto}" / "src", ignore_errors=True)
    finally:
        if not args.manter_temporarios:
            shutil.rmtree(area, ignore_errors=True)
        else:
            log.info("temporários mantidos em %s", area)

    contexto = {
        "gitlab": cfg.gitlab_url,
        "aspm": cfg.aspm_base_url if not cfg.dry_run else "(dry-run)",
        "desde": "sem limite (baseline)" if baseline else para_iso(desde),
        "ate": para_iso(inicio),
        "primeira_execucao": primeira,
        "escopo": cfg.scan_scope,
        "modo_coleta": "baseline (histórico do git, sem limite de data)" if baseline
                       else "incremental (eventos de push na janela)",
        "diagnostico_vazio": diagnostico.get("diagnostico_vazio", ""),
        "dry_run": cfg.dry_run,
        "chamadas_api": gl.chamadas,
        "projetos_considerados": len(projetos),
        "projetos_ignorados": ignorados,
        "pushes_ignorados": pulados,
        "pushes_encontrados": encontrados,
        "pushes_ja_auditados": ja_auditados,
        "teto_atingido": teto,
    }

    planilha = {}
    if cfg.report_xlsx:
        try:
            planilha = gerar_planilha(resultados, contexto, cfg.report_dir)
            log.info("planilha: %s", planilha.get("xlsx"))
        except Exception as exc:  # noqa: BLE001
            log.warning("não foi possível gerar a planilha: %s", exc)

    if not cfg.dry_run:
        # Teto atingido significa que há projetos que nem chegaram a ser lidos. Avançar
        # a janela por cima deles perderia esses pushes para sempre.
        ciclo_completo = not teto and all(not r.erros and r.envios_aspm and all(e.ok for e in r.envios_aspm) for r in resultados)
        estado.registrar_execucao(inicio, {
            "pushes": len(resultados),
            "achados": sum(len(r.achados) for r in resultados),
            "projetos": len(projetos),
        }, avancar_carimbo=ciclo_completo)
        estado.salvar()
        if not ciclo_completo:
            log.warning("janela NÃO avançada: houve teto ou falha de análise/entrega. A próxima execução "
                        "recobre a mesma janela e lê os projetos que ficaram de fora.")
    else:
        log.info("DRY-RUN: o carimbo da última execução NÃO foi avançado")

    _resumo_final(resultados, contexto, planilha, cfg)
    return 0


def _resumo_final(resultados, contexto, planilha, cfg) -> None:
    todos = [a for r in resultados for a in r.achados]
    sev = contar(todos)
    crit, alta = sev["CRITICAL"], sev["HIGH"]
    parciais = sum(1 for r in resultados if r.erros)
    arquivos = sum(r.arquivos_no_commit for r in resultados)
    varridos = sum(r.arquivos_varridos for r in resultados if r.arquivos_varridos > 0)
    aspm_ok = sum(1 for r in resultados for e in r.envios_aspm if e.ok)
    aspm_tot = sum(len(r.envios_aspm) for r in resultados)
    simulados = sum(len(r.envios_simulados) for r in resultados)
    slack_ok = sum(1 for r in resultados if r.slack == "enviado")

    print("\n" + "─" * 62)
    print("  SAST Security Sentinel — resumo da execução")
    print("─" * 62)
    print(f"  Modo de coleta      {contexto['modo_coleta']}")
    print(f"  Janela              {contexto['desde']} → {contexto['ate']}")
    print(f"  Escopo do relatório {contexto['escopo']}")
    print(f"  Projetos            {contexto['projetos_considerados']} considerados · "
          f"{len(contexto['projetos_ignorados'])} ignorados")
    print(f"  Pushes              {len(resultados)} analisados · "
          f"{contexto['pushes_ja_auditados']} já auditados · "
          f"{len(contexto['pushes_ignorados'])} sem código")
    print(f"  Arquivos            {arquivos} no(s) commit(s) · {varridos} varrido(s) pelo Semgrep")
    print(f"  ACHADOS (todos)     {len(todos)} no total")
    for nivel in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"):
        if sev.get(nivel):
            print(f"      {EM_PT[nivel]:<14}{sev[nivel]}")
    if todos:
        print(f"  Alerta no Slack     {crit + alta} de {len(todos)} "
              f"(só {', '.join(cfg.slack_severities)})")
    if cfg.dry_run:
        print(f"  ASPM          NADA ENVIADO · {simulados} envio(s) apenas simulado(s)")
    else:
        print(f"  ASPM          {aspm_ok}/{aspm_tot} envios bem-sucedidos")
    falhas_aspm = [e for r in resultados for e in r.envios_aspm if not e.ok]
    if falhas_aspm:
        print(f"      {len(falhas_aspm)} falha(s); primeira: {falhas_aspm[0].mensagem[:120]}")
    if cfg.dry_run:
        print("  Slack               NADA ENVIADO (dry-run)")
    else:
        print(f"  Slack               {slack_ok} alerta(s) enviado(s)")
    print(f"  Cobertura parcial   {parciais} push(es)")
    if contexto.get("teto_atingido"):
        print(f"  ATENÇÃO             {contexto['teto_atingido']}")
    if contexto.get("diagnostico_vazio"):
        print(f"  POR QUE ZERO        {contexto['diagnostico_vazio']}")
    if not resultados and not contexto.get("diagnostico_vazio"):
        print("  POR QUE ZERO        nenhum commit elegível na janela. "
              "Tente:  ./sentinel executar --baseline")
    elif resultados and not todos:
        if arquivos == 0:
            print("  POR QUE ZERO        nenhum arquivo analisável no código baixado")
        elif varridos == 0:
            exts: dict[str, int] = {}
            for r in resultados:
                for e, n in (r.extensoes or {}).items():
                    exts[e] = exts.get(e, 0) + n
            amostra = ", ".join(f"{e} ({n})" for e, n in sorted(exts.items(), key=lambda kv: -kv[1])[:6])
            print(f"  POR QUE ZERO        {arquivos} arquivo(s) baixado(s), mas o Semgrep não")
            print(f"                      reconheceu nenhum como alvo. Extensões: {amostra}")
            print("                      As regras de SEMGREP_CONFIGS podem não cobrir estas linguagens.")
        else:
            print(f"  RESULTADO           {varridos} arquivo(s) analisado(s), nenhuma "
                  "vulnerabilidade encontrada")
    if planilha.get("xlsx"):
        print(f"  Planilha            {planilha['xlsx']}")
    if cfg.dry_run:
        print("  Modo                DRY-RUN — nada foi enviado, estado não avançou")
    print("─" * 62 + "\n")


# ------------------------------------------------------------------------- comandos

def cmd_verificar(cfg: Config, args) -> int:
    print(f"\nConfiguração carregada de {cfg.env_path}:\n")
    print(cfg.resumo())
    print()
    if cfg.avisos_env:
        for a in cfg.avisos_env:
            print(f"  \033[31m⚠ .ENV\033[0m  {a}")
        print()
    avisos = cfg.avisos_de_seguranca()
    if avisos:
        for a in avisos:
            print(f"  \033[33m⚠ INSEGURO\033[0m  {a}")
        print()
    problemas = 0

    try:
        gl = GitLabClient(cfg.gitlab_url, cfg.gitlab_token, verify_tls=cfg.gitlab_verify_tls)
        usuario = gl.get_json("/user") or {}
        print(f"  GitLab       OK — autenticado como {usuario.get('username', '?')}"
              f"{' (administrador)' if usuario.get('is_admin') else ''}")
        if not usuario.get("is_admin") and not cfg.gitlab_projects and not cfg.gitlab_membership_only:
            print("               aviso: o token não é de administrador e GITLAB_PROJECTS está vazio.")
            print("               A enumeração verá só os projetos onde o token é membro.")
    except (GitLabError, Exception) as exc:  # noqa: BLE001
        print(f"  GitLab       FALHOU — {exc}")
        problemas += 1

    print("  ASPM         configuração validada; autenticação confirmada somente no upload")
    print(f"               Empresa: {cfg.aspm_workspace} · Produto: {cfg.aspm_business_product}")

    if cfg.slack_webhook:
        print("  Slack        webhook definido"
              f" · {len(cfg.slack_mentions)} menção(ões) no formato de user group")
    else:
        print("  Slack        não configurado (só admissível em DRY_RUN)")

    print(f"  Semgrep      {cfg.semgrep_bin or 'AUSENTE'}")
    print(f"  Bearer       {cfg.bearer_bin or 'AUSENTE — rode bash setup.sh'}")
    if cfg.trivy_enabled:
        print(f"  Trivy        {cfg.trivy_bin or 'AUSENTE — sem CVE de dependência nem IaC'}"
              + (f"  (scanners: {cfg.trivy_scanners})" if cfg.trivy_bin else ""))
    else:
        print("  Trivy        desligado (TRIVY_ENABLED=false)")

    estado = State(backend_de(cfg))
    ultima = estado.dados.get("ultima_execucao")
    print(f"  Estado       {'última execução: ' + ultima if ultima else 'nunca executado'}"
          f" · {len(estado.dados.get('pushes_auditados', {}))} push(es) no histórico")
    print()
    return 0


def cmd_estado(cfg: Config, args) -> int:
    estado = State(backend_de(cfg))
    d = estado.dados
    print(f"\nArquivo: {estado.arquivo}")
    print(f"Última execução: {d.get('ultima_execucao') or 'nunca'}")
    print(f"Pushes auditados: {len(d.get('pushes_auditados', {}))}")
    for h in (d.get("historico") or [])[-10:]:
        print(f"  {h.get('em')}  pushes={h.get('pushes')}  achados={h.get('achados')}")
    if args.limpar:
        estado.dados = {"versao": 2, "ultima_execucao": None, "pushes_auditados": {}, "historico": []}
        estado.backend.gravar(estado.dados, None)
        print("\nEstado apagado. A próxima execução recomeça pelo lookback inicial.")
    print()
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="sast-sentinel",
        description="Auditoria SAST dos pushes do GitLab → ASPM → Slack.",
    )
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("--env", help="caminho alternativo do arquivo .env")
    ap.add_argument("-v", "--verboso", action="store_true")
    sub = ap.add_subparsers(dest="comando")

    p_run = sub.add_parser("executar", help="roda o ciclo completo (padrão)")
    p_run.add_argument("--dry-run", action="store_true", help="não envia nada e não avança o estado")
    p_run.add_argument(
        "--baseline", action="store_true",
        help="avalia o estado atual do código sem limite de data: lê os últimos commits do "
             "histórico do git de cada branch monitorada. Use em repositório parado.",
    )
    p_run.add_argument("--desde", help="força a janela (AAAA-MM-DD ou ISO-8601), ignorando o estado")
    p_run.add_argument("--projetos", help="lista de projetos, sobrepondo GITLAB_PROJECTS")
    p_run.add_argument("--max-pushes", type=int, help="sobrepõe MAX_PUSHES")
    p_run.add_argument("--escopo", choices=("changed", "full"), help="sobrepõe SCAN_SCOPE")
    p_run.add_argument("--reprocessar", action="store_true",
                       help="reanalisa commits já auditados, ignorando o estado")
    p_run.add_argument("--manter-temporarios", action="store_true", help="não apaga o diretório de trabalho")

    p_pipeline = sub.add_parser("pipeline", help="analisa checkout local, sem histórico, e aplica o gate")
    p_pipeline.add_argument("--source", help="checkout; padrão CI_PROJECT_DIR ou PIPELINE_SOURCE_DIR")
    p_pipeline.add_argument("--dry-run", action="store_true", help="não envia; mantém a decisão do gate")

    sub.add_parser("verificar", help="testa a configuração e a conectividade, sem varrer nada")

    p_estado = sub.add_parser("estado", help="mostra o estado entre execuções")
    p_estado.add_argument("--limpar", action="store_true", help="apaga o estado")

    args = ap.parse_args(argv)
    comando = args.comando or "executar"
    for atributo, padrao in (("dry_run", False), ("desde", None), ("projetos", None),
                             ("max_pushes", None), ("manter_temporarios", False), ("limpar", False),
                             ("baseline", False), ("escopo", None), ("reprocessar", False),
                             ("enviar", False)):
        if not hasattr(args, atributo):
            setattr(args, atributo, padrao)

    logging.basicConfig(
        level=logging.DEBUG if args.verboso else logging.INFO,
        format="%(asctime)s  %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )

    try:
        cfg = Config.load(args.env, require_all=(comando != "estado"),
                          pipeline=True if comando == "pipeline" else None,
                          dry_run=args.dry_run)
    except ConfigError as exc:
        from .pipeline import texto_seguro
        print(f"\n  Erro de configuração: {texto_seguro(exc)}\n", file=sys.stderr)
        # Erro no gate jamais pode aprovar o job. Mantém a saída histórica da auditoria.
        return 2 if comando == "pipeline" or os.environ.get("RUN_PIPELINE", "").strip().lower() not in (
            "", "0", "false", "no", "off", "nao", "não", "n") else 0

    if args.dry_run:
        cfg.dry_run = True
    if args.projetos:
        cfg.gitlab_projects = [p.strip() for p in args.projetos.split(",") if p.strip()]
    if args.max_pushes:
        cfg.max_pushes = args.max_pushes
    if args.verboso:
        cfg.log_level = "DEBUG"
    logging.getLogger().setLevel(getattr(logging, cfg.log_level, logging.INFO))

    from .pipeline import proteger_logs
    proteger_logs()
    try:
        if cfg.run_pipeline:
            from .pipeline import executar_pipeline, verificar_pipeline, proteger_logs
            proteger_logs()
            if comando == "verificar":
                return verificar_pipeline(cfg, getattr(args, "source", None))
            if comando not in ("pipeline", "executar"):
                print("Modo pipeline aceita executar, pipeline ou verificar; não usa estado.", file=sys.stderr)
                return 2
            return executar_pipeline(cfg, getattr(args, "source", None))
        if comando == "verificar":
            return cmd_verificar(cfg, args)
        if comando == "estado":
            return cmd_estado(cfg, args)
        return executar(cfg, args)
    except KeyboardInterrupt:
        print("\ninterrompido — o estado não foi avançado.", file=sys.stderr)
        return 2 if cfg.run_pipeline else 0
    except Exception as exc:  # noqa: BLE001
        if cfg.run_pipeline:
            # Sem traceback com stdout/stderr ou dados de credenciais no gate.
            log.error("Pipeline interrompida por erro técnico (%s)", type(exc).__name__)
            return 2
        log.error("erro inesperado (%s)", type(exc).__name__)
        return 0


if __name__ == "__main__":
    sys.exit(main())
