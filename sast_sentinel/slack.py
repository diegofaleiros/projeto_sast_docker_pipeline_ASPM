"""Alerta no Slack — uma mensagem por push com achado severo.

A mensagem carrega o que foi pedido: commit/push, quem empurrou, e os achados críticos
e altos. Segredo nenhum sai daqui: os textos já vêm redigidos da triagem, e o que passa
por aqui é escapado para o markup do Slack.

Silêncio é resultado válido. Push sem achado severo não gera mensagem — ruído treina o
time a ignorar o alerta que importa.
"""

from __future__ import annotations

import json

import requests

EMOJI = {"CRITICAL": ":red_circle:", "HIGH": ":large_orange_circle:"}
LIMITE_SECAO = 2900   # o limite real é 3000
LIMITE_BLOCOS = 48    # o limite real é 50


def escapar(texto: object) -> str:
    """Escapa os três caracteres que o Slack interpreta como markup."""
    return str(texto or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def montar_payload(push, achados, cfg, envios_aspm=None, erros=None) -> dict:
    """Monta o Block Kit. `achados` já vem filtrado pelas severidades do alerta."""
    criticos = [a for a in achados if a.severidade == "CRITICAL"]
    altos = [a for a in achados if a.severidade == "HIGH"]
    mencoes = " ".join(cfg.slack_mentions)

    projeto = escapar(push.projeto_caminho)
    branch = escapar(push.branch)
    autor = escapar(push.autor_nome or push.autor_username)
    usuario = escapar(push.autor_username)
    titulo = escapar(push.titulo_commit or "(sem título de commit)")

    # O feed de eventos sabe QUEM EMPURROU; o histórico do git só sabe quem ESCREVEU o
    # commit. Rotular os dois como "quem empurrou" seria mentira num alerta de segurança.
    if getattr(push, "origem", "") == "historico-git":
        rotulo_autor = (
            f"*Autor do commit*\n{autor or usuario}\n`{usuario}`\n_origem: histórico do git_"
        )
    else:
        rotulo_autor = f"*Quem empurrou*\n{autor}\n`@{usuario}`"

    fallback = (
        f"{mencoes} SAST: {len(criticos)} CRÍTICA(S) e {len(altos)} ALTA(S) em "
        f"{projeto}@{branch} — push de {usuario} ({push.commit_curto})"
    ).strip()

    blocos: list[dict] = [
        {"type": "header",
         "text": {"type": "plain_text", "text": "🚨 SAST — vulnerabilidades severas em novo push", "emoji": True}},
        {"type": "section",
         "text": {"type": "mrkdwn",
                  "text": (f"{mencoes}\n" if mencoes else "")
                          + f"*{len(criticos)}* achado(s) *CRÍTICO(S)* e *{len(altos)}* de severidade "
                            f"*ALTA* no código alterado por este push."}},
        {"type": "section",
         "fields": [
             {"type": "mrkdwn", "text": f"*Projeto*\n`{projeto}`"},
             {"type": "mrkdwn", "text": f"*Branch*\n`{branch}`"},
             {"type": "mrkdwn",
              "text": "*Commit*\n" + (f"<{push.commit_url}|`{push.commit_curto}`>"
                                      if push.commit_url.startswith("http") else f"`{push.commit_curto}`")},
             {"type": "mrkdwn", "text": rotulo_autor},
             {"type": "mrkdwn", "text": f"*Mensagem do commit*\n{titulo}"},
             {"type": "mrkdwn",
              "text": f"*Quando*\n{escapar(push.criado_em[:19].replace('T', ' '))} UTC"},
         ]},
    ]

    if push.arquivos_alterados:
        n = len(push.arquivos_alterados)
        amostra = ", ".join(f"`{escapar(a)}`" for a in push.arquivos_alterados[:4])
        extra = f" e mais {n - 4}" if n > 4 else ""
        blocos.append({"type": "context",
                       "elements": [{"type": "mrkdwn", "text": f":page_facing_up: {n} arquivo(s) alterado(s): {amostra}{extra}"}]})

    blocos.append({"type": "divider"})

    mostrados = achados[: cfg.slack_max_findings]
    for a in mostrados:
        etiquetas = (a.cwe[:2] + a.owasp[:1]) or []
        sufixo = " · " + escapar(", ".join(etiquetas)) if etiquetas else ""
        corpo = (
            f"{EMOJI.get(a.severidade, ':white_circle:')} *[{a.severidade_pt}]* {escapar(a.titulo)}\n"
            f"`{escapar(a.local)}` · _{a.ferramenta}_{sufixo}\n"
            f"{escapar(a.descricao) or '_sem descrição fornecida pela ferramenta_'}"
        )
        if a.elevada_por:
            corpo += f"\n:arrow_up: _elevada a {a.severidade_pt}: {escapar(a.elevada_por)}_"
        if a.referencia:
            corpo += f"\n<{a.referencia}|documentação da regra>"
        blocos.append({"type": "section", "text": {"type": "mrkdwn", "text": corpo[:LIMITE_SECAO]}})

    restantes = len(achados) - len(mostrados)
    if restantes > 0:
        blocos.append({"type": "section",
                       "text": {"type": "mrkdwn",
                                "text": f":mag: *+{restantes} achado(s) severo(s) não detalhado(s) aqui.* "
                                        "Veja a lista completa no ASPM."}})

    links = [e for e in (envios_aspm or []) if e.ok and e.url]
    if links:
        blocos.append({"type": "section",
                       "text": {"type": "mrkdwn",
                                "text": ":file_folder: *No ASPM:* "
                                        + " · ".join(f"<{e.url}|{e.ferramenta}>" for e in links)}})

    falhas = [e for e in (envios_aspm or []) if not e.ok]
    if falhas:
        blocos.append({"type": "section",
                       "text": {"type": "mrkdwn",
                                "text": ":warning: *Envio ao ASPM falhou:* "
                                        + escapar("; ".join(f"{e.ferramenta}: {e.mensagem}" for e in falhas))[:600]}})

    if erros:
        blocos.append({"type": "section",
                       "text": {"type": "mrkdwn",
                                "text": ":warning: *Cobertura parcial* — " + escapar("; ".join(erros))[:700]}})

    if any(a.injecao_suspeita for a in achados):
        blocos.append({"type": "section",
                       "text": {"type": "mrkdwn",
                                "text": ":warning: O conteúdo analisado contém texto que tenta se dirigir ao "
                                        "agente (injeção de prompt). Foi tratado como dado inerte e nenhum "
                                        "achado foi suprimido."}})

    blocos.append({"type": "divider"})
    blocos.append({"type": "context",
                   "elements": [{"type": "mrkdwn",
                                 "text": ":lock: SAST Security Sentinel · somente leitura · "
                                         "não altera código, pipelines ou status de commit"}]})

    if len(blocos) > LIMITE_BLOCOS:
        blocos = blocos[: LIMITE_BLOCOS - 1] + [
            {"type": "section", "text": {"type": "mrkdwn", "text": ":scissors: _Alerta truncado no limite do Slack._"}}
        ]

    return {"text": fallback[:3000], "blocks": blocos}


def enviar(webhook: str, payload: dict, timeout: int = 30) -> tuple[bool, str]:
    if not webhook.startswith("https://hooks.slack.com/"):
        return False, "destino não é hooks.slack.com — envio recusado por segurança"
    try:
        resp = requests.post(
            webhook,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            timeout=timeout,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        return False, f"falha de rede: {exc}"
    if resp.status_code != 200:
        return False, f"HTTP {resp.status_code}: {(resp.text or '')[:200]}"
    return True, (resp.text or "ok")[:40]
