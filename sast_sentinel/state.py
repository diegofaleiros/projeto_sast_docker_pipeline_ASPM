"""Estado entre execuções — é isto que faz "desde a última execução" funcionar.

Guarda o carimbo da última execução bem-sucedida e o conjunto de pushes já auditados.
Um push só é reprocessado se você mandar (`--desde` ou `--reprocessar`).

Regra que importa: o carimbo da execução só avança DEPOIS que o ciclo termina. Se o
processo morrer no meio, a próxima execução recomeça da janela anterior e nada é
silenciosamente pulado.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .storage import BackendDeEstado, BackendLocal, ConflitoDeVersao, fundir

log = logging.getLogger(__name__)

ISO = "%Y-%m-%dT%H:%M:%SZ"


def agora() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def para_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(ISO)


def de_iso(texto: str | None) -> datetime | None:
    if not texto:
        return None
    try:
        return datetime.fromisoformat(texto.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


ESPERAS_CONFLITO = (0.5, 1.0, 2.0)  # uma tentativa extra após cada espera


class State:
    def __init__(self, backend: BackendDeEstado | Path):
        if isinstance(backend, (str, os.PathLike)):
            backend = BackendLocal(Path(backend))
        self.backend = backend
        self.arquivo = getattr(backend, "arquivo", backend.descricao)
        self.esperas = ESPERAS_CONFLITO
        self._versao_remota: str | None = None
        self.dados: dict = {"versao": 2, "ultima_execucao": None, "pushes_auditados": {}, "historico": []}
        self._carregar()

    def _carregar(self) -> None:
        try:
            carregado, self._versao_remota = self.backend.ler()
            if isinstance(carregado, dict):
                self.dados.update(carregado)
                self.dados.setdefault("pushes_auditados", {})
                self.dados.setdefault("historico", [])
        except (OSError, json.JSONDecodeError):
            # Estado corrompido não pode travar a auditoria: recomeça limpo e avisa
            # pelo campo, que a CLI reporta.
            self.dados["estado_corrompido"] = True

    # ------------------------------------------------------------------ janela
    def inicio_da_janela(self, lookback_dias: int) -> tuple[datetime, bool]:
        """Devolve (início, primeira_execucao)."""
        anterior = de_iso(self.dados.get("ultima_execucao"))
        if anterior:
            return anterior, False
        return agora() - timedelta(days=max(1, lookback_dias)), True

    # ------------------------------------------------------------------ pushes
    @staticmethod
    def chave(project_id: object, commit: str) -> str:
        return f"{project_id}:{commit}"

    def ja_auditado(self, project_id: object, commit: str) -> bool:
        return self.chave(project_id, commit) in self.dados["pushes_auditados"]

    def marcar_auditado(self, project_id: object, commit: str, detalhe: dict | None = None) -> None:
        self.dados["pushes_auditados"][self.chave(project_id, commit)] = {
            "em": para_iso(agora()),
            **(detalhe or {}),
        }

    def esquecer(self, project_id: object, commit: str) -> None:
        self.dados["pushes_auditados"].pop(self.chave(project_id, commit), None)

    # ------------------------------------------------------------------ ciclo
    def registrar_execucao(self, iniciada_em: datetime, resumo: dict,
                           avancar_carimbo: bool = True) -> None:
        """Registra a execução no histórico e, se o ciclo foi completo, avança a janela.

        `avancar_carimbo=False` quando a coleta parou num teto (MAX_PUSHES): os pushes
        dos projetos que não chegaram a ser lidos ficariam ANTES da próxima janela e
        nunca mais seriam coletados. Mantendo o carimbo, a execução seguinte recobre a
        mesma janela — e a deduplicação por commit garante que nada seja reanalisado.
        """
        if avancar_carimbo:
            self.dados["ultima_execucao"] = para_iso(iniciada_em)
        self.dados["historico"].append({
            "em": para_iso(iniciada_em), "janela_avancou": avancar_carimbo, **resumo,
        })
        self.dados["historico"] = self.dados["historico"][-50:]

    def podar(self, manter: int = 20000) -> None:
        auditados = self.dados["pushes_auditados"]
        if len(auditados) <= manter:
            return
        ordenados = sorted(auditados.items(), key=lambda kv: str(kv[1].get("em", "")), reverse=True)
        self.dados["pushes_auditados"] = dict(ordenados[:manter])

    def salvar(self) -> None:
        """Lê o remoto, funde, grava condicionalmente. Conflito: relê, funde e tenta de novo.

        Esgotadas as tentativas, registra e segue sem gravar: o estado é otimização,
        não requisito, e não pode derrubar a execução.
        """
        self.podar()
        tentativas = len(self.esperas) + 1
        for n in range(tentativas):
            remoto, versao = self.backend.ler()
            fundido = fundir(self.dados, remoto)
            try:
                self._versao_remota = self.backend.gravar(fundido, versao)
            except ConflitoDeVersao:
                if n < len(self.esperas):
                    time.sleep(self.esperas[n])
                continue
            self.dados = fundido
            return
        log.error("estado NÃO gravado em %s: conflito de versão persistente após %d tentativas "
                  "(a execução continua; o próximo push tenta de novo)",
                  self.backend.descricao, tentativas)
