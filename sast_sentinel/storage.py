"""Estado local com escrita atômica. Execute somente um auditor por volume de estado."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Protocol

ARQUIVO_ESTADO = "sentinel-state.json"
HISTORICO_MAX = 50


class ConflitoDeVersao(Exception):
    """Outra execução gravou entre o nosso `ler` e o nosso `gravar`."""


class BackendDeEstado(Protocol):
    descricao: str

    def ler(self) -> tuple[dict | None, str | None]:
        """Devolve (conteúdo, versao_remota). (None, None) se ainda não existe.

        No backend local, a versão é None.
        """

    def gravar(self, dados: dict, versao_esperada: str | None) -> str | None:
        """Grava e devolve a nova versão. Levanta ConflitoDeVersao se não bater."""


# ---------------------------------------------------------------------------- merge
def fundir(local: dict, remoto: dict | None) -> dict:
    """Une dois estados sem perder nada de nenhum."""
    remoto = remoto or {}

    auditados: dict = {}
    for origem in (remoto.get("pushes_auditados") or {}, local.get("pushes_auditados") or {}):
        for chave, valor in origem.items():
            atual = auditados.get(chave)
            if atual is None or str((valor or {}).get("em", "")) >= str((atual or {}).get("em", "")):
                auditados[chave] = valor

    datas = [d for d in (local.get("ultima_execucao"), remoto.get("ultima_execucao")) if d]

    historico: list = []
    vistos: set[str] = set()
    for item in list(remoto.get("historico") or []) + list(local.get("historico") or []):
        marca = json.dumps(item, sort_keys=True, default=str)
        if marca not in vistos:  # o local já contém o que lemos antes: não duplicar
            vistos.add(marca)
            historico.append(item)
    historico.sort(key=lambda h: str(h.get("em", "")))

    fundido = {**remoto, **local}
    fundido.update({
        "versao": 2,
        "ultima_execucao": max(datas) if datas else None,
        "pushes_auditados": auditados,
        "historico": historico[-HISTORICO_MAX:],
    })
    return fundido


# ---------------------------------------------------------------------------- local
class BackendLocal:
    def __init__(self, diretorio: Path):
        self.dir = Path(diretorio)
        self.arquivo = self.dir / ARQUIVO_ESTADO
        self.descricao = str(self.arquivo)

    def ler(self) -> tuple[dict | None, str | None]:
        if not self.arquivo.exists():
            return None, None
        with open(self.arquivo, encoding="utf-8") as fh:
            dados = json.load(fh)  # JSONDecodeError/OSError tratados por quem chama
        return (dados if isinstance(dados, dict) else None), None

    def gravar(self, dados: dict, versao_esperada: str | None) -> str | None:
        """Escrita atômica: um Ctrl-C no meio não deixa o estado pela metade."""
        self.dir.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".state-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(dados, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, self.arquivo)
            os.chmod(self.arquivo, 0o600)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        return None


def backend_de(cfg) -> BackendDeEstado:
    return BackendLocal(cfg.state_dir)
