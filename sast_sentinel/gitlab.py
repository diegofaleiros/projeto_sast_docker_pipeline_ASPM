"""Cliente do GitLab — exclusivamente leitura.

Garantias mecânicas, não apenas disciplina:
  * Só o método GET existe nesta classe. Não há post/put/patch/delete.
  * O código é obtido pelo endpoint de ARQUIVO (`GET .../archive.tar.gz`), não por clone.
    Sem remote, sem .git, sem credential helper — `git push` é impossível, não proibido.
  * Redirect NÃO é seguido: seguir reenviaria o PRIVATE-TOKEN para outro host.
  * Nenhum endpoint de pipeline, job, status de commit, MR ou hook é tocado.

Como pegamos push de TODOS os usuários
--------------------------------------
`GET /projects/:id/events?action=pushed` devolve os eventos de todos os autores daquele
projeto ("lists all visible events for a specified project"). Iterando PROJETOS cobre
automaticamente todo usuário atual e todo usuário futuro — nunca enumeramos usuários.

Enumerar usuários (`GET /users/:id/events`, que é a aba Activity do perfil) tem o
problema inverso: usuário novo só aparece se você reenumerar, e bots/service accounts
costumam nem constar em /users.
"""

from __future__ import annotations

import io
import tarfile
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import requests

from .state import de_iso

USER_AGENT = "sast-security-sentinel/2.0 (read-only)"
MAX_ARCHIVE_BYTES = 500 * 1024 * 1024


class GitLabError(Exception):
    pass


@dataclass
class Projeto:
    id: int
    caminho: str
    web_url: str = ""
    branch_default: str = "main"
    ultima_atividade: str = ""


@dataclass
class Push:
    event_id: int | None
    criado_em: str
    projeto_id: int
    projeto_caminho: str
    projeto_web_url: str
    branch_default: str
    autor_username: str
    autor_nome: str
    ref: str
    acao: str
    commit_de: str | None
    commit_para: str | None
    qtd_commits: int | None
    titulo_commit: str
    arquivos_alterados: list[str] = field(default_factory=list)
    diff_indisponivel: str = ""
    motivo_ignorado: str = ""
    # "evento-de-push" = veio do feed de Activity, e o autor é quem EMPURROU.
    # "historico-git"  = veio de GET /repository/commits, e o autor é quem ESCREVEU o
    #                    commit. O feed de eventos pode não existir (repo importado,
    #                    evento podado), e aí o histórico do git é a única fonte.
    origem: str = "evento-de-push"

    @property
    def branch(self) -> str:
        return (self.ref or "").replace("refs/heads/", "")

    @property
    def commit_curto(self) -> str:
        return (self.commit_para or "")[:10]

    @property
    def commit_url(self) -> str:
        if self.projeto_web_url and self.commit_para:
            return f"{self.projeto_web_url}/-/commit/{self.commit_para}"
        return ""

    @property
    def chave(self) -> str:
        return f"{self.projeto_id}:{self.commit_para}"


class GitLabClient:
    def __init__(self, url: str, token: str, verify_tls: bool = True, timeout: int = 60):
        self.base = url.rstrip("/")
        self.api = f"{self.base}/api/v4"
        self.timeout = timeout
        self.chamadas = 0
        self.sessao = requests.Session()
        self.sessao.headers.update(
            {"PRIVATE-TOKEN": token, "Accept": "application/json", "User-Agent": USER_AGENT}
        )
        self.sessao.verify = verify_tls
        if not verify_tls:
            # Já avisamos uma vez em avisos_de_seguranca(); silenciar o urllib3 evita
            # repetir o mesmo alerta a cada requisição e afogar o log útil.
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        # Redirect desabilitado: um 30x levaria o PRIVATE-TOKEN para outro host.
        self.sessao.max_redirects = 0

    # ------------------------------------------------------------------ transporte
    def _get(self, caminho: str, params: dict | None = None, stream: bool = False) -> requests.Response:
        url = caminho if caminho.startswith("http") else f"{self.api}{caminho}"
        for tentativa in range(1, 4):
            self.chamadas += 1
            try:
                resp = self.sessao.get(
                    url, params=params, timeout=self.timeout, allow_redirects=False, stream=stream
                )
            except requests.RequestException as exc:
                if tentativa < 3:
                    time.sleep(2 * tentativa)
                    continue
                raise GitLabError(f"falha de rede em {self._limpa(url)}: {exc}") from exc

            if resp.status_code in (301, 302, 303, 307, 308):
                destino = resp.headers.get("Location", "")
                dica = "Confira GITLAB_URL."
                if destino.startswith("https://") and url.startswith("http://"):
                    # Caso comum: o servidor força TLS. Seguir o redirect com o
                    # PRIVATE-TOKEN no header é justamente o que não fazemos.
                    dica = ("o servidor força HTTPS — troque GITLAB_URL para https:// "
                            "(se o certificado for autoassinado, use GITLAB_VERIFY_TLS=false).")
                raise GitLabError(
                    f"o servidor redirecionou {self._limpa(url)} — recusado para não reenviar o token. {dica}"
                )
            if resp.status_code == 429 and tentativa < 3:
                espera = int(resp.headers.get("Retry-After", 10) or 10)
                time.sleep(espera)
                continue
            if resp.status_code in (500, 502, 503, 504) and tentativa < 3:
                time.sleep(2 * tentativa)
                continue
            return resp
        raise GitLabError(f"tentativas esgotadas para {self._limpa(url)}")

    def get_json(self, caminho: str, params: dict | None = None):
        resp = self._get(caminho, params)
        if resp.status_code >= 400:
            raise GitLabError(f"HTTP {resp.status_code} em {self._limpa(resp.url)}")
        return resp.json() if resp.content else None

    def paginar(self, caminho: str, params: dict | None = None, teto: int = 100_000):
        """Segue Link rel=next (keyset) ou X-Next-Page (offset)."""
        params = dict(params or {})
        params.setdefault("per_page", 100)  # 100 é o máximo da API
        url, primeiro, vistos = caminho, True, 0
        while url:
            resp = self._get(url, params if primeiro else None)
            if resp.status_code >= 400:
                raise GitLabError(f"HTTP {resp.status_code} em {self._limpa(resp.url)}")
            dados = resp.json() if resp.content else []
            if not isinstance(dados, list):
                return
            for item in dados:
                yield item
                vistos += 1
                if vistos >= teto:
                    return
            proximo = resp.links.get("next", {}).get("url")
            if proximo:
                url, primeiro = proximo, True
                params = None
            elif resp.headers.get("X-Next-Page"):
                params = dict(params or {})
                params["page"] = resp.headers["X-Next-Page"]
                url, primeiro = caminho, True
            else:
                url = None

    @staticmethod
    def _limpa(url: str) -> str:
        import re

        return re.sub(r"(private_token|access_token)=[^&]*", r"\1=***", str(url))

    # ------------------------------------------------------------------ projetos
    def projeto(self, identificador: str | int) -> Projeto:
        ident = str(identificador)
        if not ident.isdigit():
            ident = urllib.parse.quote(ident, safe="")
        d = self.get_json(f"/projects/{ident}") or {}
        return Projeto(
            id=d["id"],
            caminho=d.get("path_with_namespace", str(d["id"])),
            web_url=d.get("web_url", ""),
            branch_default=d.get("default_branch") or "main",
            ultima_atividade=d.get("last_activity_at", ""),
        )

    def listar_projetos(self, membership: bool, ativos_desde: str | None, teto: int) -> list[Projeto]:
        """Enumera projetos por paginação keyset.

        Keyset é obrigatório: a paginação por offset perde registros acima de 50.000
        projetos. `last_activity_after` descarta projeto dormente antes de gastar uma
        chamada de eventos com ele — é o que torna instância grande viável.
        """
        params: dict = {
            "simple": "true",
            "archived": "false",
            "pagination": "keyset",
            "order_by": "id",
            "sort": "asc",
            "per_page": 100,
        }
        if membership:
            params["membership"] = "true"
        if ativos_desde:
            params["last_activity_after"] = ativos_desde

        saida: list[Projeto] = []
        for p in self.paginar("/projects", params, teto=teto):
            saida.append(
                Projeto(
                    id=p["id"],
                    caminho=p.get("path_with_namespace", str(p["id"])),
                    web_url=p.get("web_url", ""),
                    branch_default=p.get("default_branch") or "main",
                    ultima_atividade=p.get("last_activity_at", ""),
                )
            )
        return saida

    # ------------------------------------------------------------------ pushes
    def pushes_do_projeto(
        self, projeto: Projeto, desde: datetime, ate: datetime | None = None
    ) -> list[Push]:
        """Eventos de push do projeto — de todos os autores.

        `after`/`before` da API são DATAS, não timestamps. Pedimos um dia a mais de
        folga e filtramos com precisão de segundo no cliente, senão a janela
        "desde a última execução" perderia ou repetiria eventos na virada do dia.
        """
        from datetime import timedelta

        params = {
            "action": "pushed",
            "after": (desde - timedelta(days=1)).strftime("%Y-%m-%d"),
            "sort": "desc",
        }
        if ate:
            params["before"] = (ate + timedelta(days=1)).strftime("%Y-%m-%d")

        pushes: list[Push] = []
        for ev in self.paginar(f"/projects/{projeto.id}/events", params, teto=2000):
            criado = de_iso(ev.get("created_at"))
            if criado and criado <= desde:
                continue
            if ate and criado and criado > ate:
                continue
            pushes.append(self._para_push(ev, projeto))
        return pushes

    @staticmethod
    def _para_push(ev: dict, projeto: Projeto) -> Push:
        pd = ev.get("push_data") or {}
        autor = ev.get("author") or {}
        push = Push(
            event_id=ev.get("id"),
            criado_em=ev.get("created_at", ""),
            projeto_id=ev.get("project_id") or projeto.id,
            projeto_caminho=projeto.caminho,
            projeto_web_url=projeto.web_url,
            branch_default=projeto.branch_default,
            autor_username=ev.get("author_username") or autor.get("username") or "(desconhecido)",
            autor_nome=autor.get("name") or "",
            ref=pd.get("ref") or "",
            acao=pd.get("action") or "",
            commit_de=pd.get("commit_from"),
            commit_para=pd.get("commit_to"),
            qtd_commits=pd.get("commit_count"),
            titulo_commit=pd.get("commit_title") or "",
        )
        if not push.commit_para or push.acao == "removed":
            push.motivo_ignorado = "push de remoção de ref — não há código para analisar"
        elif pd.get("ref_type") not in (None, "branch", "tag"):
            push.motivo_ignorado = f"ref_type não suportado: {pd.get('ref_type')}"
        return push

    # ------------------------------------------------------ histórico do git
    def ultimos_commits(self, projeto_id: int, ref: str, quantidade: int = 1) -> list[dict]:
        """`GET /repository/commits` — o histórico do git, não o feed de atividade.

        Necessário porque o feed de eventos não é confiável como fonte única: repositório
        importado não gera evento de push, e o GitLab poda eventos antigos. O histórico
        do git existe sempre, e é dele que saem "os últimos commits".
        """
        dados = self.get_json(
            f"/projects/{projeto_id}/repository/commits",
            {"ref_name": ref, "per_page": max(1, min(quantidade, 100))},
        )
        return dados if isinstance(dados, list) else []

    def push_do_commit(self, projeto: Projeto, commit: dict, ref: str) -> Push:
        """Monta um registro de push a partir de um commit do histórico.

        O autor aqui é quem ESCREVEU o commit, não quem empurrou — o histórico do git não
        guarda o empurrador. `origem` marca isso para o relatório não mentir.
        """
        pais = commit.get("parent_ids") or []
        email = str(commit.get("author_email") or "").strip()
        nome = str(commit.get("author_name") or "").strip()
        return Push(
            event_id=None,
            criado_em=str(commit.get("committed_date") or commit.get("created_at") or ""),
            projeto_id=projeto.id,
            projeto_caminho=projeto.caminho,
            projeto_web_url=projeto.web_url,
            branch_default=projeto.branch_default,
            autor_username=email or nome or "(desconhecido)",
            autor_nome=nome,
            ref=f"refs/heads/{ref}" if not ref.startswith("refs/") else ref,
            acao="historico",
            commit_de=pais[0] if pais else None,
            commit_para=str(commit.get("id") or ""),
            qtd_commits=1,
            titulo_commit=str(commit.get("title") or ""),
            origem="historico-git",
        )

    # ------------------------------------------------------------------ diff
    def arquivos_alterados(self, push: Push, limite: int = 500) -> None:
        """Preenche push.arquivos_alterados via GET /repository/compare.

        Branch nova (`commit_from` nulo) não tem base: comparamos com a branch default,
        que responde "o que esta branch acrescenta". Sem isso o push inteiro ficaria
        sem atribuição de arquivo.
        """
        if push.motivo_ignorado or not push.commit_para:
            return
        base = push.commit_de or push.branch_default
        if not base:
            push.diff_indisponivel = "sem base de comparação"
            return
        try:
            d = self.get_json(
                f"/projects/{push.projeto_id}/repository/compare",
                {"from": base, "to": push.commit_para, "straight": "true"},
            ) or {}
        except GitLabError as exc:
            push.diff_indisponivel = str(exc)
            return

        arquivos: list[str] = []
        for diff in d.get("diffs") or []:
            for chave in ("new_path", "old_path"):
                caminho = diff.get(chave)
                if caminho and caminho not in arquivos:
                    arquivos.append(caminho)
        push.arquivos_alterados = arquivos[:limite]
        if len(arquivos) > limite:
            push.diff_indisponivel = f"diff truncado em {limite} arquivos (o push tocou {len(arquivos)})"

    # ------------------------------------------------------------------ código
    def baixar_codigo(self, projeto_id: int, commit: str, destino: Path) -> Path:
        """GET do archive.tar.gz e extração. Sem git, sem remote — push é impossível."""
        destino.mkdir(parents=True, exist_ok=True)
        resp = self._get(
            f"/projects/{projeto_id}/repository/archive.tar.gz", {"sha": commit}, stream=True
        )
        if resp.status_code >= 400:
            raise GitLabError(f"HTTP {resp.status_code} ao baixar o arquivo do commit {commit[:10]}")

        buffer = io.BytesIO()
        total = 0
        for pedaco in resp.iter_content(chunk_size=65536):
            total += len(pedaco)
            if total > MAX_ARCHIVE_BYTES:
                raise GitLabError(f"arquivo maior que o limite de {MAX_ARCHIVE_BYTES // 1048576} MB")
            buffer.write(pedaco)
        buffer.seek(0)

        with tarfile.open(fileobj=buffer, mode="r:gz") as tf:
            membros = [m for m in tf.getmembers() if _membro_seguro(m.name)]
            _extrair(tf, membros, destino)

        filhos = [p for p in destino.iterdir() if p.is_dir()]
        return filhos[0] if len(filhos) == 1 else destino


def _membro_seguro(nome: str) -> bool:
    """Recusa path traversal no tarball — o arquivo vem de fora, é entrada não confiável."""
    n = nome.replace("\\", "/")
    return not (n.startswith("/") or ".." in Path(n).parts)


def _extrair(tf: tarfile.TarFile, membros: list, destino: Path) -> None:
    try:  # Python 3.12+: filtro de segurança nativo
        tf.extractall(destino, members=membros, filter="data")
    except TypeError:  # pragma: no cover
        tf.extractall(destino, members=membros)
