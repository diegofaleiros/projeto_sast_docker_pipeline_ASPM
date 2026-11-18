SENTINEL ASPM - OPERAÇÃO SRE

Esta edição está em projeto_sast_docker_pipeline_ASPM. O projeto original permanece
separado. Destino dos findings: ASPM Wake, conforme guia HTML v0.431.0 de 17/11/2026.
Integração DefectDojo, backend Amazon S3 e dependência boto3 foram removidos.
Os tokens antigos de Dojo/AWS foram retirados SOMENTE do sentinel.env desta cópia.
Na pipeline, cadastre URL, PAT, Empresa e Produto em GitLab CI/CD Variables.
O sentinel.env destina-se a execuções manuais da auditoria, não ao job GitLab.

1. PREPARAR O ASPM
Crie um Produto na Empresa pela interface e anote o slug (ASPM_BUSINESS_PRODUCT).
Emita um PAT de serviço da Empresa ou Vertical (ASPM_PAT=aspm_pat_...).
Use o slug real da Empresa em ASPM_WORKSPACE. Não use o nome de exibição Wake.
Um PAT de Vertical pode atender várias Empresas, mas cada execução precisa selecionar
uma Empresa/Produto. Para empresas diferentes, use configurações/execuções separadas.
Restrinja GITLAB_PROJECTS aos repositórios da Empresa selecionada; varrer a instância
inteira em uma execução só é apropriado quando todos têm o mesmo destino ASPM.
ASPM_BASE_URL do guia: https://191.252.227.92. Confirme a URL canônica e o certificado.
A política embarcada permite esse host. Se mudar para DNS, Segurança deve atualizar
aspm_allowed_hosts em sast_sentinel/pipeline-policy.json e reconstruir a imagem.
HTTPS e validação de certificado são obrigatórios; REQUESTS_CA_BUNDLE pode apontar
para um certificado PEM montado no container. Não desligue TLS.

2. CONSTRUIR IMAGENS NOVAS (no diretório deste projeto)
  bash tests/smoke.sh
  docker build --target pipeline -t sentinel-aspm:pipeline .
  docker build --target runtime -t sentinel-aspm:auditor .
A imagem pipeline instala ferramentas e regras no build, protegidas contra escrita.
A imagem auditor instala ferramentas na inicialização; o volume /opt/tools guarda
Bearer e Trivy. Semgrep permanece no venv da imagem/container.
Não use a imagem antiga: ela continua com o destino antigo.

3. VARIÁVEIS GLOBAIS NO GITLAB
No grupo que contém os projetos: Settings > CI/CD > Variables > Add variable.
Tipo Variable; Environment scope * (ou o escopo real do ambiente do job).
A imagem não contém URL ASPM padrão: o job deve receber ASPM_BASE_URL, ASPM_PAT,
ASPM_WORKSPACE e ASPM_BUSINESS_PRODUCT pelas variáveis GitLab.
Não é preciso passar sentinel.env, --env-file nem --build-arg no pipeline.
Não coloque esses quatro valores no YAML; o container herda as variáveis do job.
ASPM_PAT e SLACK_WEBHOOK_URL: Masked/Hidden, sem expansão de referências.
Demais chaves: ASPM_BASE_URL, ASPM_WORKSPACE, ASPM_BUSINESS_PRODUCT,
ASPM_SCAN_COMPLETE=false e ASPM_POLL_TIMEOUT=900.
Use pipeline.env.example como lista das demais opções de scanner/gate.
Protected só entrega a variável em refs autorizadas pelo GitLab. Se o job rodar em
branch/MR sem o segredo, falhará; não aprove sem notificar. Configure a política de
branches/MRs e o acesso a segredos com o administrador. Não exponha PAT de serviço
amplo a forks ou a jobs arbitrários controlados pelos desenvolvedores.
O repositório central não transfere suas variáveis para projetos que o incluem:
variáveis de grupo são herdadas pelos projetos pertencentes àquele grupo/subgrupo.
Para outra Empresa, sobrescreva workspace/produto no subgrupo apropriado.

4. PUBLICAR E CHAMAR O TEMPLATE
Depois do teste local, publique a imagem em um repositório Docker autorizado:
  docker tag sentinel-aspm:pipeline SEU_USUARIO/sentinel-aspm:v1
  docker push SEU_USUARIO/sentinel-aspm:v1
  docker image inspect --format '{{index .RepoDigests 0}}' SEU_USUARIO/sentinel-aspm:v1
Substitua image.name nos dois templates pelo nome@sha256:DIGEST_REAL.
O placeholder intencional impede usar por engano o digest da imagem antiga.
Versione os templates no projeto central de Segurança/SRE. No projeto consumidor:

  stages: [security, test, build, deploy]
  include:
    - project: devsecops/seguranca-sast
      ref: SHA_COMPLETO_DO_COMMIT_GIT_APROVADO
      file: /templates/sentinel.gitlab-ci.yml

ref é o commit/tag do repositório Git de segurança; não é o SHA256 da imagem Docker.
O runner deve ter executor Docker, tag docker-sast e acesso ao ASPM, Slack e fontes
necessárias aos scanners. Bearer baixa regras na primeira execução: sem acesso,
o gate registra falha técnica e bloqueia; as regras Semgrep já vêm na imagem. A arquitetura da imagem deve corresponder ao runner.
O job usa o checkout real do projeto e chama:
  cd /app
  /opt/venv/bin/python -m sast_sentinel pipeline --source "$CI_PROJECT_DIR"
Não precisa token GitLab nem histórico nesse modo. Metadados CI_* vêm do GitLab.

HIGH/CRITICAL: saída 1; falha de scanner/upload/Slack: saída 2; aprovado: saída 0.
A notificação ASPM/Slack ocorre antes da decisão final. Somente summary.json é artifact;
relatórios nativos ficam temporários. Saída 2 tem prioridade sobre vulnerabilidades.
O deploy deve ficar em estágio posterior, sem when:always, allow_failure ou needs que
pulem o gate. Ative Pipelines must succeed e proteja a branch de produção.
O job bloqueia a esteira; não rejeita nem desfaz um push já recebido pelo GitLab.
Um include editável sozinho não impõe o gate: use configuração CI externa central
controlada por Segurança/SRE ou Pipeline Execution Policy quando disponível.
ci/security-policy.ultimate.example.yml é um exemplo a validar na versão GitLab.
Desative skip-ci na política e restrinja quem altera a configuração, runner e imagem.

5. O QUE É ENVIADO
Semgrep: JSON nativo (scan_type=semgrep), packs default, owasp-top-ten e secrets.
Bearer: JSON security por severidade (bearer-cli), scanners sast,secrets.
Trivy: análise IaC (misconfig), JSON convertido pelo próprio Trivy para SARIF 2.1.0
(trivy-iac). Mantém a cobertura IaC existente; não é limitado apenas a Dockerfile.
O contrato fornecido não define ingestão de Trivy CVEs/imagens/secrets: esses modos
são recusados nesta edição para evitar descartar achados ou classificá-los como IaC.
Isso não remove a busca de secrets por Semgrep e Bearer.
Supressões/configs locais e redução dos scanners continuam bloqueadas pela política.
Trechos de código e credenciais conhecidas são removidos antes do envio.

Cada repositório tem um product_slug derivado de host/caminho + hash curto para evitar
colisões. Auditor e pipeline usam a mesma regra. Renomear/transferir cria nova identidade.
Isso pode criar novos repositórios se já houver cargas pelo script antigo sem hash.
O primeiro upload usa auto_create=true e business_product para associar o repositório
à Empresa/Produto. O Produto deve existir; a API não muda associação pré-existente.
Os relatórios são enviados separadamente; não existe transação atômica dos três.
Um envio já concluído não é desfeito caso o seguinte falhe.

6. FECHAMENTO DE FINDINGS
ASPM_SCAN_COMPLETE começa false. Não envia true só porque o JSON existe.
Na pipeline, true só é repassado quando as três análises válidas cobrem o snapshot
inteiro e não há falhas; tags e snapshots sintéticos de merge permanecem false.
Depois de validar a cobertura, Segurança pode habilitar true na configuração central
para permitir ao ASPM fechar findings ausentes por ferramenta/branch.
Auditoria por pushes/commits históricos SEMPRE envia scan_complete=false, inclusive
SCAN_SCOPE=full. Um commit antigo não comprova que o HEAD atual está corrigido.
Assim evita fechar indevidamente achados do presente ao percorrer o histórico.

7. AUDITORIA RECORRENTE SEM S3
  cp sentinel.env.example sentinel.env
  chmod 600 sentinel.env
Preencha GitLab, ASPM e Slack; rode apenas um auditor por volume de estado.
  docker run --rm --env-file sentinel.env \
    -v sentinel-aspm-tools:/opt/tools \
    -v sentinel-aspm-state:/app/.state-aspm \
    -v sentinel-aspm-reports:/app/relatorios \
    sentinel-aspm:auditor verificar
  docker run --rm --env-file sentinel.env \
    -v sentinel-aspm-tools:/opt/tools \
    -v sentinel-aspm-state:/app/.state-aspm \
    -v sentinel-aspm-reports:/app/relatorios \
    sentinel-aspm:auditor executar
O volume de estado substitui o armazenamento remoto. Sem ele o --rm perde o histórico.
O diretório padrão novo é .state-aspm: não reutilize o estado do destino anterior,
senão commits já auditados podem ser pulados antes da primeira carga ASPM.
verificar valida configuração e GitLab; não faz upload sintético nem confirma o PAT.
A autenticação de ingestão é comprovada apenas por um recibo real de upload.

Opções de executar (coloque após executar):
  --dry-run                  não envia nem avança histórico
  --baseline                 coleta últimos commits das branches, sem limite de data
  --desde 2026-11-01          força início da janela
  --projetos grupo/repo       sobrepõe a lista de projetos
  --max-pushes 10             limita o lote
  --escopo changed           reporta arquivos alterados
  --escopo full              reporta a árvore inteira de cada commit
  --reprocessar              ignora deduplicação de commits já auditados
  --manter-temporarios        diagnóstico restrito: conserva relatórios locais
Comando estado mostra o histórico; estado --limpar apaga o estado local.
Use os MESMOS volumes/STATE_DIR nesses comandos. Isso pode provocar reenvios.
--env caminho seleciona arquivo de configuração; -v ativa logs verbosos.
A auditoria mantém sua saída histórica 0; monitore os logs e o resumo. Não use a
saída desse modo para liberar deploy: o gate obrigatório é o comando pipeline.
Só marca commit entregue após todas as entregas válidas; falhas/tetos não avançam
janela. A próxima execução recobre a janela e deduplica os commits concluídos.

8. ASSÍNCRONO, RECIBOS E FALHAS
POST /api/v1/scans/import/ leva Authorization: Token <ASPM_PAT> e X-ASPM-Workspace.
201 exige test_id UUID, engagement, branch e recibo com contadores válidos.
200 com Idempotency-Replayed=true confirma o teste anterior; recibo original não
é inventado como zero. A chave deriva de destino, repo, branch, scanner, run e hash.
202 só significa aceito. O cliente registra job_id, consulta /api/v1/scans/jobs/UUID/
na mesma origem e espera completed. failed/timeout não contam como entrega.
Consulte job_id antes de repetir uma execução em timeout: o servidor pode continuar.
Não há repetição automática de POST em erro de rede, 429 ou 5xx.
summary.json conserva job_id/test_id e recibos das entregas da pipeline.
401/403: verificar expiração/escopo do PAT e Empresa. 422: conferir Produto/formato.
409: associação divergente ou repositório arquivado; não criar duplicatas.
TLS: corrigir certificado/CA/URL canônica. Redirecionamentos são recusados.

9. LIMITES DA VALIDAÇÃO LOCAL
Os smoke tests são offline, com servidores/transportes e scanners simulados. O build
instala ferramentas reais. Isso não substitui executar um teste com seu PAT e confirmar
os findings/recibos na instância ASPM implantada. Nenhuma credencial real foi usada.
As apresentações/figuras antigas em docs/operacao-sentinel são material histórico,
não documentação desta edição. Este README.txt e os templates ASPM são a referência.
