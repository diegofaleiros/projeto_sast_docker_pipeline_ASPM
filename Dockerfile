# SAST Security Sentinel — ambiente de validação.
#
# Semgrep, Trivy e Bearer são baixados quando o container SOBE (docker-entrypoint.sh),
# não no build. Monte um volume em /opt/tools para baixar só na primeira vez.
#
#   docker build -t sentinel:2.1 .
#   docker run --rm --env-file sentinel.env -v sentinel-tools:/opt/tools sentinel:2.1 executar
#
# SEGREDOS: as variáveis abaixo são DECLARADAS aqui (com padrões não sensíveis ou vazias),
# para o container carregar o sistema completo. Os valores reais — token do GitLab, PAT
# do ASPM, webhook do Slack — entram em runtime (-e / --env-file / secret do
# orquestrador). Nunca preencha segredo neste arquivo: ele ficaria gravado nas camadas da
# imagem e em `docker history`.

FROM python:3.13-slim AS base

ARG BEARER_VERSION=2.1.3
ARG TRIVY_VERSION=0.76.2

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tar git \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin sentinel \
    && mkdir -p /opt/tools /app && chown -R sentinel:sentinel /opt/tools /app

# Dependências do agente no venv; o Semgrep fica de fora e é instalado na subida.
COPY requirements.txt /tmp/requirements.txt
RUN python -m venv /opt/venv \
    && grep -viE '^semgrep' /tmp/requirements.txt > /tmp/requirements-base.txt \
    && /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements-base.txt \
    && chown -R sentinel:sentinel /opt/venv \
    && rm /tmp/requirements*.txt

WORKDIR /app
COPY --chown=sentinel:sentinel sast_sentinel/ /app/sast_sentinel/
COPY --chown=sentinel:sentinel docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

# ---------------------------------------------------------------- ferramentas
ENV BEARER_VERSION=${BEARER_VERSION} \
    TRIVY_VERSION=${TRIVY_VERSION} \
    SEMGREP_SPEC="semgrep==1.184.0" \
    TOOLS_DIR=/opt/tools \
    PATH=/opt/venv/bin:/opt/tools/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# ---------------------------------------------------------------- GitLab (obrigatórias)
ENV GITLAB_URL="" \
    GITLAB_API_TOKEN="" \
    GITLAB_PROJECTS="" \
    GITLAB_MEMBERSHIP_ONLY="false" \
    GITLAB_BRANCHES="" \
    GITLAB_VERIFY_TLS="true"

# ---------------------------------------------------------------- ASPM (valores reais somente em runtime)
ENV ASPM_BASE_URL="https://191.252.227.92" \
    ASPM_PAT="" \
    ASPM_WORKSPACE="" \
    ASPM_BUSINESS_PRODUCT="" \
    ASPM_SCAN_COMPLETE="false" \
    ASPM_POLL_TIMEOUT="900"

# ---------------------------------------------------------------- Slack (opcional)
# SLACK_MENTIONS exige a sintaxe de grupo: <!subteam^S01ABCDEF|@sec-team>
ENV SLACK_WEBHOOK_URL="" \
    SLACK_MENTIONS="" \
    SLACK_SEVERITIES="CRITICAL,HIGH" \
    SLACK_MAX_FINDINGS="10"

# ---------------------------------------------------------------- Varredura e operação
ENV SCAN_SCOPE="changed" \
    SCAN_SKIP_PATHS=".git,node_modules,vendor,dist,build,.venv,target" \
    FIRST_RUN_LOOKBACK_DAYS="7" \
    MAX_PROJECTS="2000" \
    MAX_PUSHES="50" \
    BASELINE_ON_FIRST_RUN="true" \
    BASELINE_COMMITS="1" \
    HISTORY_FALLBACK="true" \
    SEMGREP_BIN="" \
    SEMGREP_CONFIGS="p/default p/owasp-top-ten p/secrets" \
    SEMGREP_TIMEOUT="120" \
    BEARER_BIN="" \
    BEARER_SCANNERS="sast,secrets" \
    TRIVY_BIN="" \
    TRIVY_ENABLED="true" \
    TRIVY_SCANNERS="misconfig" \
    TRIVY_TIMEOUT="600" \
    TRIVY_IGNORE_UNFIXED="false" \
    ESCALATE_HIGH_IMPACT="true" \
    STATE_DIR="/app/.state-aspm" \
    REPORT_DIR="relatorios" \
    REPORT_XLSX="true" \
    DRY_RUN="false" \
    LOG_LEVEL="INFO" \
    ALLOW_INSECURE_HTTP="false"

# Por padrão continua sendo auditoria recorrente. CI não exige credenciais GitLab.
ENV RUN_PIPELINE="false" \
    PIPELINE_BLOCK_SEVERITIES="HIGH,CRITICAL" \
    PIPELINE_FAIL_ON_SCAN_ERROR="true" \
    PIPELINE_FAIL_ON_NOTIFICATION_ERROR="true" \
    PIPELINE_SOURCE_DIR="" \
    PIPELINE_SUMMARY_PATH=""

USER sentinel
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["executar"]

# Build para GitLab CI: scanners são baixados no build, nunca pelo job.
# docker build --target pipeline -t sentinel:2.3-pipeline .
FROM base AS pipeline
RUN /usr/local/bin/docker-entrypoint.sh --version
USER root
RUN /opt/venv/bin/python -m sast_sentinel.pipeline_security \
    && chown -R root:root /app /opt/venv /opt/tools \
    && chmod -R go-w /app /opt/venv /opt/tools \
    && chmod -R a+rX /app /opt/venv /opt/tools
USER sentinel
ENV RUN_PIPELINE="true" \
    TRIVY_SCANNERS="misconfig" \
    SCAN_SKIP_PATHS=".git,sentinel-artifacts"
CMD ["pipeline"]

# Build padrão preserva o container auditor, com instalação na inicialização.
FROM base AS runtime
