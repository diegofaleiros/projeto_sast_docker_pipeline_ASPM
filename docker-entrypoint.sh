#!/usr/bin/env bash
# Baixa Semgrep, Trivy e Bearer na subida do container (se ainda não estiverem em
# $TOOLS_DIR) e entrega o controle ao Sentinel. Nunca imprime variáveis de ambiente.
set -Eeuo pipefail
umask 077
# Erros de instalação são falhas técnicas no modo CI; nunca aprovar sem scanner.
falha_instalacao() {
  case "${RUN_PIPELINE:-false}" in
    1|true|TRUE|yes|on|sim) echo "[entrypoint] falha técnica ao preparar scanners" >&2; exit 2 ;;
  esac
  if [ "${1:-}" = pipeline ]; then exit 2; fi
}
trap 'falha_instalacao "${1:-}"' ERR

TOOLS="${TOOLS_DIR:-/opt/tools}"
BIN="$TOOLS/bin"
mkdir -p "$BIN"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

case "$(uname -m)" in
  x86_64)  TRIVY_ARCH=64bit; BEARER_ARCH=amd64 ;;
  aarch64) TRIVY_ARCH=ARM64; BEARER_ARCH=arm64 ;;
  *) echo "[entrypoint] arquitetura não suportada: $(uname -m)" >&2; exit 1 ;;
esac

# baixar <url-base> <arquivo> <arquivo-de-checksums> <binario>
baixar() {
  local base="$1" arq="$2" sums="$3" bin="$4"
  curl -fsSL -o "$TMP/$arq" "$base/$arq"
  curl -fsSL -o "$TMP/$sums" "$base/$sums"
  (cd "$TMP" && grep " $arq\$" "$sums" | sha256sum -c - >/dev/null)
  tar -xzf "$TMP/$arq" -C "$TMP" "$bin"
  install -m 0755 "$TMP/$bin" "$BIN/$bin"
}

if [ ! -x /opt/venv/bin/semgrep ]; then
  echo "[entrypoint] instalando Semgrep (${SEMGREP_SPEC})..." >&2
  /opt/venv/bin/pip install --no-cache-dir --quiet "${SEMGREP_SPEC}"
fi

if [ ! -x "$BIN/trivy" ]; then
  echo "[entrypoint] baixando Trivy ${TRIVY_VERSION}..." >&2
  baixar "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}" \
         "trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" \
         "trivy_${TRIVY_VERSION}_checksums.txt" trivy
fi

if [ ! -x "$BIN/bearer" ]; then
  echo "[entrypoint] baixando Bearer ${BEARER_VERSION}..." >&2
  baixar "https://github.com/Bearer/bearer/releases/download/v${BEARER_VERSION}" \
         "bearer_${BEARER_VERSION}_linux_${BEARER_ARCH}.tar.gz" \
         "checksums.txt" bearer
fi

# O import deve vir do código da imagem, não de um pacote homônimo no checkout.
cd /app
exec /opt/venv/bin/python -m sast_sentinel "$@"
