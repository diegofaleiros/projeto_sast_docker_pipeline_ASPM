#!/usr/bin/env bash
# Testes offline: não acessam GitLab, ASPM ou Slack reais.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONDONTWRITEBYTECODE=1
"${PYTHON:-python3}" -m unittest discover -s tests -v
