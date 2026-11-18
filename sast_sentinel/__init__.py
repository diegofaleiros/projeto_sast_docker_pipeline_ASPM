"""SAST Security Sentinel — auditoria contínua dos pushes do GitLab.

Lê os eventos de push de todos os projetos desde a última execução, roda Semgrep e
Bearer sobre o código, envia os findings ao ASPM e alerta o Slack.

Opera em modo estritamente SOMENTE LEITURA no GitLab: apenas requisições GET, sem
clone, sem endpoint de pipeline, sem status de commit.
"""

__version__ = "2.0.0"
