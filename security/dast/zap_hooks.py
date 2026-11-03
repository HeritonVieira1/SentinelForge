"""Hooks do OWASP ZAP para o DAST do SentinelForge (carregado por zap-api-scan.py --hook).

Injeta o cabeçalho Authorization em TODAS as requisições do scanner (importação do OpenAPI, spider, regras passivas
e ativas) usando a regra "Replacer" do ZAP. O token vem da variável de ambiente ZAP_AUTH_TOKEN do container, e não
da linha de comando, para não aparecer em listas de processos nem em logs.

A opção `-z "-config replacer.full_list(0)..."` NÃO foi usada de propósito: foi testada e, no ZAP 2.17.0, o
cabeçalho não chegava à API (verificado com um servidor de eco). Este hook foi validado do mesmo modo.
"""
import os
import sys

RULE_DESCRIPTION = "sentinelforge-dast-auth"


def zap_started(zap, target):
    token = os.environ.get("ZAP_AUTH_TOKEN", "").strip()
    if not token:
        print("ERRO: ZAP_AUTH_TOKEN ausente; recusando varredura anônima disfarçada de autenticada.", file=sys.stderr)
        raise SystemExit(3)

    result = zap.replacer.add_rule(
        description=RULE_DESCRIPTION,
        enabled="true",
        matchtype="REQ_HEADER",
        matchregex="false",
        matchstring="Authorization",
        replacement=f"Bearer {token}",
        initiators="",  # vazio = todos os iniciadores (importação, spider, scanner...)
    )
    print(f"[sentinelforge] regra de autenticação do Replacer criada: {result}")
