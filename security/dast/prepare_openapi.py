#!/usr/bin/env python3
"""Acrescenta valores `example` reais ao contrato OpenAPI antes do ZAP importá-lo.

Por quê: sem exemplos o ZAP preenche parâmetros com literais ("id", "cveId"...). A rota `{id:guid}` rejeita isso com
404 antes de qualquer handler rodar, e os ataques nunca chegam à lógica protegida (baixíssima cobertura). Com IDs de
registros semeados no banco EFÊMERO do ambiente de teste, as requisições alcançam os endpoints de verdade.

Uso: prepare_openapi.py <openapi.json> <application_id> <vulnerability_id> <user_id>
Roda dentro do container do ZAP (python3 da imagem). Somente biblioteca padrão.
"""
import json
import sys

CVE_EXAMPLE = "CVE-2024-0001"  # formato válido; no ambiente isolado não há rota para o NVD


def example_for(path: str, name: str, ids: dict):
    if name == "cveId":
        return CVE_EXAMPLE
    if name == "applicationId":
        return ids["app"]
    if name in ("assignedUserId", "userId"):
        return ids["user"]
    if name == "entityId":
        return ids["vuln"]
    if name == "id":
        if path.startswith("/api/applications"):
            return ids["app"]
        if path.startswith("/api/vulnerabilities"):
            return ids["vuln"]
        if path.startswith("/api/users"):
            return ids["user"]
    return None


def main() -> int:
    if len(sys.argv) != 5:
        print(__doc__, file=sys.stderr)
        return 2
    doc_path, app_id, vuln_id, user_id = sys.argv[1:5]
    ids = {"app": app_id, "vuln": vuln_id, "user": user_id}
    with open(doc_path, encoding="utf-8") as fh:
        doc = json.load(fh)

    count = 0
    for path, item in (doc.get("paths") or {}).items():
        for method, operation in item.items():
            if not isinstance(operation, dict):
                continue
            for param in operation.get("parameters", []):
                value = example_for(path, param.get("name", ""), ids)
                if value is not None:
                    param["example"] = value
                    param.setdefault("schema", {})["example"] = value
                    count += 1

    with open(doc_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    print(f"[sentinelforge] exemplos reais injetados em {count} parâmetros do OpenAPI")
    return 0 if count > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
