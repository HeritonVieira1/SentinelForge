#!/usr/bin/env python3
"""Avaliador central de Security Gates do SentinelForge.

Lê relatórios do Trivy (JSON) e/ou do OWASP ZAP (traditional-json), aplica a política de
``security/security-policy.json`` e as exceções de ``security/exceptions.json`` e decide se o pipeline pode seguir.

Princípios:
  * Falha fechado: relatório ausente/ilegível, política inválida ou exceção malformada => exit 2 (reprova).
  * Sem exclusão global: toda exceção exige escopo (package ou target), justificativa, responsável, aprovador
    diferente do responsável, data de criação, validade (<= prazo máximo) e referência do risco.
  * Exceção vencida deixa de valer: o achado volta a bloquear.

Códigos de saída: 0 = aprovado, 1 = bloqueado por achados, 2 = erro de configuração/entrada.
Somente biblioteca padrão (roda no runner sem instalar nada).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SEVERITIES = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")
ZAP_RISK = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH"}
RISK_REF = re.compile(r"^(https://\S+|[A-Z][A-Z0-9]+-\d+)$")
REQUIRED_EXCEPTION_FIELDS = ("id", "tool", "justification", "owner", "approved_by", "created", "expires", "risk_ref")


class ConfigError(Exception):
    """Entrada, política ou exceção inválida: o gate deve falhar."""


@dataclass(frozen=True)
class Finding:
    tool: str  # trivy | zap
    kind: str  # vulnerability | misconfiguration | secret | alert
    id: str
    severity: str
    package: str = ""
    version: str = ""
    fixed_version: str = ""
    target: str = ""
    title: str = ""
    risk_code: int = 0  # ZAP: 0 info, 1 low, 2 medium, 3 high


@dataclass
class Decision:
    finding: Finding
    outcome: str  # block | warn | excepted | pass
    reason: str = ""
    exception: dict[str, Any] | None = None


@dataclass
class Result:
    decisions: list[Decision] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def by(self, outcome: str) -> list[Decision]:
        return [d for d in self.decisions if d.outcome == outcome]

    @property
    def exit_code(self) -> int:
        return 1 if self.by("block") else 0


# ----------------------------------------------------------------------------------------------------------------
# Carregamento
# ----------------------------------------------------------------------------------------------------------------
def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise ConfigError(f"{label}: arquivo não encontrado: {path}") from e
    except (OSError, json.JSONDecodeError) as e:
        raise ConfigError(f"{label}: JSON inválido em {path}: {e}") from e


def parse_date(value: Any, label: str) -> dt.date:
    try:
        return dt.date.fromisoformat(str(value))
    except ValueError as e:
        raise ConfigError(f"{label}: data inválida {value!r} (use AAAA-MM-DD)") from e


def validate_policy(policy: Any) -> dict[str, Any]:
    if not isinstance(policy, dict) or policy.get("version") != 1:
        raise ConfigError("política inválida: esperado objeto com version=1")
    for section in ("exceptions", "trivy", "zap"):
        if not isinstance(policy.get(section), dict):
            raise ConfigError(f"política inválida: seção '{section}' ausente")
    return policy


def trivy_findings(report: Any, label: str) -> list[Finding]:
    if not isinstance(report, dict) or "SchemaVersion" not in report:
        raise ConfigError(f"{label}: não parece um relatório JSON do Trivy (sem SchemaVersion)")
    findings: list[Finding] = []
    for result in report.get("Results") or []:
        target = str(result.get("Target", ""))
        for v in result.get("Vulnerabilities") or []:
            findings.append(Finding(
                "trivy", "vulnerability", str(v.get("VulnerabilityID", "?")), str(v.get("Severity", "UNKNOWN")).upper(),
                str(v.get("PkgName", "")), str(v.get("InstalledVersion", "")), str(v.get("FixedVersion", "") or ""),
                target, str(v.get("Title", ""))))
        for m in result.get("Misconfigurations") or []:
            if str(m.get("Status", "FAIL")).upper() != "FAIL":
                continue  # PASS/EXCEPTION não são achados
            findings.append(Finding(
                "trivy", "misconfiguration", str(m.get("ID") or m.get("AVDID") or "?"), str(m.get("Severity", "UNKNOWN")).upper(),
                target=target, title=str(m.get("Title", ""))))
        for s in result.get("Secrets") or []:
            findings.append(Finding(
                "trivy", "secret", str(s.get("RuleID", "?")), str(s.get("Severity", "UNKNOWN")).upper(),
                target=target, title=str(s.get("Title", ""))))
    return findings


def zap_findings(report: Any, label: str) -> list[Finding]:
    if not isinstance(report, dict) or "site" not in report:
        raise ConfigError(f"{label}: não parece um relatório JSON do ZAP (sem 'site')")
    findings: list[Finding] = []
    for site in report.get("site") or []:
        host = str(site.get("@name", ""))
        for alert in site.get("alerts") or []:
            try:
                code = int(alert.get("riskcode", 0))
            except (TypeError, ValueError) as e:
                raise ConfigError(f"{label}: riskcode inválido em alerta ZAP") from e
            findings.append(Finding(
                "zap", "alert", str(alert.get("alertRef") or alert.get("pluginid") or "?"), ZAP_RISK.get(code, "INFO"),
                target=host, title=str(alert.get("name", "")), risk_code=code))
    return findings


# ----------------------------------------------------------------------------------------------------------------
# Exceções
# ----------------------------------------------------------------------------------------------------------------
def validate_exceptions(data: Any, policy: dict[str, Any], today: dt.date) -> tuple[list[dict[str, Any]], list[str]]:
    """Retorna (exceções vigentes, avisos sobre vencidas). Levanta ConfigError se alguma estiver malformada."""
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("exceptions"), list):
        raise ConfigError("exceptions.json inválido: esperado {version: 1, exceptions: [...]}")

    cfg = policy["exceptions"]
    max_days = int(cfg["max_duration_days"])
    allowed_tools = set(cfg["allowed_tools"])
    min_just = int(cfg["min_justification_length"])
    active: list[dict[str, Any]] = []
    notes: list[str] = []

    for index, exc in enumerate(data["exceptions"]):
        where = f"exceptions[{index}]"
        if not isinstance(exc, dict):
            raise ConfigError(f"{where}: deve ser um objeto")
        missing = [k for k in REQUIRED_EXCEPTION_FIELDS if not str(exc.get(k, "")).strip()]
        if missing:
            raise ConfigError(f"{where}: campos obrigatórios ausentes: {', '.join(missing)}")
        if exc["tool"] not in allowed_tools:
            raise ConfigError(f"{where}: tool '{exc['tool']}' inválida (permitidas: {', '.join(sorted(allowed_tools))})")
        for key in ("id", "package", "target"):
            value = str(exc.get(key, ""))
            if any(ch in value for ch in "*?[]"):
                raise ConfigError(f"{where}: curingas não são permitidos em '{key}' (exceção global proibida)")
        if not (str(exc.get("package", "")).strip() or str(exc.get("target", "")).strip()):
            raise ConfigError(f"{where}: informe 'package' ou 'target' (exceção precisa de escopo)")
        if len(str(exc["justification"]).strip()) < min_just:
            raise ConfigError(f"{where}: justificativa curta demais (mínimo {min_just} caracteres)")
        if not RISK_REF.match(str(exc["risk_ref"])):
            raise ConfigError(f"{where}: risk_ref deve ser uma URL https ou um identificador como RISK-123")
        if str(exc["owner"]).strip().lower() == str(exc["approved_by"]).strip().lower():
            raise ConfigError(f"{where}: 'approved_by' deve ser diferente de 'owner' (aprovação independente)")

        created = parse_date(exc["created"], f"{where}.created")
        expires = parse_date(exc["expires"], f"{where}.expires")
        if created > today:
            raise ConfigError(f"{where}: 'created' está no futuro")
        if expires <= created:
            raise ConfigError(f"{where}: 'expires' deve ser posterior a 'created'")
        if (expires - created).days > max_days:
            raise ConfigError(f"{where}: validade de {(expires - created).days} dias excede o máximo de {max_days}")

        if expires < today:
            notes.append(f"Exceção vencida em {expires}: {exc['tool']}/{exc['id']} (owner: {exc['owner']}) — o achado volta a bloquear.")
            continue
        active.append(exc)
    return active, notes


def find_exception(finding: Finding, exceptions: list[dict[str, Any]]) -> dict[str, Any] | None:
    for exc in exceptions:
        if exc["tool"] != finding.tool or exc["id"] != finding.id:
            continue
        if str(exc.get("package", "")).strip() and exc["package"] != finding.package:
            continue
        if str(exc.get("target", "")).strip() and exc["target"] != finding.target:
            continue
        return exc
    return None


# ----------------------------------------------------------------------------------------------------------------
# Decisão
# ----------------------------------------------------------------------------------------------------------------
def classify(finding: Finding, policy: dict[str, Any]) -> tuple[str, str]:
    sev = finding.severity
    if finding.tool == "trivy":
        rules = policy["trivy"].get(finding.kind, {})
        if sev in rules.get("block", []):
            return "block", f"{sev} bloqueia"
        if finding.kind == "vulnerability" and sev in rules.get("block_when_fix_available", []):
            if finding.fixed_version:
                return "block", f"{sev} com correção disponível ({finding.fixed_version}) bloqueia"
            return "warn", f"{sev} sem correção disponível: requer avaliação de risco"
        if sev in rules.get("warn", []):
            return "warn", f"{sev}: requer avaliação"
        return "pass", ""
    if finding.tool == "zap":
        code = finding.risk_code
        rules = policy["zap"]["alert"]
        if code in rules["block_riskcodes"]:
            return "block", "alerta de risco alto (a confirmar; falso positivo só via exceção documentada)"
        if code in rules["warn_riskcodes"]:
            return "warn", "alerta de risco médio: requer avaliação"
        return "pass", ""
    return "pass", ""


def evaluate(findings: list[Finding], policy: dict[str, Any], exceptions: list[dict[str, Any]]) -> Result:
    result = Result()
    for f in findings:
        outcome, reason = classify(f, policy)
        exc = None
        if outcome == "block":
            exc = find_exception(f, exceptions)
            if exc:
                outcome, reason = "excepted", f"exceção vigente até {exc['expires']} (owner {exc['owner']}, aprovada por {exc['approved_by']}, {exc['risk_ref']})"
        result.decisions.append(Decision(f, outcome, reason, exc))
    return result


# ----------------------------------------------------------------------------------------------------------------
# Saída
# ----------------------------------------------------------------------------------------------------------------
def render_markdown(label: str, result: Result) -> str:
    blocks, warns, excepted = result.by("block"), result.by("warn"), result.by("excepted")
    status = "❌ **BLOQUEADO**" if blocks else "✅ **APROVADO**"
    lines = [f"## Security gate — {label}: {status}", ""]
    lines.append(f"Bloqueantes: **{len(blocks)}** · Requerem avaliação: **{len(warns)}** · Com exceção vigente: **{len(excepted)}**")
    lines.append("")

    def table(title: str, decisions: list[Decision]) -> None:
        if not decisions:
            return
        lines.extend([f"### {title}", "", "| Ferramenta | Tipo | ID | Sev. | Pacote/Alvo | Instalada | Correção | Motivo |", "|---|---|---|---|---|---|---|---|"])
        for d in sorted(decisions, key=lambda x: (-SEVERITIES.index(x.finding.severity) if x.finding.severity in SEVERITIES else 0, x.finding.id))[:100]:
            f = d.finding
            where = f.package if f.tool == "trivy" and f.package else f.target
            lines.append(f"| {f.tool} | {f.kind} | `{f.id}` | {f.severity} | {where} | {f.version} | {f.fixed_version or '—'} | {d.reason} |")
        if len(decisions) > 100:
            lines.append(f"\n_… e mais {len(decisions) - 100} (veja o relatório completo)._")
        lines.append("")

    table("Bloqueantes", blocks)
    table("Requerem avaliação (não bloqueiam)", warns)
    table("Exceções vigentes", excepted)
    if result.notes:
        lines.extend(["### Avisos de governança", ""] + [f"- {n}" for n in result.notes] + [""])
    return "\n".join(lines)


def to_json(label: str, result: Result) -> dict[str, Any]:
    return {
        "label": label,
        "exit_code": result.exit_code,
        "counts": {o: len(result.by(o)) for o in ("block", "warn", "excepted", "pass")},
        "blocking": [{"tool": d.finding.tool, "id": d.finding.id, "severity": d.finding.severity, "package": d.finding.package,
                      "target": d.finding.target, "reason": d.reason} for d in result.by("block")],
        "notes": result.notes,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--policy", required=True, type=Path)
    ap.add_argument("--exceptions", type=Path, help="padrão: o arquivo indicado na política")
    ap.add_argument("--trivy", action="append", default=[], type=Path, help="relatório JSON do Trivy (repetível)")
    ap.add_argument("--zap", action="append", default=[], type=Path, help="relatório JSON do ZAP (repetível)")
    ap.add_argument("--label", default="security")
    ap.add_argument("--today", help="AAAA-MM-DD (somente para testes)")
    ap.add_argument("--summary", type=Path, help="escreve o resumo em Markdown")
    ap.add_argument("--result", type=Path, help="escreve o resultado em JSON")
    args = ap.parse_args(argv)

    try:
        today = parse_date(args.today, "--today") if args.today else dt.date.today()
        policy = validate_policy(load_json(args.policy, "política"))
        if not args.trivy and not args.zap:
            raise ConfigError("informe ao menos um relatório (--trivy ou --zap)")

        exc_path = args.exceptions or Path(policy["exceptions"]["file"])
        exceptions, notes = validate_exceptions(load_json(exc_path, "exceções"), policy, today)

        findings: list[Finding] = []
        for p in args.trivy:
            findings += trivy_findings(load_json(p, f"trivy {p.name}"), f"trivy {p.name}")
        for p in args.zap:
            findings += zap_findings(load_json(p, f"zap {p.name}"), f"zap {p.name}")

        result = evaluate(findings, policy, exceptions)
        result.notes.extend(notes)
    except ConfigError as e:
        print(f"::error title=Security gate configuration error::{e}", file=sys.stderr)
        print(f"ERRO DE CONFIGURAÇÃO: {e}", file=sys.stderr)
        return 2

    summary = render_markdown(args.label, result)
    print(summary)
    if args.summary:
        args.summary.write_text(summary + "\n", encoding="utf-8")
    if args.result:
        args.result.write_text(json.dumps(to_json(args.label, result), indent=2), encoding="utf-8")
    if result.exit_code:
        print(f"::error title=Security gate blocked::{len(result.by('block'))} blocking finding(s) in {args.label}", file=sys.stderr)
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
