"""Testes da lógica de decisão dos Security Gates.

ATENÇÃO: os relatórios usados aqui são SINTÉTICOS, escritos à mão no formato do Trivy/ZAP, e existem apenas para
exercitar a política (bloqueia/avisa/exceção/entrada inválida). Eles NÃO representam achados reais de scanners.
Os achados reais vêm das execuções do Trivy/ZAP nos workflows.

Executar: python3 -m unittest discover -s security/tests -v
"""
import contextlib
import datetime as dt
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import evaluate_gate as gate  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
POLICY = REPO / "security" / "security-policy.json"
TODAY = "2026-11-03"


def trivy(vulns=(), misconfigs=(), secrets=(), target="image (ubuntu 24.04)"):
    return {
        "SchemaVersion": 2,
        "Results": [{
            "Target": target,
            "Vulnerabilities": [dict(zip(("VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity"), v)) for v in vulns],
            "Misconfigurations": [dict(zip(("ID", "Severity", "Status"), m)) for m in misconfigs],
            "Secrets": [dict(zip(("RuleID", "Severity"), s)) for s in secrets],
        }],
    }


def zap(alerts=()):
    return {"site": [{"@name": "http://api:8080", "alerts": [
        {"alertRef": a[0], "pluginid": a[0], "name": a[2], "riskcode": str(a[1])} for a in alerts]}]}


def valid_exception(**overrides):
    exc = {
        "id": "CVE-2099-0001", "tool": "trivy", "package": "libfoo",
        "justification": "Biblioteca não é carregada pelo processo da aplicação (imagem distroless).",
        "owner": "owner-a", "approved_by": "approver-b", "created": "2026-10-20", "expires": "2026-12-20",
        "risk_ref": "RISK-101",
    }
    exc.update(overrides)
    return exc


class GateTestCase(unittest.TestCase):
    def run_gate(self, trivy_reports=(), zap_reports=(), exceptions=None, today=TODAY, policy_path=None):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            args = ["--policy", str(policy_path or POLICY), "--today", today, "--label", "test"]
            exc_file = tmp / "exceptions.json"
            exc_file.write_text(json.dumps({"version": 1, "exceptions": exceptions or []}), encoding="utf-8")
            args += ["--exceptions", str(exc_file)]
            for i, rep in enumerate(trivy_reports):
                p = tmp / f"trivy{i}.json"
                p.write_text(json.dumps(rep), encoding="utf-8")
                args += ["--trivy", str(p)]
            for i, rep in enumerate(zap_reports):
                p = tmp / f"zap{i}.json"
                p.write_text(json.dumps(rep), encoding="utf-8")
                args += ["--zap", str(p)]
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = gate.main(args)
            return code, out.getvalue(), err.getvalue()


class VulnerabilityPolicy(GateTestCase):
    def test_clean_report_passes(self):
        code, _, _ = self.run_gate([trivy()])
        self.assertEqual(code, 0)

    def test_critical_with_fix_blocks(self):
        code, out, _ = self.run_gate([trivy(vulns=[("CVE-2099-0001", "libfoo", "1.0", "1.1", "CRITICAL")])])
        self.assertEqual(code, 1)
        self.assertIn("BLOQUEADO", out)

    def test_critical_without_fix_blocks_too(self):
        code, _, _ = self.run_gate([trivy(vulns=[("CVE-2099-0001", "libfoo", "1.0", "", "CRITICAL")])])
        self.assertEqual(code, 1)

    def test_high_with_fix_blocks(self):
        code, _, _ = self.run_gate([trivy(vulns=[("CVE-2099-0002", "libbar", "2.0", "2.1", "HIGH")])])
        self.assertEqual(code, 1)

    def test_high_without_fix_requires_assessment_but_does_not_block(self):
        code, out, _ = self.run_gate([trivy(vulns=[("CVE-2099-0002", "libbar", "2.0", "", "HIGH")])])
        self.assertEqual(code, 0)
        self.assertIn("Requerem avaliação", out)

    def test_medium_and_low_do_not_block(self):
        code, _, _ = self.run_gate([trivy(vulns=[("CVE-1", "a", "1", "2", "MEDIUM"), ("CVE-2", "b", "1", "2", "LOW")])])
        self.assertEqual(code, 0)

    def test_multiple_reports_are_combined(self):
        code, _, _ = self.run_gate([trivy(), trivy(vulns=[("CVE-2099-0001", "libfoo", "1.0", "1.1", "CRITICAL")])])
        self.assertEqual(code, 1)


class OtherTrivyFindings(GateTestCase):
    def test_secret_always_blocks(self):
        code, _, _ = self.run_gate([trivy(secrets=[("generic-api-key", "LOW")])])
        self.assertEqual(code, 1)

    def test_high_misconfiguration_blocks_but_passed_checks_do_not(self):
        self.assertEqual(self.run_gate([trivy(misconfigs=[("DS-0002", "HIGH", "FAIL")])])[0], 1)
        self.assertEqual(self.run_gate([trivy(misconfigs=[("DS-0002", "HIGH", "PASS")])])[0], 0)

    def test_medium_misconfiguration_only_warns(self):
        code, out, _ = self.run_gate([trivy(misconfigs=[("DS-0026", "MEDIUM", "FAIL")])])
        self.assertEqual(code, 0)
        self.assertIn("Requerem avaliação", out)


class ZapPolicy(GateTestCase):
    def test_high_alert_blocks(self):
        self.assertEqual(self.run_gate(zap_reports=[zap([("40018", 3, "SQL Injection")])])[0], 1)

    def test_medium_alert_warns_only(self):
        self.assertEqual(self.run_gate(zap_reports=[zap([("10038", 2, "CSP header not set")])])[0], 0)

    def test_confirmed_false_positive_can_be_excepted_with_scope(self):
        exc = valid_exception(id="40018", tool="zap", package="", target="http://api:8080",
                              justification="Falso positivo confirmado manualmente: parâmetro é validado e parametrizado no servidor.")
        self.assertEqual(self.run_gate(zap_reports=[zap([("40018", 3, "SQL Injection")])], exceptions=[exc])[0], 0)


class ExceptionGovernance(GateTestCase):
    CRITICAL = trivy(vulns=[("CVE-2099-0001", "libfoo", "1.0", "1.1", "CRITICAL")])

    def test_valid_exception_lets_the_finding_through_and_is_reported(self):
        code, out, _ = self.run_gate([self.CRITICAL], exceptions=[valid_exception()])
        self.assertEqual(code, 0)
        self.assertIn("Exceções vigentes", out)
        self.assertIn("RISK-101", out)

    def test_exception_is_scoped_to_the_package(self):
        other = trivy(vulns=[("CVE-2099-0001", "libother", "1.0", "1.1", "CRITICAL")])
        self.assertEqual(self.run_gate([other], exceptions=[valid_exception()])[0], 1)

    def test_exception_for_a_different_cve_does_not_apply(self):
        self.assertEqual(self.run_gate([self.CRITICAL], exceptions=[valid_exception(id="CVE-2099-9999")])[0], 1)

    def test_expired_exception_stops_applying_and_the_finding_blocks_again(self):
        exc = valid_exception(created="2026-08-01", expires="2026-09-30")
        code, out, _ = self.run_gate([self.CRITICAL], exceptions=[exc])
        self.assertEqual(code, 1)
        self.assertIn("Exceção vencida", out)

    def test_exception_valid_until_today_still_applies(self):
        exc = valid_exception(created="2026-10-01", expires=TODAY)
        self.assertEqual(self.run_gate([self.CRITICAL], exceptions=[exc])[0], 0)

    def test_malformed_exceptions_fail_closed(self):
        cases = {
            "sem justificativa": valid_exception(justification=""),
            "justificativa curta": valid_exception(justification="ok"),
            "sem responsável": valid_exception(owner=""),
            "sem aprovador": valid_exception(approved_by=""),
            "auto-aprovação": valid_exception(approved_by="OWNER-A"),
            "sem validade": valid_exception(expires=""),
            "sem referência": valid_exception(risk_ref=""),
            "referência inválida": valid_exception(risk_ref="depois eu vejo"),
            "validade maior que o máximo": valid_exception(created="2026-10-01", expires="2027-03-01"),
            "validade antes da criação": valid_exception(created="2026-10-20", expires="2026-10-01"),
            "criada no futuro": valid_exception(created="2026-12-01", expires="2026-12-20"),
            "data inválida": valid_exception(expires="31/12/2026"),
            "tool desconhecida": valid_exception(tool="outra"),
            "curinga no id": valid_exception(id="CVE-2099-*"),
            "curinga no pacote": valid_exception(package="lib*"),
            "sem escopo": valid_exception(package=""),
        }
        for name, exc in cases.items():
            with self.subTest(name):
                code, _, err = self.run_gate([self.CRITICAL], exceptions=[exc])
                self.assertEqual(code, 2, err)

    def test_one_bad_exception_invalidates_the_whole_file(self):
        code, _, _ = self.run_gate([self.CRITICAL], exceptions=[valid_exception(), valid_exception(owner="")])
        self.assertEqual(code, 2)


class FailClosed(GateTestCase):
    def test_missing_report_fails(self):
        code = gate.main(["--policy", str(POLICY), "--trivy", "/nao/existe.json", "--today", TODAY])
        self.assertEqual(code, 2)

    def test_unparseable_report_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "r.json"
            bad.write_text("isto não é json", encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(gate.main(["--policy", str(POLICY), "--trivy", str(bad), "--today", TODAY]), 2)

    def test_report_that_is_not_from_trivy_fails(self):
        self.assertEqual(self.run_gate([{"Results": []}])[0], 2)

    def test_no_reports_fails(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(gate.main(["--policy", str(POLICY), "--today", TODAY]), 2)

    def test_invalid_policy_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "policy.json"
            bad.write_text(json.dumps({"version": 2}), encoding="utf-8")
            self.assertEqual(self.run_gate([trivy()], policy_path=bad)[0], 2)


class RepositoryFiles(unittest.TestCase):
    def test_policy_and_committed_exceptions_are_valid(self):
        policy = gate.validate_policy(gate.load_json(POLICY, "policy"))
        data = gate.load_json(REPO / "security" / "exceptions.json", "exceptions")
        active, _ = gate.validate_exceptions(data, policy, dt.date.today())
        self.assertIsInstance(active, list)


if __name__ == "__main__":
    unittest.main()
