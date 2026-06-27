"""Tests for validation engine and safety controller."""
import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import pytest


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ===== Validation Engine Tests =====

class TestValidationMethod:
    def test_import(self):
        from nova_arsenal.validation.engine import ValidationMethod
        assert ValidationMethod.EXPLOIT_CONFIRMED.value == "exploit_confirmed"


class TestFinding:
    def test_import(self):
        from nova_arsenal.validation.engine import Finding
        f = Finding(
            finding_id="f1", title="Test", description="Test finding",
            target="10.0.0.1", technique_id="T1190", severity="high",
        )
        assert f.finding_id == "f1"
        assert f.is_validated is False
        assert f.is_false_positive is False
        assert f.max_confidence == 0.0

    def test_to_dict(self):
        from nova_arsenal.validation.engine import Finding
        f = Finding(
            finding_id="f1", title="Test", description="Test",
            target="10.0.0.1", technique_id="T1190", severity="high",
        )
        d = f.to_dict()
        assert d["finding_id"] == "f1"
        assert "validation_results" in d


class TestDeterministicValidationEngine:
    def test_import(self):
        from nova_arsenal.validation.engine import DeterministicValidationEngine
        e = DeterministicValidationEngine()
        assert e is not None

    def test_validate_finding(self):
        from nova_arsenal.validation.engine import (
            DeterministicValidationEngine, Finding, ValidationMethod,
        )
        e = DeterministicValidationEngine()
        f = Finding(
            finding_id="f1", title="Test", description="Vulnerability found",
            target="10.0.0.1", technique_id="T1190", severity="high",
            raw_data={"version": "1.0", "vulnerable_versions": ["1.0"]},
        )
        result = _run(e.validate_finding(f))
        assert result.validated is True
        assert result.confidence > 0

    def test_cross_validate(self):
        from nova_arsenal.validation.engine import (
            DeterministicValidationEngine, Finding, ValidationMethod,
        )
        e = DeterministicValidationEngine()
        f = Finding(
            finding_id="f1", title="Test", description="Vuln",
            target="10.0.0.1", technique_id="T1190", severity="high",
            raw_data={"vulnerable": True},
        )
        result = _run(e.cross_validate(f, [ValidationMethod.VULN_EXISTS]))
        assert result.validated is True

    def test_get_validated_findings(self):
        from nova_arsenal.validation.engine import (
            DeterministicValidationEngine, Finding,
        )
        e = DeterministicValidationEngine()
        f = Finding(
            finding_id="f1", title="Test", description="Vuln",
            target="10.0.0.1", technique_id="T1190", severity="high",
            raw_data={"vulnerable": True},
        )
        _run(e.validate_finding(f))
        validated = e.get_validated_findings()
        assert len(validated) >= 1

    def test_generate_report(self):
        from nova_arsenal.validation.engine import DeterministicValidationEngine
        e = DeterministicValidationEngine()
        report = e.generate_report()
        assert "total_findings" in report

    def test_export_compliance_report(self):
        from nova_arsenal.validation.engine import DeterministicValidationEngine
        e = DeterministicValidationEngine()
        report = e.export_compliance_report("SOC2")
        assert report.framework == "SOC 2 Type II"


# ===== Safety Controller Tests =====

class TestStealthMode:
    def test_import(self):
        from nova_arsenal.safety.controller import StealthMode
        assert StealthMode.LOUD.value == "loud"


class TestSafetyController:
    def test_import(self):
        from nova_arsenal.safety.controller import SafetyController
        c = SafetyController()
        assert c is not None

    def test_check_operation(self):
        from nova_arsenal.safety.controller import SafetyController, OperationRequest
        c = SafetyController()
        req = OperationRequest(
            operation_id="op1", operation_type="exploit",
            target="10.0.0.1", risk_level=3, reversible=True,
        )
        ok, _ = _run(c.check_operation(req))
        assert ok is True

    def test_blocked_target(self):
        from nova_arsenal.safety.controller import SafetyController, SafetyRule, OperationRequest
        rule = SafetyRule(rule_id="test", description="Test", blocked_targets={"192.168.1.1"})
        c = SafetyController(rule=rule)
        req = OperationRequest(
            operation_id="op1", operation_type="exploit",
            target="192.168.1.1", risk_level=3,
        )
        ok, reason = _run(c.check_operation(req))
        assert ok is False
        assert "blocked" in reason.lower()

    def test_emergency_stop(self):
        from nova_arsenal.safety.controller import SafetyController
        c = SafetyController()
        stop_id = _run(c.emergency_stop())
        assert c.is_emergency_stopped is True
        assert stop_id is not None

    def test_resume(self):
        from nova_arsenal.safety.controller import SafetyController
        c = SafetyController()
        _run(c.emergency_stop())
        _run(c.resume())
        assert c.is_emergency_stopped is False

    def test_audit_log(self):
        from nova_arsenal.safety.controller import SafetyController
        c = SafetyController()
        _run(c.emergency_stop())
        log = c.get_audit_log()
        assert len(log) >= 1

    def test_request_operation(self):
        from nova_arsenal.safety.controller import SafetyController
        c = SafetyController()
        req = _run(c.request_operation("exploit", "10.0.0.1", risk_level=3))
        assert req.operation_id is not None
