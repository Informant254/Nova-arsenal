"""Tests for MITRE mapper, credentials, ransomware, fix verification, incremental, streaming."""
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


# ===== MITRE Mapper Tests =====

class TestMITREMapper:
    def test_import(self):
        from nova_arsenal.mitre.mapper import MITREMapper
        m = MITREMapper()
        assert m is not None

    def test_add_behavior(self):
        from nova_arsenal.mitre.mapper import MITREMapper, ObservedBehavior
        m = MITREMapper()
        b = ObservedBehavior(behavior_id="b1", description="brute force attack")
        tid = m.add_behavior(b)
        assert tid == "T1110"

    def test_build_kill_chain(self):
        from nova_arsenal.mitre.mapper import MITREMapper, ObservedBehavior
        m = MITREMapper()
        m.add_behavior(ObservedBehavior(behavior_id="b1", description="brute force"))
        m.add_behavior(ObservedBehavior(behavior_id="b2", description="lateral movement"))
        kc = m.build_kill_chain()
        assert kc.mapped_techniques >= 2
        assert kc.coverage > 0

    def test_get_coverage_report(self):
        from nova_arsenal.mitre.mapper import MITREMapper, ObservedBehavior
        m = MITREMapper()
        m.add_behavior(ObservedBehavior(behavior_id="b1", description="exploit"))
        report = m.get_coverage_report()
        assert "coverage_percent" in report
        assert "uncovered_techniques" in report

    def test_get_technique(self):
        from nova_arsenal.mitre.mapper import MITREMapper
        m = MITREMapper()
        t = m.get_technique("T1190")
        assert t is not None
        assert t.name == "Exploit Public-Facing Application"


# ===== Credential Harvester Tests =====

class TestCredentialHarvester:
    def test_import(self):
        from nova_arsenal.credentials.harvester import CredentialHarvester
        h = CredentialHarvester()
        assert h is not None

    def test_harvest(self):
        from nova_arsenal.credentials.harvester import CredentialHarvester, HarvestMethod
        h = CredentialHarvester()
        creds = _run(h.harvest("10.0.0.1", methods=[HarvestMethod.SAM_DUMP]))
        assert len(creds) >= 1
        assert creds[0].credential_type.value == "ntlm_hash"

    def test_pilfer_data(self):
        from nova_arsenal.credentials.harvester import CredentialHarvester
        h = CredentialHarvester()
        result = _run(h.pilfer_data("10.0.0.1"))
        assert result.total_items >= 1
        assert result.status == "completed"

    def test_validate_credential(self):
        from nova_arsenal.credentials.harvester import (
            CredentialHarvester, HarvestedCredential, CredentialType, HarvestMethod,
        )
        h = CredentialHarvester()
        c = HarvestedCredential(
            credential_id="c1", username="admin", domain="CORP",
            credential_type=CredentialType.PASSWORD, value="Password123!",
            source="test", method=HarvestMethod.BRUTE_FORCE,
        )
        validated = _run(h.validate_credential(c, "10.0.0.1"))
        assert validated is True

    def test_analyze_with_llm(self):
        from nova_arsenal.credentials.harvester import (
            CredentialHarvester, HarvestedCredential, CredentialType, HarvestMethod,
        )
        h = CredentialHarvester()
        c = HarvestedCredential(
            credential_id="c1", username="admin", domain="",
            credential_type=CredentialType.PASSWORD, value="weak",
            source="test", method=HarvestMethod.BRUTE_FORCE,
        )
        analysis = _run(h.analyze_with_llm(c))
        assert "risk_level" in analysis

    def test_get_stats(self):
        from nova_arsenal.credentials.harvester import CredentialHarvester
        h = CredentialHarvester()
        _run(h.harvest("10.0.0.1"))
        stats = h.get_stats()
        assert stats["total_harvested"] >= 1


# ===== Ransomware Emulator Tests =====

class TestRansomwareEmulator:
    def test_import(self):
        from nova_arsenal.ransomware.emulator import RansomwareEmulator
        e = RansomwareEmulator()
        assert e is not None

    def test_emulate(self):
        from nova_arsenal.ransomware.emulator import RansomwareEmulator, RansomwarePhase
        e = RansomwareEmulator()
        result = _run(e.emulate("10.0.0.1", phases=[RansomwarePhase.ENCRYPTION]))
        assert result.files_encrypted_sim > 0
        assert result.status == "completed"

    def test_emulate_full_chain(self):
        from nova_arsenal.ransomware.emulator import RansomwareEmulator
        e = RansomwareEmulator()
        result = _run(e.emulate("10.0.0.1"))
        assert result.status == "completed"
        assert len(result.phases_completed) >= 1

    def test_get_stats(self):
        from nova_arsenal.ransomware.emulator import RansomwareEmulator
        e = RansomwareEmulator()
        _run(e.emulate("10.0.0.1"))
        stats = e.get_stats()
        assert stats["total_emulations"] >= 1


# ===== Fix Verifier Tests =====

class TestFixVerifier:
    def test_import(self):
        from nova_arsenal.fix_verification.verifier import FixVerifier
        v = FixVerifier()
        assert v is not None

    def test_register_and_verify(self):
        from nova_arsenal.fix_verification.verifier import (
            FixVerifier, OriginalFinding, VerificationStatus,
        )
        v = FixVerifier()
        f = OriginalFinding(
            finding_id="f1", title="Test", target="10.0.0.1",
            technique_id="T1190", original_severity="high",
            original_evidence="test", exploit_steps=[{"type": "check"}],
        )
        v.register_finding(f)
        result = _run(v.verify_fix("f1"))
        assert result.status == VerificationStatus.VERIFIED_FIXED

    def test_get_stats(self):
        from nova_arsenal.fix_verification.verifier import FixVerifier
        v = FixVerifier()
        stats = v.get_stats()
        assert "total_verifications" in stats


# ===== Incremental Tester Tests =====

class TestIncrementalTester:
    def test_import(self):
        from nova_arsenal.incremental.engine import IncrementalTester
        t = IncrementalTester()
        assert t is not None

    def test_detect_deltas(self):
        from nova_arsenal.incremental.engine import IncrementalTester, ChangeType
        t = IncrementalTester()
        baseline = {"file1.py": "content1", "file2.py": "content2"}
        target = {"file1.py": "modified", "file3.py": "new"}
        deltas = t.detect_deltas("v1", "v2", baseline, target)
        assert len(deltas) == 3

    def test_generate_test_plan(self):
        from nova_arsenal.incremental.engine import IncrementalTester
        t = IncrementalTester()
        baseline = {"file1.py": "content1"}
        target = {"file1.py": "modified"}
        deltas = t.detect_deltas("v1", "v2", baseline, target)
        plan = t.generate_test_plan("v1", "v2", deltas)
        assert plan.total_tests >= 1

    def test_get_stats(self):
        from nova_arsenal.incremental.engine import IncrementalTester
        t = IncrementalTester()
        stats = t.get_stats()
        assert "total_plans" in stats


# ===== Real-time Streamer Tests =====

class TestRealTimeStreamer:
    def test_import(self):
        from nova_arsenal.streaming.realtime import RealTimeStreamer
        s = RealTimeStreamer()
        assert s is not None

    def test_subscribe(self):
        from nova_arsenal.streaming.realtime import RealTimeStreamer
        s = RealTimeStreamer()
        sid = _run(s.subscribe("test"))
        assert sid is not None
        assert s.subscriber_count == 1

    def test_emit_event(self):
        from nova_arsenal.streaming.realtime import RealTimeStreamer, StreamEventType
        s = RealTimeStreamer()
        event = _run(s.emit(StreamEventType.STATUS_UPDATE, "test", {"status": "ok"}))
        assert event.event_id is not None
        assert s.event_count == 1

    def test_emit_finding(self):
        from nova_arsenal.streaming.realtime import RealTimeStreamer
        s = RealTimeStreamer()
        event = _run(s.emit_finding({"severity": "high", "title": "Test"}))
        assert event.event_id is not None

    def test_emit_agent_reasoning(self):
        from nova_arsenal.streaming.realtime import RealTimeStreamer
        s = RealTimeStreamer()
        event = _run(s.emit_agent_reasoning(
            "agent1", "scout", 1, "Thinking about approach",
        ))
        assert event.event_id is not None
        traces = s.get_reasoning_trace("agent1")
        assert len(traces) == 1

    def test_get_event_history(self):
        from nova_arsenal.streaming.realtime import RealTimeStreamer, StreamEventType
        s = RealTimeStreamer()
        _run(s.emit(StreamEventType.STATUS_UPDATE, "test", {}))
        history = s.get_event_history()
        assert len(history) == 1

    def test_get_stats(self):
        from nova_arsenal.streaming.realtime import RealTimeStreamer
        s = RealTimeStreamer()
        stats = s.get_stats()
        assert "total_events" in stats
