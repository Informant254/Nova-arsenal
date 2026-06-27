"""
Ransomware Emulation — Pentera-inspired safe ransomware simulation.

Simulates ransomware behavior (encryption, credential harvesting, shadow copy deletion)
without actual destruction. All operations are reversible and controlled.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

logger = logging.getLogger(__name__)


class RansomwarePhase(Enum):
    """Phases of a ransomware attack chain."""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_COLLECTION = "data_collection"
    SHADOW_COPY_DELETION = "shadow_copy_deletion"
    BACKUP_DISCOVERY = "backup_discovery"
    ENCRYPTION = "encryption"
    RANSOM_NOTE = "ransom_note"
    EXFILTRATION = "exfiltration"
    CLEANUP = "cleanup"


class EmulationMode(Enum):
    """How strictly the emulation mimics real ransomware."""
    SAFE = "safe"
    MODERATE = "moderate"
    AGGRESSIVE = "aggressive"


@dataclass
class RansomwareAction:
    """A single action in the ransomware emulation."""
    action_id: str
    phase: RansomwarePhase
    description: str
    reversible: bool = True
    risk_level: int = 5
    executed: bool = False
    success: bool = False
    duration_ms: float = 0.0
    evidence: str = ""
    artifacts: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "action_id": self.action_id,
            "phase": self.phase.value,
            "description": self.description,
            "reversible": self.reversible,
            "risk_level": self.risk_level,
            "executed": self.executed,
            "success": self.success,
            "duration_ms": self.duration_ms,
            "evidence": self.evidence[:500],
            "artifacts": self.artifacts,
        }


@dataclass
class RansomwareEmulationResult:
    """Result of a complete ransomware emulation."""
    emulation_id: str
    target: str
    mode: EmulationMode
    actions: list[RansomwareAction]
    phases_completed: list[str]
    total_duration_ms: float
    files_encrypted_sim: int
    shadow_copies_deleted: int
    credentials_harvested: int
    backups_discovered: int
    ransom_note_delivered: bool
    status: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "emulation_id": self.emulation_id,
            "target": self.target,
            "mode": self.mode.value,
            "actions": [a.to_dict() for a in self.actions],
            "phases_completed": self.phases_completed,
            "total_duration_ms": self.total_duration_ms,
            "files_encrypted_sim": self.files_encrypted_sim,
            "shadow_copies_deleted": self.shadow_copies_deleted,
            "credentials_harvested": self.credentials_harvested,
            "backups_discovered": self.backups_discovered,
            "ransom_note_delivered": self.ransom_note_delivered,
            "status": self.status,
            "timestamp": self.timestamp.isoformat(),
        }


class RansomwareEmulator:
    """
    Pentera-inspired safe ransomware emulator.

    Simulates the full ransomware kill chain without actual destruction.
    All file operations are simulated (hash-based), shadow copy deletions
    are logged but not executed, and ransom notes are written to a safe directory.
    """

    def __init__(self, mode: EmulationMode = EmulationMode.SAFE, output_dir: str = "/tmp/nova_ransomware_emu"):
        self.mode = mode
        self.output_dir = output_dir
        self._emulations: list[RansomwareEmulationResult] = []
        os.makedirs(output_dir, exist_ok=True)

    async def emulate(
        self,
        target: str,
        phases: list[RansomwarePhase] | None = None,
        context: dict | None = None,
    ) -> RansomwareEmulationResult:
        """Run a full ransomware emulation against a target."""
        start = time.monotonic()
        context = context or {}
        phases = phases or list(RansomwarePhase)
        actions: list[RansomwareAction] = []
        completed: list[str] = []
        files_encrypted = 0
        shadow_deleted = 0
        creds_harvested = 0
        backups_found = 0
        note_delivered = False

        for phase in phases:
            phase_actions = self._get_phase_actions(phase, context)
            for action in phase_actions:
                action.executed = True
                action.start_time = time.monotonic()
                success, evidence, artifacts = await self._execute_action(action, target, context)
                action.success = success
                action.evidence = evidence
                action.artifacts = artifacts
                action.duration_ms = (time.monotonic() - getattr(action, 'start_time', time.monotonic())) * 1000
                actions.append(action)

                if success:
                    if phase == RansomwarePhase.ENCRYPTION:
                        files_encrypted = artifacts[0].get("count", 0) if artifacts else 0
                    elif phase == RansomwarePhase.SHADOW_COPY_DELETION:
                        shadow_deleted = artifacts[0].get("count", 0) if artifacts else 0
                    elif phase == RansomwarePhase.CREDENTIAL_HARVESTING:
                        creds_harvested = artifacts[0].get("count", 0) if artifacts else 0
                    elif phase == RansomwarePhase.BACKUP_DISCOVERY:
                        backups_found = artifacts[0].get("count", 0) if artifacts else 0
                    elif phase == RansomwarePhase.RANSOM_NOTE:
                        note_delivered = True

            if any(a.success for a in phase_actions):
                completed.append(phase.value)

        duration = (time.monotonic() - start) * 1000
        result = RansomwareEmulationResult(
            emulation_id=str(uuid.uuid4()),
            target=target,
            mode=self.mode,
            actions=actions,
            phases_completed=completed,
            total_duration_ms=duration,
            files_encrypted_sim=files_encrypted,
            shadow_copies_deleted=shadow_deleted,
            credentials_harvested=creds_harvested,
            backups_discovered=backups_found,
            ransom_note_delivered=note_delivered,
            status="completed",
        )
        self._emulations.append(result)
        return result

    def _get_phase_actions(self, phase: RansomwarePhase, context: dict) -> list[RansomwareAction]:
        """Get actions for a given phase."""
        phase_map = {
            RansomwarePhase.RECONNAISSANCE: [
                RansomwareAction(str(uuid.uuid4()), phase, "Network enumeration", True, 3),
                RansomwareAction(str(uuid.uuid4()), phase, "Service discovery", True, 2),
            ],
            RansomwarePhase.INITIAL_ACCESS: [
                RansomwareAction(str(uuid.uuid4()), phase, "Exploit vulnerable service", True, 8),
                RansomwareAction(str(uuid.uuid4()), phase, "Brute force RDP", True, 7),
            ],
            RansomwarePhase.CREDENTIAL_HARVESTING: [
                RansomwareAction(str(uuid.uuid4()), phase, "SAM dump simulation", True, 6),
                RansomwareAction(str(uuid.uuid4()), phase, "LSASS memory read", True, 7),
                RansomwareAction(str(uuid.uuid4()), phase, "Kerberoasting", True, 5),
            ],
            RansomwarePhase.PRIVILEGE_ESCALATION: [
                RansomwareAction(str(uuid.uuid4()), phase, "Token impersonation", True, 6),
                RansomwareAction(str(uuid.uuid4()), phase, "Service exploitation", True, 8),
            ],
            RansomwarePhase.LATERAL_MOVEMENT: [
                RansomwareAction(str(uuid.uuid4()), phase, "PsExec to target hosts", True, 7),
                RansomwareAction(str(uuid.uuid4()), phase, "WMI execution", True, 6),
            ],
            RansomwarePhase.DATA_COLLECTION: [
                RansomwareAction(str(uuid.uuid4()), phase, "Enumerate sensitive files", True, 4),
                RansomwareAction(str(uuid.uuid4()), phase, "Archive collected data", True, 5),
            ],
            RansomwarePhase.SHADOW_COPY_DELETION: [
                RansomwareAction(str(uuid.uuid4()), phase, "Delete shadow copies (simulated)", True, 9),
                RansomwareAction(str(uuid.uuid4()), phase, "Disable recovery (simulated)", True, 8),
            ],
            RansomwarePhase.BACKUP_DISCOVERY: [
                RansomwareAction(str(uuid.uuid4()), phase, "Discover backup solutions", True, 4),
                RansomwareAction(str(uuid.uuid4()), phase, "Enumerate backup repositories", True, 5),
            ],
            RansomwarePhase.ENCRYPTION: [
                RansomwareAction(str(uuid.uuid4()), phase, "Simulate file encryption", True, 10),
                RansomwareAction(str(uuid.uuid4()), phase, "Generate encryption hashes", True, 8),
            ],
            RansomwarePhase.RANSOM_NOTE: [
                RansomwareAction(str(uuid.uuid4()), phase, "Deliver ransom note", True, 9),
            ],
            RansomwarePhase.EXFILTRATION: [
                RansomwareAction(str(uuid.uuid4()), phase, "Simulate data exfiltration", True, 8),
            ],
            RansomwarePhase.CLEANUP: [
                RansomwareAction(str(uuid.uuid4()), phase, "Remove artifacts (simulated)", True, 7),
            ],
        }
        return phase_map.get(phase, [])

    async def _execute_action(
        self, action: RansomwareAction, target: str, context: dict
    ) -> tuple[bool, str, list[dict]]:
        """Execute a single action and return (success, evidence, artifacts)."""
        phase = action.phase

        if phase == RansomwarePhase.ENCRYPTION:
            return await self._simulate_encryption(target, context)
        elif phase == RansomwarePhase.SHADOW_COPY_DELETION:
            return await self._simulate_shadow_deletion(target, context)
        elif phase == RansomwarePhase.CREDENTIAL_HARVESTING:
            return await self._simulate_credential_harvest(target, context)
        elif phase == RansomwarePhase.BACKUP_DISCOVERY:
            return await self._simulate_backup_discovery(target, context)
        elif phase == RansomwarePhase.RANSOM_NOTE:
            return await self._deliver_ransom_note(target, context)
        elif phase == RansomwarePhase.DATA_COLLECTION:
            return await self._simulate_data_collection(target, context)
        elif phase == RansomwarePhase.EXFILTRATION:
            return await self._simulate_exfiltration(target, context)
        else:
            return True, f"{action.description} completed (simulated)", []

    async def _simulate_encryption(self, target: str, context: dict) -> tuple[bool, str, list[dict]]:
        """Simulate encryption by computing hashes without modifying files."""
        extensions = [".doc", ".pdf", ".xls", ".jpg", ".png", ".sql", ".bak", ".zip"]
        file_count = 0
        for ext in extensions:
            for i in range(10):
                fake_path = f"/simulated/{target}/file_{i}{ext}"
                file_hash = hashlib.sha256(fake_path.encode()).hexdigest()
                file_count += 1

        evidence = f"Simulated encryption of {file_count} files (hash-only, no modification)"
        artifacts = [{"count": file_count, "extensions": extensions, "mode": "hash_only"}]
        return True, evidence, artifacts

    async def _simulate_shadow_deletion(self, target: str, context: dict) -> tuple[bool, str, list[dict]]:
        """Simulate shadow copy deletion."""
        shadow_copies = [
            "\\Device\\HarddiskVolumeShadowCopy1",
            "\\Device\\HarddiskVolumeShadowCopy2",
            "\\Device\\HarddiskVolumeShadowCopy3",
        ]
        evidence = f"Identified {len(shadow_copies)} shadow copies (deletion simulated, not executed)"
        artifacts = [{"count": len(shadow_copies), "copies": shadow_copies}]
        return True, evidence, artifacts

    async def _simulate_credential_harvest(self, target: str, context: dict) -> tuple[bool, str, list[dict]]:
        """Simulate credential harvesting."""
        creds_found = [
            {"type": "ntlm", "user": "Administrator"},
            {"type": "password", "user": "svc_backup"},
            {"type": "kerberos", "user": "krbtgt"},
        ]
        evidence = f"Harvested {len(creds_found)} credential types (simulated)"
        artifacts = [{"count": len(creds_found), "types": [c["type"] for c in creds_found]}]
        return True, evidence, artifacts

    async def _simulate_backup_discovery(self, target: str, context: dict) -> tuple[bool, str, list[dict]]:
        """Simulate backup solution discovery."""
        backups = [
            {"solution": "Veeam", "path": "\\\\backup-server\\Veeam"},
            {"solution": "ShadowProtect", "path": "\\\\nas\\ShadowProtect"},
            {"solution": "Windows Backup", "path": "C:\\Backup"},
        ]
        evidence = f"Discovered {len(backups)} backup solutions (simulated)"
        artifacts = [{"count": len(backups), "solutions": backups}]
        return True, evidence, artifacts

    async def _deliver_ransom_note(self, target: str, context: dict) -> tuple[bool, str, list[dict]]:
        """Deliver a simulated ransom note to output directory."""
        note = {
            "emulation": True,
            "warning": "THIS IS A SIMULATED RANSOM NOTE - NO ACTUAL ENCRYPTION OCCURRED",
            "message": "Your files have been encrypted in this simulation.",
            "bitcoin_address": "SIMULATED_ADDRESS_NOT_REAL",
            "instructions": "This is a security test. No payment is required.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        note_path = os.path.join(self.output_dir, f"ransom_note_{uuid.uuid4().hex[:8]}.json")
        try:
            with open(note_path, "w") as f:
                json.dump(note, f, indent=2)
        except Exception:
            note_path = "write_failed"
        evidence = f"Ransom note delivered to {note_path}"
        artifacts = [{"path": note_path, "type": "ransom_note"}]
        return True, evidence, artifacts

    async def _simulate_data_collection(self, target: str, context: dict) -> tuple[bool, str, list[dict]]:
        """Simulate data collection for exfiltration."""
        sensitive_patterns = [
            "*.sql", "*.bak", "*.key", "*.pem", "*.env",
            "*password*", "*secret*", "*credential*",
        ]
        evidence = f"Enumerated {len(sensitive_patterns)} sensitive file patterns (simulated)"
        artifacts = [{"count": len(sensitive_patterns), "patterns": sensitive_patterns}]
        return True, evidence, artifacts

    async def _simulate_exfiltration(self, target: str, context: dict) -> tuple[bool, str, list[dict]]:
        """Simulate data exfiltration."""
        evidence = "Simulated exfiltration of collected data to staging area"
        artifacts = [{"staging_path": "/simulated/staging", "size_mb": 0}]
        return True, evidence, artifacts

    def get_emulations(self) -> list[dict]:
        """Return all emulation results."""
        return [e.to_dict() for e in self._emulations]

    def get_latest(self) -> dict | None:
        """Return the most recent emulation result."""
        if self._emulations:
            return self._emulations[-1].to_dict()
        return None

    def get_stats(self) -> dict:
        """Return emulation statistics."""
        total_actions = sum(len(e.actions) for e in self._emulations)
        successful = sum(
            sum(1 for a in e.actions if a.success)
            for e in self._emulations
        )
        return {
            "total_emulations": len(self._emulations),
            "total_actions": total_actions,
            "successful_actions": successful,
            "total_files_encrypted_sim": sum(e.files_encrypted_sim for e in self._emulations),
            "total_shadow_deleted": sum(e.shadow_copies_deleted for e in self._emulations),
            "total_creds_harvested": sum(e.credentials_harvested for e in self._emulations),
            "total_backups_found": sum(e.backups_discovered for e in self._emulations),
        }
