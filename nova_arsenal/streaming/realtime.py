"""
Real-time Finding Streaming — XBOW-inspired live updates.

Streams findings, agent reasoning traces, and status updates
to connected clients via WebSocket or SSE.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable

logger = logging.getLogger(__name__)


class StreamEventType(Enum):
    """Types of events that can be streamed."""
    FINDING_NEW = "finding_new"
    FINDING_UPDATED = "finding_updated"
    FINDING_VALIDATED = "finding_validated"
    FINDING_FALSE_POSITIVE = "finding_false_positive"
    AGENT_STARTED = "agent_started"
    AGENT_COMPLETED = "agent_completed"
    AGENT_FAILED = "agent_failed"
    AGENT_REASONING = "agent_reasoning"
    CHAIN_STARTED = "chain_started"
    CHAIN_COMPLETED = "chain_completed"
    CHAIN_STEP = "chain_step"
    STATUS_UPDATE = "status_update"
    PROGRESS = "progress"
    ERROR = "error"
    HEARTBEAT = "heartbeat"


@dataclass
class StreamEvent:
    """A single event in the real-time stream."""
    event_id: str
    event_type: StreamEventType
    timestamp: datetime
    source: str
    data: dict
    severity: str = "info"
    metadata: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps({
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "data": self.data,
            "severity": self.severity,
            "metadata": self.metadata,
        }, default=str)

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "data": self.data,
            "severity": self.severity,
            "metadata": self.metadata,
        }


@dataclass
class StreamSubscriber:
    """A client subscribed to the event stream."""
    subscriber_id: str
    name: str
    filters: list[StreamEventType] = field(default_factory=list)
    connected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_event_id: str = ""
    event_count: int = 0
    callback: Callable | None = None


@dataclass
class AgentReasoningTrace:
    """A reasoning trace from an agent."""
    trace_id: str
    agent_id: str
    agent_type: str
    step: int
    thought: str
    action: str | None = None
    observation: str | None = None
    confidence: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "trace_id": self.trace_id,
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "step": self.step,
            "thought": self.thought,
            "action": self.action,
            "observation": self.observation,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
        }


class RealTimeStreamer:
    """
    XBOW-inspired real-time finding streamer.

    Broadcasts findings, agent reasoning, and status updates
    to all connected subscribers.
    """

    def __init__(self, max_history: int = 1000, heartbeat_interval: float = 30.0):
        self.max_history = max_history
        self.heartbeat_interval = heartbeat_interval
        self._subscribers: dict[str, StreamSubscriber] = {}
        self._event_history: list[StreamEvent] = []
        self._reasoning_traces: dict[str, list[AgentReasoningTrace]] = {}
        self._running = False
        self._heartbeat_task: asyncio.Task | None = None
        self._lock = asyncio.Lock()

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    @property
    def event_count(self) -> int:
        return len(self._event_history)

    async def start(self) -> None:
        """Start the streamer and heartbeat."""
        self._running = True
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        logger.info("Real-time streamer started")

    async def stop(self) -> None:
        """Stop the streamer."""
        self._running = False
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
        logger.info("Real-time streamer stopped")

    async def subscribe(
        self,
        name: str,
        filters: list[StreamEventType] | None = None,
        callback: Callable | None = None,
    ) -> str:
        """Subscribe to the event stream. Returns subscriber ID."""
        subscriber_id = str(uuid.uuid4())
        subscriber = StreamSubscriber(
            subscriber_id=subscriber_id,
            name=name,
            filters=filters or [],
            callback=callback,
        )
        async with self._lock:
            self._subscribers[subscriber_id] = subscriber
        logger.info(f"Subscriber {name} connected ({subscriber_id})")
        return subscriber_id

    async def unsubscribe(self, subscriber_id: str) -> None:
        """Unsubscribe from the event stream."""
        async with self._lock:
            self._subscribers.pop(subscriber_id, None)
        logger.info(f"Subscriber {subscriber_id} disconnected")

    async def emit(
        self,
        event_type: StreamEventType,
        source: str,
        data: dict,
        severity: str = "info",
        metadata: dict | None = None,
    ) -> StreamEvent:
        """Emit an event to all subscribers."""
        event = StreamEvent(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            timestamp=datetime.now(timezone.utc),
            source=source,
            data=data,
            severity=severity,
            metadata=metadata or {},
        )

        async with self._lock:
            self._event_history.append(event)
            if len(self._event_history) > self.max_history:
                self._event_history = self._event_history[-self.max_history:]

        await self._broadcast(event)
        return event

    async def emit_finding(self, finding: dict, source: str = "scanner") -> StreamEvent:
        """Emit a new finding event."""
        return await self.emit(
            StreamEventType.FINDING_NEW,
            source,
            finding,
            severity=finding.get("severity", "info"),
        )

    async def emit_validation(self, finding_id: str, validated: bool, evidence: str) -> StreamEvent:
        """Emit a validation result event."""
        event_type = StreamEventType.FINDING_VALIDATED if validated else StreamEventType.FINDING_FALSE_POSITIVE
        return await self.emit(
            event_type,
            "validator",
            {"finding_id": finding_id, "validated": validated, "evidence": evidence},
            severity="high" if validated else "info",
        )

    async def emit_agent_reasoning(
        self, agent_id: str, agent_type: str, step: int,
        thought: str, action: str | None = None, observation: str | None = None,
        confidence: float = 0.0,
    ) -> StreamEvent:
        """Emit an agent reasoning trace."""
        trace = AgentReasoningTrace(
            trace_id=str(uuid.uuid4()),
            agent_id=agent_id,
            agent_type=agent_type,
            step=step,
            thought=thought,
            action=action,
            observation=observation,
            confidence=confidence,
        )

        if agent_id not in self._reasoning_traces:
            self._reasoning_traces[agent_id] = []
        self._reasoning_traces[agent_id].append(trace)

        return await self.emit(
            StreamEventType.AGENT_REASONING,
            agent_id,
            trace.to_dict(),
            severity="info",
        )

    async def emit_chain_step(self, chain_id: str, step: int, description: str) -> StreamEvent:
        """Emit an attack chain step event."""
        return await self.emit(
            StreamEventType.CHAIN_STEP,
            "chain",
            {"chain_id": chain_id, "step": step, "description": description},
        )

    async def emit_progress(self, task: str, current: int, total: int) -> StreamEvent:
        """Emit a progress update."""
        return await self.emit(
            StreamEventType.PROGRESS,
            "coordinator",
            {"task": task, "current": current, "total": total, "percent": (current / total * 100) if total > 0 else 0},
        )

    async def emit_status(self, status: str, details: dict | None = None) -> StreamEvent:
        """Emit a status update."""
        return await self.emit(
            StreamEventType.STATUS_UPDATE,
            "system",
            {"status": status, "details": details or {}},
        )

    def get_event_history(
        self,
        event_type: StreamEventType | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Return event history, optionally filtered by type."""
        events = self._event_history
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return [e.to_dict() for e in events[-limit:]]

    def get_reasoning_trace(self, agent_id: str) -> list[dict]:
        """Return the reasoning trace for a specific agent."""
        traces = self._reasoning_traces.get(agent_id, [])
        return [t.to_dict() for t in traces]

    def get_all_traces(self) -> dict[str, list[dict]]:
        """Return all reasoning traces grouped by agent."""
        return {
            aid: [t.to_dict() for t in traces]
            for aid, traces in self._reasoning_traces.items()
        }

    def get_subscribers(self) -> list[dict]:
        """Return all active subscribers."""
        return [
            {
                "subscriber_id": s.subscriber_id,
                "name": s.name,
                "filters": [f.value for f in s.filters],
                "connected_at": s.connected_at.isoformat(),
                "event_count": s.event_count,
            }
            for s in self._subscribers.values()
        ]

    async def _broadcast(self, event: StreamEvent) -> None:
        """Broadcast an event to all matching subscribers."""
        event_json = event.to_json()
        disconnected: list[str] = []

        for sid, subscriber in self._subscribers.items():
            if subscriber.filters and event.event_type not in subscriber.filters:
                continue

            subscriber.last_event_id = event.event_id
            subscriber.event_count += 1

            if subscriber.callback:
                try:
                    await subscriber.callback(event)
                except Exception as exc:
                    logger.warning(f"Callback error for {subscriber.name}: {exc}")
                    disconnected.append(sid)

        for sid in disconnected:
            await self.unsubscribe(sid)

    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats."""
        while self._running:
            try:
                await asyncio.sleep(self.heartbeat_interval)
                if self._subscribers:
                    await self.emit(
                        StreamEventType.HEARTBEAT,
                        "system",
                        {"subscriber_count": self.subscriber_count},
                    )
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning(f"Heartbeat error: {exc}")

    def get_stats(self) -> dict:
        """Return streaming statistics."""
        type_counts = {}
        for e in self._event_history:
            t = e.event_type.value
            type_counts[t] = type_counts.get(t, 0) + 1

        return {
            "total_events": self.event_count,
            "active_subscribers": self.subscriber_count,
            "total_traces": sum(len(t) for t in self._reasoning_traces.values()),
            "event_type_breakdown": type_counts,
            "running": self._running,
        }
