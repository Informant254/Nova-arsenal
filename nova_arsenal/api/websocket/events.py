"""
Nova-Arsenal WebSocket Events

WebSocket handlers for real-time agent updates.
"""

import json
import logging
from typing import Dict, Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

router = APIRouter()


class ConnectionManager:
    """Manages WebSocket connections."""

    def __init__(self):
        self.active_connections: Dict[int, Set[WebSocket]] = {}
        self.user_connections: Dict[int, WebSocket] = {}

    async def connect(self, websocket: WebSocket, agent_id: int, user_id: int):
        """Accept and store a new WebSocket connection."""
        await websocket.accept()
        
        if agent_id not in self.active_connections:
            self.active_connections[agent_id] = set()
        self.active_connections[agent_id].add(websocket)
        self.user_connections[user_id] = websocket
        
        logger.info(f"WebSocket connected: agent_id={agent_id}, user_id={user_id}")

    def disconnect(self, websocket: WebSocket, agent_id: int, user_id: int):
        """Remove a WebSocket connection."""
        if agent_id in self.active_connections:
            self.active_connections[agent_id].discard(websocket)
            if not self.active_connections[agent_id]:
                del self.active_connections[agent_id]
        
        if user_id in self.user_connections:
            del self.user_connections[user_id]
        
        logger.info(f"WebSocket disconnected: agent_id={agent_id}, user_id={user_id}")

    async def send_to_agent(self, agent_id: int, message: dict):
        """Send a message to all connections for an agent."""
        if agent_id in self.active_connections:
            dead_connections = set()
            for connection in self.active_connections[agent_id]:
                try:
                    await connection.send_json(message)
                except Exception:
                    dead_connections.add(connection)
            
            # Clean up dead connections
            for conn in dead_connections:
                self.active_connections[agent_id].discard(conn)

    async def send_to_user(self, user_id: int, message: dict):
        """Send a message to a specific user."""
        if user_id in self.user_connections:
            try:
                await self.user_connections[user_id].send_json(message)
            except Exception:
                del self.user_connections[user_id]

    async def broadcast(self, message: dict):
        """Broadcast a message to all connected clients."""
        dead_connections = []
        for agent_id, connections in self.active_connections.items():
            for connection in connections:
                try:
                    await connection.send_json(message)
                except Exception:
                    dead_connections.append((agent_id, connection))
        
        # Clean up dead connections
        for agent_id, conn in dead_connections:
            self.active_connections[agent_id].discard(conn)


# Global connection manager
manager = ConnectionManager()


@router.websocket("/ws/agent/{agent_id}")
async def agent_websocket(websocket: WebSocket, agent_id: int):
    """
    WebSocket endpoint for real-time agent updates.
    
    Events:
        - agent_started: Agent began execution
        - agent_completed: Agent finished
        - agent_error: Agent encountered error
        - tool_called: Tool invocation
        - tool_result: Tool output received
        - finding_discovered: New finding identified
        - progress_update: Progress percentage
        - log_message: Agent log output
    """
    # Get user ID from query params or auth
    user_id = int(websocket.query_params.get("user_id", 0))
    
    await manager.connect(websocket, agent_id, user_id)
    
    try:
        while True:
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                event_type = message.get("type", "")
                
                # Handle client messages
                if event_type == "ping":
                    await websocket.send_json({"type": "pong"})
                elif event_type == "subscribe":
                    # Client subscribing to specific events
                    pass
                    
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON received: {data[:100]}")
                
    except WebSocketDisconnect:
        manager.disconnect(websocket, agent_id, user_id)


async def emit_agent_event(agent_id: int, event_type: str, data: dict):
    """Emit an agent event to all subscribers."""
    await manager.send_to_agent(agent_id, {
        "type": event_type,
        "agent_id": agent_id,
        "data": data,
    })
