from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import Dict, List, Any
import json
import asyncio

router = APIRouter()

class ConnectionManager:
    def __init__(self):
        # Map scan_id -> list of connected WebSockets
        self.active_connections: Dict[int, List[WebSocket]] = {}
        self.global_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket, scan_id: int = 0):
        await websocket.accept()
        if scan_id == 0:
            self.global_connections.append(websocket)
        else:
            if scan_id not in self.active_connections:
                self.active_connections[scan_id] = []
            self.active_connections[scan_id].append(websocket)

    def disconnect(self, websocket: WebSocket, scan_id: int = 0):
        if scan_id == 0:
            if websocket in self.global_connections:
                self.global_connections.remove(websocket)
        else:
            if scan_id in self.active_connections and websocket in self.active_connections[scan_id]:
                self.active_connections[scan_id].remove(websocket)

    async def broadcast_to_scan(self, scan_id: int, message: Dict[str, Any]):
        msg_str = json.dumps(message)
        # Send to scan-specific listeners
        if scan_id in self.active_connections:
            for conn in list(self.active_connections[scan_id]):
                try:
                    await conn.send_text(msg_str)
                except Exception:
                    pass
        # Also broadcast to global listeners
        for conn in list(self.global_connections):
            try:
                await conn.send_text(msg_str)
            except Exception:
                pass

manager = ConnectionManager()

async def broadcast_scan_event(scan_id: int, event: Dict[str, Any]):
    await manager.broadcast_to_scan(scan_id, event)

@router.websocket("/ws/scan-live")
async def websocket_endpoint_global(websocket: WebSocket):
    await manager.connect(websocket, 0)
    try:
        while True:
            # Keep-alive loop
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, 0)

@router.websocket("/ws/scans/{scan_id}")
async def websocket_endpoint_scan(websocket: WebSocket, scan_id: int):
    await manager.connect(websocket, scan_id)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, scan_id)
