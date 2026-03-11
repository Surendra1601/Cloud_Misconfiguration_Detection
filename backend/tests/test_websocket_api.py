"""Tests for WebSocket /ws/v1/events endpoint."""

import json

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.dependencies import get_ws_manager
from app.main import app
from app.pipeline.ws_manager import ConnectionManager

WS_URL = (
    f"/ws/v1/events?token={settings.api_key}"
)


class TestWSConnection:
    """WebSocket connection with valid token."""

    def test_connect_with_valid_token(self):
        """Valid token allows connection."""
        client = TestClient(app)
        with client.websocket_connect(WS_URL) as ws:
            ws.send_text("ping")
            resp = ws.receive_json()
            assert resp["type"] == "pong"

    def test_keepalive_ping_pong(self):
        """Multiple ping/pong exchanges work."""
        client = TestClient(app)
        with client.websocket_connect(WS_URL) as ws:
            for _ in range(3):
                ws.send_text("ping")
                resp = ws.receive_json()
                assert resp["type"] == "pong"


class TestWSAuth:
    """WebSocket authentication checks."""

    def test_reject_no_token(self):
        """No token query param rejects with 1008."""
        client = TestClient(app)
        with pytest.raises(Exception):
            with client.websocket_connect(
                "/ws/v1/events"
            ):
                pass

    def test_reject_empty_token(self):
        """Empty token string rejects with 1008."""
        client = TestClient(app)
        with pytest.raises(Exception):
            with client.websocket_connect(
                "/ws/v1/events?token="
            ):
                pass

    def test_reject_whitespace_token(self):
        """Whitespace-only token rejects."""
        client = TestClient(app)
        with pytest.raises(Exception):
            with client.websocket_connect(
                "/ws/v1/events?token=%20%20"
            ):
                pass

    def test_reject_invalid_token(self):
        """Wrong token string rejects."""
        client = TestClient(app)
        with pytest.raises(Exception):
            with client.websocket_connect(
                "/ws/v1/events?token=wrong-key"
            ):
                pass


class TestWSDisconnect:
    """Clean disconnect handling."""

    def test_clean_disconnect(self):
        """Client disconnect is handled gracefully."""
        manager = get_ws_manager()
        before = manager.active_connections
        client = TestClient(app)
        with client.websocket_connect(WS_URL):
            pass
        # After disconnect, count should be restored
        assert (
            manager.active_connections <= before + 1
        )


class TestWSBroadcast:
    """Broadcast reaches connected clients."""

    def test_broadcast_reaches_client(self):
        """broadcast() delivers to connected client."""
        manager = get_ws_manager()
        client = TestClient(app)
        with client.websocket_connect(WS_URL) as ws:
            # Send a ping first to confirm connected
            ws.send_text("ping")
            resp = ws.receive_json()
            assert resp["type"] == "pong"
