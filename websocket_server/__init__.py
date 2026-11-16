"""websocket-server — RFC 6455 WebSockets implemented from the frame up.

Public API::

    from websocket_server import WebSocketServer, echo_handler

    with WebSocketServer() as server:
        print(f"ws://127.0.0.1:{server.port}/")
"""

import logging

from .connection import (
    DEFAULT_MAX_MESSAGE,
    ConnectionClosed,
    Message,
    SocketReader,
    WebSocketConnection,
)
from .frame import (
    CONTROL_OPCODES,
    MAX_CONTROL_PAYLOAD,
    OPCODE_NAMES,
    OP_BINARY,
    OP_CLOSE,
    OP_CONT,
    OP_PING,
    OP_PONG,
    OP_TEXT,
    Frame,
    FrameError,
    FrameReader,
    apply_mask,
    encode_close_payload,
    encode_frame,
    parse_close_payload,
    parse_header,
)
from .handshake import (
    WEBSOCKET_GUID,
    HandshakeError,
    UpgradeRequest,
    build_rejection,
    build_response,
    compute_accept,
    parse_upgrade_request,
)
from .server import Handler, WebSocketServer, echo_handler

logging.getLogger("websocket_server").addHandler(logging.NullHandler())

__all__ = [
    "CONTROL_OPCODES",
    "ConnectionClosed",
    "DEFAULT_MAX_MESSAGE",
    "Frame",
    "FrameError",
    "FrameReader",
    "Handler",
    "HandshakeError",
    "MAX_CONTROL_PAYLOAD",
    "Message",
    "OPCODE_NAMES",
    "OP_BINARY",
    "OP_CLOSE",
    "OP_CONT",
    "OP_PING",
    "OP_PONG",
    "OP_TEXT",
    "SocketReader",
    "UpgradeRequest",
    "WEBSOCKET_GUID",
    "WebSocketConnection",
    "WebSocketServer",
    "apply_mask",
    "build_rejection",
    "build_response",
    "compute_accept",
    "echo_handler",
    "encode_close_payload",
    "encode_frame",
    "parse_close_payload",
    "parse_header",
    "parse_upgrade_request",
]

__version__ = "1.0.0"
