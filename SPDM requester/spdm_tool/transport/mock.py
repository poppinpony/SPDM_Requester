"""
transport/mock.py

MockTransport — 不接硬體時的測試用 Transport。

可以預先設定 response queue，讓測試在無硬體環境中執行。
也可以用來模擬碟機回傳特定錯誤（如 0x7F UnexpectedRequest）。

範例：
    from spdm_tool.transport.mock import MockTransport
    from spdm_tool.messages.error import ErrorResponse, ErrorCode

    mock = MockTransport()

    # 讓碟機故意回 UnexpectedRequest
    mock.queue_response(
        ErrorResponse(error_code=ErrorCode.UNEXPECTED_REQUEST).encode()
    )

    req = SpdmRequester(mock)
    resp = req.send(GetCertificateRequest())  # 沒走 VCA，看看回什麼
    print(resp)   # → ErrorResponse(UnexpectedRequest, ...)
"""

from __future__ import annotations

import logging
from collections import deque
from ..requester import Transport

logger = logging.getLogger(__name__)


class MockTransport(Transport):
    """
    測試用假 Transport。

    使用方式：
      1. 呼叫 queue_response() 預先設定要回的 bytes
      2. 若 queue 空了，送出任何訊息都回 b''（空回應）
      3. 所有送出的訊息記錄在 sent_messages[]
    """

    def __init__(self):
        self._queue: deque[bytes] = deque()
        self.sent_messages: list[bytes] = []

    def queue_response(self, data: bytes) -> "MockTransport":
        """加入一個預設回應（FIFO）"""
        self._queue.append(data)
        return self   # 支援 chaining

    def queue_responses(self, *responses: bytes) -> "MockTransport":
        for r in responses:
            self._queue.append(r)
        return self

    def send(self, data: bytes) -> None:
        logger.debug("MockTransport TX [%d bytes]: %s", len(data), data.hex())
        self.sent_messages.append(data)

    def receive(self, timeout_ms: int = 5000) -> bytes:
        if self._queue:
            resp = self._queue.popleft()
            logger.debug("MockTransport RX [%d bytes]: %s", len(resp), resp.hex())
            return resp
        logger.warning("MockTransport: response queue empty, returning empty bytes")
        return b""

    def close(self) -> None:
        pass

    def clear(self) -> None:
        self._queue.clear()
        self.sent_messages.clear()
