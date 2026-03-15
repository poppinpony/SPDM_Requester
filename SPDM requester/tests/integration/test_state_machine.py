"""
tests/integration/test_state_machine.py

State Machine 驗證測試：
故意送錯誤順序，驗證碟機是否回正確的 0x7F ERROR。

使用 MockTransport 可在無硬體時執行。
"""

import pytest
from spdm_tool.requester import SpdmRequester
from spdm_tool.transport.mock import MockTransport
from spdm_tool.messages.error import ErrorResponse, ErrorCode
from spdm_tool.messages.version import VersionResponse, VersionEntry
from spdm_tool.messages.capabilities import CapabilitiesResponse
from spdm_tool.messages.algorithms import AlgorithmsResponse
from spdm_tool.messages.certificate import GetCertificateRequest


def make_error(code: int) -> bytes:
    return ErrorResponse(version=0x13, error_code=code).encode()


def make_version_resp() -> bytes:
    return VersionResponse(entries=[VersionEntry(1, 3)]).encode()


def make_caps_resp() -> bytes:
    return CapabilitiesResponse(version=0x13, flags=0x00).encode()


def make_algos_resp() -> bytes:
    return AlgorithmsResponse(version=0x13).encode()


class TestStateMachineErrors:

    def test_get_certificate_before_vca_returns_unexpected_request(self):
        """
        狀況：跳過 VCA，直接送 GET_CERTIFICATE
        預期：Responder 回 ERROR(UnexpectedRequest, 0x04)
        """
        mock = MockTransport()
        mock.queue_response(make_error(ErrorCode.UNEXPECTED_REQUEST))

        req = SpdmRequester(mock)
        resp = req.send(GetCertificateRequest())

        assert isinstance(resp, ErrorResponse)
        assert resp.error_code == ErrorCode.UNEXPECTED_REQUEST

    def test_version_mismatch(self):
        """
        狀況：送 GET_VERSION，碟機回 VersionMismatch
        預期：解析為 ErrorResponse(VersionMismatch)
        """
        mock = MockTransport()
        mock.queue_response(make_error(ErrorCode.VERSION_MISMATCH))

        req = SpdmRequester(mock)
        resp = req.do_get_version()

        assert isinstance(resp, ErrorResponse)
        assert resp.is_version_mismatch()

    def test_vca_then_certificate_succeeds_with_mock(self):
        """
        模擬正常流程：VCA 完成後取憑證應成功（使用 mock）
        """
        from spdm_tool.messages.certificate import CertificateResponse

        mock = MockTransport()
        # VCA 三個 response
        mock.queue_response(make_version_resp())
        mock.queue_response(make_caps_resp())
        mock.queue_response(make_algos_resp())
        # GET_CERTIFICATE response（最後一塊）
        cert_resp = CertificateResponse(
            slot_id=0,
            portion_length=4,
            remainder_length=0,
            cert_chain_data=b'\xAB\xCD\xEF\x00',
        )
        mock.queue_response(cert_resp.encode())

        req = SpdmRequester(mock)
        req.do_vca()
        cert = req.do_get_certificate(slot=0)

        assert isinstance(cert, bytes)
        assert cert == b'\xAB\xCD\xEF\x00'

    def test_send_raw_and_parse_error(self):
        """
        用 send_raw 送出任意格式，解析回來的 ERROR
        """
        mock = MockTransport()
        mock.queue_response(make_error(ErrorCode.INVALID_REQUEST))

        req = SpdmRequester(mock)

        # 故意送一個只有 header 的 GET_CERTIFICATE（缺少 Offset/Length 欄位）
        incomplete_msg = bytes([0x13, 0x82, 0x00, 0x00])
        raw_resp = req.send_raw(incomplete_msg)

        from spdm_tool.messages.base import SpdmMessage
        parsed = SpdmMessage.from_bytes(raw_resp)

        assert isinstance(parsed, ErrorResponse)
        assert parsed.error_code == ErrorCode.INVALID_REQUEST
