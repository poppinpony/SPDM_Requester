"""
tests/unit/test_messages.py

SPDM 訊息 Builder/Parser 基本單元測試（不需要硬體）
"""

import pytest
from spdm_tool.messages.base import SpdmHeader, RequestCode, ResponseCode, SpdmMessage
from spdm_tool.messages.version import GetVersionRequest, VersionResponse, VersionEntry
from spdm_tool.messages.capabilities import GetCapabilitiesRequest, CapabilitiesResponse
from spdm_tool.messages.error import ErrorResponse, ErrorCode
from spdm_tool.messages.measurements import GetMeasurementsRequest, MeasIndex


class TestSpdmHeader:
    def test_encode_decode_roundtrip(self):
        h = SpdmHeader(version=0x13, code=0x84, param1=0x01, param2=0x02)
        raw = h.encode()
        assert len(raw) == 4
        h2 = SpdmHeader.decode(raw)
        assert h2.version == 0x13
        assert h2.code    == 0x84
        assert h2.param1  == 0x01
        assert h2.param2  == 0x02

    def test_is_request(self):
        assert SpdmHeader(code=0x84).is_request()
        assert not SpdmHeader(code=0x04).is_request()

    def test_is_error(self):
        assert SpdmHeader(code=ResponseCode.ERROR).is_error()
        assert not SpdmHeader(code=ResponseCode.VERSION).is_error()


class TestGetVersionRequest:
    def test_encode_is_4_bytes(self):
        raw = GetVersionRequest().encode()
        assert len(raw) == 4
        assert raw[1] == RequestCode.GET_VERSION
        assert raw[0] == 0x10  # GET_VERSION 固定 v1.0

    def test_decode_roundtrip(self):
        raw = GetVersionRequest(version=0x10, param1=0, param2=0).encode()
        decoded = GetVersionRequest.decode(raw)
        assert decoded.version == 0x10


class TestVersionResponse:
    def test_encode_decode(self):
        resp = VersionResponse(
            version=0x10,
            entries=[VersionEntry(1, 3), VersionEntry(1, 2)],
        )
        raw = resp.encode()
        decoded = VersionResponse.decode(raw)
        assert len(decoded.entries) == 2
        assert decoded.entries[0].major == 1
        assert decoded.entries[0].minor == 3

    def test_supported_versions(self):
        resp = VersionResponse(entries=[VersionEntry(1, 3), VersionEntry(1, 2)])
        assert "1.3" in resp.supported_versions()
        assert "1.2" in resp.supported_versions()


class TestErrorResponse:
    def test_encode_decode(self):
        err = ErrorResponse(
            version=0x13,
            error_code=ErrorCode.UNEXPECTED_REQUEST,
            error_data=0x00,
        )
        raw = err.encode()
        assert len(raw) == 4
        decoded = ErrorResponse.decode(raw)
        assert decoded.error_code == ErrorCode.UNEXPECTED_REQUEST
        assert decoded.error_name == "UnexpectedRequest"

    def test_response_not_ready(self):
        from spdm_tool.messages.error import ResponseNotReadyData
        ext = ResponseNotReadyData(rdt_exponent=10, request_code=0x84, token=0xAB, rdtm=5)
        err = ErrorResponse(
            error_code=ErrorCode.RESPONSE_NOT_READY,
            extended=ext.encode(),
        )
        raw = err.encode()
        decoded = ErrorResponse.decode(raw)
        info = decoded.response_not_ready_info()
        assert info is not None
        assert info.rdt_exponent == 10
        assert info.token == 0xAB
        assert info.rdt_us() == 1024


class TestGetMeasurementsRequest:
    def test_no_sig(self):
        raw = GetMeasurementsRequest(request_sig=False, index=MeasIndex.ALL).encode()
        assert len(raw) == 4
        assert raw[2] == 0x00  # param1: no sig

    def test_with_sig(self):
        raw = GetMeasurementsRequest(request_sig=True, index=MeasIndex.ALL).encode()
        assert len(raw) == 4 + 32 + 1  # header + nonce + slot_id
        assert raw[2] & 0x01            # param1 bit0 = 1


class TestFromBytes:
    def test_auto_dispatch_to_error(self):
        raw = ErrorResponse(error_code=ErrorCode.UNEXPECTED_REQUEST).encode()
        parsed = SpdmMessage.from_bytes(raw)
        assert isinstance(parsed, ErrorResponse)

    def test_unknown_code_becomes_raw(self):
        from spdm_tool.messages.base import RawSpdmMessage
        raw = bytes([0x13, 0x55, 0x00, 0x00])  # 0x55 = unknown
        parsed = SpdmMessage.from_bytes(raw)
        assert isinstance(parsed, RawSpdmMessage)
