"""
messages/error.py  —  ERROR Response (0x7F)

DSP0274 Table 64（1.3）
這是測試工具最關心的訊息 — 碟機的錯誤回應。
"""

from __future__ import annotations
import struct
from dataclasses import dataclass, field
from .base import SpdmMessage, SpdmHeader, ResponseCode


# ──────────────────────────────────────────────────────────────────────────────
# 完整 Error Code 對照表（DSP0274 Table 65）
# ──────────────────────────────────────────────────────────────────────────────

class ErrorCode:
    INVALID_REQUEST        = 0x01
    BUSY                   = 0x03
    UNEXPECTED_REQUEST     = 0x04
    UNSPECIFIED            = 0x05
    DECRYPT_ERROR          = 0x06
    UNSUPPORTED_REQUEST    = 0x07
    REQUEST_IN_FLIGHT      = 0x08
    INVALID_RESPONSE_CODE  = 0x09
    SESSION_LIMIT_EXCEEDED = 0x0A
    SESSION_REQUIRED       = 0x0B
    RESET_REQUIRED         = 0x0C
    RESPONSE_TOO_LARGE     = 0x0D
    REQUEST_TOO_LARGE      = 0x0E
    LARGE_RESPONSE         = 0x0F
    MESSAGE_LOST           = 0x10
    INVALID_POLICY         = 0x11
    DATA_TOO_LARGE         = 0x12
    VERSION_MISMATCH       = 0x41
    RESPONSE_NOT_READY     = 0x42
    REQUEST_RESYNCH        = 0x43
    OPERATION_FAILED       = 0x44
    NO_PENDING_REQUESTS    = 0x45
    REQUEST_SESSION_TERMINATED = 0x46
    INVALID_STATE          = 0x47
    VENDOR_DEFINED         = 0xFF

    _NAMES = {
        0x01: "InvalidRequest",
        0x03: "Busy",
        0x04: "UnexpectedRequest",
        0x05: "Unspecified",
        0x06: "DecryptError",
        0x07: "UnsupportedRequest",
        0x08: "RequestInFlight",
        0x09: "InvalidResponseCode",
        0x0A: "SessionLimitExceeded",
        0x0B: "SessionRequired",
        0x0C: "ResetRequired",
        0x0D: "ResponseTooLarge",
        0x0E: "RequestTooLarge",
        0x0F: "LargeResponse",
        0x10: "MessageLost",
        0x11: "InvalidPolicy",
        0x12: "DataTooLarge",
        0x41: "VersionMismatch",
        0x42: "ResponseNotReady",
        0x43: "RequestResynch",
        0x44: "OperationFailed",
        0x45: "NoPendingRequests",
        0x46: "RequestSessionTerminated",
        0x47: "InvalidState",
        0xFF: "VendorDefined",
    }

    @classmethod
    def name(cls, code: int) -> str:
        return cls._NAMES.get(code, f"Unknown(0x{code:02X})")


@dataclass
class ResponseNotReadyData:
    """ResponseNotReady 的 Extended Error Data（4 bytes）"""
    rdt_exponent: int = 0   # 2^rdt_exponent µs = RDT
    request_code: int = 0   # 觸發此 error 的 RequestResponseCode
    token:        int = 0   # 用於 RESPOND_IF_READY 的 token
    rdtm:         int = 0   # WT_Max 乘數

    def encode(self) -> bytes:
        return struct.pack("BBBB",
                           self.rdt_exponent, self.request_code,
                           self.token, self.rdtm)

    @classmethod
    def decode(cls, data: bytes) -> "ResponseNotReadyData":
        if len(data) < 4:
            return cls()
        exp, code, token, rdtm = struct.unpack_from("BBBB", data)
        return cls(rdt_exponent=exp, request_code=code, token=token, rdtm=rdtm)

    def rdt_us(self) -> int:
        return 1 << self.rdt_exponent


@dataclass
class ErrorResponse(SpdmMessage):
    """
    ERROR Response (0x7F)

    Param1 (error_code):  錯誤分類碼
    Param2 (error_data):  錯誤特定資料
    Payload: ExtendedErrorData（0~32 bytes，依 error_code 而定）
    """
    version:    int   = 0x13
    error_code: int   = 0x00   # Param1
    error_data: int   = 0x00   # Param2
    extended:   bytes = field(default_factory=bytes)

    def encode(self) -> bytes:
        hdr = SpdmHeader(
            version=self.version,
            code=ResponseCode.ERROR,
            param1=self.error_code,
            param2=self.error_data,
        ).encode()
        return hdr + self.extended

    @classmethod
    def decode(cls, data: bytes) -> "ErrorResponse":
        h = SpdmHeader.decode(data)
        extended = data[SpdmHeader.SIZE:]
        return cls(version=h.version,
                   error_code=h.param1,
                   error_data=h.param2,
                   extended=extended)

    @property
    def error_name(self) -> str:
        return ErrorCode.name(self.error_code)

    def response_not_ready_info(self) -> ResponseNotReadyData | None:
        if self.error_code == ErrorCode.RESPONSE_NOT_READY:
            return ResponseNotReadyData.decode(self.extended)
        return None

    def is_unexpected_request(self) -> bool:
        return self.error_code == ErrorCode.UNEXPECTED_REQUEST

    def is_version_mismatch(self) -> bool:
        return self.error_code == ErrorCode.VERSION_MISMATCH

    def __repr__(self) -> str:
        return (f"ErrorResponse({self.error_name}, "
                f"data=0x{self.error_data:02X}, "
                f"ext={self.extended.hex() if self.extended else ''})")
