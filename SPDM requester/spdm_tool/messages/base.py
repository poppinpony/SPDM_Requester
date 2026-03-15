"""
messages/base.py

SPDM 訊息的基礎結構。
所有 Request / Response 類別都繼承自此。

SPDM 4-byte header（DSP0274 Table 4）：
  Byte 0: SPDMVersion
  Byte 1: RequestResponseCode
  Byte 2: Param1
  Byte 3: Param2
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import ClassVar


# ──────────────────────────────────────────────────────────────────────────────
# RequestResponseCode 定義（DSP0274 Table 4）
# ──────────────────────────────────────────────────────────────────────────────

class RequestCode(IntEnum):
    GET_DIGESTS                    = 0x81
    GET_CERTIFICATE                = 0x82
    CHALLENGE                      = 0x83
    GET_VERSION                    = 0x84
    GET_MEASUREMENTS               = 0xE0
    GET_CAPABILITIES               = 0xE1
    NEGOTIATE_ALGORITHMS           = 0xE3
    KEY_EXCHANGE                   = 0xE4
    FINISH                         = 0xE5
    PSK_EXCHANGE                   = 0xE6
    PSK_FINISH                     = 0xE7
    HEARTBEAT                      = 0xE8
    KEY_UPDATE                     = 0xE9
    GET_ENCAPSULATED_REQUEST       = 0xEA
    DELIVER_ENCAPSULATED_RESPONSE  = 0xEB
    END_SESSION                    = 0xEC
    GET_CSR                        = 0xED
    SET_CERTIFICATE                = 0xEE
    GET_MEASUREMENT_EXTENSION_LOG  = 0xEF
    SUBSCRIBE_EVENT_TYPES          = 0xF0
    SEND_EVENT                     = 0xF1
    GET_KEY_PAIR_INFO              = 0xFC
    SET_KEY_PAIR_INFO              = 0xFD
    VENDOR_DEFINED_REQUEST         = 0xFE
    RESPOND_IF_READY               = 0xFF


class ResponseCode(IntEnum):
    DIGESTS                        = 0x01
    CERTIFICATE                    = 0x02
    CHALLENGE_AUTH                 = 0x03
    VERSION                        = 0x04
    CHUNK_SEND_ACK                 = 0x05
    CHUNK_RESPONSE                 = 0x06
    MEASUREMENTS                   = 0x60
    CAPABILITIES                   = 0x61
    ALGORITHMS                     = 0x63
    KEY_EXCHANGE_RSP               = 0x64
    FINISH_RSP                     = 0x65
    PSK_EXCHANGE_RSP               = 0x66
    PSK_FINISH_RSP                 = 0x67
    HEARTBEAT_ACK                  = 0x68
    KEY_UPDATE_ACK                 = 0x69
    ENCAPSULATED_REQUEST           = 0x6A
    ENCAPSULATED_RESPONSE_ACK      = 0x6B
    END_SESSION_ACK                = 0x6C
    CSR                            = 0x6D
    SET_CERTIFICATE_RSP            = 0x6E
    MEASUREMENT_EXTENSION_LOG      = 0x6F
    SUBSCRIBE_EVENT_TYPES_ACK      = 0x70
    EVENT_ACK                      = 0x71
    KEY_PAIR_INFO                  = 0x7C
    SET_KEY_PAIR_INFO_ACK          = 0x7D
    VENDOR_DEFINED_RESPONSE        = 0x7E
    ERROR                          = 0x7F


class SpdmVersion(IntEnum):
    """
    SPDMVersion byte encoding：高 nibble = Major，低 nibble = Minor
    e.g. 0x12 → SPDM 1.2, 0x13 → 1.3, 0x14 → 1.4
    注意：GET_VERSION 的請求固定用 0x10
    """
    V1_0 = 0x10
    V1_1 = 0x11
    V1_2 = 0x12
    V1_3 = 0x13
    V1_4 = 0x14


# ──────────────────────────────────────────────────────────────────────────────
# Header
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class SpdmHeader:
    """
    SPDM 通用 4-byte header。
    所有欄位都允許直接指定任意值，讓測試可送出非標準訊息。
    """
    version: int = SpdmVersion.V1_3
    code: int    = 0x00
    param1: int  = 0x00
    param2: int  = 0x00

    STRUCT_FMT: ClassVar[str] = "!BBBB"   # 4 bytes, big-endian（SPDM 網路序）
    SIZE: ClassVar[int] = 4

    def encode(self) -> bytes:
        return struct.pack(self.STRUCT_FMT,
                           self.version, self.code, self.param1, self.param2)

    @classmethod
    def decode(cls, data: bytes) -> "SpdmHeader":
        if len(data) < cls.SIZE:
            raise ValueError(f"Header too short: {len(data)} < {cls.SIZE}")
        v, c, p1, p2 = struct.unpack_from(cls.STRUCT_FMT, data)
        return cls(version=v, code=c, param1=p1, param2=p2)

    def is_request(self) -> bool:
        return self.code >= 0x80

    def is_response(self) -> bool:
        return not self.is_request()

    def is_error(self) -> bool:
        return self.code == ResponseCode.ERROR

    def __repr__(self) -> str:
        try:
            code_name = (RequestCode(self.code).name
                         if self.is_request()
                         else ResponseCode(self.code).name)
        except ValueError:
            code_name = f"0x{self.code:02X}"
        return (f"SpdmHeader(ver=0x{self.version:02X}, "
                f"code={code_name}, p1=0x{self.param1:02X}, p2=0x{self.param2:02X})")


# ──────────────────────────────────────────────────────────────────────────────
# 訊息基底類別
# ──────────────────────────────────────────────────────────────────────────────

class SpdmMessage:
    """
    所有 SPDM 訊息的基底。

    使用方式（三個層次）：
      高階 → 直接用各子類別（欄位有型別與預設值）
      中階 → 建立後修改任意欄位，再呼叫 encode()
      低階 → SpdmMessage.from_bytes(raw) 直接從 raw bytes 建立
    """

    def encode(self) -> bytes:
        raise NotImplementedError

    @classmethod
    def decode(cls, data: bytes) -> "SpdmMessage":
        raise NotImplementedError

    @staticmethod
    def from_bytes(data: bytes) -> "SpdmMessage":
        """
        根據 header 的 RequestResponseCode 自動選擇正確子類別解析。
        若遇到未知 code，回傳 RawSpdmMessage。
        """
        if len(data) < SpdmHeader.SIZE:
            return RawSpdmMessage(data)
        code = data[1]
        cls_ = _get_dispatch().get(code, RawSpdmMessage)
        return cls_.decode(data)


@dataclass
class RawSpdmMessage(SpdmMessage):
    """
    未知或故意送出的任意 SPDM 訊息（raw bytes）。
    提供最大自由度：可直接帶任意 bytes 送出，也用於解析未知 response。
    """
    raw: bytes = field(default_factory=bytes)

    def encode(self) -> bytes:
        return self.raw

    @classmethod
    def decode(cls, data: bytes) -> "RawSpdmMessage":
        return cls(raw=bytes(data))

    @property
    def header(self) -> SpdmHeader:
        return SpdmHeader.decode(self.raw)

    def __repr__(self) -> str:
        return f"RawSpdmMessage({self.raw.hex()})"


# ──────────────────────────────────────────────────────────────────────────────
# Dispatch table（lazy-loaded 一次，避免每次 from_bytes() 都重建 dict 和 import）
# ──────────────────────────────────────────────────────────────────────────────

_DISPATCH_CACHE: dict[int, type] | None = None


def _get_dispatch() -> dict[int, type]:
    global _DISPATCH_CACHE
    if _DISPATCH_CACHE is not None:
        return _DISPATCH_CACHE

    from . import (
        GetVersionRequest, VersionResponse,
        GetCapabilitiesRequest, CapabilitiesResponse,
        NegotiateAlgorithmsRequest, AlgorithmsResponse,
        GetDigestsRequest, DigestsResponse,
        GetCertificateRequest, CertificateResponse,
        ChallengeRequest, ChallengeAuthResponse,
        GetMeasurementsRequest, MeasurementsResponse,
        KeyExchangeRequest, KeyExchangeRspResponse,
        FinishRequest, FinishRspResponse,
        EndSessionRequest, EndSessionAckResponse,
        ErrorResponse,
    )
    _DISPATCH_CACHE = {
        RequestCode.GET_VERSION:          GetVersionRequest,
        ResponseCode.VERSION:             VersionResponse,
        RequestCode.GET_CAPABILITIES:     GetCapabilitiesRequest,
        ResponseCode.CAPABILITIES:        CapabilitiesResponse,
        RequestCode.NEGOTIATE_ALGORITHMS: NegotiateAlgorithmsRequest,
        ResponseCode.ALGORITHMS:          AlgorithmsResponse,
        RequestCode.GET_DIGESTS:          GetDigestsRequest,
        ResponseCode.DIGESTS:             DigestsResponse,
        RequestCode.GET_CERTIFICATE:      GetCertificateRequest,
        ResponseCode.CERTIFICATE:         CertificateResponse,
        RequestCode.CHALLENGE:            ChallengeRequest,
        ResponseCode.CHALLENGE_AUTH:      ChallengeAuthResponse,
        RequestCode.GET_MEASUREMENTS:     GetMeasurementsRequest,
        ResponseCode.MEASUREMENTS:        MeasurementsResponse,
        RequestCode.KEY_EXCHANGE:         KeyExchangeRequest,
        ResponseCode.KEY_EXCHANGE_RSP:    KeyExchangeRspResponse,
        RequestCode.FINISH:               FinishRequest,
        ResponseCode.FINISH_RSP:          FinishRspResponse,
        RequestCode.END_SESSION:          EndSessionRequest,
        ResponseCode.END_SESSION_ACK:     EndSessionAckResponse,
        ResponseCode.ERROR:               ErrorResponse,
    }
    return _DISPATCH_CACHE
