"""
messages/end_session.py  —  END_SESSION (0xEC) / END_SESSION_ACK (0x6C)

DSP0274 Table 87/89（1.3）
"""

from __future__ import annotations
from dataclasses import dataclass
from .base import SpdmMessage, SpdmHeader, RequestCode, ResponseCode


@dataclass
class EndSessionRequest(SpdmMessage):
    """Param1: Bit 0 = EndSessionRequestAttributes（0=normal，1=preserve_negotiated_state）"""
    version:    int = 0x13
    attributes: int = 0x00
    param2:     int = 0x00

    def encode(self) -> bytes:
        return SpdmHeader(
            version=self.version,
            code=RequestCode.END_SESSION,
            param1=self.attributes,
            param2=self.param2,
        ).encode()

    @classmethod
    def decode(cls, data: bytes) -> "EndSessionRequest":
        h = SpdmHeader.decode(data)
        return cls(version=h.version, attributes=h.param1, param2=h.param2)


@dataclass
class EndSessionAckResponse(SpdmMessage):
    version: int = 0x13
    param1:  int = 0x00
    param2:  int = 0x00

    def encode(self) -> bytes:
        return SpdmHeader(
            version=self.version,
            code=ResponseCode.END_SESSION_ACK,
            param1=self.param1,
            param2=self.param2,
        ).encode()

    @classmethod
    def decode(cls, data: bytes) -> "EndSessionAckResponse":
        h = SpdmHeader.decode(data)
        return cls(version=h.version, param1=h.param1, param2=h.param2)
