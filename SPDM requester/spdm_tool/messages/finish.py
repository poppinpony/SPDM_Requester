"""
messages/finish.py  —  FINISH (0xE5) / FINISH_RSP (0x65)

DSP0274 Table 72/73（1.3）
"""

from __future__ import annotations
from dataclasses import dataclass, field
from .base import SpdmMessage, SpdmHeader, RequestCode, ResponseCode
import struct


@dataclass
class FinishRequest(SpdmMessage):
    """
    FINISH Request (0xE5)

    Param1: Bit 0 = SignatureIncluded（互相認證時 Requester 要附上簽名）
    Param2: SlotID（僅 Param1.Bit0=1 時有效）
    """
    version:        int   = 0x13
    sig_included:   bool  = False
    slot_id:        int   = 0
    signature:      bytes = field(default_factory=bytes)
    verify_data:    bytes = field(default_factory=bytes)

    def encode(self) -> bytes:
        param1 = 0x01 if self.sig_included else 0x00
        hdr = SpdmHeader(
            version=self.version,
            code=RequestCode.FINISH,
            param1=param1,
            param2=self.slot_id if self.sig_included else 0,
        ).encode()
        payload = b""
        if self.sig_included:
            payload += self.signature
        payload += self.verify_data
        return hdr + payload

    @classmethod
    def decode(cls, data: bytes, sig_size: int = 0, hmac_size: int = 32) -> "FinishRequest":
        h = SpdmHeader.decode(data)
        sig_included = bool(h.param1 & 0x01)
        off = 4
        sig = b""
        if sig_included and sig_size:
            sig = data[off: off + sig_size]
            off += sig_size
        verify = data[off: off + hmac_size]
        return cls(version=h.version, sig_included=sig_included,
                   slot_id=h.param2, signature=sig, verify_data=verify)


@dataclass
class FinishRspResponse(SpdmMessage):
    """FINISH_RSP Response (0x65)"""
    version:      int   = 0x13
    param1:       int   = 0x00
    param2:       int   = 0x00
    verify_data:  bytes = field(default_factory=bytes)

    def encode(self) -> bytes:
        hdr = SpdmHeader(
            version=self.version,
            code=ResponseCode.FINISH_RSP,
            param1=self.param1,
            param2=self.param2,
        ).encode()
        return hdr + self.verify_data

    @classmethod
    def decode(cls, data: bytes, hmac_size: int = 32) -> "FinishRspResponse":
        h = SpdmHeader.decode(data)
        verify = data[4: 4 + hmac_size]
        return cls(version=h.version, param1=h.param1,
                   param2=h.param2, verify_data=verify)
