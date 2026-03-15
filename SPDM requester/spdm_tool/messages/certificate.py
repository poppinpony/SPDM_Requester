"""
messages/certificate.py  —  GET_CERTIFICATE (0x82) / CERTIFICATE (0x02)

DSP0274 Table 38/40（1.3）
"""

from __future__ import annotations
import struct
from dataclasses import dataclass, field
from .base import SpdmMessage, SpdmHeader, RequestCode, ResponseCode


@dataclass
class GetCertificateRequest(SpdmMessage):
    """
    GET_CERTIFICATE Request

    Param1: Bit[3:0] = SlotID（0~7），Bit[7:4] = Reserved
    Param2: 屬性旗標（Bit 0 = SlotSizeRequested，1.3+）
    """
    version: int = 0x13
    slot_id: int = 0        # Param1[3:0]
    param2:  int = 0x00
    offset:  int = 0        # 憑證鏈起始偏移（bytes）
    length:  int = 0xFFFF   # 請求長度（0xFFFF = 盡量多）

    def encode(self) -> bytes:
        hdr = SpdmHeader(
            version=self.version,
            code=RequestCode.GET_CERTIFICATE,
            param1=self.slot_id & 0x0F,
            param2=self.param2,
        ).encode()
        return hdr + struct.pack("<HH", self.offset, self.length)

    @classmethod
    def decode(cls, data: bytes) -> "GetCertificateRequest":
        h = SpdmHeader.decode(data)
        obj = cls(version=h.version, slot_id=h.param1 & 0xF, param2=h.param2)
        if len(data) >= 8:
            obj.offset, obj.length = struct.unpack_from("<HH", data, 4)
        return obj


@dataclass
class CertificateResponse(SpdmMessage):
    """
    CERTIFICATE Response (0x02)

    Param1: Bit[3:0] = SlotID
    Param2: 屬性旗標

    Payload:
      PortionLength   (2 bytes LE) — 本次回應的憑證資料長度
      RemainderLength (2 bytes LE) — 剩餘未傳輸的長度（0 = 全部傳完）
      CertChainData   (PortionLength bytes)
    """
    version:          int   = 0x13
    slot_id:          int   = 0
    param2:           int   = 0x00
    portion_length:   int   = 0
    remainder_length: int   = 0
    cert_chain_data:  bytes = field(default_factory=bytes)

    def encode(self) -> bytes:
        hdr = SpdmHeader(
            version=self.version,
            code=ResponseCode.CERTIFICATE,
            param1=self.slot_id & 0x0F,
            param2=self.param2,
        ).encode()
        payload = struct.pack("<HH", self.portion_length, self.remainder_length)
        payload += self.cert_chain_data
        return hdr + payload

    @classmethod
    def decode(cls, data: bytes) -> "CertificateResponse":
        h = SpdmHeader.decode(data)
        obj = cls(version=h.version, slot_id=h.param1 & 0xF, param2=h.param2)
        if len(data) >= 8:
            obj.portion_length, obj.remainder_length = struct.unpack_from("<HH", data, 4)
            obj.cert_chain_data = data[8: 8 + obj.portion_length]
        return obj

    @property
    def is_last_chunk(self) -> bool:
        return self.remainder_length == 0

    def __repr__(self) -> str:
        return (f"CertificateResponse(slot={self.slot_id}, "
                f"portion={self.portion_length}, "
                f"remainder={self.remainder_length})")
