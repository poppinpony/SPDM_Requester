"""
messages/digests.py  —  GET_DIGESTS (0x81) / DIGESTS (0x01)

DSP0274 Table 34/35（1.3）
"""

from __future__ import annotations
import struct
from dataclasses import dataclass, field
from .base import SpdmMessage, SpdmHeader, RequestCode, ResponseCode


@dataclass
class GetDigestsRequest(SpdmMessage):
    version: int = 0x13
    param1:  int = 0x00
    param2:  int = 0x00

    def encode(self) -> bytes:
        return SpdmHeader(
            version=self.version,
            code=RequestCode.GET_DIGESTS,
            param1=self.param1,
            param2=self.param2,
        ).encode()

    @classmethod
    def decode(cls, data: bytes) -> "GetDigestsRequest":
        h = SpdmHeader.decode(data)
        return cls(version=h.version, param1=h.param1, param2=h.param2)


@dataclass
class DigestsResponse(SpdmMessage):
    """
    DIGESTS Response (0x01)

    Param1: Reserved
    Param2: SlotMask（Bit N = Slot N 有憑證）

    Payload: hash_size * popcount(slot_mask) bytes
    """
    version:   int        = 0x13
    param1:    int        = 0x00
    slot_mask: int        = 0x00         # Param2
    digests:   list[bytes] = field(default_factory=list)  # 每個 slot 的 hash

    def encode(self) -> bytes:
        hdr = SpdmHeader(
            version=self.version,
            code=ResponseCode.DIGESTS,
            param1=self.param1,
            param2=self.slot_mask,
        ).encode()
        return hdr + b"".join(self.digests)

    @classmethod
    def decode(cls, data: bytes, hash_size: int = 32) -> "DigestsResponse":
        """
        hash_size：由 NEGOTIATE_ALGORITHMS 協商的 hash 大小（預設 SHA-256 = 32）
        """
        h = SpdmHeader.decode(data)
        slot_mask = h.param2
        digests = []
        offset = SpdmHeader.SIZE
        for bit in range(8):
            if slot_mask & (1 << bit):
                d = data[offset: offset + hash_size]
                digests.append(d)
                offset += hash_size
        return cls(version=h.version, param1=h.param1,
                   slot_mask=slot_mask, digests=digests)

    def populated_slots(self) -> list[int]:
        return [i for i in range(8) if self.slot_mask & (1 << i)]

    def __repr__(self) -> str:
        slots = self.populated_slots()
        return (f"DigestsResponse(slots={slots}, "
                f"digests=[{', '.join(d.hex()[:8]+'...' for d in self.digests)}])")
