"""
messages/version.py  —  GET_VERSION (0x84) / VERSION (0x04)

DSP0274 Table 8 / Table 9
"""

from __future__ import annotations
import struct
from dataclasses import dataclass, field
from .base import SpdmMessage, SpdmHeader, RequestCode, ResponseCode, SpdmVersion


@dataclass
class GetVersionRequest(SpdmMessage):
    """
    GET_VERSION Request

    注意：SPDMVersion 欄位固定為 0x10（1.0），即使溝通對象是 1.3/1.4 版本。
    Param1, Param2 為 Reserved（預設 0x00）。
    """
    version: int = SpdmVersion.V1_0   # 固定 0x10，per Spec
    param1:  int = 0x00
    param2:  int = 0x00

    def encode(self) -> bytes:
        return SpdmHeader(
            version=self.version,
            code=RequestCode.GET_VERSION,
            param1=self.param1,
            param2=self.param2,
        ).encode()

    @classmethod
    def decode(cls, data: bytes) -> "GetVersionRequest":
        h = SpdmHeader.decode(data)
        return cls(version=h.version, param1=h.param1, param2=h.param2)

    def __repr__(self) -> str:
        return f"GetVersionRequest(ver=0x{self.version:02X})"


@dataclass
class VersionEntry:
    """
    16-bit version entry：[MajorVer(4)][MinorVer(4)][UpdateVer(4)][Alpha(4)]
    """
    major:  int = 1
    minor:  int = 3
    update: int = 0
    alpha:  int = 0

    def encode(self) -> bytes:
        value = ((self.major & 0xF) << 12 |
                 (self.minor & 0xF) << 8  |
                 (self.update & 0xF) << 4 |
                 (self.alpha & 0xF))
        return struct.pack("<H", value)

    @classmethod
    def decode(cls, value: int) -> "VersionEntry":
        return cls(
            major  = (value >> 12) & 0xF,
            minor  = (value >> 8)  & 0xF,
            update = (value >> 4)  & 0xF,
            alpha  =  value        & 0xF,
        )

    def to_string(self) -> str:
        s = f"{self.major}.{self.minor}"
        if self.update:
            s += f".{self.update}"
        if self.alpha:
            s += f" alpha{self.alpha}"
        return s

    def __repr__(self) -> str:
        return f"VersionEntry({self.to_string()})"


@dataclass
class VersionResponse(SpdmMessage):
    """
    VERSION Response (0x04)

    Byte 4:   Reserved
    Byte 5:   VersionNumberEntryCount (n)
    Byte 6+:  VersionNumberEntry[0..n-1]  (每個 2 bytes, little-endian)
    """
    version:  int                      = SpdmVersion.V1_0
    param1:   int                      = 0x00
    param2:   int                      = 0x00
    entries:  list[VersionEntry]       = field(default_factory=list)

    def encode(self) -> bytes:
        hdr = SpdmHeader(
            version=self.version,
            code=ResponseCode.VERSION,
            param1=self.param1,
            param2=self.param2,
        ).encode()
        n = len(self.entries)
        payload = struct.pack("BB", 0x00, n)
        for e in self.entries:
            payload += e.encode()
        return hdr + payload

    @classmethod
    def decode(cls, data: bytes) -> "VersionResponse":
        h = SpdmHeader.decode(data)
        if len(data) < 6:
            return cls(version=h.version, param1=h.param1, param2=h.param2)
        _reserved, n = struct.unpack_from("BB", data, 4)
        entries = []
        for i in range(n):
            offset = 6 + i * 2
            if offset + 2 > len(data):
                break
            (val,) = struct.unpack_from("<H", data, offset)
            entries.append(VersionEntry.decode(val))
        return cls(version=h.version, param1=h.param1,
                   param2=h.param2, entries=entries)

    def supported_versions(self) -> list[str]:
        return [e.to_string() for e in self.entries]

    def __repr__(self) -> str:
        return f"VersionResponse(versions={self.supported_versions()})"
