"""
messages/measurements.py  —  GET_MEASUREMENTS (0xE0) / MEASUREMENTS (0x60)

DSP0274 Table 49/52（1.3）
"""

from __future__ import annotations
import os
import struct
from dataclasses import dataclass, field
from .base import SpdmMessage, SpdmHeader, RequestCode, ResponseCode


class MeasIndex:
    """GET_MEASUREMENTS Param2 特殊值"""
    ALL          = 0xFF   # 取全部測量值
    COUNT_ONLY   = 0x00   # 只回傳數量，不回傳資料


@dataclass
class MeasurementBlock:
    """
    單一 Measurement Block（DSP0274 Table 48）

    Byte 0:   Index
    Byte 1:   MeasurementSpecification（Bit 0 = DMTF）
    Byte 2-3: MeasurementSize (LE)
    Byte 4+:  Measurement（DMTF: [type(1)][size(2)][value(variable)]）
    """
    index:      int   = 0
    meas_spec:  int   = 1   # 0x01 = DMTF
    measurement: bytes = field(default_factory=bytes)

    def encode(self) -> bytes:
        size = len(self.measurement)
        return struct.pack("<B B H", self.index, self.meas_spec, size) + self.measurement

    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> tuple["MeasurementBlock", int]:
        """回傳 (block, new_offset)"""
        if offset + 4 > len(data):
            return cls(), offset
        idx, spec, size = struct.unpack_from("<B B H", data, offset)
        meas = data[offset + 4: offset + 4 + size]
        return cls(index=idx, meas_spec=spec, measurement=meas), offset + 4 + size

    def __repr__(self) -> str:
        return f"MeasBlock(idx=0x{self.index:02X}, size={len(self.measurement)})"


@dataclass
class GetMeasurementsRequest(SpdmMessage):
    """
    GET_MEASUREMENTS Request (0xE0)

    Param1: Bit 0 = request_signature，Bit 1 = new_measurement_requested（1.3+）
    Param2: measurement index（0x00=count, 0x01-0xFE=specific, 0xFF=all）

    若 Param1.Bit0=1 則 Payload 包含 Nonce(32) + SlotID(1)
    """
    version:      int   = 0x13
    request_sig:  bool  = False    # Param1 Bit 0
    new_req:      bool  = False    # Param1 Bit 1（1.3+）
    index:        int   = MeasIndex.ALL   # Param2
    nonce:        bytes = field(default_factory=lambda: os.urandom(32))
    slot_id:      int   = 0        # 僅 request_sig=True 時有效

    def encode(self) -> bytes:
        param1 = 0
        if self.request_sig:
            param1 |= 0x01
        if self.new_req:
            param1 |= 0x02
        hdr = SpdmHeader(
            version=self.version,
            code=RequestCode.GET_MEASUREMENTS,
            param1=param1,
            param2=self.index,
        ).encode()
        if self.request_sig:
            nonce = self.nonce if len(self.nonce) == 32 else os.urandom(32)
            return hdr + nonce + struct.pack("B", self.slot_id & 0x0F)
        return hdr

    @classmethod
    def decode(cls, data: bytes) -> "GetMeasurementsRequest":
        h = SpdmHeader.decode(data)
        obj = cls(version=h.version,
                  request_sig=bool(h.param1 & 0x01),
                  new_req=bool(h.param1 & 0x02),
                  index=h.param2)
        if obj.request_sig and len(data) >= 37:
            obj.nonce   = data[4:36]
            obj.slot_id = data[36] & 0x0F
        return obj


@dataclass
class MeasurementsResponse(SpdmMessage):
    """
    MEASUREMENTS Response (0x60)

    Param1: 若請求只問數量（index=0x00），此處為 measurement count
    Param2: 回傳的 measurement index（0 = 全部）
    """
    version:              int                   = 0x13
    param1:               int                   = 0x00   # count or reserved
    param2:               int                   = 0x00   # index
    blocks:               list[MeasurementBlock] = field(default_factory=list)
    nonce:                bytes                 = field(default_factory=bytes)
    opaque_data:          bytes                 = field(default_factory=bytes)
    signature:            bytes                 = field(default_factory=bytes)

    def encode(self) -> bytes:
        blocks_bytes = b"".join(b.encode() for b in self.blocks)
        record_len = len(blocks_bytes)
        hdr = SpdmHeader(
            version=self.version,
            code=ResponseCode.MEASUREMENTS,
            param1=self.param1,
            param2=self.param2,
        ).encode()
        payload = struct.pack("<H", record_len)           # MeasurementRecordLength
        payload += struct.pack("B", len(self.blocks))    # NumberOfBlocks
        payload += struct.pack("B", 0x00)                # ContentChanged / Reserved
        payload += blocks_bytes
        if self.nonce:
            payload += self.nonce
            payload += struct.pack("<H", len(self.opaque_data))
            payload += self.opaque_data
            payload += self.signature
        return hdr + payload

    @classmethod
    def decode(cls, data: bytes, sig_size: int = 0) -> "MeasurementsResponse":
        h = SpdmHeader.decode(data)
        obj = cls(version=h.version, param1=h.param1, param2=h.param2)
        if len(data) < 8:
            return obj
        record_len, = struct.unpack_from("<H", data, 4)
        num_blocks,  = struct.unpack_from("B",  data, 6)
        offset = 8
        for _ in range(num_blocks):
            blk, offset = MeasurementBlock.decode(data, offset)
            obj.blocks.append(blk)
        if offset + 32 <= len(data):
            obj.nonce = data[offset: offset + 32]
            offset += 32
        if offset + 2 <= len(data):
            opaque_len, = struct.unpack_from("<H", data, offset)
            offset += 2
            obj.opaque_data = data[offset: offset + opaque_len]
            offset += opaque_len
        if sig_size and offset + sig_size <= len(data):
            obj.signature = data[offset: offset + sig_size]
        return obj

    def __repr__(self) -> str:
        return (f"MeasurementsResponse("
                f"count={len(self.blocks)}, "
                f"signed={bool(self.signature)}, "
                f"blocks={self.blocks})")
