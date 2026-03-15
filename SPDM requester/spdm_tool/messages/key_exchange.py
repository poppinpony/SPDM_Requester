"""
messages/key_exchange.py  —  KEY_EXCHANGE (0xE4) / KEY_EXCHANGE_RSP (0x64)

DSP0274 Table 69/71（1.3）
"""

from __future__ import annotations
import os
import struct
from dataclasses import dataclass, field
from .base import SpdmMessage, SpdmHeader, RequestCode, ResponseCode
from .challenge import MeasHashType


@dataclass
class KeyExchangeRequest(SpdmMessage):
    """
    KEY_EXCHANGE Request (0xE4)

    Param1: MeasurementSummaryHashType
    Param2: SlotID
    """
    version:            int   = 0x13
    meas_type:          int   = MeasHashType.NONE
    slot_id:            int   = 0
    req_session_id:     int   = 0x0001   # 2 bytes，Requester 貢獻的 SessionID 前半
    session_policy:     int   = 0x00     # Bit 0: TerminationPolicy
    random_data:        bytes = field(default_factory=lambda: os.urandom(32))
    exchange_data:      bytes = field(default_factory=bytes)  # DHE public key
    opaque_data:        bytes = field(default_factory=bytes)

    def encode(self) -> bytes:
        hdr = SpdmHeader(
            version=self.version,
            code=RequestCode.KEY_EXCHANGE,
            param1=self.meas_type,
            param2=self.slot_id,
        ).encode()
        payload = struct.pack("<H", self.req_session_id)
        payload += struct.pack("B", self.session_policy)
        payload += b'\x00'                               # Reserved
        nonce = self.random_data if len(self.random_data) == 32 else os.urandom(32)
        payload += nonce
        payload += self.exchange_data
        payload += struct.pack("<H", len(self.opaque_data))
        payload += self.opaque_data
        return hdr + payload

    @classmethod
    def decode(cls, data: bytes, dhe_key_size: int = 64) -> "KeyExchangeRequest":
        h = SpdmHeader.decode(data)
        obj = cls(version=h.version, meas_type=h.param1, slot_id=h.param2)
        if len(data) >= 12:
            obj.req_session_id, = struct.unpack_from("<H", data, 4)
            obj.session_policy  = data[6]
            obj.random_data     = data[8:40]
            obj.exchange_data   = data[40: 40 + dhe_key_size]
            off = 40 + dhe_key_size
            if off + 2 <= len(data):
                opaque_len, = struct.unpack_from("<H", data, off)
                obj.opaque_data = data[off + 2: off + 2 + opaque_len]
        return obj


@dataclass
class KeyExchangeRspResponse(SpdmMessage):
    """KEY_EXCHANGE_RSP Response (0x64)"""
    version:             int   = 0x13
    heartbeat_period:    int   = 0x00   # Param1
    param2:              int   = 0x00
    rsp_session_id:      int   = 0x0001
    mut_auth_requested:  int   = 0x00
    slot_id_param:       int   = 0x00
    random_data:         bytes = field(default_factory=lambda: os.urandom(32))
    exchange_data:       bytes = field(default_factory=bytes)
    meas_summary_hash:   bytes = field(default_factory=bytes)
    opaque_data:         bytes = field(default_factory=bytes)
    signature:           bytes = field(default_factory=bytes)
    responder_verify:    bytes = field(default_factory=bytes)

    @classmethod
    def decode(cls, data: bytes,
               dhe_key_size: int = 64,
               hash_size: int = 32,
               sig_size: int = 64,
               has_meas_hash: bool = False) -> "KeyExchangeRspResponse":
        h = SpdmHeader.decode(data)
        obj = cls(version=h.version,
                  heartbeat_period=h.param1,
                  param2=h.param2)
        off = 4
        obj.rsp_session_id,   = struct.unpack_from("<H", data, off); off += 2
        obj.mut_auth_requested = data[off]; off += 1
        obj.slot_id_param      = data[off]; off += 1
        obj.random_data        = data[off: off + 32]; off += 32
        obj.exchange_data      = data[off: off + dhe_key_size]; off += dhe_key_size
        if has_meas_hash:
            obj.meas_summary_hash = data[off: off + hash_size]; off += hash_size
        opaque_len, = struct.unpack_from("<H", data, off); off += 2
        obj.opaque_data = data[off: off + opaque_len]; off += opaque_len
        if sig_size and off + sig_size <= len(data):
            obj.signature = data[off: off + sig_size]; off += sig_size
        obj.responder_verify = data[off:]
        return obj

    def session_id_from(self, req_session_id: int) -> int:
        """合成完整 4-byte Session ID = Req(2) || Rsp(2)"""
        return (req_session_id << 16) | (self.rsp_session_id & 0xFFFF)
