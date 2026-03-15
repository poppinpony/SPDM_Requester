"""
messages/challenge.py  —  CHALLENGE (0x83) / CHALLENGE_AUTH (0x03)

DSP0274 Table 44/45（1.3）
"""

from __future__ import annotations
import os
import struct
from dataclasses import dataclass, field
from .base import SpdmMessage, SpdmHeader, RequestCode, ResponseCode


class MeasHashType:
    """Param1（CHALLENGE）/ Param2（GET_MEASUREMENTS）的測量摘要類型"""
    NONE    = 0x00
    TCB     = 0x01
    ALL     = 0xFF


@dataclass
class ChallengeRequest(SpdmMessage):
    """
    CHALLENGE Request (0x83)

    Param1: SlotID（0~7 或 0xFF for provisioned public key）
    Param2: MeasurementSummaryHashType
    Payload: Nonce（32 bytes random）
    """
    version:   int   = 0x13
    slot_id:   int   = 0              # Param1
    meas_type: int   = MeasHashType.NONE  # Param2
    nonce:     bytes = field(default_factory=lambda: os.urandom(32))

    def encode(self) -> bytes:
        nonce = self.nonce if len(self.nonce) == 32 else os.urandom(32)
        hdr = SpdmHeader(
            version=self.version,
            code=RequestCode.CHALLENGE,
            param1=self.slot_id,
            param2=self.meas_type,
        ).encode()
        return hdr + nonce

    @classmethod
    def decode(cls, data: bytes) -> "ChallengeRequest":
        h = SpdmHeader.decode(data)
        nonce = data[4:36] if len(data) >= 36 else b'\x00' * 32
        return cls(version=h.version, slot_id=h.param1,
                   meas_type=h.param2, nonce=nonce)


@dataclass
class ChallengeAuthResponse(SpdmMessage):
    """
    CHALLENGE_AUTH Response (0x03)

    Param1: BasicMutAuthReq（Bit 0）
    Param2: SlotMask

    Payload:
      CertChainHash        (H bytes)  — 協商 hash 大小
      Nonce                (32 bytes) — Responder 亂數
      MeasurementSummaryHash (H bytes，僅當 CHALLENGE.Param2 ≠ 0)
      OpaqueDataLength     (2 bytes LE)
      OpaqueData           (variable)
      Signature            (SigLen bytes)
    """
    version:             int   = 0x13
    param1:              int   = 0x00
    slot_mask:           int   = 0x00   # Param2
    cert_chain_hash:     bytes = field(default_factory=bytes)
    nonce:               bytes = field(default_factory=bytes)
    meas_summary_hash:   bytes = field(default_factory=bytes)
    opaque_data:         bytes = field(default_factory=bytes)
    signature:           bytes = field(default_factory=bytes)

    def encode(self) -> bytes:
        hdr = SpdmHeader(
            version=self.version,
            code=ResponseCode.CHALLENGE_AUTH,
            param1=self.param1,
            param2=self.slot_mask,
        ).encode()
        payload = self.cert_chain_hash
        payload += self.nonce
        payload += self.meas_summary_hash
        payload += struct.pack("<H", len(self.opaque_data))
        payload += self.opaque_data
        payload += self.signature
        return hdr + payload

    @classmethod
    def decode(cls, data: bytes,
               hash_size: int = 32,
               sig_size: int = 64,
               has_meas_hash: bool = False) -> "ChallengeAuthResponse":
        """
        hash_size:     協商的 hash 大小（SHA-256=32, SHA-384=48, SHA-512=64）
        sig_size:      簽名大小（依算法，ECDSA P-256=64, P-384=96）
        has_meas_hash: 若 CHALLENGE.Param2 ≠ 0 則為 True
        """
        h = SpdmHeader.decode(data)
        offset = SpdmHeader.SIZE

        cert_chain_hash = data[offset: offset + hash_size]
        offset += hash_size

        nonce = data[offset: offset + 32]
        offset += 32

        meas_summary_hash = b""
        if has_meas_hash:
            meas_summary_hash = data[offset: offset + hash_size]
            offset += hash_size

        opaque_len = 0
        opaque_data = b""
        if offset + 2 <= len(data):
            opaque_len, = struct.unpack_from("<H", data, offset)
            offset += 2
            opaque_data = data[offset: offset + opaque_len]
            offset += opaque_len

        signature = data[offset: offset + sig_size]

        return cls(
            version=h.version,
            param1=h.param1,
            slot_mask=h.param2,
            cert_chain_hash=cert_chain_hash,
            nonce=nonce,
            meas_summary_hash=meas_summary_hash,
            opaque_data=opaque_data,
            signature=signature,
        )

    def __repr__(self) -> str:
        return (f"ChallengeAuthResponse("
                f"slot_mask=0x{self.slot_mask:02X}, "
                f"cert_hash={self.cert_chain_hash.hex()[:12]}..., "
                f"sig_len={len(self.signature)})")
