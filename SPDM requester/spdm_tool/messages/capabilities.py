"""
messages/capabilities.py  —  GET_CAPABILITIES (0xE1) / CAPABILITIES (0x61)

DSP0274 Table 11 / Table 12
"""

from __future__ import annotations
import struct
from dataclasses import dataclass
from .base import SpdmMessage, SpdmHeader, RequestCode, ResponseCode


# ──────────────────────────────────────────────────────────────────────────────
# Capability Flags（DSP0274 Table 13/14）
# ──────────────────────────────────────────────────────────────────────────────

class ReqFlags:
    """Requester capability flags（CAPABILITIES Request Flags field）"""
    CERT_CAP                   = 1 << 1
    CHAL_CAP                   = 1 << 2   # Deprecated in 1.3+
    ENCRYPT_CAP                = 1 << 6
    MAC_CAP                    = 1 << 7
    MUT_AUTH_CAP               = 1 << 8
    KEY_EX_CAP                 = 1 << 9
    PSK_CAP_REQUESTER          = 1 << 10
    ENCAP_CAP                  = 1 << 12
    HBEAT_CAP                  = 1 << 13
    KEY_UPD_CAP                = 1 << 14
    HANDSHAKE_IN_THE_CLEAR_CAP = 1 << 15
    PUB_KEY_ID_CAP             = 1 << 16
    CHUNK_CAP                  = 1 << 17
    ALIAS_CERT_CAP             = 1 << 18
    SET_CERT_CAP               = 1 << 19
    CSR_CAP                    = 1 << 20
    CERT_INSTALL_RESET_CAP     = 1 << 21
    EP_INFO_CAP_NOTSIG         = 1 << 22
    EP_INFO_CAP_SIG            = 1 << 23
    MEL_CAP                    = 1 << 24
    EVENT_CAP                  = 1 << 25
    MULTI_KEY_CAP_ONLY         = 1 << 26
    MULTI_KEY_CAP_CONN         = 1 << 27
    GET_KEY_PAIR_INFO_CAP      = 1 << 28
    SET_KEY_PAIR_INFO_CAP      = 1 << 29


class RspFlags(ReqFlags):
    """Responder capability flags（同 ReqFlags，加上 Responder-only bits）"""
    CACHE_CAP                  = 1 << 0
    MEAS_CAP_NO_SIG            = 1 << 4
    MEAS_CAP_SIG               = 1 << 5
    MEAS_FRESH_CAP             = 1 << 11


# ──────────────────────────────────────────────────────────────────────────────
# Messages
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class GetCapabilitiesRequest(SpdmMessage):
    """
    GET_CAPABILITIES Request

    Byte 4:    CTExponent
    Byte 5:    Reserved
    Byte 6-7:  Reserved
    Byte 8-11: Flags (u32 LE)
    Byte 12-15: DataTransferSize (u32 LE)
    Byte 16-19: MaxSPDMmsgSize (u32 LE)
    """
    version:           int = 0x13
    param1:            int = 0x00
    param2:            int = 0x00
    ct_exponent:       int = 0x0E        # 2^14 µs ≒ 16 ms（預設值）
    flags:             int = (ReqFlags.CERT_CAP |
                              ReqFlags.ENCRYPT_CAP |
                              ReqFlags.MAC_CAP |
                              ReqFlags.KEY_EX_CAP |
                              ReqFlags.CHUNK_CAP)
    data_transfer_size: int = 0x1200     # 4608 bytes
    max_spdm_msg_size:  int = 0x1200

    _PAYLOAD_FMT = "<BBxxI II"  # ct_exp, reserved, reserved16, flags, dts, max

    def encode(self) -> bytes:
        hdr = SpdmHeader(
            version=self.version,
            code=RequestCode.GET_CAPABILITIES,
            param1=self.param1,
            param2=self.param2,
        ).encode()
        payload = struct.pack(
            "<B B 2x I I I",
            self.ct_exponent,
            0x00,               # Reserved
            self.flags,
            self.data_transfer_size,
            self.max_spdm_msg_size,
        )
        return hdr + payload

    @classmethod
    def decode(cls, data: bytes) -> "GetCapabilitiesRequest":
        h = SpdmHeader.decode(data)
        obj = cls(version=h.version, param1=h.param1, param2=h.param2)
        if len(data) >= 20:
            obj.ct_exponent, = struct.unpack_from("B", data, 4)
            obj.flags,       = struct.unpack_from("<I", data, 8)
            obj.data_transfer_size, = struct.unpack_from("<I", data, 12)
            obj.max_spdm_msg_size,  = struct.unpack_from("<I", data, 16)
        return obj


@dataclass
class CapabilitiesResponse(SpdmMessage):
    """CAPABILITIES Response (0x61)"""
    version:            int = 0x13
    param1:             int = 0x00
    param2:             int = 0x00
    ct_exponent:        int = 0x00
    flags:              int = 0x00
    data_transfer_size: int = 0x00
    max_spdm_msg_size:  int = 0x00

    def encode(self) -> bytes:
        hdr = SpdmHeader(
            version=self.version,
            code=ResponseCode.CAPABILITIES,
            param1=self.param1,
            param2=self.param2,
        ).encode()
        payload = struct.pack(
            "<B B 2x I I I",
            self.ct_exponent,
            0x00,
            self.flags,
            self.data_transfer_size,
            self.max_spdm_msg_size,
        )
        return hdr + payload

    @classmethod
    def decode(cls, data: bytes) -> "CapabilitiesResponse":
        h = SpdmHeader.decode(data)
        obj = cls(version=h.version, param1=h.param1, param2=h.param2)
        if len(data) >= 20:
            obj.ct_exponent, = struct.unpack_from("B", data, 4)
            obj.flags,       = struct.unpack_from("<I", data, 8)
            obj.data_transfer_size, = struct.unpack_from("<I", data, 12)
            obj.max_spdm_msg_size,  = struct.unpack_from("<I", data, 16)
        return obj

    def has_flag(self, flag: int) -> bool:
        return bool(self.flags & flag)

    def __repr__(self) -> str:
        return (f"CapabilitiesResponse(flags=0x{self.flags:08X}, "
                f"ct_exp={self.ct_exponent}, "
                f"dts={self.data_transfer_size}, "
                f"max={self.max_spdm_msg_size})")
