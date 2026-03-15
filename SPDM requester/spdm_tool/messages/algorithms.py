"""
messages/algorithms.py  —  NEGOTIATE_ALGORITHMS (0xE3) / ALGORITHMS (0x63)

DSP0274 Table 15~25
"""

from __future__ import annotations
import struct
from dataclasses import dataclass, field
from .base import SpdmMessage, SpdmHeader, RequestCode, ResponseCode


# ──────────────────────────────────────────────────────────────────────────────
# Algorithm bitmask 常數（DSP0274 Table 18/20）
# ──────────────────────────────────────────────────────────────────────────────

class BaseAsymAlgo:
    RSASSA_2048        = 1 << 0
    RSAPSS_2048        = 1 << 1
    RSASSA_3072        = 1 << 2
    RSAPSS_3072        = 1 << 3
    ECDSA_P256         = 1 << 4
    RSASSA_4096        = 1 << 5
    RSAPSS_4096        = 1 << 6
    ECDSA_P384         = 1 << 7
    ECDSA_P521         = 1 << 8
    SM2_P256           = 1 << 9
    EDDSA_ED25519      = 1 << 10
    EDDSA_ED448        = 1 << 11


class BaseHashAlgo:
    SHA_256            = 1 << 0
    SHA_384            = 1 << 1
    SHA_512            = 1 << 2
    SHA3_256           = 1 << 3
    SHA3_384           = 1 << 4
    SHA3_512           = 1 << 5
    SM3_256            = 1 << 6


class DheGroup:
    FFDHE_2048         = 1 << 0
    FFDHE_3072         = 1 << 1
    FFDHE_4096         = 1 << 2
    SECP_256_R1        = 1 << 3
    SECP_384_R1        = 1 << 4
    SECP_521_R1        = 1 << 5
    SM2_P256           = 1 << 6


class AeadCipher:
    AES_128_GCM        = 1 << 0
    AES_256_GCM        = 1 << 1
    CHACHA20_POLY1305  = 1 << 2
    AEAD_SM4_GCM       = 1 << 3


class KeySchedule:
    SPDM               = 1 << 0


class MeasSpec:
    DMTF               = 1 << 0


# AlgType for ReqAlgStruct
class AlgType:
    DHE            = 0x02
    AEAD           = 0x03
    REQ_BASE_ASYM  = 0x04
    KEY_SCHEDULE   = 0x05


# ──────────────────────────────────────────────────────────────────────────────
# Algorithm Structure（ReqAlgStruct）
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class AlgStruct:
    """
    4-byte algorithm structure (DSP0274 Table 22)
    Byte 0: AlgType
    Byte 1: AlgCount  [7:4]=FixedAlgCount, [3:0]=ExtAlgCount
    Byte 2-3: AlgSupported (bitmask, LE)
    """
    alg_type:      int = 0
    alg_supported: int = 0   # bitmask of supported algorithms
    ext_count:     int = 0

    def encode(self) -> bytes:
        alg_count = (1 << 4) | (self.ext_count & 0xF)  # 1 fixed struct
        return struct.pack("<B B H", self.alg_type, alg_count, self.alg_supported)

    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> "AlgStruct":
        alg_type, alg_count, alg_supported = struct.unpack_from("<B B H", data, offset)
        ext_count = alg_count & 0xF
        return cls(alg_type=alg_type, alg_supported=alg_supported, ext_count=ext_count)


# ──────────────────────────────────────────────────────────────────────────────
# NEGOTIATE_ALGORITHMS Request
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class NegotiateAlgorithmsRequest(SpdmMessage):
    """
    NEGOTIATE_ALGORITHMS Request (0xE3)

    Param1: Number of algorithm structures (ReqAlgStruct count)
    """
    version:       int = 0x13
    param1:        int = 0       # 會在 encode 時自動設為 alg_structs 的數量
    param2:        int = 0x00

    meas_spec:     int = MeasSpec.DMTF
    other_params:  int = 0x00    # OtherParamsSupport (opaque data format)
    base_asym:     int = BaseAsymAlgo.ECDSA_P256 | BaseAsymAlgo.ECDSA_P384
    base_hash:     int = BaseHashAlgo.SHA_256 | BaseHashAlgo.SHA_384
    mel_spec:      int = 0x00

    alg_structs: list[AlgStruct] = field(default_factory=lambda: [
        AlgStruct(AlgType.DHE,           DheGroup.SECP_256_R1 | DheGroup.SECP_384_R1),
        AlgStruct(AlgType.AEAD,          AeadCipher.AES_256_GCM | AeadCipher.CHACHA20_POLY1305),
        AlgStruct(AlgType.REQ_BASE_ASYM, BaseAsymAlgo.ECDSA_P256 | BaseAsymAlgo.ECDSA_P384),
        AlgStruct(AlgType.KEY_SCHEDULE,  KeySchedule.SPDM),
    ])

    def encode(self) -> bytes:
        num_structs = len(self.alg_structs)
        structs_bytes = b"".join(s.encode() for s in self.alg_structs)
        # Length = total message size（header + fixed fields + structs）
        # Fixed portion after header: 2(len) + 1(meas_spec) + 1(other_params) +
        #   4(base_asym) + 4(base_hash) + 12(reserved) + 1(ext_asym_cnt) +
        #   1(ext_hash_cnt) + 1(reserved) + 1(mel_spec) = 28 bytes
        length = SpdmHeader.SIZE + 28 + len(structs_bytes)
        hdr = SpdmHeader(
            version=self.version,
            code=RequestCode.NEGOTIATE_ALGORITHMS,
            param1=num_structs,
            param2=self.param2,
        ).encode()
        payload = struct.pack("<H", length)                    # Length (2)
        payload += struct.pack("B", self.meas_spec)            # MeasurementSpec (1)
        payload += struct.pack("B", self.other_params)         # OtherParamsSupport (1)
        payload += struct.pack("<I", self.base_asym)           # BaseAsymAlgo (4)
        payload += struct.pack("<I", self.base_hash)           # BaseHashAlgo (4)
        payload += b'\x00' * 12                                # Reserved (12)
        payload += struct.pack("B", 0)                         # ExtAsymCount (1)
        payload += struct.pack("B", 0)                         # ExtHashCount (1)
        payload += struct.pack("B", 0)                         # Reserved (1)
        payload += struct.pack("B", self.mel_spec)             # MELspecification (1)
        payload += structs_bytes
        return hdr + payload

    @classmethod
    def decode(cls, data: bytes) -> "NegotiateAlgorithmsRequest":
        h = SpdmHeader.decode(data)
        obj = cls(version=h.version, param1=h.param1, param2=h.param2)
        if len(data) >= 32:
            obj.meas_spec,  = struct.unpack_from("B", data, 6)
            obj.other_params, = struct.unpack_from("B", data, 7)
            obj.base_asym,  = struct.unpack_from("<I", data, 8)
            obj.base_hash,  = struct.unpack_from("<I", data, 12)
            obj.mel_spec,   = struct.unpack_from("B", data, 31)
            num_structs = h.param1
            obj.alg_structs = []
            offset = 32
            for _ in range(num_structs):
                if offset + 4 > len(data):
                    break
                obj.alg_structs.append(AlgStruct.decode(data, offset))
                offset += 4
        return obj


# ──────────────────────────────────────────────────────────────────────────────
# ALGORITHMS Response
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class AlgorithmsResponse(SpdmMessage):
    """ALGORITHMS Response (0x63)"""
    version:           int = 0x13
    param1:            int = 0
    param2:            int = 0x00

    meas_spec_sel:     int = 0
    other_params_sel:  int = 0
    base_asym_sel:     int = 0   # 選定的單一算法（非 bitmask）
    base_hash_sel:     int = 0

    alg_structs: list[AlgStruct] = field(default_factory=list)

    def encode(self) -> bytes:
        num_structs = len(self.alg_structs)
        structs_bytes = b"".join(s.encode() for s in self.alg_structs)
        length = SpdmHeader.SIZE + 28 + len(structs_bytes)
        hdr = SpdmHeader(
            version=self.version,
            code=ResponseCode.ALGORITHMS,
            param1=num_structs,
            param2=self.param2,
        ).encode()
        payload = struct.pack("<H", length)
        payload += struct.pack("B", self.meas_spec_sel)
        payload += struct.pack("B", self.other_params_sel)
        payload += struct.pack("<I", self.base_asym_sel)
        payload += struct.pack("<I", self.base_hash_sel)
        payload += b'\x00' * 12
        payload += struct.pack("BBBB", 0, 0, 0, 0)
        payload += structs_bytes
        return hdr + payload

    @classmethod
    def decode(cls, data: bytes) -> "AlgorithmsResponse":
        h = SpdmHeader.decode(data)
        obj = cls(version=h.version, param1=h.param1, param2=h.param2)
        if len(data) >= 32:
            obj.meas_spec_sel,   = struct.unpack_from("B", data, 6)
            obj.other_params_sel, = struct.unpack_from("B", data, 7)
            obj.base_asym_sel,   = struct.unpack_from("<I", data, 8)
            obj.base_hash_sel,   = struct.unpack_from("<I", data, 12)
            num_structs = h.param1
            obj.alg_structs = []
            offset = 32
            for _ in range(num_structs):
                if offset + 4 > len(data):
                    break
                obj.alg_structs.append(AlgStruct.decode(data, offset))
                offset += 4
        return obj

    def get_dhe_sel(self) -> int:
        for s in self.alg_structs:
            if s.alg_type == AlgType.DHE:
                return s.alg_supported
        return 0

    def get_aead_sel(self) -> int:
        for s in self.alg_structs:
            if s.alg_type == AlgType.AEAD:
                return s.alg_supported
        return 0
