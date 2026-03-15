"""
requester.py

SPDM Requester 引擎 — 提供三個操作層次：

  Layer 1  send_raw(bytes) → bytes
           最低階。直接把任意 bytes 送出並收回 raw bytes。
           不做任何驗證，可送出非法順序、非法欄位的訊息。

  Layer 2  send(SpdmMessage) → SpdmMessage
           中階。自動 encode/decode，回傳 parsed SpdmMessage。
           不強制 state machine。

  Layer 3  各 do_xxx() 輔助方法
           高階。包含常見流程（VCA、取憑證鏈等），並可選擇啟用 validator。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from .messages.base import SpdmMessage, RawSpdmMessage, SpdmHeader, ResponseCode
from .messages.error import ErrorResponse
from .messages.version import GetVersionRequest, VersionResponse
from .messages.capabilities import GetCapabilitiesRequest, CapabilitiesResponse
from .messages.algorithms import NegotiateAlgorithmsRequest, AlgorithmsResponse
from .messages.digests import GetDigestsRequest, DigestsResponse
from .messages.certificate import GetCertificateRequest, CertificateResponse
from .messages.challenge import ChallengeRequest, ChallengeAuthResponse
from .messages.measurements import GetMeasurementsRequest, MeasurementsResponse
from .messages.end_session import EndSessionRequest, EndSessionAckResponse

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Transport 抽象介面（由 transport/doe.py 實作）
# ──────────────────────────────────────────────────────────────────────────────

class Transport:
    def send(self, data: bytes) -> None:
        raise NotImplementedError

    def receive(self, timeout_ms: int = 5000) -> bytes:
        raise NotImplementedError

    def close(self) -> None:
        pass


# ──────────────────────────────────────────────────────────────────────────────
# 協商結果快取
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class NegotiatedState:
    """VCA 完成後協商到的參數，供後續訊息 decode 使用"""
    spdm_version:    int = 0x13
    hash_size:       int = 32    # bytes（SHA-256 預設）
    sig_size:        int = 64    # bytes（ECDSA P-256 預設）
    dhe_key_size:    int = 64    # bytes（SECP_256_R1 預設）
    base_asym_sel:   int = 0
    base_hash_sel:   int = 0
    dhe_sel:         int = 0
    aead_sel:        int = 0
    ct_exponent:     int = 0
    responder_flags: int = 0


# ──────────────────────────────────────────────────────────────────────────────
# Requester 主類別
# ──────────────────────────────────────────────────────────────────────────────

class SpdmRequester:
    """
    SPDM Requester 引擎。

    範例：
        transport = DoeTransport(vid=0x1234, devid=0xAB28)
        req = SpdmRequester(transport)

        # 低階：送任意 bytes
        raw = req.send_raw(bytes.fromhex("1084000000"))
        print(raw.hex())

        # 中階：送 message object，自動解析回應
        resp = req.send(GetVersionRequest())

        # 高階：走標準流程
        req.do_vca()
        req.do_get_certificate(slot=0)
    """

    def __init__(self, transport: Transport,
                 default_version: int = 0x13,
                 timeout_ms: int = 5000):
        self.transport     = transport
        self.default_ver   = default_version
        self.timeout_ms    = timeout_ms
        self.negotiated    = NegotiatedState(spdm_version=default_version)

        # 原始訊息紀錄（用於 M1/M2/L1/L2 transcript 計算）
        self._transcript: list[bytes] = []

    # ──────────────────────────────────────────────────────────────────────────
    # Layer 1：最低階，完全不限制
    # ──────────────────────────────────────────────────────────────────────────

    def send_raw(self, data: bytes) -> bytes:
        """
        直接送出任意 bytes，回傳 raw response bytes。
        不解析、不驗證。適合測試邊界行為（故意送錯誤順序、非法欄位）。
        """
        logger.debug("TX raw [%d bytes]: %s", len(data), data.hex())
        self.transport.send(data)
        resp = self.transport.receive(self.timeout_ms)
        logger.debug("RX raw [%d bytes]: %s", len(resp), resp.hex())
        self._transcript.append(data)
        self._transcript.append(resp)
        return resp

    # ──────────────────────────────────────────────────────────────────────────
    # Layer 2：中階，送 message object，自動解析
    # ──────────────────────────────────────────────────────────────────────────

    def send(self, request: SpdmMessage) -> SpdmMessage:
        """
        送出 SpdmMessage，回傳 parsed SpdmMessage。
        不強制 state machine，可以自由順序送出任何訊息。
        """
        raw_req  = request.encode()
        raw_resp = self.send_raw(raw_req)
        parsed   = SpdmMessage.from_bytes(raw_resp)
        logger.info("TX %r  →  RX %r", request, parsed)
        return parsed

    def send_expect(self, request: SpdmMessage,
                    expected_code: int) -> SpdmMessage:
        """
        送出 request，若 response code 不是 expected_code 則丟出例外。
        錯誤回應（0x7F）永遠被接受並解析為 ErrorResponse，不丟例外。
        """
        resp = self.send(request)
        if isinstance(resp, ErrorResponse):
            logger.warning("Received ERROR: %r", resp)
            return resp
        # 取 response code：直接讀 raw[1]，避免重新 encode/decode
        raw  = resp.encode()
        code = raw[1] if len(raw) >= 2 else 0
        if code != expected_code:
            raise UnexpectedResponseError(
                expected=expected_code, got=code, response=resp)
        return resp

    # ──────────────────────────────────────────────────────────────────────────
    # Layer 3：高階輔助方法
    # ──────────────────────────────────────────────────────────────────────────

    def do_get_version(self) -> VersionResponse | ErrorResponse:
        """
        發送 GET_VERSION，更新 negotiated.spdm_version 為最高共同支援版本。
        GET_VERSION 會重置碟機的 state machine，可隨時呼叫。
        """
        self._transcript.clear()   # GET_VERSION 重置 transcript
        resp = self.send_expect(
            GetVersionRequest(),
            expected_code=ResponseCode.VERSION,
        )
        if isinstance(resp, VersionResponse) and resp.entries:
            # 選最高版本
            best = max(resp.entries, key=lambda e: (e.major, e.minor))
            self.negotiated.spdm_version = (best.major << 4) | best.minor
            logger.info("Negotiated SPDM version: %s", best.to_string())
        return resp

    def do_get_capabilities(self,
                            flags: Optional[int] = None,
                            ct_exponent: int = 0x0E,
                            data_transfer_size: int = 0x1200,
                            max_msg_size: int = 0x1200,
                            ) -> CapabilitiesResponse | ErrorResponse:
        req = GetCapabilitiesRequest(
            version=self.negotiated.spdm_version,
            ct_exponent=ct_exponent,
            data_transfer_size=data_transfer_size,
            max_spdm_msg_size=max_msg_size,
        )
        if flags is not None:
            req.flags = flags
        resp = self.send_expect(req, expected_code=ResponseCode.CAPABILITIES)
        if isinstance(resp, CapabilitiesResponse):
            self.negotiated.responder_flags = resp.flags
            self.negotiated.ct_exponent     = resp.ct_exponent
        return resp

    def do_negotiate_algorithms(self,
                                request: Optional[NegotiateAlgorithmsRequest] = None,
                                ) -> AlgorithmsResponse | ErrorResponse:
        if request is None:
            request = NegotiateAlgorithmsRequest(version=self.negotiated.spdm_version)
        resp = self.send_expect(request, expected_code=ResponseCode.ALGORITHMS)
        if isinstance(resp, AlgorithmsResponse):
            self.negotiated.base_asym_sel = resp.base_asym_sel
            self.negotiated.base_hash_sel = resp.base_hash_sel
            self.negotiated.dhe_sel       = resp.get_dhe_sel()
            self.negotiated.aead_sel      = resp.get_aead_sel()
            self.negotiated.hash_size     = _hash_size(resp.base_hash_sel)
            self.negotiated.sig_size      = _sig_size(resp.base_asym_sel)
            self.negotiated.dhe_key_size  = _dhe_key_size(resp.get_dhe_sel())
        return resp

    def do_vca(self) -> tuple[VersionResponse | ErrorResponse,
                              CapabilitiesResponse | ErrorResponse,
                              AlgorithmsResponse | ErrorResponse]:
        """
        執行 VCA 三步驟（Version → Capabilities → Algorithms）。
        回傳三個 response 的 tuple。
        """
        v = self.do_get_version()
        c = self.do_get_capabilities()
        a = self.do_negotiate_algorithms()
        return v, c, a

    def do_get_digests(self) -> DigestsResponse | ErrorResponse:
        resp = self.send_expect(
            GetDigestsRequest(version=self.negotiated.spdm_version),
            expected_code=ResponseCode.DIGESTS,
        )
        return resp

    def do_get_certificate(self, slot: int = 0) -> bytes | ErrorResponse:
        """
        自動分段讀取完整憑證鏈，回傳完整 DER bytes。
        """
        cert_data = b""
        offset = 0
        while True:
            req = GetCertificateRequest(
                version=self.negotiated.spdm_version,
                slot_id=slot,
                offset=offset,
                length=0x0400,   # 每次請求 1KB
            )
            resp = self.send_expect(req, expected_code=ResponseCode.CERTIFICATE)
            if isinstance(resp, ErrorResponse):
                return resp
            assert isinstance(resp, CertificateResponse)
            cert_data += resp.cert_chain_data
            offset     += resp.portion_length
            if resp.is_last_chunk:
                break
        logger.info("Certificate chain: %d bytes, slot=%d", len(cert_data), slot)
        return cert_data

    def do_challenge(self, slot: int = 0,
                     meas_type: int = 0x00) -> ChallengeAuthResponse | ErrorResponse:
        resp = self.send_expect(
            ChallengeRequest(
                version=self.negotiated.spdm_version,
                slot_id=slot,
                meas_type=meas_type,
            ),
            expected_code=ResponseCode.CHALLENGE_AUTH,
        )
        return resp

    def do_get_measurements(self, index: int = 0xFF,
                             request_sig: bool = True,
                             slot: int = 0) -> MeasurementsResponse | ErrorResponse:
        resp = self.send_expect(
            GetMeasurementsRequest(
                version=self.negotiated.spdm_version,
                request_sig=request_sig,
                index=index,
                slot_id=slot,
            ),
            expected_code=ResponseCode.MEASUREMENTS,
        )
        return resp

    def do_end_session(self, session_id: Optional[int] = None,
                       ) -> EndSessionAckResponse | ErrorResponse:
        return self.send_expect(
            EndSessionRequest(version=self.negotiated.spdm_version),
            expected_code=ResponseCode.END_SESSION_ACK,
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Transcript 存取（供 validation 計算 M1/M2）
    # ──────────────────────────────────────────────────────────────────────────

    def transcript_bytes(self) -> bytes:
        return b"".join(self._transcript)

    def clear_transcript(self) -> None:
        self._transcript.clear()


# ──────────────────────────────────────────────────────────────────────────────
# 例外
# ──────────────────────────────────────────────────────────────────────────────

class UnexpectedResponseError(Exception):
    def __init__(self, expected: int, got: int, response: SpdmMessage):
        self.expected = expected
        self.got      = got
        self.response = response
        super().__init__(
            f"Expected response 0x{expected:02X}, got 0x{got:02X}: {response!r}")


# ──────────────────────────────────────────────────────────────────────────────
# 算法大小查詢輔助（依協商結果推算）
# ──────────────────────────────────────────────────────────────────────────────

def _hash_size(base_hash_sel: int) -> int:
    from .messages.algorithms import BaseHashAlgo
    if base_hash_sel & (BaseHashAlgo.SHA_512 | BaseHashAlgo.SHA3_512):
        return 64
    if base_hash_sel & (BaseHashAlgo.SHA_384 | BaseHashAlgo.SHA3_384):
        return 48
    return 32  # SHA-256 / SM3

def _sig_size(base_asym_sel: int) -> int:
    from .messages.algorithms import BaseAsymAlgo
    if base_asym_sel & BaseAsymAlgo.ECDSA_P521:
        return 132
    if base_asym_sel & BaseAsymAlgo.ECDSA_P384:
        return 96
    if base_asym_sel & (BaseAsymAlgo.RSASSA_4096 | BaseAsymAlgo.RSAPSS_4096):
        return 512
    if base_asym_sel & (BaseAsymAlgo.RSASSA_3072 | BaseAsymAlgo.RSAPSS_3072):
        return 384
    if base_asym_sel & (BaseAsymAlgo.RSASSA_2048 | BaseAsymAlgo.RSAPSS_2048):
        return 256
    return 64  # ECDSA P-256 / EdDSA

def _dhe_key_size(dhe_sel: int) -> int:
    from .messages.algorithms import DheGroup
    if dhe_sel & DheGroup.SECP_521_R1:
        return 132
    if dhe_sel & DheGroup.SECP_384_R1:
        return 96
    if dhe_sel & DheGroup.FFDHE_4096:
        return 512
    if dhe_sel & DheGroup.FFDHE_3072:
        return 384
    if dhe_sel & DheGroup.FFDHE_2048:
        return 256
    return 64  # SECP_256_R1
