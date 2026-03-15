"""
transport/doe.py

PCIe DOE Transport — Python ctypes 封裝 spdm_transport.so。

建置 C 層：
  cd c_layer && mkdir build && cd build
  cmake .. && make
  → 產生 ../spdm_tool/transport/libspdm_transport.so

使用方式：
  from spdm_tool.transport.doe import DoeTransport
  t = DoeTransport(vid=0x1234, devid=0xAB28)
  t.send(bytes.fromhex("108400000000"))
  resp = t.receive(timeout_ms=3000)
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
import sys
from pathlib import Path

from ..requester import Transport

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# 載入共享庫
# ──────────────────────────────────────────────────────────────────────────────

_LIB: ctypes.CDLL | None = None


def _find_lib() -> str:
    """尋找 libspdm_transport.so 的路徑（Linux only）"""
    if sys.platform != "linux":
        raise DoeTransportError("DoeTransport only supports Linux.")

    # 1. 同目錄（CMake 輸出位置）
    here = Path(__file__).parent
    for name in ("libspdm_transport.so", "spdm_transport.so"):
        candidate = here / name
        if candidate.exists():
            return str(candidate)

    # 2. 環境變數
    env = os.environ.get("SPDM_TRANSPORT_LIB")
    if env and Path(env).exists():
        return env

    raise FileNotFoundError(
        "Cannot find libspdm_transport.so.\n"
        "Build it with:\n"
        "  cd c_layer && mkdir -p build && cd build\n"
        "  cmake .. && make"
    )


def _load_lib() -> ctypes.CDLL:
    global _LIB
    if _LIB is not None:
        return _LIB
    lib = ctypes.CDLL(_find_lib())

    # doe_open(vid: u16, devid: u16) -> int
    lib.doe_open.argtypes  = [ctypes.c_uint16, ctypes.c_uint16]
    lib.doe_open.restype   = ctypes.c_int

    # doe_close(handle: int)
    lib.doe_close.argtypes = [ctypes.c_int]
    lib.doe_close.restype  = None

    # doe_send(handle, buf, size) -> int
    lib.doe_send.argtypes  = [ctypes.c_int,
                               ctypes.c_char_p,
                               ctypes.c_size_t]
    lib.doe_send.restype   = ctypes.c_int

    # doe_receive(handle, buf, buf_size, out_size*, timeout_ms) -> int
    lib.doe_receive.argtypes = [ctypes.c_int,
                                 ctypes.c_char_p,
                                 ctypes.c_size_t,
                                 ctypes.POINTER(ctypes.c_size_t),
                                 ctypes.c_uint32]
    lib.doe_receive.restype  = ctypes.c_int

    # doe_enumerate(out_vids*, out_devids*, max_count) -> int
    lib.doe_enumerate.argtypes = [ctypes.POINTER(ctypes.c_uint16),
                                   ctypes.POINTER(ctypes.c_uint16),
                                   ctypes.c_int]
    lib.doe_enumerate.restype  = ctypes.c_int

    _LIB = lib
    return lib


# ──────────────────────────────────────────────────────────────────────────────
# 錯誤碼（對應 transport.h）
# ──────────────────────────────────────────────────────────────────────────────

_ERR_MAP = {
     0: "OK",
    -1: "NOT_FOUND",
    -2: "BUSY",
    -3: "IO_ERROR",
    -4: "BUF_SMALL",
    -5: "NO_DATA",
    -6: "PARAM_ERROR",
}

def _check(rc: int, op: str) -> None:
    if rc != 0:
        msg = _ERR_MAP.get(rc, f"error {rc}")
        raise DoeTransportError(f"doe_{op}: {msg} (rc={rc})")


class DoeTransportError(IOError):
    pass


# ──────────────────────────────────────────────────────────────────────────────
# DoeTransport 類別
# ──────────────────────────────────────────────────────────────────────────────

_MAX_BUF = 0x2000   # 8192 bytes，LIBSPDM_MAX_SPDM_MSG_SIZE

class DoeTransport(Transport):
    """
    透過 PCIe DOE 與 SSD 通訊的 Transport 實作。
    需要 root 或 CAP_SYS_RAWIO 權限。
    """

    def __init__(self, vid: int, devid: int):
        self._lib    = _load_lib()
        self._handle = self._lib.doe_open(
            ctypes.c_uint16(vid),
            ctypes.c_uint16(devid),
        )
        if self._handle < 0:
            raise DoeTransportError(
                f"Cannot open PCIe device VID=0x{vid:04X} DevID=0x{devid:04X} "
                f"(rc={self._handle}). "
                "Check device is present and you have root privileges."
            )
        logger.info("DOE opened: VID=0x%04X DevID=0x%04X handle=%d",
                    vid, devid, self._handle)

    def send(self, data: bytes) -> None:
        # DOE 要求 4-byte 對齊 — 補 padding
        if len(data) % 4 != 0:
            data = data + b'\x00' * (4 - len(data) % 4)
        rc = self._lib.doe_send(
            ctypes.c_int(self._handle),
            data,
            ctypes.c_size_t(len(data)),
        )
        _check(rc, "send")

    def receive(self, timeout_ms: int = 5000) -> bytes:
        buf      = ctypes.create_string_buffer(_MAX_BUF)
        out_size = ctypes.c_size_t(0)
        rc = self._lib.doe_receive(
            ctypes.c_int(self._handle),
            buf,
            ctypes.c_size_t(_MAX_BUF),
            ctypes.byref(out_size),
            ctypes.c_uint32(timeout_ms),
        )
        _check(rc, "receive")
        return bytes(buf.raw[: out_size.value])

    def close(self) -> None:
        if self._handle >= 0:
            self._lib.doe_close(ctypes.c_int(self._handle))
            self._handle = -1

    def __enter__(self) -> "DoeTransport":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()


# ──────────────────────────────────────────────────────────────────────────────
# 工具函數：列出系統上支援 DOE 的裝置
# ──────────────────────────────────────────────────────────────────────────────

def list_doe_devices() -> list[tuple[int, int]]:
    """回傳 [(vid, devid), ...] 清單"""
    try:
        lib = _load_lib()
    except FileNotFoundError:
        return []
    max_devs = 32
    vids   = (ctypes.c_uint16 * max_devs)()
    devids = (ctypes.c_uint16 * max_devs)()
    count  = lib.doe_enumerate(vids, devids, max_devs)
    if count < 0:
        return []
    return [(int(vids[i]), int(devids[i])) for i in range(count)]
