# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 專案目的

針對 SSD 碟機的 SPDM Requester 工具，用於驗證碟機 FW 行為是否符合 DMTF DSP0274 規格（支援 v1.2.1、v1.2.3、v1.3.2、v1.4.0）。

核心設計原則：**SPDM 協議邏輯完全在 Python，C 層只負責 Transport I/O**，讓 Python 層可自由控制訊息順序（包括故意送錯誤順序以測試 state machine）。

## 建置與執行

```bash
# 安裝 Python 套件
pip install -e ".[dev]"

# 建置 C Transport Library（需要 cmake + gcc，Linux only）
cd c_layer && mkdir -p build && cd build
cmake .. && make
# → 產生 spdm_tool/transport/libspdm_transport.so

# 執行單元測試（不需硬體）
pytest tests/unit/

# 執行 integration 測試（不需硬體，使用 MockTransport）
pytest tests/integration/

# CLI
spdm-tool --help
spdm-tool list-devices
spdm-tool --vid 0x1234 --devid 0xAB28 vca
spdm-tool --vid 0x1234 --devid 0xAB28 get-certificate --slot 0
spdm-tool --vid 0x1234 --devid 0xAB28 send-raw --hex "1084000000"
```

## 架構

```
Python CLI (Click)            ← spdm_tool/cli/main.py
    ↓
SpdmRequester                 ← spdm_tool/requester.py
  Layer 1: send_raw(bytes)    ← 無限制，可送任意順序
  Layer 2: send(SpdmMessage)  ← 自動 encode/decode
  Layer 3: do_vca() 等        ← 高階流程
    ↓
SpdmMessage 子類別            ← spdm_tool/messages/
  每個 SPDM 命令一個檔案，全欄位可自訂
    ↓
Transport (ctypes)            ← spdm_tool/transport/
  DoeTransport   → C libspdm_transport.so（PCIe DOE）
  MockTransport  → 無硬體測試用
    ↓
C Transport Layer             ← c_layer/src/transport/doe_transport.c
  直接操作 PCIe DOE 暫存器（需要 root）
```

## 重要設計決策

- **不使用 libspdm**：避免 libspdm state machine 限制，讓測試可故意送非法順序
- **三層 API**：`send_raw` → `send` → `do_xxx`，越低階自由度越高
- **MockTransport**：所有無硬體測試都用 MockTransport，在 CI 環境也可執行
- **Transcript 紀錄**：`requester._transcript` 記錄所有 TX/RX raw bytes，供 M1/M2/L1/L2 計算

## 關鍵檔案

- [spdm_tool/messages/base.py](spdm_tool/messages/base.py) — SPDM header + RequestCode/ResponseCode enum
- [spdm_tool/messages/error.py](spdm_tool/messages/error.py) — ErrorResponse + 完整 ErrorCode 對照表
- [spdm_tool/requester.py](spdm_tool/requester.py) — 核心引擎，三層 API
- [c_layer/include/transport.h](c_layer/include/transport.h) — C Transport API 定義
- [c_layer/src/transport/doe_transport.c](c_layer/src/transport/doe_transport.c) — PCIe DOE 實作

## Spec 參考

規格文件在 `Spec/` 目錄（已轉換為 .txt）：
- DSP0274_1.2.1.txt, DSP0274_1.2.3.txt
- DSP0274_1.3.2.txt, DSP0274_1.4.0.txt

## 尚未實作

- `validation/` — Spec 合規驗證規則
- Session 建立（KEY_EXCHANGE/FINISH）
- GET_CSR / SET_CERTIFICATE
- SMBus Transport（c_layer/src/transport/smbus_transport.c stub 已預留）
