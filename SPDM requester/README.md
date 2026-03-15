# SPDM Requester Tool

針對 SSD 碟機的 SPDM 請求工具，用於驗證碟機韌體行為是否符合 DMTF DSP0274 規格。

支援版本：**v1.2.1、v1.2.3、v1.3.2、v1.4.0**

---

## 核心設計

**SPDM 協議邏輯全部在 Python，C 層只負責 Transport I/O。**

這個設計讓你可以：
- 用任意順序發送 SPDM 請求（包括故意送錯誤順序）
- 觀察碟機在非預期請求下回傳的 `0x7F ERROR` 錯誤碼
- 驗證碟機的 state machine 行為是否符合 Spec

---

## 系統需求

- Linux（使用 sysfs 存取 PCIe Config Space）
- Python 3.10+
- cmake + gcc（建置 C Transport Library）
- root 或 `CAP_SYS_RAWIO` 權限（存取 PCIe DOE 暫存器）

---

## 安裝

```bash
# 1. 安裝 Python 套件
pip install -e ".[dev]"

# 2. 建置 C Transport Library
cd c_layer && mkdir -p build && cd build
cmake .. && make
# → 產生 spdm_tool/transport/libspdm_transport.so
```

---

## 快速開始

```bash
# 列出系統上支援 PCIe DOE 的裝置
sudo spdm-tool list-devices

# 執行 VCA（Version + Capabilities + Algorithms）
sudo spdm-tool --vid 0x1234 --devid 0xAB28 vca

# 取得憑證鏈（自動執行 VCA）
sudo spdm-tool --vid 0x1234 --devid 0xAB28 get-certificate --slot 0

# 取得測量值
sudo spdm-tool --vid 0x1234 --devid 0xAB28 get-measurements --index 0xFF

# 執行 CHALLENGE 認證
sudo spdm-tool --vid 0x1234 --devid 0xAB28 challenge --slot 0
```

---

## State Machine 測試

這是本工具的核心用途：**故意送出非法順序，驗證碟機的錯誤回應是否正確**。

```bash
# 跳過 VCA，直接送 GET_CERTIFICATE → 預期碟機回 0x7F UnexpectedRequest
sudo spdm-tool --vid 0x1234 --devid 0xAB28 get-certificate --slot 0 --skip-vca

# 送出任意 raw bytes（最低階，無任何限制）
sudo spdm-tool --vid 0x1234 --devid 0xAB28 send-raw --hex "1082000000000000FFFF"
```

在 Python 中直接操作：

```python
from spdm_tool.transport.doe import DoeTransport
from spdm_tool.requester import SpdmRequester
from spdm_tool.messages.certificate import GetCertificateRequest
from spdm_tool.messages.error import ErrorResponse, ErrorCode

transport = DoeTransport(vid=0x1234, devid=0xAB28)
req = SpdmRequester(transport)

# 故意跳過 VCA，直接送 GET_CERTIFICATE
resp = req.send(GetCertificateRequest(slot_id=0))

assert isinstance(resp, ErrorResponse)
assert resp.error_code == ErrorCode.UNEXPECTED_REQUEST  # 驗證碟機行為正確
print(resp)  # ErrorResponse(UnexpectedRequest, data=0x00, ext=)
```

---

## 三層 API

| 層次 | 方法 | 說明 |
|------|------|------|
| 最低階 | `req.send_raw(bytes)` | 送任意 bytes，完全無限制 |
| 中階 | `req.send(SpdmMessage)` | 自動 encode/decode，不強制 state machine |
| 高階 | `req.do_vca()` 等 | 標準流程，自動更新協商狀態 |

---

## 架構

```
Python CLI (Click)
    ↓
SpdmRequester (requester.py)
  send_raw() / send() / do_vca() / ...
    ↓
SpdmMessage 子類別 (messages/)
  GetVersionRequest, ChallengeRequest, ErrorResponse ...
    ↓
Transport (transport/)
  DoeTransport  → libspdm_transport.so（PCIe DOE, 需要硬體）
  MockTransport → 無硬體測試用
    ↓
C Transport Layer (c_layer/)
  /sys/bus/pci/devices/<BDF>/config  (sysfs)
```

---

## 不需硬體的測試

所有單元測試與整合測試皆使用 `MockTransport`，可在無硬體環境中執行。

```bash
# 單元測試（訊息 encode/decode）
pytest tests/unit/

# 整合測試（state machine 錯誤回應驗證）
pytest tests/integration/

# 全部測試
pytest
```

`MockTransport` 使用範例：

```python
from spdm_tool.transport.mock import MockTransport
from spdm_tool.messages.error import ErrorResponse, ErrorCode

mock = MockTransport()
mock.queue_response(
    ErrorResponse(error_code=ErrorCode.UNEXPECTED_REQUEST).encode()
)

req = SpdmRequester(mock)
resp = req.send(GetCertificateRequest())
assert isinstance(resp, ErrorResponse)
```

---

## 專案結構

```
├── spdm_tool/
│   ├── cli/main.py          # Click CLI 入口
│   ├── requester.py         # 核心引擎（三層 API）
│   ├── messages/            # 每個 SPDM 命令對應一個檔案
│   │   ├── base.py          # SpdmHeader, RequestCode, ResponseCode
│   │   ├── error.py         # ErrorResponse + 完整 ErrorCode 表
│   │   └── ...
│   └── transport/
│       ├── doe.py           # ctypes 封裝 libspdm_transport.so
│       └── mock.py          # 測試用 Transport
├── c_layer/
│   ├── include/transport.h  # C API 定義
│   └── src/transport/
│       └── doe_transport.c  # PCIe DOE sysfs 實作
├── tests/
│   ├── unit/                # 訊息 encode/decode 測試
│   └── integration/         # State machine 驗證測試
└── Spec/                    # DMTF DSP0274 規格文件（PDF）
```

---

## 目前尚未實作

- Validation 框架（對照 Spec 規則驗證 response 欄位）
- Session 建立（KEY_EXCHANGE / FINISH）
- GET_CSR / SET_CERTIFICATE
- SMBus Transport（介面已預留）
