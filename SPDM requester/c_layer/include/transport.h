#ifndef SPDM_TRANSPORT_H
#define SPDM_TRANSPORT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ *
 * 回傳碼
 * ------------------------------------------------------------------ */
#define TRANSPORT_OK               0
#define TRANSPORT_ERR_NOT_FOUND   -1   /* 找不到指定 PCIe 裝置         */
#define TRANSPORT_ERR_BUSY        -2   /* DOE 忙碌超時                  */
#define TRANSPORT_ERR_IO          -3   /* 暫存器讀寫失敗                */
#define TRANSPORT_ERR_BUF_SMALL   -4   /* 提供的 buffer 不夠大          */
#define TRANSPORT_ERR_NO_DATA     -5   /* DOR 超時，沒有資料可讀        */
#define TRANSPORT_ERR_PARAM       -6   /* 參數錯誤                      */

/* ------------------------------------------------------------------ *
 * PCIe DOE Transport
 * ------------------------------------------------------------------ */

/**
 * doe_open - 開啟並定位 PCIe DOE 裝置
 *
 * @vid:    PCI Vendor ID (e.g. 0x1234)
 * @devid:  PCI Device ID (e.g. 0xAB28)
 *
 * 成功回傳不透明 handle (> 0)，失敗回傳 TRANSPORT_ERR_NOT_FOUND。
 * 需要 root 或 CAP_SYS_RAWIO 權限。
 */
int doe_open(uint16_t vid, uint16_t devid);

/**
 * doe_close - 關閉裝置並釋放資源
 */
void doe_close(int handle);

/**
 * doe_send - 透過 DOE Mailbox 發送 SPDM 訊息
 *
 * @handle:      doe_open 回傳的 handle
 * @buf:         要發送的資料（bytes）
 * @size:        資料長度（bytes），必須是 4 的倍數
 *
 * 回傳 TRANSPORT_OK 或負值錯誤碼。
 */
int doe_send(int handle, const uint8_t *buf, size_t size);

/**
 * doe_receive - 從 DOE Mailbox 接收 SPDM 回應
 *
 * @handle:      doe_open 回傳的 handle
 * @buf:         接收 buffer
 * @buf_size:    buffer 大小
 * @out_size:    實際接收到的資料長度（bytes）
 * @timeout_ms:  等待逾時（毫秒），0 表示無限等待
 *
 * 回傳 TRANSPORT_OK 或負值錯誤碼。
 */
int doe_receive(int handle, uint8_t *buf, size_t buf_size,
                size_t *out_size, uint32_t timeout_ms);

/**
 * doe_enumerate - 列出系統上所有支援 DOE 的 PCIe 裝置
 *
 * @out_vids:    輸出 VID 陣列（由呼叫端提供，長度 max_count）
 * @out_devids:  輸出 DevID 陣列
 * @max_count:   陣列最大筆數
 *
 * 回傳找到的裝置數量，負值表示錯誤。
 */
int doe_enumerate(uint16_t *out_vids, uint16_t *out_devids, int max_count);

/* ------------------------------------------------------------------ *
 * SMBus Transport（預留介面，後續實作）
 * ------------------------------------------------------------------ */

int smbus_open(int bus, uint8_t addr);
void smbus_close(int handle);
int smbus_send(int handle, const uint8_t *buf, size_t size);
int smbus_receive(int handle, uint8_t *buf, size_t buf_size,
                  size_t *out_size, uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* SPDM_TRANSPORT_H */
