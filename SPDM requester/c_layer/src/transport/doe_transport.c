/**
 * doe_transport.c
 *
 * PCIe DOE (Data Object Exchange) Transport Layer — Linux sysfs 實作
 *
 * 直接透過 /sys/bus/pci/devices/<BDF>/config 操作 PCI Config Space，
 * 不依賴 libpci 也不依賴 libspdm，讓 Python 層完全控制 SPDM 訊息流。
 *
 * 權限需求：root 或 CAP_SYS_RAWIO
 *
 * 參考規格：
 *   - PCIe Base Specification 6.x, Section 6.30 (DOE)
 *   - DMTF DSP0274 SPDM Specification
 */

#include "transport.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>

#include <fcntl.h>      /* open, O_RDWR, O_RDONLY */
#include <unistd.h>     /* pread, pwrite, close    */
#include <dirent.h>     /* opendir, readdir, closedir */

/* ------------------------------------------------------------------ *
 * DOE Extended Capability 暫存器偏移（PCIe Spec 6.x Table 6-30）
 * ------------------------------------------------------------------ */
#define DOE_CAP_ID              0x2E
#define DOE_REG_CTRL            0x08
#define DOE_REG_STATUS          0x0C
#define DOE_REG_WRITE_MAILBOX   0x10
#define DOE_REG_READ_MAILBOX    0x14

#define DOE_CTRL_ABORT          (1u << 0)
#define DOE_CTRL_GO             (1u << 31)

#define DOE_STATUS_BUSY         (1u << 0)
#define DOE_STATUS_ERROR        (1u << 2)
#define DOE_STATUS_DOR          (1u << 31)

#define PCI_CFG_EXT_CAP_BASE    0x100
#define PCI_CFG_EXT_CAP_SIZE    0x1000

#define SYSFS_PCI_DEVICES       "/sys/bus/pci/devices"

/* ------------------------------------------------------------------ *
 * Handle 結構
 * ------------------------------------------------------------------ */
#define MAX_HANDLES  8

typedef struct {
    int  valid;
    int  config_fd;
    int  doe_offset;
    char bdf[32];
} DoeHandle;

static DoeHandle g_handles[MAX_HANDLES];

/* ------------------------------------------------------------------ *
 * sysfs config space 讀寫
 * ------------------------------------------------------------------ */

static int cfg_read32(int fd, int offset, uint32_t *out) {
    return (pread(fd, out, 4, offset) == 4) ? TRANSPORT_OK : TRANSPORT_ERR_IO;
}

static int cfg_write32(int fd, int offset, uint32_t val) {
    return (pwrite(fd, &val, 4, offset) == 4) ? TRANSPORT_OK : TRANSPORT_ERR_IO;
}

/* ------------------------------------------------------------------ *
 * 時間工具
 * ------------------------------------------------------------------ */

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ------------------------------------------------------------------ *
 * DOE Extended Capability 搜尋
 * ------------------------------------------------------------------ */

static int find_doe_offset(int config_fd) {
    int offset = PCI_CFG_EXT_CAP_BASE;
    while (offset > 0 && offset < PCI_CFG_EXT_CAP_SIZE) {
        uint32_t header;
        if (cfg_read32(config_fd, offset, &header) != TRANSPORT_OK)
            break;
        if (header == 0 || header == 0xFFFFFFFF)
            break;
        if ((header & 0xFFFF) == DOE_CAP_ID)
            return offset;
        offset = (int)((header >> 20) & 0xFFF);
    }
    return -1;
}

/* ------------------------------------------------------------------ *
 * 共用等待邏輯（doe_wait_not_busy / doe_wait_dor 的共同核心）
 *
 * wait_bit:     要等待的 status bit（DOE_STATUS_BUSY 或 DOE_STATUS_DOR）
 * wait_for_set: 1 = 等待 bit 被設置；0 = 等待 bit 被清除
 * timeout_err:  逾時時回傳的錯誤碼
 * ------------------------------------------------------------------ */

static int doe_wait_status(DoeHandle *h, uint32_t timeout_ms,
                           uint32_t wait_bit, int wait_for_set,
                           int timeout_err) {
    uint64_t deadline = now_ms() + (timeout_ms == 0 ? 5000 : timeout_ms);
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 }; /* 1ms */

    while (1) {
        uint32_t status;
        if (cfg_read32(h->config_fd, h->doe_offset + DOE_REG_STATUS, &status) != TRANSPORT_OK)
            return TRANSPORT_ERR_IO;

        if (status & DOE_STATUS_ERROR) {
            cfg_write32(h->config_fd, h->doe_offset + DOE_REG_CTRL, DOE_CTRL_ABORT);
            return TRANSPORT_ERR_IO;
        }

        int condition = wait_for_set ? !!(status & wait_bit) : !(status & wait_bit);
        if (condition)
            return TRANSPORT_OK;

        if (timeout_ms != 0 && now_ms() > deadline)
            return timeout_err;

        nanosleep(&ts, NULL);
    }
}

static int doe_wait_not_busy(DoeHandle *h, uint32_t timeout_ms) {
    return doe_wait_status(h, timeout_ms, DOE_STATUS_BUSY, 0, TRANSPORT_ERR_BUSY);
}

static int doe_wait_dor(DoeHandle *h, uint32_t timeout_ms) {
    return doe_wait_status(h, timeout_ms, DOE_STATUS_DOR, 1, TRANSPORT_ERR_NO_DATA);
}

/* ------------------------------------------------------------------ *
 * 共用 PCIe 裝置掃描 helper
 *
 * 開啟 /sys/bus/pci/devices/<bdf>/config，讀取 VID/DID，
 * 尋找 DOE Extended Capability。
 * 成功回傳 config_fd（> 0）；失敗或不符合條件回傳 -1。
 * 呼叫端負責 close() 回傳的 fd。
 * ------------------------------------------------------------------ */

static int open_doe_config(const char *bdf,
                           uint16_t *out_vid, uint16_t *out_did,
                           int *out_doe_offset) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s/config", SYSFS_PCI_DEVICES, bdf);

    int fd = open(path, O_RDWR);
    if (fd < 0) return -1;

    uint32_t id_reg;
    if (cfg_read32(fd, 0x00, &id_reg) != TRANSPORT_OK) {
        close(fd);
        return -1;
    }

    int doe_off = find_doe_offset(fd);
    if (doe_off < 0) {
        close(fd);
        return -1;
    }

    if (out_vid)        *out_vid        = (uint16_t)(id_reg & 0xFFFF);
    if (out_did)        *out_did        = (uint16_t)(id_reg >> 16);
    if (out_doe_offset) *out_doe_offset = doe_off;
    return fd;
}

/* ------------------------------------------------------------------ *
 * 公開 API 實作
 * ------------------------------------------------------------------ */

int doe_open(uint16_t vid, uint16_t devid) {
    int slot = -1;
    for (int i = 0; i < MAX_HANDLES; i++) {
        if (!g_handles[i].valid) { slot = i; break; }
    }
    if (slot < 0) return TRANSPORT_ERR_PARAM;

    DIR *dir = opendir(SYSFS_PCI_DEVICES);
    if (!dir) {
        fprintf(stderr, "[doe] Cannot open %s: %s\n",
                SYSFS_PCI_DEVICES, strerror(errno));
        return TRANSPORT_ERR_NOT_FOUND;
    }

    int result = TRANSPORT_ERR_NOT_FOUND;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        uint16_t dev_vid, dev_did;
        int doe_off;
        int fd = open_doe_config(entry->d_name, &dev_vid, &dev_did, &doe_off);
        if (fd < 0) continue;

        if (dev_vid != vid || dev_did != devid) {
            close(fd);
            continue;
        }

        g_handles[slot].valid      = 1;
        g_handles[slot].config_fd  = fd;
        g_handles[slot].doe_offset = doe_off;
        snprintf(g_handles[slot].bdf, sizeof(g_handles[slot].bdf),
                 "%s", entry->d_name);

        fprintf(stderr, "[doe] Opened %s VID=0x%04X DID=0x%04X doe_offset=0x%X\n",
                entry->d_name, vid, devid, doe_off);
        result = slot;
        break;
    }
    closedir(dir);

    if (result == TRANSPORT_ERR_NOT_FOUND)
        fprintf(stderr, "[doe] Device VID=0x%04X DID=0x%04X with DOE not found\n",
                vid, devid);
    return result;
}

void doe_close(int handle) {
    if (handle < 0 || handle >= MAX_HANDLES || !g_handles[handle].valid)
        return;
    close(g_handles[handle].config_fd);
    memset(&g_handles[handle], 0, sizeof(DoeHandle));
}

int doe_send(int handle, const uint8_t *buf, size_t size) {
    if (handle < 0 || handle >= MAX_HANDLES || !g_handles[handle].valid)
        return TRANSPORT_ERR_PARAM;
    if (!buf || size == 0 || size % 4 != 0)
        return TRANSPORT_ERR_PARAM;

    DoeHandle *h = &g_handles[handle];

    int rc = doe_wait_not_busy(h, 2000);
    if (rc != TRANSPORT_OK) return rc;

    const uint32_t *dwords = (const uint32_t *)buf;
    size_t n = size / 4;
    for (size_t i = 0; i < n; i++) {
        rc = cfg_write32(h->config_fd,
                         h->doe_offset + DOE_REG_WRITE_MAILBOX,
                         dwords[i]);
        if (rc != TRANSPORT_OK) return rc;
    }

    return cfg_write32(h->config_fd, h->doe_offset + DOE_REG_CTRL, DOE_CTRL_GO);
}

int doe_receive(int handle, uint8_t *buf, size_t buf_size,
                size_t *out_size, uint32_t timeout_ms) {
    if (handle < 0 || handle >= MAX_HANDLES || !g_handles[handle].valid)
        return TRANSPORT_ERR_PARAM;
    if (!buf || !out_size || buf_size < 4)
        return TRANSPORT_ERR_PARAM;

    DoeHandle *h = &g_handles[handle];

    int rc = doe_wait_dor(h, timeout_ms);
    if (rc != TRANSPORT_OK) return rc;

    size_t bytes_read = 0;
    while (1) {
        uint32_t status;
        if (cfg_read32(h->config_fd, h->doe_offset + DOE_REG_STATUS, &status) != TRANSPORT_OK)
            return TRANSPORT_ERR_IO;
        if (!(status & DOE_STATUS_DOR))
            break;

        if (bytes_read + 4 > buf_size) {
            /* 排空 mailbox 避免裝置卡住 */
            uint32_t dummy;
            cfg_read32(h->config_fd, h->doe_offset + DOE_REG_READ_MAILBOX, &dummy);
            cfg_write32(h->config_fd, h->doe_offset + DOE_REG_READ_MAILBOX, 0);
            *out_size = bytes_read;
            return TRANSPORT_ERR_BUF_SMALL;
        }

        uint32_t dword;
        if (cfg_read32(h->config_fd, h->doe_offset + DOE_REG_READ_MAILBOX, &dword) != TRANSPORT_OK)
            return TRANSPORT_ERR_IO;
        memcpy(buf + bytes_read, &dword, 4);
        bytes_read += 4;

        cfg_write32(h->config_fd, h->doe_offset + DOE_REG_READ_MAILBOX, 0);
    }

    *out_size = bytes_read;
    return TRANSPORT_OK;
}

int doe_enumerate(uint16_t *out_vids, uint16_t *out_devids, int max_count) {
    if (!out_vids || !out_devids || max_count <= 0)
        return TRANSPORT_ERR_PARAM;

    DIR *dir = opendir(SYSFS_PCI_DEVICES);
    if (!dir) return TRANSPORT_ERR_IO;

    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && count < max_count) {
        if (entry->d_name[0] == '.') continue;

        uint16_t vid, did;
        int fd = open_doe_config(entry->d_name, &vid, &did, NULL);
        if (fd < 0) continue;

        close(fd);
        out_vids[count]   = vid;
        out_devids[count] = did;
        count++;
    }
    closedir(dir);
    return count;
}

/* ------------------------------------------------------------------ *
 * SMBus stub（預留，後續實作）
 * ------------------------------------------------------------------ */

int smbus_open(int bus, uint8_t addr) {
    (void)bus; (void)addr;
    fprintf(stderr, "[smbus] not yet implemented\n");
    return TRANSPORT_ERR_IO;
}
void smbus_close(int handle)  { (void)handle; }
int smbus_send(int handle, const uint8_t *buf, size_t size) {
    (void)handle; (void)buf; (void)size;
    return TRANSPORT_ERR_IO;
}
int smbus_receive(int handle, uint8_t *buf, size_t buf_size,
                  size_t *out_size, uint32_t timeout_ms) {
    (void)handle; (void)buf; (void)buf_size;
    (void)out_size; (void)timeout_ms;
    return TRANSPORT_ERR_IO;
}
