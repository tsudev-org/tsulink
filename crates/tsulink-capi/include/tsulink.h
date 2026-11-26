/*
 * tsulink.h - C ABI của Tsu Link (ADR-0005). Viết tay; test `header_khop_ham_xuat` canh khớp với src/lib.rs.
 * Giấy phép Apache-2.0. Chuẩn: tsudev-standards docs/LOCAL_SYNC.md.
 *
 * Quy ước:
 *  - Mọi hàm trả int32_t: 0 = thành công, > 0 = mã lỗi (bảng dưới), -1 = lỗi nội bộ.
 *    Thông điệp lỗi của lần gọi hỏng gần nhất TRÊN LUỒNG ĐÓ: tsulink_last_error() (không giải phóng).
 *  - Chuỗi vào/ra là UTF-8 kết thúc NUL. Chuỗi ra (char**) giải phóng bằng tsulink_string_free;
 *    byte ra bằng tsulink_bytes_free. Kết quả có cấu trúc là JSON.
 *  - Đối tượng mờ giải phóng bằng hàm _free của nó (NULL thì bỏ qua). Dùng được từ nhiều luồng.
 *  - Hàm chờ (ghép đôi, đồng bộ, khám phá) CHẶN luồng gọi; huỷ bằng TsulinkCancel từ luồng khác.
 *  - Callback tiến độ chạy trên luồng nền của thư viện; không gọi ngược vào thư viện từ trong callback.
 *  - Luật L1: chỉ địa chỉ mạng nội bộ (RFC 1918, link-local, ULA); loopback và địa chỉ công cộng bị từ chối.
 */
#ifndef TSULINK_H
#define TSULINK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Mã lỗi ổn định (chỉ THÊM, không đổi). */
#define TSULINK_OK 0
#define TSULINK_PANIC (-1)
#define TSULINK_E_MALFORMED 1
#define TSULINK_E_BAD_FINGERPRINT 2
#define TSULINK_E_PUBLIC_ADDRESS 3
#define TSULINK_E_EXPIRED 4
#define TSULINK_E_RNG 5
#define TSULINK_E_IDENTITY 6
#define TSULINK_E_TLS 7
#define TSULINK_E_IO 8
#define TSULINK_E_TIMEOUT 9
#define TSULINK_E_IDLE_TIMEOUT 10
#define TSULINK_E_BACKUP 11
#define TSULINK_E_WRONG_PASSWORD 12
#define TSULINK_E_WEAK_PASSWORD 13
#define TSULINK_E_LOCKED 14
#define TSULINK_E_PAIRING_REJECTED 15
#define TSULINK_E_PROTOCOL 16
#define TSULINK_E_SCHEMA_MISMATCH 17
#define TSULINK_E_CLOCK_SKEW 18
#define TSULINK_E_CORRUPT 19
#define TSULINK_E_CANCELLED 20
#define TSULINK_E_INVALID_INPUT 21
#define TSULINK_E_CLOSED 22

typedef struct TsulinkNode TsulinkNode;
typedef struct TsulinkCancel TsulinkCancel;
typedef struct TsulinkPairingHost TsulinkPairingHost;
typedef struct TsulinkSas TsulinkSas;
typedef struct TsulinkListener TsulinkListener;
typedef struct TsulinkDiscovery TsulinkDiscovery;

/* (user, BLAKE3 tệp, byte đã có, tổng byte) */
typedef void (*TsulinkProgressCb)(void *user, const char *hash, uint64_t done, uint64_t total);

/* ---- chung ---- */
const char *tsulink_version(void);
const char *tsulink_last_error(void);
void tsulink_string_free(char *s);
void tsulink_bytes_free(uint8_t *p, size_t len);
int32_t tsulink_identity_generate(uint8_t **cert, size_t *cert_len, uint8_t **key, size_t *key_len);
int32_t tsulink_local_ips(char **out_json);
TsulinkCancel *tsulink_cancel_new(void);
void tsulink_cancel_trigger(const TsulinkCancel *c);
void tsulink_cancel_free(TsulinkCancel *c);

/* ---- thiết bị: config_json = {"data_dir","app","alias","schema_version"} ---- */
int32_t tsulink_node_open(const char *config_json, const uint8_t *cert, size_t cert_len, const uint8_t *key,
                          size_t key_len, TsulinkNode **out);
void tsulink_node_free(TsulinkNode *n);
int32_t tsulink_node_fingerprint(const TsulinkNode *n, char **out);
int32_t tsulink_node_write(const TsulinkNode *n, const char *table, const char *key, const char *value_json);
int32_t tsulink_node_delete(const TsulinkNode *n, const char *table, const char *key);
int32_t tsulink_node_read(const TsulinkNode *n, const char *table, const char *key, char **out_json_or_null);
int32_t tsulink_node_changes_after(const TsulinkNode *n, uint64_t after, uint32_t limit, char **out_json);
int32_t tsulink_node_purge_tombstones(const TsulinkNode *n, uint64_t *out_count);
int32_t tsulink_node_doc_ids(const TsulinkNode *n, char **out_json);
int32_t tsulink_node_doc_save(const TsulinkNode *n, const char *id, uint8_t **out_or_null, size_t *out_len);
int32_t tsulink_node_doc_merge(const TsulinkNode *n, const char *id, const uint8_t *data, size_t len);
int32_t tsulink_node_file_import(const TsulinkNode *n, const char *path, char **out_hash);
int32_t tsulink_node_file_path(const TsulinkNode *n, const char *hash, char **out_path_or_null);
int32_t tsulink_node_devices(const TsulinkNode *n, char **out_json);
int32_t tsulink_node_remove_device(const TsulinkNode *n, const char *fingerprint, int32_t *removed);
int32_t tsulink_node_prune_stale_devices(const TsulinkNode *n, uint64_t *out_count);

/* ---- ghép đôi ---- */
int32_t tsulink_pairing_host_open(const TsulinkNode *n, uint16_t port, TsulinkPairingHost **out);
void tsulink_pairing_host_free(TsulinkPairingHost *h);
int32_t tsulink_pairing_host_port(const TsulinkPairingHost *h, uint16_t *out);
int32_t tsulink_pairing_host_qr_uri(const TsulinkPairingHost *h, const char *ips_json_or_null, char **out_uri);
int32_t tsulink_pairing_host_accept_qr(const TsulinkPairingHost *h, const TsulinkCancel *cancel,
                                       char **out_device_json);
int32_t tsulink_pairing_host_accept_sas(const TsulinkPairingHost *h, uint64_t wait_secs,
                                        const TsulinkCancel *cancel, TsulinkSas **out);
int32_t tsulink_join_qr(const TsulinkNode *n, const char *uri, const TsulinkCancel *cancel, char **out_device_json);
int32_t tsulink_join_sas(const TsulinkNode *n, const char *addr, const TsulinkCancel *cancel, TsulinkSas **out);
int32_t tsulink_sas_info(const TsulinkSas *s, char **out_json);
int32_t tsulink_sas_finish(const TsulinkSas *s, int32_t confirmed, char **out_device_json);
void tsulink_sas_free(TsulinkSas *s);

/* ---- đồng bộ ---- */
int32_t tsulink_sync_with(const TsulinkNode *n, const char *peer, const char *addr, const char *wanted_json_or_null,
                          TsulinkProgressCb progress, void *user, const TsulinkCancel *cancel, char **out_report_json);
int32_t tsulink_listen(const TsulinkNode *n, uint16_t port, TsulinkListener **out);
int32_t tsulink_listener_port(const TsulinkListener *l, uint16_t *out);
int32_t tsulink_listener_serve_one(const TsulinkListener *l, const char *wanted_json_or_null,
                                   TsulinkProgressCb progress, void *user, const TsulinkCancel *cancel,
                                   char **out_json);
void tsulink_listener_free(TsulinkListener *l);

/* ---- khám phá ---- */
int32_t tsulink_discovery_start(const TsulinkNode *n, TsulinkDiscovery **out);
int32_t tsulink_discovery_announce(const TsulinkDiscovery *d, uint16_t port, uint32_t *sent);
int32_t tsulink_discovery_next(const TsulinkDiscovery *d, uint64_t wait_ms, const TsulinkCancel *cancel,
                               char **out_peer_json_or_null);
void tsulink_discovery_free(TsulinkDiscovery *d);

#ifdef __cplusplus
}
#endif

#endif /* TSULINK_H */
