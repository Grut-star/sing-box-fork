#ifndef EIDOLON_BRIDGE_H
#define EIDOLON_BRIDGE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void* EidolonHandle;

// Инициализация TCP (TLS) и QUIC туннелей
EIDOLON_EXPORT EidolonHandle eidolon_dial_tcp(const char* host, uint16_t port, const uint8_t* token, size_t token_len, uintptr_t data_fd);
EIDOLON_EXPORT EidolonHandle eidolon_dial_quic(const char* host, uint16_t port, const uint8_t* token, size_t token_len, uintptr_t data_fd);
// Фаза 1 перехода на MoQ: дозвон по MoQT (WebTransport-over-H3).
// datagram_fd (Фаза 4) — второй FD к Go под ненадёжный датаграм-lane (0 = выкл).
EIDOLON_EXPORT EidolonHandle eidolon_dial_moqt(const char* host, uint16_t port, const uint8_t* token, size_t token_len, uintptr_t data_fd, uintptr_t datagram_fd, int64_t network_handle);

// Серверный listen (только Linux): QUIC и MoQT. Мост к локальному ядру на cb_port.
EIDOLON_EXPORT EidolonHandle eidolon_listen_quic(const char* host, uint16_t port, const uint8_t* secret, size_t secret_len, uintptr_t cb_port);
EIDOLON_EXPORT EidolonHandle eidolon_listen_moqt(const char* host, uint16_t port, const uint8_t* secret, size_t secret_len, uintptr_t cb_port, uintptr_t datagram_cb_port);

// Чтение, запись и закрытие
int eidolon_read(EidolonHandle handle, uint8_t* buffer, size_t buffer_len);
int eidolon_write(EidolonHandle handle, const uint8_t* buffer, size_t buffer_len);
void eidolon_close(EidolonHandle handle);

// Фаза 3 Этап C — миграция несущего QUIC/MoQT-соединения на другую сеть Android
// (Wi-Fi<->сота) без разрыва туннеля. network_handle — из ConnectivityManager
// (Network.getNetworkHandle()). No-op для не-MoQT сессий.
EIDOLON_EXPORT void eidolon_migrate(EidolonHandle handle, int64_t network_handle);

// Фаза 5 WP-4 — энергетический режим несущей (keep-alive heartbeat + wake-resync).
// state: 0=active, 1=background, 2=doze. No-op для не-MoQT/закрытых сессий.
EIDOLON_EXPORT void eidolon_set_power_state(EidolonHandle handle, int state);

// Экспорт сессионного ключа для AEAD
int eidolon_export_key(EidolonHandle handle, uint8_t* out_key, size_t key_len);

// Фаза 4 FC-3 — телеметрия несущего QUIC-соединения для receiver-driven flow
// control (адаптив FEC в пределах свободной ёмкости). Мгновенный снимок
// congestion-контроллера несущей MoQT-сессии. eidolon_get_stats возвращает 0
// при успехе (out заполнен), -1 если сессия не MoQT / не готова / закрыта.
// Layout обязан совпадать с protocol/eidolon/bridge.h (ABI cgo<->нативка).
typedef struct {
    uint64_t bandwidth_bps;   // BandwidthEstimate несущей, байт/с
    uint64_t cwnd_bytes;      // congestion window, байт
    uint64_t inflight_bytes;  // bytes in flight
    uint64_t smoothed_rtt_us; // сглаженный RTT, микросекунды
    uint64_t packets_lost;    // накопительно потеряно пакетов
    uint64_t ecn_ce;          // накопительно получено ECN-CE марок несущей
    uint64_t max_datagram;    // DPLPMTUD: макс. payload WT-датаграммы (без фрагментации)
} EidolonStats;

EIDOLON_EXPORT int eidolon_get_stats(EidolonHandle handle, EidolonStats* out);

#ifdef __cplusplus
}
#endif

#endif // EIDOLON_BRIDGE_H