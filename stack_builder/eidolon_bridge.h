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

// Фаза 6 — сервис-прикрытие (Вариант 3). Публичный MoQ-трек прикрытия в том же ядре:
// сервер анонсирует подписчикам namespace (ns=="" => per-session правдоподобный) + трек
// track; при реальной подписке коннектит cover_cb_port к Go, получает кадры
// [len:2 BE][payload] и публикует их datagram-объектами (on-demand). Вызывать ДО
// eidolon_listen_moqt; не вызван — прикрытие выкл.
EIDOLON_EXPORT void eidolon_cover_configure(uint16_t cover_cb_port, const char* ns, const char* track);

// P5.4 — app-private директория для персистентного session-cache (тикеты резумпции
// переживают перезапуск процесса). Зовётся из Go ДО первого дозвона; пусто/NULL => выкл.
// С диска восстанавливается ТОЛЬКО 1-RTT (0-RTT запрещён: anti-replay гибнет с процессом).
EIDOLON_EXPORT void eidolon_set_resumption_cache_dir(const char* dir);

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

// Weaver W1 #4 — JA4 enforcement (native-first, both lanes). allow — массив JA4-строк
// (санкционированные стеки); n==0 => выключено (всех пускаем). Копируется внутрь нативки,
// Go-буфер после вызова свободен. Вызывать ДО eidolon_listen_quic/moqt.
// Layout/сигнатура обязаны совпадать с protocol/eidolon/bridge.h (ABI cgo<->нативка).
EIDOLON_EXPORT void eidolon_ja4_configure(const char* const* allow, size_t n);

// Считает JA4 сырого ClientHello через BoringSSL. hello начинается с legacy_version
// (record+handshake заголовки сняты), как требует SSL_parse_client_hello. transport —
// 't' (TLS/TCP) или 'q' (QUIC). Пишет NUL-терминированную строку в out (<= out_len),
// возвращает её длину (без NUL) или <0 при ошибке разбора.
EIDOLON_EXPORT int eidolon_ja4_compute(const uint8_t* hello, size_t hello_len,
                                       char transport, char* out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif // EIDOLON_BRIDGE_H