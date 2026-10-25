#ifndef EIDOLON_BRIDGE_H
#define EIDOLON_BRIDGE_H

#include <stdint.h>
#include <stddef.h>

// Макрос для экспорта функций в динамическую библиотеку (.so / .dll)
#if defined(_WIN32)
#define EIDOLON_EXPORT __declspec(dllexport)
#else
#define EIDOLON_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef void* EidolonHandle;

// Колбэк защиты сокета (Android VpnService.protect): получает fd, возвращает 0 при успехе.
// Регистрируется один раз из Go; нативный стек зовёт его на свой сокет до connect,
// иначе сокет ядра уходит обратно в TUN (см. диагностику -102 ERR_CONNECTION_REFUSED).
typedef int (*EidolonProtectFunc)(int fd);
EIDOLON_EXPORT void eidolon_set_protect(EidolonProtectFunc cb);

// Инициализация TCP (TLS 1.3) и UDP (QUIC / HTTP3)
// Функция возвращает управление сразу после инициализации асинхронной помпы данных.
EIDOLON_EXPORT EidolonHandle eidolon_dial_tcp(const char* host, uint16_t port, const uint8_t* token, size_t token_len, uintptr_t data_fd);
EIDOLON_EXPORT EidolonHandle eidolon_dial_quic(const char* host, uint16_t port, const uint8_t* token, size_t token_len, uintptr_t data_fd);
// Фаза 2 перехода на MoQ: дозвон/listen по MoQT (WebTransport-over-H3).
// datagram_fd (Фаза 4) — второй FD к Go под ненадёжный датаграм-lane (0 = выкл).
// network_handle — underlying Android-сеть (Network.getNetworkHandle()); несущий
// QUIC-сокет привязывается к ней в обход VpnService-TUN (0 = kInvalidNetworkHandle).
EIDOLON_EXPORT EidolonHandle eidolon_dial_moqt(const char* host, uint16_t port, const uint8_t* token, size_t token_len, uintptr_t data_fd, uintptr_t datagram_fd, int64_t network_handle);

// Экспорт TLS-ключа (RFC 5705) для нашего внутреннего AEAD
EIDOLON_EXPORT int eidolon_export_key(EidolonHandle handle, uint8_t* out_key, size_t key_len);

// Чтение, запись и закрытие (читаем/пишем напрямую через FD в Go, поэтому read/write тут опциональны)
// Жесткое закрытие сессии и освобождение файловых дескрипторов
EIDOLON_EXPORT int eidolon_read(EidolonHandle handle, uint8_t* buffer, size_t buffer_len);
EIDOLON_EXPORT int eidolon_write(EidolonHandle handle, const uint8_t* buffer, size_t buffer_len);
EIDOLON_EXPORT void eidolon_close(EidolonHandle handle);

// Фаза 3 Этап C — миграция несущего QUIC/MoQT-соединения на другую сеть Android
// (Wi-Fi<->сота) без разрыва туннеля. network_handle — из ConnectivityManager
// (Network.getNetworkHandle()). No-op для не-MoQT сессий.
EIDOLON_EXPORT void eidolon_migrate(EidolonHandle handle, int64_t network_handle);

// Фаза 4 FC-3 — телеметрия несущего QUIC-соединения для receiver-driven flow
// control (адаптив FEC в пределах свободной ёмкости). Мгновенный снимок
// congestion-контроллера несущей MoQT-сессии. eidolon_get_stats возвращает 0
// при успехе (out заполнен), -1 если сессия не MoQT / не готова / закрыта.
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

EIDOLON_EXPORT EidolonHandle eidolon_listen_quic(const char* host, uint16_t port, const uint8_t* secret, size_t secret_len, uintptr_t go_callback_port);
EIDOLON_EXPORT EidolonHandle eidolon_listen_moqt(const char* host, uint16_t port, const uint8_t* secret, size_t secret_len, uintptr_t go_callback_port, uintptr_t datagram_cb_port);

EIDOLON_EXPORT void eidolon_init();

#ifdef __cplusplus
}
#endif

#endif // EIDOLON_BRIDGE_H