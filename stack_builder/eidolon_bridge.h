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
EIDOLON_EXPORT EidolonHandle eidolon_dial_moqt(const char* host, uint16_t port, const uint8_t* token, size_t token_len, uintptr_t data_fd);

// Серверный listen (только Linux): QUIC и MoQT. Мост к локальному ядру на cb_port.
EIDOLON_EXPORT EidolonHandle eidolon_listen_quic(const char* host, uint16_t port, const uint8_t* secret, size_t secret_len, uintptr_t cb_port);
EIDOLON_EXPORT EidolonHandle eidolon_listen_moqt(const char* host, uint16_t port, const uint8_t* secret, size_t secret_len, uintptr_t cb_port);

// Чтение, запись и закрытие
int eidolon_read(EidolonHandle handle, uint8_t* buffer, size_t buffer_len);
int eidolon_write(EidolonHandle handle, const uint8_t* buffer, size_t buffer_len);
void eidolon_close(EidolonHandle handle);

// Фаза 3 Этап C — миграция несущего QUIC/MoQT-соединения на другую сеть Android
// (Wi-Fi<->сота) без разрыва туннеля. network_handle — из ConnectivityManager
// (Network.getNetworkHandle()). No-op для не-MoQT сессий.
EIDOLON_EXPORT void eidolon_migrate(EidolonHandle handle, int64_t network_handle);

// Экспорт сессионного ключа для AEAD
int eidolon_export_key(EidolonHandle handle, uint8_t* out_key, size_t key_len);

#ifdef __cplusplus
}
#endif

#endif // EIDOLON_BRIDGE_H