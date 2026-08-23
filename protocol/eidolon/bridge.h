#ifndef EIDOLON_BRIDGE_H
#define EIDOLON_BRIDGE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void* EidolonHandle;

// Инициализация TCP (TLS 1.3) и UDP (QUIC / HTTP3)
// Функция возвращает управление сразу после инициализации асинхронной помпы данных.
EidolonHandle eidolon_dial_tcp(const char* host, uint16_t port, const uint8_t* token, size_t token_len, int data_fd);
EidolonHandle eidolon_dial_quic(const char* host, uint16_t port, const uint8_t* token, size_t token_len, int data_fd);

// Экспорт TLS-ключа (RFC 5705) для нашего внутреннего AEAD
int eidolon_export_key(EidolonHandle handle, uint8_t* out_key, size_t key_len);

// Жесткое закрытие сессии и освобождение файловых дескрипторов
void eidolon_close(EidolonHandle handle);

#ifdef __cplusplus
}
#endif

#endif // EIDOLON_BRIDGE_H