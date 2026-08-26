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

// Инициализация TCP (TLS 1.3) и UDP (QUIC / HTTP3)
// Функция возвращает управление сразу после инициализации асинхронной помпы данных.
EIDOLON_EXPORT EidolonHandle eidolon_dial_tcp(const char* host, uint16_t port, const uint8_t* token, size_t token_len, uintptr_t data_fd);
EIDOLON_EXPORT EidolonHandle eidolon_dial_quic(const char* host, uint16_t port, const uint8_t* token, size_t token_len, uintptr_t data_fd);

// Экспорт TLS-ключа (RFC 5705) для нашего внутреннего AEAD
EIDOLON_EXPORT int eidolon_export_key(EidolonHandle handle, uint8_t* out_key, size_t key_len);

// Чтение, запись и закрытие (читаем/пишем напрямую через FD в Go, поэтому read/write тут опциональны)
// Жесткое закрытие сессии и освобождение файловых дескрипторов
EIDOLON_EXPORT int eidolon_read(EidolonHandle handle, uint8_t* buffer, size_t buffer_len);
EIDOLON_EXPORT int eidolon_write(EidolonHandle handle, const uint8_t* buffer, size_t buffer_len);
EIDOLON_EXPORT void eidolon_close(EidolonHandle handle);

EIDOLON_EXPORT void eidolon_init();

#ifdef __cplusplus
}
#endif

#endif // EIDOLON_BRIDGE_H