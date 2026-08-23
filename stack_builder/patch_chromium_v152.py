import re
import sys
import os

def apply_patch(filepath, pattern, replacement, flags=0, replace_all=False):
    if not os.path.exists(filepath):
        print(f"[-] File not found: {filepath}")
        sys.exit(1)

    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Защита от двойного патчинга
    if "eidolon_active" in content or "eidolon_token" in content or "GetSSL()" in content:
        if "ProofVerifyContextChromium" not in content or "eidolon_active" in content:
            print(f"[~] Already patched: {filepath}")
            return

    count_to_replace = 0 if replace_all else 1
    new_content, count = re.subn(pattern, replacement, content, count=count_to_replace, flags=flags)

    if count == 0:
        #print(f"[!] Failed to find pattern in: {filepath}")
        #sys.exit(1)
        # ВМЕСТО sys.exit(1) ПРОСТО ВЫХОДИМ ИЗ ФУНКЦИИ
        print(f"[!] Warning: Failed to find pattern in {filepath}. Skipping.")
        return

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(new_content)
    print(f"[+] Successfully patched: {filepath} ({count} changes)")

def main():
    print("=== Eidolon Chromium v152 Auto-Patcher ===")

    # 1. SSLConfig: Добавляем поля сразу после ignore_certificate_errors
    apply_patch(
        'net/ssl/ssl_config.h',
        r'(bool ignore_certificate_errors = false;)',
        r'\1\n\n  // EIDOLON: Контейнер для Context-Bound TOTP токена\n'
        r'  bool eidolon_active = false;\n'
        r'  std::array<uint8_t, 32> eidolon_token;\n'
    )

    # 2. BoringSSL: Перехватываем новую логику ResizeForOverwrite в v152
    apply_patch(
        'third_party/boringssl/src/ssl/handshake_client.cc',
        r'(hs->session_id\.ResizeForOverwrite\(SSL_MAX_SSL_SESSION_ID_LENGTH\);\n\s*)(if \(!RAND_bytes\(hs->session_id\.data\(\), hs->session_id\.size\(\)\)\) \{)',
        r'\1// EIDOLON HOOK: Подмена Session ID\n'
        r'        void* eidolon_token = SSL_get_ex_data(ssl, 0);\n'
        r'        if (eidolon_token != nullptr) {\n'
        r'          OPENSSL_memcpy(hs->session_id.data(), eidolon_token, 32);\n'
        r'        } else {\n'
        r'          \2\n'
        r'        }'
    )

    # 3. QUIC: Расширяем контекст
    apply_patch(
        'net/quic/crypto/proof_verifier_chromium.h',
        r'(int cert_verify_flags;\n\s*NetLogWithSource net_log;)',
        r'\1\n\n  // EIDOLON:\n  bool eidolon_active = false;'
    )

    # 4. QUIC: Обход проверки сертификата
    apply_patch(
        'net/quic/crypto/proof_verifier_chromium.cc',
        r'(const ProofVerifyContextChromium\* chromium_context =\n\s*reinterpret_cast<const ProofVerifyContextChromium\*>\(verify_context\);)',
        r'\1\n\n  // EIDOLON HOOK: Обход проверки сертификата\n'
        r'  if (chromium_context && chromium_context->eidolon_active) {\n'
        r'    *error_details = "";\n'
        r'    return quic::QUIC_SUCCESS;\n'
        r'  }\n',
        replace_all=True
    )

    # 5. TCP: Внедрение токена в SSL сокет (Обновлено под v152)
    apply_patch(
        'net/socket/ssl_client_socket_impl.cc',
        r'(if \(!ssl_ \|\| !context->SetClientSocketForSSL\(ssl_\.get\(\), this\)\)[\s\n]*return ERR_UNEXPECTED;)',
        r'\1\n\n'
        r'  // EIDOLON: Передаем токен вниз в BoringSSL\n'
        r'  if (ssl_config_.eidolon_active) {\n'
        r'    ssl_config_.ignore_certificate_errors = true;\n'
        r'    SSL_set_ex_data(ssl_.get(), 0, (void*)ssl_config_.eidolon_token.data());\n'
        r'  }\n'
    )

    # 6. TCP: Экспортируем GetSSL() для нашего моста
    # Ищем объявление метода IsConnectedAndIdle() и добавляем GetSSL() рядом с ним
    apply_patch(
        'net/socket/ssl_client_socket_impl.h',
        r'(bool IsConnectedAndIdle\(\) const override;)',
        r'\1\n\n  // EIDOLON: Доступ к низкоуровневому SSL объекту для экспорта ключей\n'
        r'  SSL* GetSSL() const { return ssl_.get(); }\n'
    )

    # 7. Mac OS 15 SDK fix: удаляем хардкод отсутствующих файлов Apple
    apply_patch(
        'build/modules/BUILD.gn',
        r'\s*"\$mac_sdk_path/usr/include/DarwinFoundation[1-3]\.modulemap",',
        r'',
        replace_all=True
    )

    # 8. Mac OS 15 SDK (XCode 16) fix for posix_spawn
    apply_patch(
        'base/process/launch_mac.cc',
        r'posix_spawn_file_actions_addchdir\(',
        r'posix_spawn_file_actions_addchdir_np(',
        replace_all=True
    )

    # 9. QUIC: Экспорт ключей (RFC 5705) для AEAD
    apply_patch(
        'net/quic/quic_chromium_client_session.h',
        r'(quic::ParsedQuicVersion GetQuicVersion\(\) const;)',
        r'\1\n\n    // EIDOLON: Expose TLS Exporter for QUIC\n'
        r'    bool ExportKeyingMaterial(std::string_view label, std::string_view context, uint8_t* result, size_t result_len) const {\n'
        r'      if (session_ && session_->GetMutableCryptoStream()) {\n'
        r'        std::string exported_key;\n'
        r'        if (session_->GetMutableCryptoStream()->ExportKeyingMaterial(label, context, result_len, &exported_key)) {\n'
        r'          base::span<uint8_t>(result, result_len).copy_from(base::as_byte_span(exported_key).first(result_len));\n'
        r'          return true;\n'
        r'        }\n'
        r'      }\n'
        r'      return false;\n'
        r'    }\n'
    )

if __name__ == '__main__':
    main()