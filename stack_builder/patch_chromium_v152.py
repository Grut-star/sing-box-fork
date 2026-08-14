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
    if "eidolon_active" in content or "eidolon_token" in content:
        if "ProofVerifyContextChromium" not in content or "eidolon_active" in content:
            print(f"[~] Already patched: {filepath}")
            return

    count_to_replace = 0 if replace_all else 1
    new_content, count = re.subn(pattern, replacement, content, count=count_to_replace, flags=flags)

    if count == 0:
        print(f"[!] Failed to find pattern in: {filepath}")
        sys.exit(1)

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

    # 4. QUIC: Обход проверки сертификата (применяем ко всем методам: VerifyProof и VerifyCertChain)
    apply_patch(
        'net/quic/crypto/proof_verifier_chromium.cc',
        r'(const ProofVerifyContextChromium\* chromium_context =\n\s*reinterpret_cast<const ProofVerifyContextChromium\*>\(verify_context\);)',
        r'\1\n\n  // EIDOLON HOOK: Обход проверки сертификата\n'
        r'  if (chromium_context && chromium_context->eidolon_active) {\n'
        r'    *error_details = "";\n'
        r'    return quic::QUIC_SUCCESS;\n'
        r'  }\n',
        replace_all=True # Заменит в обоих местах
    )

    # 5. TCP: Внедрение токена в SSL сокет
    # Так как вы не скинули метод SSLClientSocketImpl::Init(), мы цепляемся
    # за стандартный вызов SSL_set_app_data, который всегда есть в Chromium
    apply_patch(
        'net/socket/ssl_client_socket_impl.cc',
        r'(SSL_set_app_data\(ssl_\.get\(\), this\);)',
        r'\1\n\n  // EIDOLON: Передаем токен вниз в BoringSSL\n'
        r'  if (ssl_config_.eidolon_active) {\n'
        r'    ssl_config_.ignore_certificate_errors = true;\n'
        r'    SSL_set_ex_data(ssl_.get(), 0, (void*)ssl_config_.eidolon_token.data());\n'
        r'  }\n'
    )

if __name__ == '__main__':
    main()