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

    # 1. SSLConfig: секрет для HMAC. Токен (nonce||tag) считается внутри BoringSSL
    #    над key_share, поэтому наверх отдаём только мастер-секрет.
    apply_patch(
        'net/ssl/ssl_config.h',
        r'(bool ignore_certificate_errors = false;)',
        r'\1\n\n  // EIDOLON: привязка токена к key_share\n'
        r'  bool eidolon_active = false;\n'
        r'  std::vector<uint8_t> eidolon_secret;\n'
    )

    # 2a. BoringSSL: заголовки для HMAC / time / vector
    apply_patch(
        'third_party/boringssl/src/ssl/handshake_client.cc',
        r'#include "internal.h"',
        r'#include <time.h>\n'
        r'#include <vector>\n'
        r'#include <openssl/hmac.h>\n'
        r'#include "internal.h"'
    )

    # 2b. BoringSSL: SessionID = nonce || HMAC(secret, window || nonce || key_share_bytes).
    #     Инъекция ПОСЛЕ ssl_setup_key_shares (key_share_bytes уже готов) и ДО
    #     ssl_add_client_hello (ClientHello ещё не сериализован). Это даёт реальную
    #     привязку токена к эфемерному ключу клиента.
    apply_patch(
        'third_party/boringssl/src/ssl/handshake_client.cc',
        r'if \(!ssl_setup_pre_shared_keys\(hs\) \|\|\s*//\s*'
        r'!ssl_setup_key_shares\(hs, /\*override_group_id=\*/0\) \|\|\s*'
        r'!ssl_setup_extension_permutation\(hs\) \|\|\s*'
        r'!ssl_encrypt_client_hello\(hs, Span\(ech_enc, ech_enc_len\)\) \|\|\s*'
        r'!ssl_add_client_hello\(hs\)\) \{\s*return ssl_hs_error;\s*\}',
        r'if (!ssl_setup_pre_shared_keys(hs) ||\n'
        r'      !ssl_setup_key_shares(hs, /*override_group_id=*/0)) {\n'
        r'    return ssl_hs_error;\n'
        r'  }\n'
        r'\n'
        r'  // EIDOLON key_share binding (eidolon_active)\n'
        r'  {\n'
        r'    const std::vector<uint8_t>* eidolon_secret =\n'
        r'        static_cast<const std::vector<uint8_t>*>(SSL_get_ex_data(ssl, 0));\n'
        r'    if (eidolon_secret != nullptr && !eidolon_secret->empty()) {\n'
        r'      uint8_t eidolon_nonce[16];\n'
        r'      RAND_bytes(eidolon_nonce, sizeof(eidolon_nonce));\n'
        r'      uint64_t eidolon_window = (uint64_t)(time(nullptr) / 5);\n'
        r'      std::vector<uint8_t> eidolon_input;\n'
        r'      eidolon_input.reserve(8 + 16 + hs->key_share_bytes.size());\n'
        r'      for (int i = 0; i < 8; i++) {\n'
        r'        eidolon_input.push_back((uint8_t)((eidolon_window >> ((7 - i) * 8)) & 0xff));\n'
        r'      }\n'
        r'      eidolon_input.insert(eidolon_input.end(), eidolon_nonce, eidolon_nonce + 16);\n'
        r'      eidolon_input.insert(eidolon_input.end(), hs->key_share_bytes.data(),\n'
        r'                           hs->key_share_bytes.data() + hs->key_share_bytes.size());\n'
        r'      uint8_t eidolon_mac[SHA256_DIGEST_LENGTH];\n'
        r'      unsigned eidolon_mac_len = 0;\n'
        r'      if (HMAC(EVP_sha256(), eidolon_secret->data(), eidolon_secret->size(),\n'
        r'               eidolon_input.data(), eidolon_input.size(), eidolon_mac,\n'
        r'               &eidolon_mac_len) != nullptr && eidolon_mac_len >= 16) {\n'
        r'        hs->session_id.ResizeForOverwrite(32);\n'
        r'        OPENSSL_memcpy(hs->session_id.data(), eidolon_nonce, 16);\n'
        r'        OPENSSL_memcpy(hs->session_id.data() + 16, eidolon_mac, 16);\n'
        r'      }\n'
        r'    }\n'
        r'  }\n'
        r'\n'
        r'  if (!ssl_setup_extension_permutation(hs) ||\n'
        r'      !ssl_encrypt_client_hello(hs, Span(ech_enc, ech_enc_len)) ||\n'
        r'      !ssl_add_client_hello(hs)) {\n'
        r'    return ssl_hs_error;\n'
        r'  }'
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

    # 5. TCP: передаём СЕКРЕТ вниз в BoringSSL (токен считается там над key_share)
    apply_patch(
        'net/socket/ssl_client_socket_impl.cc',
        r'(if \(!ssl_ \|\| !context->SetClientSocketForSSL\(ssl_\.get\(\), this\)\)[\s\n]*return ERR_UNEXPECTED;)',
        r'\1\n\n'
        r'  // EIDOLON: передаём секрет в BoringSSL для привязки токена к key_share\n'
        r'  if (ssl_config_.eidolon_active) {\n'
        r'    ssl_config_.ignore_certificate_errors = true;\n'
        r'    SSL_set_ex_data(ssl_.get(), 0, (void*)&ssl_config_.eidolon_secret);\n'
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
        r'          UNSAFE_BUFFERS(base::span<uint8_t>(result, result_len)).copy_from(base::as_byte_span(exported_key).first(result_len));\n'
        r'          return true;\n'
        r'        }\n'
        r'      }\n'
        r'      return false;\n'
        r'    }\n'
    )

    # 10. MoQT (Фаза 0 перехода на MoQ): quiche содержит реализацию Media over QUIC
    #     Transport (src/quiche/quic/moqt/*), но Chromium НЕ собирает её ни в один
    #     GN-таргет (списки moqt_srcs/moqt_hdrs из source_list.gni нигде не исполь-
    #     зуются). Инъектируем source_set("moqt") перед component("quiche"), чтобы
    #     libeidolon мог на него залинковаться. Пока БЕЗ tools/ (moqt_server/relay/
    #     client/chat) — они тянут event-loop и CLI-флаги; серверные tools подключим
    #     на Фазе 6 отдельным таргетом. WebTransport-over-H3 уже в ядре quiche
    #     (web_transport_http3.cc в quiche_core_srcs), отдельной правки не требует.
    apply_patch(
        'net/third_party/quiche/BUILD.gn',
        r'component\("quiche"\) \{',
        r'source_set("moqt") {\n'
        r'  testonly = true\n'
        r'  sources = moqt_srcs + moqt_hdrs\n'
        r'  sources -= [\n'
        r'    "src/quiche/quic/moqt/tools/chat_client.cc",\n'
        r'    "src/quiche/quic/moqt/tools/moq_chat.cc",\n'
        r'    "src/quiche/quic/moqt/tools/moqt_client.cc",\n'
        r'    "src/quiche/quic/moqt/tools/moqt_relay.cc",\n'
        r'    "src/quiche/quic/moqt/tools/moqt_server.cc",\n'
        r'  ]\n'
        r'  configs += [ ":quiche_internal_config" ]\n'
        r'  public_configs = [ ":quiche_config" ]\n'
        r'  cflags = [\n'
        r'    # Шим operator<< для AbslStringify-типов moqt (пишется build.sh).\n'
        r'    "-include", rebase_path("//net/eidolon/moqt_ostream_shims.h", root_build_dir),\n'
        r'    # Глушим style-варнинги апстрим-кода quiche moqt (не наш код): он\n'
        r'    # никогда не собирался под строгие флаги Chromium, отсюда ~2000 строк шума.\n'
        r'    "-Wno-inconsistent-missing-override",\n'
        r'    "-Wno-extra-semi",\n'
        r'    "-Wno-deprecated-copy",\n'
        r'    "-Wno-unused-private-field",\n'
        r'  ]\n'
        r'  deps = [\n'
        r'    "//base",\n'
        r'    "//net",\n'
        r'    "//url",\n'
        r'    ":quiche",\n'
        r'  ]\n'
        r'}\n'
        r'\n'
        r'component("quiche") {'
    )

    # 10a. A1 (Фаза 5): серверный GSO batch-writer. QuicGsoBatchWriter и его группа
    #      (quic_batch_writer_base/buffer, quic_sendmmsg_batch_writer, quic_linux_socket_utils)
    #      лежат в linux_only_srcs, но Chromium НЕ линкует их ни в один GN-таргет →
    #      mold: undefined symbol QuicGsoBatchWriter при линковке libeidolon. Тянем группу
    #      в static_library("epoll_tool_support"): он Linux-only (if build_epoll_based_tools),
    #      libeidolon его уже линкует (оттуда QuicServerIoHarness/QuicDefaultPacketWriter),
    #      и в нём УЖЕ есть quic_syscall_wrapper.cc — единственная внешняя зависимость
    #      batch_writer. Значит все символы резолвятся в ОДНОМ таргете под теми же
    #      quiche-конфигами (без moqt-cflags/shim). linux_only_* в scope (source_list.gni).
    apply_patch(
        'net/third_party/quiche/BUILD.gn',
        r'io_tool_support_srcs \+ io_tool_support_hdrs',
        r'io_tool_support_srcs + io_tool_support_hdrs +\n'
        r'              linux_only_srcs + linux_only_hdrs',
    )

    # 12. Connection Migration (Фаза 3, Этап C): Wi-Fi<->сота без teardown туннеля.
    #     DedicatedWebTransportHttp3Client владеет своим QUIC-соединением, сокетом и
    #     reader'ом, но НЕ использует QuicChromiumClientSession (её миграционный
    #     менеджер недоступен). Добавляем сфокусированный validate-then-migrate прямо
    #     на клиенте: объявляем метод+поля здесь, реализуем в eidolon_bridge.cc
    #     (is_component_build=false → один статический линк, приватный доступ ок).
    #     12a. include для типа QuicPathValidationContext в сигнатуре.
    apply_patch(
        'net/quic/dedicated_web_transport_http3_client.h',
        r'(#include "net/third_party/quiche/src/quiche/quic/core/quic_connection_id\.h")',
        r'\1\n'
        r'#include "net/third_party/quiche/src/quiche/quic/core/quic_path_validator.h"'
    )
    #     12b. Публичные точки входа миграции (вызываются из нативного моста и из
    #          result-delegate валидации пути).
    apply_patch(
        'net/quic/dedicated_web_transport_http3_client.h',
        r'(handles::NetworkHandle target_network\(\) const \{ return target_network_; \})',
        r'\1\n'
        r'\n'
        r'  // [EIDOLON] Миграция несущего QUIC-соединения на другую сеть Android\n'
        r'  // (Wi-Fi<->сота). Валидирует новый путь (PATH_CHALLENGE/RESPONSE), затем\n'
        r'  // переносит соединение на свежий сокет, привязанный к |network|; сессия\n'
        r'  // WebTransport/MoQT и все стримы сохраняются. Вызывать на сетевом потоке.\n'
        r'  void EidolonMigrateToNetwork(handles::NetworkHandle network);\n'
        r'  // Коммит/отмена из result-delegate валидации пути.\n'
        r'  void EidolonCommitMigration(\n'
        r'      std::unique_ptr<quic::QuicPathValidationContext> context);\n'
        r'  void EidolonAbortMigration();'
    )
    #     12c. Приватное состояние пробы миграции (сокет/writer/reader новой сети).
    apply_patch(
        'net/quic/dedicated_web_transport_http3_client.h',
        r'(  std::unique_ptr<QuicChromiumPacketReader> packet_reader_;)',
        r'\1\n'
        r'\n'
        r'  // [EIDOLON] Проба миграции: сокет/writer/reader новой сети до коммита.\n'
        r'  void EidolonOnProbeConnected(quic::QuicSocketAddress peer, int rv);\n'
        r'  std::unique_ptr<DatagramClientSocket> eidolon_probe_socket_;\n'
        r'  std::unique_ptr<QuicChromiumPacketReader> eidolon_probe_reader_;\n'
        r'  std::unique_ptr<QuicChromiumPacketWriter> eidolon_probe_writer_;'
    )

    # 11. MoQT keying material (Фаза 2): AEAD-ключ туннеля берём из TLS-экспортера
    #     несущего WebTransport/QUIC-соединения (channel binding), а НЕ из master_secret.
    #     webtransport::Session на H3 — это quic::WebTransportHttp3, который держит
    #     приватный QuicSpdySession* session_. Экспонируем его публичным аксессором,
    #     чтобы eidolon_bridge.cc (и клиент, и сервер) мог вызвать
    #     GetCryptoStream()->ExportKeyingMaterial("eidolon-traffic-key", ...).
    #     Один патч покрывает оба конца: тип WebTransportHttp3 одинаков на client/server.
    apply_patch(
        'net/third_party/quiche/src/quiche/quic/core/http/web_transport_http3.h',
        r'(WebTransportHttp3\(QuicSpdySession\* session, QuicSpdyStream\* connect_stream,\s*\n\s*WebTransportSessionId id\);)',
        r'\1\n'
        r'\n'
        r'  // [EIDOLON] Доступ к несущей QUIC-сессии для экспорта keying material\n'
        r'  // (channel-bound AEAD-ключ туннеля поверх WebTransport/MoQT).\n'
        r'  QuicSpdySession* eidolon_quic_session() { return session_; }'
    )


#     apply_patch(
#         'third_party/abseil-cpp/absl/base/internal/spinlock_win32.inc',
#         r'#include <windows\.h>',
#         r'#include <minwinbase.h>\n#include <windows.h>'
#     )

if __name__ == '__main__':
    main()