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

    # 1. SSLConfig: Weaver W1 blob для привязки токена к key_share. eidolon_secret
    #    теперь несёт НЕ master_secret, а capKey(32)||D(32)||Data(>=36) (clientWeaverBlob,
    #    outbound_weaver.go). Сам слот wire_id||MAC считает BoringSSL над key_share.
    #    Имя поля eidolon_secret сохраняем (меняется семантика, не ABI).
    apply_patch(
        'net/ssl/ssl_config.h',
        r'(bool ignore_certificate_errors = false;)',
        r'\1\n\n  // EIDOLON: Weaver-blob (capKey||D||Data) для привязки токена к key_share\n'
        r'  bool eidolon_active = false;\n'
        r'  std::vector<uint8_t> eidolon_secret;\n'
    )

    # 2a. BoringSSL: заголовки для HMAC / HKDF / time / vector
    apply_patch(
        'third_party/boringssl/src/ssl/handshake_client.cc',
        r'#include "internal.h"',
        r'#include <time.h>\n'
        r'#include <vector>\n'
        r'#include <openssl/hmac.h>\n'
        r'#include <openssl/hkdf.h>\n'
        r'#include "internal.h"'
    )

    # 2b. BoringSSL: Weaver W1 слот. SessionID(32) = wire_id(8) || MAC(24), где
    #     wire_id = trunc8(HMAC-SHA256(capKey, "weaver-wireid-v1" || BE64(bucket5))),
    #     k = HKDF-SHA256(ikm=D||capKey, info="weaver-k-v1"),
    #     MAC = trunc24(HMAC-SHA256(k, "weaver-mac-v1" || Data || key_share || CtxTCP)).
    #     wire_id (а не случайный nonce, как в легаси) позволяет серверу ВЫБРАТЬ, под
    #     какой capKey проверять (один общий master_secret ушёл). Инъекция ПОСЛЕ
    #     ssl_setup_key_shares (key_share_bytes готов) и ДО ssl_add_client_hello. Сервер
    #     (inbound.go: Validator.Validate ctx=CtxTCP, exporter=key_share) индексирует cap
    #     по wire_id, реконструирует Data через cap.MarshalData() и пересчитывает MAC.
    #     Формулы — protocol/eidolon/weaver/primitives.go (byte-exact).
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
        r'  // EIDOLON weaver W1 key_share binding (eidolon_active).\n'
        r'  // ex_data(0) blob = capKey(32) || D(32) || Data(>=36). Slot = wire_id(8)||MAC(24).\n'
        r'  {\n'
        r'    const std::vector<uint8_t>* eidolon_blob =\n'
        r'        static_cast<const std::vector<uint8_t>*>(SSL_get_ex_data(ssl, 0));\n'
        r'    if (eidolon_blob != nullptr && eidolon_blob->size() >= 64) {\n'
        r'      const uint8_t* ew_capkey = eidolon_blob->data();\n'
        r'      const uint8_t* ew_d = eidolon_blob->data() + 32;\n'
        r'      const uint8_t* ew_data = eidolon_blob->data() + 64;\n'
        r'      size_t ew_data_len = eidolon_blob->size() - 64;\n'
        r'      uint64_t ew_bucket = (uint64_t)(time(nullptr) / 5);\n'
        r'      uint8_t ew_be_bucket[8];\n'
        r'      for (int i = 0; i < 8; i++) {\n'
        r'        ew_be_bucket[i] = (uint8_t)((ew_bucket >> ((7 - i) * 8)) & 0xff);\n'
        r'      }\n'
        r'      // wire_id = trunc8(HMAC-SHA256(capKey, "weaver-wireid-v1" || BE64(bucket)))\n'
        r'      static const char kEwWireLabel[] = "weaver-wireid-v1";  // 16 bytes\n'
        r'      std::vector<uint8_t> ew_wid_in;\n'
        r'      ew_wid_in.insert(ew_wid_in.end(), kEwWireLabel, kEwWireLabel + 16);\n'
        r'      ew_wid_in.insert(ew_wid_in.end(), ew_be_bucket, ew_be_bucket + 8);\n'
        r'      uint8_t ew_wid[SHA256_DIGEST_LENGTH];\n'
        r'      unsigned ew_wid_len = 0;\n'
        r'      HMAC(EVP_sha256(), ew_capkey, 32, ew_wid_in.data(), ew_wid_in.size(),\n'
        r'           ew_wid, &ew_wid_len);\n'
        r'      // k = HKDF-SHA256(ikm = D || capKey, salt = "", info = "weaver-k-v1")\n'
        r'      uint8_t ew_kin[64];\n'
        r'      OPENSSL_memcpy(ew_kin, ew_d, 32);\n'
        r'      OPENSSL_memcpy(ew_kin + 32, ew_capkey, 32);\n'
        r'      uint8_t ew_k[32];\n'
        r'      static const char kEwKLabel[] = "weaver-k-v1";  // 11 bytes\n'
        r'      int ew_hkdf_ok = HKDF(ew_k, sizeof(ew_k), EVP_sha256(), ew_kin,\n'
        r'                            sizeof(ew_kin), nullptr, 0,\n'
        r'                            (const uint8_t*)kEwKLabel, 11);\n'
        r'      // MAC = trunc24(HMAC(k, "weaver-mac-v1" || Data || key_share || CtxTCP))\n'
        r'      static const char kEwMacLabel[] = "weaver-mac-v1";     // 13 bytes\n'
        r'      static const char kEwTcpCtx[]  = "weaver-ctx-tcp-v1";  // 17 bytes\n'
        r'      std::vector<uint8_t> ew_mac_in;\n'
        r'      ew_mac_in.reserve(13 + ew_data_len + hs->key_share_bytes.size() + 17);\n'
        r'      ew_mac_in.insert(ew_mac_in.end(), kEwMacLabel, kEwMacLabel + 13);\n'
        r'      ew_mac_in.insert(ew_mac_in.end(), ew_data, ew_data + ew_data_len);\n'
        r'      ew_mac_in.insert(ew_mac_in.end(), hs->key_share_bytes.data(),\n'
        r'                       hs->key_share_bytes.data() + hs->key_share_bytes.size());\n'
        r'      ew_mac_in.insert(ew_mac_in.end(), kEwTcpCtx, kEwTcpCtx + 17);\n'
        r'      uint8_t ew_mac[SHA256_DIGEST_LENGTH];\n'
        r'      unsigned ew_mac_len = 0;\n'
        r'      if (ew_hkdf_ok && ew_wid_len >= 8 &&\n'
        r'          HMAC(EVP_sha256(), ew_k, sizeof(ew_k), ew_mac_in.data(),\n'
        r'               ew_mac_in.size(), ew_mac, &ew_mac_len) != nullptr &&\n'
        r'          ew_mac_len >= 24) {\n'
        r'        hs->session_id.ResizeForOverwrite(32);\n'
        r'        OPENSSL_memcpy(hs->session_id.data(), ew_wid, 8);\n'
        r'        OPENSSL_memcpy(hs->session_id.data() + 8, ew_mac, 24);\n'
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

    # 5. TCP: передаём Weaver-blob (capKey||D||Data) вниз в BoringSSL через ex_data(0)
    #    (слот wire_id||MAC считается там над key_share, см. 2b).
    apply_patch(
        'net/socket/ssl_client_socket_impl.cc',
        r'(if \(!ssl_ \|\| !context->SetClientSocketForSSL\(ssl_\.get\(\), this\)\)[\s\n]*return ERR_UNEXPECTED;)',
        r'\1\n\n'
        r'  // EIDOLON: передаём Weaver-blob в BoringSSL для привязки токена к key_share\n'
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
        r'    # Глушим style-варнинги апстрим-кода quiche moqt (не наш код): он\n'
        r'    # никогда не собирался под строгие флаги Chromium, отсюда ~2000 строк шума.\n'
        r'    "-Wno-inconsistent-missing-override",\n'
        r'    "-Wno-extra-semi",\n'
        r'    "-Wno-deprecated-copy",\n'
        r'    "-Wno-unused-private-field",\n'
        r'  ]\n'
        r'  # Шим operator<< для AbslStringify-типов moqt (пишется build.sh) — force-include.\n'
        r'  # На Windows компилятор — clang-cl (MSVC-драйвер), который НЕ понимает GCC-флаг\n'
        r'  # "-include": глотает его как unknown arg, а путь-аргумент становится ВТОРЫМ\n'
        r'  # входным файлом -> "cannot specify /Fo... when compiling multiple source files".\n'
        r'  # Там нужен MSVC-флаг /FI<path>. На прочих платформах — обычный clang с "-include".\n'
        r'  if (is_win) {\n'
        r'    cflags += [ "/FI" + rebase_path("//net/eidolon/moqt_ostream_shims.h", root_build_dir) ]\n'
        r'  } else {\n'
        r'    cflags += [ "-include", rebase_path("//net/eidolon/moqt_ostream_shims.h", root_build_dir) ]\n'
        r'  }\n'
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

    # 10b. MoQT PUBLISH_NAMESPACE teardown fix (quiche-156 регрессия). Все MoQT
    #      bidi-стримы ставят stream_parser()->set_allow_fin(true) в OnStreamBound
    #      (subscribe/publish/fetch/track_status/publish_namespace-REQUEST), КРОМЕ
    #      MoqtPublishNamespaceResponseStream — его OnStreamBound пуст (лишь TODO о
    #      приоритете). Из-за этого, когда publisher (наш сервер анонсит cover-ns, или
    #      любой PUBLISH_NAMESPACE) FIN-ит PN-стрим после REQUEST_ERROR (quiche делает
    #      это в OnControlMessage(RequestError)), подписчик читает ЛЕГАЛЬНЫЙ FIN своим
    #      response-парсером с allow_fin_=false -> "Unexpected FIN on a control stream"
    #      -> OnFatalError -> MoqtSession::Error -> ВСЯ сессия убита ~1 RTT после
    #      establish. Это рвало reliable URL-тест (EOF) e2e на redroid (2026-10-31).
    #      Ставим set_allow_fin(true), как у всех прочих. Если апстрим-версия чуть иная
    #      (CI тянет latest Stable) и паттерн не сматчится — apply_patch просто
    #      пропустит (клиентский accept-фикс C в eidolon_bridge.cc страхует).
    apply_patch(
        'net/third_party/quiche/src/quiche/quic/moqt/moqt_publish_namespace_stream.h',
        r'(void OnStreamBound\(\) override \{\n)(\s*)(// TODO\(martinduke\): Set the priority for this stream\.)',
        r'\1\2stream_parser()->set_allow_fin(true);  // [EIDOLON] PN response stream must allow FIN (quiche-156 regr)\n'
        r'\2\3'
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

    # 13. P5.4 (Фаза 5): включение TLS-резумпции/0-RTT на несущей. crypto_config_
    #     строится в ctor с session_cache=nullptr (хардкод) → тикеты не хранятся,
    #     0-RTT невозможен. Добавляем метод, подключающий ОБЩИЙ персистентный
    #     session-cache к приватному crypto_config_ (реализация в eidolon_bridge.cc).
    apply_patch(
        'net/quic/dedicated_web_transport_http3_client.h',
        r'(  void EidolonAbortMigration\(\);)',
        r'\1\n'
        r'\n'
        r'  // [EIDOLON] P5.4: подключить общий персистентный session-cache к\n'
        r'  // crypto_config этого клиента ДО Connect() (resumption/0-RTT при re-dial).\n'
        r'  void EidolonEnableResumption();'
    )

    # 14. M.1 (Фаза 5): ре-запуск DPLPMTUD после миграции. SetMtuDiscoveryTarget в
    #     QuicConnection приватный, поэтому объявляем ПУБЛИЧНЫЙ тонкий метод-обёртку
    #     (реализация — член-функция в eidolon_bridge.cc, имеет доступ к private).
    #     Якорь — публичный set_keep_alive_ping_timeout.
    apply_patch(
        'net/third_party/quiche/src/quiche/quic/core/quic_connection.h',
        r'(  void set_keep_alive_ping_timeout\(QuicTime::Delta keep_alive_ping_timeout\);)',
        r'\1\n'
        r'\n'
        r'  // [EIDOLON] M.1: заново взвести path-MTU discovery (growth-пробинг) после\n'
        r'  // миграции несущей на новую сеть. Реализация в eidolon_bridge.cc.\n'
        r'  void EidolonRestartMtuDiscovery();'
    )

    # 15. Weaver W1 #4 — JA4 observe на QUIC-линии. EarlySelectCertCallback — единственное
    #     место с сырым SSL_CLIENT_HELLO на сервере. Реализация eidolon_ja4_quic_observe в
    #     net/eidolon/eidolon_bridge.cc: считает JA4 той же реализацией, что TCP-линия, и
    #     логирует сверку с allow-set. NON-FATAL: возврат колбэка НЕ меняем — TLS-alert
    #     демаскировал бы порт (запрещено спекой), а доступ к туннелю на QUIC и так гейтится
    #     токеном в 80-байтной meta (acceptMetaLoop). Жёсткий decoy на QUIC — CI-доработка (§9).
    #
    #     15a: forward-decl НА NAMESPACE-SCOPE (внутри namespace quic, перед определением
    #     функции). ВАЖНО: linkage-specification `extern "C"` НЕЛЬЗЯ ставить в block-scope
    #     (ошибка "expected unqualified-id") — только на namespace scope. SSL_CLIENT_HELLO уже
    #     виден (openssl/ssl.h включён выше; это тип параметра функции-якоря).
    apply_patch(
        'net/third_party/quiche/src/quiche/quic/core/tls_server_handshaker.cc',
        r'(ssl_select_cert_result_t TlsServerHandshaker::EarlySelectCertCallback\(\n'
        r'    const SSL_CLIENT_HELLO\* client_hello\) \{)',
        r'// [EIDOLON] Weaver W1 #4 — forward-decl нативного JA4-observe (namespace-scope;\n'
        r'// block-scope extern "C" запрещён стандартом). Реализация — net/eidolon/eidolon_bridge.cc.\n'
        r'extern "C" void eidolon_ja4_quic_observe(const SSL_CLIENT_HELLO*);\n'
        r'\n'
        r'\1'
    )

    #     15b: сам вызов — обычный statement в block-scope (без extern "C").
    apply_patch(
        'net/third_party/quiche/src/quiche/quic/core/tls_server_handshaker.cc',
        r'(  // This is the first call\.\n  select_cert_status_ = QUIC_PENDING;)',
        r'\1\n'
        r'\n'
        r'  // [EIDOLON] Weaver W1 #4 — JA4 observe (native-first, обе линии), NON-FATAL.\n'
        r'  eidolon_ja4_quic_observe(client_hello);'
    )


#     apply_patch(
#         'third_party/abseil-cpp/absl/base/internal/spinlock_win32.inc',
#         r'#include <windows\.h>',
#         r'#include <minwinbase.h>\n#include <windows.h>'
#     )

if __name__ == '__main__':
    main()