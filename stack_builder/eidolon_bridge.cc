#include "bridge.h"

#include "build/build_config.h"

#if BUILDFLAG(IS_POSIX)
#include <unistd.h>
#include <fcntl.h>
#include "base/files/file_descriptor_watcher_posix.h"
#include "base/posix/eintr_wrapper.h"
#endif
#if BUILDFLAG(IS_ANDROID)
#include <sched.h>   // sched_setaffinity (C1: pin io-потока на little-ядра)
#include <errno.h>
#include <fstream>   // чтение /sys .../cpu_capacity без зависимости от base/files
#endif
#if BUILDFLAG(IS_WIN)
#include <winsock2.h>
#include <windows.h>
#include <basetsd.h>
#include "base/win/object_watcher.h"
#include "base/memory/raw_ptr.h"
#include "base/no_destructor.h"

typedef SSIZE_T ssize_t;

#endif

// --- ДОБАВЛЕННЫЕ ИНКЛУДЫ ДЛЯ ИНИЦИАЛИЗАЦИИ ---
#include "base/at_exit.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "base/command_line.h"
#include "base/logging.h"
// EIDOLON_DIAG: полное определение LoggingSettings и констант LoggingDestination
// (LOG_TO_SYSTEM_DEBUG_LOG) в Chromium 155+ вынесено из base/logging.h сюда.
#include "base/logging/logging_settings.h"

#include <vector>
#include <string>
#include <atomic>

#include "net/socket/tcp_client_socket.h"
#include "net/socket/ssl_client_socket_impl.h"
#include "net/ssl/ssl_config.h"
#include "net/base/address_list.h"
#include "net/base/ip_endpoint.h"
#include "net/base/io_buffer.h"
#include "net/third_party/quiche/src/quiche/common/http/http_header_block.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/http/http_util.h"
#include "net/http/transport_security_state.h"
#include "net/socket/ssl_client_socket.h"
#include "components/version_info/version_info.h"
#include "base/strings/string_number_conversions.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"

#include "base/compiler_specific.h"
#include "base/functional/callback_helpers.h"
#include "base/functional/bind.h"
#include "base/threading/thread.h"
#include "base/task/single_thread_task_runner.h"
#include "base/run_loop.h"
#include "base/synchronization/waitable_event.h"
#include "base/time/time.h"
#include "base/containers/span.h"

#include "net/base/network_handle.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/quic/quic_context.h"
#include "net/quic/quic_chromium_client_session.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/crypto_protocol.h" // quic::kAFF2/kAFIA/kMTUH (A3/M.1)
// P5.4 (0-RTT/resumption): персистентный клиентский session-cache между дозвонами.
// (База quic::SessionCache объявлена в quic_client_session_cache.h + транзитивно в
// quic_crypto_client_config.h; отдельного session_cache.h в дереве нет.)
#include "net/third_party/quiche/src/quiche/quic/core/crypto/quic_client_session_cache.h"
// WP-4/WP-5: публичные ручки несущей (set_keep_alive_ping_timeout/SendPing/
// SetMaxPacketLength) + MTU-таргеты DPLPMTUD.
#include "net/third_party/quiche/src/quiche/quic/core/quic_connection.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_constants.h"
#include "net/quic/quic_chromium_client_stream.h"
#include "net/quic/quic_session_pool.h"
#include "net/quic/quic_session_attempt.h"
#include "net/quic/quic_endpoint.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_context.h"
#include "net/http/http_network_session.h"
#include "net/http/http_transaction_factory.h"
#include "net/base/host_port_pair.h"
#include "net/spdy/multiplexed_session_creation_initiator.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/cert_verify_result.h"
#include "net/base/net_errors.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "base/memory/scoped_refptr.h"
#include "net/cert/x509_certificate.h"
#include "net/proxy_resolution/proxy_config_service_fixed.h"
#include "net/proxy_resolution/proxy_config_with_annotation.h"

#include "net/quic/crypto/proof_source_chromium.h"
#include "net/cert/cert_verify_proc.h"
#include <optional>

// --- MoQT / WebTransport (Фаза 1 перехода на MoQ) ---
// Клиент WebTransport-over-H3 из Chromium net (сохраняет наш URLRequestContext с
// EidolonCertVerifier и protect-хуки), отдаёт quic::WebTransportSession* (==
// webtransport::Session*), на который садится quiche MoqtSession.
#include "net/quic/web_transport_client.h"
// Фаза 3 Этап C — Connection Migration: прямой доступ к клиенту WT-over-H3,
// его пакетному reader/writer, сокет-фабрике и path-валидатору QUIC.
#include "net/quic/dedicated_web_transport_http3_client.h"
#include "net/quic/quic_chromium_packet_reader.h"
#include "net/quic/quic_chromium_packet_writer.h"
#include "net/quic/address_utils.h"
#include "net/socket/datagram_client_socket.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/udp_client_socket.h"
#include "net/socket/socket_descriptor.h"
#include "net/base/address_family.h"
#include <netinet/in.h>
#include <sys/socket.h>
#include "net/http/http_network_session.h"
#include "quiche/quic/core/quic_path_validator.h"
#include "net/quic/quic_chromium_alarm_factory.h"
#include "net/quic/platform/impl/quic_chromium_clock.h"
#include "net/http/http_response_headers.h"
#include "net/base/network_anonymization_key.h"
#include "net/dns/host_resolver.h"
#include "net/dns/mapped_host_resolver.h"
#include "url/gurl.h"
#include "url/origin.h"
#include "quiche/quic/moqt/moqt_session.h"
#include "quiche/quic/moqt/moqt_known_track_publisher.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_object.h"
#include "quiche/quic/moqt/moqt_fetch_task.h"
#include "quiche/common/quiche_mem_slice.h"
#include <map>
#include <functional>
// WebTransportHttp3 — конкретный тип webtransport::Session* на H3 (и клиент, и сервер).
// Пропатчен аксессором eidolon_quic_session() -> доступ к QUIC-крипто для ExportKeyingMaterial.
#include "quiche/quic/core/http/web_transport_http3.h"
// Серверная обвязка MoQT (линкуется только на linux; на android код под #if не инстанцируется).
#include "quiche/quic/core/http/web_transport_only_dispatcher.h"
#include "quiche/quic/core/io/quic_server_io_harness.h"
#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
#include "quiche/quic/core/batch_writer/quic_gso_batch_writer.h" // A1: GSO send-batch (Linux; .cc втянут патчем в epoll_tool_support)
#endif
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/io/quic_default_event_loop.h"
#include "quiche/quic/core/quic_default_clock.h"
#include "quiche/quic/core/quic_default_connection_helper.h"
#include "quiche/quic/core/quic_version_manager.h"
#include "quiche/quic/core/deterministic_connection_id_generator.h"
#include "quiche/quic/core/crypto/quic_crypto_server_config.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/crypto/key_exchange.h"
#include "quiche/quic/moqt/moqt_quic_config.h"
#include "quiche/quic/tools/quic_simple_crypto_server_stream_helper.h"
#include "absl/types/span.h"

// === ЗАЩИТА СЕРВЕРНЫХ ЗАВИСИМОСТЕЙ QUIC ===
#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
#include "quiche/quic/tools/quic_simple_server_backend.h"
#include "quiche/quic/tools/quic_memory_cache_backend.h"
#include "quiche/quic/tools/quic_server.h"
#include "quiche/quic/tools/quic_simple_dispatcher.h"
#include "quiche/quic/tools/quic_simple_server_session.h"
#include "quiche/quic/tools/quic_simple_server_stream.h"
#include "base/task/thread_pool.h"
#include "quiche/quic/core/quic_default_connection_helper.h"
#include "quiche/quic/tools/quic_simple_crypto_server_stream_helper.h"
#include "net/cert/cert_verify_proc.h"
#include <optional>
#endif
// ===========================================

static base::AtExitManager* g_exit_manager = nullptr;
static base::Thread* g_io_thread = nullptr;
// Выделенный поток для нативного QUIC-сервера. Нужен, чтобы серверный event loop
// жил на потоке с Chromium SingleThreadTaskRunner (ForwardToGo/ResetQUIC/
// WriteOrBufferBody постят задачи на него), и при этом НЕ блокировался бесконечно
// (HandleEventsForever) — вместо этого прокачиваем event loop самоперепостящейся
// задачей WaitForEvents, так поток успевает исполнять и постленные задачи.
static base::Thread* g_quic_thread = nullptr;

// EIDOLON_DIAG: колбэк protect(fd) из Go (Android VpnService.protect). Без него сокет
// нативного стека уходит обратно в TUN и дозвон падает (-102 ERR_CONNECTION_REFUSED).
static EidolonProtectFunc g_protect_func = nullptr;

// Защищает уже открытый сокет (fd) от захвата VpnService. Безопасно при nullptr-колбэке.
static void EidolonProtectFd(int fd) {
    if (g_protect_func == nullptr || fd < 0) {
        return;
    }
    int rv = g_protect_func(fd);
    if (rv != 0) {
        LOG(ERROR) << "EIDOLON_DIAG: protect(fd) failed rv=" << rv << " fd=" << fd;
    } else {
        LOG(INFO) << "EIDOLON_DIAG: socket protected fd=" << fd;
    }
}

// =========================================================================
// WP-4/WP-5 (Фаза 5): sleep/wake + keep-alive + 0-RTT + MTU/CID на миграции.
// =========================================================================

// P5.1 keep-alive. Таймаут keep-alive-пинга = «молчим столько → шлём PING».
// Пинг НЕ фаерит, пока по соединению идёт трафик (quiche ставит пинг-аларм только
// при пустом in-flight и ShouldKeepConnectionAlive()==true — у нас всегда открыт
// WT/CONNECT-стрим). Поэтому в foreground с данными эти значения ни на что не
// влияют (трафик вытесняет пинг), а работают только в простое/фоне/Doze, держа
// NAT/роутер-маппинг и путь тёплыми в ОБЕ стороны (клиент→PING→сервер→ACK→клиент).
// Все интервалы СТРОГО < idle-timeout несущей (мы ставим idle=120с, см.
// kEidolonCarrierIdleTimeout), с запасом. ВАЖНО: буквальный «active=RTT/2» из плана
// для bulk-туннеля НЕ берём — при RTT 15мс это пинг раз в 7мс на любой микро-паузе,
// радио не уснёт (прямо против цели по батарее). active держим как редкую страховку.
enum EidolonPowerState {
    kEidolonPowerActive = 0,      // экран/приложение активно: трафик сам держит путь
    kEidolonPowerBackground = 1,  // фон: редкий heartbeat
    kEidolonPowerDoze = 2,        // Doze/сон: самый редкий, но < idle
};
static constexpr int kEidolonKeepAliveActiveMs = 15 * 1000;       // foreground-страховка
static constexpr int kEidolonKeepAliveBackgroundMs = 25 * 1000;   // фон
static constexpr int kEidolonKeepAliveDozeMs = 50 * 1000;         // Doze (< 120с idle)

// Несущий idle-timeout: поднимаем с дефолта (~30с) до 120с, чтобы Doze-heartbeat
// (до 50с, плюс возможная пачковка Doze-окон) НЕ ловил timeout. Сервер ставит
// такой же (см. серверный config_), эффективный idle = min(обе стороны).
static constexpr int kEidolonCarrierIdleTimeoutSec = 120;

// M.1: консервативный MTU на свежем пути сразу после миграции (Wi-Fi↔сота) — чтобы
// «толстые» пакеты не черно-дырили на меньшем MTU соты до завершения ре-DPLPMTUD.
static constexpr size_t kEidolonMigrationSafeMtu = 1200;

// P5.4: ОДИН персистентный клиентский session-cache на весь процесс. TLS1.3 тикеты
// резумпции, которые сервер выдаёт по завершении handshake, складываются сюда по
// QuicServerId и переживают ПОЛНЫЙ пере-дозвон (несущая умерла → penalty → re-dial),
// давая resumption (короткий handshake без пере-проверки серта) и, где стек поддержит,
// 0-RTT early-data. Replay-риск 0-RTT закрыт нашим токен-replay-cache (привязка к
// key_share, окно 5с — см. патч key_share binding). shared_ptr: один инстанс общий
// для crypto_config всех WT-клиентов (каждый дозвон строит свой url_context/клиент).
static std::shared_ptr<quic::SessionCache>& EidolonSharedSessionCacheRef() {
    static base::NoDestructor<std::shared_ptr<quic::SessionCache>> cache(
            std::make_shared<quic::QuicClientSessionCache>());
    return *cache;
}

// EidolonProtectingSocketFactory — кастомная ClientSocketFactory, защищающая UDP-сокеты
// несущей QUIC/WebTransport от собственного VpnService-TUN тем же механизмом, что и
// TCP-линия: VpnService.protect(fd) через g_protect_func.
//
// Почему не bind-к-NetworkHandle: Chromium умеет привязать QUIC-сокет к underlying-сети
// (CreateWebTransportClient(network_handle)), но на Android это идёт через
// net::android::BindToNetwork -> dlsym("android_setsocknetwork"), который в нашей среде
// (redroid) не резолвится -> ERR_NOT_IMPLEMENTED, и дозвон падает. protect(fd) работает
// везде (им же живёт рабочая TCP-линия).
//
// Создаём UDP-fd сами, защищаем ДО connect и усыновляем в UDPClientSocket (сконструирован
// с kInvalidNetworkHandle, чтобы он сам не пытался bind). TCP/SSL-фабрики делегируем дефолту.
class EidolonProtectingSocketFactory : public net::ClientSocketFactory {
public:
    std::unique_ptr<net::DatagramClientSocket> CreateDatagramClientSocket(
            net::DatagramSocket::BindType bind_type,
            net::handles::NetworkHandle /*target_network*/,  // игнорируем: protect вместо bind
            net::NetLog* net_log, const net::NetLogSource& source) override {
        auto socket = std::make_unique<net::UDPClientSocket>(
                bind_type, net_log, source, net::handles::kInvalidNetworkHandle);
        // TODO(ipv6): серверы eidolon сейчас IPv4; при dual-stack определять семейство по dest.
        net::SocketDescriptor fd = net::CreatePlatformSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fd != net::kInvalidSocket) {
            EidolonProtectFd(fd);
            int rv = socket->AdoptOpenedSocket(net::ADDRESS_FAMILY_IPV4, fd);
            if (rv != net::OK) {
                LOG(ERROR) << "EIDOLON_DIAG: UDP AdoptOpenedSocket failed rv=" << rv;
            }
        } else {
            LOG(ERROR) << "EIDOLON_DIAG: CreatePlatformSocket(UDP) failed";
        }
        return socket;
    }
    std::unique_ptr<net::TransportClientSocket> CreateTransportClientSocket(
            const net::AddressList& addresses, net::handles::NetworkHandle target_network,
            std::unique_ptr<net::SocketPerformanceWatcher> watcher,
            net::NetworkQualityEstimator* nqe, net::NetLog* net_log,
            const net::NetLogSource& source) override {
        return net::ClientSocketFactory::GetDefaultFactory()->CreateTransportClientSocket(
                addresses, target_network, std::move(watcher), nqe, net_log, source);
    }
    std::unique_ptr<net::SSLClientSocket> CreateSSLClientSocket(
            net::SSLClientContext* context, std::unique_ptr<net::StreamSocket> stream_socket,
            const net::HostPortPair& host_and_port, const net::SSLConfig& ssl_config) override {
        return net::ClientSocketFactory::GetDefaultFactory()->CreateSSLClientSocket(
                context, std::move(stream_socket), host_and_port, ssl_config);
    }
};

class EidolonCertVerifier : public net::CertVerifier {
public:
    explicit EidolonCertVerifier(std::unique_ptr<net::CertVerifier> default_verifier)
            : default_verifier_(std::move(default_verifier)) {}

    int Verify(const RequestParams& params,
               net::CertVerifyResult* verify_result,
               net::CompletionOnceCallback callback,
               std::unique_ptr<Request>* out_req,
               const net::NetLogWithSource& net_log) override {

        // Создаем обертку для коллбэка на случай, если проверка уйдет в фон (асинхронно)
        auto wrapped_callback = base::BindOnce(
                [](net::CertVerifyResult* result_ptr,
                   scoped_refptr<net::X509Certificate> cert,
                   net::CompletionOnceCallback original_callback,
                   int rv) {
                    // Если дефолтная проверка упала (например, это REALITY), применяем "наш код"
                    if (rv != net::OK) {
                        result_ptr->verified_cert = cert;
                        result_ptr->is_issued_by_known_root = true;
                        result_ptr->cert_status = 0; // Сбрасываем ошибки
                        rv = net::OK;
                    }
                    std::move(original_callback).Run(rv);
                },
                verify_result, params.certificate(), std::move(callback));

        // 1. Вызываем стандартную проверку Chromium ("проверяет сертификат как обычно")
        int rv = default_verifier_->Verify(
                params, verify_result, std::move(wrapped_callback), out_req, net_log);

        // 2. Если результат вернулся моментально и это ошибка — перехватываем
        if (rv != net::OK && rv != net::ERR_IO_PENDING) {
            verify_result->verified_cert = params.certificate();
            verify_result->is_issued_by_known_root = true;
            verify_result->cert_status = 0;
            return net::OK;
        }

        // 3. Если всё ОК (валидный сертификат), возвращаем как есть
        return rv;
    }

    void Verify2QwacBinding(
            const std::string& binding,
            const std::string& hostname,
            const scoped_refptr<net::X509Certificate>& tls_cert,
            base::OnceCallback<void(const scoped_refptr<net::X509Certificate>&)> callback,
            const net::NetLogWithSource& net_log) override {

        default_verifier_->Verify2QwacBinding(
                binding, hostname, tls_cert, std::move(callback), net_log);
    }

    void SetConfig(const Config& config) override { default_verifier_->SetConfig(config); }
    void AddObserver(Observer* observer) override { default_verifier_->AddObserver(observer); }
    void RemoveObserver(Observer* observer) override { default_verifier_->RemoveObserver(observer); }

private:
    std::unique_ptr<net::CertVerifier> default_verifier_;
};

// -------------------------------------------------------------------------
// АСИНХРОННАЯ СЕССИЯ (DATA PUMP)
// -------------------------------------------------------------------------

// Кастомный MoQT-паблишер туннеля (Фаза 2); определён ниже EidolonSession,
// т.к. держит на неё указатель. Члены сессии хранят его через базовый тип.
class EidolonTrackPublisher;

#if BUILDFLAG(IS_WIN)
struct EidolonSession : public base::win::ObjectWatcher::Delegate {
#else
struct EidolonSession {
#endif
    std::unique_ptr<net::StreamSocket> tcp_socket;
    std::unique_ptr<net::CertVerifier> cert_verifier; // Владелец верификатора
    std::unique_ptr<net::SSLClientContext> ssl_context; // Должен жить вместе с TLS сокетом
    std::unique_ptr<net::URLRequestContext> url_context;
    std::unique_ptr<net::QuicChromiumClientSession::Handle> quic_session_handle;
    std::unique_ptr<net::QuicChromiumClientStream::Handle> quic_stream_handle;
    std::unique_ptr<net::QuicSessionAttempt> quic_attempt; // Сохраняем попытку установки QUIC-сессии
    uintptr_t data_fd_ = 0;
    bool is_quic_ = false;
    bool is_closed_ = false;
    // WP-4 (Фаза 5): последний энергетический режим несущей (0=active/1=bg/2=doze),
    // чтобы ловить именно ПЕРЕХОД в active (wake-resync шлём один раз на пробуждение).
    int power_state_ = 0;  // kEidolonPowerActive

    // --- MoQT / WebTransport (Фаза 1) ---
    // Порядок объявления важен: разрушаются в обратном порядке, поэтому
    // moqt_session_ (держит webtransport::Session*, владеемый wt_client_) объявлен
    // ПОСЛЕ wt_client_ → уничтожается ПЕРВЫМ; wt_visitor_ объявлен раньше клиента →
    // переживает его (клиент держит на visitor сырой указатель).
    bool is_moqt_ = false;
    std::vector<uint8_t> moqt_token_;  // токен для гейтинга namespace (Фаза 2)
    std::unique_ptr<net::WebTransportClientVisitor> wt_visitor_;
    std::unique_ptr<net::WebTransportClient> wt_client_;
    std::unique_ptr<moqt::MoqtSession> moqt_session_;

    // --- MoQT data-plane (Фаза 2): двунаправленный туннель на объектах ---
    // Все эти члены сбрасываются в Close() ПОСЛЕ moqt_session_.reset(), поэтому
    // сессия (держащая на них сырые указатели) к моменту их разрушения уже мертва.
    std::unique_ptr<moqt::MoqtKnownTrackPublisher> moqt_known_publisher_;  // отдаётся сессии как publisher()
    std::shared_ptr<moqt::MoqtTrackPublisher> moqt_local_pub_;             // наш продюсер (владение)
    raw_ptr<EidolonTrackPublisher> moqt_local_pub_raw_ = nullptr;          // типизированный доступ (не владеет)
    std::unique_ptr<moqt::SubscribeVisitor> moqt_sub_visitor_;             // нисходящий потребитель -> FD
    bool moqt_upstream_paused_ = false;                                    // backpressure FD-ридера

    // --- MoQT datagram-lane (Фаза 4): ненадёжный путь (проксируемый UDP) ---
    // Отдельный трек датаграм-объектов (subgroup=nullopt => WT/QUIC-датаграммы) и
    // отдельный FD к Go (datagram_fd_), кадрированный [len:2 BE][payload] (STREAM +
    // length-framing; те же ключи/кодек датаграмм — в Go). Fire-and-forget: потеря
    // при переполнении/без подписчика допустима (семантика UDP). Эти члены сбрасываются
    // в Close() ПОСЛЕ moqt_session_.reset() (сессия держит на них сырые указатели).
    uintptr_t datagram_fd_ = 0;
    std::shared_ptr<moqt::MoqtTrackPublisher> moqt_dgram_pub_;    // наш датаграм-продюсер (владение)
    raw_ptr<class EidolonDatagramPublisher> moqt_dgram_pub_raw_ = nullptr;
    std::unique_ptr<moqt::SubscribeVisitor> moqt_dgram_sub_visitor_;
    std::vector<std::string> pending_dgram_writes_;              // кадры [len:2][payload] в Go-FD
    std::string dgram_read_buf_;                                 // недособранный кадр со стороны Go

    // Инструменты асинхронного I/O
    scoped_refptr<net::IOBufferWithSize> read_buf_;

#if BUILDFLAG(IS_POSIX)
    std::unique_ptr<base::FileDescriptorWatcher::Controller> fd_read_controller_;
    std::unique_ptr<base::FileDescriptorWatcher::Controller> fd_write_controller_;
    std::unique_ptr<base::FileDescriptorWatcher::Controller> dgram_read_controller_;
    std::unique_ptr<base::FileDescriptorWatcher::Controller> dgram_write_controller_;
#elif BUILDFLAG(IS_WIN)
    HANDLE socket_event_ = INVALID_HANDLE_VALUE;
    base::win::ObjectWatcher socket_watcher_;
    // Датаграм-lane (Фаза 4) реализован только для POSIX (Android/Linux — цели деплоя);
    // на Windows-хосте датаграммы не поднимаются (datagram_fd_ остаётся 0).
#endif

    bool socket_write_pending_ = false;
    bool socket_read_pending_ = false;
    std::vector<std::string> pending_fd_writes_;
    // Заголовки ответа HTTP/3 (:status). ReadInitialHeaders ДОЛЖЕН их прочитать,
    // иначе QuicChromiumClientStream::OnBodyAvailable не отдаёт тело в ReadBody.
    quiche::HttpHeaderBlock quic_response_headers_;

    EidolonSession(uintptr_t fd, bool quic, uintptr_t datagram_fd = 0)
            : data_fd_(fd), is_quic_(quic), datagram_fd_(datagram_fd) {
        // Переводим FD(ы) от Go в неблокирующий режим (Non-Blocking)
#if BUILDFLAG(IS_POSIX)
        int flags = fcntl(static_cast<int>(data_fd_), F_GETFL, 0);
        fcntl(static_cast<int>(data_fd_), F_SETFL, flags | O_NONBLOCK);
        if (datagram_fd_ != 0) {
            int dflags = fcntl(static_cast<int>(datagram_fd_), F_GETFL, 0);
            fcntl(static_cast<int>(datagram_fd_), F_SETFL, dflags | O_NONBLOCK);
        }
#elif BUILDFLAG(IS_WIN)
        u_long mode = 1;
        ioctlsocket(static_cast<SOCKET>(data_fd_), FIONBIO, &mode);
        if (datagram_fd_ != 0) {
            u_long dmode = 1;
            ioctlsocket(static_cast<SOCKET>(datagram_fd_), FIONBIO, &dmode);
        }
#endif

        // Аллоцируем буфер 64 КБ (достаточно для QUIC Datagram / Jumbo Frames)
        read_buf_ = base::MakeRefCounted<net::IOBufferWithSize>(65536);
    }

#if BUILDFLAG(IS_WIN)
    ~EidolonSession() override {
        Close();
    }
    // События от Windows Sockets
    void OnObjectSignaled(HANDLE object) override {
        if (is_closed_) return;

        if (object == socket_event_) {
            WSANETWORKEVENTS network_events;
            if (WSAEnumNetworkEvents(static_cast<SOCKET>(data_fd_), socket_event_, &network_events) == 0) {
                if (network_events.lNetworkEvents & (FD_READ | FD_CLOSE)) {
                    OnFdReadable();
                }
                if (!is_closed_ && (network_events.lNetworkEvents & FD_WRITE)) {
                    TryWriteToFd();
                }
            }
            if (!is_closed_) {
                // Возобновляем слежение
                socket_watcher_.StartWatchingOnce(socket_event_, this);
            }
        }
    }
#else
    ~EidolonSession() {
        Close();
    }
#endif

    void StartPump() {
        if (is_closed_) return;

#if BUILDFLAG(IS_POSIX)
        // Начинаем следить за доступностью данных от Go
        fd_read_controller_ = base::FileDescriptorWatcher::WatchReadable(
                static_cast<int>(data_fd_),
                base::BindRepeating(&EidolonSession::OnFdReadable, base::Unretained(this))
        );
#elif BUILDFLAG(IS_WIN)
        socket_event_ = WSACreateEvent();
        WSAEventSelect(static_cast<SOCKET>(data_fd_), socket_event_, FD_READ | FD_WRITE | FD_CLOSE);
        socket_watcher_.StartWatchingOnce(socket_event_, this);
#endif

        // Запускаем первичное чтение из Chromium сокета.
        if (is_moqt_) {
            // MoQT: восходящее уже обслуживается watcher'ом FD (выше) -> объекты;
            // нисходящее приходит асинхронно через EidolonSubscribeVisitor. Здесь
            // нечего инициировать — нет Chromium-сокета для чтения.
        } else if (is_quic_) {
            // HTTP/3: СНАЧАЛА читаем initial headers (:status 200) ответа. Пока
            // приложение их не прочитает, QuicChromiumClientStream::OnBodyAvailable
            // (quic_chromium_client_stream.cc:666) видит headers_delivered_==false
            // и буферизует тело, не уведомляя Handle → ReadBody висит в ERR_IO_PENDING
            // вечно (симптом: нисходящие QUIC-пакеты приходят, но "ReadBody rv=" не
            // логируется, запрос таймаутит). ReadBody запускаем ТОЛЬКО из колбэка,
            // чтобы headers_delivered_ уже был true и забуференное тело отдалось.
            int rv = quic_stream_handle->ReadInitialHeaders(
                    &quic_response_headers_,
                    base::BindOnce(&EidolonSession::OnQuicInitialHeadersRead, base::Unretained(this)));
            if (rv != net::ERR_IO_PENDING) OnQuicInitialHeadersRead(rv);
        } else {
            DoSocketRead();
        }
    }

    void OnQuicInitialHeadersRead(int rv) {
        if (is_closed_) return;
        LOG(INFO) << "EIDOLON_DIAG: client QUIC initial headers rv=" << rv;
        if (rv < 0) {
            Close();
            return;
        }
        // headers_delivered_ теперь true — тело разблокировано; запускаем ReadBody.
        DoSocketRead();
    }

    // --- НАПРАВЛЕНИЕ: Go FD -> Chromium Socket ---

    void OnFdReadable() {
        if (is_closed_ || socket_write_pending_) return;

        std::vector<uint8_t> temp_buf(65536);

#if BUILDFLAG(IS_POSIX)
        ssize_t bytes_read = HANDLE_EINTR(read(static_cast<int>(data_fd_), temp_buf.data(), temp_buf.size()));
        bool is_eagain = (bytes_read < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
#elif BUILDFLAG(IS_WIN)
        ssize_t bytes_read = recv(static_cast<SOCKET>(data_fd_), reinterpret_cast<char*>(temp_buf.data()), temp_buf.size(), 0);
        bool is_eagain = (bytes_read == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK);
        if (bytes_read == SOCKET_ERROR) bytes_read = -1;
#endif

        // MoQT: байты из Go-FD -> объекты нашего восходящего трека (без Chromium-сокета).
        if (is_moqt_) {
            LOG(INFO) << "EIDOLON_DIAG: OnFdReadable(MoQT) bytes_read=" << bytes_read
                      << " eagain=" << is_eagain;
            if (bytes_read > 0) {
                PublishUpstreamBytes(std::string_view(reinterpret_cast<char*>(temp_buf.data()),
                                                      static_cast<size_t>(bytes_read)));
            } else if (bytes_read == 0 || (bytes_read < 0 && !is_eagain)) {
                CloseUpstream();
                Close();
            }
            // is_eagain (<0) — просто ждём следующего события watcher'а.
            return;
        }

        if (bytes_read > 0) {
            auto write_buf = base::MakeRefCounted<net::StringIOBuffer>(
                    std::string(reinterpret_cast<char*>(temp_buf.data()), bytes_read));
            socket_write_pending_ = true;

#if BUILDFLAG(IS_POSIX)
            // PREVENT 100% CPU BUSY LOOP: Приостанавливаем опрос FD
            fd_read_controller_.reset();
#endif

            int rv = 0;
            if (is_quic_) {
                LOG(INFO) << "EIDOLON_DIAG: client QUIC pump -> WriteStreamData bytes=" << bytes_read;
                std::string_view data_sv(write_buf->data(), bytes_read);
                rv = quic_stream_handle->WriteStreamData(
                        data_sv, false,
                        base::BindOnce(&EidolonSession::OnSocketWriteComplete, base::Unretained(this)));
            } else {
                rv = tcp_socket->Write(
                        write_buf.get(), bytes_read,
                        base::BindOnce(&EidolonSession::OnSocketWriteComplete, base::Unretained(this)),
                        TRAFFIC_ANNOTATION_FOR_TESTS);
            }

            if (rv != net::ERR_IO_PENDING) OnSocketWriteComplete(rv);
        } else if (bytes_read == 0 || (bytes_read < 0 && !is_eagain)) {
            Close();
        }
    }

    void OnSocketWriteComplete(int rv) {
        if (is_closed_) return;
        socket_write_pending_ = false;

        if (is_quic_) LOG(INFO) << "EIDOLON_DIAG: client QUIC pump write complete rv=" << rv;

        if (rv < 0) {
            Close(); // Ошибка записи в сеть
            return;
        }
#if BUILDFLAG(IS_POSIX)
        // Возобновляем прослушивание FD после того как буфер сети освободился
        if (!fd_read_controller_) {
            fd_read_controller_ = base::FileDescriptorWatcher::WatchReadable(
                    static_cast<int>(data_fd_),
                    base::BindRepeating(&EidolonSession::OnFdReadable, base::Unretained(this)));
        }
#elif BUILDFLAG(IS_WIN)
        // PREVENT DEADLOCK: Восстанавливаем edge-trigger на Windows
        OnFdReadable();
#endif
        // Если сеть готова, OnFdReadable вызовется автоматически nhờ FileDescriptorWatcher / ObjectWatcher
    }

    // --- НАПРАВЛЕНИЕ: Chromium Socket -> Go FD ---

    void DoSocketRead() {
        if (is_closed_ || socket_read_pending_) return;
        socket_read_pending_ = true;

        int rv = 0;
        if (is_quic_) {
            rv = quic_stream_handle->ReadBody(
                    read_buf_.get(), read_buf_->size(),
                    base::BindOnce(&EidolonSession::OnSocketReadComplete, base::Unretained(this)));
        } else {
            rv = tcp_socket->Read(
                    read_buf_.get(), read_buf_->size(),
                    base::BindOnce(&EidolonSession::OnSocketReadComplete, base::Unretained(this)));
        }

        if (rv != net::ERR_IO_PENDING) {
            OnSocketReadComplete(rv);
        }
    }

    void OnSocketReadComplete(int rv) {
        if (is_closed_) return;
        socket_read_pending_ = false;

        if (is_quic_) LOG(INFO) << "EIDOLON_DIAG: client QUIC pump ReadBody rv=" << rv;

        if (rv > 0) {
            // Данные получены, ставим в очередь на запись в Go
            pending_fd_writes_.push_back(std::string(read_buf_->data(), rv));
            TryWriteToFd();
        } else {
            Close(); // EOF или ошибка сети
        }
    }

    void TryWriteToFd() {
        if (is_closed_) return;

        while (!pending_fd_writes_.empty()) {
            auto& chunk = pending_fd_writes_.front();

#if BUILDFLAG(IS_POSIX)
            ssize_t written = HANDLE_EINTR(write(static_cast<int>(data_fd_), chunk.data(), chunk.size()));
            bool is_eagain = (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
#elif BUILDFLAG(IS_WIN)
            ssize_t written = send(static_cast<SOCKET>(data_fd_), chunk.data(), chunk.size(), 0);
            bool is_eagain = (written == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK);
            if (written == SOCKET_ERROR) written = -1;
#endif

            if (written > 0) {
                if (static_cast<size_t>(written) == chunk.size()) {
                    pending_fd_writes_.erase(pending_fd_writes_.begin());
                } else {
                    chunk = chunk.substr(written);
                    break; // Ядро ОС перегружено, ждем готовности FD
                }
            } else if (written < 0 && is_eagain) {
                break; // Ждем доступности буфера FD
            } else {
                Close(); // Фатальная ошибка Local Socket
                return;
            }
        }

#if BUILDFLAG(IS_POSIX)
        if (!pending_fd_writes_.empty()) {
            // Включаем ожидание доступности записи, если не влезло
            if (!fd_write_controller_) {
                fd_write_controller_ = base::FileDescriptorWatcher::WatchWritable(
                        static_cast<int>(data_fd_),
                        base::BindRepeating(&EidolonSession::TryWriteToFd, base::Unretained(this)));
            }
        } else {
            // Всё записано, выключаем watcher записи и продолжаем читать сеть
            fd_write_controller_.reset();
            // PREVENT STACK OVERFLOW: Разрываем синхронную рекурсию через очередь задач.
            // Для MoQT нет Chromium-сокета (нисходящее идёт через visitor) — не постим.
            if (!is_moqt_ && !socket_read_pending_) {
                base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
                    FROM_HERE, base::BindOnce(&EidolonSession::DoSocketRead, base::Unretained(this)));
            }
        }
#elif BUILDFLAG(IS_WIN)
        // Для Windows событие FD_WRITE сработает автоматически (edge-triggered)
        if (!is_moqt_ && pending_fd_writes_.empty() && !socket_read_pending_) {
            base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
                FROM_HERE, base::BindOnce(&EidolonSession::DoSocketRead, base::Unretained(this)));
        }
#endif
    }

    // --- MoQT data-plane helpers (Фаза 2), всё на g_io_thread ---

    // Нисходящее: байты из объекта подписки -> очередь записи в Go-FD.
    void EnqueueFdWrite(absl::string_view data) {
        if (is_closed_ || data.empty()) return;
        pending_fd_writes_.push_back(std::string(data));
        TryWriteToFd();
    }

    // Снять backpressure восходящего потока: заново встать на чтение FD.
    void ResumeMoqtUpstream() {
        if (is_closed_ || !moqt_upstream_paused_) return;
        moqt_upstream_paused_ = false;
#if BUILDFLAG(IS_POSIX)
        if (!fd_read_controller_) {
            fd_read_controller_ = base::FileDescriptorWatcher::WatchReadable(
                    static_cast<int>(data_fd_),
                    base::BindRepeating(&EidolonSession::OnFdReadable, base::Unretained(this)));
        }
#endif
    }

    // Восходящее: добавить байты как объект + применить backpressure по watermark.
    void PublishUpstreamBytes(std::string_view data);  // тело после EidolonTrackPublisher
    void CloseUpstream();                              // тело после EidolonTrackPublisher

    // --- MoQT datagram-lane (Фаза 4), всё на g_io_thread, только POSIX ---
    // Запуск слежения за датаграм-FD от Go (кадры [len:2 BE][payload]).
    void StartDatagramPump() {
#if BUILDFLAG(IS_POSIX)
        if (is_closed_ || datagram_fd_ == 0) return;
        dgram_read_controller_ = base::FileDescriptorWatcher::WatchReadable(
                static_cast<int>(datagram_fd_),
                base::BindRepeating(&EidolonSession::OnDatagramFdReadable, base::Unretained(this)));
#endif
    }
    // Go-FD -> датаграм-объекты трека. Тело out-of-line (нужен полный тип publisher'а).
    void OnDatagramFdReadable();
    // Входящая датаграмма (объект подписки) -> кадр [len:2][payload] в Go-FD.
    void EnqueueDatagramWrite(absl::string_view datagram) {
        if (is_closed_ || datagram_fd_ == 0 || datagram.empty()) return;
        if (datagram.size() > 0xFFFF) return;  // не кадрируется 2 байтами -> дроп (UDP ок)
        std::string frame;
        frame.reserve(2 + datagram.size());
        frame.push_back(static_cast<char>((datagram.size() >> 8) & 0xFF));
        frame.push_back(static_cast<char>(datagram.size() & 0xFF));
        frame.append(datagram.data(), datagram.size());
        pending_dgram_writes_.push_back(std::move(frame));
        TryWriteDatagramFd();
    }
    void TryWriteDatagramFd() {
#if BUILDFLAG(IS_POSIX)
        if (is_closed_ || datagram_fd_ == 0) return;
        while (!pending_dgram_writes_.empty()) {
            auto& chunk = pending_dgram_writes_.front();
            ssize_t written = HANDLE_EINTR(write(static_cast<int>(datagram_fd_), chunk.data(), chunk.size()));
            bool is_eagain = (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
            if (written > 0) {
                if (static_cast<size_t>(written) == chunk.size()) {
                    pending_dgram_writes_.erase(pending_dgram_writes_.begin());
                } else {
                    chunk = chunk.substr(written);
                    break;  // ядро перегружено — ждём готовности FD
                }
            } else if (written < 0 && is_eagain) {
                break;
            } else {
                Close();  // датаграм-FD мёртв (Go-сторона ушла) -> рвём сессию
                return;
            }
        }
        if (!pending_dgram_writes_.empty()) {
            if (!dgram_write_controller_) {
                dgram_write_controller_ = base::FileDescriptorWatcher::WatchWritable(
                        static_cast<int>(datagram_fd_),
                        base::BindRepeating(&EidolonSession::TryWriteDatagramFd, base::Unretained(this)));
            }
        } else {
            dgram_write_controller_.reset();
        }
#endif
    }

    void Close() {
        if (is_closed_) return;
        is_closed_ = true;

        // Отключаем наблюдателей
#if BUILDFLAG(IS_POSIX)
        fd_read_controller_.reset();
        fd_write_controller_.reset();
        dgram_read_controller_.reset();
        dgram_write_controller_.reset();
        if (data_fd_ != 0) {
            close(static_cast<int>(data_fd_));
            data_fd_ = 0;
        }
        if (datagram_fd_ != 0) {
            close(static_cast<int>(datagram_fd_));
            datagram_fd_ = 0;
        }
#elif BUILDFLAG(IS_WIN)
        socket_watcher_.StopWatching();
        if (socket_event_ != INVALID_HANDLE_VALUE) {
            WSACloseEvent(socket_event_);
            socket_event_ = INVALID_HANDLE_VALUE;
        }
        if (data_fd_ != 0) {
            closesocket(static_cast<SOCKET>(data_fd_));
            data_fd_ = 0;
        }
#endif

        // MoQT teardown: сессию первой (она держит webtransport::Session*,
        // владеемый wt_client_), затем клиент, затем visitor.
        moqt_session_.reset();
        // Data-plane после сессии: сессия держала на них сырые указатели.
        moqt_sub_visitor_.reset();
        moqt_dgram_sub_visitor_.reset();
        moqt_known_publisher_.reset();
        moqt_local_pub_raw_ = nullptr;
        moqt_local_pub_.reset();
        moqt_dgram_pub_raw_ = nullptr;
        moqt_dgram_pub_.reset();
        wt_client_.reset();
        wt_visitor_.reset();

        if (is_quic_) {
            quic_stream_handle.reset();
            quic_session_handle.reset();
        } else {
            if (tcp_socket) {
                tcp_socket->Disconnect();
                tcp_socket.reset();
            }
        }
    }
};

// -------------------------------------------------------------------------
// Фаза 6 — сервис-прикрытие (Вариант 3): общий генератор правдоподобных MoQT-
// namespace (per-session) + глобальная конфигурация прикрытия.
// -------------------------------------------------------------------------
// Генератор нужен обоим концам: сервер — для cover-namespace, клиент (WP-D) — для
// туннель-ns, чтобы туннель и прикрытие НЕ делились на «фикс-ns vs случайный».
// Имя = {<слово-из-пула>, <случайный id>} (CSPRNG) — выглядит как id станции/шоу.
static moqt::TrackNamespace EidolonPlausibleNamespace() {
    static const char* const kWords[] = {
            "radio", "live", "stream", "fm", "media", "audio", "cast", "studio"};
    constexpr size_t kWordCount = sizeof(kWords) / sizeof(kWords[0]);
    static const char kAlphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    uint8_t rnd[9];
    quic::QuicRandom::GetInstance()->RandBytes(rnd, sizeof(rnd));
    std::string word(kWords[rnd[0] % kWordCount]);
    std::string id;
    id.reserve(8);
    for (int i = 1; i <= 8; ++i) {
        id.push_back(kAlphabet[rnd[i] % (sizeof(kAlphabet) - 1)]);
    }
    return moqt::TrackNamespace({absl::string_view(word), absl::string_view(id)});
}

// Глобальная конфигурация прикрытия. Ставится ОДИН РАЗ из eidolon_cover_configure
// (Go StartCoverIngest) ДО старта listen; читается на g_quic_thread при настройке
// сессий. ns_override пустой => namespace генерим per-session генератором выше.
static bool g_cover_enabled = false;
static uint16_t g_cover_cb_port = 0;
static std::string g_cover_ns_override;
static std::string g_cover_track = "audio";

// -------------------------------------------------------------------------
// MoQT data-plane (Фаза 2): кастомный надёжный паблишер + подписчик туннеля
// -------------------------------------------------------------------------
// Watermark'и backpressure восходящего потока (байты недоставленных объектов в окне).
static constexpr uint64_t kMoqtUpstreamHighWatermark = 1u << 20;       // 1 MiB -> пауза чтения FD
static constexpr uint64_t kMoqtUpstreamLowWatermark  = 256u * 1024;    // 256 KiB -> возобновление

// EidolonTrackPublisher: байтопоток туннеля -> MoQT-объекты в group 0 / subgroup 0 с
// возрастающим object_id. Один subgroup = один надёжный WT-стрим, поэтому порядок и
// целостность байтов сохранены (под туннелем в Go идёт smux/AEAD, которым нужен lossless).
// В отличие от MoqtOutgoingQueue НЕ вытесняем недоставленные объекты: освобождаем только
// то, что сессия уже вытянула (object_id < highest_pulled_), и так же снимаем backpressure.
class EidolonTrackPublisher : public moqt::MoqtTrackPublisher {
public:
    // on_resumable вызывается (на потоке сессии), когда доставленное освобождено и окно
    // опустилось ниже low-watermark — хост может возобновить своего продюсера. Может быть пуст.
    EidolonTrackPublisher(moqt::FullTrackName track, const quic::QuicClock* clock,
                          std::function<void()> on_resumable = {})
            : track_(std::move(track)), clock_(clock), on_resumable_(std::move(on_resumable)) {}

    // --- Продюсер (поток сессии) ---
    void AddBytes(std::string_view data) {
        if (closed_ || data.empty()) return;
        uint64_t id = next_object_id_++;
        moqt::Location loc(0, id);
        moqt::PublishedObjectMetadata md;
        md.location = loc;
        md.subgroup = 0;
        md.status = moqt::MoqtObjectStatus::kNormal;
        md.publisher_priority = moqt::kDefaultPublisherPriority;
        md.first_object_in_subgroup = (id == 0);
        md.payload_length = data.size();
        md.arrival_time = clock_->ApproximateNow();
        window_.emplace(id, std::make_shared<moqt::CachedObject>(
                md, quiche::QuicheMemSlice::Copy(data), /*fin_after_this=*/false));
        bytes_in_window_ += data.size();
        LOG(INFO) << "EIDOLON_DIAG: TrackPublisher[" << track_.ToString() << "] AddBytes id="
                  << id << " size=" << data.size() << " listeners=" << listeners_.size()
                  << " window=" << bytes_in_window_;
        for (moqt::MoqtObjectListener* l : listeners_) {
            l->OnNewObjectAvailable(loc, /*subgroup=*/0, moqt::kDefaultPublisherPriority);
        }
    }

    void CloseStream() {
        if (closed_) return;
        closed_ = true;
        moqt::Location last(0, next_object_id_ == 0 ? 0 : next_object_id_ - 1);
        for (moqt::MoqtObjectListener* l : listeners_) {
            l->OnNewFinAvailable(last, /*subgroup_id=*/0);
        }
    }

    uint64_t BytesInWindow() const { return bytes_in_window_; }
    // Переустановить resume-колбэк после конструирования (нужно, когда продюсер
    // создаётся позже паблишера — серверный "d"-трек).
    void SetOnResumable(std::function<void()> f) { on_resumable_ = std::move(f); }

    // --- MoqtTrackPublisher ---
    const moqt::FullTrackName& GetTrackName() const override { return track_; }

    std::optional<moqt::PublishedObject> GetCachedObject(
            uint64_t group, std::optional<uint64_t> subgroup, uint64_t min_object,
            uint64_t offset) const override {
        LOG(INFO) << "EIDOLON_DIAG: TrackPublisher[" << track_.ToString() << "] GetCachedObject group="
                  << group << " min_object=" << min_object << " offset=" << offset
                  << " window_objs=" << window_.size();
        if (group != 0) return std::nullopt;
        auto it = window_.lower_bound(min_object);
        if (it == window_.end()) return std::nullopt;  // ещё не произведён — ждём OnNewObjectAvailable
        if (min_object > highest_pulled_) {
            highest_pulled_ = min_object;               // всё < min_object доставлено -> эвикт
            while (!window_.empty() && window_.begin()->first < highest_pulled_) {
                bytes_in_window_ -= window_.begin()->second->metadata().payload_length;
                window_.erase(window_.begin());
            }
            if (on_resumable_ && bytes_in_window_ <= kMoqtUpstreamLowWatermark) on_resumable_();
        }
        return it->second->ToPublishedObject(offset);
    }

    void AddObjectListener(moqt::MoqtObjectListener* listener,
                           const moqt::MessageParameters& /*parameters*/) override {
        listeners_.insert(listener);
        LOG(INFO) << "EIDOLON_DIAG: TrackPublisher[" << track_.ToString()
                  << "] AddObjectListener -> listeners=" << listeners_.size()
                  << " window_objs=" << window_.size();
        listener->OnSubscribeAccepted();
        // ФИКС гонки publish-before-subscribe: продюсер (Go-FD pump) начинает
        // публиковать объекты сразу после dial, ДО того как пир пришлёт SUBSCRIBE.
        // Без реплея forward-доставка сессии стартует с хвоста окна (следующего
        // OnNewObjectAvailable), безвозвратно теряя всё, что было опубликовано до
        // подписки — в т.ч. 50-байтный преамбул (token‖flowID‖padLen) объекта 0 на
        // треке "u", без которого сервер не открывает cb_port. Подписка у нас всегда
        // AbsoluteStart(0,0)+forward(true), поэтому все кэшированные объекты в окне.
        // Проигрываем их новому подписчику по возрастанию id (window_ — std::map);
        // сессия вытянет их через GetCachedObject в правильном порядке. Симметрично
        // чинит и обратный трек "d" (сервер->клиент).
        //
        // Guard: backlog реплеим РОВНО ОДИН РАЗ за жизнь паблишера. У туннеля один
        // логический подписчик-пир (сессия ↔ клиент 1:1), и преамбул/ранние байты
        // нужны только самой первой подписке — дальше всё идёт живой доставкой через
        // AddBytes→OnNewObjectAvailable. При повторном SUBSCRIBE (UNSUBSCRIBE→SUBSCRIBE)
        // окно уже частично эвикнуто по highest_pulled_, и повторный дамп хвоста
        // задвоил бы уже доставленные объекты — поэтому второй раз не реплеим.
        if (backlog_replayed_) return;
        backlog_replayed_ = true;
        // Снапшот id до нотификаций: OnNewObjectAvailable синхронно дёргает
        // GetCachedObject, который эвиктит доставленное из window_, поэтому
        // итерировать сам контейнер во время реплея нельзя (инвалидация).
        std::vector<uint64_t> replay_ids;
        replay_ids.reserve(window_.size());
        for (const auto& entry : window_) replay_ids.push_back(entry.first);
        for (uint64_t id : replay_ids) {
            listener->OnNewObjectAvailable(moqt::Location(0, id), /*subgroup=*/0,
                                           moqt::kDefaultPublisherPriority);
        }
    }
    void RemoveObjectListener(moqt::MoqtObjectListener* listener) override {
        listeners_.erase(listener);
    }
    absl::Status UpdateObjectListener(moqt::MoqtObjectListener* /*listener*/,
                                      const moqt::MessageParameters& /*parameters*/) override {
        return absl::OkStatus();
    }
    std::optional<moqt::Location> largest_location() const override {
        if (window_.empty()) return std::nullopt;
        return moqt::Location(0, window_.rbegin()->first);
    }
    std::optional<quic::QuicTimeDelta> expiration() const override {
        return quic::QuicTimeDelta::Zero();
    }
    // chromium-156 MoQT API: extensions()/TrackExtensions -> properties()/TrackProperties;
    // у трека нет key-value свойств, отдаём пустой TrackProperties.
    const moqt::TrackProperties& properties() const override { return properties_; }
    // Fetch (RFC объекты по запросу) туннелю не нужен: control-plane у нас —
    // live publish/subscribe. В 156 сигнатуры получили FetchResponseCallback, а
    // MoqtFailedFetch удалён — сообщаем kNotSupported через callback и отдаём nullptr
    // (как MoqtOutgoingQueue для неподдерживаемого Fetch).
    std::unique_ptr<moqt::MoqtFetchTask> StandaloneFetch(
            moqt::Location, moqt::Location, moqt::MoqtDeliveryOrder,
            moqt::FetchResponseCallback callback) override {
        std::move(callback)(moqt::MoqtRequestErrorInfo(
                moqt::RequestErrorCode::kNotSupported, std::nullopt,
                "eidolon tunnel: fetch unsupported"));
        return nullptr;
    }
    std::unique_ptr<moqt::MoqtFetchTask> RelativeFetch(
            uint64_t, moqt::MoqtDeliveryOrder, moqt::FetchResponseCallback callback) override {
        std::move(callback)(moqt::MoqtRequestErrorInfo(
                moqt::RequestErrorCode::kNotSupported, std::nullopt,
                "eidolon tunnel: fetch unsupported"));
        return nullptr;
    }
    std::unique_ptr<moqt::MoqtFetchTask> AbsoluteFetch(
            uint64_t, moqt::MoqtDeliveryOrder, moqt::FetchResponseCallback callback) override {
        std::move(callback)(moqt::MoqtRequestErrorInfo(
                moqt::RequestErrorCode::kNotSupported, std::nullopt,
                "eidolon tunnel: fetch unsupported"));
        return nullptr;
    }

private:
    moqt::FullTrackName track_;
    raw_ptr<const quic::QuicClock> clock_;
    std::function<void()> on_resumable_;
    moqt::TrackProperties properties_;
    mutable std::map<uint64_t, std::shared_ptr<moqt::CachedObject>> window_;
    uint64_t next_object_id_ = 0;
    mutable uint64_t bytes_in_window_ = 0;
    mutable uint64_t highest_pulled_ = 0;
    bool closed_ = false;
    bool backlog_replayed_ = false;  // backlog реплеится один раз (первой подписке)
    absl::flat_hash_set<moqt::MoqtObjectListener*> listeners_;
};

// EidolonSubscribeVisitor: объекты нисходящего трека -> байты в Go-FD.
class EidolonSubscribeVisitor : public moqt::SubscribeVisitor {
public:
    explicit EidolonSubscribeVisitor(EidolonSession* sess) : sess_(sess) {}

    void OnReply(const moqt::FullTrackName& ftn,
                 std::variant<moqt::SubscribeOkData, moqt::MoqtRequestErrorInfo> response) override {
        if (std::holds_alternative<moqt::MoqtRequestErrorInfo>(response)) {
            LOG(ERROR) << "EIDOLON_DIAG: MoQT subscribe REJECTED track=" << ftn.ToString();
            sess_->Close();
        } else {
            LOG(INFO) << "EIDOLON_DIAG: MoQT subscribe OK track=" << ftn.ToString();
        }
    }
    void OnCanAckObjects(moqt::MoqtObjectAckFunction) override {}
    void OnObjectFragment(const moqt::FullTrackName& /*ftn*/,
                          const moqt::PublishedObjectMetadata& /*metadata*/,
                          absl::string_view object, uint64_t /*offset*/) override {
        // Один subgroup -> фрагменты приходят по порядку; конкатенация = байтопоток.
        LOG(INFO) << "EIDOLON_DIAG: client downstream OnObjectFragment size=" << object.size();
        sess_->EnqueueFdWrite(object);
    }
    void OnPublishDone(moqt::FullTrackName) override { sess_->Close(); }
    void OnMalformedTrack(const moqt::FullTrackName&) override { sess_->Close(); }
    void OnStreamFin(const moqt::FullTrackName&, moqt::DataStreamIndex) override {}
    void OnStreamReset(const moqt::FullTrackName&, moqt::DataStreamIndex) override {}

private:
    raw_ptr<EidolonSession> sess_;
};

// -------------------------------------------------------------------------
// MoQT datagram-lane (Фаза 4): fire-and-forget паблишер + подписчик датаграмм
// -------------------------------------------------------------------------
// EidolonDatagramPublisher: каждый AddDatagram -> один MoQT datagram-object
// (md.subgroup=nullopt => LivePublisher::SendDatagram => WT/QUIC-датаграмма).
// В отличие от надёжного трека НЕ копим окно: SendDatagram синхронен из
// OnNewObjectAvailable (дёргает GetCachedObject тут же), поэтому держим ровно
// один «текущий» объект и сбрасываем после нотификации. Нет подписчика/
// переполнение -> дроп (семантика UDP). Байты уже зашифрованы Go-кодеком.
class EidolonDatagramPublisher : public moqt::MoqtTrackPublisher {
public:
    EidolonDatagramPublisher(moqt::FullTrackName track, const quic::QuicClock* clock)
            : track_(std::move(track)), clock_(clock) {}

    // --- Продюсер (g_io_thread) ---
    void AddDatagram(std::string_view data) {
        if (closed_ || data.empty() || listeners_.empty()) return;  // нет пути -> дроп
        uint64_t id = next_object_id_++;
        moqt::Location loc(0, id);
        moqt::PublishedObjectMetadata md;
        md.location = loc;
        md.subgroup = std::nullopt;                 // <-- датаграмма
        md.status = moqt::MoqtObjectStatus::kNormal;
        md.publisher_priority = moqt::kDefaultPublisherPriority;
        md.first_object_in_subgroup = std::nullopt;  // для датаграмм недоступно
        md.payload_length = data.size();
        md.arrival_time = clock_->ApproximateNow();
        current_ = std::make_shared<moqt::CachedObject>(
                md, quiche::QuicheMemSlice::Copy(data), /*fin_after_this=*/false);
        current_id_ = id;
        // SendDatagram вызывается синхронно из OnNewObjectAvailable -> GetCachedObject
        // вернёт current_ прямо сейчас. После — объект доставлен (one-shot).
        for (moqt::MoqtObjectListener* l : listeners_) {
            l->OnNewObjectAvailable(loc, /*subgroup=*/std::nullopt,
                                    moqt::kDefaultPublisherPriority);
        }
        current_.reset();
    }
    void CloseStream() { closed_ = true; }

    // --- MoqtTrackPublisher ---
    const moqt::FullTrackName& GetTrackName() const override { return track_; }
    std::optional<moqt::PublishedObject> GetCachedObject(
            uint64_t group, std::optional<uint64_t> /*subgroup*/, uint64_t min_object,
            uint64_t offset) const override {
        if (group != 0 || !current_ || min_object > current_id_) return std::nullopt;
        return current_->ToPublishedObject(offset);
    }
    void AddObjectListener(moqt::MoqtObjectListener* listener,
                           const moqt::MessageParameters& /*parameters*/) override {
        listeners_.insert(listener);
        listener->OnSubscribeAccepted();
        // Backlog НЕ реплеим: датаграммы fire-and-forget, прошлое не досылаем.
    }
    void RemoveObjectListener(moqt::MoqtObjectListener* listener) override {
        listeners_.erase(listener);
    }
    absl::Status UpdateObjectListener(moqt::MoqtObjectListener* /*listener*/,
                                      const moqt::MessageParameters& /*parameters*/) override {
        return absl::OkStatus();
    }
    std::optional<moqt::Location> largest_location() const override {
        return std::nullopt;  // истории не держим
    }
    std::optional<quic::QuicTimeDelta> expiration() const override {
        return quic::QuicTimeDelta::Zero();
    }
    // chromium-156: extensions()/TrackExtensions -> properties()/TrackProperties.
    const moqt::TrackProperties& properties() const override { return properties_; }
    // Fetch датаграм-треку не нужен (fire-and-forget). В 156 +FetchResponseCallback,
    // MoqtFailedFetch удалён -> kNotSupported через callback + nullptr.
    std::unique_ptr<moqt::MoqtFetchTask> StandaloneFetch(
            moqt::Location, moqt::Location, moqt::MoqtDeliveryOrder,
            moqt::FetchResponseCallback callback) override {
        std::move(callback)(moqt::MoqtRequestErrorInfo(
                moqt::RequestErrorCode::kNotSupported, std::nullopt,
                "eidolon dgram: fetch unsupported"));
        return nullptr;
    }
    std::unique_ptr<moqt::MoqtFetchTask> RelativeFetch(
            uint64_t, moqt::MoqtDeliveryOrder, moqt::FetchResponseCallback callback) override {
        std::move(callback)(moqt::MoqtRequestErrorInfo(
                moqt::RequestErrorCode::kNotSupported, std::nullopt,
                "eidolon dgram: fetch unsupported"));
        return nullptr;
    }
    std::unique_ptr<moqt::MoqtFetchTask> AbsoluteFetch(
            uint64_t, moqt::MoqtDeliveryOrder, moqt::FetchResponseCallback callback) override {
        std::move(callback)(moqt::MoqtRequestErrorInfo(
                moqt::RequestErrorCode::kNotSupported, std::nullopt,
                "eidolon dgram: fetch unsupported"));
        return nullptr;
    }

private:
    moqt::FullTrackName track_;
    raw_ptr<const quic::QuicClock> clock_;
    moqt::TrackProperties properties_;
    mutable std::shared_ptr<moqt::CachedObject> current_;  // «текущий» объект под SendDatagram
    mutable uint64_t current_id_ = 0;
    uint64_t next_object_id_ = 0;
    bool closed_ = false;
    absl::flat_hash_set<moqt::MoqtObjectListener*> listeners_;
};

// EidolonDatagramSubscribeVisitor: КАЖДЫЙ объект входящего датаграм-трека = одна
// датаграмма (одна UDP-посылка). НЕ конкатенируем (в отличие от надёжного визитора).
class EidolonDatagramSubscribeVisitor : public moqt::SubscribeVisitor {
public:
    explicit EidolonDatagramSubscribeVisitor(EidolonSession* sess) : sess_(sess) {}
    void OnReply(const moqt::FullTrackName& ftn,
                 std::variant<moqt::SubscribeOkData, moqt::MoqtRequestErrorInfo> response) override {
        if (std::holds_alternative<moqt::MoqtRequestErrorInfo>(response)) {
            LOG(ERROR) << "EIDOLON_DIAG: MoQT dgram subscribe REJECTED track=" << ftn.ToString();
        } else {
            LOG(INFO) << "EIDOLON_DIAG: MoQT dgram subscribe OK track=" << ftn.ToString();
        }
    }
    void OnCanAckObjects(moqt::MoqtObjectAckFunction) override {}
    void OnObjectFragment(const moqt::FullTrackName&, const moqt::PublishedObjectMetadata&,
                          absl::string_view object, uint64_t /*offset*/) override {
        LOG(INFO) << "EIDOLON_DIAG: dgram OnObjectFragment size=" << object.size();
        sess_->EnqueueDatagramWrite(object);  // один объект -> один кадр в Go-FD
    }
    void OnPublishDone(moqt::FullTrackName) override {}
    void OnMalformedTrack(const moqt::FullTrackName&) override {}
    void OnStreamFin(const moqt::FullTrackName&, moqt::DataStreamIndex) override {}
    void OnStreamReset(const moqt::FullTrackName&, moqt::DataStreamIndex) override {}
private:
    raw_ptr<EidolonSession> sess_;
};

// Out-of-line методы EidolonSession, которым нужен полный тип EidolonTrackPublisher.
void EidolonSession::PublishUpstreamBytes(std::string_view data) {
    if (!moqt_local_pub_raw_) return;
    moqt_local_pub_raw_->AddBytes(data);
#if BUILDFLAG(IS_POSIX)
    if (moqt_local_pub_raw_->BytesInWindow() > kMoqtUpstreamHighWatermark) {
        fd_read_controller_.reset();   // backpressure: пауза чтения FD
        moqt_upstream_paused_ = true;
    }
#endif
}

void EidolonSession::CloseUpstream() {
    if (moqt_local_pub_raw_) moqt_local_pub_raw_->CloseStream();
}

// Go датаграм-FD -> датаграм-объекты трека. Кадры [len:2 BE][payload]; один
// кадр = одна датаграмма = один AddDatagram. Неполный хвост остаётся в буфере.
void EidolonSession::OnDatagramFdReadable() {
#if BUILDFLAG(IS_POSIX)
    if (is_closed_ || datagram_fd_ == 0) return;
    std::vector<uint8_t> temp(65536);
    ssize_t n = HANDLE_EINTR(read(static_cast<int>(datagram_fd_), temp.data(), temp.size()));
    bool is_eagain = (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
    if (n > 0) {
        dgram_read_buf_.append(reinterpret_cast<char*>(temp.data()), static_cast<size_t>(n));
        size_t off = 0;
        while (dgram_read_buf_.size() - off >= 2) {
            size_t len = (static_cast<uint8_t>(dgram_read_buf_[off]) << 8) |
                         static_cast<uint8_t>(dgram_read_buf_[off + 1]);
            if (dgram_read_buf_.size() - off - 2 < len) break;  // полный payload ещё не пришёл
            if (moqt_dgram_pub_raw_ && len > 0) {
                moqt_dgram_pub_raw_->AddDatagram(
                        std::string_view(dgram_read_buf_.data() + off + 2, len));
            }
            off += 2 + len;
        }
        if (off > 0) dgram_read_buf_.erase(0, off);
    } else if (n == 0 || (n < 0 && !is_eagain)) {
        Close();
    }
#endif
}

// -------------------------------------------------------------------------
// ХЕЛПЕР ДЛЯ АСИНХРОННОГО ДОЗВОНА QUIC (Без блокировок)
// -------------------------------------------------------------------------
class QUICDialHelper : public net::QuicSessionAttempt::Delegate {
public:
    static void Start(EidolonSession* sess, const std::string& ip, const std::string& sni, uint16_t port, const std::vector<uint8_t>& token, base::WaitableEvent* event) {
        auto* dialer = new QUICDialHelper(sess, ip, sni, port, token, event);
        dialer->Run();
    }
    net::QuicSessionPool* GetQuicSessionPool() override {
        return sess_->url_context->http_transaction_factory()->GetSession()->quic_session_pool();
    }
    const net::QuicSessionAliasKey& GetKey() override { return session_alias_key_; }
    const net::NetLogWithSource& GetNetLog() override { return net_log_; }

private:
    QUICDialHelper(EidolonSession* sess, const std::string& ip, const std::string& sni, uint16_t port, const std::vector<uint8_t>& token, base::WaitableEvent* event)
            : sess_(sess), ip_(ip), sni_(sni), port_(port), token_(token), event_(event), scheme_host_port_("https", sni, port) {
        // Создаем временный ключ сессии для инициализации QuicSessionAliasKey
        net::QuicSessionKey session_key(
                net::HostPortPair(sni, port), net::PRIVACY_MODE_DISABLED, net::ProxyChain::Direct(),
                net::SessionUsage::kDestination, net::SocketTag(),
                net::NetworkAnonymizationKey(), net::SecureDnsPolicy::kAllow,
                false, false, net::handles::kInvalidNetworkHandle);

        session_alias_key_ = net::QuicSessionAliasKey(scheme_host_port_, session_key);
    }

    void Run() {
        net::URLRequestContextBuilder builder;
        builder.DisableHttpCache();

        builder.set_proxy_config_service(
                std::make_unique<net::ProxyConfigServiceFixed>(
                        net::ProxyConfigWithAnnotation::CreateDirect()
                )
        );

        builder.SetCertVerifier(
                std::make_unique<EidolonCertVerifier>(net::CertVerifier::CreateDefault(nullptr))
        );

        auto quic_context = std::make_unique<net::QuicContext>();
        quic_context->params()->supported_versions = net::DefaultSupportedQuicVersions();

        // A3 (Фаза 5): ACK-frequency — экономия радио/батареи клиента. По умолчанию
        // телефон шлёт ACK каждые 2 пакета; на видеопотоке это сотни ACK/с, которые
        // непрерывно греют передатчик и не дают модему уснуть (C-DRX). BBRv3 на
        // сервере работает от своего pacing-таймера и частые ACK ему не нужны.
        // Включаем ACK-децимацию чисто через connection-опции (своего кода в quiche
        // не требуется, серверной правки — тоже):
        //   kAFF2 (client-SENT)      → сервер по завершении handshake шлёт нам
        //                              AckFrequencyFrame (quic_connection.cc:484);
        //   kAFIA (client-INDEP)     → анонсируем min_ack_delay, т.е. РАЗРЕШАЕМ приём
        //                              управления частотой ACK (quic_session.cc:233).
        // Пинг НЕ растёт: кадр строится с reordering_threshold=1 — немедленный ACK
        // при первой же дыре в номерах (fast-retransmit цел), а max_ack_delay
        // ограничен ~0.25·RTT (kPeerAckDecimationDelay).
        quic_context->params()->connection_options.push_back(quic::kAFF2);
        quic_context->params()->client_connection_options.push_back(quic::kAFIA);

        // A5 (ОТЛОЖЕНО, опционально на будущее): явный порядок cipher-suite внешнего
        // QUIC-TLS — AES-128-GCM первым при наличии HWCAP_AES/PMULL (на ARMv8-crypto
        // AES-GCM в 2.5–3× дешевле ChaCha20 по тактам/энергии на МБ), ChaCha20 как
        // фоллбэк для чипов без AES-акселератора. НЕ включаем сейчас: ⚠️ порядок
        // cipher-suite виден в ClientHello и ДОЛЖЕН совпадать с реальным Chrome, иначе
        // уезжает отпечаток (прикрытие, §4/фаза 7). BoringSSL и так предпочитает
        // AES-GCM при аппаратном AES, так что выигрыш может быть уже получен по
        // умолчанию — включать только после сверки отпечатка с живым Chrome.

        builder.SetSpdyAndQuicEnabled(false, true);
        builder.set_quic_context(std::move(quic_context));
        sess_->url_context = builder.Build();

        net::HttpNetworkSession* http_session = sess_->url_context->http_transaction_factory()->GetSession();
        net::QuicSessionPool* quic_pool = http_session->quic_session_pool();

        net::HostPortPair host_port(sni_, port_);

        net::IPAddress ip_addr;
        if (!ip_addr.AssignFromIPLiteral(ip_)) {
            LOG(ERROR) << "EIDOLON_DIAG: QUIC bad IP literal: '" << ip_ << "' sni=" << sni_;
            Finish(false); return;
        }
        LOG(INFO) << "EIDOLON_DIAG: QUIC dialing " << ip_ << ":" << port_ << " sni=" << sni_;

        net::QuicSessionKey session_key(
                host_port, net::PRIVACY_MODE_DISABLED, net::ProxyChain::Direct(),
                net::SessionUsage::kDestination, net::SocketTag(),
                net::NetworkAnonymizationKey(), net::SecureDnsPolicy::kAllow,
                false, false, net::handles::kInvalidNetworkHandle);

        net::QuicEndpoint quic_endpoint(
                net::DefaultSupportedQuicVersions().front(),
                net::IPEndPoint(ip_addr, port_),
                net::ConnectionEndpointMetadata());

        sess_->quic_attempt = quic_pool->CreateSessionAttempt(
                this, session_key, quic_endpoint, 0,
                base::TimeTicks::Now(), base::TimeTicks::Now(),
                std::nullopt, false, {},
                net::MultiplexedSessionCreationInitiator::kUnknown, std::nullopt);

        // 1. Старт хендшейка (учитываем синхронное завершение)
        int rv = sess_->quic_attempt->Start(base::BindOnce(&QUICDialHelper::OnSessionAttemptComplete, base::Unretained(this)));
        if (rv != net::ERR_IO_PENDING) OnSessionAttemptComplete(rv);
    }

    net::QuicSessionAliasKey session_alias_key_;
    net::NetLogWithSource net_log_;

    void OnSessionAttemptComplete(int rv) {
        if (rv != net::OK || !sess_->quic_attempt->session()) {
            LOG(ERROR) << "EIDOLON_DIAG: QUIC session attempt failed rv=" << rv << " ("
                       << net::ErrorToString(rv) << ") has_session="
                       << (sess_->quic_attempt->session() != nullptr) << " sni=" << sni_
                       << " " << ip_ << ":" << port_;
            Finish(false); return;
        }

        sess_->quic_session_handle = sess_->quic_attempt->session()->CreateHandle(std::move(scheme_host_port_));
        if (!sess_->quic_session_handle || !sess_->quic_session_handle->IsConnected()) {
            LOG(ERROR) << "EIDOLON_DIAG: QUIC session handle not connected sni=" << sni_;
            Finish(false); return;
        }

        // 2. Запрос стрима (учитываем синхронное завершение)
        int stream_rv = sess_->quic_session_handle->RequestStream(
                true,
                base::BindOnce(&QUICDialHelper::OnStreamRequested, base::Unretained(this)),
                TRAFFIC_ANNOTATION_FOR_TESTS);

        if (stream_rv != net::ERR_IO_PENDING) OnStreamRequested(stream_rv);
    }

    void OnStreamRequested(int rv) {
        if (rv != net::OK) {
            LOG(ERROR) << "EIDOLON_DIAG: QUIC stream request failed rv=" << rv << " ("
                       << net::ErrorToString(rv) << ") sni=" << sni_;
            Finish(false); return;
        }
        LOG(INFO) << "EIDOLON_DIAG: QUIC stream established sni=" << sni_;

        sess_->quic_stream_handle = sess_->quic_session_handle->ReleaseStream();

        quiche::HttpHeaderBlock headers;
        headers[":method"] = "CONNECT";
        headers[":authority"] = sni_ + ":" + std::to_string(port_);
        headers[":scheme"] = "https";
        headers["user-agent"] = version_info::GetProductNameAndVersionForUserAgent();
        // Токен теперь едет в теле потока (token||flowID||padLen), а не в заголовке.
        (void)token_;
        headers["padding"] = std::string(32, '0');

        sess_->quic_stream_handle->WriteHeaders(std::move(headers), false, nullptr);

        Finish(true);
    }

    void Finish(bool success) {
        if (success) {
            sess_->StartPump();
        } else {
            sess_->Close();
        }
        event_->Signal();
        delete this;
    }

    raw_ptr<EidolonSession> sess_;
    std::string ip_;
    std::string sni_;
    uint16_t port_;
    std::vector<uint8_t> token_;
    raw_ptr<base::WaitableEvent> event_;
    url::SchemeHostPort scheme_host_port_;
};

// -------------------------------------------------------------------------
// MoQT / WebTransport-over-H3 (Фаза 1): visitor + dial helper
// -------------------------------------------------------------------------
// net::WebTransportClient уведомляет наш visitor; мы форвардим события 1:1 в
// quiche MoqtSession (он — webtransport::SessionVisitor). Набор методов совпадает.
class EidolonWtVisitor : public net::WebTransportClientVisitor {
public:
    EidolonWtVisitor(EidolonSession* sess, std::vector<uint8_t> token, base::WaitableEvent* event)
            : sess_(sess), event_(event) {
        sess_->moqt_token_ = std::move(token);
    }

    // Local Network Access: разрешаем (мы подключаемся к своему серверу).
    void OnLocalNetworkAccessCheck(const net::IPEndPoint& /*server_address*/,
                                   const net::NetLogWithSource& /*net_log*/,
                                   net::CompletionOnceCallback callback) override {
        std::move(callback).Run(net::OK);
    }
    void OnBeforeConnect(const net::IPEndPoint& /*server_address*/) override {}

    void OnConnected(scoped_refptr<net::HttpResponseHeaders> /*response_headers*/) override {
        if (sess_->is_closed_) { SignalOnce(false); return; }
        quic::WebTransportSession* wt = sess_->wt_client_->session();
        if (!wt) {
            LOG(ERROR) << "EIDOLON_DIAG: MoQT OnConnected but session()==null";
            // НЕ зовём Close() здесь: мы внутри колбэка wt_client_, а Close()
            // сбросил бы wt_client_ (delete-during-callback). Ставим только флаг —
            // teardown произойдёт при удалении EidolonSession (деструкторы членов).
            sess_->is_closed_ = true; SignalOnce(false); return;
        }
        // Отдельная alarm-factory под таймеры MoqtSession (goaway и т.п.). Мы на
        // g_io_thread — берём его task runner и Chromium-часы.
        auto alarm_factory = std::make_unique<net::QuicChromiumAlarmFactory>(
                base::SingleThreadTaskRunner::GetCurrentDefault().get(),
                quic::QuicChromiumClock::GetInstance());

        moqt::MoqtSessionCallbacks callbacks;
        EidolonSession* sess = sess_;
        callbacks.session_established_callback = [sess] {
            LOG(INFO) << "EIDOLON_DIAG: MoQT session established (peer SETUP ok)";
            if (sess->is_closed_ || !sess->moqt_session_) return;

            // P5.1 (Фаза 5) — начальный keep-alive несущей (active=15с) сразу по
            // установлению, чтобы фон/Doze не рвал сессию по idle ещё ДО того, как
            // Android-слой пришлёт первый eidolon_set_power_state. Дальше интервал
            // уточняется из Kotlin по жизненному циклу. Фаерит лишь в простое.
            if (sess->wt_client_ && sess->wt_client_->session()) {
                auto* wt0 = static_cast<quic::WebTransportHttp3*>(sess->wt_client_->session());
                quic::QuicSpdySession* qs0 = wt0->eidolon_quic_session();
                if (qs0 && qs0->connection()) {
                    qs0->connection()->set_keep_alive_ping_timeout(
                            quic::QuicTime::Delta::FromMilliseconds(kEidolonKeepAliveActiveMs));
                    LOG(INFO) << "EIDOLON_DIAG: P5.1 initial keep-alive armed ("
                              << kEidolonKeepAliveActiveMs << "ms)";
                }
            }

            // --- Фаза 2: двунаправленный туннель на объектах (реактивная модель) ---
            // "u" — публикуем (вверх), "d" — подписываемся (вниз). Нативный слой прозрачен:
            // Go кладёт в FD преамбулу token‖flowID‖pad + данные, мы гоняем их как объекты.
            // WP-D (Фаза 6): namespace БОЛЬШЕ НЕ статичный {"eidolon"} — генерим правдоподобный
            // per-session (тот же генератор, что у cover), чтобы туннель и прикрытие не делились
            // на «фикс-ns vs случайный». Сервер зеркалит присланное имя (берёт tns из анонса).
            // Гейт держится на токене в преамбуле "u" (валидирует Go), не на имени namespace.
            moqt::TrackNamespace ns = EidolonPlausibleNamespace();
            moqt::FullTrackName up_track(ns, "u");
            moqt::FullTrackName down_track(ns, "d");
            absl::string_view tok_sv(reinterpret_cast<const char*>(sess->moqt_token_.data()),
                                     sess->moqt_token_.size());

            // 1. Публикуем восходящий трек: продюсер -> known-publisher -> сессии.
            auto up_pub = std::make_shared<EidolonTrackPublisher>(
                    up_track, quic::QuicChromiumClock::GetInstance(),
                    [sess] { sess->ResumeMoqtUpstream(); });
            sess->moqt_local_pub_raw_ = up_pub.get();
            sess->moqt_local_pub_ = up_pub;
            sess->moqt_known_publisher_ = std::make_unique<moqt::MoqtKnownTrackPublisher>();
            sess->moqt_known_publisher_->Add(up_pub);
            sess->moqt_session_->set_publisher(sess->moqt_known_publisher_.get());

            // Анонсируем namespace с auth-токеном -> сервер валидирует гейт и подпишется на "u".
            moqt::MessageParameters pub_params;
            pub_params.authorization_tokens.push_back(
                    moqt::AuthToken(moqt::AuthTokenType::kOutOfBand, tok_sv));
            sess->moqt_session_->PublishNamespace(
                    ns, pub_params,
                    [](std::variant<moqt::MessageParameters, moqt::MoqtRequestErrorInfo> r) {
                        LOG(INFO) << "EIDOLON_DIAG: MoQT PublishNamespace reply ok="
                                  << std::holds_alternative<moqt::MessageParameters>(r);
                    },
                    [] { LOG(INFO) << "EIDOLON_DIAG: MoQT namespace cancelled by peer"; });

            // 2. Подписка на "d": абсолютный старт (0,0) -> все байты с начала.
            sess->moqt_sub_visitor_ = std::make_unique<EidolonSubscribeVisitor>(sess);
            moqt::MessageParameters sub_params((moqt::Location(0, 0)));  // AbsoluteStart
            sub_params.set_forward(true);
            sub_params.authorization_tokens.push_back(
                    moqt::AuthToken(moqt::AuthTokenType::kOutOfBand, tok_sv));
            sess->moqt_session_->Subscribe(down_track, sess->moqt_sub_visitor_.get(), sub_params);

            // --- Фаза 4: датаграм-трек (ненадёжный путь, проксируемый UDP) ---
            // Публикуем "ud" (вверх-датаграммы) + подписываемся на "dd" (вниз).
            // Тот же namespace "eidolon" и тот же known_publisher. Включается только
            // если Go передал датаграм-FD (datagram_fd_ != 0).
            if (sess->datagram_fd_ != 0) {
                moqt::FullTrackName up_dgram(ns, "ud");
                moqt::FullTrackName down_dgram(ns, "dd");
                auto dgram_pub = std::make_shared<EidolonDatagramPublisher>(
                        up_dgram, quic::QuicChromiumClock::GetInstance());
                sess->moqt_dgram_pub_raw_ = dgram_pub.get();
                sess->moqt_dgram_pub_ = dgram_pub;
                sess->moqt_known_publisher_->Add(dgram_pub);

                sess->moqt_dgram_sub_visitor_ =
                        std::make_unique<EidolonDatagramSubscribeVisitor>(sess);
                moqt::MessageParameters dgram_sub_params((moqt::Location(0, 0)));  // AbsoluteStart
                dgram_sub_params.set_forward(true);
                dgram_sub_params.authorization_tokens.push_back(
                        moqt::AuthToken(moqt::AuthTokenType::kOutOfBand, tok_sv));
                sess->moqt_session_->Subscribe(down_dgram, sess->moqt_dgram_sub_visitor_.get(),
                                               dgram_sub_params);
                sess->StartDatagramPump();
                LOG(INFO) << "EIDOLON_DIAG: datagram-lane up: publish 'ud' + subscribe 'dd'";
            }

            // 3. Запускаем FD-насос (восходящее: FD -> объекты трека "u").
            sess->StartPump();
        };
        callbacks.session_terminated_callback =
                +[](absl::string_view e) { LOG(ERROR) << "EIDOLON_DIAG: MoQT terminated: " << e; };

        sess_->moqt_session_ = std::make_unique<moqt::MoqtSession>(
                wt, moqt::MoqtSessionParameters(quic::Perspective::IS_CLIENT),
                std::move(alarm_factory), std::move(callbacks));

        // WebTransport готов → запускаем MoQT (клиент шлёт свой SETUP). Данные-план
        // (publish/subscribe + FD-насос) поднимается в session_established_callback,
        // т.е. ПОСЛЕ обмена SETUP — иначе SUBSCRIBE уйдёт раньше рукопожатия MoQT.
        sess_->moqt_session_->OnSessionReady();
        LOG(INFO) << "EIDOLON_DIAG: WebTransport connected, MoQT client session created";
        SignalOnce(true);
    }

    void OnConnectionFailed(const net::WebTransportError& error) override {
        LOG(ERROR) << "EIDOLON_DIAG: WebTransport connect failed: " << error.details;
        sess_->is_closed_ = true; SignalOnce(false);  // не Close() внутри колбэка wt_client_
    }
    void OnDraining() override {}
    void OnClosed(const std::optional<net::WebTransportCloseInfo>& close_info) override {
        if (sess_->moqt_session_) {
            sess_->moqt_session_->OnSessionClosed(
                    close_info ? close_info->code : 0,
                    close_info ? close_info->reason : std::string());
        }
        sess_->is_closed_ = true; SignalOnce(false);
    }
    void OnError(const net::WebTransportError& error) override {
        LOG(ERROR) << "EIDOLON_DIAG: WebTransport error: " << error.details;
        if (sess_->moqt_session_) sess_->moqt_session_->OnSessionClosed(0, error.details);
        sess_->is_closed_ = true; SignalOnce(false);
    }

    // Форвардинг в MoqtSession (webtransport::SessionVisitor).
    void OnIncomingBidirectionalStreamAvailable() override {
        if (sess_->moqt_session_) sess_->moqt_session_->OnIncomingBidirectionalStreamAvailable();
    }
    void OnIncomingUnidirectionalStreamAvailable() override {
        if (sess_->moqt_session_) sess_->moqt_session_->OnIncomingUnidirectionalStreamAvailable();
    }
    void OnDatagramReceived(std::string_view datagram) override {
        if (sess_->moqt_session_) sess_->moqt_session_->OnDatagramReceived(datagram);
    }
    void OnCanCreateNewOutgoingBidirectionalStream() override {
        if (sess_->moqt_session_) sess_->moqt_session_->OnCanCreateNewOutgoingBidirectionalStream();
    }
    void OnCanCreateNewOutgoingUnidirectionalStream() override {
        if (sess_->moqt_session_) sess_->moqt_session_->OnCanCreateNewOutgoingUnidirectionalStream();
    }
    void OnDatagramProcessed(std::optional<quic::DatagramStatus> /*status*/) override {}

private:
    void SignalOnce(bool /*success*/) {
        if (signaled_) return;
        signaled_ = true;
        if (event_) event_->Signal();
    }
    raw_ptr<EidolonSession> sess_;
    raw_ptr<base::WaitableEvent> event_;
    bool signaled_ = false;
};

class MoQTDialHelper {
public:
    static void Start(EidolonSession* sess, const std::string& ip, const std::string& sni,
                      uint16_t port, const std::vector<uint8_t>& token, base::WaitableEvent* event,
                      net::handles::NetworkHandle network_handle) {
        LOG(INFO) << "EIDOLON_DIAG: MoQTDialHelper::Start ENTER ip=" << ip
                  << " sni=" << sni << " port=" << port
                  << " network_handle=" << network_handle
                  << " on_io_thread=" << (base::SingleThreadTaskRunner::GetCurrentDefault() != nullptr);
        net::URLRequestContextBuilder builder;
        builder.DisableHttpCache();
        builder.set_proxy_config_service(
                std::make_unique<net::ProxyConfigServiceFixed>(
                        net::ProxyConfigWithAnnotation::CreateDirect()));
        builder.SetCertVerifier(
                std::make_unique<EidolonCertVerifier>(net::CertVerifier::CreateDefault(nullptr)));
        LOG(INFO) << "EIDOLON_DIAG: Start step1 cert_verifier+proxy set";

        // Пин IP (анти-DNS-poisoning): authority = sni, но резолвим sni -> ip статически.
        auto base_resolver = net::HostResolver::CreateStandaloneResolver(nullptr);
        LOG(INFO) << "EIDOLON_DIAG: Start step2 standalone resolver created";
        auto mapped_resolver = std::make_unique<net::MappedHostResolver>(std::move(base_resolver));
        mapped_resolver->AddRuleFromString("MAP " + sni + " " + ip);
        builder.set_host_resolver(std::move(mapped_resolver));
        LOG(INFO) << "EIDOLON_DIAG: Start step3 mapped resolver set (MAP " << sni << " " << ip << ")";

        auto quic_context = std::make_unique<net::QuicContext>();
        quic_context->params()->supported_versions = net::DefaultSupportedQuicVersions();
        // A3 (Фаза 5) — ACK-frequency НА БОЕВОМ MoQT-карьере. Ранее эти опции стояли
        // только в legacy QUICDialHelper (путь eidolon_dial_quic, не используется), т.е.
        // на реальной несущей ACK-децимация была ВЫКЛЮЧЕНА. InitializeQuicConfig()
        // (net/quic/quic_context.cc) переносит connection_options/client_connection_options
        // из params прямиком в QuicConfig WT-клиента, так что здесь они и нужны.
        //   kAFF2 (client-SENT)  → сервер по завершении handshake шлёт нам AckFrequencyFrame;
        //   kAFIA (client-INDEP) → анонсируем min_ack_delay (разрешаем приём управления ACK).
        // Пинг не растёт: reordering_threshold=1 (немедленный ACK на дыру, fast-retransmit
        // цел), max_ack_delay ≤ ~0.25·RTT.
        quic_context->params()->connection_options.push_back(quic::kAFF2);
        quic_context->params()->client_connection_options.push_back(quic::kAFIA);
        // M.1 (Фаза 5) — включаем DPLPMTUD (kMTUH, target 1400): quiche прощупывает путь
        // и поднимает размер пакета несущей до оптимального без фрагментации. Важно для
        // эффективности датаграм-lane/FEC (больше payload на кадр). На миграции делаем
        // ре-пробинг (см. EidolonCommitMigration).
        quic_context->params()->connection_options.push_back(quic::kMTUH);
        // P5.1/P5.2 (Фаза 5) — idle-timeout несущей 120с (дефолт ~30с мал для Doze-
        // heartbeat до 50с). Сервер ставит столько же; эффективный idle = min(обе стороны).
        // Все keep-alive-интервалы (15/25/50с) держатся строго ниже.
        quic_context->params()->idle_connection_timeout =
                base::Seconds(kEidolonCarrierIdleTimeoutSec);
        builder.SetSpdyAndQuicEnabled(false, true);
        builder.set_quic_context(std::move(quic_context));
        // Защищаем UDP-сокеты несущей от собственного VpnService-TUN через protect(fd)
        // (bind-к-NetworkHandle в redroid = ERR_NOT_IMPLEMENTED). network_handle=0 — не
        // Android / без VPN: фабрику не ставим, идём дефолтным путём.
        if (network_handle != net::handles::kInvalidNetworkHandle) {
            builder.set_client_socket_factory(
                    std::make_unique<EidolonProtectingSocketFactory>());
            LOG(INFO) << "EIDOLON_DIAG: installed protecting socket factory (network_handle="
                      << network_handle << ")";
        }
        LOG(INFO) << "EIDOLON_DIAG: Start step4 quic context set, calling builder.Build()";
        sess->url_context = builder.Build();
        LOG(INFO) << "EIDOLON_DIAG: Start step5 URLRequestContext built ok=" << (sess->url_context != nullptr);

        GURL url("https://" + sni + ":" + std::to_string(port) + "/eidolon");
        url::Origin origin = url::Origin::Create(url);
        LOG(INFO) << "EIDOLON_DIAG: Start step6 url=" << url.spec();

        net::WebTransportParameters params;
        params.enable_web_transport_http3 = true;
        // MoQT согласует WebTransport-subprotocol = строка версии MoQT. Клиент ОБЯЗАН
        // предложить kDefaultMoqtVersion (draft16) в application_protocols, иначе WT
        // согласует пустой subprotocol и клиентская MoqtSession рвёт сессию в
        // OnSessionReady: GetNegotiatedSubprotocol() != parameters_.version ->
        // "MOQT peer chose wrong subprotocol" (quiche moqt_session.cc:125-131).
        // Сервер выбирает ровно этот subprotocol в subprotocol_callback.
        params.application_protocols.push_back(std::string(moqt::kDefaultMoqtVersion));
        // Проверка сертификата WT-клиента ПОДТВЕРЖДЕНА (chromium-155
        // net/quic/dedicated_web_transport_http3_client.cc CreateProofVerifier):
        // при пустом server_certificate_fingerprints клиент строит
        // ProofVerifierChromium(context->cert_verifier(), ...) — т.е. использует
        // НАШ EidolonCertVerifier из url_context. Его override-ветка ставит
        // is_issued_by_known_root=true + cert_status=0, что удовлетворяет
        // known-root-требование ProofVerifierChromium (работает и для self-signed
        // cover). e2e подтвердил happy-path (валидный ACME-серт): "WebTransport
        // connected". Поэтому fingerprints/отдельный proof-патч НЕ нужны.
        // (Рантайм override-ветки для self-signed серта пока не прогонялся —
        // проверить, если сервер когда-нибудь отдаёт не-публичный серт.)

        sess->wt_visitor_ = std::make_unique<EidolonWtVisitor>(sess, token, event);
        LOG(INFO) << "EIDOLON_DIAG: Start step7 visitor created, calling CreateWebTransportClient";
        // Несущий QUIC-сокет защищаем от собственного VpnService-TUN через
        // protect(fd) (EidolonProtectingSocketFactory, установлена выше по
        // network_handle). Сюда передаём kInvalidNetworkHandle: bind-к-сети на
        // Android идёт через android_setsocknetwork, которого в нашей среде нет
        // (-> ERR_NOT_IMPLEMENTED). Без защиты сокет уходит в TUN и дозвон падает
        // с ERR_CONNECTION_REFUSED (TCP-линия защищена SetBeforeConnectCallback).
        sess->wt_client_ = net::CreateWebTransportClient(
                url, origin, sess->wt_visitor_.get(), net::NetworkAnonymizationKey(),
                net::handles::kInvalidNetworkHandle, sess->url_context.get(), params);
        LOG(INFO) << "EIDOLON_DIAG: Start step8 WebTransport client created ok=" << (sess->wt_client_ != nullptr);
        // P5.4 (Фаза 5) — подключаем ОБЩИЙ персистентный session-cache к crypto_config
        // этого клиента ДО Connect() (его читает TlsClientHandshaker на старте
        // handshake). Тикеты резумпции с прошлых дозвонов к тому же серверу дают
        // короткий handshake/0-RTT при re-dial после смерти несущей. Метод добавлен
        // патчем (crypto_config_ приватный); для не-Dedicated клиента — no-op.
        if (sess->wt_client_) {
            static_cast<net::DedicatedWebTransportHttp3Client*>(sess->wt_client_.get())
                    ->EidolonEnableResumption();
        }
        LOG(INFO) << "EIDOLON_DIAG: MoQT dialing " << ip << ":" << port << " sni=" << sni;
        // Connect асинхронный: event просигналит visitor из OnConnected/OnConnectionFailed.
        sess->wt_client_->Connect();
        LOG(INFO) << "EIDOLON_DIAG: Start step9 Connect() returned (async, awaiting visitor callback)";
    }
};

// -------------------------------------------------------------------------
// ХЕЛПЕР ДЛЯ АСИНХРОННОГО ДОЗВОНА TCP (Без блокировок)
// -------------------------------------------------------------------------
class TCPDialHelper {
public:
    static void Start(EidolonSession* sess, const std::string& ip, const std::string& sni, uint16_t port, const std::vector<uint8_t>& token, base::WaitableEvent* event) {
        auto* dialer = new TCPDialHelper(sess, ip, sni, port, token, event);
        dialer->Run();
    }

private:
    TCPDialHelper(EidolonSession* sess, const std::string& ip, const std::string& sni, uint16_t port, const std::vector<uint8_t>& token, base::WaitableEvent* event)
            : sess_(sess), ip_(ip), sni_(sni), port_(port), token_(token), event_(event) {}

    void Run() {
        net::IPAddress ip_addr;
        if (!ip_addr.AssignFromIPLiteral(ip_)) {
            LOG(ERROR) << "EIDOLON_DIAG: TCP bad IP literal: '" << ip_ << "' sni=" << sni_;
            Finish(false); return;
        }

        LOG(INFO) << "EIDOLON_DIAG: TCP dialing " << ip_ << ":" << port_ << " sni=" << sni_;
        auto tcp_socket = std::make_unique<net::TCPClientSocket>(
                net::AddressList(net::IPEndPoint(ip_addr, port_)), nullptr, nullptr, nullptr, net::NetLogSource(), net::handles::kInvalidNetworkHandle);

        // EIDOLON_DIAG: защищаем сокет от VpnService до connect. Колбэк вызывается
        // уже после открытия fd (socket Open), но до connect(), поэтому fd валиден.
        net::TCPClientSocket* tcp_ptr = tcp_socket.get();
        tcp_ptr->SetBeforeConnectCallback(base::BindRepeating([](net::TCPClientSocket* s) -> int {
            EidolonProtectFd(s->SocketDescriptorForTesting());
            return net::OK;
        }, base::Unretained(tcp_ptr)));

        raw_socket_ = std::move(tcp_socket);
        int rv = raw_socket_->Connect(base::BindOnce(&TCPDialHelper::OnTcpConnected, base::Unretained(this)));
        if (rv != net::ERR_IO_PENDING) OnTcpConnected(rv);
    }

    void OnTcpConnected(int rv) {
        if (rv != net::OK) {
            LOG(ERROR) << "EIDOLON_DIAG: TCP connect failed rv=" << rv << " ("
                       << net::ErrorToString(rv) << ") " << ip_ << ":" << port_;
            Finish(false); return;
        }

        // 1. Делегируем сборку всего стека (включая TransportSecurityState) билдеру
        net::URLRequestContextBuilder builder;
        builder.DisableHttpCache();

        // Явно отключаем поиск системных прокси (PAC/WPAD)
        // Явно отключаем прокси через фиксированный конфиг, чтобы не падали DCHECK при ошибках SSL
        builder.set_proxy_config_service(
                std::make_unique<net::ProxyConfigServiceFixed>(
                        net::ProxyConfigWithAnnotation::CreateDirect()
                )
        );

        // Внедряем наш кастомный верификатор
        builder.SetCertVerifier(
                std::make_unique<EidolonCertVerifier>(net::CertVerifier::CreateDefault(nullptr))
        );

        // Сохраняем контекст в сессии, чтобы он жил всё время соединения
        sess_->url_context = builder.Build();

        // 2. Извлекаем HttpNetworkSession через фабрику транзакций
        net::HttpNetworkSession* http_session =
                sess_->url_context->http_transaction_factory()->GetSession();

        // 3. Получаем легитимный, правильно инициализированный SSLClientContext!
        net::SSLClientContext* ssl_context = http_session->ssl_client_context();

        // 4. Готовим конфигурацию SSL с нашим токеном
        net::SSLConfig ssl_config;
        ssl_config.eidolon_active = true;

        // token_ теперь несёт мастер-секрет; сам токен (nonce||tag) BoringSSL
        // считает над key_share уже внутри рукопожатия.
        ssl_config.eidolon_secret.assign(token_.begin(), token_.end());

        // 5. Создаем SSLClientSocket штатным фабричным методом Chromium
        sess_->tcp_socket = ssl_context->CreateSSLClientSocket(
                std::move(raw_socket_),
                net::HostPortPair(sni_, port_),
                ssl_config
        );

        rv = sess_->tcp_socket->Connect(base::BindOnce(&TCPDialHelper::OnSslConnected, base::Unretained(this)));
        if (rv != net::ERR_IO_PENDING) OnSslConnected(rv);
    }

    void OnSslConnected(int rv) {
        if (rv != net::OK) {
            LOG(ERROR) << "EIDOLON_DIAG: TCP TLS handshake failed rv=" << rv << " ("
                       << net::ErrorToString(rv) << ") sni=" << sni_ << " " << ip_ << ":" << port_;
        } else {
            LOG(INFO) << "EIDOLON_DIAG: TCP TLS handshake OK sni=" << sni_;
        }
        Finish(rv == net::OK);
    }

    void Finish(bool success) {
        if (success) {
            sess_->StartPump(); // Запускаем помпу на успешном хендшейке
        } else {
            sess_->Close();
        }
        event_->Signal();
        delete this; // Самоуничтожение
    }

    raw_ptr<EidolonSession> sess_;
    std::string ip_;
    std::string sni_;
    uint16_t port_;
    std::vector<uint8_t> token_;
    raw_ptr<base::WaitableEvent> event_;
    std::unique_ptr<net::StreamSocket> raw_socket_;
};

// === СЕРВЕРНАЯ ЧАСТЬ QUIC СТРОГО ПОД ЛИНУКС ===
#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)

// Указатель на серверный QUIC event loop для кросс-потокового WakeUp:
// когда g_io_thread постит задачу на g_quic_thread (WriteOrBufferBody/ResetQUIC),
// будим RunEventLoopOnce, чтобы задача исполнилась без ожидания таймаута (50 мс).
static quic::QuicEventLoop* g_quic_event_loop = nullptr;

static void WakeQuicLoop() {
    if (g_quic_event_loop && g_quic_event_loop->SupportsWakeUp()) {
        g_quic_event_loop->WakeUp();
    }
}

class EidolonServerStream;

class BidirectionalPump : public base::RefCountedThreadSafe<BidirectionalPump> {
public:
    BidirectionalPump(EidolonServerStream* quic_stream, scoped_refptr<base::SingleThreadTaskRunner> quic_runner)
            : quic_stream_(quic_stream), quic_runner_(std::move(quic_runner)),
              read_buf_(base::MakeRefCounted<net::IOBufferWithSize>(65536)) {}

    // Declarations only. Implementations moved below EidolonServerStream.
    void ConnectTCP(uint16_t cb_port, std::string token, std::string session_key, std::string flow_id);
    void WriteToTCP(std::string_view data);
    void DetachQUIC();

private:
    friend class base::RefCountedThreadSafe<BidirectionalPump>;
    ~BidirectionalPump() {
        // tcp_socket_ создан и обслуживается ТОЛЬКО на g_io_thread, поэтому его
        // thread_checker привязан к этому потоку. Последняя ссылка на pump может
        // упасть на g_quic_thread (стрим закрылся/сбросился раньше, чем завершился
        // TCP — напр. клиент отвалился по таймауту): тогда дефолтный деструктор
        // уничтожил бы tcp_socket_ здесь же и вызвал SocketPosix::Close() на чужом
        // потоке → DCHECK(thread_checker_.CalledOnValidThread()) FATAL
        // (socket_posix.cc:432). Поэтому передаём владение сокетом на g_io_thread,
        // где он и будет корректно закрыт. release() не трогает сам сокет (только
        // внутренний указатель unique_ptr), поэтому безопасен на любом потоке.
        if (tcp_socket_ && g_io_thread) {
            g_io_thread->task_runner()->DeleteSoon(FROM_HERE, tcp_socket_.release());
        }
    }

    void OnTCPConnect(std::string token, std::string session_key, std::string flow_id, int rv);
    void PumpTCPToQUIC();
    void OnTCPRead(int rv);
    // Все эти методы и поля живут на g_io_thread, поэтому блокировки им не нужны.
    void TryFlushTCP();
    void OnTCPWriteComplete(int rv);
    void ResetQUIC();

    base::Lock quic_lock_;
    raw_ptr<EidolonServerStream> quic_stream_;
    scoped_refptr<base::SingleThreadTaskRunner> quic_runner_;
    std::unique_ptr<net::StreamSocket> tcp_socket_;
    scoped_refptr<net::IOBufferWithSize> read_buf_;
    // Буфер исходящих в TCP данных и флаги — только g_io_thread.
    bool tcp_connected_ = false;
    bool tcp_write_pending_ = false;
    std::string tcp_write_buf_;
};

class EidolonServerStream : public quic::QuicSpdyStream {
public:
    EidolonServerStream(quic::QuicStreamId id, quic::QuicSpdySession* session, uint16_t cb_port)
            : quic::QuicSpdyStream(id, session, quic::BIDIRECTIONAL), cb_port_(cb_port) {}

    ~EidolonServerStream() override {
        if (pump_) pump_->DetachQUIC();
    }

    void OnInitialHeadersComplete(bool fin, size_t frame_len, const quic::QuicHeaderList& header_list) override {
        quic::QuicSpdyStream::OnInitialHeadersComplete(fin, frame_len, header_list);
        LOG(INFO) << "EIDOLON_DIAG: QUIC server stream headers complete id=" << id() << " fin=" << fin;
        quiche::HttpHeaderBlock response_headers;
        response_headers[":status"] = "200";
        WriteHeaders(std::move(response_headers), false, nullptr);
        // КЛЮЧЕВОЕ: очищаем header_list_, иначе FinishedReadingHeaders()
        // (== headers_decompressed_ && header_list_.empty()) навсегда ложно, и
        // QuicSpdyStream::OnDataAvailable блокирует доставку тела (OnBodyAvailable
        // не вызывается) — DATA-кадры декодируются, но тело не отдаётся приложению.
        ConsumeHeaderList();
    }

    // EIDOLON_DIAG: виден ли вообще входящий DATA-кадр HTTP/3 на этом стриме.
    bool OnDataFrameStart(quic::QuicByteCount header_length, quic::QuicByteCount payload_length) override {
        LOG(INFO) << "EIDOLON_DIAG: QUIC server OnDataFrameStart hdr=" << header_length
                  << " payload=" << payload_length << " id=" << id();
        return quic::QuicSpdyStream::OnDataFrameStart(header_length, payload_length);
    }

    void OnBodyAvailable() override {
        LOG(INFO) << "EIDOLON_DIAG: QUIC server OnBodyAvailable entry HasBytesToRead=" << HasBytesToRead();
        // ВАЖНО: читаем ДЕКОДИРОВАННОЕ тело HTTP/3 через API QuicSpdyStream
        // (HasBytesToRead/GetReadableRegions/MarkConsumed идут в body_manager_),
        // а НЕ sequencer() напрямую. Для HTTP/3 сырой sequencer уже поглощён
        // декодером кадров, поэтому sequencer()->HasBytesToRead() ложен и
        // прежний цикл никогда не выполнялся → ForwardToGo не вызывался.
        while (HasBytesToRead()) {
            struct iovec iov;
            if (GetReadableRegions(&iov, 1) == 0) break;
            std::string_view data(static_cast<const char*>(iov.iov_base), iov.iov_len);

            if (!flow_id_read_) {
                buffer_.append(data);
                MarkConsumed(iov.iov_len);
                LOG(INFO) << "EIDOLON_DIAG: QUIC server body chunk=" << iov.iov_len << " buffered=" << buffer_.size();

                if (buffer_.size() >= 50) {
                    uint16_t pad_len = (static_cast<uint8_t>(buffer_[48]) << 8) | static_cast<uint8_t>(buffer_[49]);
                    if (buffer_.size() >= 50u + pad_len) {
                        std::string token = buffer_.substr(0, 32);
                        std::string flow_id = buffer_.substr(32, 16);
                        flow_id_read_ = true;

                        uint8_t key[32] = {0};

                        quic::QuicCryptoStream* crypto_stream = const_cast<quic::QuicCryptoStream*>(session()->GetCryptoStream());
                        if (crypto_stream) {
                            std::string exported;
                            if (crypto_stream->ExportKeyingMaterial("eidolon-traffic-key", "", 32, &exported)) {
                                memcpy(key, exported.data(), 32);
                            }
                        }

                        ForwardToGo(token, std::string((char*)key, 32), flow_id);

                        if (buffer_.size() > 50u + pad_len) {
                            if (pump_) pump_->WriteToTCP(buffer_.substr(50 + pad_len));
                            else leftover_data_ = buffer_.substr(50 + pad_len);
                        }
                        buffer_.clear();
                    }
                }
            } else {
                if (pump_) pump_->WriteToTCP(data);
                else leftover_data_.append(data);
                MarkConsumed(iov.iov_len);
            }
        }
        if (sequencer()->IsClosed()) OnFinRead();
    }

private:
    void ForwardToGo(const std::string& token, const std::string& session_key, const std::string& flow_id) {
        LOG(INFO) << "EIDOLON_DIAG: QUIC server ForwardToGo cb_port=" << cb_port_
                  << " token_prefix=" << (token.size() >= 2 ? (int)(uint8_t)token[0] : -1);
        pump_ = base::MakeRefCounted<BidirectionalPump>(this, base::SingleThreadTaskRunner::GetCurrentDefault());
        g_io_thread->task_runner()->PostTask(FROM_HERE,
                                             base::BindOnce(&BidirectionalPump::ConnectTCP, pump_, cb_port_, token, session_key, flow_id));

        if (!leftover_data_.empty()) {
            pump_->WriteToTCP(leftover_data_);
            leftover_data_.clear();
        }
    }

    uint16_t cb_port_;
    bool flow_id_read_ = false;
    std::string buffer_;
    std::string leftover_data_;
    scoped_refptr<BidirectionalPump> pump_;
};

// =====================================================================
// Реализации методов BidirectionalPump
// =====================================================================

void BidirectionalPump::ConnectTCP(uint16_t cb_port, std::string token, std::string session_key, std::string flow_id) {
    net::IPAddress ip;
    (void)ip.AssignFromIPLiteral("127.0.0.1"); // <-- ИСПРАВЛЕН ВАРНИНГ [[nodiscard]]

    LOG(INFO) << "EIDOLON_DIAG: QUIC server ConnectTCP -> 127.0.0.1:" << cb_port;
    tcp_socket_ = std::make_unique<net::TCPClientSocket>(
            net::AddressList(net::IPEndPoint(ip, cb_port)), nullptr, nullptr, nullptr, net::NetLogSource(), net::handles::kInvalidNetworkHandle);

    int rv = tcp_socket_->Connect(base::BindOnce(&BidirectionalPump::OnTCPConnect, base::RetainedRef(this), token, session_key, flow_id));
    if (rv != net::ERR_IO_PENDING) OnTCPConnect(token, session_key, flow_id, rv);
}

void BidirectionalPump::WriteToTCP(std::string_view data) {
    // Направление QUIC -> TCP. Буферизуем на g_io_thread; реальная запись — через
    // TryFlushTCP, которая держит не более одной незавершённой записи за раз.
    g_io_thread->task_runner()->PostTask(FROM_HERE, base::BindOnce([](scoped_refptr<BidirectionalPump> self, std::string d) {
        self->tcp_write_buf_.append(d);
        self->TryFlushTCP();
    }, base::RetainedRef(this), std::string(data)));
}

void BidirectionalPump::DetachQUIC() {
    base::AutoLock lock(quic_lock_);
    quic_stream_ = nullptr;
}

void BidirectionalPump::OnTCPConnect(std::string token, std::string session_key, std::string flow_id, int rv) {
    LOG(INFO) << "EIDOLON_DIAG: QUIC server cb_port connect rv=" << rv << " (" << net::ErrorToString(rv) << ")";
    if (rv != net::OK) {
        // Подключение к ядру не удалось — рвём QUIC-поток, иначе клиент висит.
        tcp_socket_.reset();
        ResetQUIC();
        return;
    }
    tcp_connected_ = true;
    // meta (token||session_key||flow_id) обязана уйти первой, до любых данных.
    tcp_write_buf_.insert(0, token + session_key + flow_id);
    TryFlushTCP();
    PumpTCPToQUIC();
}

void BidirectionalPump::TryFlushTCP() {
    if (!tcp_connected_ || tcp_write_pending_ || tcp_write_buf_.empty() || !tcp_socket_) {
        return;
    }
    tcp_write_pending_ = true;
    auto io_buf = base::MakeRefCounted<net::StringIOBuffer>(tcp_write_buf_);
    int rv = tcp_socket_->Write(io_buf.get(), static_cast<int>(tcp_write_buf_.size()),
                                base::BindOnce(&BidirectionalPump::OnTCPWriteComplete, base::RetainedRef(this)),
                                TRAFFIC_ANNOTATION_FOR_TESTS);
    if (rv != net::ERR_IO_PENDING) OnTCPWriteComplete(rv);
}

void BidirectionalPump::OnTCPWriteComplete(int rv) {
    tcp_write_pending_ = false;
    if (rv <= 0) {
        tcp_socket_.reset();
        ResetQUIC();
        return;
    }
    // Возможна частичная запись: убираем записанное и продолжаем с остатком.
    tcp_write_buf_.erase(0, static_cast<size_t>(rv));
    TryFlushTCP();
}

void BidirectionalPump::ResetQUIC() {
    quic_runner_->PostTask(FROM_HERE, base::BindOnce([](scoped_refptr<BidirectionalPump> self) {
        base::AutoLock lock(self->quic_lock_);
        if (self->quic_stream_) {
            self->quic_stream_->Reset(quic::QUIC_STREAM_CANCELLED);
        }
    }, base::RetainedRef(this)));
    WakeQuicLoop();
}

void BidirectionalPump::PumpTCPToQUIC() {
    if (!tcp_socket_) return;
    int rv = tcp_socket_->Read(read_buf_.get(), read_buf_->size(),
                               base::BindOnce(&BidirectionalPump::OnTCPRead, base::RetainedRef(this)));
    if (rv != net::ERR_IO_PENDING) OnTCPRead(rv);
}

void BidirectionalPump::OnTCPRead(int rv) {
    // EIDOLON_DIAG: обратный путь Go -> cb_port -> QUIC. rv>0 = байты ответа ядра.
    LOG(INFO) << "EIDOLON_DIAG: QUIC server OnTCPRead rv=" << rv
              << (rv > 0 ? std::string() : (" (" + net::ErrorToString(rv) + ")"));
    if (rv <= 0) {
        tcp_socket_.reset();
        ResetQUIC();
        return;
    }

    // Следующее чтение запускаем только ПОСЛЕ отдачи порции в QUIC (back-pressure):
    // иначе при медленном QUIC-пире очередь задач с 64-КБ копиями росла бы без предела.
    quic_runner_->PostTask(FROM_HERE, base::BindOnce([](scoped_refptr<BidirectionalPump> self, std::string d) {
        {
            base::AutoLock lock(self->quic_lock_);
            if (self->quic_stream_ == nullptr) {
                LOG(INFO) << "EIDOLON_DIAG: QUIC server WriteOrBufferBody SKIPPED (stream gone) bytes=" << d.size();
                return; // поток уже отвалился — читать дальше незачем
            }
            LOG(INFO) << "EIDOLON_DIAG: QUIC server WriteOrBufferBody -> client bytes=" << d.size();
            self->quic_stream_->WriteOrBufferBody(d, false);
        }
        g_io_thread->task_runner()->PostTask(
            FROM_HERE, base::BindOnce(&BidirectionalPump::PumpTCPToQUIC, self));
    }, base::RetainedRef(this), std::string(read_buf_->data(), rv)));
    WakeQuicLoop();
}

class EidolonServerSession : public quic::QuicSimpleServerSession {
public:
    EidolonServerSession(const quic::QuicConfig& config, const quic::ParsedQuicVersionVector& supported_versions,
                         quic::QuicConnection* connection, quic::QuicSession::Visitor* visitor,
                         quic::QuicCryptoServerStreamBase::Helper* helper, const quic::QuicCryptoServerConfig* crypto_config,
                         quic::QuicCompressedCertsCache* compressed_certs_cache, quic::QuicSimpleServerBackend* backend,
                         uint16_t cb_port)
            : quic::QuicSimpleServerSession(config, supported_versions, connection, visitor, helper, crypto_config, compressed_certs_cache, backend),
              cb_port_(cb_port) {}

protected:
    quic::QuicSpdyStream* CreateIncomingStream(quic::QuicStreamId id) override {
        if (!ShouldCreateIncomingStream(id)) return nullptr;
        LOG(INFO) << "EIDOLON_DIAG: QUIC server incoming stream id=" << id;
        auto* stream = new EidolonServerStream(id, this, cb_port_);
        ActivateStream(absl::WrapUnique(stream));
        return stream;
    }
private:
    uint16_t cb_port_;
};

class EidolonDispatcher : public quic::QuicSimpleDispatcher {
public:
    EidolonDispatcher(const quic::QuicConfig* config, const quic::QuicCryptoServerConfig* crypto_config,
                      quic::QuicVersionManager* version_manager, std::unique_ptr<quic::QuicConnectionHelperInterface> helper,
                      std::unique_ptr<quic::QuicCryptoServerStreamBase::Helper> session_helper,
                      std::unique_ptr<quic::QuicAlarmFactory> alarm_factory, quic::QuicSimpleServerBackend* backend,
                      uint8_t expected_server_connection_id_length, quic::ConnectionIdGeneratorInterface& generator,
                      uint16_t cb_port)
            : quic::QuicSimpleDispatcher(config, crypto_config, version_manager, std::move(helper), std::move(session_helper),
                                         std::move(alarm_factory), backend, expected_server_connection_id_length, generator),
              cb_port_(cb_port) {}

protected:
    std::unique_ptr<quic::QuicSession> CreateQuicSession(
            quic::QuicConnectionId connection_id, const quic::QuicSocketAddress& self_address,
            const quic::QuicSocketAddress& peer_address, absl::string_view alpn,
            const quic::ParsedQuicVersion& version, const quic::ParsedClientHello& parsed_chlo,
            quic::ConnectionIdGeneratorInterface& connection_id_generator) override {

        LOG(INFO) << "EIDOLON_DIAG: QUIC server session created peer=" << peer_address.ToString()
                  << " alpn=" << std::string(alpn) << " version=" << version;

        quic::QuicConnection* connection = new quic::QuicConnection(
                connection_id, self_address, peer_address, helper(), alarm_factory(), writer(),
                false, quic::Perspective::IS_SERVER, {version}, connection_id_generator);

        auto session = std::make_unique<EidolonServerSession>(
                config(), GetSupportedVersions(), connection, this, session_helper(),
                crypto_config(), compressed_certs_cache(), server_backend(), cb_port_);
        session->Initialize();
        return session;
    }
private:
    uint16_t cb_port_;
};

class EidolonServer : public quic::QuicServer {
public:
    EidolonServer(std::unique_ptr<quic::ProofSource> proof_source, quic::QuicSimpleServerBackend* backend, uint16_t cb_port)
            : quic::QuicServer(std::move(proof_source), nullptr, backend), cb_port_(cb_port) {}

protected:
    quic::QuicDispatcher* CreateQuicDispatcher() override {
        return new EidolonDispatcher(
                &config(), &crypto_config(), version_manager(),
                std::make_unique<quic::QuicDefaultConnectionHelper>(),
                std::make_unique<quic::QuicSimpleCryptoServerStreamHelper>(),
                event_loop()->CreateAlarmFactory(), server_backend(),
                expected_server_connection_id_length(), connection_id_generator(), cb_port_);
    }
private:
    uint16_t cb_port_;
};

class QUICListenHelper {
public:
    static void Start(const std::string& host, uint16_t port, uint16_t cb_port) {
        auto* listener = new QUICListenHelper(host, port, cb_port);
        // Запускаем серверный QUIC на выделенном потоке с SingleThreadTaskRunner,
        // а НЕ на ThreadPool: иначе OnBodyAvailable/ForwardToGo падают на
        // SingleThreadTaskRunner::GetCurrentDefault(), а постленные на QUIC-поток
        // задачи (запись в стрим) некому исполнять.
        g_quic_thread->task_runner()->PostTask(
                FROM_HERE, base::BindOnce(&QUICListenHelper::Run, base::Unretained(listener)));
    }

private:
    QUICListenHelper(const std::string& host, uint16_t port, uint16_t cb_port)
            : host_(host), port_(port), cb_port_(cb_port) {}

    void Run() {
        backend_ = std::make_unique<quic::QuicMemoryCacheBackend>();

        auto proof_source = std::make_unique<net::ProofSourceChromium>();
        // ВАЖНО: Инициализация сертификатов, иначе Chromium аппаратно сбросит ClientHello
        if (!proof_source->Initialize(
                base::FilePath(FILE_PATH_LITERAL("cert.pem")),
                base::FilePath(FILE_PATH_LITERAL("key.pem")),
                base::FilePath(FILE_PATH_LITERAL("")))) {
            LOG(ERROR) << "eidolon: QUIC proof source Initialize failed (cert.pem/key.pem not found or invalid)";
            delete this;
            return;
        }

        server_ = std::make_unique<EidolonServer>(std::move(proof_source), backend_.get(), cb_port_);

        quic::QuicIpAddress ip;
        if (!ip.FromString(host_)) {
            LOG(ERROR) << "eidolon: QUIC listen host parse failed: " << host_;
            delete this;
            return;
        }
        quic::QuicSocketAddress address(ip, port_);

        if (!server_->CreateUDPSocketAndListen(address)) {
            LOG(ERROR) << "eidolon: QUIC CreateUDPSocketAndListen failed on " << host_ << ":" << port_;
            delete this;
            return;
        }
        LOG(INFO) << "EIDOLON_DIAG: QUIC server listening (pumped) on " << host_ << ":" << port_;
        g_quic_event_loop = server_->event_loop();
        // Вместо блокирующего HandleEventsForever крутим event loop самоперепостящейся
        // задачей: WaitForEvents = RunEventLoopOnce(50мс), между итерациями g_quic_thread
        // исполняет постленные задачи (запись в QUIC-стрим, reset). Объект живёт, пока
        // крутится помпа (не delete this).
        PumpOnce();
    }

    void PumpOnce() {
        if (!server_) return;
        server_->WaitForEvents();
        g_quic_thread->task_runner()->PostTask(
                FROM_HERE, base::BindOnce(&QUICListenHelper::PumpOnce, base::Unretained(this)));
    }

    std::unique_ptr<quic::QuicMemoryCacheBackend> backend_;
    std::unique_ptr<EidolonServer> server_;
    std::string host_;
    uint16_t port_;
    uint16_t cb_port_;
};

// =====================================================================
// MoQT-СЕРВЕР (Фаза 2): WebTransport-over-H3 + MoQT, мост к cb_port
// =====================================================================
// Зеркалит QUIC-путь (EidolonServerStream + BidirectionalPump), но несущая —
// WebTransport/MoQT. Одна MoqtSession = один flow. Натив прозрачен: преамбулу
// token‖flowID‖padLen‖pad читаем из первых байт восходящего трека "u" (её
// авторитетно валидирует Go по 80-байтовой meta). sessionKey = TLS-экспортер
// несущей QUIC-сессии ("eidolon-traffic-key"), как в QUIC/TCP-путях.

// Мост одной сессии: "u" объекты -> cb_port TCP; cb_port TCP -> "d" объекты.
// down_pub_/session_ трогаем только на g_quic_thread; tcp_* — только на g_io_thread.
class EidolonMoqtFlow : public base::RefCountedThreadSafe<EidolonMoqtFlow> {
public:
    EidolonMoqtFlow(uint16_t cb_port, EidolonTrackPublisher* down_pub, moqt::MoqtSession* session,
                    std::shared_ptr<std::string> dgram_token = nullptr)
            : cb_port_(cb_port), down_pub_(down_pub), session_(session),
              dgram_token_(std::move(dgram_token)),
              read_buf_(base::MakeRefCounted<net::IOBufferWithSize>(65536)) {}

    // [g_quic_thread] Колбэк после разбора преамбулы (dgram_token готов) -> ранний коннект
    // датаграм-cb_port. Если преамбула уже разобрана к моменту установки — вызываем сразу.
    void SetOnPreambleParsed(base::RepeatingClosure cb) {
        on_preamble_parsed_ = std::move(cb);
        if (preamble_done_ && on_preamble_parsed_) on_preamble_parsed_.Run();
    }

    // [g_quic_thread] Байты восходящего трека "u".
    void OnUpstreamBytes(std::string_view data) {
        if (!preamble_done_) {
            buffer_.append(data);
            // Преамбула Фазы 4: token(32)‖flowID(16)‖dgramToken(32)‖padLen(2)‖pad.
            if (buffer_.size() >= 82) {
                uint16_t pad_len = (static_cast<uint8_t>(buffer_[80]) << 8) |
                                   static_cast<uint8_t>(buffer_[81]);
                if (buffer_.size() >= 82u + pad_len) {
                    std::string token = buffer_.substr(0, 32);
                    std::string flow_id = buffer_.substr(32, 16);
                    std::string dgram_token = buffer_.substr(48, 32);  // Фаза 4: токен датаграм-дорожки
                    std::string key = ExportKey();                 // sessionKey (TLS-экспортер)
                    std::string rest = buffer_.substr(82 + pad_len);
                    if (dgram_token_) *dgram_token_ = dgram_token;  // отдаём датаграм-flow'у (тот же peer)
                    preamble_done_ = true;
                    buffer_.clear();
                    LOG(INFO) << "EIDOLON_DIAG: MoQT server preamble ok -> cb_port=" << cb_port_;
                    g_io_thread->task_runner()->PostTask(
                            FROM_HERE, base::BindOnce(&EidolonMoqtFlow::ConnectTCP,
                                                      base::RetainedRef(this), token, key, flow_id, rest));
                    if (on_preamble_parsed_) on_preamble_parsed_.Run();  // ранний коннект датаграм-cb_port
                }
            }
            return;
        }
        g_io_thread->task_runner()->PostTask(
                FROM_HERE, base::BindOnce(&EidolonMoqtFlow::WriteToTCP,
                                          base::RetainedRef(this), std::string(data)));
    }
    void OnUpstreamFin() {}

    // [g_quic_thread] "d"-паблишер освободил доставленное (окно ниже low) -> снова читаем cb_port.
    void ResumeDownstream() {
        if (!downstream_paused_) return;
        downstream_paused_ = false;
        g_io_thread->task_runner()->PostTask(
                FROM_HERE, base::BindOnce(&EidolonMoqtFlow::PumpTCPToDownstream, base::RetainedRef(this)));
    }

    // [g_quic_thread] Сессия уходит: больше не трогаем down_pub_/session_.
    void Detach() { down_pub_ = nullptr; session_ = nullptr; }

private:
    friend class base::RefCountedThreadSafe<EidolonMoqtFlow>;
    ~EidolonMoqtFlow() {
        // tcp_socket_ создаётся/живёт на g_io_thread — закрываем его там же.
        if (tcp_socket_ && g_io_thread) {
            g_io_thread->task_runner()->DeleteSoon(FROM_HERE, tcp_socket_.release());
        }
    }

    // [g_quic_thread] Экспорт keying material несущей QUIC-сессии под WebTransport.
    std::string ExportKey() {
        std::string out;
        if (!session_ || !session_->session()) return out;
        auto* wt = static_cast<quic::WebTransportHttp3*>(session_->session());
        quic::QuicSpdySession* qs = wt->eidolon_quic_session();
        const quic::QuicCryptoStream* cs = qs ? qs->GetCryptoStream() : nullptr;
        if (cs) {
            const_cast<quic::QuicCryptoStream*>(cs)->ExportKeyingMaterial(
                    "eidolon-traffic-key", "", 32, &out);
        }
        return out;
    }

    // [g_io_thread]
    void ConnectTCP(std::string token, std::string key, std::string flow_id, std::string rest) {
        net::IPAddress ip;
        (void)ip.AssignFromIPLiteral("127.0.0.1");
        tcp_socket_ = std::make_unique<net::TCPClientSocket>(
                net::AddressList(net::IPEndPoint(ip, cb_port_)), nullptr, nullptr, nullptr,
                net::NetLogSource(), net::handles::kInvalidNetworkHandle);
        tcp_write_buf_ = token + key + flow_id + rest;  // meta(80) первой, затем данные
        int rv = tcp_socket_->Connect(
                base::BindOnce(&EidolonMoqtFlow::OnTCPConnect, base::RetainedRef(this)));
        if (rv != net::ERR_IO_PENDING) OnTCPConnect(rv);
    }
    void OnTCPConnect(int rv) {
        LOG(INFO) << "EIDOLON_DIAG: MoQT server cb_port connect rv=" << rv;
        if (rv != net::OK) { tcp_socket_.reset(); return; }
        tcp_connected_ = true;
        TryFlushTCP();
        PumpTCPToDownstream();
    }
    void WriteToTCP(std::string data) {
        tcp_write_buf_.append(data);
        TryFlushTCP();
    }
    void TryFlushTCP() {
        if (!tcp_connected_ || tcp_write_pending_ || tcp_write_buf_.empty() || !tcp_socket_) return;
        tcp_write_pending_ = true;
        auto io_buf = base::MakeRefCounted<net::StringIOBuffer>(tcp_write_buf_);
        int rv = tcp_socket_->Write(io_buf.get(), static_cast<int>(tcp_write_buf_.size()),
                base::BindOnce(&EidolonMoqtFlow::OnTCPWriteComplete, base::RetainedRef(this)),
                TRAFFIC_ANNOTATION_FOR_TESTS);
        if (rv != net::ERR_IO_PENDING) OnTCPWriteComplete(rv);
    }
    void OnTCPWriteComplete(int rv) {
        tcp_write_pending_ = false;
        if (rv <= 0) { tcp_socket_.reset(); return; }
        tcp_write_buf_.erase(0, static_cast<size_t>(rv));
        TryFlushTCP();
    }
    void PumpTCPToDownstream() {
        if (!tcp_socket_) return;
        int rv = tcp_socket_->Read(read_buf_.get(), read_buf_->size(),
                base::BindOnce(&EidolonMoqtFlow::OnTCPRead, base::RetainedRef(this)));
        if (rv != net::ERR_IO_PENDING) OnTCPRead(rv);
    }
    void OnTCPRead(int rv) {
        if (rv <= 0) { tcp_socket_.reset(); return; }
        // Отдаём порцию в "d"-паблишер на g_quic_thread, затем читаем дальше (back-pressure).
        g_quic_thread->task_runner()->PostTask(
                FROM_HERE, base::BindOnce([](scoped_refptr<EidolonMoqtFlow> self, std::string d) {
                    if (self->down_pub_) self->down_pub_->AddBytes(d);
                    // Backpressure: если окно "d" переполнено (медленный клиент) — не читаем
                    // cb_port дальше; ResumeDownstream возобновит после слива ниже low-watermark.
                    if (self->down_pub_ && self->down_pub_->BytesInWindow() > kMoqtUpstreamHighWatermark) {
                        self->downstream_paused_ = true;
                    } else {
                        g_io_thread->task_runner()->PostTask(
                                FROM_HERE, base::BindOnce(&EidolonMoqtFlow::PumpTCPToDownstream, self));
                    }
                }, base::RetainedRef(this), std::string(read_buf_->data(), rv)));
        WakeQuicLoop();
    }

    uint16_t cb_port_;
    raw_ptr<EidolonTrackPublisher> down_pub_;  // g_quic_thread
    raw_ptr<moqt::MoqtSession> session_;        // g_quic_thread
    std::shared_ptr<std::string> dgram_token_;  // peer->session_token: пишем из преамбулы (g_quic_thread)
    base::RepeatingClosure on_preamble_parsed_; // g_quic_thread: триггер раннего коннекта датаграм-cb_port
    scoped_refptr<net::IOBufferWithSize> read_buf_;
    bool preamble_done_ = false;                // g_quic_thread
    bool downstream_paused_ = false;            // g_quic_thread (backpressure cb_port->"d")
    std::string buffer_;                        // g_quic_thread
    std::unique_ptr<net::StreamSocket> tcp_socket_;  // g_io_thread
    bool tcp_connected_ = false;                // g_io_thread
    bool tcp_write_pending_ = false;            // g_io_thread
    std::string tcp_write_buf_;                 // g_io_thread
};

// Подписчик восходящего трека "u" на сервере -> байты в мост.
class EidolonMoqtUpstreamVisitor : public moqt::SubscribeVisitor {
public:
    explicit EidolonMoqtUpstreamVisitor(scoped_refptr<EidolonMoqtFlow> flow) : flow_(std::move(flow)) {}
    void OnReply(const moqt::FullTrackName& ftn,
                 std::variant<moqt::SubscribeOkData, moqt::MoqtRequestErrorInfo> r) override {
        LOG(INFO) << "EIDOLON_DIAG: MoQT server subscribe(u) reply ok="
                  << std::holds_alternative<moqt::SubscribeOkData>(r) << " track=" << ftn.ToString();
    }
    void OnCanAckObjects(moqt::MoqtObjectAckFunction) override {}
    void OnObjectFragment(const moqt::FullTrackName&, const moqt::PublishedObjectMetadata&,
                          absl::string_view object, uint64_t) override {
        LOG(INFO) << "EIDOLON_DIAG: MoQT server upstream OnObjectFragment size=" << object.size();
        flow_->OnUpstreamBytes(object);
    }
    void OnPublishDone(moqt::FullTrackName) override { flow_->OnUpstreamFin(); }
    void OnMalformedTrack(const moqt::FullTrackName&) override {}
    void OnStreamFin(const moqt::FullTrackName&, moqt::DataStreamIndex) override {}
    void OnStreamReset(const moqt::FullTrackName&, moqt::DataStreamIndex) override {}
private:
    scoped_refptr<EidolonMoqtFlow> flow_;
};

// Серверный датаграм-мост (Фаза 4): "ud"-объекты -> датаграм cb_port TCP;
// датаграм cb_port -> "dd"-объекты. В отличие от надёжного моста payload'ы
// непрозрачны (уже зашифрованы Go-кодеком), преамбулу не парсим. На cb_port
// первой уходит meta(80)=token‖key‖flowID(zeros) — Go поднимает серверный
// DatagramCodec по key и валидирует token. Fire-and-forget: потерю допускаем.
class EidolonMoqtDatagramFlow : public base::RefCountedThreadSafe<EidolonMoqtDatagramFlow> {
public:
    EidolonMoqtDatagramFlow(uint16_t cb_port, EidolonDatagramPublisher* down_pub,
                            moqt::MoqtSession* session, std::shared_ptr<std::string> dgram_token)
            : cb_port_(cb_port), down_pub_(down_pub), session_(session),
              dgram_token_(std::move(dgram_token)),
              read_buf_(base::MakeRefCounted<net::IOBufferWithSize>(65536)) {}

    // [g_quic_thread] Ранний коннект датаграм-cb_port: вызывается reliable-flow'ом сразу
    // после разбора преамбулы (dgram_token_ готов и СВЕЖ — в окне валидности токена ~15с).
    // Коннект при setup, а не лениво на первой датаграмме (та может прийти через минуты).
    void StartCbPortEager() {
        if (cb_started_) return;
        if (!dgram_token_ || dgram_token_->empty()) return;  // преамбула ещё не разобрана
        cb_started_ = true;
        std::string tok = *dgram_token_;  // g_quic_thread — без гонок с reliable-flow
        std::string key = ExportKey();
        g_io_thread->task_runner()->PostTask(
                FROM_HERE, base::BindOnce(&EidolonMoqtDatagramFlow::ConnectCbPort,
                                          base::RetainedRef(this), tok, key));
        // Фаза 4 (б): периодический push телеметрии несущей в Go (downstream
        // flow control: spare-clamp/ECN для server->client FEC). Снимаем на
        // g_quic_thread (сессия жива), шлём тем же каналом, что датаграммы.
        g_quic_thread->task_runner()->PostDelayedTask(
                FROM_HERE, base::BindOnce(&EidolonMoqtDatagramFlow::EmitStats,
                                          base::RetainedRef(this)),
                base::Milliseconds(200));
    }

    // [g_quic_thread] входящий датаграм-объект с "ud" -> кадр в cb_port TCP.
    void OnUpstreamDatagram(std::string_view data) {
        if (!cb_started_) return;  // ранний коннект ещё не прошёл -> дроп (fire-and-forget)
        std::string frame;
        frame.reserve(2 + data.size());
        frame.push_back(static_cast<char>((data.size() >> 8) & 0xFF));
        frame.push_back(static_cast<char>(data.size() & 0xFF));
        frame.append(data.data(), data.size());
        g_io_thread->task_runner()->PostTask(
                FROM_HERE, base::BindOnce(&EidolonMoqtDatagramFlow::WriteToCb,
                                          base::RetainedRef(this), std::move(frame)));
    }
    // [g_quic_thread] сессия уходит.
    void Detach() { down_pub_ = nullptr; session_ = nullptr; }

private:
    friend class base::RefCountedThreadSafe<EidolonMoqtDatagramFlow>;
    ~EidolonMoqtDatagramFlow() {
        if (tcp_socket_ && g_io_thread) {
            g_io_thread->task_runner()->DeleteSoon(FROM_HERE, tcp_socket_.release());
        }
    }

    // [g_quic_thread] keying material несущей WebTransport/QUIC-сессии.
    std::string ExportKey() {
        std::string out;
        if (!session_ || !session_->session()) return out;
        auto* wt = static_cast<quic::WebTransportHttp3*>(session_->session());
        quic::QuicSpdySession* qs = wt->eidolon_quic_session();
        const quic::QuicCryptoStream* cs = qs ? qs->GetCryptoStream() : nullptr;
        if (cs) {
            const_cast<quic::QuicCryptoStream*>(cs)->ExportKeyingMaterial(
                    "eidolon-traffic-key", "", 32, &out);
        }
        return out;
    }

    // [g_quic_thread] Фаза 4 (б): снимок телеметрии несущей -> кадр в cb_port.
    // Кадр: [0x8000|CarrierStatsWireLen : 2 BE][7×uint64 BE] (bandwidth, cwnd,
    // inflight, rtt_us, lost, ecnCE, maxDatagram). Бит 0x8000 длины отличает его
    // от датаграммы (те всегда < 0x8000). Перепостит себя через 200мс, пока
    // сессия жива; на Detach (session_==null) — тихо останавливается. Доступ к
    // сессии только здесь (g_quic_thread), запись — на g_io_thread (WriteToCb).
    void EmitStats() {
        if (!cb_started_ || !session_ || !session_->session()) return;
        auto* wt = static_cast<quic::WebTransportHttp3*>(session_->session());
        quic::QuicSpdySession* qs = wt->eidolon_quic_session();
        quic::QuicConnection* conn = qs ? qs->connection() : nullptr;
        if (conn) {
            const quic::QuicConnectionStats& cs = conn->GetStats();
            const quic::QuicSentPacketManager& spm = conn->sent_packet_manager();
            uint64_t f[7] = {0, 0, 0, 0, 0, 0, 0};
            int64_t bw = spm.BandwidthEstimate().ToBytesPerSecond();
            if (bw > 0) f[0] = static_cast<uint64_t>(bw);
            f[1] = static_cast<uint64_t>(spm.GetCongestionWindowInBytes());
            f[2] = static_cast<uint64_t>(spm.GetBytesInFlight());
            const quic::RttStats* rtt = spm.GetRttStats();
            if (rtt) {
                int64_t us = rtt->smoothed_rtt().ToMicroseconds();
                if (us > 0) f[3] = static_cast<uint64_t>(us);
            }
            f[4] = static_cast<uint64_t>(cs.packets_lost);
            f[5] = static_cast<uint64_t>(cs.num_ecn_marks_received.ce);
            f[6] = static_cast<uint64_t>(wt->GetMaxDatagramSize());

            const int kLen = 7 * 8;  // == flowctl.CarrierStatsWireLen
            std::string frame;
            frame.reserve(2 + kLen);
            uint16_t hdr = static_cast<uint16_t>(0x8000 | kLen);
            frame.push_back(static_cast<char>((hdr >> 8) & 0xFF));
            frame.push_back(static_cast<char>(hdr & 0xFF));
            for (int i = 0; i < 7; ++i) {
                for (int b = 7; b >= 0; --b) {
                    frame.push_back(static_cast<char>((f[i] >> (b * 8)) & 0xFF));
                }
            }
            g_io_thread->task_runner()->PostTask(
                    FROM_HERE, base::BindOnce(&EidolonMoqtDatagramFlow::WriteToCb,
                                              base::RetainedRef(this), std::move(frame)));
        }
        g_quic_thread->task_runner()->PostDelayedTask(
                FROM_HERE, base::BindOnce(&EidolonMoqtDatagramFlow::EmitStats,
                                          base::RetainedRef(this)),
                base::Milliseconds(200));
    }

    // [g_io_thread]
    void ConnectCbPort(std::string token, std::string key) {
        net::IPAddress ip;
        (void)ip.AssignFromIPLiteral("127.0.0.1");
        tcp_socket_ = std::make_unique<net::TCPClientSocket>(
                net::AddressList(net::IPEndPoint(ip, cb_port_)), nullptr, nullptr, nullptr,
                net::NetLogSource(), net::handles::kInvalidNetworkHandle);
        // meta(80): token(32)‖key(32)‖flowID(16 нулей). Go валидирует token (channel-bound
        // к key=sessionKey), строит серверный DatagramCodec(key). Токен — отдельный свежий
        // (из преамбулы), не reliable (тот одноразовый).
        cb_write_buf_ = token + key + std::string(16, '\0');
        int rv = tcp_socket_->Connect(
                base::BindOnce(&EidolonMoqtDatagramFlow::OnCbConnect, base::RetainedRef(this)));
        if (rv != net::ERR_IO_PENDING) OnCbConnect(rv);
    }
    void OnCbConnect(int rv) {
        LOG(INFO) << "EIDOLON_DIAG: MoQT server dgram cb_port connect rv=" << rv;
        if (rv != net::OK) { tcp_socket_.reset(); return; }
        cb_connected_ = true;
        TryFlushCb();
        PumpCbToDownstream();
    }
    void WriteToCb(std::string frame) {
        cb_write_buf_.append(frame);
        TryFlushCb();
    }
    void TryFlushCb() {
        if (!cb_connected_ || cb_write_pending_ || cb_write_buf_.empty() || !tcp_socket_) return;
        cb_write_pending_ = true;
        auto io_buf = base::MakeRefCounted<net::StringIOBuffer>(cb_write_buf_);
        int rv = tcp_socket_->Write(io_buf.get(), static_cast<int>(cb_write_buf_.size()),
                base::BindOnce(&EidolonMoqtDatagramFlow::OnCbWriteComplete, base::RetainedRef(this)),
                TRAFFIC_ANNOTATION_FOR_TESTS);
        if (rv != net::ERR_IO_PENDING) OnCbWriteComplete(rv);
    }
    void OnCbWriteComplete(int rv) {
        cb_write_pending_ = false;
        if (rv <= 0) { tcp_socket_.reset(); return; }
        cb_write_buf_.erase(0, static_cast<size_t>(rv));
        TryFlushCb();
    }
    void PumpCbToDownstream() {
        if (!tcp_socket_) return;
        int rv = tcp_socket_->Read(read_buf_.get(), read_buf_->size(),
                base::BindOnce(&EidolonMoqtDatagramFlow::OnCbRead, base::RetainedRef(this)));
        if (rv != net::ERR_IO_PENDING) OnCbRead(rv);
    }
    void OnCbRead(int rv) {
        if (rv <= 0) { tcp_socket_.reset(); return; }
        cb_read_buf_.append(read_buf_->data(), static_cast<size_t>(rv));
        // Парсим полные кадры [len:2 BE][payload] -> публикуем каждый как "dd"-объект.
        size_t off = 0;
        while (cb_read_buf_.size() - off >= 2) {
            size_t len = (static_cast<uint8_t>(cb_read_buf_[off]) << 8) |
                         static_cast<uint8_t>(cb_read_buf_[off + 1]);
            if (cb_read_buf_.size() - off - 2 < len) break;
            std::string payload = cb_read_buf_.substr(off + 2, len);
            off += 2 + len;
            if (len == 0) continue;
            g_quic_thread->task_runner()->PostTask(
                    FROM_HERE, base::BindOnce([](scoped_refptr<EidolonMoqtDatagramFlow> self,
                                                 std::string d) {
                        if (self->down_pub_) self->down_pub_->AddDatagram(d);
                    }, base::RetainedRef(this), std::move(payload)));
        }
        if (off > 0) cb_read_buf_.erase(0, off);
        WakeQuicLoop();
        PumpCbToDownstream();  // датаграммы fire-and-forget: читаем дальше без backpressure
    }

    uint16_t cb_port_;
    raw_ptr<EidolonDatagramPublisher> down_pub_;  // g_quic_thread
    raw_ptr<moqt::MoqtSession> session_;           // g_quic_thread
    std::shared_ptr<std::string> dgram_token_;     // peer->session_token (из reliable-преамбулы)
    scoped_refptr<net::IOBufferWithSize> read_buf_;
    bool cb_started_ = false;                      // g_quic_thread
    std::string cb_read_buf_;                      // g_io_thread (недособранный кадр)
    std::unique_ptr<net::StreamSocket> tcp_socket_;  // g_io_thread
    bool cb_connected_ = false;                    // g_io_thread
    bool cb_write_pending_ = false;                // g_io_thread
    std::string cb_write_buf_;                     // g_io_thread
};

// Подписчик входящего датаграм-трека "ud" на сервере -> датаграм-мост.
class EidolonMoqtDatagramUpstreamVisitor : public moqt::SubscribeVisitor {
public:
    explicit EidolonMoqtDatagramUpstreamVisitor(scoped_refptr<EidolonMoqtDatagramFlow> flow)
            : flow_(std::move(flow)) {}
    void OnReply(const moqt::FullTrackName& ftn,
                 std::variant<moqt::SubscribeOkData, moqt::MoqtRequestErrorInfo> r) override {
        LOG(INFO) << "EIDOLON_DIAG: MoQT server subscribe(ud) reply ok="
                  << std::holds_alternative<moqt::SubscribeOkData>(r) << " track=" << ftn.ToString();
    }
    void OnCanAckObjects(moqt::MoqtObjectAckFunction) override {}
    void OnObjectFragment(const moqt::FullTrackName&, const moqt::PublishedObjectMetadata&,
                          absl::string_view object, uint64_t) override {
        flow_->OnUpstreamDatagram(object);  // один объект = одна датаграмма
    }
    void OnPublishDone(moqt::FullTrackName) override {}
    void OnMalformedTrack(const moqt::FullTrackName&) override {}
    void OnStreamFin(const moqt::FullTrackName&, moqt::DataStreamIndex) override {}
    void OnStreamReset(const moqt::FullTrackName&, moqt::DataStreamIndex) override {}
private:
    scoped_refptr<EidolonMoqtDatagramFlow> flow_;
};

// -------------------------------------------------------------------------
// Фаза 6 — сервис-прикрытие (Вариант 3): публичный live cover-паблишер + бродкастер.
// -------------------------------------------------------------------------
// EidolonCoverTrackPublisher — публичный (не токен-гейтный) live-трек прикрытия.
// Модель как у датаграм-паблишера (Фаза 4): каждый чанк контента = один MoQT
// datagram-объект (md.subgroup=nullopt => LivePublisher::SendDatagram), fire-and-
// forget. Для живого медиа это естественно: объекты независимы, поздний вход и
// дропы тривиальны (в отличие от надёжного subgroup-стрима, где эвикшн рвёт
// непрерывность). При появлении первого подписчика цепляемся к бродкастеру
// (= «есть зонд, давай контент»), при уходе последнего — отцепляемся (on-demand).
class EidolonCoverBroadcaster;  // fwd
class EidolonCoverTrackPublisher : public moqt::MoqtTrackPublisher {
public:
    EidolonCoverTrackPublisher(moqt::FullTrackName track, const quic::QuicClock* clock,
                               EidolonCoverBroadcaster* broadcaster)
            : track_(std::move(track)), clock_(clock), broadcaster_(broadcaster) {}

    // [g_quic_thread] бродкастер отдаёт очередной чанк живого контента.
    void PushPayload(std::string_view data) {
        if (closed_ || data.empty() || listeners_.empty()) return;  // нет зонда -> дроп
        uint64_t id = next_object_id_++;
        moqt::Location loc(0, id);
        moqt::PublishedObjectMetadata md;
        md.location = loc;
        md.subgroup = std::nullopt;                  // <-- датаграмма
        md.status = moqt::MoqtObjectStatus::kNormal;
        md.publisher_priority = moqt::kDefaultPublisherPriority;
        md.first_object_in_subgroup = std::nullopt;  // для датаграмм недоступно
        md.payload_length = data.size();
        md.arrival_time = clock_->ApproximateNow();
        current_ = std::make_shared<moqt::CachedObject>(
                md, quiche::QuicheMemSlice::Copy(data), /*fin_after_this=*/false);
        current_id_ = id;
        for (moqt::MoqtObjectListener* l : listeners_) {
            l->OnNewObjectAvailable(loc, /*subgroup=*/std::nullopt,
                                    moqt::kDefaultPublisherPriority);
        }
        current_.reset();  // one-shot: SendDatagram синхронен из OnNewObjectAvailable
    }

    void Detach();  // тело после EidolonCoverBroadcaster (session уходит)

    // --- MoqtTrackPublisher ---
    const moqt::FullTrackName& GetTrackName() const override { return track_; }
    std::optional<moqt::PublishedObject> GetCachedObject(
            uint64_t group, std::optional<uint64_t> /*subgroup*/, uint64_t min_object,
            uint64_t offset) const override {
        if (group != 0 || !current_ || min_object > current_id_) return std::nullopt;
        return current_->ToPublishedObject(offset);
    }
    void AddObjectListener(moqt::MoqtObjectListener* listener,
                           const moqt::MessageParameters& /*parameters*/) override;  // тело ниже
    void RemoveObjectListener(moqt::MoqtObjectListener* listener) override;          // тело ниже
    absl::Status UpdateObjectListener(moqt::MoqtObjectListener* /*listener*/,
                                      const moqt::MessageParameters& /*parameters*/) override {
        return absl::OkStatus();
    }
    std::optional<moqt::Location> largest_location() const override {
        return std::nullopt;  // истории не держим (живой край)
    }
    std::optional<quic::QuicTimeDelta> expiration() const override {
        return quic::QuicTimeDelta::Zero();
    }
    const moqt::TrackProperties& properties() const override { return properties_; }
    std::unique_ptr<moqt::MoqtFetchTask> StandaloneFetch(
            moqt::Location, moqt::Location, moqt::MoqtDeliveryOrder,
            moqt::FetchResponseCallback callback) override {
        std::move(callback)(moqt::MoqtRequestErrorInfo(
                moqt::RequestErrorCode::kNotSupported, std::nullopt, "eidolon cover: fetch unsupported"));
        return nullptr;
    }
    std::unique_ptr<moqt::MoqtFetchTask> RelativeFetch(
            uint64_t, moqt::MoqtDeliveryOrder, moqt::FetchResponseCallback callback) override {
        std::move(callback)(moqt::MoqtRequestErrorInfo(
                moqt::RequestErrorCode::kNotSupported, std::nullopt, "eidolon cover: fetch unsupported"));
        return nullptr;
    }
    std::unique_ptr<moqt::MoqtFetchTask> AbsoluteFetch(
            uint64_t, moqt::MoqtDeliveryOrder, moqt::FetchResponseCallback callback) override {
        std::move(callback)(moqt::MoqtRequestErrorInfo(
                moqt::RequestErrorCode::kNotSupported, std::nullopt, "eidolon cover: fetch unsupported"));
        return nullptr;
    }

private:
    moqt::FullTrackName track_;
    raw_ptr<const quic::QuicClock> clock_;
    raw_ptr<EidolonCoverBroadcaster> broadcaster_;
    moqt::TrackProperties properties_;
    mutable std::shared_ptr<moqt::CachedObject> current_;
    mutable uint64_t current_id_ = 0;
    uint64_t next_object_id_ = 0;
    bool closed_ = false;
    bool attached_ = false;  // зацеплены ли к бродкастеру (= есть подписчик)
    absl::flat_hash_set<moqt::MoqtObjectListener*> listeners_;
};

// EidolonCoverBroadcaster — процессный синглтон: один источник контента (одно
// соединение к Go cover-cb_port) фанится на ВСЕ cover-паблишеры (по одному на
// сессию-зонд). Рефкаунт по числу зацепленных паблишеров: 0->1 коннектим Go
// (Go стартует источник ffmpeg/synthetic), ->0 закрываем (Go глушит источник).
// Фрейминг от Go: [len:2 BE][payload] поверх loopback-TCP. Вся cover-машинерия и
// pubs_ — на g_quic_thread; сокет и чтение — на g_io_thread.
class EidolonCoverBroadcaster {
public:
    static EidolonCoverBroadcaster* Get() {
        static base::NoDestructor<EidolonCoverBroadcaster> inst;
        return inst.get();
    }

    // [g_quic_thread] у паблишера появился первый подписчик.
    void Attach(EidolonCoverTrackPublisher* pub) {
        if (!pubs_.insert(pub).second) return;
        LOG(INFO) << "EIDOLON_DIAG: cover broadcaster attach refcount=" << pubs_.size();
        if (pubs_.size() == 1) StartSource();
    }
    // [g_quic_thread] у паблишера ушёл последний подписчик / сессия закрылась.
    void DetachPub(EidolonCoverTrackPublisher* pub) {
        if (pubs_.erase(pub) == 0) return;
        LOG(INFO) << "EIDOLON_DIAG: cover broadcaster detach refcount=" << pubs_.size();
        if (pubs_.empty()) StopSource();
    }

private:
    friend class base::NoDestructor<EidolonCoverBroadcaster>;
    EidolonCoverBroadcaster()
            : read_buf_(base::MakeRefCounted<net::IOBufferWithSize>(65536)) {}

    // [g_quic_thread] поднять источник: взвести want_connected_ и попросить g_io_thread коннектить.
    void StartSource() {
        want_connected_.store(true);
        g_io_thread->task_runner()->PostTask(
                FROM_HERE, base::BindOnce(&EidolonCoverBroadcaster::ConnectOnIo,
                                          base::Unretained(this)));
    }
    // [g_quic_thread] погасить источник.
    void StopSource() {
        want_connected_.store(false);
        g_io_thread->task_runner()->PostTask(
                FROM_HERE, base::BindOnce(&EidolonCoverBroadcaster::CloseOnIo,
                                          base::Unretained(this)));
    }

    // [g_io_thread]
    void ConnectOnIo() {
        if (!want_connected_.load() || socket_ || g_cover_cb_port == 0) return;
        net::IPAddress ip;
        (void)ip.AssignFromIPLiteral("127.0.0.1");
        socket_ = std::make_unique<net::TCPClientSocket>(
                net::AddressList(net::IPEndPoint(ip, g_cover_cb_port)), nullptr, nullptr, nullptr,
                net::NetLogSource(), net::handles::kInvalidNetworkHandle);
        int rv = socket_->Connect(
                base::BindOnce(&EidolonCoverBroadcaster::OnConnect, base::Unretained(this)));
        if (rv != net::ERR_IO_PENDING) OnConnect(rv);
    }
    void OnConnect(int rv) {
        LOG(INFO) << "EIDOLON_DIAG: cover source connect rv=" << rv;
        if (rv != net::OK || !want_connected_.load()) { socket_.reset(); return; }
        inbuf_.clear();
        ReadOnIo();
    }
    void ReadOnIo() {
        if (!socket_) return;
        int rv = socket_->Read(read_buf_.get(), read_buf_->size(),
                base::BindOnce(&EidolonCoverBroadcaster::OnRead, base::Unretained(this)));
        if (rv != net::ERR_IO_PENDING) OnRead(rv);
    }
    void OnRead(int rv) {
        if (rv <= 0 || !want_connected_.load()) { socket_.reset(); return; }
        inbuf_.append(read_buf_->data(), static_cast<size_t>(rv));
        // Выделяем полные кадры [len:2 BE][payload] и шлём их на g_quic_thread.
        size_t pos = 0;
        while (inbuf_.size() - pos >= 2) {
            size_t n = (static_cast<uint8_t>(inbuf_[pos]) << 8) |
                       static_cast<uint8_t>(inbuf_[pos + 1]);
            if (inbuf_.size() - pos - 2 < n) break;  // кадр ещё не целиком
            std::string payload = inbuf_.substr(pos + 2, n);
            pos += 2 + n;
            g_quic_thread->task_runner()->PostTask(
                    FROM_HERE, base::BindOnce(&EidolonCoverBroadcaster::Distribute,
                                              base::Unretained(this), std::move(payload)));
        }
        if (pos > 0) inbuf_.erase(0, pos);
        WakeQuicLoop();
        ReadOnIo();
    }
    void CloseOnIo() {
        if (want_connected_.load()) return;  // гонка start/stop/start: оставляем жить
        socket_.reset();
        inbuf_.clear();
    }

    // [g_quic_thread] раздать кадр всем зацепленным cover-паблишерам. Снапшот до
    // нотификаций: PushPayload синхронно дёргает SendDatagram, который при обрыве может
    // ре-энтрантно снять подписчика (DetachPub) и изменить pubs_ под итерацией.
    void Distribute(std::string payload) {
        std::vector<EidolonCoverTrackPublisher*> snapshot(pubs_.begin(), pubs_.end());
        for (EidolonCoverTrackPublisher* p : snapshot) p->PushPayload(payload);
    }

    absl::flat_hash_set<EidolonCoverTrackPublisher*> pubs_;  // g_quic_thread
    std::unique_ptr<net::TCPClientSocket> socket_;           // g_io_thread
    scoped_refptr<net::IOBufferWithSize> read_buf_;          // g_io_thread
    std::string inbuf_;                                      // g_io_thread
    std::atomic<bool> want_connected_{false};
};

void EidolonCoverTrackPublisher::AddObjectListener(
        moqt::MoqtObjectListener* listener, const moqt::MessageParameters& /*parameters*/) {
    listeners_.insert(listener);
    listener->OnSubscribeAccepted();
    LOG(INFO) << "EIDOLON_DIAG: cover subscribe accepted track=" << track_.ToString()
              << " listeners=" << listeners_.size();
    if (!attached_) {
        attached_ = true;
        if (broadcaster_) broadcaster_->Attach(this);  // 0->1: старт источника
    }
    // Backlog НЕ реплеим: живой край, прошлое не досылаем (как у датаграм-трека).
}

void EidolonCoverTrackPublisher::RemoveObjectListener(moqt::MoqtObjectListener* listener) {
    listeners_.erase(listener);
    if (listeners_.empty() && attached_) {
        attached_ = false;
        if (broadcaster_) broadcaster_->DetachPub(this);  // ->0: стоп источника
    }
}

void EidolonCoverTrackPublisher::Detach() {
    closed_ = true;
    if (attached_) {
        attached_ = false;
        if (broadcaster_) broadcaster_->DetachPub(this);
    }
    listeners_.clear();
}

// Всё состояние одной MoQT-сессии; живёт, пока жива MoqtSession (держим в
// session_deleted_callback). Сессия ссылается на publisher/visitor сырыми указателями.
struct EidolonMoqtPeer {
    uint16_t cb_port = 0;
    std::shared_ptr<EidolonTrackPublisher> down_pub;          // "d" (сервер->клиент)
    std::unique_ptr<moqt::MoqtKnownTrackPublisher> known_publisher;
    std::unique_ptr<moqt::SubscribeVisitor> up_visitor;       // "u" (клиент->сервер)
    scoped_refptr<EidolonMoqtFlow> flow;
    bool subscribed_up = false;

    // --- Фаза 4: датаграм-lane ---
    uint16_t dgram_cb_port = 0;
    std::shared_ptr<EidolonDatagramPublisher> down_dgram_pub;      // "dd" (сервер->клиент)
    std::unique_ptr<moqt::SubscribeVisitor> dgram_up_visitor;      // "ud" (клиент->сервер)
    scoped_refptr<EidolonMoqtDatagramFlow> dgram_flow;
    bool subscribed_up_dgram = false;

    // Фаза 4: отдельный свежий токен датаграм-дорожки, снятый reliable-flow'ом из преамбулы
    // "u" и переданный датаграм-flow'у для meta cb_port (channel-bound к sessionKey, Go
    // валидирует). Пишется reliable-flow'ом, читается датаграм-flow'ом — оба на g_quic_thread.
    std::shared_ptr<std::string> session_token = std::make_shared<std::string>();

    // --- Фаза 6: сервис-прикрытие (Вариант 3) ---
    std::shared_ptr<EidolonCoverTrackPublisher> cover_pub;  // публичный live cover-трек
    moqt::TrackNamespace cover_ns;                          // per-session namespace прикрытия
};

// Конфигурируем только что созданную серверную MoqtSession (вызывается из handler_factory;
// session() трогать здесь НЕЛЬЗЯ — он ещё не готов, только сохраняем).
static void ConfigureEidolonMoqtSession(moqt::MoqtSession* session, uint16_t cb_port,
                                        uint16_t dgram_cb_port) {
    auto peer = std::make_shared<EidolonMoqtPeer>();
    peer->cb_port = cb_port;
    peer->dgram_cb_port = dgram_cb_port;

    peer->known_publisher = std::make_unique<moqt::MoqtKnownTrackPublisher>();

    // Фаза 6: публичный cover-паблишер прикрытия в тот же known_publisher. namespace
    // per-session (генератор) либо фикс-override из конфига; трек из конфига. Зонд,
    // подписавшись на анонсированный cover-ns, получит живой контент (on-demand).
    // Независим от туннельного ns (у прикрытия своё имя).
    if (g_cover_enabled) {
        peer->cover_ns = g_cover_ns_override.empty()
                ? EidolonPlausibleNamespace()
                : moqt::TrackNamespace({absl::string_view(g_cover_ns_override)});
        moqt::FullTrackName cover_track(peer->cover_ns, g_cover_track);
        peer->cover_pub = std::make_shared<EidolonCoverTrackPublisher>(
                cover_track, quic::QuicDefaultClock::Get(), EidolonCoverBroadcaster::Get());
        peer->known_publisher->Add(peer->cover_pub);
    }

    session->set_publisher(peer->known_publisher.get());

    EidolonMoqtPeer* peer_raw = peer.get();
    // WP-D (Фаза 6): туннельный namespace выбирает КЛИЕНТ (per-session, правдоподобный),
    // сервер ЗЕРКАЛИТ присланное имя tns из анонса. Поэтому всю туннельную проводку,
    // зависящую от имени (down_pub "d" + мост cb_port + подписки "u"/"ud"/"dd"), создаём
    // ЗДЕСЬ: раньше ns был захардкожен {"eidolon"} и проводка стояла в config-time, но имя
    // известно только из анонса. Клиент сперва анонсит, ПОТОМ подписывается на "d" — так
    // down_pub регистрируется в known_publisher ДО прихода SUBSCRIBE(d). Гейт — токен в
    // преамбуле "u" (валидирует Go), не имя namespace.
    session->callbacks().incoming_publish_namespace_callback =
            [session, peer_raw](const moqt::TrackNamespace& tns,
                                const moqt::MessageParameters* params,
                                moqt::MoqtResponseCallback cb) {
                if (cb) std::move(cb)(moqt::MessageParameters{});  // accept
                if (params == nullptr) return;                     // DONE
                if (!peer_raw->subscribed_up) {
                    peer_raw->subscribed_up = true;
                    moqt::FullTrackName up_track(tns, "u");
                    moqt::FullTrackName down_track(tns, "d");
                    // "d"-паблишер (сервер->клиент) + reliable-мост cb_port под присланным ns.
                    peer_raw->down_pub = std::make_shared<EidolonTrackPublisher>(
                            down_track, quic::QuicDefaultClock::Get());
                    peer_raw->known_publisher->Add(peer_raw->down_pub);
                    peer_raw->flow = base::MakeRefCounted<EidolonMoqtFlow>(
                            peer_raw->cb_port, peer_raw->down_pub.get(), session,
                            peer_raw->session_token);
                    peer_raw->up_visitor =
                            std::make_unique<EidolonMoqtUpstreamVisitor>(peer_raw->flow);
                    // Backpressure cb_port->"d": возобновляем чтение cb_port при сливе окна "d".
                    peer_raw->down_pub->SetOnResumable(
                            [f = peer_raw->flow.get()] { f->ResumeDownstream(); });
                    moqt::MessageParameters sub((moqt::Location(0, 0)));  // AbsoluteStart
                    sub.set_forward(true);
                    session->Subscribe(up_track, peer_raw->up_visitor.get(), sub);
                    LOG(INFO) << "EIDOLON_DIAG: MoQT server accepted namespace " << tns.ToString()
                              << ", subscribed(u)";
                }
                // Датаграм-lane (Фаза 4): токен НЕ из namespace authorization_tokens (он не
                // доезжает до Go сырыми 32 байтами). Отдельный свежий dgramToken приходит в
                // reliable-преамбуле "u"; reliable-flow кладёт его в peer->session_token и
                // триггерит ранний коннект датаграм-cb_port (StartCbPortEager) — токен свеж.
                if (peer_raw->dgram_cb_port != 0 && !peer_raw->subscribed_up_dgram) {
                    peer_raw->subscribed_up_dgram = true;
                    moqt::FullTrackName up_dgram(tns, "ud");
                    moqt::FullTrackName down_dgram(tns, "dd");
                    peer_raw->down_dgram_pub = std::make_shared<EidolonDatagramPublisher>(
                            down_dgram, quic::QuicDefaultClock::Get());
                    peer_raw->known_publisher->Add(peer_raw->down_dgram_pub);
                    peer_raw->dgram_flow = base::MakeRefCounted<EidolonMoqtDatagramFlow>(
                            peer_raw->dgram_cb_port, peer_raw->down_dgram_pub.get(), session,
                            peer_raw->session_token);
                    peer_raw->dgram_up_visitor =
                            std::make_unique<EidolonMoqtDatagramUpstreamVisitor>(peer_raw->dgram_flow);
                    moqt::MessageParameters dsub((moqt::Location(0, 0)));
                    dsub.set_forward(true);
                    session->Subscribe(up_dgram, peer_raw->dgram_up_visitor.get(), dsub);
                    if (peer_raw->flow) {
                        peer_raw->flow->SetOnPreambleParsed(base::BindRepeating(
                                &EidolonMoqtDatagramFlow::StartCbPortEager, peer_raw->dgram_flow));
                    }
                    LOG(INFO) << "EIDOLON_DIAG: MoQT server subscribed(ud) datagram-lane ns="
                              << tns.ToString();
                }
            };

    // Фаза 6: по установлению сессии (после SETUP) сервер АНОНСИРУЕТ публичный
    // cover-namespace подписчику — чтобы зонд узнал имя (оно per-session/рандомно) и
    // подписался. Анонс уходит ВСЕМ сессиям (и туннельным): туннельный клиент мягко
    // отклонит его дефолтным incoming_publish_namespace_callback (kNotSupported, сессию
    // не рвёт) — это ещё и усиливает неотличимость (все сессии несут cover-анонс).
    if (g_cover_enabled) {
        EidolonMoqtPeer* peer_raw2 = peer.get();
        session->callbacks().session_established_callback = [session, peer_raw2] {
            if (!peer_raw2->cover_pub) return;
            moqt::MessageParameters pub_params;  // публичный трек: без auth-токена
            session->PublishNamespace(
                    peer_raw2->cover_ns, pub_params,
                    [](std::variant<moqt::MessageParameters, moqt::MoqtRequestErrorInfo> r) {
                        LOG(INFO) << "EIDOLON_DIAG: cover PublishNamespace reply ok="
                                  << std::holds_alternative<moqt::MessageParameters>(r);
                    },
                    [] { LOG(INFO) << "EIDOLON_DIAG: cover namespace cancelled by peer"; });
            LOG(INFO) << "EIDOLON_DIAG: cover announced ns=" << peer_raw2->cover_ns.ToString();
        };
    }

    // Держим peer живым до конца сессии; затем отвязываем мосты.
    session->callbacks().session_deleted_callback = [peer]() mutable {
        if (peer->flow) peer->flow->Detach();
        if (peer->dgram_flow) peer->dgram_flow->Detach();
        if (peer->cover_pub) peer->cover_pub->Detach();  // Фаза 6: стоп источника при уходе зонда
    };
}

// Серверный listen MoQT: инлайн-аналог moqt::MoqtServer (чтобы eidolon_bridge.cc,
// видящий quic/tools, собрал всё сам — без линковки tools/moqt_server.cc в moqt source_set).
class EidolonMoqtListenHelper {
public:
    static void Start(const std::string& host, uint16_t port, uint16_t cb_port,
                      uint16_t dgram_cb_port) {
        auto* self = new EidolonMoqtListenHelper(host, port, cb_port, dgram_cb_port);
        g_quic_thread->task_runner()->PostTask(
                FROM_HERE, base::BindOnce(&EidolonMoqtListenHelper::Run, base::Unretained(self)));
    }

private:
    EidolonMoqtListenHelper(const std::string& host, uint16_t port, uint16_t cb_port,
                            uint16_t dgram_cb_port)
            : host_(host), port_(port), cb_port_(cb_port), dgram_cb_port_(dgram_cb_port),
              config_(moqt::GenerateQuicConfig()) {}  // QuicConfig не копируется присваиванием

    void Run() {
        auto proof_source = std::make_unique<net::ProofSourceChromium>();
        if (!proof_source->Initialize(base::FilePath(FILE_PATH_LITERAL("cert.pem")),
                                      base::FilePath(FILE_PATH_LITERAL("key.pem")),
                                      base::FilePath(FILE_PATH_LITERAL("")))) {
            LOG(ERROR) << "eidolon: MoQT proof source Initialize failed (cert.pem/key.pem)";
            delete this; return;
        }

        char secret[32];
        quic::QuicRandom::GetInstance()->RandBytes(secret, sizeof(secret));
        // config_ инициализирован в init-list (GenerateQuicConfig): присваивать нельзя.
        crypto_config_ = std::make_unique<quic::QuicCryptoServerConfig>(
                std::string(secret, sizeof(secret)), quic::QuicRandom::GetInstance(),
                std::move(proof_source), quic::KeyExchangeSource::Default());
        version_manager_ = std::make_unique<quic::QuicVersionManager>(
                quic::CurrentSupportedVersionsWithTls());
        conn_id_gen_ = std::make_unique<quic::DeterministicConnectionIdGenerator>(
                quic::kQuicDefaultConnectionIdLength);
        event_loop_ = quic::GetDefaultEventLoop()->Create(quic::QuicDefaultClock::Get());

        // P5.2 (Фаза 5) — серверный idle-timeout 120с, в пару к клиентскому (эффективный
        // idle = min(обе стороны)). Нужен запас под клиентский Doze-heartbeat (до 50с),
        // иначе сервер закрыл бы сессию в простое. Отдельный серверный keep-alive-пинг НЕ
        // шлём намеренно: клиентский heartbeat (15/25/50с) уже гонит ДВУНАПРАВЛЕННЫЙ
        // трафик (client→PING→server→ACK→client), чего достаточно, чтобы NAT/роутер на
        // пути НЕ «замораживал» UDP-маппинг ни в одну сторону. config_ инициализирован
        // в init-list (GenerateQuicConfig); присваивать нельзя, но мутировать — можно.
        config_.SetIdleNetworkTimeout(
                quic::QuicTime::Delta::FromSeconds(kEidolonCarrierIdleTimeoutSec));
        LOG(INFO) << "EIDOLON_DIAG: P5.2 server idle-timeout set to "
                  << kEidolonCarrierIdleTimeoutSec << "s";

        dispatcher_ = std::make_unique<quic::WebTransportOnlyDispatcher>(
                &config_, crypto_config_.get(), version_manager_.get(),
                std::make_unique<quic::QuicDefaultConnectionHelper>(),
                std::make_unique<quic::QuicSimpleCryptoServerStreamHelper>(),
                event_loop_->CreateAlarmFactory(), quic::kQuicDefaultConnectionIdLength,
                *conn_id_gen_);

        uint16_t cb_port = cb_port_;
        uint16_t dgram_cb_port = dgram_cb_port_;
        quic::QuicEventLoop* loop = event_loop_.get();
        dispatcher_->parameters().handler_factory =
                [cb_port, dgram_cb_port, loop](webtransport::Session* session,
                                const quic::WebTransportIncomingRequestDetails& /*details*/)
                        -> absl::StatusOr<quic::WebTransportConnectResponse> {
                    auto moqt_session = std::make_unique<moqt::MoqtSession>(
                            session, moqt::MoqtSessionParameters(quic::Perspective::IS_SERVER),
                            loop->CreateAlarmFactory());
                    ConfigureEidolonMoqtSession(moqt_session.get(), cb_port, dgram_cb_port);
                    quic::WebTransportConnectResponse response;
                    response.visitor = std::move(moqt_session);
                    return response;
                };
        dispatcher_->parameters().subprotocol_callback =
                +[](absl::Span<const absl::string_view> subs) -> int {
                    for (size_t i = 0; i < subs.size(); ++i) {
                        if (subs[i] == moqt::kDefaultMoqtVersion) return static_cast<int>(i);
                    }
                    return -1;
                };

        quic::QuicIpAddress ip;
        if (!ip.FromString(host_)) {
            LOG(ERROR) << "eidolon: MoQT listen host parse failed: " << host_;
            delete this; return;
        }
        quic::QuicSocketAddress address(ip, port_);
        auto fd = quic::CreateAndBindServerSocket(address);
        if (!fd.ok()) {
            LOG(ERROR) << "eidolon: MoQT CreateAndBindServerSocket failed: " << fd.status();
            delete this; return;
        }
        fd_ = *std::move(fd);
        auto io = quic::QuicServerIoHarness::Create(event_loop_.get(), dispatcher_.get(), *fd_);
        if (!io.ok()) {
            LOG(ERROR) << "eidolon: MoQT QuicServerIoHarness::Create failed: " << io.status();
            delete this; return;
        }
        io_ = *std::move(io);
        // A1 (Фаза 5): GSO batch-writer на отдачу сервера вместо per-packet
        // QuicDefaultPacketWriter (что ставит io_->InitializeWriter). Ядро нарезает
        // пачку QUIC-пакетов одним sendmmsg/UDP_SEGMENT — экономия CPU/энергии под
        // высоким битрейтом. Пинг НЕ растёт: тайминг держит BBRv3-pacing, GSO лишь
        // группирует уже запланированные пакеты. fd_ (OwnedSocketFd) переживает
        // writer; writer владения fd не берёт (как default).
        // ЛИНК: реализации batch_writer (linux_only_srcs: quic_gso_batch_writer.cc,
        // quic_batch_writer_base/buffer.cc, quic_linux_socket_utils.cc) Chromium не
        // собирает ни в один GN-таргет — втянуты в static_library("epoll_tool_support")
        // патчем patch_chromium_v152.py (п.10a): он Linux-only, libeidolon его уже
        // линкует, и в нём лежит quic_syscall_wrapper (единственная внешняя зависимость
        // группы). Ядро сервера GSO поддерживает (5.15, UDP_SEGMENT OK). Откат =
        // io_->InitializeWriter();
        dispatcher_->InitializeWithWriter(new quic::QuicGsoBatchWriter(*fd_));
        LOG(INFO) << "EIDOLON_DIAG: MoQT server GSO batch-writer initialized (A1)";
        LOG(INFO) << "EIDOLON_DIAG: MoQT server listening on " << host_ << ":" << port_;
        g_quic_event_loop = event_loop_.get();
        PumpOnce();
    }

    void PumpOnce() {
        if (!event_loop_) return;
        event_loop_->RunEventLoopOnce(quic::QuicTime::Delta::FromMilliseconds(50));
        g_quic_thread->task_runner()->PostTask(
                FROM_HERE, base::BindOnce(&EidolonMoqtListenHelper::PumpOnce, base::Unretained(this)));
    }

    std::string host_;
    uint16_t port_;
    uint16_t cb_port_;
    uint16_t dgram_cb_port_;
    quic::QuicConfig config_;
    std::unique_ptr<quic::QuicCryptoServerConfig> crypto_config_;
    std::unique_ptr<quic::QuicVersionManager> version_manager_;
    std::unique_ptr<quic::DeterministicConnectionIdGenerator> conn_id_gen_;
    std::unique_ptr<quic::QuicEventLoop> event_loop_;
    std::unique_ptr<quic::WebTransportOnlyDispatcher> dispatcher_;
    quic::OwnedSocketFd fd_;
    std::unique_ptr<quic::QuicServerIoHarness> io_;
};

#endif // BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
// ===============================================================

// =========================================================================
// Фаза 3 Этап C — Connection Migration (Wi-Fi<->сота) для WT-over-H3 клиента.
// Validate-then-migrate: валидируем новый путь (PATH_CHALLENGE/RESPONSE), затем
// переносим QUIC-соединение на свежий сокет новой сети. Сессия MoQT и все стримы
// переживают переход прозрачно (тот же connection ID, ниже уровня приложения).
// Реализуем прямо на клиенте (методы объявлены патчем item 12): он владеет
// connection_/socket/reader и даёт к ним приватный доступ (static-линк).
// =========================================================================
namespace {

// Контекст валидации пути: отдаёт writer пробного (нового) сокета.
    class EidolonMigrationPathContext : public quic::QuicPathValidationContext {
    public:
        EidolonMigrationPathContext(const quic::QuicSocketAddress& self,
                                    const quic::QuicSocketAddress& peer,
                                    quic::QuicPacketWriter* writer)
                : quic::QuicPathValidationContext(self, peer), writer_(writer) {}
        quic::QuicPacketWriter* WriterToUse() override { return writer_; }

    private:
        raw_ptr<quic::QuicPacketWriter> writer_;  // не владеет (владеет клиент до коммита)
    };

// Result-delegate: на успехе валидации коммитим миграцию, иначе отменяем.
    class EidolonMigrationResultDelegate
            : public quic::QuicPathValidator::ResultDelegate {
    public:
        explicit EidolonMigrationResultDelegate(
                net::DedicatedWebTransportHttp3Client* client)
                : client_(client) {}
        void OnPathValidationSuccess(
                std::unique_ptr<quic::QuicPathValidationContext> context,
                quic::QuicTime /*start_time*/) override {
            LOG(INFO) << "EIDOLON_DIAG: migration path validated OK";
            client_->EidolonCommitMigration(std::move(context));
        }
        void OnPathValidationFailure(
                std::unique_ptr<quic::QuicPathValidationContext> /*context*/) override {
            LOG(INFO) << "EIDOLON_DIAG: migration path validation FAILED";
            client_->EidolonAbortMigration();
        }

    private:
        raw_ptr<net::DedicatedWebTransportHttp3Client> client_;
    };

}  // namespace

void net::DedicatedWebTransportHttp3Client::EidolonMigrateToNetwork(
        net::handles::NetworkHandle network) {
    if (!connection_ || !connection_->connected()) {
        LOG(INFO) << "EIDOLON_DIAG: migrate skipped (connection not ready)";
        return;
    }
    if (eidolon_probe_socket_ || eidolon_probe_reader_) {
        LOG(INFO) << "EIDOLON_DIAG: migrate already in progress, ignoring";
        return;
    }
    LOG(INFO) << "EIDOLON_DIAG: EidolonMigrateToNetwork network=" << network;

    // Пробный сокет на новой сети. Привязка к NetworkHandle сама маршрутизирует в
    // неё и обходит VPN-TUN на Android.
    eidolon_probe_socket_ =
            context_->GetNetworkSessionContext()
                    ->client_socket_factory->CreateDatagramClientSocket(
                            net::DatagramSocket::DEFAULT_BIND, network, net_log_.net_log(),
                            net_log_.source());
    if (quic_context_->params()->enable_socket_recv_optimization)
        eidolon_probe_socket_->EnableRecvOptimization();
    eidolon_probe_socket_->UseNonBlockingIO();

    net::IPEndPoint peer_ip = net::ToIPEndPoint(connection_->peer_address());
    int rv = eidolon_probe_socket_->ConnectAsync(
            peer_ip,
            base::BindOnce(
                    &net::DedicatedWebTransportHttp3Client::EidolonOnProbeConnected,
                    base::Unretained(this), connection_->peer_address()));
    if (rv != net::ERR_IO_PENDING)
        EidolonOnProbeConnected(connection_->peer_address(), rv);
}

void net::DedicatedWebTransportHttp3Client::EidolonOnProbeConnected(
        quic::QuicSocketAddress peer, int rv) {
    if (rv != net::OK || !eidolon_probe_socket_) {
        LOG(INFO) << "EIDOLON_DIAG: migrate probe connect failed rv=" << rv;
        EidolonAbortMigration();
        return;
    }
    eidolon_probe_socket_->SetReceiveBufferSize(net::kQuicSocketReceiveBufferSize);
    int dnf = eidolon_probe_socket_->SetDoNotFragment();
    (void)dnf;  // ERR_NOT_IMPLEMENTED допустимо (как в DoConnectConfigure)
    eidolon_probe_socket_->SetSendBufferSize(quic::kMaxOutgoingPacketSize * 20);

    eidolon_probe_writer_ = std::make_unique<net::QuicChromiumPacketWriter>(
            eidolon_probe_socket_.get(), task_runner_);
    eidolon_probe_reader_ = std::make_unique<net::QuicChromiumPacketReader>(
            std::move(eidolon_probe_socket_), quic_context_->clock(), this,
            net::kQuicYieldAfterPacketsRead,
            quic::QuicTime::Delta::FromMilliseconds(
                    net::kQuicYieldAfterDurationMilliseconds),
            net_log_);
    eidolon_probe_reader_->StartReading();

    net::IPEndPoint local;
    eidolon_probe_reader_->socket()->GetLocalAddress(&local);
    quic::QuicSocketAddress self = net::ToQuicSocketAddress(local);

    LOG(INFO) << "EIDOLON_DIAG: migrate validating path self=" << self.ToString()
              << " peer=" << peer.ToString();
    connection_->ValidatePath(
            std::make_unique<EidolonMigrationPathContext>(self, peer,
                                                          eidolon_probe_writer_.get()),
            std::make_unique<EidolonMigrationResultDelegate>(this),
            quic::PathValidationReason::kConnectionMigration);
}

void net::DedicatedWebTransportHttp3Client::EidolonCommitMigration(
        std::unique_ptr<quic::QuicPathValidationContext> context) {
    if (!eidolon_probe_writer_ || !eidolon_probe_reader_) {
        LOG(INFO) << "EIDOLON_DIAG: migrate commit without probe, aborting";
        EidolonAbortMigration();
        return;
    }
    quic::QuicSocketAddress self = context->self_address();
    quic::QuicSocketAddress peer = context->peer_address();
    // M.2 (Фаза 5) — CID rotation на миграции: фиксируем серверный CID ДО переноса,
    // чтобы подтвердить его смену ПОСЛЕ. quiche в MigratePath() сам зовёт
    // UpdateConnectionIdsOnMigration() и берёт запасной CID (сервер выдаёт их по
    // active_connection_id_limit, дефолт 2 → запас есть) — анти-корреляция пути на
    // проводе. Нам тут править нечего, только проверяем и логируем.
    quic::QuicConnectionId cid_before = connection_->connection_id();
    // Write-ошибки нового пути обрабатываем мы (как и для исходного writer).
    eidolon_probe_writer_->set_delegate(this);
    bool ok = connection_->MigratePath(self, peer, eidolon_probe_writer_.release(),
            /*owns_writer=*/true);
    LOG(INFO) << "EIDOLON_DIAG: migrate MigratePath ok=" << ok;
    if (!ok) {
        EidolonAbortMigration();
        return;
    }
    // Старый reader (и его сокет) уничтожается — трафик идёт с нового сокета.
    packet_reader_ = std::move(eidolon_probe_reader_);

    quic::QuicConnectionId cid_after = connection_->connection_id();
    LOG(INFO) << "EIDOLON_DIAG: M.2 CID on migration before=" << cid_before
              << " after=" << cid_after
              << (cid_before == cid_after ? " (NOT rotated — нет запасного CID?)"
                                          : " (rotated OK)");

    // M.1 (Фаза 5) — проактивный сброс MTU на свежем пути. После Wi-Fi→сота старый
    // (возможно подросший DPLPMTUD до ~1400) размер пакета черно-дырит на меньшем MTU
    // соты, пока blackhole-детектор не откатит — это вспышка потерь «толстых» пакетов.
    // Сразу ужимаем до безопасного 1200, затем ре-запускаем DPLPMTUD (growth-пробинг),
    // чтобы на новом пути снова найти оптимум. SetMaxPacketLength — публичный; ре-арм
    // дискавери — через патч-метод (SetMtuDiscoveryTarget приватный в quiche).
    connection_->SetMaxPacketLength(kEidolonMigrationSafeMtu);
    connection_->EidolonRestartMtuDiscovery();
    LOG(INFO) << "EIDOLON_DIAG: M.1 MTU reset to " << kEidolonMigrationSafeMtu
              << " + DPLPMTUD re-probe armed after migration";
}

// P5.4 (Фаза 5) — включить TLS-резумпцию: подключить общий персистентный
// session-cache к crypto_config этого клиента. Вызывается из MoQTDialHelper ДО
// Connect(). crypto_config_ приватный → метод добавлен патчем в заголовок клиента,
// а реализация тут (тот же TU, доступ к file-local кэшу). set_session_cache просто
// меняет shared_ptr; TlsClientHandshaker читает его на старте handshake.
void net::DedicatedWebTransportHttp3Client::EidolonEnableResumption() {
    crypto_config_.set_session_cache(EidolonSharedSessionCacheRef());
    LOG(INFO) << "EIDOLON_DIAG: P5.4 shared session-cache attached (resumption/0-RTT)";
}

// M.1 (Фаза 5) — ре-запуск DPLPMTUD после миграции. SetMtuDiscoveryTarget приватен в
// QuicConnection, поэтому это ЧЛЕН-функция QuicConnection (объявлена патчем в
// quic_connection.h), реализованная здесь: как член она имеет доступ к private.
// Enable(long_term_mtu_, target) заново взводит mtu_discoverer_; дальше MaybeSetMtuAlarm
// на отправках пакетов сам гонит growth-пробинг до нового оптимума на свежем пути.
void quic::QuicConnection::EidolonRestartMtuDiscovery() {
    SetMtuDiscoveryTarget(quic::kMtuDiscoveryTargetPacketSizeHigh);
}

void net::DedicatedWebTransportHttp3Client::EidolonAbortMigration() {
    eidolon_probe_reader_.reset();
    eidolon_probe_writer_.reset();
    eidolon_probe_socket_.reset();
}

// -------------------------------------------------------------------------
// C-API (ДЛЯ GOLANG)
// -------------------------------------------------------------------------

extern "C" {


static base::NoDestructor<net::TransportSecurityState> g_transport_security_state;

#if BUILDFLAG(IS_POSIX)
static base::FileDescriptorWatcher* g_file_descriptor_watcher = nullptr;
#endif

EIDOLON_EXPORT void eidolon_set_protect(EidolonProtectFunc cb) {
    g_protect_func = cb;
}

// Фаза 6 — конфигурация сервиса-прикрытия. Зовётся один раз из Go (StartCoverIngest)
// ДО eidolon_listen_moqt. Копируем строки в глобалы (set-once pre-listen; машинерия
// прикрытия — только серверная IS_LINUX-часть, но символ экспортируем на всех ABI,
// т.к. cgo bridge.go ссылается на него и в android-сборке). ns=="" => per-session.
EIDOLON_EXPORT void eidolon_cover_configure(uint16_t cover_cb_port, const char* ns,
                                            const char* track) {
    g_cover_cb_port = cover_cb_port;
    g_cover_ns_override = (ns != nullptr) ? std::string(ns) : std::string();
    if (track != nullptr && track[0] != '\0') {
        g_cover_track = std::string(track);
    }
    g_cover_enabled = (cover_cb_port != 0);
    LOG(INFO) << "EIDOLON_DIAG: cover configured enabled=" << g_cover_enabled
              << " cb_port=" << g_cover_cb_port << " track=" << g_cover_track
              << " ns_override=" << (g_cover_ns_override.empty() ? "<per-session>" : g_cover_ns_override);
}

#if BUILDFLAG(IS_ANDROID)
// C1 (Фаза 5): пин сетевого+крипто io-потока на энергоэффективные (little) ядра.
// Сетевой цикл QUIC + AEAD + сборка объектов — высокая пропускная способность, но
// НЕ пиковая частота; на little-ядрах та же работа потребляет в разы меньше ватт.
// Кластер little определяем по МИНИМАЛЬНОМУ cpu_capacity (надёжнее хардкода «ядра
// 0..3» — топологии разные). Нет данных capacity или ядра однородны (нет
// big.LITTLE) → НЕ пиним: мис-пиннинг хуже отсутствия. Запускается НА io-потоке,
// поэтому sched_setaffinity(0,…) целит именно его. Только Android: на сервере
// (Linux) пин на слабые ядра резал бы throughput.
void PinIoThreadToLittleCoresOnIoThread() {
    long ncpu = sysconf(_SC_NPROCESSORS_CONF);
    if (ncpu <= 1 || ncpu > CPU_SETSIZE) {
        return;
    }
    std::vector<long> cap(static_cast<size_t>(ncpu), -1);
    long minCap = -1;
    for (long c = 0; c < ncpu; ++c) {
        std::ifstream f("/sys/devices/system/cpu/cpu" + std::to_string(c) + "/cpu_capacity");
        long v = 0;
        if (f >> v && v > 0) {
            cap[static_cast<size_t>(c)] = v;
            if (minCap < 0 || v < minCap) {
                minCap = v;
            }
        }
    }
    if (minCap < 0) {
        LOG(INFO) << "EIDOLON_DIAG: C1 affinity skipped (нет cpu_capacity)";
        return;
    }
    cpu_set_t set;
    CPU_ZERO(&set);
    int pinned = 0;
    for (long c = 0; c < ncpu; ++c) {
        if (cap[static_cast<size_t>(c)] == minCap) {
            CPU_SET(c, &set);
            ++pinned;
        }
    }
    if (pinned == 0 || pinned == ncpu) {
        LOG(INFO) << "EIDOLON_DIAG: C1 affinity skipped (однородные ядра, нет big.LITTLE)";
        return;
    }
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        LOG(INFO) << "EIDOLON_DIAG: C1 sched_setaffinity failed errno=" << errno;
    } else {
        LOG(INFO) << "EIDOLON_DIAG: C1 io-thread pinned to " << pinned
                  << " little core(s), cpu_capacity=" << minCap;
    }
}
#endif  // IS_ANDROID

EIDOLON_EXPORT void eidolon_init() {
    if (!base::CommandLine::InitializedForCurrentProcess()) {
        base::CommandLine::Init(0, nullptr);
    }
    if (!g_exit_manager) {
        // EIDOLON_DIAG: направляем логи Chromium и в системный журнал (logcat на Android),
        // и в stderr. На Linux у LOG_TO_SYSTEM_DEBUG_LOG нет ветки вывода (base/logging.cc
        // обрабатывает только Win/Apple/Android/Fuchsia), а ShouldLogToStderr пропускает лишь
        // ERROR/FATAL — поэтому INFO/WARNING на сервере терялись. LOG_TO_STDERR это чинит,
        // не ломая logcat на клиенте.
        {
            logging::LoggingSettings log_settings;
            log_settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG | logging::LOG_TO_STDERR;
            logging::InitLogging(log_settings);
            logging::SetMinLogLevel(logging::LOGGING_INFO);
            LOG(INFO) << "EIDOLON_DIAG: native logging initialized";
        }
        g_exit_manager = new base::AtExitManager();
        base::ThreadPoolInstance::CreateAndStartWithDefaultParams("Eidolon_ThreadPool");
        g_io_thread = new base::Thread("EidolonIOThread");
        base::Thread::Options options;
        options.message_pump_type = base::MessagePumpType::IO;
        g_io_thread->StartWithOptions(std::move(options));

#if BUILDFLAG(IS_ANDROID)
        // C1: пин io-потока на little-ядра исполняем НА нём самом (задача в его
        // очереди), чтобы sched_setaffinity(0,…) применился к нужному потоку.
        g_io_thread->task_runner()->PostTask(
                FROM_HERE, base::BindOnce(&PinIoThreadToLittleCoresOnIoThread));
#endif

#if BUILDFLAG(IS_POSIX)
        g_file_descriptor_watcher = new base::FileDescriptorWatcher(g_io_thread->task_runner());
#endif

        // Отдельный поток под серверный QUIC event loop (см. g_quic_thread выше).
        // Только там, где компилируется серверный QUIC (Linux/ChromeOS); на клиенте
        // (Android) QUICListenHelper не собирается, лишний поток не нужен.
#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
        g_quic_thread = new base::Thread("EidolonQuicThread");
        base::Thread::Options quic_options;
        quic_options.message_pump_type = base::MessagePumpType::IO;
        g_quic_thread->StartWithOptions(std::move(quic_options));
#endif
    }
}

void EnsureChromiumIOThread() {
    eidolon_init();
}

EIDOLON_EXPORT EidolonHandle eidolon_dial_tcp(const char* host, uint16_t port, const uint8_t* token, size_t token_len, uintptr_t data_fd) {
    EnsureChromiumIOThread();
    auto session = std::make_unique<EidolonSession>(data_fd, false);
    std::string target_host(host);
    std::string target_ip = target_host;
    std::string target_sni = target_host;
    size_t sep = target_host.find('|');
    if (sep != std::string::npos) {
        target_ip = target_host.substr(0, sep);
        target_sni = target_host.substr(sep + 1);
    }

    auto safe_span = UNSAFE_BUFFERS(base::span<const uint8_t>(token, token_len));
    std::vector<uint8_t> token_vec(safe_span.begin(), safe_span.end());
    base::WaitableEvent connect_event(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED);

    g_io_thread->task_runner()->PostTask(FROM_HERE, base::BindOnce([](
            EidolonSession* sess, std::string ip_str, std::string sni_str, uint16_t port_num, std::vector<uint8_t> tok, base::WaitableEvent* event) {
        TCPDialHelper::Start(sess, ip_str, sni_str, port_num, tok, event);
    }, session.get(), target_ip, target_sni, port, token_vec, &connect_event));

    connect_event.Wait();
    if (session->is_closed_) {
        auto* s_ptr = session.release();
        g_io_thread->task_runner()->PostTask(FROM_HERE, base::BindOnce([](EidolonSession* s) { delete s; }, s_ptr));
        return nullptr;
    }
    return session.release();
}

EIDOLON_EXPORT EidolonHandle eidolon_dial_quic(const char* host, uint16_t port, const uint8_t* token, size_t token_len, uintptr_t data_fd) {
    EnsureChromiumIOThread();
    auto session = std::make_unique<EidolonSession>(data_fd, true);
    std::string target_host(host);
    std::string target_ip = target_host;
    std::string target_sni = target_host;
    size_t sep = target_host.find('|');
    if (sep != std::string::npos) {
        target_ip = target_host.substr(0, sep);
        target_sni = target_host.substr(sep + 1);
    }

    // ФИКС ВАРНИНГА: Используем безопасное копирование span
    auto safe_span = UNSAFE_BUFFERS(base::span<const uint8_t>(token, token_len));
    std::vector<uint8_t> token_vec(safe_span.begin(), safe_span.end());

    base::WaitableEvent connect_event(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED);

    g_io_thread->task_runner()->PostTask(FROM_HERE, base::BindOnce([](
            EidolonSession* sess, std::string ip_str, std::string sni_str, uint16_t port_num, std::vector<uint8_t> tok, base::WaitableEvent* event) {
        QUICDialHelper::Start(sess, ip_str, sni_str, port_num, tok, event);
    }, session.get(), target_ip, target_sni, port, token_vec, &connect_event));

    connect_event.Wait();
    if (session->is_closed_) {
        auto* s_ptr = session.release();
        g_io_thread->task_runner()->PostTask(FROM_HERE, base::BindOnce([](EidolonSession* s) { delete s; }, s_ptr));
        return nullptr;
    }
    return session.release();
}

// Фаза 1: дозвон по MoQT (WebTransport-over-H3). Сигнатура как у dial_quic.
// Data-plane (Go-FD <-> MoQT объекты/датаграммы) — Фаза 2; пока устанавливаем
// только WebTransport + MoQT-сессию (control-plane) и валидируем линковку.
EIDOLON_EXPORT EidolonHandle eidolon_dial_moqt(const char* host, uint16_t port, const uint8_t* token, size_t token_len, uintptr_t data_fd, uintptr_t datagram_fd, int64_t network_handle) {
    LOG(INFO) << "EIDOLON_DIAG: eidolon_dial_moqt ENTRY host=" << (host ? host : "(null)")
              << " port=" << port << " token_len=" << token_len << " data_fd=" << data_fd
              << " datagram_fd=" << datagram_fd << " network_handle=" << network_handle;
    EnsureChromiumIOThread();
    LOG(INFO) << "EIDOLON_DIAG: eidolon_dial_moqt io-thread ready (running="
              << (g_io_thread && g_io_thread->IsRunning()) << ")";
    auto session = std::make_unique<EidolonSession>(data_fd, false, datagram_fd);
    session->is_moqt_ = true;
    std::string target_host(host);
    std::string target_ip = target_host;
    std::string target_sni = target_host;
    size_t sep = target_host.find('|');
    if (sep != std::string::npos) {
        target_ip = target_host.substr(0, sep);
        target_sni = target_host.substr(sep + 1);
    }
    LOG(INFO) << "EIDOLON_DIAG: eidolon_dial_moqt parsed ip=" << target_ip
              << " sni=" << target_sni;

    auto safe_span = UNSAFE_BUFFERS(base::span<const uint8_t>(token, token_len));
    std::vector<uint8_t> token_vec(safe_span.begin(), safe_span.end());

    base::WaitableEvent connect_event(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED);

    LOG(INFO) << "EIDOLON_DIAG: eidolon_dial_moqt posting MoQTDialHelper::Start to io-thread";
    g_io_thread->task_runner()->PostTask(FROM_HERE, base::BindOnce([](
                                                                           EidolonSession* sess, std::string ip_str, std::string sni_str, uint16_t port_num, std::vector<uint8_t> tok, base::WaitableEvent* event, net::handles::NetworkHandle net_handle) {
                                                                       MoQTDialHelper::Start(sess, ip_str, sni_str, port_num, tok, event, net_handle);
                                                                   }, session.get(), target_ip, target_sni, port, token_vec, &connect_event,
                                                                   static_cast<net::handles::NetworkHandle>(network_handle)));

    LOG(INFO) << "EIDOLON_DIAG: eidolon_dial_moqt waiting on connect_event";
    connect_event.Wait();
    LOG(INFO) << "EIDOLON_DIAG: eidolon_dial_moqt connect_event signaled, is_closed="
              << session->is_closed_;
    if (session->is_closed_) {
        LOG(ERROR) << "EIDOLON_DIAG: eidolon_dial_moqt FAILED (session closed) -> returning null";
        auto* s_ptr = session.release();
        g_io_thread->task_runner()->PostTask(FROM_HERE, base::BindOnce([](EidolonSession* s) { delete s; }, s_ptr));
        return nullptr;
    }
    LOG(INFO) << "EIDOLON_DIAG: eidolon_dial_moqt SUCCESS -> returning handle";
    return session.release();
}

EIDOLON_EXPORT int eidolon_export_key(EidolonHandle handle, uint8_t* out_key, size_t key_len) {
if (!handle || key_len != 32) return -1;
auto* session = static_cast<EidolonSession*>(handle);
int result = -1;
base::WaitableEvent event(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED);

g_io_thread->task_runner()->PostTask(FROM_HERE, base::BindOnce([](
        EidolonSession* s, uint8_t* key, size_t len, int* res, base::WaitableEvent* ev) {
    if (s->is_moqt_) {
        // MoQT: экспортируем keying material из несущей QUIC-сессии под WebTransport.
        if (s->wt_client_ && s->wt_client_->session()) {
            auto* wt = static_cast<quic::WebTransportHttp3*>(s->wt_client_->session());
            quic::QuicSpdySession* qs = wt->eidolon_quic_session();
            const quic::QuicCryptoStream* cs = qs ? qs->GetCryptoStream() : nullptr;
            std::string exported;
            if (cs && const_cast<quic::QuicCryptoStream*>(cs)->ExportKeyingMaterial(
                    "eidolon-traffic-key", "", len, &exported) && exported.size() == len) {
                memcpy(key, exported.data(), len);
                *res = 0;
            }
        }
    } else if (s->is_quic_) {
        if (s->quic_session_handle && s->quic_session_handle->ExportKeyingMaterial("eidolon-traffic-key", "", key, len)) {
            *res = 0;
        }
    } else {
        auto* ssl_socket = static_cast<net::SSLClientSocket*>(s->tcp_socket.get());
        if (ssl_socket) {
            // ФИКС ВАРНИНГА: Используем макросы безопасности
            int export_rv = ssl_socket->ExportKeyingMaterial(
                    "eidolon-traffic-key",
                    std::nullopt,
                    UNSAFE_BUFFERS(base::span<uint8_t>(key, len))
            );
            if (export_rv == net::OK) {
                *res = 0;
            }
        }
    }
    ev->Signal();
}, session, out_key, key_len, &result, &event));

event.Wait();
return result;
}

EIDOLON_EXPORT void eidolon_close(EidolonHandle handle) {
if (!handle) return;
auto* session = static_cast<EidolonSession*>(handle);
if (g_io_thread) {
g_io_thread->task_runner()->PostTask(FROM_HERE, base::BindOnce([](EidolonSession* s) {
    delete s;
}, session));
} else {
delete session;
}
}

// Фаза 3 Этап C — мигрировать несущее QUIC-соединение сессии на другую сеть
// Android (Wi-Fi<->сота) без разрыва туннеля. network_handle — NetworkHandle из
// ConnectivityManager (Network.getNetworkHandle()). Только для MoQT/QUIC-несущей
// (wt_client_); TCP-линии не мигрируют (перехиливаются пулом в Go).
EIDOLON_EXPORT void eidolon_migrate(EidolonHandle handle, int64_t network_handle) {
if (!handle || !g_io_thread) return;
auto* session = static_cast<EidolonSession*>(handle);
g_io_thread->task_runner()->PostTask(FROM_HERE, base::BindOnce([](
        EidolonSession* s, net::handles::NetworkHandle net_handle) {
    if (s->is_closed_ || !s->wt_client_) return;
    auto* wt = static_cast<net::DedicatedWebTransportHttp3Client*>(s->wt_client_.get());
    wt->EidolonMigrateToNetwork(net_handle);
}, session, static_cast<net::handles::NetworkHandle>(network_handle)));
}

// WP-4 (Фаза 5) — смена энергетического режима несущей (P5.1 keep-alive + P5.3 wake).
// state: 0=active (foreground), 1=background, 2=doze. Go зовёт из Android-колбэка на
// жизненный цикл приложения (foreground/background) и Doze (PowerManager). Делает:
//  • выставляет keep-alive-таймаут пинга под режим (фаерит лишь в простое, трафик его
//    вытесняет; все значения < idle=120с) — реже радио-пробуждений в фоне/Doze;
//  • при ПРОБУЖДЕНИИ (переход в active) немедленно шлёт PING — высокоприоритетный
//    health-check пути: вынуждает немедленный ACK-обмен, quiche-recovery (PTO) тут же
//    до-ретрансмитит всё потерянное во сне по НАДЁЖНОЙ линии (это и есть «resync» из
//    P5.3). Явный запрос SN/окна + до-запрос FEC НЕ применим: надёжная линия
//    (CONNECT-стрим) само-восстанавливается ретрансмитом QUIC, а датаграм-lane
//    forward-error-corrected by design (NACK-канала нет — FEC заменяет ретрансмит).
// Fire-and-forget: без WaitableEvent, как eidolon_migrate.
EIDOLON_EXPORT void eidolon_set_power_state(EidolonHandle handle, int state) {
if (!handle || !g_io_thread) return;
auto* session = static_cast<EidolonSession*>(handle);
g_io_thread->task_runner()->PostTask(FROM_HERE, base::BindOnce([](
        EidolonSession* s, int st) {
    if (s->is_closed_ || !s->is_moqt_ || !s->wt_client_ || !s->wt_client_->session())
        return;
    auto* wt = static_cast<quic::WebTransportHttp3*>(s->wt_client_->session());
    quic::QuicSpdySession* qs = wt->eidolon_quic_session();
    quic::QuicConnection* conn = qs ? qs->connection() : nullptr;
    if (!conn || !conn->connected()) return;

    int interval_ms = kEidolonKeepAliveActiveMs;
    const char* name = "active";
    if (st == kEidolonPowerBackground) {
        interval_ms = kEidolonKeepAliveBackgroundMs; name = "background";
    } else if (st == kEidolonPowerDoze) {
        interval_ms = kEidolonKeepAliveDozeMs; name = "doze";
    }
    conn->set_keep_alive_ping_timeout(
            quic::QuicTime::Delta::FromMilliseconds(interval_ms));

    // Пробуждение (любой переход В active): немедленный health-check пути.
    bool waking = (st == kEidolonPowerActive) && (s->power_state_ != kEidolonPowerActive);
    if (waking) {
        conn->SendPing();
        LOG(INFO) << "EIDOLON_DIAG: P5.3 wake resync — high-prio PING sent";
    }
    s->power_state_ = st;
    LOG(INFO) << "EIDOLON_DIAG: P5.1 power state=" << name
              << " keep-alive=" << interval_ms << "ms";
}, session, state));
}

// Фаза 4 FC-3 — снимок congestion-состояния несущей QUIC-сессии под WebTransport
// для receiver-driven flow control (адаптив FEC в пределах свободной ёмкости).
// Модель та же, что у eidolon_export_key: хоп на g_io_thread + WaitableEvent,
// доступ к несущей QUIC через wt->eidolon_quic_session()->connection().
// Только клиентская MoQT-несущая (wt_client_); иначе -1.
//
// NB(CI): имена аксессоров quiche подтвердить при первой сборке chromium —
// sent_packet_manager().BandwidthEstimate()/GetCongestionWindowInBytes()/
// GetBytesInFlight()/GetRttStats()->smoothed_rtt(); GetStats().packets_lost.
// ECN-CE: cs.num_ecn_marks_received.ce (QuicEcnCounts, quiche quic_types.h).
EIDOLON_EXPORT int eidolon_get_stats(EidolonHandle handle, EidolonStats* out) {
if (!handle || !out) return -1;
auto* session = static_cast<EidolonSession*>(handle);
int result = -1;
*out = EidolonStats{};
base::WaitableEvent event(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED);

g_io_thread->task_runner()->PostTask(FROM_HERE, base::BindOnce([](
        EidolonSession* s, EidolonStats* o, int* res, base::WaitableEvent* ev) {
    if (s->is_moqt_ && s->wt_client_ && s->wt_client_->session()) {
        auto* wt = static_cast<quic::WebTransportHttp3*>(s->wt_client_->session());
        quic::QuicSpdySession* qs = wt->eidolon_quic_session();
        quic::QuicConnection* conn = qs ? qs->connection() : nullptr;
        if (conn) {
            const quic::QuicConnectionStats& cs = conn->GetStats();
            const quic::QuicSentPacketManager& spm = conn->sent_packet_manager();
            int64_t bw = spm.BandwidthEstimate().ToBytesPerSecond();
            if (bw > 0) o->bandwidth_bps = static_cast<uint64_t>(bw);
            o->cwnd_bytes = static_cast<uint64_t>(spm.GetCongestionWindowInBytes());
            o->inflight_bytes = static_cast<uint64_t>(spm.GetBytesInFlight());
            const quic::RttStats* rtt = spm.GetRttStats();
            if (rtt) {
                int64_t us = rtt->smoothed_rtt().ToMicroseconds();
                if (us > 0) o->smoothed_rtt_us = static_cast<uint64_t>(us);
            }
            o->packets_lost = static_cast<uint64_t>(cs.packets_lost);
            // ECN-CE: кумулятивно получено CE-марок несущей (ранний сигнал
            // затора для AIMD-отступления spare в flowctl, до роста loss).
            o->ecn_ce = static_cast<uint64_t>(cs.num_ecn_marks_received.ce);
            // DPLPMTUD: макс. payload WT-датаграммы (quiche учёл path-MTU
            // несущей QUIC + WT-оверхед) — бюджет кадра для датаграм-lane в Go.
            o->max_datagram = static_cast<uint64_t>(wt->GetMaxDatagramSize());
            *res = 0;
        }
    }
    ev->Signal();
}, session, out, &result, &event));

event.Wait();
return result;
}

EIDOLON_EXPORT EidolonHandle eidolon_listen_quic(const char* host, uint16_t port, const uint8_t* secret, size_t secret_len, uintptr_t cb_port) {
#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
    EnsureChromiumIOThread();
    auto session = std::make_unique<EidolonSession>(0, true);
    std::string target_host(host);

    g_io_thread->task_runner()->PostTask(FROM_HERE, base::BindOnce([](
            std::string host_str, uint16_t port_num, uint16_t p) {
        QUICListenHelper::Start(host_str, port_num, p);
    }, target_host, port, static_cast<uint16_t>(cb_port)));

    return session.release();
#else
    return nullptr;
#endif
}

// Серверный listen по MoQT (WebTransport-over-H3). Сигнатура как у eidolon_listen_quic.
// secret сейчас не используется для ключей (sessionKey = TLS-экспортер несущей сессии);
// токен авторитетно валидирует Go по 80-байтовой meta, как в QUIC-пути.
EIDOLON_EXPORT EidolonHandle eidolon_listen_moqt(const char* host, uint16_t port, const uint8_t* secret, size_t secret_len, uintptr_t cb_port, uintptr_t datagram_cb_port) {
#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
    (void)secret; (void)secret_len;
    EnsureChromiumIOThread();
    auto session = std::make_unique<EidolonSession>(0, false);
    session->is_moqt_ = true;
    std::string target_host(host);
    EidolonMoqtListenHelper::Start(target_host, port, static_cast<uint16_t>(cb_port),
                                   static_cast<uint16_t>(datagram_cb_port));
    return session.release();
#else
    (void)secret; (void)secret_len; (void)datagram_cb_port;
    return nullptr;
#endif
}

} // extern "C"


#if defined(__ANDROID__)
#include <jni.h>
#include "base/android/jni_android.h"

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    base::android::InitVM(vm);
    return JNI_VERSION_1_4;
}
#endif
