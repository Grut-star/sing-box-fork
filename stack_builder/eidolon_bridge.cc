#include "bridge.h"

#include "build/build_config.h"

#if BUILDFLAG(IS_POSIX)
#include <unistd.h>
#include <fcntl.h>
#include "base/files/file_descriptor_watcher_posix.h"
#include "base/posix/eintr_wrapper.h"
#elif BUILDFLAG(IS_WIN)
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

#include <vector>
#include <string>

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
#include "quiche/quic/tools/quic_simple_server_backend.h"
#include "quiche/quic/tools/quic_memory_cache_backend.h"
#include "quiche/quic/tools/quic_server.h"
#include "quiche/quic/tools/quic_simple_dispatcher.h"
#include "quiche/quic/tools/quic_simple_server_session.h"
#include "quiche/quic/tools/quic_simple_server_stream.h"
#include "base/task/thread_pool.h"
#include "quiche/quic/core/quic_default_connection_helper.h"
#include "quiche/quic/tools/quic_simple_crypto_server_stream_helper.h"

static base::AtExitManager* g_exit_manager = nullptr;
static base::Thread* g_io_thread = nullptr;

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

    // Инструменты асинхронного I/O
    scoped_refptr<net::IOBufferWithSize> read_buf_;

#if BUILDFLAG(IS_POSIX)
    std::unique_ptr<base::FileDescriptorWatcher::Controller> fd_read_controller_;
    std::unique_ptr<base::FileDescriptorWatcher::Controller> fd_write_controller_;
#elif BUILDFLAG(IS_WIN)
    HANDLE socket_event_ = INVALID_HANDLE_VALUE;
    base::win::ObjectWatcher socket_watcher_;
#endif

    bool socket_write_pending_ = false;
    bool socket_read_pending_ = false;
    std::vector<std::string> pending_fd_writes_;

    EidolonSession(uintptr_t fd, bool quic) : data_fd_(fd), is_quic_(quic) {
        // Переводим FD от Go в неблокирующий режим (Non-Blocking)
#if BUILDFLAG(IS_POSIX)
        int flags = fcntl(static_cast<int>(data_fd_), F_GETFL, 0);
        fcntl(static_cast<int>(data_fd_), F_SETFL, flags | O_NONBLOCK);
#elif BUILDFLAG(IS_WIN)
        u_long mode = 1;
        ioctlsocket(static_cast<SOCKET>(data_fd_), FIONBIO, &mode);
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

        // Запускаем первичное чтение из Chromium сокета
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
            // PREVENT STACK OVERFLOW: Разрываем синхронную рекурсию через очередь задач
            if (!socket_read_pending_) {
                base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
                    FROM_HERE, base::BindOnce(&EidolonSession::DoSocketRead, base::Unretained(this)));
            }
        }
#elif BUILDFLAG(IS_WIN)
        // Для Windows событие FD_WRITE сработает автоматически (edge-triggered)
        if (pending_fd_writes_.empty() && !socket_read_pending_) {
            base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
                FROM_HERE, base::BindOnce(&EidolonSession::DoSocketRead, base::Unretained(this)));
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
        if (data_fd_ != 0) {
            close(static_cast<int>(data_fd_));
            data_fd_ = 0;
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
// ХЕЛПЕР ДЛЯ АСИНХРОННОГО ДОЗВОНА QUIC (Без блокировок)
// -------------------------------------------------------------------------
class QUICDialHelper : public net::QuicSessionAttempt::Delegate {
public:
    static void Start(EidolonSession* sess, const std::string& host, uint16_t port, const std::vector<uint8_t>& token, base::WaitableEvent* event) {
        auto* dialer = new QUICDialHelper(sess, host, port, token, event);
        dialer->Run();
    }
    net::QuicSessionPool* GetQuicSessionPool() override {
        return sess_->url_context->http_transaction_factory()->GetSession()->quic_session_pool();
    }
    const net::QuicSessionAliasKey& GetKey() override { return session_alias_key_; }
    const net::NetLogWithSource& GetNetLog() override { return net_log_; }

private:
    QUICDialHelper(EidolonSession* sess, const std::string& host, uint16_t port, const std::vector<uint8_t>& token, base::WaitableEvent* event)
            : sess_(sess), host_(host), port_(port), token_(token), event_(event), scheme_host_port_("https", host, port) {
        // Init alias key
        session_alias_key_ = net::QuicSessionAliasKey(
                net::HostPortPair(host, port), net::PRIVACY_MODE_DISABLED, net::ProxyChain::Direct(),
                net::SessionUsage::kDestination, net::SocketTag(),
                net::NetworkAnonymizationKey(), net::SecureDnsPolicy::kAllow, false);
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

        builder.SetSpdyAndQuicEnabled(false, true);
        builder.set_quic_context(std::move(quic_context));
        sess_->url_context = builder.Build();

        net::HttpNetworkSession* http_session = sess_->url_context->http_transaction_factory()->GetSession();
        net::QuicSessionPool* quic_pool = http_session->quic_session_pool();

        net::HostPortPair host_port(host_, port_);

        net::IPAddress ip;
        if (!ip.AssignFromIPLiteral(host_)) { Finish(false); return; }

        net::QuicSessionKey session_key(
                host_port, net::PRIVACY_MODE_DISABLED, net::ProxyChain::Direct(),
                net::SessionUsage::kDestination, net::SocketTag(),
                net::NetworkAnonymizationKey(), net::SecureDnsPolicy::kAllow,
                false, false, net::handles::kInvalidNetworkHandle);

        net::QuicEndpoint quic_endpoint(
                net::DefaultSupportedQuicVersions().front(),
                net::IPEndPoint(ip, port_),
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
            Finish(false); return;
        }

        sess_->quic_session_handle = sess_->quic_attempt->session()->CreateHandle(std::move(scheme_host_port_));
        if (!sess_->quic_session_handle || !sess_->quic_session_handle->IsConnected()) {
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
            Finish(false); return;
        }

        sess_->quic_stream_handle = sess_->quic_session_handle->ReleaseStream();

        quiche::HttpHeaderBlock headers;
        headers[":method"] = "CONNECT";
        headers[":authority"] = host_ + ":" + std::to_string(port_);
        headers[":scheme"] = "https";
        headers["user-agent"] = version_info::GetProductNameAndVersionForUserAgent();
        headers["x-eidolon-token"] = base::HexEncode(token_);
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
    std::string host_;
    uint16_t port_;
    std::vector<uint8_t> token_;
    raw_ptr<base::WaitableEvent> event_;
    url::SchemeHostPort scheme_host_port_;
};

// -------------------------------------------------------------------------
// ХЕЛПЕР ДЛЯ АСИНХРОННОГО ДОЗВОНА TCP (Без блокировок)
// -------------------------------------------------------------------------
class TCPDialHelper {
public:
    static void Start(EidolonSession* sess, const std::string& host, uint16_t port, const std::vector<uint8_t>& token, base::WaitableEvent* event) {
        auto* dialer = new TCPDialHelper(sess, host, port, token, event);
        dialer->Run();
    }

private:
    TCPDialHelper(EidolonSession* sess, const std::string& host, uint16_t port, const std::vector<uint8_t>& token, base::WaitableEvent* event)
            : sess_(sess), host_(host), port_(port), token_(token), event_(event) {}

    void Run() {
        net::IPAddress ip;
        if (!ip.AssignFromIPLiteral(host_)) { Finish(false); return; }

        raw_socket_ = std::make_unique<net::TCPClientSocket>(
                net::AddressList(net::IPEndPoint(ip, port_)), nullptr, nullptr, nullptr, net::NetLogSource(), net::handles::kInvalidNetworkHandle);

        int rv = raw_socket_->Connect(base::BindOnce(&TCPDialHelper::OnTcpConnected, base::Unretained(this)));
        if (rv != net::ERR_IO_PENDING) OnTcpConnected(rv);
    }

    void OnTcpConnected(int rv) {
        if (rv != net::OK) { Finish(false); return; }

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

        size_t copy_len = std::min(token_.size(), static_cast<size_t>(32));
        UNSAFE_BUFFERS(base::span<uint8_t>(ssl_config.eidolon_token)).copy_from(
                UNSAFE_BUFFERS(base::span<const uint8_t>(token_.data(), copy_len)));

        // 5. Создаем SSLClientSocket штатным фабричным методом Chromium
        sess_->tcp_socket = ssl_context->CreateSSLClientSocket(
                std::move(raw_socket_),
                net::HostPortPair(host_, port_),
                ssl_config
        );

        rv = sess_->tcp_socket->Connect(base::BindOnce(&TCPDialHelper::OnSslConnected, base::Unretained(this)));
        if (rv != net::ERR_IO_PENDING) OnSslConnected(rv);
    }

    void OnSslConnected(int rv) {
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
    std::string host_;
    uint16_t port_;
    std::vector<uint8_t> token_;
    raw_ptr<base::WaitableEvent> event_;
    std::unique_ptr<net::StreamSocket> raw_socket_;
};

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
    ~BidirectionalPump() = default;

    void OnTCPConnect(std::string token, std::string session_key, std::string flow_id, int rv);
    void PumpTCPToQUIC();
    void OnTCPRead(int rv);

    base::Lock quic_lock_;
    raw_ptr<EidolonServerStream> quic_stream_;
    scoped_refptr<base::SingleThreadTaskRunner> quic_runner_;
    std::unique_ptr<net::StreamSocket> tcp_socket_;
    scoped_refptr<net::IOBufferWithSize> read_buf_;
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
        quiche::HttpHeaderBlock response_headers;
        response_headers[":status"] = "200";
        WriteHeaders(std::move(response_headers), false, nullptr);
    }

    void OnBodyAvailable() override {
        while (sequencer()->HasBytesToRead()) {
            struct iovec iov;
            if (sequencer()->GetReadableRegions(&iov, 1) == 0) break;
            std::string_view data(static_cast<const char*>(iov.iov_base), iov.iov_len);

            if (!flow_id_read_) {
                buffer_.append(data);
                sequencer()->MarkConsumed(iov.iov_len);

                if (buffer_.size() >= 50) {
                    uint16_t pad_len = (static_cast<uint8_t>(buffer_[48]) << 8) | static_cast<uint8_t>(buffer_[49]);
                    if (buffer_.size() >= 50u + pad_len) {
                        std::string token = buffer_.substr(0, 32);
                        std::string flow_id = buffer_.substr(32, 16);
                        flow_id_read_ = true;

                        uint8_t key[32] = {0};
                        if (session()->GetMutableCryptoStream()) {
                            std::string exported;
                            if (session()->GetMutableCryptoStream()->ExportKeyingMaterial("eidolon-traffic-key", "", 32, &exported)) {
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
                sequencer()->MarkConsumed(iov.iov_len);
            }
        }
        if (sequencer()->IsClosed()) OnFinRead();
    }

private:
    void ForwardToGo(const std::string& token, const std::string& session_key, const std::string& flow_id) {
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

class EidolonServerStream;

class BidirectionalPump : public base::RefCountedThreadSafe<BidirectionalPump> {
public:
    BidirectionalPump(EidolonServerStream* quic_stream, scoped_refptr<base::SingleThreadTaskRunner> quic_runner)
            : quic_stream_(quic_stream), quic_runner_(std::move(quic_runner)),
              read_buf_(base::MakeRefCounted<net::IOBufferWithSize>(65536)) {}

    // Только объявления. Реализации перенесены ниже EidolonServerStream.
    void ConnectTCP(uint16_t cb_port, std::string token, std::string session_key, std::string flow_id);
    void WriteToTCP(std::string_view data);
    void DetachQUIC();

private:
    friend class base::RefCountedThreadSafe<BidirectionalPump>;
    ~BidirectionalPump() = default;

    void OnTCPConnect(std::string token, std::string session_key, std::string flow_id, int rv);
    void PumpTCPToQUIC();
    void OnTCPRead(int rv);

    base::Lock quic_lock_;
    raw_ptr<EidolonServerStream> quic_stream_;
    scoped_refptr<base::SingleThreadTaskRunner> quic_runner_;
    std::unique_ptr<net::StreamSocket> tcp_socket_;
    scoped_refptr<net::IOBufferWithSize> read_buf_;
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
        quiche::HttpHeaderBlock response_headers;
        response_headers[":status"] = "200";
        WriteHeaders(std::move(response_headers), false, nullptr);
    }

    void OnBodyAvailable() override {
        while (sequencer()->HasBytesToRead()) {
            struct iovec iov;
            if (sequencer()->GetReadableRegions(&iov, 1) == 0) break;
            std::string_view data(static_cast<const char*>(iov.iov_base), iov.iov_len);

            if (!flow_id_read_) {
                buffer_.append(data);
                sequencer()->MarkConsumed(iov.iov_len);

                if (buffer_.size() >= 50) {
                    uint16_t pad_len = (static_cast<uint8_t>(buffer_[48]) << 8) | static_cast<uint8_t>(buffer_[49]);
                    if (buffer_.size() >= 50u + pad_len) {
                        std::string token = buffer_.substr(0, 32);
                        std::string flow_id = buffer_.substr(32, 16);
                        flow_id_read_ = true;

                        uint8_t key[32] = {0};
                        if (session()->GetMutableCryptoStream()) {
                            std::string exported;
                            if (session()->GetMutableCryptoStream()->ExportKeyingMaterial("eidolon-traffic-key", "", 32, &exported)) {
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
                sequencer()->MarkConsumed(iov.iov_len);
            }
        }
        if (sequencer()->IsClosed()) OnFinRead();
    }

private:
    void ForwardToGo(const std::string& token, const std::string& session_key, const std::string& flow_id) {
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

    tcp_socket_ = std::make_unique<net::TCPClientSocket>(
            net::AddressList(net::IPEndPoint(ip, cb_port)), nullptr, nullptr, nullptr, net::NetLogSource(), net::handles::kInvalidNetworkHandle);

    int rv = tcp_socket_->Connect(base::BindOnce(&BidirectionalPump::OnTCPConnect, base::RetainedRef(this), token, session_key, flow_id));
    if (rv != net::ERR_IO_PENDING) OnTCPConnect(token, session_key, flow_id, rv);
}

void BidirectionalPump::WriteToTCP(std::string_view data) {
    g_io_thread->task_runner()->PostTask(FROM_HERE, base::BindOnce([](scoped_refptr<BidirectionalPump> self, std::string d) {
        if (!self->tcp_socket_) return;
        auto io_buf = base::MakeRefCounted<net::StringIOBuffer>(d);
        self->tcp_socket_->Write(io_buf.get(), d.size(), base::BindOnce([](int){}), TRAFFIC_ANNOTATION_FOR_TESTS);
    }, base::RetainedRef(this), std::string(data)));
}

void BidirectionalPump::DetachQUIC() {
    base::AutoLock lock(quic_lock_);
    quic_stream_ = nullptr;
}

void BidirectionalPump::OnTCPConnect(std::string token, std::string session_key, std::string flow_id, int rv) {
    if (rv != net::OK) return;
    std::string meta = token + session_key + flow_id;
    auto io_buf = base::MakeRefCounted<net::StringIOBuffer>(meta);
    tcp_socket_->Write(io_buf.get(), meta.size(), base::BindOnce([](int){}), TRAFFIC_ANNOTATION_FOR_TESTS);
    PumpTCPToQUIC();
}

void BidirectionalPump::PumpTCPToQUIC() {
    if (!tcp_socket_) return;
    int rv = tcp_socket_->Read(read_buf_.get(), read_buf_->size(),
                               base::BindOnce(&BidirectionalPump::OnTCPRead, base::RetainedRef(this)));
    if (rv != net::ERR_IO_PENDING) OnTCPRead(rv);
}

void BidirectionalPump::OnTCPRead(int rv) {
    if (rv <= 0) {
        tcp_socket_.reset();
        quic_runner_->PostTask(FROM_HERE, base::BindOnce([](scoped_refptr<BidirectionalPump> self) {
            base::AutoLock lock(self->quic_lock_);
            if (self->quic_stream_) {
                self->quic_stream_->Reset(quic::QUIC_STREAM_CANCELLED);
            }
        }, base::RetainedRef(this)));
        return;
    }

    quic_runner_->PostTask(FROM_HERE, base::BindOnce([](scoped_refptr<BidirectionalPump> self, std::string d) {
        base::AutoLock lock(self->quic_lock_);
        if (self->quic_stream_) {
            self->quic_stream_->WriteOrBufferBody(d, false);
        }
    }, base::RetainedRef(this), std::string(read_buf_->data(), rv)));

    PumpTCPToQUIC();
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
        base::ThreadPool::PostTask(FROM_HERE, {base::MayBlock()},
                                   base::BindOnce(&QUICListenHelper::Run, base::Unretained(listener)));
    }

private:
    QUICListenHelper(const std::string& host, uint16_t port, uint16_t cb_port)
            : host_(host), port_(port), cb_port_(cb_port) {}

    void Run() {
        backend_ = std::make_unique<quic::QuicMemoryCacheBackend>();

        auto proof_source = std::make_unique<net::ProofSourceChromium>();
        // ВАЖНО: Инициализация сертификатов, иначе Chromium аппаратно сбросит ClientHello[cite: 5, 6]
        proof_source->Initialize(
                base::FilePath("cert.pem"),
                base::FilePath("key.pem"),
                base::FilePath(""));

        server_ = std::make_unique<EidolonServer>(std::move(proof_source), backend_.get(), cb_port_);

        quic::QuicIpAddress ip;
        ip.FromString(host_);
        quic::QuicSocketAddress address(ip, port_);

        if (server_->CreateUDPSocketAndListen(address)) {
            server_->HandleEventsForever();
        }
        delete this;
    }

    std::unique_ptr<quic::QuicMemoryCacheBackend> backend_;
    std::unique_ptr<EidolonServer> server_;
    std::string host_;
    uint16_t port_;
    uint16_t cb_port_;
};

// -------------------------------------------------------------------------
// C-API (ДЛЯ GOLANG)
// -------------------------------------------------------------------------

extern "C" {


static base::NoDestructor<net::TransportSecurityState> g_transport_security_state;

#if BUILDFLAG(IS_POSIX)
static base::FileDescriptorWatcher* g_file_descriptor_watcher = nullptr;
#endif

EIDOLON_EXPORT void eidolon_init() {
    if (!base::CommandLine::InitializedForCurrentProcess()) {
        base::CommandLine::Init(0, nullptr);
    }
    if (!g_exit_manager) {
        g_exit_manager = new base::AtExitManager();
        base::ThreadPoolInstance::CreateAndStartWithDefaultParams("Eidolon_ThreadPool");
        g_io_thread = new base::Thread("EidolonIOThread");
        base::Thread::Options options;
        options.message_pump_type = base::MessagePumpType::IO;
        g_io_thread->StartWithOptions(std::move(options));

#if BUILDFLAG(IS_POSIX)
        g_file_descriptor_watcher = new base::FileDescriptorWatcher(g_io_thread->task_runner());
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
    auto safe_span = UNSAFE_BUFFERS(base::span<const uint8_t>(token, token_len));
    std::vector<uint8_t> token_vec(safe_span.begin(), safe_span.end());
    base::WaitableEvent connect_event(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED);

    g_io_thread->task_runner()->PostTask(FROM_HERE, base::BindOnce([](
            EidolonSession* sess, std::string host_str, uint16_t port_num, std::vector<uint8_t> tok, base::WaitableEvent* event) {
        TCPDialHelper::Start(sess, host_str, port_num, tok, event);
    }, session.get(), target_host, port, token_vec, &connect_event));

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
    std::vector<uint8_t> token_vec(token, token + token_len);
    base::WaitableEvent connect_event(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED);

    g_io_thread->task_runner()->PostTask(FROM_HERE, base::BindOnce([](
            EidolonSession* sess, std::string host_str, uint16_t port_num, std::vector<uint8_t> tok, base::WaitableEvent* event) {
        QUICDialHelper::Start(sess, host_str, port_num, tok, event);
    }, session.get(), target_host, port, token_vec, &connect_event));

    connect_event.Wait();
    if (session->is_closed_) {
        auto* s_ptr = session.release();
        g_io_thread->task_runner()->PostTask(FROM_HERE, base::BindOnce([](EidolonSession* s) { delete s; }, s_ptr));
        return nullptr;
    }
    return session.release();
}

EIDOLON_EXPORT int eidolon_export_key(EidolonHandle handle, uint8_t* out_key, size_t key_len) {
if (!handle || key_len != 32) return -1;
auto* session = static_cast<EidolonSession*>(handle);
int result = -1;
base::WaitableEvent event(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED);

g_io_thread->task_runner()->PostTask(FROM_HERE, base::BindOnce([](
        EidolonSession* s, uint8_t* key, size_t len, int* res, base::WaitableEvent* ev) {
    if (s->is_quic_) {
        if (s->quic_session_handle && s->quic_session_handle->ExportKeyingMaterial("eidolon-traffic-key", "", key, len)) {
            *res = 0;
        }
    } else {
        auto* ssl_socket = static_cast<net::SSLClientSocketImpl*>(s->tcp_socket.get());
        if (ssl_socket && ssl_socket->GetSSL()) {
            if (SSL_export_keying_material(ssl_socket->GetSSL(), key, len, "eidolon-traffic-key", 19, nullptr, 0, 0) == 1) {
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

EIDOLON_EXPORT EidolonHandle eidolon_listen_quic(const char* host, uint16_t port, const uint8_t* secret, size_t secret_len, uintptr_t cb_port) {
    EnsureChromiumIOThread();
    auto session = std::make_unique<EidolonSession>(0, true);
    std::string target_host(host);

    g_io_thread->task_runner()->PostTask(FROM_HERE, base::BindOnce([](
            std::string host_str, uint16_t port_num, uint16_t p) {
        QUICListenHelper::Start(host_str, port_num, p);
    }, target_host, port, static_cast<uint16_t>(cb_port)));

    return session.release();
}

} // extern "C"