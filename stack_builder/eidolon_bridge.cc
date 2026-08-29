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
class QUICDialHelper {
public:
    static void Start(EidolonSession* sess, const std::string& host, uint16_t port, const std::vector<uint8_t>& token, base::WaitableEvent* event) {
        auto* dialer = new QUICDialHelper(sess, host, port, token, event);
        dialer->Run();
    }

private:
    QUICDialHelper(EidolonSession* sess, const std::string& host, uint16_t port, const std::vector<uint8_t>& token, base::WaitableEvent* event)
            : sess_(sess), host_(host), port_(port), token_(token), event_(event), scheme_host_port_("https", host, port) {}

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
                nullptr, session_key, quic_endpoint, 0,
                base::TimeTicks::Now(), base::TimeTicks::Now(),
                std::nullopt, false, {},
                net::MultiplexedSessionCreationInitiator::kUnknown, std::nullopt);

        // 1. Старт хендшейка (учитываем синхронное завершение)
        int rv = sess_->quic_attempt->Start(base::BindOnce(&QUICDialHelper::OnSessionAttemptComplete, base::Unretained(this)));
        if (rv != net::ERR_IO_PENDING) OnSessionAttemptComplete(rv);
    }

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

// -------------------------------------------------------------------------
// C-API (ДЛЯ GOLANG)
// -------------------------------------------------------------------------

extern "C" {

// Глобальные объекты жизненного цикла
static base::AtExitManager* g_exit_manager = nullptr;
static base::Thread* g_io_thread = nullptr;

// Добавляем глобальный стейт безопасности транспорта
static base::NoDestructor<net::TransportSecurityState> g_transport_security_state;

#if BUILDFLAG(IS_POSIX)
// КРИТИЧНО: Явный наблюдатель за дескрипторами для POSIX.
// Без него FileDescriptorWatcher::WatchReadable падает с SIGSEGV.
static base::FileDescriptorWatcher* g_file_descriptor_watcher = nullptr;
#endif

// Единая функция инициализации (вызывается из Go)
EIDOLON_EXPORT void eidolon_init() {
    // 0. Инициализация командной строки (критично для сетевого стека Chromium)
    if (!base::CommandLine::InitializedForCurrentProcess()) {
        base::CommandLine::Init(0, nullptr);
    }

    if (!g_exit_manager) {
        // 1. Инициализация менеджера очистки
        g_exit_manager = new base::AtExitManager();

        // 2. Инициализация пула потоков Chromium (необходим для внутренних нужд движка)
        base::ThreadPoolInstance::CreateAndStartWithDefaultParams("Eidolon_ThreadPool");

        // 3. Создаем наш выделенный IO-поток для работы с сетью
        g_io_thread = new base::Thread("EidolonIOThread");
        base::Thread::Options options;
        options.message_pump_type = base::MessagePumpType::IO;
        g_io_thread->StartWithOptions(std::move(options));

        // Инициализируем TransportSecurityState (безопасно, так как есть дефолтный конструктор)
#if BUILDFLAG(IS_POSIX)
        // 4. ВОТ РЕШЕНИЕ ПРОБЛЕМЫ: явно создаем FileDescriptorWatcher
        // и указываем ему использовать TaskRunner нашего IO-потока.
        g_file_descriptor_watcher = new base::FileDescriptorWatcher(
            g_io_thread->task_runner()
        );
#endif
    }
}

void EnsureChromiumIOThread() {
    // Подменяем старый вызов, чтобы гарантировать полную инициализацию
    // при любых сценариях дозвона
    eidolon_init();
}

EIDOLON_EXPORT EidolonHandle eidolon_dial_tcp(const char* host, uint16_t port, const uint8_t* token, size_t token_len, uintptr_t data_fd) {
    EnsureChromiumIOThread();

    auto session = std::make_unique<EidolonSession>(data_fd, false);
    std::string target_host(host);
    auto safe_span = UNSAFE_BUFFERS(base::span<const uint8_t>(token, token_len));
    std::vector<uint8_t> token_vec(safe_span.begin(), safe_span.end());

    base::WaitableEvent connect_event(base::WaitableEvent::ResetPolicy::MANUAL,
                                      base::WaitableEvent::InitialState::NOT_SIGNALED);

    // Дозвон происходит полностью в IO-потоке
    g_io_thread->task_runner()->PostTask(FROM_HERE, base::BindOnce([](
            EidolonSession* sess, std::string host_str, uint16_t port_num, std::vector<uint8_t> tok, base::WaitableEvent* event) {
        TCPDialHelper::Start(sess, host_str, port_num, tok, event);
    }, session.get(), target_host, port, token_vec, &connect_event));

    // Блокируем Go-горутину (это нормально, CGO вызов вернется после хендшейка)
    connect_event.Wait();

    if (session->is_closed_) {
        // PREVENT MAIN THREAD CRASH: Delete URLRequestContext on IO Thread
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

    // 1. Преобразуем сырой токен в вектор для безопасной передачи
    std::vector<uint8_t> token_vec(token, token + token_len);

    base::WaitableEvent connect_event(base::WaitableEvent::ResetPolicy::MANUAL,
                                      base::WaitableEvent::InitialState::NOT_SIGNALED);

    // 2. Передаем std::vector<uint8_t> tok в PostTask
    g_io_thread->task_runner()->PostTask(FROM_HERE, base::BindOnce([](
            EidolonSession* sess, std::string host_str, uint16_t port_num, std::vector<uint8_t> tok, base::WaitableEvent* event) {
        QUICDialHelper::Start(sess, host_str, port_num, tok, event);
    }, session.get(), target_host, port, token_vec, &connect_event));

    connect_event.Wait();

    if (session->is_closed_) {
        // PREVENT MAIN THREAD CRASH: Delete URLRequestContext on IO Thread
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

// Выполнение строго в IO-потоке, чтобы исключить Data Race с помпой
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
    delete s; // Деструктор автоматически вызовет Close()
}, session));
} else {
delete session;
}
}

} // extern "C"