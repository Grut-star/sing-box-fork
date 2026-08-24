#include "bridge.h"

#include <unistd.h>
#include <fcntl.h>
#include <vector>
#include <string>

#include "net/socket/tcp_client_socket.h"
#include "net/socket/ssl_client_socket_impl.h"
#include "net/ssl/ssl_config.h"
#include "net/base/address_list.h"
#include "net/base/ip_endpoint.h"
#include "net/base/io_buffer.h"
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
#include "base/files/file_descriptor_watcher_posix.h"
#include "base/posix/eintr_wrapper.h"

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

extern "C" {

// Глобальный IO-поток Chromium
static base::Thread* g_io_thread = nullptr;

void EnsureChromiumIOThread() {
    if (!g_io_thread) {
        g_io_thread = new base::Thread("EidolonIOThread");
        base::Thread::Options options;
        options.message_pump_type = base::MessagePumpType::IO; // КРИТИЧНО для FileDescriptorWatcher
        g_io_thread->StartWithOptions(std::move(options));
    }
}

// -------------------------------------------------------------------------
// АСИНХРОННАЯ СЕССИЯ (DATA PUMP)
// -------------------------------------------------------------------------
struct EidolonSession {
    std::unique_ptr<net::StreamSocket> tcp_socket;
    std::unique_ptr<net::SSLClientContext> ssl_context; // Должен жить вместе с TLS сокетом
    std::unique_ptr<net::URLRequestContext> url_context;
    std::unique_ptr<net::QuicChromiumClientSession::Handle> quic_session_handle;
    std::unique_ptr<net::QuicChromiumClientStream::Handle> quic_stream_handle;

    int data_fd_ = -1;
    bool is_quic_ = false;
    bool is_closed_ = false;

    // Инструменты асинхронного I/O
    scoped_refptr<net::IOBufferWithSize> read_buf_;
    std::unique_ptr<base::FileDescriptorWatcher::Controller> fd_read_controller_;
    std::unique_ptr<base::FileDescriptorWatcher::Controller> fd_write_controller_;

    bool socket_write_pending_ = false;
    bool socket_read_pending_ = false;
    std::vector<std::string> pending_fd_writes_;

    EidolonSession(int fd, bool quic) : data_fd_(fd), is_quic_(quic) {
        // Переводим FD от Go в неблокирующий режим (Non-Blocking)
        int flags = fcntl(data_fd_, F_GETFL, 0);
        fcntl(data_fd_, F_SETFL, flags | O_NONBLOCK);

        // Аллоцируем буфер 64 КБ (достаточно для QUIC Datagram / Jumbo Frames)
        read_buf_ = base::MakeRefCounted<net::IOBufferWithSize>(65536);
    }

    ~EidolonSession() {
        Close();
    }

    void StartPump() {
        if (is_closed_) return;

        // Начинаем следить за доступностью данных от Go
        fd_read_controller_ = base::FileDescriptorWatcher::WatchReadable(
                data_fd_,
                base::BindRepeating(&EidolonSession::OnFdReadable, base::Unretained(this))
        );

        // Запускаем первичное чтение из Chromium сокета
        DoSocketRead();
    }

    // --- НАПРАВЛЕНИЕ: Go FD -> Chromium Socket ---

    void OnFdReadable() {
        if (is_closed_ || socket_write_pending_) return;

        std::vector<uint8_t> temp_buf(65536);
        ssize_t bytes_read = HANDLE_EINTR(read(data_fd_, temp_buf.data(), temp_buf.size()));

        if (bytes_read > 0) {
            auto write_buf = base::MakeRefCounted<net::StringIOBuffer>(
                    std::string(reinterpret_cast<char*>(temp_buf.data()), bytes_read));
            socket_write_pending_ = true;

            int rv = 0;
            if (is_quic_) {
                std::string_view data_sv(write_buf->data(), bytes_read);
                rv = quic_stream_handle_->WriteStreamData(
                        data_sv, false,
                        base::BindOnce(&EidolonSession::OnSocketWriteComplete, base::Unretained(this)));
            } else {
                rv = tcp_socket_->Write(
                        write_buf.get(), bytes_read,
                        base::BindOnce(&EidolonSession::OnSocketWriteComplete, base::Unretained(this)),
                        TRAFFIC_ANNOTATION_FOR_TESTS);
            }

            if (rv != net::ERR_IO_PENDING) {
                OnSocketWriteComplete(rv);
            }
        } else if (bytes_read == 0 || (bytes_read < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
            // Сокет со стороны Go был закрыт (EOF) или произошла фатальная ошибка
            Close();
        }
    }

    void OnSocketWriteComplete(int rv) {
        if (is_closed_) return;
        socket_write_pending_ = false;

        if (rv < 0) {
            Close(); // Ошибка записи в сеть
        }
        // Если сеть готова, OnFdReadable вызовется автоматически nhờ FileDescriptorWatcher
    }

    // --- НАПРАВЛЕНИЕ: Chromium Socket -> Go FD ---

    void DoSocketRead() {
        if (is_closed_ || socket_read_pending_) return;
        socket_read_pending_ = true;

        int rv = 0;
        if (is_quic_) {
            rv = quic_stream_handle_->ReadBody(
                    read_buf_.get(), read_buf_->size(),
                    base::BindOnce(&EidolonSession::OnSocketReadComplete, base::Unretained(this)));
        } else {
            rv = tcp_socket_->Read(
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
            ssize_t written = HANDLE_EINTR(write(data_fd_, chunk.data(), chunk.size()));

            if (written > 0) {
                if (static_cast<size_t>(written) == chunk.size()) {
                    pending_fd_writes_.erase(pending_fd_writes_.begin());
                } else {
                    chunk = chunk.substr(written);
                    break; // Ядро ОС перегружено, ждем готовности FD
                }
            } else if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                break; // Ждем доступности буфера FD
            } else {
                Close(); // Фатальная ошибка Unix Socket
                return;
            }
        }

        if (!pending_fd_writes_.empty()) {
            // Включаем ожидание доступности записи, если не влезло
            if (!fd_write_controller_) {
                fd_write_controller_ = base::FileDescriptorWatcher::WatchWritable(
                        data_fd_,
                        base::BindRepeating(&EidolonSession::TryWriteToFd, base::Unretained(this)));
            }
        } else {
            // Всё записано, выключаем watcher записи и продолжаем читать сеть
            fd_write_controller_.reset();
            DoSocketRead();
        }
    }

    void Close() {
        if (is_closed_) return;
        is_closed_ = true;

        // Отключаем наблюдателей
        fd_read_controller_.reset();
        fd_write_controller_.reset();

        if (data_fd_ != -1) {
            close(data_fd_);
            data_fd_ = -1;
        }

        if (is_quic_) {
            quic_stream_handle_.reset();
            quic_session_handle_.reset();
        } else {
            if (tcp_socket_) {
                tcp_socket_->Disconnect();
                tcp_socket_.reset();
            }
        }
    }
};

// -------------------------------------------------------------------------
// ХЕЛПЕР ДЛЯ АСИНХРОННОГО ДОЗВОНА TCP (Без блокировок)
// -------------------------------------------------------------------------
class TCPDialHelper {
public:
    static void Start(EidolonSession* sess, const std::string& host, uint16_t port, const std::vector<uint8_t>& token, base::WaitableEvent* event) {
        auto dialer = new TCPDialHelper(sess, host, port, token, event);
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

        net::SSLConfig ssl_config;
        ssl_config.eidolon_active = true;

        size_t copy_len = std::min(token_.size(), static_cast<size_t>(32));
        UNSAFE_BUFFERS(base::span<uint8_t>(ssl_config.eidolon_token)).copy_from(
                UNSAFE_BUFFERS(base::span<const uint8_t>(token_.data(), copy_len)));

        sess_->ssl_context = std::make_unique<net::SSLClientContext>(nullptr, nullptr, nullptr, nullptr, nullptr);

        sess_->tcp_socket = std::make_unique<net::SSLClientSocketImpl>(
                sess_->ssl_context.get(), std::move(raw_socket_), net::HostPortPair(host_, port_), ssl_config);

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

    EidolonSession* sess_;
    std::string host_;
    uint16_t port_;
    std::vector<uint8_t> token_;
    base::WaitableEvent* event_;
    std::unique_ptr<net::StreamSocket> raw_socket_;
};

// -------------------------------------------------------------------------
// C-API (ДЛЯ GOLANG)
// -------------------------------------------------------------------------

EidolonHandle eidolon_dial_tcp(const char* host, uint16_t port, const uint8_t* token, size_t token_len, int data_fd) {
    EnsureChromiumIOThread();

    auto session = std::make_unique<EidolonSession>(data_fd, false);
    std::string target_host(host);
    std::vector<uint8_t> token_vec(token, token + token_len);

    base::WaitableEvent connect_event(base::WaitableEvent::ResetPolicy::MANUAL,
                                      base::WaitableEvent::InitialState::NOT_SIGNALED);

    // Дозвон происходит полностью в IO-потоке
    g_io_thread->task_runner()->PostTask(FROM_HERE, base::BindOnce([](
            EidolonSession* sess, std::string host_str, uint16_t port_num, std::vector<uint8_t> tok, base::WaitableEvent* event) {
        TCPDialHelper::Start(sess, host_str, port_num, tok, event);
    }, session.get(), target_host, port, token_vec, &connect_event));

    // Блокируем Go-горутину (это нормально, CGO вызов вернется после хендшейка)
    connect_event.Wait();

    if (session->is_closed_) return nullptr;
    return session.release();
}

EidolonHandle eidolon_dial_quic(const char* host, uint16_t port, const uint8_t* token, size_t token_len, int data_fd) {
    EnsureChromiumIOThread();

    auto session = std::make_unique<EidolonSession>(data_fd, true);
    std::string target_host(host);

    base::WaitableEvent connect_event(base::WaitableEvent::ResetPolicy::MANUAL,
                                      base::WaitableEvent::InitialState::NOT_SIGNALED);

    g_io_thread->task_runner()->PostTask(FROM_HERE, base::BindOnce([](
            EidolonSession* sess, std::string host_str, uint16_t port_num, base::WaitableEvent* event) {

        net::URLRequestContextBuilder builder;
        builder.DisableHttpCache();

        auto quic_context = std::make_unique<net::QuicContext>();
        quic_context->params()->supported_versions = net::DefaultSupportedQuicVersions();

        builder.SetSpdyAndQuicEnabled(false, true);
        builder.set_quic_context(std::move(quic_context));
        sess->url_context = builder.Build();

        net::HttpNetworkSession* http_session = sess->url_context->http_transaction_factory()->GetSession();
        net::QuicSessionPool* quic_pool = http_session->quic_session_pool();

        net::HostPortPair host_port(host_str, port_num);
        url::SchemeHostPort scheme_host_port("https", host_str, port_num);

        net::IPAddress ip;
        if (!ip.AssignFromIPLiteral(host_str)) {
            sess->Close();
            event->Signal();
            return;
        }

        net::QuicSessionKey session_key(
                host_port, net::PRIVACY_MODE_DISABLED, net::ProxyChain::Direct(),
                net::SessionUsage::kDestination, net::SocketTag(),
                net::NetworkAnonymizationKey(), net::SecureDnsPolicy::kAllow,
                false, false, net::handles::kInvalidNetworkHandle);

        net::QuicEndpoint quic_endpoint(
                net::DefaultSupportedQuicVersions().front(),
                net::IPEndPoint(ip, port_num),
                net::ConnectionEndpointMetadata());

        auto session_attempt = quic_pool->CreateSessionAttempt(
                nullptr, session_key, quic_endpoint, 0,
                base::TimeTicks::Now(), base::TimeTicks::Now(),
                std::nullopt, false, {},
                net::MultiplexedSessionCreationInitiator::kUnknown, std::nullopt);

        int rv = session_attempt->Start(base::BindOnce([](
                EidolonSession* inner_sess, net::QuicSessionAttempt* attempt, url::SchemeHostPort shp, base::WaitableEvent* inner_event, int result) {

            if (result == net::OK && attempt->session()) {
                inner_sess->quic_session_handle = attempt->session()->CreateHandle(std::move(shp));
                if (inner_sess->quic_session_handle && inner_sess->quic_session_handle->IsConnected()) {
                    inner_sess->quic_session_handle->RequestStream(
                            true,
                            base::BindOnce([](EidolonSession* s, base::WaitableEvent* ev, int stream_result) {
                                if (stream_result == net::OK) {
                                    s->quic_stream_handle = s->quic_session_handle->ReleaseStream();
                                    s->StartPump(); // Запускаем помпу после открытия стрима
                                } else {
                                    s->Close();
                                }
                                ev->Signal();
                            }, inner_sess, inner_event),
                            TRAFFIC_ANNOTATION_FOR_TESTS);
                    return;
                }
            }
            inner_sess->Close();
            inner_event->Signal();
        }, sess, session_attempt.get(), scheme_host_port, event));

        if (rv != net::ERR_IO_PENDING) {
            sess->Close();
            event->Signal();
        }

    }, session.get(), target_host, port, &connect_event));

    connect_event.Wait();

    if (session->is_closed_) return nullptr;
    return session.release();
}

int eidolon_export_key(EidolonHandle handle, uint8_t* out_key, size_t key_len) {
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

void eidolon_close(EidolonHandle handle) {
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