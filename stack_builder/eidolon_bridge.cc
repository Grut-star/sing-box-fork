#include "net/socket/tcp_client_socket.h"
#include "net/socket/ssl_client_socket_impl.h"
#include "net/ssl/ssl_config.h"
#include "net/base/address_list.h"
#include "net/base/ip_endpoint.h"
#include "net/base/io_buffer.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"

// Заголовочные файлы для Chromium IO и QUIC
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

#include "eidolon_bridge.h"

extern "C" {

// 1. Глобальный IO-поток Chromium.
static base::Thread* g_io_thread = nullptr;

void EnsureChromiumIOThread() {
    if (!g_io_thread) {
        g_io_thread = new base::Thread("EidolonIOThread");
        base::Thread::Options options;
        options.message_pump_type = base::MessagePumpType::IO;
        g_io_thread->StartWithOptions(std::move(options));
    }
}

// 2. Вспомогательный класс-синхронизатор
class SyncWaiter {
public:
    SyncWaiter() : event_(base::WaitableEvent::ResetPolicy::MANUAL,
                          base::WaitableEvent::InitialState::NOT_SIGNALED) {}

    base::OnceCallback<void(int)> callback() {
        return base::BindOnce(&SyncWaiter::OnComplete, base::Unretained(this));
    }

    int WaitForResult(int rv) {
        if (rv == net::ERR_IO_PENDING) {
            event_.Wait();
            return result_;
        }
        return rv;
    }

private:
    void OnComplete(int result) {
        result_ = result;
        event_.Signal();
    }

    base::WaitableEvent event_;
    int result_ = 0;
};

// 3. Единая структура сессии
struct EidolonSession {
    std::unique_ptr<net::StreamSocket> tcp_socket;

    std::unique_ptr<net::URLRequestContext> url_context;
    std::unique_ptr<net::QuicChromiumClientSession::Handle> quic_session_handle;
    std::unique_ptr<net::QuicChromiumClientStream::Handle> quic_stream_handle;

    bool is_quic() const {
        return quic_stream_handle != nullptr;
    }
};

// -------------------------------------------------------------------------
// ИНИЦИАЛИЗАЦИЯ TCP
// -------------------------------------------------------------------------

EidolonHandle eidolon_dial_tcp(const char* host, uint16_t port, const uint8_t* token) {
    auto session = std::make_unique<EidolonSession>();

    net::IPAddress ip;
    if (!ip.AssignFromIPLiteral(host)) return nullptr;
    net::AddressList addr_list(net::IPEndPoint(ip, port));

    auto tcp_socket = std::make_unique<net::TCPClientSocket>(
            addr_list, nullptr, nullptr, nullptr, net::NetLogSource(), net::handles::kInvalidNetworkHandle);

    if (tcp_socket->Connect(base::DoNothing()) != net::OK) return nullptr;

    net::SSLConfig ssl_config;
    ssl_config.eidolon_active = true;

    // Fix: Unsafe pointer arithmetic
    base::span<const uint8_t> token_span(token, 32);
    base::span<uint8_t> target_span(ssl_config.eidolon_token);
    target_span.copy_from(token_span);

    net::SSLClientContext ssl_context(nullptr, nullptr, nullptr, nullptr, nullptr);

    session->tcp_socket = std::make_unique<net::SSLClientSocketImpl>(
            &ssl_context, std::move(tcp_socket), net::HostPortPair(host, port), ssl_config);

    if (session->tcp_socket->Connect(base::DoNothing()) != net::OK) return nullptr;

    return session.release();
}

// -------------------------------------------------------------------------
// ИНИЦИАЛИЗАЦИЯ QUIC
// -------------------------------------------------------------------------

EidolonHandle eidolon_dial_quic(const char* host, uint16_t port, const uint8_t* token) {
    EnsureChromiumIOThread();

    auto session = std::make_unique<EidolonSession>();
    std::string target_host(host);

    // Подготовка синхронизатора для Go-потока
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

        // Парсим IP адрес для QuicEndpoint
        net::IPAddress ip;
        if (!ip.AssignFromIPLiteral(host_str)) {
            event->Signal();
            return;
        }
        net::IPEndPoint ip_endpoint(ip, port_num);

        net::QuicSessionKey session_key(
                host_port, net::PRIVACY_MODE_DISABLED, net::ProxyChain::Direct(),
                net::SessionUsage::kDestination, net::SocketTag(),
                net::NetworkAnonymizationKey(), net::SecureDnsPolicy::kAllow,
                /*require_dns_https_alpn=*/false,
                /*disable_cert_verification_network_fetches=*/false,
                /*target_network=*/net::handles::kInvalidNetworkHandle);

        // Формируем корректный QuicEndpoint (Без заглушек, с реальным IP и версией)
        net::QuicEndpoint quic_endpoint(
                net::DefaultSupportedQuicVersions().front(),
                ip_endpoint,
                net::ConnectionEndpointMetadata());

        auto session_attempt = quic_pool->CreateSessionAttempt(
                nullptr, session_key, quic_endpoint,
                0 /* cert_verify_flags */,
                base::TimeTicks::Now(), base::TimeTicks::Now(),
                std::nullopt, /*use_dns_aliases=*/false, {},
                net::MultiplexedSessionCreationInitiator::kUnknown,
                std::nullopt);

        int rv = session_attempt->Start(base::BindOnce([](
                EidolonSession* inner_sess, net::QuicSessionAttempt* attempt, url::SchemeHostPort shp, base::WaitableEvent* inner_event, int result) {

            // Запрашиваем handle через session()
            if (result == net::OK && attempt->session()) {
                inner_sess->quic_session_handle = attempt->session()->CreateHandle(std::move(shp));
                if (inner_sess->quic_session_handle && inner_sess->quic_session_handle->IsConnected()) {
                    // Создаем двунаправленный стрим
                    inner_sess->quic_session_handle->RequestStream(
                            true, // requires_confirmation
                            base::BindOnce([](EidolonSession* s, base::WaitableEvent* ev, int stream_result) {
                                if (stream_result == net::OK) {
                                    s->quic_stream_handle = s->quic_session_handle->ReleaseStream();
                                }
                                ev->Signal();
                            }, inner_sess, inner_event),
                            TRAFFIC_ANNOTATION_FOR_TESTS);
                    return; // Ждем коллбека RequestStream
                }
            }
            inner_event->Signal(); // Сигнал при ошибке
        }, sess, session_attempt.get(), scheme_host_port, event));

        if (rv != net::ERR_IO_PENDING) {
            event->Signal(); // Завершилось синхронно (маловероятно, но возможно)
        }

    }, session.get(), target_host, port, &connect_event));

    connect_event.Wait();

    // Защита: Если стрим не удалось создать, возвращаем null
    if (!session->is_quic()) {
        return nullptr;
    }

    return session.release();
}

// -------------------------------------------------------------------------
// I/O ОПЕРАЦИИ И КРИПТОГРАФИЯ
// -------------------------------------------------------------------------

int eidolon_export_key(EidolonHandle handle, uint8_t* out_key, size_t key_len) {
    if (!handle || key_len != 32) return -1;
    auto* session = static_cast<EidolonSession*>(handle);

    // Экспорт ключа для QUIC
    if (session->is_quic()) {
        bool success = session->quic_session_handle->ExportKeyingMaterial(
                "eidolon-traffic-key", "", out_key, key_len);
        return success ? 0 : -1;
    }

    // Экспорт ключа для TCP
    auto* ssl_socket = static_cast<net::SSLClientSocketImpl*>(session->tcp_socket.get());
    if (!ssl_socket || !ssl_socket->GetSSL()) return -1;

    int res = SSL_export_keying_material(
            ssl_socket->GetSSL(), out_key, key_len, "eidolon-traffic-key", 19, nullptr, 0, 0);
    return res == 1 ? 0 : -1;
}

int eidolon_read(EidolonHandle handle, uint8_t* buffer, size_t buffer_len) {
    if (!handle) return -1;
    auto* session = static_cast<EidolonSession*>(handle);
    auto io_buffer = base::MakeRefCounted<net::IOBufferWithSize>(buffer_len);

    SyncWaiter waiter;
    int rv;

    if (session->is_quic()) {
        rv = session->quic_stream_handle->ReadBody(io_buffer.get(), buffer_len, waiter.callback());
    } else {
        rv = session->tcp_socket->Read(io_buffer.get(), buffer_len, waiter.callback());
    }

    rv = waiter.WaitForResult(rv);
    if (rv > 0) {
        // Fix: Unsafe memcpy
        base::span<uint8_t>(buffer, rv).copy_from(
                base::span<const uint8_t>(reinterpret_cast<const uint8_t*>(io_buffer->data()), rv)
        );
    }
    return rv;
}

int eidolon_write(EidolonHandle handle, const uint8_t* buffer, size_t buffer_len) {
    if (!handle) return -1;
    auto* session = static_cast<EidolonSession*>(handle);

    SyncWaiter waiter;
    int rv;

    if (session->is_quic()) {
        std::string_view data(reinterpret_cast<const char*>(buffer), buffer_len);
        // Chromium QUIC WriteStreamData может завершиться мгновенно, если есть окно контроля потока
        rv = session->quic_stream_handle->WriteStreamData(data, false, waiter.callback());
    } else {
        auto io_buffer = base::MakeRefCounted<net::IOBufferWithSize>(buffer_len);
        // Fix: Unsafe memcpy
        base::span<uint8_t>(reinterpret_cast<uint8_t*>(io_buffer->data()), buffer_len).copy_from(
                base::span<const uint8_t>(buffer, buffer_len)
        );

        rv = session->tcp_socket->Write(
                io_buffer.get(), buffer_len, waiter.callback(), TRAFFIC_ANNOTATION_FOR_TESTS);
    }

    return waiter.WaitForResult(rv);
}

void eidolon_close(EidolonHandle handle) {
    if (handle) {
        auto* session = static_cast<EidolonSession*>(handle);
        if (session->is_quic()) {
            session->quic_stream_handle.reset();
            session->quic_session_handle.reset();
        } else if (session->tcp_socket) {
            session->tcp_socket->Disconnect();
        }
        delete session;
    }
}

} // extern "C"