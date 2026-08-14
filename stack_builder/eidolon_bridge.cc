#include "net/socket/tcp_client_socket.h"
#include "net/socket/ssl_client_socket_impl.h"
#include "net/ssl/ssl_config.h"
#include "net/base/address_list.h"
#include "net/base/ip_endpoint.h"
#include "net/base/io_buffer.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"

#include "eidolon_bridge.h"

extern "C" {

struct EidolonSession {
    std::unique_ptr<net::StreamSocket> socket;
};

EidolonHandle eidolon_dial_tcp(const char* host, uint16_t port, const uint8_t* token) {
    auto session = std::make_unique<EidolonSession>();

    net::IPAddress ip;
    if (!ip.AssignFromIPLiteral(host)) return nullptr;
    net::AddressList addr_list(net::IPEndPoint(ip, port));

    auto tcp_socket = std::make_unique<net::TCPClientSocket>(
            addr_list, nullptr, nullptr, nullptr, net::NetLogSource());

    if (tcp_socket->Connect(base::DoNothing()) != net::OK) return nullptr;

    net::SSLConfig ssl_config;
    // Активируем наши хуки из патча
    ssl_config.eidolon_active = true;
    std::copy(token, token + 32, ssl_config.eidolon_token.begin());

    net::SSLClientContext ssl_context(nullptr, nullptr, nullptr, nullptr, nullptr);

    session->socket = std::make_unique<net::SSLClientSocketImpl>(
            &ssl_context, std::move(tcp_socket), net::HostPortPair(host, port), ssl_config);

    if (session->socket->Connect(base::DoNothing()) != net::OK) return nullptr;

    return session.release();
}

int eidolon_export_key(EidolonHandle handle, uint8_t* out_key, size_t key_len) {
    if (!handle || key_len != 32) return -1;
    auto* session = static_cast<EidolonSession*>(handle);
    auto* ssl_socket = static_cast<net::SSLClientSocketImpl*>(session->socket.get());

    if (!ssl_socket->GetSSL()) return -1;

    int res = SSL_export_keying_material(ssl_socket->GetSSL(), out_key, key_len, "eidolon-traffic-key", 19, nullptr, 0, 0);
    return res == 1 ? 0 : -1;
}

int eidolon_read(EidolonHandle handle, uint8_t* buffer, size_t buffer_len) {
    if (!handle) return -1;
    auto* session = static_cast<EidolonSession*>(handle);
    auto io_buffer = base::MakeRefCounted<net::IOBufferWithSize>(buffer_len);
    int rv = session->socket->Read(io_buffer.get(), buffer_len, base::DoNothing());
    if (rv > 0) memcpy(buffer, io_buffer->data(), rv);
    return rv;
}

int eidolon_write(EidolonHandle handle, const uint8_t* buffer, size_t buffer_len) {
    if (!handle) return -1;
    auto* session = static_cast<EidolonSession*>(handle);
    auto io_buffer = base::MakeRefCounted<net::IOBufferWithSize>(buffer_len);
    memcpy(io_buffer->data(), buffer, buffer_len);
    return session->socket->Write(io_buffer.get(), buffer_len, base::DoNothing(), net::NetworkTrafficAnnotationTag());
}

void eidolon_close(EidolonHandle handle) {
    if (handle) {
        auto* session = static_cast<EidolonSession*>(handle);
        session->socket->Disconnect();
        delete session;
    }
}

// Заглушка для QUIC (реализуется через URLRequestContextBuilder)
EidolonHandle eidolon_dial_quic(const char* host, uint16_t port, const uint8_t* token) {
    return nullptr; // TODO: Дополним QUIC-мост на следующем шаге
}

} // extern "C"