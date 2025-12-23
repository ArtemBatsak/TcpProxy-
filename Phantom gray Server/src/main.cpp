#include <asio.hpp>
#include <asio/ssl.hpp>
#include <iostream>
#include <memory>
#include <vector>
#include <thread>
#include <cstdint>
#include <chrono>
#include "server_class.h"

using asio::ip::tcp;
using namespace std;

// Simple packet used on the TLS control channel
struct Packet {
    uint32_t type;
    uint32_t value;
};

string SERVER_IP = "";
string LOCAL_IP = "";
uint16_t CONTROL_PORT = 44555;
uint16_t LOCAL_PORT = 25565;
uint32_t ID_CLIENT = 3691175;
uint32_t POOL_SIZE = 3;

struct Ports {
    uint32_t data_port;
    uint32_t client_port;
};

// Asynchronously receive commands from the control TLS socket and act on them
void async_receive_command(
    std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_sock,
    std::shared_ptr<Client> client);

// Create a Client instance configured with the provided data port and start command reception
void create_client(std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_sock,
    uint32_t data_port,
    uint32_t client_port,
    asio::io_context& io);

int main() {
    try {
        asio::io_context io;

        asio::ssl::context ctx(asio::ssl::context::tlsv12_client);
        ctx.set_verify_mode(asio::ssl::verify_none);
        ctx.set_options(
            asio::ssl::context::default_workarounds |
            asio::ssl::context::no_sslv2 |
            asio::ssl::context::no_sslv3
        );
        auto ssl_sock = std::make_shared<asio::ssl::stream<tcp::socket>>(io, ctx);

        tcp::resolver resolver(io);
        auto endpoints = resolver.resolve(SERVER_IP, std::to_string(CONTROL_PORT));

        asio::async_connect(ssl_sock->lowest_layer(), endpoints,
            [ssl_sock, &io](const asio::error_code& ec, const tcp::endpoint&) {
                if (ec) {
                    std::cerr
                        << "Connect failed: "
                        << ec.category().name()
                        << " (" << ec.value() << ")\n";
                    return;
                }

                ssl_sock->async_handshake(asio::ssl::stream_base::client,
                    [ssl_sock, &io](const asio::error_code& ec) {
                        if (ec){
                            std::cerr
                                << "SSL handshake failed: "
                                << ec.category().name()
                                << " (" << ec.value() << ")\n";
                            return;
                        }
                        std::cout << "SSL handshake successful\n";

                        uint32_t net_id = htonl(ID_CLIENT);
                        asio::async_write(*ssl_sock, asio::buffer(&net_id, sizeof(net_id)),
                            [ssl_sock, &io](const asio::error_code& ec, std::size_t) {
                                if (ec) {
                                    std::cerr
                                        << "Failed to send client ID:"
                                        << ec.category().name()
                                        << " (" << ec.value() << ")\n";
                                    return;
                                }

                                auto buf_ok = std::make_shared<uint32_t>();
                                asio::async_read(*ssl_sock, asio::buffer(buf_ok.get(), sizeof(uint32_t)),
                                    [ssl_sock, &io, buf_ok](const asio::error_code& ec, std::size_t bytes_read) {
                                        if (ec || bytes_read != sizeof(uint32_t)) {
                                            std::cerr
                                                << "Failed to read OK after ID:"
                                                << ec.category().name()
                                                << " (" << ec.value() << ")\n";

                                            return;
                                        }

                                        if (ntohl(*buf_ok) != 1) {
                                            std::cerr << "Authorization failed\n";

                                            return;
                                        }

                                        std::cout << "ID accepted by server\n";

                                        uint32_t net_pool = htonl(POOL_SIZE);
                                        asio::async_write(*ssl_sock, asio::buffer(&net_pool, sizeof(net_pool)),
                                            [ssl_sock, &io](const asio::error_code& ec, std::size_t) {
                                                if (ec) {
                                                    std::cerr
                                                        << "Failed to send pool size: "
                                                        << ec.category().name()
                                                        << " (" << ec.value() << ")\n";

                                                    return;
                                                }

                                                auto buf_ports = std::make_shared<std::array<uint32_t, 3>>();
                                                asio::async_read(*ssl_sock, asio::buffer(*buf_ports),
                                                    [ssl_sock, &io, buf_ports](const asio::error_code& ec, std::size_t bytes_read) {
                                                        if (ec || bytes_read != sizeof(*buf_ports)) {
                                                            std::cerr
                                                                << "Failed to read OK+ports after pool: "
                                                                << ec.category().name()
                                                                << " (" << ec.value() << ")\n";

                                                            return;
                                                        }

                                                        uint32_t ok = ntohl((*buf_ports)[0]);
                                                        if (ok != 1) {
                                                            std::cerr << "Server rejected pool size\n";
                                                            return;
                                                        }

                                                        uint32_t client_port = ntohl((*buf_ports)[1]);
                                                        uint32_t data_port = ntohl((*buf_ports)[2]);

                                                        std::cout << "Pool accepted. Data port: " << data_port
                                                            << ", Client port: " << client_port << "\n";

                                                        create_client(ssl_sock, data_port, client_port, io);
                                                    });
                                            });
                                    });
                            });
                    });
            });

        io.run();
    }
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }
    return 0;
}

// Instantiate Client and start receiving commands from control socket
void create_client(std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_sock,
    uint32_t data_port,
    uint32_t client_port,
    asio::io_context& io)
{
    auto client = std::make_shared<Client>(SERVER_IP, LOCAL_IP, LOCAL_PORT, static_cast<uint16_t>(data_port), io);
    async_receive_command(ssl_sock, client);
}

// Read Packet structures from the control TLS socket and handle CONNECT/PING/PONG
void async_receive_command(
    std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_sock,
    std::shared_ptr<Client> client)
{
    auto packet = std::make_shared<Packet>();

    asio::async_read(*ssl_sock, asio::buffer(packet.get(), sizeof(Packet)),
        [ssl_sock, packet, client](asio::error_code ec, std::size_t length) {
            if (!ec && length == sizeof(Packet)) {
                uint32_t type = ntohl(packet->type);
                uint32_t value = ntohl(packet->value);

                switch (type) {
                case 2:
                    std::cout << "[CONNECT] OTP=" << value << "\n";
                    client->connectToServer(value);
                    break;

                case 1:
                {
                    auto pong_pkt = std::make_shared<Packet>();
                    pong_pkt->type = htonl(3);
                    pong_pkt->value = htonl(value);

                    asio::async_write(*ssl_sock, asio::buffer(pong_pkt.get(), sizeof(Packet)),
                        [ssl_sock, pong_pkt](const asio::error_code& write_ec, std::size_t) {
                            if (write_ec) {
                                std::cerr << "Failed to send PONG: " << write_ec.message() << "\n";
                            }
                        });
                    break;
                }

                case 3:
                    std::cout << "[PONG] value=" << value << "\n";
                    break;

                default:
                    std::cerr << "[UNKNOWN] type=" << type << " value=" << value << "\n";
                    break;
                }

                async_receive_command(ssl_sock, client);
            }
            else {
                std::cerr << "Control socket read error: " << ec.message() << "\n";
            }
        });
}

