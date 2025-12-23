#include "Server_class.h"

Client::Client(const std::string& server_ip,
    const std::string& local_ip,
    uint16_t local_port,
    uint16_t data_port,
    asio::io_context& io)
    : server_ip_(server_ip)
    , local_ip_(local_ip)
    , local_port_(local_port)
    , data_port_(data_port)
    , io_(io)
    , next_pair_id_(1)
{
}

void Client::connectToServer(uint32_t otp)
{
    auto self = shared_from_this();
    auto data_sock = std::make_shared<tcp::socket>(io_);

    tcp::resolver resolver(io_);
    auto endpoints = resolver.resolve(server_ip_, std::to_string(data_port_));

    asio::async_connect(*data_sock, endpoints,
        [this, self, data_sock, otp](const asio::error_code& ec, const tcp::endpoint&)
        {
            if (ec) return;

            uint32_t net_otp = htonl(otp);
            asio::async_write(*data_sock, asio::buffer(&net_otp, sizeof(net_otp)),
                [this, self, data_sock](const asio::error_code& ec_write, std::size_t)
                {
                    if (ec_write) {
                        data_sock->close();
                        return;
                    }

                    auto buffer = std::make_shared<std::array<char, 4096>>();
                    data_sock->async_read_some(asio::buffer(*buffer),
                        [this, self, data_sock, buffer]
                        (const asio::error_code& ec_read, std::size_t bytes_read)
                        {
                            if (ec_read || bytes_read == 0) {
                                data_sock->close();
                                return;
                            }

                            auto client_sock = std::make_shared<tcp::socket>(io_);
                            asio::error_code ec_addr;
                            auto local_addr = asio::ip::make_address(local_ip_, ec_addr);
                            if (ec_addr) {
                                data_sock->close();
                                return;
                            }

                            tcp::endpoint local_ep(local_addr, local_port_);
                            client_sock->async_connect(local_ep,
                                [this, self, data_sock, client_sock, buffer, bytes_read]
                                (const asio::error_code& ec_conn)
                                {
                                    if (ec_conn) {
                                        data_sock->close();
                                        return;
                                    }

                                    asio::async_write(*client_sock,
                                        asio::buffer(buffer->data(), bytes_read),
                                        [this, self, data_sock, client_sock]
                                        (const asio::error_code& ec_write2, std::size_t)
                                        {
                                            if (ec_write2) {
                                                client_sock->close();
                                                data_sock->close();
                                                return;
                                            }

                                            link_par pair;
                                            pair.data_socket = data_sock;
                                            pair.client_socket = client_sock;
                                            pair.pair_id = make_pair_id();

                                            start_splice(pair);
                                        });
                                });
                        });
                });
        });
}

void Client::splice_loop(std::shared_ptr<tcp::socket> in_sock,
    std::shared_ptr<tcp::socket> out_sock,
    uint64_t pair_id)
{
    auto self = shared_from_this();
    auto buffer = std::make_shared<std::array<char, 4096>>();

    in_sock->async_read_some(asio::buffer(*buffer),
        [this, self, in_sock, out_sock, buffer, pair_id]
        (const asio::error_code& ec, std::size_t bytes)
        {
            if (ec || bytes == 0) {
                remove_pair(pair_id);
                return;
            }

            asio::async_write(*out_sock, asio::buffer(buffer->data(), bytes),
                [this, self, in_sock, out_sock, buffer, pair_id]
                (const asio::error_code& ec_write, std::size_t)
                {
                    if (ec_write) {
                        remove_pair(pair_id);
                        return;
                    }

                    splice_loop(in_sock, out_sock, pair_id);
                });
        });
}

void Client::start_splice(const link_par& pair)
{
    {
        std::lock_guard<std::mutex> lock(link_pool_mutex_);
        link_pool_.push_back(pair);
    }

    splice_loop(pair.client_socket, pair.data_socket, pair.pair_id);
    splice_loop(pair.data_socket, pair.client_socket, pair.pair_id);
}

uint64_t Client::make_pair_id()
{
    for (;;) {
        uint64_t id = next_pair_id_.fetch_add(1, std::memory_order_relaxed);
        if (id == 0) continue;

        std::lock_guard<std::mutex> lock(link_pool_mutex_);
        auto it = std::find_if(link_pool_.begin(), link_pool_.end(),
            [id](const link_par& p) { return p.pair_id == id; });

        if (it == link_pool_.end())
            return id;
    }
}

void Client::remove_pair(uint64_t pair_id)
{
    std::shared_ptr<tcp::socket> client_sock;
    std::shared_ptr<tcp::socket> data_sock;

    {
        std::lock_guard<std::mutex> lock(link_pool_mutex_);
        auto it = std::find_if(link_pool_.begin(), link_pool_.end(),
            [pair_id](const link_par& p) { return p.pair_id == pair_id; });

        if (it == link_pool_.end())
            return;

        client_sock = it->client_socket;
        data_sock = it->data_socket;
        link_pool_.erase(it);
    }

    if (client_sock && client_sock->is_open()) {
        asio::error_code ec;
        client_sock->shutdown(tcp::socket::shutdown_both, ec);
        client_sock->close(ec);
    }

    if (data_sock && data_sock->is_open()) {
        asio::error_code ec;
        data_sock->shutdown(tcp::socket::shutdown_both, ec);
        data_sock->close(ec);
    }
}

void Client::remove_all_pairs()
{
    std::vector<link_par> pairs;

    {
        std::lock_guard<std::mutex> lock(link_pool_mutex_);
        pairs.swap(link_pool_);
    }

    for (auto& p : pairs) {
        if (p.client_socket && p.client_socket->is_open()) {
            asio::error_code ec;
            p.client_socket->shutdown(tcp::socket::shutdown_both, ec);
            p.client_socket->close(ec);
        }

        if (p.data_socket && p.data_socket->is_open()) {
            asio::error_code ec;
            p.data_socket->shutdown(tcp::socket::shutdown_both, ec);
            p.data_socket->close(ec);
        }
    }
}
