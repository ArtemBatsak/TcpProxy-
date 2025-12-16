#include "Server_class.h"

void GrayServer::init_acceptor(int data_port, int client_port) {
    data_acceptor_ = std::make_shared<asio::ip::tcp::acceptor>(
        io_context_,
        asio::ip::tcp::endpoint(asio::ip::tcp::v4(), data_port));

    client_acceptor_ = std::make_shared<asio::ip::tcp::acceptor>(
        io_context_,
        asio::ip::tcp::endpoint(asio::ip::tcp::v4(), client_port));
}

void GrayServer::async_accept_data() {
    auto self = shared_from_this();
    if (!self->alive) return;
    auto sock = std::make_shared<asio::ip::tcp::socket>(io_context_);

    data_acceptor_->async_accept(*sock,
        [self, sock](const asio::error_code& ec)
        {
            if (!self->alive) return;
            if (!ec)
            {
                self->handle_new_data(sock);
            }
            self->async_accept_data();
        });
}

void GrayServer::handle_new_data(std::shared_ptr<asio::ip::tcp::socket> sock) {
    auto self = shared_from_this();
    if (!self->alive) return;
    auto buf = std::make_shared<uint32_t>();

    asio::async_read(*sock, asio::buffer(buf.get(), sizeof(uint32_t)),
        [this, self, sock, buf](const asio::error_code& ec, std::size_t bytes_read) {
            if (!self->alive) return;
            if (ec || bytes_read != sizeof(uint32_t)) {
                asio::error_code ignored;
                sock->shutdown(asio::ip::tcp::socket::shutdown_both, ignored);
                sock->close(ignored);
                return;
            }

            uint32_t received_otp = ntohl(*buf);

            if (received_otp != current_otp) {
                asio::error_code ignored;
                sock->shutdown(asio::ip::tcp::socket::shutdown_both, ignored);
                sock->close(ignored);
                return;
            }

            enable_keepalive(sock);
            {
                std::lock_guard<std::mutex> lock(data_pool_mutex);
                data_pool.push_back(sock);
            }
            self->try_create_pair();
        });
}

uint32_t GrayServer::generate_otp() {
    static thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<uint32_t> dist(100000, 999999);
    return dist(rng);
}

void GrayServer::check_data_pool() {
    auto self = shared_from_this();
    if (!self->alive) return;

    bool expected = false;
    if (!check_in_progress.compare_exchange_strong(expected, true))
        return;

    {
        std::lock_guard<std::mutex> lock(data_pool_mutex);

        auto it = data_pool.begin();
        while (it != data_pool.end()) {
            if (!(*it)->is_open()) {
                it = data_pool.erase(it);
            }
            else {
                ++it;
            }
        }
    }

    if (data_pool.size() < pool_size) {
        current_otp = generate_otp();

        if (!control_socket || !control_socket->lowest_layer().is_open()) {
            check_in_progress = false;
            return;
        }

        send_control_packet(2, current_otp, [self](const asio::error_code& ec) {
            self->check_in_progress = false;
            });
    }
    else {
        check_in_progress = false;
    }

    data_pool_timer.expires_after(std::chrono::seconds(1));
    data_pool_timer.async_wait([self](const asio::error_code& ec) {
        if (!self->alive || ec == asio::error::operation_aborted) return;
        self->check_data_pool();
        });
}

void GrayServer::enable_keepalive(std::shared_ptr<asio::ip::tcp::socket> sock)
{
    asio::error_code ec;
    sock->set_option(asio::socket_base::keep_alive(true), ec);
    if (ec) {
        return;
    }

#ifdef _WIN32
    tcp_keepalive ka;
    ka.onoff = 1;
    ka.keepalivetime = 20000;
    ka.keepaliveinterval = 5000;
    DWORD bytesReturned;
    WSAIoctl(sock->native_handle(), SIO_KEEPALIVE_VALS, &ka, sizeof(ka), nullptr, 0, &bytesReturned, nullptr, nullptr);
#else
    int idle = 20;
    int interval = 5;
    int count = 3;
    int fd = sock->native_handle();

    setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
    setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &count, sizeof(count));
#endif
}

void GrayServer::shutdown()
{
    auto self = shared_from_this();

    asio::post(io_context_, [self]() {
        bool expected = true;
        if (!self->alive.compare_exchange_strong(expected, false))
            return;

        self->ping_timer.cancel();
        self->pong_timer.cancel();
        self->data_pool_timer.cancel();

        asio::error_code ec;

        if (self->data_acceptor_ && self->data_acceptor_->is_open())
            self->data_acceptor_->close(ec);

        if (self->client_acceptor_ && self->client_acceptor_->is_open())
            self->client_acceptor_->close(ec);

        if (self->control_socket &&
            self->control_socket->lowest_layer().is_open())
        {
            self->control_socket->lowest_layer().shutdown(
                asio::ip::tcp::socket::shutdown_both, ec);
            self->control_socket->lowest_layer().close(ec);
        }

        self->remove_all_pairs();

        {
            std::lock_guard<std::mutex> lock(self->data_pool_mutex);
            for (auto& sock : self->data_pool) {
                if (sock && sock->is_open())
                    sock->close(ec);
            }
            self->data_pool.clear();
        }

        {
            std::lock_guard<std::mutex> lock(self->client_pool_mutex);
            for (auto& sock : self->client_pool) {
                if (sock && sock->is_open())
                    sock->close(ec);
            }
            self->client_pool.clear();
        }

        if (auto mgr = self->manager_.lock()) {
            mgr->remove(self->id);
        }

        });
}

void GrayServer::send_ping() {
    auto self = shared_from_this();
    if (!self->alive || !control_socket || !control_socket->lowest_layer().is_open()) return;

    send_control_packet(1, 0, [self](const asio::error_code& ec) {
        if (ec) {
            self->shutdown();
            return;
        }
        self->wait_pong();
        });
}

void GrayServer::wait_pong() {
    auto self = shared_from_this();
    if (!self->alive || !control_socket || !control_socket->lowest_layer().is_open()) return;

    auto buf = std::make_shared<std::array<char, 4>>();

    pong_timer.expires_after(std::chrono::seconds(ping_timeout_sec));
    pong_timer.async_wait([self](const asio::error_code& ec) {
        if (ec == asio::error::operation_aborted) return;
        if (!self->alive) return;
        self->shutdown();
        });

    asio::async_read(*control_socket,
        asio::buffer(*buf),
        [self, buf](const asio::error_code& ec, std::size_t bytes_read) {
            self->pong_timer.cancel();
            if (!self->alive) return;
            if (ec || bytes_read != 4) {
                self->shutdown();
                return;
            }

            self->schedule_ping();
        });
}

void GrayServer::schedule_ping() {
    auto self = shared_from_this();
    ping_timer.expires_after(std::chrono::seconds(ping_interval_sec));
    ping_timer.async_wait([self](const asio::error_code& ec) {
        if (!self->alive || ec == asio::error::operation_aborted) return;
        self->send_ping();
        });
}

void GrayServer::async_accept_client() {
    auto self = shared_from_this();
    if (!self->alive) return;

    auto sock = std::make_shared<asio::ip::tcp::socket>(io_context_);

    client_acceptor_->async_accept(*sock,
        [self, sock](const asio::error_code& ec)
        {
            if (!self->alive) return;
            if (!self->client_acceptor_ || !self->client_acceptor_->is_open()) return;

            if (!ec)
            {
                {
                    std::lock_guard<std::mutex> lock(self->client_pool_mutex);
                    self->client_pool.push_back(sock);
                }
                self->try_create_pair();
            }

            self->async_accept_client();
        });
}

uint64_t GrayServer::generate_id(std::shared_ptr<asio::ip::tcp::socket> sock) {
    auto endpoint = sock->remote_endpoint();
    auto ip = endpoint.address().to_string();
    auto port = std::to_string(endpoint.port());

    ip.erase(std::remove(ip.begin(), ip.end(), '.'), ip.end());

    std::string id_str = ip + port;

    return std::stoull(id_str);
}

void GrayServer::try_create_pair() {
    std::shared_ptr<asio::ip::tcp::socket> client_sock;
    std::shared_ptr<asio::ip::tcp::socket> data_sock;

    {
        std::lock_guard<std::mutex> lock_client(client_pool_mutex);
        std::lock_guard<std::mutex> lock_data(data_pool_mutex);

        if (client_pool.empty() || data_pool.empty()) return;

        client_sock = client_pool.back();
        client_pool.pop_back();

        auto it = std::find_if(data_pool.begin(), data_pool.end(),
            [](const auto& sock) { return sock->is_open(); });

        if (it == data_pool.end()) {
            client_pool.push_back(client_sock);
            return;
        }

        data_sock = *it;
        data_pool.erase(it);
    }

    link_par pair;
    pair.client_socket = client_sock;
    pair.data_socket = data_sock;
    pair.pair_id = generate_id(client_sock);
    pair.done_count = 2;

    {
        std::lock_guard<std::mutex> lock(link_pool_mutex);
        link_pool.push_back(pair);
    }

    splice_loop(client_sock, data_sock, pair.pair_id);
    splice_loop(data_sock, client_sock, pair.pair_id);
}

void GrayServer::splice_loop(
    std::shared_ptr<asio::ip::tcp::socket> in_sock,
    std::shared_ptr<asio::ip::tcp::socket> out_sock,
    uint64_t pair_id)
{
    auto self = shared_from_this();
    auto buffer = std::make_shared<std::array<char, 4096>>();

    in_sock->async_read_some(
        asio::buffer(*buffer),
        [self, in_sock, out_sock, buffer, pair_id]
        (const asio::error_code& ec, std::size_t bytes)
        {
            if (ec) {
                self->remove_pair(pair_id);
                return;
            }

            if (bytes == 0) {
                self->remove_pair(pair_id);
                return;
            }

            asio::async_write(
                *out_sock,
                asio::buffer(buffer->data(), bytes),
                [self, in_sock, out_sock, buffer, pair_id]
                (const asio::error_code& ec_write, std::size_t written)
                {
                    if (ec_write) {
                        self->remove_pair(pair_id);
                        return;
                    }

                    self->splice_loop(in_sock, out_sock, pair_id);
                });
        });
}

void GrayServer::remove_pair(uint64_t pair_id) {

    std::shared_ptr<asio::ip::tcp::socket> client_sock;
    std::shared_ptr<asio::ip::tcp::socket> data_sock;
    {
        std::lock_guard<std::mutex> lock(link_pool_mutex);

        auto it = std::find_if(link_pool.begin(), link_pool.end(),
            [pair_id](const link_par& pair) { return pair.pair_id == pair_id; });

        if (it == link_pool.end()) return;

        client_sock = it->client_socket;
        data_sock = it->data_socket;

        link_pool.erase(it);
    }

    if (client_sock && client_sock->is_open()) {
        asio::error_code ec;
        client_sock->shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        client_sock->close(ec);
    }

    if (data_sock && data_sock->is_open()) {
        asio::error_code ec;
        data_sock->shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        data_sock->close(ec);
    }

}

void GrayServer::remove_all_pairs() {
    std::vector<link_par> pairs_to_remove;

    {
        std::lock_guard<std::mutex> lock(link_pool_mutex);
        pairs_to_remove.swap(link_pool);
    }

    for (auto& pair : pairs_to_remove) {
        if (pair.client_socket && pair.client_socket->is_open()) {
            asio::error_code ec;
            pair.client_socket->shutdown(asio::ip::tcp::socket::shutdown_both, ec);
            pair.client_socket->close(ec);
        }

        if (pair.data_socket && pair.data_socket->is_open()) {
            asio::error_code ec;
            pair.data_socket->shutdown(asio::ip::tcp::socket::shutdown_both, ec);
            pair.data_socket->close(ec);
        }
    }
}

void GrayServer::send_control_packet(uint32_t type, uint32_t value, std::function<void(const asio::error_code&)> handler) {
    if (!alive || !control_socket || !control_socket->lowest_layer().is_open()) return;

    auto pkt = std::make_shared<Packet>();
    pkt->type = htonl(type);
    pkt->value = htonl(value);

    asio::async_write(*control_socket,
        asio::buffer(pkt.get(), sizeof(Packet)),
        [self = shared_from_this(), pkt, handler](const asio::error_code& ec, std::size_t) {
            if (ec) {
                self->shutdown();
            }
            if (handler) handler(ec);
        });
}
