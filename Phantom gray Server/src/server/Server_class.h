#pragma once

#include <asio.hpp>
#include <array>
#include <vector>
#include <memory>
#include <mutex>
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <string>

using asio::ip::tcp;

struct link_par {
    std::shared_ptr<tcp::socket> data_socket;
    std::shared_ptr<tcp::socket> client_socket;
    uint64_t pair_id;
};

class Client : public std::enable_shared_from_this<Client> {
public:
    Client(const std::string& server_ip,
        const std::string& local_ip,
        uint16_t local_port,
        uint16_t data_port,
        asio::io_context& io);

    void connectToServer(uint32_t otp);

    void remove_pair(uint64_t pair_id);
    void remove_all_pairs();

private:
    void splice_loop(std::shared_ptr<tcp::socket> in_sock,
        std::shared_ptr<tcp::socket> out_sock,
        uint64_t pair_id);

    void start_splice(const link_par& pair);
    uint64_t make_pair_id();

private:
    std::string server_ip_;
    std::string local_ip_;
    uint16_t local_port_;
    uint16_t data_port_;
    asio::io_context& io_;

    std::vector<link_par> link_pool_;
    std::mutex link_pool_mutex_;
    std::atomic<uint64_t> next_pair_id_;
};
