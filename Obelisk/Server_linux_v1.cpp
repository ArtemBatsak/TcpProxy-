
// Server_linux_v1.cpp
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <memory>
#include <csignal>

// OpenSSL
#ifdef _WIN32
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#endif
// For Linux and macOS, link with -lssl -lcrypto

#include "Data.h"         
#include "Server_class.h" 

using asio::ip::tcp;

std::atomic<bool> running(true);

const int CONTROL_PORT = 44555;

struct Ports {
    uint32_t data_port;
    uint32_t client_port;
};

// Generate self-signed certificate and private key in PEM format
std::pair<std::string, std::string> generate_self_signed_cert_pem();
bool load_cert_and_key_into_context(asio::ssl::context& ctx, const std::string& cert_pem, const std::string& key_pem);

// Thread for command input
void command_thread(DataServers& data_servers, asio::io_context& io, ServerManager& server_manager);

// Start accepting control connections with TLS and handle them
void start_control_accept(
    asio::ssl::context& ssl_ctx,
    tcp::acceptor& acceptor,
    DataServers& data_servers,
    asio::io_context& io,
    std::shared_ptr<ServerManager> server_manager
); 

// Asynchronous authorization socket and create object GrayServer
void async_authorize(std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_sock, 
    DataServers& data_servers, 
    asio::io_context& io, 
    std::shared_ptr<ServerManager> server_manager);



int main() {
    try {
        std::cout << "Obelisk started\n";

        asio::io_context io;
        DataServers data_servers;
        auto server_manager = std::make_shared<ServerManager>();

        asio::signal_set signals(io, SIGINT, SIGTERM);
        signals.async_wait([&](const asio::error_code&, int) {
            std::cout << "\nShutdown signal received, stopping the Obelisk...\n";
            running = false;
            server_manager->shutdown_all();
            io.stop();
            });

        asio::ssl::context ssl_ctx(asio::ssl::context::tls_server);
        ssl_ctx.set_options(asio::ssl::context::default_workarounds
            | asio::ssl::context::no_sslv2
            | asio::ssl::context::no_sslv3
            | asio::ssl::context::single_dh_use);

       
        auto pem = generate_self_signed_cert_pem();
        if (!load_cert_and_key_into_context(ssl_ctx, pem.second, pem.first)) {
            std::cerr << "Failed to load certificate into SSL context\n";
            return 1;
        }
        std::cout << "Self-signed certificate generated (in memory)\n";


        tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), CONTROL_PORT));
        std::cout << "Server started on port " << CONTROL_PORT << " (TLS control)\n";

        start_control_accept(ssl_ctx, acceptor, data_servers, io, server_manager);

        int num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0) num_threads = 1;

        std::vector<std::thread> threads;
        threads.reserve(num_threads);
        for (int i = 0; i < num_threads; ++i)
            threads.emplace_back([&io]() { io.run(); });

        std::thread cmd_thread([&data_servers, &io, server_manager]() {

            command_thread(data_servers, io, *server_manager);
            });

        for (auto& t : threads) t.join();
        cmd_thread.join();

        std::cout << "Obelisk has stopped\n";
    }
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }
    return 0;
}




// ----------------------------------------------------------------------------
// Asynchronous accept on the TLS control port
// ----------------------------------------------------------------------------
void start_control_accept(asio::ssl::context& ssl_ctx,
    tcp::acceptor& acceptor,
    DataServers& data_servers,
    asio::io_context& io,
    std::shared_ptr<ServerManager> server_manager)
{
    auto ssl_sock = std::make_shared<asio::ssl::stream<tcp::socket>>(io, ssl_ctx);

    acceptor.async_accept(ssl_sock->lowest_layer(),
        [ssl_sock, &acceptor, &ssl_ctx, &data_servers, &io, server_manager](const asio::error_code& ec) mutable {
            if (!ec) {
                async_authorize(ssl_sock, data_servers, io, server_manager);
            }
            else {
                std::cerr << "Accept error: " << ec.message() << "\n";
            }

            if (running) {
                start_control_accept(ssl_ctx, acceptor, data_servers, io, server_manager);
            }
        });
}



// ----------------------------------------------------------------------------
// async_authorize: делает async_handshake, затем читает ровно 4 байта ID,
// если авторизован — создаёт GrayServer и передаёт управление ssl_sock ему.
// ВАЖНО: не закрываем ssl_sock — передаём его GrayServer'у.
// ----------------------------------------------------------------------------
void async_authorize(std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_sock,
    DataServers& data_servers,
    asio::io_context& io,
    std::shared_ptr<ServerManager> server_manager)
{
    auto self = ssl_sock;

    auto close_socket = [self](const std::string& msg) {
        std::cerr << msg << std::endl;
        asio::error_code ec;
        self->lowest_layer().shutdown(tcp::socket::shutdown_both, ec);
        self->lowest_layer().close(ec);
        };

    self->async_handshake(asio::ssl::stream_base::server,
        [self, &data_servers, &io, close_socket, server_manager](const asio::error_code& ec)
        {
            if (ec) {
                close_socket("Handshake failed: " + ec.message());
                return;
            }

            auto buf_id = std::make_shared<uint32_t>();
            asio::async_read(*self, asio::buffer(buf_id.get(), sizeof(uint32_t)),
                [self, buf_id, &data_servers, &io, close_socket, server_manager](const asio::error_code& ec, std::size_t)
                {
                    if (ec) {
                        close_socket("Failed to read ID: " + ec.message());
                        return;
                    }

                    uint32_t id = ntohl(*buf_id);

                    if (!data_servers.authorize_id(id)) {
                        close_socket("Unauthorized ID: " + std::to_string(id));
                        return;
                    }

                    auto ok = std::make_shared<uint32_t>(htonl(1));
                    asio::async_write(*self, asio::buffer(ok.get(), sizeof(uint32_t)),
                        [self, ok, &data_servers, &io, close_socket, server_manager, id](const asio::error_code& ec, std::size_t)
                        {
                            if (ec) {
                                close_socket("Failed to send OK after ID: " + ec.message());
                                return;
                            }

                            auto buf_pool = std::make_shared<uint32_t>();
                            asio::async_read(*self, asio::buffer(buf_pool.get(), sizeof(uint32_t)),
                                [self, buf_pool, &data_servers, &io, close_socket, server_manager, id](const asio::error_code& ec, std::size_t)
                                {
                                    if (ec) {
                                        close_socket("Failed to read pool size: " + ec.message());
                                        return;
                                    }

                                    uint32_t pool_size = ntohl(*buf_pool);
                                    std::cout << "ID " << id << " pool size = " << pool_size << "\n";

                                    Ports ports;
                                    try {
                                        auto p = data_servers.get_ports_by_id(id);
                                        ports.data_port = p[0];
                                        ports.client_port = p[1];

                                        auto server = std::make_shared<GrayServer>(
                                            id,
                                            self,
                                            io,
                                            ports.client_port,
                                            ports.data_port,
                                            pool_size,
                                            server_manager
                                        );

										// TODO: обработка исключений внутри GrayServer
                                        auto buf_resp = std::make_shared<std::array<uint32_t, 3>>();
                                        (*buf_resp)[0] = htonl(1);
                                        (*buf_resp)[1] = htonl(ports.data_port);
                                        (*buf_resp)[2] = htonl(ports.client_port);

                                        asio::async_write(*self, asio::buffer(*buf_resp),
                                            [self, buf_resp](const asio::error_code& ec, std::size_t)
                                            {
                                                if (ec) {
                                                    std::cerr << "Failed to send OK+ports: " << ec.message() << "\n";
                                                }
                                            });
                                        server_manager->add(server);
										server->start();
                                    }
                                    catch (const std::exception& e) {
                                        close_socket("Failed to create GrayServer: " + std::string(e.what()));
                                        return;
                                    }

                                    
                                });
                        });
                });
        });
}


// ----------------------------------------------------------------------------
// Simple command thread
// ----------------------------------------------------------------------------
void command_thread(DataServers& data_servers, asio::io_context& io, ServerManager& server_manager) {
    while (running) {

        std::cout << "> ";
        std::string cmd;
        std::getline(std::cin, cmd);
        if (!running) break;

        // ---- /add ----
        if (cmd == "/add") {
            data_servers.add_id();
        }

        // ---- /show ----
        else if (cmd == "/show") {
            data_servers.show_id();
        }

        // ---- /delete ----
        else if (cmd == "/delete") {
            try {
                data_servers.delete_id();
            }
            catch (const std::exception& e) {
                std::cerr << "Delete error: " << e.what() << "\n";
            }
        }
		else if (cmd == "/shutdown") {
			std::cout << "Shutting down Obelisk...\n";
			running = false;
            server_manager.shutdown_all();
            io.stop();
		    }
            // ---- unknown command ----
        else {
            std::cout << "Unknown command\n";
        }

    }
}


std::pair<std::string, std::string> generate_self_signed_cert_pem()
{
    EVP_PKEY* pkey = nullptr;
    X509* x509 = nullptr;
    BIGNUM* bn = nullptr;

    std::string priv_pem, cert_pem;

    do {
        bn = BN_new();
        if (!bn) break;
        if (!BN_set_word(bn, RSA_F4)) break;

        RSA* rsa = RSA_new();
        if (!rsa) break;
        if (!RSA_generate_key_ex(rsa, 2048, bn, nullptr)) { RSA_free(rsa); break; }

        pkey = EVP_PKEY_new();
        if (!pkey) { RSA_free(rsa); break; }
        if (!EVP_PKEY_assign_RSA(pkey, rsa)) { RSA_free(rsa); EVP_PKEY_free(pkey); pkey = nullptr; break; }

        x509 = X509_new();
        if (!x509) break;

        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
        X509_set_pubkey(x509, pkey);

        X509_NAME* name = X509_get_subject_name(x509);
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"RU", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"GrayCompany", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"grayserver.local", -1, -1, 0);

        X509_set_issuer_name(x509, name);

        if (!X509_sign(x509, pkey, EVP_sha256())) break;

        BIO* bio_priv = BIO_new(BIO_s_mem());
        BIO* bio_cert = BIO_new(BIO_s_mem());
        if (!bio_priv || !bio_cert) { BIO_free(bio_priv); BIO_free(bio_cert); break; }

        if (!PEM_write_bio_PrivateKey(bio_priv, pkey, nullptr, nullptr, 0, nullptr, nullptr)) { BIO_free(bio_priv); BIO_free(bio_cert); break; }
        if (!PEM_write_bio_X509(bio_cert, x509)) { BIO_free(bio_priv); BIO_free(bio_cert); break; }

        // extract as std::string
        char* data_ptr = nullptr;
        long len = BIO_get_mem_data(bio_priv, &data_ptr);
        if (len > 0) priv_pem.assign(data_ptr, static_cast<size_t>(len));

        len = BIO_get_mem_data(bio_cert, &data_ptr);
        if (len > 0) cert_pem.assign(data_ptr, static_cast<size_t>(len));

        BIO_free(bio_priv);
        BIO_free(bio_cert);

    } while (false);

    if (x509) X509_free(x509);
    if (pkey) EVP_PKEY_free(pkey);
    if (bn) BN_free(bn);

    return { priv_pem, cert_pem };
}

bool load_cert_and_key_into_context(asio::ssl::context& ctx,
    const std::string& cert_pem,
    const std::string& key_pem)
{
    SSL_CTX* ssl_ctx = ctx.native_handle();
    if (!ssl_ctx) return false;

    BIO* bio_cert = BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size()));
    BIO* bio_key = BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size()));

    if (!bio_cert || !bio_key) return false;

    X509* x509 = PEM_read_bio_X509(bio_cert, nullptr, nullptr, nullptr);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio_key, nullptr, nullptr, nullptr);

    BIO_free(bio_cert);
    BIO_free(bio_key);

    if (!x509 || !pkey) {
        if (x509) X509_free(x509);
        if (pkey) EVP_PKEY_free(pkey);
        return false;
    }

    bool ok = SSL_CTX_use_certificate(ssl_ctx, x509) == 1 &&
        SSL_CTX_use_PrivateKey(ssl_ctx, pkey) == 1 &&
        SSL_CTX_check_private_key(ssl_ctx) == 1;

    X509_free(x509);
    EVP_PKEY_free(pkey);

    return ok;
}

