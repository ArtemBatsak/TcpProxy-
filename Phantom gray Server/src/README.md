README
Overview

This project is an asynchronous TLS client written in C++ using Asio.
The client connects to a control server over a secure TLS channel, authenticates using a client ID, negotiates pool parameters and ports, and then listens for control commands such as connection requests and keepalive messages.

The code is designed to be part of a larger client–server architecture where a central control server manages client connections.

Features

TLS-secured control connection

Fully asynchronous, non-blocking I/O

Client authentication via ID

Pool size and port negotiation

Control command handling:

CONNECT — connect to the data server using a one-time password (OTP)

PING / PONG — keepalive and liveness checks

Dependencies

C++17 or newer

Asio (standalone or Boost.Asio)

OpenSSL

Configuration

Before building, configure the following parameters:

string SERVER_IP;
string LOCAL_IP;
uint16_t CONTROL_PORT;
uint16_t LOCAL_PORT;
uint32_t ID_CLIENT;
uint32_t POOL_SIZE;

Build

Example build command on Linux:

g++ -std=c++17 main.cpp -lssl -lcrypto -pthread

Notes

TLS certificate verification is disabled (verify_none); this is not recommended for production use.

Data-channel logic is encapsulated in the Client class (server_class.h).

The architecture is optimized for scalability through asynchronous networking.
