
Obelisk — TCP Proxy for NAT Servers

Obelisk is a high-performance multithreaded TCP proxy written in C++ using Asio standalone and TLS for secure control.

The program allows servers behind NAT to receive external IP addresses and ports for client connections.

Key Features

TCP Proxy through NAT

Servers behind NAT without public IPs initiate outgoing connections to Obelisk via the control port.

After authorization, each server receives ports for client connections.

All client connections arriving at these ports are forwarded to the server behind NAT.

TLS Control Port

Used for server authorization and communication about newly created sockets.

One control socket can serve multiple servers.

The control channel allows the server to notify about new data/client sockets.

Socket Pool

Each server maintains a pool of data and client sockets to handle multiple simultaneous connections.

At least one pair of sockets is required for one server behind NAT.

Multithreading

Uses asio::io_context and can run multiple threads equal to the number of CPU cores.

Reduces latency and improves performance when serving multiple servers and clients.

Security and Performance

TLS ensures a secure control channel.

Written in C++ for maximum control and high-speed network handling.

How It Works

Obelisk starts and listens on the control port (TLS).

A server behind NAT initiates an outgoing TLS connection to Obelisk.

The program validates the server ID and pool size.

A GrayServer instance is created with pools of client and data sockets.

Clients connect to the assigned Obelisk ports, and their data is forwarded to the NATed server.

The program periodically checks the socket pools to ensure availability.

On shutdown or /shutdown command, all sockets are safely closed.

Command-Line Management

/add — add a new server (ID + ports)

/show — list all registered servers

/delete — remove a server and free its ports

/shutdown — stop Obelisk

Dependencies

Asio standalone

OpenSSL (for TLS/SSL)

C++17 or later

Platform-dependent network libraries:

Windows: ws2_32.lib

Linux/macOS: -lssl -lcrypto -lpthread

Highlights

Supports multiple servers behind NAT simultaneously.

Efficient multithreaded connection handling.

Minimal latency with socket pools and asynchronous architecture.

Easy CLI management for servers and ports.
