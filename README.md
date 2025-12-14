Secure TCP Proxy (White / Gray Server Architecture)
Overview

This project implements a high-performance TCP proxy designed for scenarios where backend servers are located behind NAT or private networks (“gray servers”), while traffic is accepted on a public-facing server (“white server”).

The system separates control traffic and data traffic to achieve both security and low latency.

Architecture

The solution consists of two main components:

White Server (Public IP)

Runs on a server with a public IP address

Accepts client connections from the Internet

Maintains a registry of authorized gray servers

Acts as a proxy, forwarding client traffic to the appropriate gray server

Responsibilities:

Accepts secure control connections from gray servers

Verifies gray server IDs against an internal table

Uses one shared TLS control port for all gray servers

Assigns a dedicated pair of TCP ports for data forwarding

Handles each client using an independent socket

Gray Server (Behind NAT)

Runs behind NAT or in a private network

Initiates a secure outbound connection to the white server

Does not require a public IP address

Responsibilities:

Establishes a secure SSL/TCP control connection

Maintains a pool of pre-initialized data connections

Forwards client traffic between local services and the white server

Security Model

The control channel is protected using TLS (OpenSSL) with self-signed certificates generated in memory

Certificates are not stored on disk

All sensitive operations (authorization, commands, port assignment) occur over the secure control socket

Data connections are intentionally unencrypted (raw TCP) to minimize overhead and latency.
Many target applications already implement their own security mechanisms, and additional encryption at the proxy layer would increase latency without clear benefits.

Connection Model

One TLS control socket per gray server

One pair of TCP sockets per data channel:

White → Client (incoming client traffic)

Gray → White (outgoing traffic)

Each client is handled via a dedicated socket

No shared or broadcast sockets are used

This guarantees:

Full isolation between clients

Stable parallel processing

Predictable performance under load

Connection Pool

The gray server maintains a pre-initialized pool of data connections.

This allows:

Fast client connection handling

No TCP handshake delays at client connect time

Reduced latency during high traffic bursts

Implementation Details

Language: C++

Networking: ASIO (asynchronous I/O)

Security: OpenSSL

Fully asynchronous, non-blocking design

Multi-threaded execution using asio::io_context

Designed for low latency and high throughput

Control Commands (White Server)

The white server provides a simple CLI interface:

/add
  Adds a new gray server entry and allocates ports.

/show
  Displays all registered gray servers and assigned ports.

/delete
  Removes a gray server entry and releases its resources.

Typical Workflow

Gray server establishes a TLS control connection to the white server

White server validates the gray server ID

Ports for data forwarding are assigned

Gray server initializes its data connection pool

Clients connect to the white server public port

Traffic is proxied bidirectionally between client and gray server

Use Cases

Exposing private services to the Internet

NAT traversal without port forwarding

Low-latency TCP proxying

Centralized access point for multiple backend servers
