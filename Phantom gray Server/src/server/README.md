
Overview

This module implements the data-channel client logic.
It establishes a TCP connection to a remote data server using a one-time password (OTP), then transparently forwards traffic between the remote data socket and a local client socket.

The class acts as a bidirectional TCP proxy, managing multiple concurrent socket pairs asynchronously.

Key Responsibilities

Connect to the data server using an OTP

Accept incoming data and forward it to a local service

Create and manage paired socket connections

Asynchronous, full-duplex traffic forwarding (splice)

Safe cleanup of connections on errors or disconnects

Architecture

Each connection is represented as a socket pair:

Data socket ↔ Local client socket

Traffic is forwarded in both directions using asynchronous read/write loops

Active connections are tracked in a thread-safe pool with unique pair IDs
