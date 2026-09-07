# Day 4: Socket Programming Architecture

## 1. The Socket Abstraction
A network socket is an OS kernel communication abstraction defined by a 5-tuple:
`Protocol, Source IP, Source Port, Destination IP, Destination Port`

## 2. Lifecycle States
- **Server:** `socket()` -> `bind()` -> `listen()` -> `accept()` -> `recv()/send()` -> `close()`
- **Client:** `socket()` -> `connect()` -> `send()/recv()` -> `close()`