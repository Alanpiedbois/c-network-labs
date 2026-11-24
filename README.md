# C network labs

Network programming in C on Linux, built step by step: from a raw TCP
socket up to a filtering TCP proxy (a small application-level firewall).

| Lab | Topic | Status |
|---|---|---|
| [`echo/`](echo/) | TCP echo server, one client at a time (`socket`, `bind`, `listen`, `accept`) | done |
| [`poll/`](poll/) | Many clients in one thread with `poll()` (event loop, non-blocking by design) | done |
| [`libevent/`](libevent/) | Same server on libevent: callbacks, buffered non-blocking I/O, epoll/kqueue backends | done |
| [`proxy/`](proxy/) | Filtering TCP proxy: allow/deny rules on client IP (CIDR, first match wins, default deny), bidirectional relay, half-close, backpressure, connection logs | done |

## Build and run

Requires `gcc` and `make` on Linux, plus `libevent-dev` for the
libevent lab (`sudo apt install libevent-dev`).

```sh
cd echo
make
./echo_server 4242
```

In another terminal:

```sh
nc localhost 4242
```

Everything you type is sent back. Watch the TCP handshake, data and
teardown with:

```sh
sudo tcpdump -i lo -n port 4242
```

## Filtering proxy

```sh
(cd libevent && make && ./echo_server 5000) &        # backend
cd proxy && make && ./tcp_proxy 4400 127.0.0.1 5000 rules.conf
```

With the sample `rules.conf`:

```
deny  127.0.0.2
allow 127.0.0.0/8
```

`nc 127.0.0.1 4400` is relayed to the backend, while
`nc -s 127.0.0.2 127.0.0.1 4400` is refused. The proxy logs `ALLOW`,
`DENY`, `LINK` and `CLOSE` (with the bytes sent each way).
