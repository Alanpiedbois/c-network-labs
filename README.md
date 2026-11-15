# C network labs

Network programming in C on Linux, built step by step: from a raw TCP
socket up to a stateful packet filter.

| Lab | Topic | Status |
|---|---|---|
| [`echo/`](echo/) | TCP echo server, one client at a time (`socket`, `bind`, `listen`, `accept`) | done |
| `poll/` | Many clients in one thread with `poll()`, then with libevent | next |
| `ftp/` | FTP server (RFC 959 subset): control and data connections, PASV/PORT | planned |
| `teams/` | Chat server and client with a custom protocol and persistence | planned |
| `firewall/` | Stateful packet filter: header parsing, rules, connection tracking | planned |

## Build and run

Requires `gcc` and `make` on Linux.

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
