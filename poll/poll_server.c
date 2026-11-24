/*
 * TCP echo server, many clients in one thread with poll().
 * Usage: ./poll_server <port>
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_FDS     64    /* listening socket + 63 clients */
#define BACKLOG     5
#define BUFFER_SIZE 1024

static int parse_port(const char *str)
{
    char *end;
    long port;

    errno = 0;
    port = strtol(str, &end, 10);
    if (errno != 0 || end == str || *end != '\0' || port < 1 || port > 65535)
        return -1;
    return (int)port;
}

/*
 * Known limitation: the socket is blocking, so a client that stops
 * reading stalls everyone here. The libevent version fixes it.
 */
static int write_all(int fd, const char *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, buf, len);

        if (n == -1) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

static int create_server(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        exit(EXIT_FAILURE);
    }
    if (listen(fd, BACKLOG) == -1) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    return fd;
}

static void accept_client(int server_fd, struct pollfd *fds, int *nfds)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    int client_fd = accept(server_fd, (struct sockaddr *)&addr, &len);
    if (client_fd == -1) {
        perror("accept");
        return;
    }
    if (*nfds >= MAX_FDS) {
        fprintf(stderr, "too many clients, rejecting fd %d\n", client_fd);
        close(client_fd);
        return;
    }

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
    printf("client connected: %s:%d (fd %d)\n", ip, ntohs(addr.sin_port), client_fd);

    fds[*nfds].fd = client_fd;
    fds[*nfds].events = POLLIN;
    fds[*nfds].revents = 0;   /* slot may hold a removed client's revents */
    (*nfds)++;
}

/* Moves the last slot into i: the caller must look at slot i again. */
static void remove_client(struct pollfd *fds, int *nfds, int i)
{
    printf("client disconnected (fd %d)\n", fds[i].fd);
    close(fds[i].fd);
    fds[i] = fds[*nfds - 1];
    (*nfds)--;
}

/* Returns -1 when the client is gone. */
static int serve_client(int fd)
{
    char buffer[BUFFER_SIZE];

    ssize_t n = read(fd, buffer, sizeof(buffer));
    if (n == -1) {
        perror("read");
        return -1;
    }
    if (n == 0)
        return -1;
    if (write_all(fd, buffer, (size_t)n) == -1) {
        perror("write");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    int port = parse_port(argv[1]);
    if (port == -1) {
        fprintf(stderr, "invalid port: %s (expected 1-65535)\n", argv[1]);
        return EXIT_FAILURE;
    }

    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);

    int server_fd = create_server(port);
    printf("listening on port %d\n", port);

    /* slot 0 is the listening socket, the rest are clients */
    struct pollfd fds[MAX_FDS];
    int nfds = 1;
    fds[0].fd = server_fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    while (1) {
        if (poll(fds, nfds, -1) == -1) {
            if (errno == EINTR)
                continue;
            perror("poll");
            exit(EXIT_FAILURE);
        }

        if (fds[0].revents & POLLIN)
            accept_client(server_fd, fds, &nfds);

        for (int i = 1; i < nfds; i++) {
            if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR)))
                continue;
            if (serve_client(fds[i].fd) == -1) {
                remove_client(fds, &nfds, i);
                i--;
            }
        }
    }
}
