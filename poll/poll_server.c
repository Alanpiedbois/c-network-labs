/*
 * poll_server - TCP echo server for many clients in a single thread.
 *
 * poll() watches the listening socket and every client socket at once,
 * and wakes the process only when one of them is ready. Each wake-up
 * does at most one accept() or one read() per ready socket, so no call
 * ever blocks and one silent client cannot stall the others.
 *
 * Usage: ./poll_server <port>
 */

#include <arpa/inet.h>   /* htons, htonl, ntohs, inet_ntop */
#include <errno.h>       /* errno, EINTR */
#include <netinet/in.h>  /* struct sockaddr_in, INADDR_ANY */
#include <poll.h>        /* poll, struct pollfd */
#include <signal.h>      /* signal, SIGPIPE */
#include <stdio.h>       /* printf, fprintf, perror */
#include <stdlib.h>      /* strtol, exit */
#include <string.h>      /* memset */
#include <sys/socket.h>  /* socket, setsockopt, bind, listen, accept */
#include <unistd.h>      /* read, write, close */

#define MAX_FDS     64    /* listening socket + up to 63 clients */
#define BACKLOG     5     /* pending connections queued by the kernel */
#define BUFFER_SIZE 1024

/* Parses a TCP port; returns -1 unless str is a number in 1..65535. */
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
 * Writes all len bytes. write() may send fewer bytes than asked
 * (partial write), so loop until everything is sent.
 * Returns 0 on success, -1 on error.
 *
 * Limitation: on a blocking socket this waits while the client's
 * receive buffer is full, which stalls every other client. The
 * libevent version fixes this with buffered, non-blocking writes.
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

/* Creates a TCP socket listening on all interfaces; exits on failure. */
static int create_server(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    /* Allow an immediate restart while the old port is in TIME_WAIT. */
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

/* Accepts one pending client and adds it to the watch list. */
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
    /* The slot may hold a stale revents from a removed client. */
    fds[*nfds].revents = 0;
    (*nfds)++;
}

/*
 * Closes the client in slot i and fills the hole with the last slot.
 * The caller must visit slot i again: it now holds another client.
 */
static void remove_client(struct pollfd *fds, int *nfds, int i)
{
    printf("client disconnected (fd %d)\n", fds[i].fd);
    close(fds[i].fd);
    fds[i] = fds[*nfds - 1];
    (*nfds)--;
}

/*
 * Serves one ready client with a single read, which cannot block.
 * Returns 0 if the client stays, -1 if it left or failed.
 */
static int serve_client(int fd)
{
    char buffer[BUFFER_SIZE];

    ssize_t n = read(fd, buffer, sizeof(buffer));
    if (n == -1) {
        perror("read");
        return -1;
    }
    if (n == 0)
        return -1;   /* orderly shutdown by the client */
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

    /* A client that vanishes mid-write must not kill the server. */
    signal(SIGPIPE, SIG_IGN);
    /* Flush logs line by line, even when redirected to a file. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    int server_fd = create_server(port);
    printf("listening on port %d\n", port);

    /* Slot 0 is always the listening socket; slots 1..nfds-1 are clients. */
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
            /* POLLHUP / POLLERR: hang-up or socket error, read() reports it. */
            if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR)))
                continue;
            if (serve_client(fds[i].fd) == -1) {
                remove_client(fds, &nfds, i);
                i--;   /* slot i now holds the former last client */
            }
        }
    }
}
