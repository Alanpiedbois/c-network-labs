/*
 * echo_server - TCP echo server, one client at a time.
 *
 * Accepts a client, sends back every byte it receives until it
 * disconnects, then waits for the next one.
 *
 * Usage: ./echo_server <port>
 */

#include <arpa/inet.h>   /* htons, htonl, ntohs, inet_ntop */
#include <errno.h>       /* errno, EINTR */
#include <netinet/in.h>  /* struct sockaddr_in, INADDR_ANY */
#include <signal.h>      /* signal, SIGPIPE */
#include <stdio.h>       /* printf, fprintf, perror */
#include <stdlib.h>      /* strtol, exit */
#include <string.h>      /* memset */
#include <sys/socket.h>  /* socket, setsockopt, bind, listen, accept */
#include <unistd.h>      /* read, write, close */

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

/* Echoes everything the client sends until it disconnects or fails. */
static void handle_client(int client_fd)
{
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    while ((bytes_read = read(client_fd, buffer, sizeof(buffer))) > 0) {
        if (write_all(client_fd, buffer, (size_t)bytes_read) == -1) {
            perror("write");
            return;
        }
    }
    if (bytes_read == -1)
        perror("read");
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

    /*
     * Writing to a client that already closed raises SIGPIPE, which
     * kills the process by default. Ignore it: write() then fails
     * with EPIPE and only that client is dropped.
     */
    signal(SIGPIPE, SIG_IGN);

    /*
     * stdout is fully buffered when redirected to a file or a pipe:
     * logs would only appear once the buffer fills. Flush every line.
     */
    setvbuf(stdout, NULL, _IOLBF, 0);

    int server_fd = create_server(port);
    printf("listening on port %d\n", port);

    while (1) {
        struct sockaddr_in client;
        socklen_t len = sizeof(client);

        int client_fd = accept(server_fd, (struct sockaddr *)&client, &len);
        if (client_fd == -1) {
            perror("accept");
            continue;
        }

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client.sin_addr, ip, sizeof(ip));
        int client_port = ntohs(client.sin_port);

        printf("client connected: %s:%d\n", ip, client_port);
        handle_client(client_fd);
        close(client_fd);
        printf("client disconnected: %s:%d\n", ip, client_port);
    }
}
