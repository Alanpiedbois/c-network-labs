/*
 * TCP echo server, one client at a time.
 * Usage: ./echo_server <port>
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

/* write() can send less than asked: loop until everything is out. */
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

    /* restart without waiting for TIME_WAIT to expire */
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

    /* writing to a closed client must fail with EPIPE, not kill us */
    signal(SIGPIPE, SIG_IGN);
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
