/*
 * Same echo server as poll/, on libevent (epoll / kqueue).
 * Usage: ./echo_server <port>
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>

#define BACKLOG 5

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

static void event_cb(struct bufferevent *bev, short events, void *ctx)
{
    (void)ctx;

    if (!(events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)))
        return;

    evutil_socket_t fd = bufferevent_getfd(bev);
    if (events & BEV_EVENT_ERROR) {
        int err = EVUTIL_SOCKET_ERROR();
        fprintf(stderr, "client error (fd %d): %s\n",
                (int)fd, evutil_socket_error_to_string(err));
    }
    printf("client disconnected (fd %d)\n", (int)fd);
    bufferevent_free(bev);
}

static void read_cb(struct bufferevent *bev, void *ctx)
{
    (void)ctx;

    struct evbuffer *input = bufferevent_get_input(bev);
    struct evbuffer *output = bufferevent_get_output(bev);
    evbuffer_add_buffer(output, input);
}

static void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
                      struct sockaddr *addr, int socklen, void *ctx)
{
    (void)socklen;
    (void)ctx;

    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
    printf("client connected: %s:%d (fd %d)\n", ip, ntohs(sin->sin_port), (int)fd);

    struct bufferevent *bev = bufferevent_socket_new(
        evconnlistener_get_base(listener), fd, BEV_OPT_CLOSE_ON_FREE);
    if (bev == NULL) {
        fprintf(stderr, "bufferevent_socket_new failed\n");
        close(fd);
        return;
    }

    bufferevent_setcb(bev, read_cb, NULL, event_cb, NULL);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
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

    signal(SIGPIPE, SIG_IGN);   /* libevent does not do it for us */
    setvbuf(stdout, NULL, _IOLBF, 0);

    struct event_base *base = event_base_new();
    if (base == NULL) {
        fprintf(stderr, "event_base_new failed\n");
        return EXIT_FAILURE;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    struct evconnlistener *listener = evconnlistener_new_bind(
        base, accept_cb, NULL,
        LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, BACKLOG,
        (struct sockaddr *)&addr, sizeof(addr));
    if (listener == NULL) {
        perror("evconnlistener_new_bind");
        event_base_free(base);
        return EXIT_FAILURE;
    }

    printf("listening on port %d (backend: %s)\n", port, event_base_get_method(base));
    event_base_dispatch(base);

    evconnlistener_free(listener);
    event_base_free(base);
    return EXIT_SUCCESS;
}
