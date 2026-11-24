/*
 * tcp_proxy - a tiny application-level firewall built on libevent.
 *
 * Accepts TCP clients on a local port and checks each client IP
 * against an ordered rule list (first match wins, default deny).
 * Allowed clients are relayed to a fixed backend in both directions:
 *
 *     client <--> [ tcp_proxy: rules + logs ] <--> backend
 *
 * Every connection is logged: ALLOW / DENY, then CLOSE with the
 * number of bytes sent each way.
 *
 * Usage: ./tcp_proxy <listen_port> <backend_ip> <backend_port> <rules_file>
 */

#include <arpa/inet.h>           /* inet_ntop, inet_pton, ntohl, htons */
#include <errno.h>               /* errno */
#include <netinet/in.h>          /* struct sockaddr_in */
#include <signal.h>              /* signal, SIGPIPE */
#include <stdint.h>              /* uint32_t */
#include <stdio.h>               /* printf, fprintf, fopen, fgets */
#include <stdlib.h>              /* strtol, calloc, free */
#include <string.h>              /* strcmp, strchr, strcspn */
#include <sys/socket.h>          /* shutdown */

#include <event2/buffer.h>       /* evbuffer_* */
#include <event2/bufferevent.h>  /* bufferevent_* */
#include <event2/event.h>        /* event_base_* */
#include <event2/listener.h>     /* evconnlistener_* */

#define BACKLOG     16
#define MAX_RULES   64
#define MAX_PENDING (256 * 1024) /* bytes queued toward one side before we pause the other */

/* One line of the rules file, e.g. "allow 192.168.1.0/24". */
struct rule {
    int      allow;   /* 1 = allow, 0 = deny */
    uint32_t net;     /* network address, host byte order */
    uint32_t mask;    /* netmask, host byte order (/24 = 0xFFFFFF00) */
};

/* Global proxy settings, passed to accept_cb as ctx. */
struct proxy {
    struct rule        rules[MAX_RULES];
    int                nrules;
    struct sockaddr_in backend_addr;
};

/* One relayed connection: two sockets glued together. */
struct conn {
    struct bufferevent *client;
    struct bufferevent *backend;
    char                peer[32];  /* "ip:port" of the client, for logs */
    size_t              up;        /* bytes client -> backend */
    size_t              down;      /* bytes backend -> client */
    int                 client_eof;   /* client sent FIN: nothing more to read from it */
    int                 backend_eof;
    int                 client_fin;   /* we sent FIN to the client */
    int                 backend_fin;
};

static void read_cb(struct bufferevent *bev, void *ctx);
static void write_cb(struct bufferevent *bev, void *ctx);
static void event_cb(struct bufferevent *bev, short events, void *ctx);

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

/* Parses "allow|deny <ip>[/<prefix>]" or "allow|deny any". Returns 0 or -1. */
static int parse_rule(const char *line, struct rule *r)
{
    char action[8];
    char target[32];
    int prefix = 32;

    if (sscanf(line, "%7s %31s", action, target) != 2)
        return -1;

    if (strcmp(action, "allow") == 0)
        r->allow = 1;
    else if (strcmp(action, "deny") == 0)
        r->allow = 0;
    else
        return -1;

    if (strcmp(target, "any") == 0) {
        r->net = 0;
        r->mask = 0;   /* mask 0: every IP matches */
        return 0;
    }

    char *slash = strchr(target, '/');
    if (slash != NULL) {
        char *end;
        long p = strtol(slash + 1, &end, 10);
        if (end == slash + 1 || *end != '\0' || p < 0 || p > 32)
            return -1;
        prefix = (int)p;
        *slash = '\0';   /* cut "10.0.0.0/8" into "10.0.0.0" */
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, target, &addr) != 1)
        return -1;

    /* Shifting a 32-bit value by 32 is undefined in C, so /0 is special. */
    r->mask = prefix == 0 ? 0 : 0xFFFFFFFFu << (32 - prefix);
    r->net = ntohl(addr.s_addr) & r->mask;
    return 0;
}

/* Loads the rules file; '#' starts a comment, blank lines are skipped. */
static int load_rules(const char *path, struct proxy *p)
{
    FILE *f = fopen(path, "r");
    char line[128];
    int lineno = 0;

    if (f == NULL) {
        perror(path);
        return -1;
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        char probe;

        lineno++;
        line[strcspn(line, "#\n")] = '\0';
        if (sscanf(line, " %c", &probe) != 1)
            continue;   /* blank or comment-only line */
        if (p->nrules == MAX_RULES) {
            fprintf(stderr, "%s:%d: too many rules (max %d)\n", path, lineno, MAX_RULES);
            fclose(f);
            return -1;
        }
        if (parse_rule(line, &p->rules[p->nrules]) < 0) {
            fprintf(stderr, "%s:%d: invalid rule\n", path, lineno);
            fclose(f);
            return -1;
        }
        p->nrules++;
    }
    fclose(f);
    return 0;
}

/* First matching rule decides; no match means deny. ip is in host byte order. */
static int is_allowed(const struct proxy *p, uint32_t ip)
{
    for (int i = 0; i < p->nrules; i++) {
        if ((ip & p->rules[i].mask) == p->rules[i].net)
            return p->rules[i].allow;
    }
    return 0;
}

/* The other end of the pipe. */
static struct bufferevent *partner(struct conn *c, struct bufferevent *bev)
{
    return bev == c->client ? c->backend : c->client;
}

static int *eof_flag(struct conn *c, struct bufferevent *bev)
{
    return bev == c->client ? &c->client_eof : &c->backend_eof;
}

static int *fin_flag(struct conn *c, struct bufferevent *bev)
{
    return bev == c->client ? &c->client_fin : &c->backend_fin;
}

static void conn_free(struct conn *c)
{
    printf("CLOSE %s (up %zu B, down %zu B)\n", c->peer, c->up, c->down);
    bufferevent_free(c->client);    /* closes the sockets (BEV_OPT_CLOSE_ON_FREE) */
    bufferevent_free(c->backend);
    free(c);
}

/*
 * Moves everything src received into its partner's output buffer.
 * If the partner cannot keep up (slow reader), stop reading src until
 * the partner's backlog drops: memory stays bounded at ~MAX_PENDING.
 */
static void relay(struct conn *c, struct bufferevent *src)
{
    struct bufferevent *dst = partner(c, src);
    struct evbuffer *in = bufferevent_get_input(src);
    struct evbuffer *out = bufferevent_get_output(dst);
    size_t n = evbuffer_get_length(in);

    if (src == c->client)
        c->up += n;
    else
        c->down += n;
    evbuffer_add_buffer(out, in);

    if (!*eof_flag(c, src) && evbuffer_get_length(out) >= MAX_PENDING) {
        bufferevent_disable(src, EV_READ);
        /* write_cb fires once dst's output falls to MAX_PENDING / 2 */
        bufferevent_setwatermark(dst, EV_WRITE, MAX_PENDING / 2, 0);
        bufferevent_setcb(dst, read_cb, write_cb, event_cb, c);
    }
}

static void read_cb(struct bufferevent *bev, void *ctx)
{
    relay(ctx, bev);
}

/*
 * The source side of dst sent FIN. Once dst's output buffer is empty,
 * pass the FIN on with shutdown(SHUT_WR): "no more data, but I still
 * listen". The other direction keeps flowing (TCP half-close).
 * When both directions are finished, the connection is closed.
 */
static void finish_direction(struct conn *c, struct bufferevent *dst)
{
    if (*fin_flag(c, dst))
        return;
    if (evbuffer_get_length(bufferevent_get_output(dst)) > 0) {
        /* still sending: write_cb calls us again once the buffer is empty */
        bufferevent_setwatermark(dst, EV_WRITE, 0, 0);
        bufferevent_setcb(dst, read_cb, write_cb, event_cb, c);
        return;
    }
    shutdown(bufferevent_getfd(dst), SHUT_WR);
    *fin_flag(c, dst) = 1;
    bufferevent_setcb(dst, read_cb, NULL, event_cb, c);
    if (c->client_fin && c->backend_fin)
        conn_free(c);
}

/*
 * bev's output buffer drained down to its low watermark.
 * Source finished: the buffer is now empty, pass the FIN on.
 * Otherwise: the backlog went down, resume reading the source.
 */
static void write_cb(struct bufferevent *bev, void *ctx)
{
    struct conn *c = ctx;
    struct bufferevent *src = partner(c, bev);

    if (*eof_flag(c, src)) {
        finish_direction(c, bev);
        return;
    }
    bufferevent_setcb(bev, read_cb, NULL, event_cb, c);
    bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
    bufferevent_enable(src, EV_READ);
}

/* Backend connected, or one side sent FIN, or a socket failed. */
static void event_cb(struct bufferevent *bev, short events, void *ctx)
{
    struct conn *c = ctx;

    if (events & BEV_EVENT_CONNECTED) {
        printf("LINK  %s <-> backend\n", c->peer);
        return;
    }
    if (events & BEV_EVENT_ERROR) {
        /* refused, reset (RST)...: the pipe is broken, drop everything */
        int err = EVUTIL_SOCKET_ERROR();
        fprintf(stderr, "ERROR %s (%s side): %s\n", c->peer,
                bev == c->client ? "client" : "backend",
                evutil_socket_error_to_string(err));
        conn_free(c);
        return;
    }
    if (events & BEV_EVENT_EOF) {
        /* bev sent FIN: forward its last bytes, then the FIN itself */
        *eof_flag(c, bev) = 1;
        relay(c, bev);
        bufferevent_disable(bev, EV_READ);
        finish_direction(c, partner(c, bev));
    }
}

/* A client connected: apply the rules, then open the backend side. */
static void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
                      struct sockaddr *addr, int socklen, void *ctx)
{
    (void)socklen;
    struct proxy *p = ctx;
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    char ip[INET_ADDRSTRLEN];
    char peer[32];

    inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
    snprintf(peer, sizeof(peer), "%s:%d", ip, ntohs(sin->sin_port));

    if (!is_allowed(p, ntohl(sin->sin_addr.s_addr))) {
        printf("DENY  %s\n", peer);
        evutil_closesocket(fd);
        return;
    }

    struct event_base *base = evconnlistener_get_base(listener);
    struct conn *c = calloc(1, sizeof(*c));
    if (c == NULL) {
        evutil_closesocket(fd);
        return;
    }
    memcpy(c->peer, peer, sizeof(peer));
    c->client = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    c->backend = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    if (c->client == NULL || c->backend == NULL) {
        fprintf(stderr, "bufferevent_socket_new failed\n");
        if (c->client != NULL)
            bufferevent_free(c->client);
        else
            evutil_closesocket(fd);
        if (c->backend != NULL)
            bufferevent_free(c->backend);
        free(c);
        return;
    }

    printf("ALLOW %s\n", c->peer);
    bufferevent_setcb(c->client, read_cb, NULL, event_cb, c);
    bufferevent_setcb(c->backend, read_cb, NULL, event_cb, c);

    /* Non-blocking connect: BEV_EVENT_CONNECTED or BEV_EVENT_ERROR comes later.
     * Data the client sends meanwhile waits in the backend's output buffer. */
    if (bufferevent_socket_connect(c->backend, (struct sockaddr *)&p->backend_addr,
                                   sizeof(p->backend_addr)) < 0) {
        fprintf(stderr, "ERROR %s: cannot start backend connection\n", c->peer);
        conn_free(c);
        return;
    }
    bufferevent_enable(c->client, EV_READ | EV_WRITE);
    bufferevent_enable(c->backend, EV_READ | EV_WRITE);
}

int main(int argc, char **argv)
{
    static struct proxy p;   /* static: zeroed, and kept off the stack */

    if (argc != 5) {
        fprintf(stderr, "usage: %s <listen_port> <backend_ip> <backend_port> <rules_file>\n",
                argv[0]);
        return 1;
    }

    int listen_port = parse_port(argv[1]);
    int backend_port = parse_port(argv[3]);
    if (listen_port < 0 || backend_port < 0) {
        fprintf(stderr, "invalid port\n");
        return 1;
    }
    p.backend_addr.sin_family = AF_INET;
    p.backend_addr.sin_port = htons(backend_port);
    if (inet_pton(AF_INET, argv[2], &p.backend_addr.sin_addr) != 1) {
        fprintf(stderr, "invalid backend ip: %s\n", argv[2]);
        return 1;
    }
    if (load_rules(argv[4], &p) < 0)
        return 1;

    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);

    struct event_base *base = event_base_new();
    if (base == NULL) {
        fprintf(stderr, "event_base_new failed\n");
        return 1;
    }

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(listen_port);

    struct evconnlistener *listener = evconnlistener_new_bind(
        base, accept_cb, &p, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
        BACKLOG, (struct sockaddr *)&sin, sizeof(sin));
    if (listener == NULL) {
        perror("evconnlistener_new_bind");
        event_base_free(base);
        return 1;
    }

    printf("listening on port %d, backend %s:%d, %d rule(s)\n",
           listen_port, argv[2], backend_port, p.nrules);
    event_base_dispatch(base);

    evconnlistener_free(listener);
    event_base_free(base);
    return 0;
}
