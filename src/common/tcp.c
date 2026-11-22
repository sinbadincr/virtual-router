#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "minivr/netio.h"

int parse_hostport(const char *s, char ip[16], uint16_t *port) {
    const char *colon = strrchr(s, ':');
    if (!colon || colon == s || colon - s > 15)
        return -1;
    memcpy(ip, s, (size_t)(colon - s));
    ip[colon - s] = 0;
    char *end;
    long p = strtol(colon + 1, &end, 10);
    struct in_addr a;
    if (*end || p < 1 || p > 65535 || inet_pton(AF_INET, ip, &a) != 1)
        return -1;
    *port = (uint16_t)p;
    return 0;
}

static int fill(struct sockaddr_in *sa, const char *ip, uint16_t port) {
    memset(sa, 0, sizeof *sa);
    sa->sin_family = AF_INET;
    sa->sin_port = htons(port);
    return inet_pton(AF_INET, ip, &sa->sin_addr) == 1 ? 0 : -1;
}

int tcp_listen(const char *ip, uint16_t port, int backlog) {
    struct sockaddr_in sa;
    if (fill(&sa, ip, port) != 0) {
        errno = EINVAL;
        return -1;
    }
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0 || listen(fd, backlog) < 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    return fd;
}

int tcp_connect(const char *bind_ip, const char *ip, uint16_t port, int *pending) {
    struct sockaddr_in sa, la;
    if (fill(&sa, ip, port) != 0 || (bind_ip && fill(&la, bind_ip, 0) != 0)) {
        errno = EINVAL;
        return -1;
    }
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    if (bind_ip && bind(fd, (struct sockaddr *)&la, sizeof la) < 0)
        goto err;
    *pending = 0;
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        if (errno != EINPROGRESS)
            goto err;
        *pending = 1;
    }
    return fd;
err : {
    int e = errno;
    close(fd);
    errno = e;
    return -1;
}
}

int tcp_connect_done(int fd) {
    int err = 0;
    socklen_t l = sizeof err;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &l) < 0)
        return errno;
    return err;
}

/* ---- protocol messages ---- */

int mc_init(struct msgconn *c, int fd, size_t tx_cap) {
    memset(c, 0, sizeof *c);
    c->fd = fd;
    c->tx = malloc(tx_cap);
    if (!c->tx)
        return -1;
    c->tx_cap = tx_cap;
    return 0;
}

void mc_close(struct msgconn *c) {
    if (c->fd >= 0)
        close(c->fd);
    c->fd = -1;
    free(c->tx);
    c->tx = NULL;
    c->rx_have = c->tx_len = c->tx_off = 0;
}

int mc_recv(struct msgconn *c, size_t *msg_len, enum proto_err *why) {
    for (;;) {
        if (c->rx_have >= PROTO_HDR) {
            uint8_t type;
            uint32_t len, seq;
            enum proto_err r = proto_hdr_check(c->rx, &type, &len, &seq);
            if (r != PE_OK) {
                *why = r;
                return MC_BAD_HEADER;
            }
            if (c->rx_have >= len) {
                *msg_len = len;
                return MC_MSG;
            }
        }
        size_t want = PROTO_HDR;
        if (c->rx_have >= PROTO_HDR) {
            uint32_t len = ((uint32_t)c->rx[4] << 24) | ((uint32_t)c->rx[5] << 16) |
                           ((uint32_t)c->rx[6] << 8) | c->rx[7];
            want = len;
        }
        ssize_t n = recv(c->fd, c->rx + c->rx_have, want - c->rx_have, MSG_DONTWAIT);
        if (n == 0) {
            if (c->rx_have > 0)
                *why = PE_TRUNCATED;
            return MC_EOF;
        }
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return MC_MORE;
            if (errno == EINTR)
                continue;
            return MC_IOERR;
        }
        c->rx_have += (size_t)n;
        c->bytes_in += (uint64_t)n;
    }
}

void mc_consume(struct msgconn *c, size_t msg_len) {
    if (msg_len >= c->rx_have) {
        c->rx_have = 0;
    } else {
        memmove(c->rx, c->rx + msg_len, c->rx_have - msg_len);
        c->rx_have -= msg_len;
    }
    c->msgs_in++;
}

int mc_flush(struct msgconn *c) {
    while (c->tx_off < c->tx_len) {
        ssize_t n = send(c->fd, c->tx + c->tx_off, c->tx_len - c->tx_off, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 0;
            if (errno == EINTR)
                continue;
            return -1;
        }
        c->tx_off += (size_t)n;
        c->bytes_out += (uint64_t)n;
    }
    c->tx_len = c->tx_off = 0;
    return 0;
}

int mc_pending(const struct msgconn *c) {
    return (int)(c->tx_len - c->tx_off);
}

int mc_send(struct msgconn *c, const uint8_t *msg, size_t len) {
    if (c->tx_off > 0 && c->tx_off == c->tx_len)
        c->tx_off = c->tx_len = 0;
    if (c->tx_len + len > c->tx_cap) {
        if (c->tx_off > 0) { /* compact before declaring the peer slow */
            memmove(c->tx, c->tx + c->tx_off, c->tx_len - c->tx_off);
            c->tx_len -= c->tx_off;
            c->tx_off = 0;
        }
        if (c->tx_len + len > c->tx_cap) {
            errno = ENOBUFS;
            return -1;
        }
    }
    memcpy(c->tx + c->tx_len, msg, len);
    c->tx_len += len;
    c->msgs_out++;
    return mc_flush(c);
}
