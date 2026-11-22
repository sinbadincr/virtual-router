#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "../daemon/evloop.h"
#include "minivr/clock.h"
#include "minivr/frame.h"
#include "minivr/log.h"
#include "minivr/netio.h"

int unix_listen(const char *path) {
    struct sockaddr_un addr;
    if (strlen(path) >= sizeof addr.sun_path) {
        errno = ENAMETOOLONG;
        return -1;
    }
    char dir[sizeof addr.sun_path];
    strcpy(dir, path);
    char *slash = strrchr(dir, '/');
    if (slash && slash != dir) {
        *slash = 0;
        if (mkdir(dir, 0700) < 0 && errno != EEXIST)
            return -1;
    }
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);
    struct stat st;
    if (lstat(path, &st) == 0) {
        int probe = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        int rc = connect(probe, (struct sockaddr *)&addr, sizeof addr);
        int e = errno;
        close(probe);
        if (rc == 0) {
            errno = EADDRINUSE;
            return -1;
        }
        if (e != ECONNREFUSED || !S_ISSOCK(st.st_mode)) {
            errno = e ? e : EEXIST;
            return -1;
        }
        unlink(path);
    }
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    mode_t old = umask(077);
    int rc = bind(fd, (struct sockaddr *)&addr, sizeof addr);
    umask(old);
    if (rc < 0 || chmod(path, 0600) < 0 || listen(fd, 16) < 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    return fd;
}

int unix_connect(const char *path) {
    struct sockaddr_un addr;
    if (strlen(path) >= sizeof addr.sun_path) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    return fd;
}

/* ---- text-command server (same framing and peer check as minivrd's control socket) ---- */

#define USRV_MAX_CLIENTS 8
#define USRV_IDLE_NS (5 * NS_PER_SEC)

struct uclient {
    struct evsrc src;
    int in_use;
    uint64_t last_ns;
    struct frame_rx rx;
    uint8_t tx[FRAME_HDR + FRAME_MAX];
    size_t tx_len, tx_off;
};

static struct evsrc listener = {.fd = -1};
static struct uclient clients[USRV_MAX_CLIENTS];
static uid_t allowed;
static usrv_handler handler;
static void *handler_arg;
static char resp[FRAME_MAX];

static void uclose(struct uclient *c) {
    if (!c->in_use)
        return;
    ev_del(&c->src);
    close(c->src.fd);
    c->in_use = 0;
}

static int uflush(struct uclient *c) {
    while (c->tx_off < c->tx_len) {
        ssize_t n = send(c->src.fd, c->tx + c->tx_off, c->tx_len - c->tx_off, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EAGAIN) {
                ev_mod(&c->src, EPOLLIN | EPOLLOUT);
                return 0;
            }
            return -1;
        }
        c->tx_off += (size_t)n;
    }
    c->tx_len = c->tx_off = 0;
    ev_mod(&c->src, EPOLLIN);
    return 0;
}

static void write_err(struct jw *w, const char *code, const char *msg) {
    jw_reset(w);
    jw_obj_begin(w, NULL);
    jw_bool(w, "ok", false);
    jw_obj_begin(w, "error");
    jw_str(w, "code", code);
    jw_str(w, "message", msg);
    jw_obj_end(w);
    jw_obj_end(w);
}

static void uhandle(struct uclient *c, const uint8_t *p, size_t len) {
    char line[1024];
    struct jw w;
    jw_init(&w, resp, sizeof resp);
    if (len >= sizeof line) {
        write_err(&w, "bad-syntax", "command too long");
    } else {
        memcpy(line, p, len);
        line[len] = 0;
        handler(handler_arg, line, &w);
        if (jw_finish(&w) != 0) {
            jw_reset(&w);
            write_err(&w, "bad-syntax", "response exceeds 65536 bytes; use offset/limit");
        }
    }
    int n = frame_encode(resp, w.len, c->tx, sizeof c->tx);
    c->tx_len = n < 0 ? 0 : (size_t)n;
    c->tx_off = 0;
}

static void uclient_cb(struct evsrc *s, uint32_t events) {
    struct uclient *c = (struct uclient *)s;
    if (events & (EPOLLERR | EPOLLHUP)) {
        uclose(c);
        return;
    }
    if (events & EPOLLOUT) {
        if (uflush(c) < 0)
            uclose(c);
        return;
    }
    if (!(events & EPOLLIN) || c->tx_len)
        return;
    uint8_t buf[4096];
    ssize_t n = recv(c->src.fd, buf, sizeof buf, MSG_DONTWAIT);
    if (n == 0 || (n < 0 && errno != EAGAIN && errno != EINTR)) {
        uclose(c);
        return;
    }
    if (n < 0)
        return;
    c->last_ns = clock_now_ns();
    size_t off = 0;
    while (off < (size_t)n && !c->tx_len) {
        off += frame_rx_feed(&c->rx, buf + off, (size_t)n - off);
        const uint8_t *p;
        size_t len;
        int g = frame_rx_get(&c->rx, &p, &len);
        if (g < 0) {
            uclose(c);
            return;
        }
        if (g == 0)
            break;
        uhandle(c, p, len);
        frame_rx_init(&c->rx);
    }
    if (c->tx_len && uflush(c) < 0)
        uclose(c);
}

static void ulistener_cb(struct evsrc *s, uint32_t events) {
    (void)events;
    int fd = accept4(s->fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0)
        return;
    struct ucred cred;
    socklen_t cl = sizeof cred;
    struct uclient *c = NULL;
    for (int i = 0; i < USRV_MAX_CLIENTS && !c; i++)
        if (!clients[i].in_use)
            c = &clients[i];
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cl) < 0 ||
        (cred.uid != 0 && cred.uid != allowed) || !c) {
        char json[200];
        struct jw w;
        jw_init(&w, json, sizeof json);
        write_err(&w, c ? "not-permitted" : "busy", c ? "peer uid not allowed" : "too many clients");
        uint8_t out[FRAME_HDR + sizeof json];
        int n = frame_encode(json, w.len, out, sizeof out);
        if (n > 0)
            (void)!send(fd, out, (size_t)n, MSG_NOSIGNAL | MSG_DONTWAIT);
        close(fd);
        return;
    }
    memset(&c->src, 0, sizeof c->src);
    c->src.fd = fd;
    c->src.cb = uclient_cb;
    c->in_use = 1;
    c->last_ns = clock_now_ns();
    c->tx_len = c->tx_off = 0;
    frame_rx_init(&c->rx);
    if (ev_add(&c->src, EPOLLIN) < 0) {
        close(fd);
        c->in_use = 0;
    }
}

int usrv_init(const char *path, uid_t allowed_uid, usrv_handler h, void *arg) {
    int fd = unix_listen(path);
    if (fd < 0) {
        log_error("ctl", "cannot create control socket", "path=%s errno=%d", path, errno);
        return -1;
    }
    allowed = allowed_uid;
    handler = h;
    handler_arg = arg;
    listener.fd = fd;
    listener.cb = ulistener_cb;
    if (ev_add(&listener, EPOLLIN) < 0) {
        close(fd);
        return -1;
    }
    return 0;
}

void usrv_tick(uint64_t now) {
    for (int i = 0; i < USRV_MAX_CLIENTS; i++)
        if (clients[i].in_use && now - clients[i].last_ns > USRV_IDLE_NS)
            uclose(&clients[i]);
}

void usrv_close(void) {
    for (int i = 0; i < USRV_MAX_CLIENTS; i++)
        uclose(&clients[i]);
    if (listener.fd >= 0) {
        ev_del(&listener);
        close(listener.fd);
        listener.fd = -1;
    }
}
