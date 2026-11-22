#include "minivr/ctl_server.h"

#include <errno.h>
#include <sys/uio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "../daemon/evloop.h"
#include "minivr/clock.h"
#include "minivr/cmd.h"
#include "minivr/frame.h"
#include "minivr/log.h"

#define MAX_CLIENTS 8
#define IDLE_NS (5 * NS_PER_SEC)

struct client {
    struct evsrc src;
    int in_use;
    uint64_t last_ns;
    struct frame_rx rx;
    uint8_t tx[FRAME_HDR + FRAME_MAX];
    size_t tx_len, tx_off;
    struct cmd_session sess;
    int fd_error; /* an fd arrived that the session may not send */
};

static struct evsrc listener = {.fd = -1};
static struct client clients[MAX_CLIENTS];
static uid_t owner;
static char resp[FRAME_MAX];

static void client_close(struct client *c) {
    if (!c->in_use)
        return;
    ev_del(&c->src);
    close(c->src.fd);
    cmd_session_close(&c->sess);
    c->in_use = 0;
}

/* Try to flush pending output; returns -1 if the client must be closed. */
static int client_flush(struct client *c) {
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

static void queue_response(struct client *c, const char *json, size_t len) {
    int n = frame_encode(json, len, c->tx, sizeof c->tx);
    c->tx_len = n < 0 ? 0 : (size_t)n;
    c->tx_off = 0;
}

static void handle_request(struct client *c, const uint8_t *p, size_t len) {
    char line[1024];
    struct jw w;
    struct cmd_err err;
    jw_init(&w, resp, sizeof resp);
    if (c->fd_error) {
        c->fd_error = 0;
        cmd_fail(&err, "not-permitted", "file descriptors are only accepted on the agent session");
        jw_obj_begin(&w, NULL);
        jw_bool(&w, "ok", false);
        jw_obj_begin(&w, "error");
        jw_str(&w, "code", err.code);
        jw_str(&w, "message", err.message);
        jw_obj_end(&w);
        jw_obj_end(&w);
    } else if (len >= sizeof line) {
        cmd_fail(&err, "bad-syntax", "command too long");
        jw_obj_begin(&w, NULL);
        jw_bool(&w, "ok", false);
        jw_obj_begin(&w, "error");
        jw_str(&w, "code", err.code);
        jw_str(&w, "message", err.message);
        jw_obj_end(&w);
        jw_obj_end(&w);
    } else {
        memcpy(line, p, len);
        line[len] = 0;
        cmd_exec_session(&c->sess, line, &w, &err);
        if (jw_finish(&w) != 0) {
            jw_reset(&w);
            jw_obj_begin(&w, NULL);
            jw_bool(&w, "ok", false);
            jw_obj_begin(&w, "error");
            jw_str(&w, "code", "bad-syntax");
            jw_str(&w, "message", "response exceeds 65536 bytes; use offset/limit");
            jw_obj_end(&w);
            jw_obj_end(&w);
        }
    }
    if (c->sess.fd_in >= 0) { /* the command did not take the passed fd */
        close(c->sess.fd_in);
        c->sess.fd_in = -1;
    }
    queue_response(c, resp, w.len);
}

static void client_cb(struct evsrc *s, uint32_t events) {
    struct client *c = (struct client *)s;
    if (events & (EPOLLERR | EPOLLHUP)) {
        client_close(c);
        return;
    }
    if (events & EPOLLOUT) {
        if (client_flush(c) < 0)
            client_close(c);
        return;
    }
    if (!(events & EPOLLIN) || c->tx_len)
        return;
    uint8_t buf[4096];
    union {
        struct cmsghdr align;
        uint8_t b[CMSG_SPACE(4 * sizeof(int))];
    } ctl;
    struct iovec iov = {buf, sizeof buf};
    struct msghdr mh = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = ctl.b,
                        .msg_controllen = sizeof ctl.b};
    ssize_t n = recvmsg(c->src.fd, &mh, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    if (n >= 0) {
        int nfds = 0;
        for (struct cmsghdr *cm = CMSG_FIRSTHDR(&mh); cm; cm = CMSG_NXTHDR(&mh, cm)) {
            if (cm->cmsg_level != SOL_SOCKET || cm->cmsg_type != SCM_RIGHTS)
                continue;
            size_t cnt = (cm->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            for (size_t k = 0; k < cnt; k++) {
                int fd;
                memcpy(&fd, CMSG_DATA(cm) + k * sizeof(int), sizeof fd);
                if (c->sess.role == CMD_ROLE_AGENT && nfds == 0 && c->sess.fd_in < 0)
                    c->sess.fd_in = fd;
                else {
                    close(fd);
                    c->fd_error = 1;
                }
                nfds++;
            }
        }
        if (mh.msg_flags & MSG_CTRUNC)
            c->fd_error = 1;
    }
    if (n == 0 || (n < 0 && errno != EAGAIN && errno != EINTR)) {
        client_close(c);
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
            log_warn("ctl", "oversized frame, closing client");
            client_close(c);
            return;
        }
        if (g == 0)
            break;
        handle_request(c, p, len);
        frame_rx_init(&c->rx);
    }
    if (c->tx_len && client_flush(c) < 0)
        client_close(c);
}

static void send_error_and_close(int fd, const char *code, const char *msg) {
    char json[256];
    uint8_t out[FRAME_HDR + sizeof json];
    struct jw w;
    jw_init(&w, json, sizeof json);
    jw_obj_begin(&w, NULL);
    jw_bool(&w, "ok", false);
    jw_obj_begin(&w, "error");
    jw_str(&w, "code", code);
    jw_str(&w, "message", msg);
    jw_obj_end(&w);
    jw_obj_end(&w);
    int n = frame_encode(json, w.len, out, sizeof out);
    if (n > 0)
        (void)!send(fd, out, (size_t)n, MSG_NOSIGNAL | MSG_DONTWAIT);
    close(fd);
}

static void listener_cb(struct evsrc *s, uint32_t events) {
    (void)events;
    int fd = accept4(s->fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0)
        return;
    struct ucred cred;
    socklen_t cl = sizeof cred;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cl) < 0 ||
        (cred.uid != 0 && cred.uid != owner)) {
        log_warn("ctl", "rejected peer", "uid=%u", cl == sizeof cred ? (unsigned)cred.uid : 0u);
        send_error_and_close(fd, "not-permitted", "peer uid not allowed");
        return;
    }
    struct client *c = NULL;
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (!clients[i].in_use) {
            c = &clients[i];
            break;
        }
    if (!c) {
        send_error_and_close(fd, "busy", "too many clients");
        return;
    }
    memset(&c->src, 0, sizeof c->src);
    c->src.fd = fd;
    c->src.cb = client_cb;
    c->in_use = 1;
    c->fd_error = 0;
    cmd_session_open(&c->sess, cl == sizeof cred ? (int)cred.pid : 0, (unsigned)cred.uid);
    c->last_ns = clock_now_ns();
    c->tx_len = c->tx_off = 0;
    frame_rx_init(&c->rx);
    if (ev_add(&c->src, EPOLLIN) < 0) {
        close(fd);
        cmd_session_close(&c->sess);
        c->in_use = 0;
    }
}

int ctl_server_init(const char *path, uid_t owner_uid) {
    struct sockaddr_un addr;
    if (strlen(path) >= sizeof addr.sun_path) {
        log_error("ctl", "socket path too long", "path=%s", path);
        return -1;
    }
    owner = owner_uid;

    /* Create only the parent directory, only if missing. */
    char dir[sizeof addr.sun_path];
    strcpy(dir, path);
    char *slash = strrchr(dir, '/');
    if (slash && slash != dir) {
        *slash = 0;
        if (mkdir(dir, 0700) < 0 && errno != EEXIST) {
            log_error("ctl", "cannot create socket directory", "dir=%s errno=%d", dir, errno);
            return -1;
        }
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
            log_error("ctl", "already running", "path=%s", path);
            return -1;
        }
        if (e != ECONNREFUSED || !S_ISSOCK(st.st_mode)) {
            log_error("ctl", "cannot reuse socket path", "path=%s errno=%d", path, e);
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
        log_error("ctl", "cannot create control socket", "path=%s errno=%d", path, errno);
        close(fd);
        return -1;
    }
    listener.fd = fd;
    listener.cb = listener_cb;
    if (ev_add(&listener, EPOLLIN) < 0) {
        close(fd);
        return -1;
    }
    return 0;
}

void ctl_server_tick(uint64_t now) {
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i].in_use && now - clients[i].last_ns > IDLE_NS)
            client_close(&clients[i]);
}

void ctl_server_close(void) {
    for (int i = 0; i < MAX_CLIENTS; i++)
        client_close(&clients[i]);
    if (listener.fd >= 0) {
        ev_del(&listener);
        close(listener.fd);
        listener.fd = -1;
    }
}
