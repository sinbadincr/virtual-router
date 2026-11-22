#ifndef MINIVR_NETIO_H
#define MINIVR_NETIO_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "json_out.h"
#include "proto.h"

/* Non-blocking sockets and framed I/O for the controller and the agent (not used by minivrd). */

/* ---- TCP ---- */
int tcp_listen(const char *ip, uint16_t port, int backlog); /* fd or -1 (errno) */
/* Start a non-blocking connect, optionally bound to a local address. Returns the fd, or -1.
 * *pending is 1 when the connect is still in progress (wait for EPOLLOUT, then tcp_connect_done). */
int tcp_connect(const char *bind_ip, const char *ip, uint16_t port, int *pending);
int tcp_connect_done(int fd); /* 0 connected, else the errno of the failed connect */
int parse_hostport(const char *s, char ip[16], uint16_t *port); /* "a.b.c.d:port"; 0 or -1 */

/* ---- protocol v1 messages over a stream, header-first ---- */
struct msgconn {
    int fd;
    uint8_t rx[PROTO_MAX_MSG];
    size_t rx_have;
    uint8_t *tx;
    size_t tx_cap, tx_len, tx_off;
    uint64_t msgs_in, msgs_out, bytes_in, bytes_out;
};

int mc_init(struct msgconn *c, int fd, size_t tx_cap); /* 0, or -1 when tx cannot be allocated */
void mc_close(struct msgconn *c);                       /* closes the fd, frees the buffer */
enum mc_rx { MC_MSG = 1, MC_MORE = 0, MC_EOF = -1, MC_BAD_HEADER = -2, MC_IOERR = -3 };
/* Read what is available. MC_MSG: one whole message is in c->rx (c->msg_len bytes) until
 * mc_consume. MC_BAD_HEADER: *why is the reason, decided from the 12-byte header before any
 * body byte is read. MC_EOF with a partial message sets *why = PE_TRUNCATED. */
int mc_recv(struct msgconn *c, size_t *msg_len, enum proto_err *why);
void mc_consume(struct msgconn *c, size_t msg_len);
/* Queue a message and try to send; 0, or -1 when the send buffer would exceed its cap (the caller
 * closes the session with slow-peer) or on a socket error (errno). */
int mc_send(struct msgconn *c, const uint8_t *msg, size_t len);
int mc_flush(struct msgconn *c); /* 0 ok (maybe still pending), -1 socket error */
int mc_pending(const struct msgconn *c); /* bytes waiting to be written */

/* ---- Unix sockets ---- */
int unix_listen(const char *path); /* listening fd, 0600; probes for a live daemon first */
int unix_connect(const char *path);                        /* blocking connect, fd or -1 */

/* Text-command server with the minivrd framing (4-byte length + line), 0600, SO_PEERCRED.
 * `handler` writes the whole response envelope into `out`. */
typedef void (*usrv_handler)(void *arg, const char *line, struct jw *out);
int usrv_init(const char *path, uid_t allowed_uid, usrv_handler handler, void *arg);
void usrv_close(void);
void usrv_tick(uint64_t now_ns); /* idle client timeout */
#endif
