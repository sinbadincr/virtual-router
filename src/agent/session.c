/* Agent <-> controller session and the reconcile loop (data-model §5). */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "../daemon/evloop.h"
#include "agent.h"
#include "minivr/ctl_model.h"
#include "minivr/clock.h"
#include "minivr/log.h"
#include "minivr/proto.h"
#include "pio.h"

struct nentry g_have_s[RC_CAP];
struct nstate g_have;

static struct msgconn mc;
static struct evsrc src = {.fd = -1};
static bool connecting, have_conn;
static uint32_t next_seq = 1;
static uint64_t last_rx_ns, last_tx_ns, next_try_ns;
static struct backoff bo;
static bool bo_init;

static struct rc_cmd cmds[RC_CAP];
static struct rc_conflict conf[16];
static struct nentry dels_s[RC_CAP], adds_s[RC_CAP];

void agent_sess_counters(uint64_t out[4]) {
    out[0] = g_ag.msgs_in + (have_conn ? mc.msgs_in : 0);
    out[1] = g_ag.msgs_out + (have_conn ? mc.msgs_out : 0);
    out[2] = g_ag.bytes_in + (have_conn ? mc.bytes_in : 0);
    out[3] = g_ag.bytes_out + (have_conn ? mc.bytes_out : 0);
}

bool agent_session_up(void) {
    return have_conn && g_ag.sess >= AS_SYNCING;
}

/* ---- reconcile ---- */

static void add_failed(const struct rc_cmd *c, const char *code, const char *msg) {
    if (g_ag.nfailed >= AG_MAX_FAILED)
        return;
    struct ag_failed *f = &g_ag.failed[g_ag.nfailed++];
    f->e = c->entry;
    snprintf(f->cmd, sizeof f->cmd, "%s", c->text);
    snprintf(f->code, sizeof f->code, "%s", code);
    snprintf(f->msg, sizeof f->msg, "%s", msg);
}

void agent_reconcile(void) {
    if (!g_ag.fwd_up || !g_ag.rc.want_valid || g_ag.rc.syncing)
        return;
    if (!g_have.e)
        ns_init(&g_have, g_have_s, RC_CAP);
    if (fwd_read(&g_have, &g_ag.rc.foreign) != 0) {
        fwd_close();
        return;
    }
    if (!g_ag.adopted_logged) {
        g_ag.adopted_logged = true;
        log_info("agent", "forwarder state read", "adopted=%u", g_have.n);
    }
    int n = rc_plan(&g_ag.rc, &g_have, cmds, RC_CAP, conf, 16, &g_ag.nconf);
    for (unsigned i = 0; i < g_ag.nconf; i++)
        g_ag.conflicts[i] = conf[i].entry;
    g_ag.nfailed = 0;
    if (n < 0) {
        log_error("agent", "reconcile plan too large");
        return;
    }
    unsigned ok = 0;
    for (int i = 0; i < n; i++) {
        const struct rc_cmd *c = &cmds[i];
        char code[24], msg[160];
        int fd = -1, rc;
        if (c->is_port_add) {
            fd = afp_socket_open(c->entry.name);
            if (fd < 0) {
                add_failed(c, errno == ENODEV ? "not-found" : "socket-error", strerror(errno));
                continue;
            }
        }
        rc = fwd_exec(c->text, fd, code, msg);
        if (fd >= 0)
            close(fd);
        if (rc == FWD_IO) {
            fwd_close();
            return;
        }
        if (rc == 0 || (c->is_del && strcmp(code, "not-found") == 0) ||
            (c->is_del && strcmp(code, "unknown-port") == 0))
            ok++;
        else
            add_failed(c, code, msg);
    }
    g_ag.dirty = g_ag.nfailed > 0;
    if (n > 0 || g_ag.nconf)
        log_info("agent", "reconciled", "cmds=%d ok=%u failed=%u conflicts=%u", n, ok, g_ag.nfailed,
                 g_ag.nconf);
}

static void entries_json(struct jw *w, const char *key, const struct rc_cmd *c, int n, bool del) {
    jw_arr_begin(w, key);
    for (int i = 0; i < n; i++)
        if (c[i].is_del == del && !(c[i].is_del == false && false))
            ne_json(w, &c[i].entry);
    jw_arr_end(w);
}

void agent_diff_json(struct jw *w) {
    int n = 0;
    unsigned nc = 0;
    if (g_ag.fwd_up && g_ag.rc.want_valid) {
        if (!g_have.e)
            ns_init(&g_have, g_have_s, RC_CAP);
        if (fwd_read(&g_have, &g_ag.rc.foreign) == 0)
            n = rc_plan(&g_ag.rc, &g_have, cmds, RC_CAP, conf, 16, &nc);
        if (n < 0)
            n = 0;
    }
    entries_json(w, "missing", cmds, n, false);
    entries_json(w, "stale", cmds, n, true);
    jw_arr_begin(w, "conflicts");
    for (unsigned i = 0; i < nc; i++) {
        static const char *const names[] = {"config", "cli", "agent"};
        ne_json_ex(w, &conf[i].entry, names[conf[i].entry.owner % 3]);
    }
    jw_arr_end(w);
}

/* ---- messages ---- */

static void tx(const uint8_t *msg, size_t len) {
    if (!len)
        return;
    if (mc_send(&mc, msg, len) != 0) {
        agent_session_close("send-failed");
        return;
    }
    if (mc_pending(&mc) > 0)
        ev_mod(&src, EPOLLIN | EPOLLOUT);
    last_tx_ns = clock_now_ns();
}

static uint32_t seq(void) {
    return next_seq++;
}

static void send_hello(void) {
    uint8_t buf[128];
    tx(buf, proto_enc_hello(buf, sizeof buf, seq(), g_ag.node, g_ag.underlay_ip, g_ag.underlay_mac));
}

static void send_bindings(void) {
    static uint8_t buf[PROTO_MAX_MSG];
    struct penc e;
    penc_begin(&e, buf, sizeof buf, PM_BIND, seq());
    for (int i = 0; i < AG_MAX_BINDINGS; i++)
        if (g_ag.bind[i].used) {
            (void)penc_binding(&e, g_ag.bind[i].vmi, g_ag.bind[i].port);
            g_ag.bind[i].reported = true;
        }
    tx(buf, penc_finish(&e));
    penc_begin(&e, buf, sizeof buf, PM_BIND_END, seq());
    tx(buf, penc_finish(&e));
}

void agent_report_bind(const char *vmi, const char *port) {
    if (!have_conn || g_ag.sess < AS_SYNCING)
        return;
    uint8_t buf[256];
    struct penc e;
    penc_begin(&e, buf, sizeof buf, port ? PM_BIND : PM_UNBIND, seq());
    penc_binding(&e, vmi, port);
    tx(buf, penc_finish(&e));
    for (int i = 0; i < AG_MAX_BINDINGS; i++)
        if (g_ag.bind[i].used && strcmp(g_ag.bind[i].vmi, vmi) == 0)
            g_ag.bind[i].reported = true;
}

struct rxctx {
    unsigned nbad;
    char bad[8][24];
    unsigned nd, na;
    struct perror errs[8];
    unsigned nerrs;
};

static void on_entry(void *a, bool is_del, const struct nentry *e) {
    struct rxctx *r = a;
    if (is_del && r->nd < RC_CAP)
        dels_s[r->nd++] = *e;
    else if (!is_del && r->na < RC_CAP)
        adds_s[r->na++] = *e;
}

static void on_bad(void *a, enum proto_err why) {
    struct rxctx *r = a;
    g_ag.proto_err[why]++;
    if (r->nbad < 8)
        snprintf(r->bad[r->nbad], sizeof r->bad[0], "%s", proto_err_name(why));
    r->nbad++;
}

static void on_error(void *a, const struct perror *e) {
    struct rxctx *r = a;
    if (r->nerrs < 8)
        r->errs[r->nerrs++] = *e;
}

static void send_ack(uint32_t acked, const struct rxctx *r) {
    static uint8_t buf[PROTO_MAX_MSG];
    struct penc e;
    penc_begin(&e, buf, sizeof buf, PM_ACK, seq());
    penc_u32(&e, PA_ACKED_SEQ, acked);
    struct perror er;
    for (unsigned i = 0; r && i < r->nbad && i < 8; i++) {
        memset(&er, 0, sizeof er);
        er.code = PC_BAD_ENTRY;
        snprintf(er.text, sizeof er.text, "%s", r->bad[i]);
        penc_error(&e, &er);
    }
    for (unsigned i = 0; i < g_ag.nfailed; i++) {
        memset(&er, 0, sizeof er);
        er.has_entry = true;
        er.key = g_ag.failed[i].e;
        er.code = PC_ENTRY_REJECTED;
        snprintf(er.text, sizeof er.text, "%.60s: %.130s", g_ag.failed[i].code, g_ag.failed[i].msg);
        penc_error(&e, &er);
    }
    for (unsigned i = 0; i < g_ag.nconf; i++) {
        static const char *const names[] = {"config", "cli", "agent"};
        memset(&er, 0, sizeof er);
        er.has_entry = true;
        er.key = g_ag.conflicts[i];
        er.code = PC_ENTRY_REJECTED;
        snprintf(er.text, sizeof er.text, "exists: key held by %s", names[g_ag.conflicts[i].owner % 3]);
        penc_error(&e, &er);
    }
    tx(buf, penc_finish(&e));
}

static void handle(const uint8_t *buf, size_t len) {
    struct pmsg m;
    static struct rxctx r;
    memset(&r, 0, sizeof r);
    enum proto_err why = proto_decode(buf, len, &m, NULL, NULL);
    if (why != PE_OK) {
        g_ag.proto_err[why]++;
        uint8_t out[256];
        tx(out, proto_enc_reject(out, sizeof out, seq(), PC_MALFORMED, proto_err_name(why), -1));
        agent_session_close(proto_err_name(why));
        return;
    }
    last_rx_ns = clock_now_ns();
    struct proto_sink sk = {NULL, on_entry, on_error, on_bad};
    switch (m.type) {
    case PM_HELLO_ACK:
        if (g_ag.sess != AS_HELLO)
            goto unexpected;
        g_ag.keepalive_s = m.keepalive_s ? m.keepalive_s : 3;
        g_ag.hold_s = m.hold_s ? m.hold_s : 9;
        bo_init = false;
        backoff_reset(&bo);
        g_ag.sess = AS_SYNCING;
        send_bindings();
        break;
    case PM_KEEPALIVE:
        if (g_ag.sess < AS_SYNCING)
            goto unexpected;
        break;
    case PM_REJECT:
        snprintf(g_ag.last_error, sizeof g_ag.last_error, "rejected: %.40s (%s)", m.err_text,
                 proto_code_name(m.err_code));
        agent_session_close(g_ag.last_error);
        break;
    case PM_SYNC_BEGIN:
        if (g_ag.sess != AS_SYNCING && g_ag.sess != AS_IN_SYNC)
            goto unexpected;
        rc_sync_begin(&g_ag.rc, m.gen);
        g_ag.gen = m.gen;
        g_ag.sess = AS_SYNCING;
        break;
    case PM_UPDATE:
        if (g_ag.sess < AS_SYNCING || m.gen != g_ag.rc.gen)
            goto unexpected;
        proto_decode(buf, len, &m, &sk, &r);
        if (rc_update(&g_ag.rc, dels_s, r.nd, adds_s, r.na) != 0) {
            uint8_t out[256];
            tx(out, proto_enc_reject(out, sizeof out, seq(), PC_TABLE_FULL, "node state too large", -1));
            agent_session_close("table-full");
            return;
        }
        if (!g_ag.rc.syncing)
            agent_reconcile();
        send_ack(m.seq, &r);
        break;
    case PM_SYNC_END:
        if (rc_sync_end(&g_ag.rc, m.gen) != 0)
            goto unexpected;
        agent_reconcile(); /* the sweep: stale agent entries go only now */
        g_ag.sess = AS_IN_SYNC;
        send_ack(m.seq, NULL);
        break;
    case PM_ACK:
        proto_decode(buf, len, &m, &sk, &r);
        for (unsigned i = 0; i < r.nerrs; i++) {
            if (!r.errs[i].has_vmi || g_ag.nbind_err >= 8)
                continue;
            unsigned k = g_ag.nbind_err++;
            snprintf(g_ag.bind_err[k].vmi, NE_NAME, "%s", r.errs[i].vmi);
            snprintf(g_ag.bind_err[k].code, 24, "%s", proto_code_name(r.errs[i].code));
            snprintf(g_ag.bind_err[k].text, 80, "%.79s", r.errs[i].text);
        }
        break;
    default:
        goto unexpected;
    }
    return;
unexpected: {
    g_ag.proto_err[PE_UNEXPECTED]++;
    uint8_t out[256];
    tx(out, proto_enc_reject(out, sizeof out, seq(), PC_UNEXPECTED, "message not valid in this state", -1));
    agent_session_close("unexpected");
}
}

/* ---- connection ---- */

void agent_session_close(const char *why) {
    if (!have_conn && !connecting)
        return;
    g_ag.msgs_in += mc.msgs_in;
    g_ag.msgs_out += mc.msgs_out;
    g_ag.bytes_in += mc.bytes_in;
    g_ag.bytes_out += mc.bytes_out;
    if (src.fd >= 0)
        ev_del(&src);
    mc_close(&mc);
    src.fd = -1;
    have_conn = connecting = false;
    rc_session_lost(&g_ag.rc);
    g_ag.sess = AS_CONNECTING;
    if (why != g_ag.last_error)
        snprintf(g_ag.last_error, sizeof g_ag.last_error, "%.63s", why);
    if (!bo_init) {
        backoff_reset(&bo);
        bo_init = true;
    }
    g_ag.backoff_ms = backoff_next(&bo);
    next_try_ns = clock_now_ns() + (uint64_t)g_ag.backoff_ms * NS_PER_MS;
    log_info("agent", "session closed", "reason=%s retry_ms=%u", why, g_ag.backoff_ms);
}

static void on_event(struct evsrc *s, uint32_t events) {
    (void)s;
    if (connecting) {
        int e = tcp_connect_done(src.fd);
        if (e != 0 || (events & EPOLLERR)) {
            char t[64];
            snprintf(t, sizeof t, "connect: %s", strerror(e ? e : ECONNREFUSED));
            agent_session_close(t);
            return;
        }
        connecting = false;
        have_conn = true;
        if (mc_init(&mc, src.fd, 1u << 20) != 0) {
            agent_session_close("alloc");
            return;
        }
        next_seq = 1;
        last_rx_ns = last_tx_ns = clock_now_ns();
        g_ag.sess = AS_HELLO;
        g_ag.sess_since_ns = last_rx_ns;
        ev_mod(&src, EPOLLIN);
        send_hello();
        return;
    }
    if (events & (EPOLLERR | EPOLLHUP)) {
        agent_session_close("tcp-closed");
        return;
    }
    if (events & EPOLLOUT) {
        if (mc_flush(&mc) < 0) {
            agent_session_close("send-failed");
            return;
        }
        if (mc_pending(&mc) == 0)
            ev_mod(&src, EPOLLIN);
    }
    if (!(events & EPOLLIN))
        return;
    for (int g = 0; g < 64 && have_conn; g++) {
        size_t len = 0;
        enum proto_err why = PE_OK;
        int r = mc_recv(&mc, &len, &why);
        if (r == MC_MORE)
            return;
        if (r == MC_EOF || r == MC_IOERR) {
            if (why == PE_TRUNCATED)
                g_ag.proto_err[PE_TRUNCATED]++;
            agent_session_close(why == PE_TRUNCATED ? "truncated" : "tcp-closed");
            return;
        }
        if (r == MC_BAD_HEADER) {
            g_ag.proto_err[why]++;
            agent_session_close(proto_err_name(why));
            return;
        }
        static uint8_t copy[PROTO_MAX_MSG];
        memcpy(copy, mc.rx, len);
        mc_consume(&mc, len);
        handle(copy, len);
    }
}

void agent_session_start(void) {
    if (have_conn || connecting || !g_ag.underlay_known)
        return;
    int pending = 0;
    int fd = tcp_connect(g_ag.bind_ip, g_ag.ctrl_ip, g_ag.ctrl_port, &pending);
    if (fd < 0) {
        char t[64];
        snprintf(t, sizeof t, "connect: %s", strerror(errno));
        agent_session_close(t);
        have_conn = connecting = true; /* so close() does its bookkeeping once */
        src.fd = -1;
        connecting = have_conn = false;
        return;
    }
    src.fd = fd;
    src.cb = on_event;
    connecting = true;
    g_ag.sess = AS_CONNECTING;
    if (ev_add(&src, EPOLLIN | EPOLLOUT) < 0) {
        close(fd);
        src.fd = -1;
        connecting = false;
    }
}

void agent_session_tick(uint64_t now) {
    if (!have_conn && !connecting) {
        if (now >= next_try_ns)
            agent_session_start();
        return;
    }
    if (!have_conn)
        return;
    if (now - last_rx_ns > (uint64_t)(g_ag.hold_s ? g_ag.hold_s : 9) * NS_PER_SEC) {
        g_ag.proto_err[PE_HOLD_EXPIRED]++;
        agent_session_close("hold-expired");
        return;
    }
    if (now - last_tx_ns >= (uint64_t)(g_ag.keepalive_s ? g_ag.keepalive_s : 3) * NS_PER_SEC &&
        g_ag.sess >= AS_SYNCING) {
        uint8_t b[16];
        tx(b, proto_enc_keepalive(b, sizeof b, seq()));
    }
    if (have_conn && mc_pending(&mc) > 0)
        (void)mc_flush(&mc);
}
