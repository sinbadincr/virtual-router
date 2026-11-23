/* Controller sessions: one TCP session per node (data-model §4, contracts/protocol.md). */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "../daemon/evloop.h"
#include "ctl.h"
#include "minivr/clock.h"
#include "minivr/log.h"
#include "minivr/proto.h"

#define KEEPALIVE_S 3
#define HOLD_S 9
#define TX_CAP (1u << 20)
#define STATE_CAP 4096
#define MAX_INFLIGHT 32
#define MAX_ERRS 8
#define MAX_SESS (CM_MAX_NODES + 8)

enum sstate { SS_HELLO_WAIT, SS_BINDING, SS_SYNCING, SS_IN_SYNC, SS_OUT_OF_SYNC };

struct inflight {
    uint32_t seq;
    bool is_sync_end;
    uint8_t nlabels;
    uint16_t labels[16];
};

struct entry_err {
    char kind[8], key[48], code[24], text[80];
};

struct sess {
    struct evsrc src;
    bool in_use;
    struct msgconn mc;
    enum sstate state;
    int node; /* -1 before HELLO */
    char peer[24];
    uint32_t next_seq, gen;
    uint64_t since_ns, last_rx_ns, last_tx_ns;
    struct inflight infl[MAX_INFLIGHT];
    unsigned ninfl;
    uint32_t last_seq, acked_seq;
    bool seen[CM_MAX_VMIS]; /* VMIs reported during the initial bind list */
    bool bound_end;
    bool synced;            /* SYNC_BEGIN..SYNC_END was sent */
};

/* what outlives a session, per node */
struct nodeinfo {
    struct nentry S_s[STATE_CAP]; /* last state sent */
    struct nstate S;
    char last_error[48];
    struct entry_err errs[MAX_ERRS];
    unsigned nerr;
    uint64_t proto_err[PE_COUNT];
    uint64_t msgs_in, msgs_out, bytes_in, bytes_out;
    uint32_t gen;
};

static struct sess sess[MAX_SESS];
static struct sess *node_sess[CM_MAX_NODES];
static struct nodeinfo ninfo[CM_MAX_NODES];
static struct evsrc listener = {.fd = -1};
static bool inited;

static struct nentry d_s[STATE_CAP], dels_s[STATE_CAP], adds_s[STATE_CAP];

static void init_once(void) {
    if (inited)
        return;
    for (unsigned i = 0; i < CM_MAX_NODES; i++)
        ns_init(&ninfo[i].S, ninfo[i].S_s, STATE_CAP);
    inited = true;
}

static void set_last_error(int node, const char *text) {
    if (node >= 0)
        snprintf(ninfo[node].last_error, sizeof ninfo[node].last_error, "%s", text);
}

/* ---- sending ---- */

static void sess_close(struct sess *s, const char *why);

static int send_msg(struct sess *s, const uint8_t *msg, size_t len) {
    if (mc_send(&s->mc, msg, len) != 0) {
        sess_close(s, errno == ENOBUFS ? "slow-peer" : "send-failed");
        return -1;
    }
    if (mc_pending(&s->mc) > 0)
        ev_mod(&s->src, EPOLLIN | EPOLLOUT);
    s->last_tx_ns = clock_now_ns();
    return 0;
}

static uint32_t seq_next(struct sess *s) {
    s->last_seq = s->next_seq;
    return s->next_seq++;
}

static void reject_and_close(struct sess *s, unsigned code, const char *text, int version_supported) {
    uint8_t buf[512];
    size_t n = proto_enc_reject(buf, sizeof buf, seq_next(s), (uint16_t)code, text, version_supported);
    if (n)
        (void)mc_send(&s->mc, buf, n);
    if (code < 16)
        g_ctl.stats.reject[code]++;
    g_ctl.stats.sessions_rejected++;
    sess_close(s, text);
}

static void count_proto_err(struct sess *s, enum proto_err e) {
    if (e < PE_COUNT) {
        g_ctl.stats.proto_err[e]++;
        if (s->node >= 0)
            ninfo[s->node].proto_err[e]++;
    }
}

/* ---- closing ---- */

static void sess_close(struct sess *s, const char *why) {
    if (!s->in_use)
        return;
    if (s->node >= 0) {
        struct nodeinfo *ni = &ninfo[s->node];
        ni->msgs_in += s->mc.msgs_in;
        ni->msgs_out += s->mc.msgs_out;
        ni->bytes_in += s->mc.bytes_in;
        ni->bytes_out += s->mc.bytes_out;
        set_last_error(s->node, why);
        g_ctl.m.nodes[s->node].connected = false;
        if (node_sess[s->node] == s)
            node_sess[s->node] = NULL;
        log_info("session", "closed", "node=%s reason=%s", g_ctl.m.nodes[s->node].name, why);
    } else {
        log_info("session", "closed before hello", "peer=%s reason=%s", s->peer, why);
    }
    ev_del(&s->src);
    mc_close(&s->mc);
    s->in_use = false;
}

/* ---- full sync and diffs ---- */

static void entry_key_text(const struct nentry *e, char out[48]) {
    char a[20];
    switch (e->kind) {
    case NE_VRF: case NE_NODE: case NE_PORT: snprintf(out, 48, "%s", e->name); break;
    case NE_VNI: snprintf(out, 48, "%u", e->vni); break;
    case NE_LABEL: snprintf(out, 48, "%u", e->label); break;
    case NE_NEIGH: ne_ip_str(e->ip, a); snprintf(out, 48, "%s %s", e->vrf, a); break;
    case NE_ROUTE: ne_prefix_str(e->prefix, e->plen, a); snprintf(out, 48, "%s %s", e->vrf, a); break;
    default: out[0] = 0;
    }
}

static void forget_errors_for(struct nodeinfo *ni, const struct nentry *e) {
    char key[48];
    entry_key_text(e, key);
    for (unsigned i = 0; i < ni->nerr;) {
        if (strcmp(ni->errs[i].kind, ne_kind_name(e->kind)) == 0 && strcmp(ni->errs[i].key, key) == 0)
            ni->errs[i] = ni->errs[--ni->nerr];
        else
            i++;
    }
}

static struct inflight *infl_add(struct sess *s, uint32_t seq, bool is_sync_end) {
    if (s->ninfl >= MAX_INFLIGHT)
        return NULL;
    struct inflight *f = &s->infl[s->ninfl++];
    memset(f, 0, sizeof *f);
    f->seq = seq;
    f->is_sync_end = is_sync_end;
    return f;
}

/* Send dels then adds as UPDATE messages (as many entries per message as fit). */
static void send_updates(struct sess *s, const struct nentry *dels, unsigned nd,
                         const struct nentry *adds, unsigned na) {
    static uint8_t buf[PROTO_MAX_MSG];
    unsigned id = 0, ia = 0;
    struct nodeinfo *ni = &ninfo[s->node];
    while (id < nd || ia < na) {
        struct penc e;
        uint32_t seq = seq_next(s);
        penc_begin(&e, buf, sizeof buf, PM_UPDATE, seq);
        penc_u32(&e, PA_GEN, s->gen);
        struct inflight *f = infl_add(s, seq, false);
        if (!f) { /* too many unacknowledged updates: the peer is not keeping up */
            sess_close(s, "slow-peer");
            return;
        }
        unsigned sent = 0;
        while (id < nd && penc_entry(&e, true, &dels[id]) == 0) {
            if (dels[id].kind == NE_LABEL && f->nlabels < 16)
                f->labels[f->nlabels++] = (uint16_t)dels[id].label;
            forget_errors_for(ni, &dels[id]);
            id++;
            sent++;
        }
        while (id >= nd && ia < na && penc_entry(&e, false, &adds[ia]) == 0) {
            forget_errors_for(ni, &adds[ia]);
            ia++;
            sent++;
        }
        size_t n = penc_finish(&e);
        if (!n || sent == 0) { /* a single entry that cannot fit would loop forever */
            sess_close(s, "encode-failed");
            return;
        }
        g_ctl.stats.updates_sent++;
        g_ctl.stats.entries_sent += sent;
        if (send_msg(s, buf, n) != 0)
            return;
    }
}

static void push_node(unsigned node) {
    struct sess *s = node_sess[node];
    if (!s || !s->synced)
        return;
    struct nstate D;
    ns_init(&D, d_s, STATE_CAP);
    if (cm_compute(&g_ctl.m, node, &D) != 0) {
        log_error("session", "node state too large", "node=%s", g_ctl.m.nodes[node].name);
        return;
    }
    struct ndiff d = {dels_s, adds_s, 0, 0, STATE_CAP, STATE_CAP};
    if (ns_diff(&ninfo[node].S, &D, &d) != 0 || (d.ndels == 0 && d.nadds == 0))
        return;
    send_updates(s, d.dels, d.ndels, d.adds, d.nadds);
    if (s->in_use) {
        ns_copy(&ninfo[node].S, &D);
        s->state = SS_SYNCING;
    }
}

void sess_push_all(void) {
    init_once();
    for (unsigned n = 0; n < CM_MAX_NODES; n++)
        if (g_ctl.m.nodes[n].used)
            push_node(n);
}

static void full_sync(struct sess *s) {
    static uint8_t buf[PROTO_MAX_MSG];
    unsigned node = (unsigned)s->node;
    struct nodeinfo *ni = &ninfo[node];
    struct nstate D;
    ns_init(&D, d_s, STATE_CAP);
    if (cm_compute(&g_ctl.m, node, &D) != 0) {
        reject_and_close(s, PC_TABLE_FULL, "node state too large", -1);
        return;
    }
    s->gen = ++ni->gen;
    ni->nerr = 0;
    uint32_t seq = seq_next(s);
    size_t n = proto_enc_gen(buf, sizeof buf, PM_SYNC_BEGIN, seq, s->gen);
    if (send_msg(s, buf, n) != 0)
        return;
    send_updates(s, NULL, 0, D.e, D.n);
    if (!s->in_use)
        return;
    seq = seq_next(s);
    struct inflight *f = infl_add(s, seq, true);
    n = proto_enc_gen(buf, sizeof buf, PM_SYNC_END, seq, s->gen);
    if (!f || send_msg(s, buf, n) != 0) {
        if (s->in_use)
            sess_close(s, "slow-peer");
        return;
    }
    ns_copy(&ni->S, &D);
    s->synced = true;
    s->state = SS_SYNCING;
}

/* ---- incoming messages ---- */

struct rx {
    struct sess *s;
    uint8_t type;
    struct perror errs[8];
    unsigned nerrs;
    struct perror ack_errs[MAX_ERRS];
    unsigned nack;
    bool bad_entry;
};

static void add_ack_err(struct rx *r, unsigned code, const char *vmi, const char *text) {
    if (code < 16)
        g_ctl.stats.reject[code]++; /* counted by reason in `stats show` */
    if (r->nack >= MAX_ERRS)
        return;
    struct perror *e = &r->ack_errs[r->nack++];
    memset(e, 0, sizeof *e);
    e->code = (uint16_t)code;
    if (vmi) {
        e->has_vmi = true;
        snprintf(e->vmi, sizeof e->vmi, "%s", vmi);
    }
    snprintf(e->text, sizeof e->text, "%s", text);
}

static void on_binding(void *arg, const struct pbinding *b) {
    struct rx *r = arg;
    struct sess *s = r->s;
    unsigned node = (unsigned)s->node;
    if (r->type == PM_UNBIND) {
        (void)cm_unbind(&g_ctl.m, node, b->vmi);
        return;
    }
    if (r->s->state == SS_BINDING) {
        int i = cm_vmi_idx(&g_ctl.m, b->vmi);
        if (i >= 0)
            s->seen[i] = true;
    }
    if (!b->has_port) {
        add_ack_err(r, PC_BAD_ENTRY, b->vmi, "binding without port");
        return;
    }
    unsigned label;
    int from;
    switch (cm_bind(&g_ctl.m, node, b->vmi, b->port, &label, &from)) {
    case CM_BIND_OK:
        log_info("session", "bound", "vmi=%s node=%s port=%s label=%u", b->vmi,
                 g_ctl.m.nodes[node].name, b->port, label);
        break;
    case CM_BIND_UNKNOWN_VMI: add_ack_err(r, PC_UNKNOWN_VMI, b->vmi, "no such VM interface"); break;
    case CM_BIND_PORT_IN_USE: add_ack_err(r, PC_PORT_IN_USE, b->vmi, "port already bound to another VM interface"); break;
    case CM_BIND_TABLE_FULL: add_ack_err(r, PC_TABLE_FULL, b->vmi, "too many bound VM interfaces on this node"); break;
    }
}

static void on_bad_entry(void *arg, enum proto_err why) {
    struct rx *r = arg;
    count_proto_err(r->s, why);
    add_ack_err(r, PC_BAD_ENTRY, NULL, proto_err_name(why));
}

static void on_error(void *arg, const struct perror *e) {
    struct rx *r = arg;
    struct sess *s = r->s;
    if (r->nerrs < 8)
        r->errs[r->nerrs++] = *e;
    g_ctl.stats.ack_errors++;
    struct nodeinfo *ni = &ninfo[s->node];
    if (ni->nerr < MAX_ERRS) {
        struct entry_err *x = &ni->errs[ni->nerr++];
        memset(x, 0, sizeof *x);
        if (e->has_entry) {
            snprintf(x->kind, sizeof x->kind, "%s", ne_kind_name(e->key.kind));
            entry_key_text(&e->key, x->key);
        }
        snprintf(x->code, sizeof x->code, "%s", proto_code_name(e->code));
        snprintf(x->text, sizeof x->text, "%.79s", e->text);
    }
}

static void send_ack(struct sess *s, uint32_t acked, const struct perror *errs, unsigned n) {
    static uint8_t buf[PROTO_MAX_MSG];
    struct penc e;
    penc_begin(&e, buf, sizeof buf, PM_ACK, seq_next(s));
    penc_u32(&e, PA_ACKED_SEQ, acked);
    for (unsigned i = 0; i < n; i++)
        (void)penc_error(&e, &errs[i]);
    size_t len = penc_finish(&e);
    if (len)
        send_msg(s, buf, len);
}

static void handle_ack(struct sess *s, const struct pmsg *m) {
    for (unsigned i = 0; i < s->ninfl; i++) {
        if (s->infl[i].seq != m->acked_seq)
            continue;
        struct inflight f = s->infl[i];
        s->infl[i] = s->infl[--s->ninfl];
        s->acked_seq = m->acked_seq;
        for (unsigned k = 0; k < f.nlabels; k++)
            cm_label_release(&g_ctl.m, (unsigned)s->node, f.labels[k]);
        if (f.is_sync_end && ninfo[s->node].nerr == 0) {
            /* after a full sync the forwarder holds exactly D: every quarantined label is free */
            for (unsigned l = CM_LABEL_MIN; l <= CM_LABEL_MAX; l++)
                if (cm_label_quarantined(&g_ctl.m, (unsigned)s->node, l))
                    cm_label_release(&g_ctl.m, (unsigned)s->node, l);
        }
        break;
    }
    s->state = (s->ninfl == 0 && ninfo[s->node].nerr == 0) ? SS_IN_SYNC
               : ninfo[s->node].nerr ? SS_OUT_OF_SYNC : SS_SYNCING;
}

static void handle_hello(struct sess *s, const struct pmsg *m) {
    int node = cm_node_idx(&g_ctl.m, m->node_name);
    if (node < 0) {
        reject_and_close(s, PC_UNKNOWN_NODE, "node is not allowed to join", -1);
        return;
    }
    if (node_sess[node]) { /* the live session stays untouched */
        reject_and_close(s, PC_DUPLICATE_SESSION, "node already has a live session", -1);
        return;
    }
    s->node = node;
    node_sess[node] = s;
    g_ctl.m.nodes[node].connected = true;
    cm_node_learn(&g_ctl.m, (unsigned)node, m->underlay_ip, m->rmac);
    s->state = SS_BINDING;
    g_ctl.stats.sessions_accepted++;
    memset(s->seen, 0, sizeof s->seen);
    uint8_t buf[64];
    size_t n = proto_enc_hello_ack(buf, sizeof buf, seq_next(s), KEEPALIVE_S, HOLD_S);
    send_msg(s, buf, n);
    log_info("session", "hello", "node=%s peer=%s", m->node_name, s->peer);
}

static void handle_message(struct sess *s, const uint8_t *buf, size_t len) {
    struct pmsg m;
    enum proto_err why = proto_decode(buf, len, &m, NULL, NULL); /* structure first, nothing applied */
    if (why != PE_OK) {
        count_proto_err(s, why);
        reject_and_close(s, PC_MALFORMED, proto_err_name(why), -1);
        return;
    }
    s->last_rx_ns = clock_now_ns();
    struct rx r = {.s = s, .type = m.type};

    switch (m.type) {
    case PM_HELLO:
        if (s->state != SS_HELLO_WAIT)
            goto unexpected;
        handle_hello(s, &m);
        return;
    case PM_KEEPALIVE:
        if (s->state == SS_HELLO_WAIT)
            goto unexpected;
        return;
    case PM_REJECT:
        sess_close(s, "peer-reject");
        return;
    case PM_BIND:
    case PM_UNBIND: {
        if (s->state == SS_HELLO_WAIT || (m.type == PM_UNBIND && s->state == SS_BINDING))
            goto unexpected;
        struct proto_sink sk = {on_binding, NULL, NULL, on_bad_entry};
        proto_decode(buf, len, &m, &sk, &r);
        send_ack(s, m.seq, r.ack_errs, r.nack);
        if (s->in_use && s->bound_end)
            ctl_commit(); /* a later plug moves the VMI: every affected node is recomputed */
        return;
    }
    case PM_BIND_END:
        if (s->state != SS_BINDING)
            goto unexpected;
        for (int i = 0; i < CM_MAX_VMIS; i++) /* the reported list replaces the node's bindings */
            if (g_ctl.m.vmis[i].used && g_ctl.m.vmis[i].node == s->node && !s->seen[i])
                cm_unbind(&g_ctl.m, (unsigned)s->node, g_ctl.m.vmis[i].name);
        s->bound_end = true;
        ctl_commit(); /* persist the bindings first (also pushes the other nodes) */
        if (s->in_use)
            full_sync(s);
        return;
    case PM_ACK: {
        if (!s->synced)
            goto unexpected;
        struct proto_sink sk = {NULL, NULL, on_error, on_bad_entry};
        proto_decode(buf, len, &m, &sk, &r);
        handle_ack(s, &m);
        return;
    }
    default: /* HELLO_ACK, SYNC_BEGIN, UPDATE, SYNC_END flow controller -> agent only */
        goto unexpected;
    }
unexpected:
    count_proto_err(s, PE_UNEXPECTED);
    reject_and_close(s, PC_UNEXPECTED, "message not valid in this state", -1);
}

/* ---- socket events ---- */

static void sess_cb(struct evsrc *src, uint32_t events) {
    struct sess *s = (struct sess *)src;
    if (events & (EPOLLERR | EPOLLHUP)) {
        sess_close(s, "tcp-closed");
        return;
    }
    if (events & EPOLLOUT) {
        if (mc_flush(&s->mc) < 0) {
            sess_close(s, "send-failed");
            return;
        }
        if (mc_pending(&s->mc) == 0)
            ev_mod(&s->src, EPOLLIN);
    }
    if (!(events & EPOLLIN))
        return;
    for (int guard = 0; guard < 64 && s->in_use; guard++) {
        size_t len = 0;
        enum proto_err why = PE_OK;
        int r = mc_recv(&s->mc, &len, &why);
        if (r == MC_MORE)
            return;
        if (r == MC_EOF) {
            if (why == PE_TRUNCATED)
                count_proto_err(s, PE_TRUNCATED);
            sess_close(s, why == PE_TRUNCATED ? "truncated" : "tcp-closed");
            return;
        }
        if (r == MC_IOERR) {
            sess_close(s, "io-error");
            return;
        }
        if (r == MC_BAD_HEADER) {
            count_proto_err(s, why);
            reject_and_close(s, why == PE_BAD_VERSION ? PC_BAD_VERSION : PC_MALFORMED,
                             proto_err_name(why), why == PE_BAD_VERSION ? PROTO_VERSION : -1);
            return;
        }
        static uint8_t copy[PROTO_MAX_MSG];
        memcpy(copy, s->mc.rx, len);
        mc_consume(&s->mc, len);
        handle_message(s, copy, len);
    }
}

static void listener_cb(struct evsrc *src, uint32_t events) {
    (void)events;
    struct sockaddr_in sa;
    socklen_t sl = sizeof sa;
    int fd = accept4(src->fd, (struct sockaddr *)&sa, &sl, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0)
        return;
    struct sess *s = NULL;
    for (unsigned i = 0; i < MAX_SESS && !s; i++)
        if (!sess[i].in_use)
            s = &sess[i];
    if (!s) {
        close(fd);
        return;
    }
    memset(s, 0, sizeof *s);
    if (mc_init(&s->mc, fd, TX_CAP) != 0) {
        close(fd);
        return;
    }
    s->in_use = true;
    s->node = -1;
    s->state = SS_HELLO_WAIT;
    s->next_seq = 1;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sa.sin_addr, ip, sizeof ip);
    snprintf(s->peer, sizeof s->peer, "%s:%u", ip, ntohs(sa.sin_port));
    s->since_ns = s->last_rx_ns = s->last_tx_ns = clock_now_ns();
    s->src.fd = fd;
    s->src.cb = sess_cb;
    if (ev_add(&s->src, EPOLLIN) < 0)
        sess_close(s, "epoll");
}

int sess_listen(const char *ip, uint16_t port) {
    init_once();
    int fd = tcp_listen(ip, port, 16);
    if (fd < 0) {
        log_error("session", "cannot listen", "addr=%s:%u errno=%d", ip, port, errno);
        return -1;
    }
    listener.fd = fd;
    listener.cb = listener_cb;
    return ev_add(&listener, EPOLLIN);
}

void sess_tick(uint64_t now) {
    for (unsigned i = 0; i < MAX_SESS; i++) {
        struct sess *s = &sess[i];
        if (!s->in_use)
            continue;
        if (now - s->last_rx_ns > (uint64_t)HOLD_S * NS_PER_SEC) {
            count_proto_err(s, PE_HOLD_EXPIRED);
            reject_and_close(s, PC_HOLD_EXPIRED, "hold-expired", -1);
            continue;
        }
        if (s->state != SS_HELLO_WAIT && now - s->last_tx_ns >= (uint64_t)KEEPALIVE_S * NS_PER_SEC) {
            uint8_t buf[16];
            size_t n = proto_enc_keepalive(buf, sizeof buf, seq_next(s));
            send_msg(s, buf, n);
        }
        if (s->in_use && mc_pending(&s->mc) > 0)
            (void)mc_flush(&s->mc);
    }
}

void sess_shutdown(void) {
    for (unsigned i = 0; i < MAX_SESS; i++)
        if (sess[i].in_use) {
            uint8_t buf[128];
            size_t n = proto_enc_reject(buf, sizeof buf, seq_next(&sess[i]), PC_SHUTDOWN, "shutdown", -1);
            (void)mc_send(&sess[i].mc, buf, n);
            sess_close(&sess[i], "shutdown");
        }
    if (listener.fd >= 0) {
        ev_del(&listener);
        close(listener.fd);
        listener.fd = -1;
    }
}

bool sess_node_live(unsigned node) {
    return node < CM_MAX_NODES && node_sess[node] != NULL;
}

void sess_node_info(unsigned node, struct cg_node_info *out) {
    init_once();
    struct nodeinfo *ni = &ninfo[node];
    struct sess *s = node_sess[node];
    static const char *const names[] = {"hello", "binding", "syncing", "in-sync", "out-of-sync"};
    out->state = s ? names[s->state] : "none";
    if (s)
        snprintf(out->peer, sizeof out->peer, "%s", s->peer);
    out->since_s = s ? (clock_now_ns() - s->since_ns) / NS_PER_SEC : 0;
    snprintf(out->last_error, sizeof out->last_error, "%s", ni->last_error);
    out->msgs_in = ni->msgs_in + (s ? s->mc.msgs_in : 0);
    out->msgs_out = ni->msgs_out + (s ? s->mc.msgs_out : 0);
    out->bytes_in = ni->bytes_in + (s ? s->mc.bytes_in : 0);
    out->bytes_out = ni->bytes_out + (s ? s->mc.bytes_out : 0);
    out->last_seq = s ? s->last_seq : 0;
    out->acked_seq = s ? s->acked_seq : 0;
    out->in_sync = s && s->state == SS_IN_SYNC;
    out->entries = ni->S.n;
    out->nerr = ni->nerr;
    for (unsigned i = 0; i < ni->nerr && i < 8; i++) {
        snprintf(out->errs[i].kind, sizeof out->errs[i].kind, "%s", ni->errs[i].kind);
        snprintf(out->errs[i].key, sizeof out->errs[i].key, "%s", ni->errs[i].key);
        snprintf(out->errs[i].code, sizeof out->errs[i].code, "%s", ni->errs[i].code);
        snprintf(out->errs[i].text, sizeof out->errs[i].text, "%.79s", ni->errs[i].text);
    }
    memcpy(out->proto_err, ni->proto_err, sizeof out->proto_err < sizeof ni->proto_err ? sizeof out->proto_err : sizeof ni->proto_err);
}
