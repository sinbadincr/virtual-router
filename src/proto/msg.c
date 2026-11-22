/* Protocol v1: header, message-level attributes, decode/encode (contracts/protocol.md). */
#include <string.h>

#include "proto_int.h"

#define BIT(t) ((uint32_t)1 << (t))

static const char *const err_names[PE_COUNT] = {
    [PE_OK] = "ok",
    [PE_TRUNCATED] = "truncated",
    [PE_BAD_VERSION] = "bad-version",
    [PE_BAD_FLAGS] = "bad-flags",
    [PE_BAD_LENGTH] = "bad-length",
    [PE_TOO_LARGE] = "too-large",
    [PE_UNKNOWN_TYPE] = "unknown-type",
    [PE_UNEXPECTED] = "unexpected",
    [PE_ATTR_SHORT] = "attr-short",
    [PE_ATTR_OVERRUN] = "attr-overrun",
    [PE_ATTR_SIZE] = "attr-size",
    [PE_ATTR_VALUE] = "attr-value",
    [PE_ATTR_MISSING] = "attr-missing",
    [PE_ATTR_DUP] = "attr-dup",
    [PE_NEST_DEPTH] = "nest-depth",
    [PE_HOLD_EXPIRED] = "hold-expired",
    [PE_ENTRY_ATTR_VALUE] = "entry-attr-value",
    [PE_ENTRY_ATTR_MISSING] = "entry-attr-missing",
    [PE_ENTRY_ATTR_DUP] = "entry-attr-dup",
    [PE_ENTRY_UNKNOWN_KIND] = "entry-unknown-kind",
};

const char *proto_err_name(enum proto_err e) {
    return (unsigned)e < PE_COUNT ? err_names[e] : "?";
}

bool proto_err_is_entry(enum proto_err e) {
    return e >= PE_ENTRY_ATTR_VALUE && e < PE_COUNT;
}

static const char *const code_names[] = {
    "?",          "bad-version",    "unknown-node", "duplicate-session", "malformed",
    "unexpected", "hold-expired",   "slow-peer",    "unknown-vmi",       "port-in-use",
    "entry-rejected", "shutdown",   "bad-entry",    "table-full",
};

const char *proto_code_name(unsigned code) {
    return code < sizeof code_names / sizeof *code_names ? code_names[code] : "?";
}

static uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

enum proto_err proto_hdr_check(const uint8_t hdr[PROTO_HDR], uint8_t *type, uint32_t *length,
                               uint32_t *seq) {
    if (hdr[0] != PROTO_VERSION)
        return PE_BAD_VERSION;
    if (hdr[2] != 0 || hdr[3] != 0)
        return PE_BAD_FLAGS;
    uint32_t len = rd32(hdr + 4);
    if (len < PROTO_HDR)
        return PE_BAD_LENGTH;
    if (len > PROTO_MAX_MSG)
        return PE_TOO_LARGE;
    if (hdr[1] < 1 || hdr[1] > PM_MAX)
        return PE_UNKNOWN_TYPE;
    *type = hdr[1];
    *length = len;
    *seq = rd32(hdr + 8);
    return PE_OK;
}

static uint32_t required_for(uint8_t type) {
    switch (type) {
    case PM_HELLO: return BIT(PA_NODE_NAME) | BIT(PA_UNDERLAY_IP) | BIT(PA_RMAC);
    case PM_HELLO_ACK: return BIT(PA_KEEPALIVE_S) | BIT(PA_HOLD_S);
    case PM_REJECT: return BIT(PA_ERR_CODE) | BIT(PA_ERR_TEXT);
    case PM_SYNC_BEGIN: case PM_UPDATE: case PM_SYNC_END: return BIT(PA_GEN);
    case PM_ACK: return BIT(PA_ACKED_SEQ);
    default: return 0;
    }
}

/* One scalar message-level attribute; returns PE_OK or the structural reason. */
static enum proto_err scalar(struct pmsg *m, const struct pattr *a) {
    if (m->has & BIT(a->type))
        return PE_ATTR_DUP;
    switch (a->type) {
    case PA_NODE_NAME:
        if (a->vlen < 1 || a->vlen > NE_NAME - 1)
            return PE_ATTR_VALUE;
        if (!proto_str_ok(a->val, a->vlen))
            return PE_ATTR_VALUE;
        memcpy(m->node_name, a->val, a->vlen);
        m->node_name[a->vlen] = 0;
        break;
    case PA_UNDERLAY_IP:
        if (a->vlen != 4)
            return PE_ATTR_SIZE;
        m->underlay_ip = rd32(a->val);
        break;
    case PA_RMAC:
        if (a->vlen != 6)
            return PE_ATTR_SIZE;
        if (a->val[0] & 1)
            return PE_ATTR_VALUE;
        memcpy(m->rmac, a->val, 6);
        break;
    case PA_KEEPALIVE_S:
    case PA_HOLD_S:
    case PA_ERR_CODE: {
        if (a->vlen != 2)
            return PE_ATTR_SIZE;
        uint16_t v = (uint16_t)((a->val[0] << 8) | a->val[1]);
        if (a->type == PA_KEEPALIVE_S)
            m->keepalive_s = v;
        else if (a->type == PA_HOLD_S)
            m->hold_s = v;
        else
            m->err_code = v;
        break;
    }
    case PA_ERR_TEXT:
        if (a->vlen < 1 || a->vlen > PROTO_TEXT_MAX)
            return PE_ATTR_VALUE;
        for (size_t i = 0; i < a->vlen; i++)
            if (a->val[i] < 0x20 || a->val[i] == 0x7f)
                return PE_ATTR_VALUE;
        memcpy(m->err_text, a->val, a->vlen);
        m->err_text[a->vlen] = 0;
        break;
    case PA_VERSION_SUPPORTED:
        if (a->vlen != 1)
            return PE_ATTR_SIZE;
        m->version_supported = a->val[0];
        break;
    case PA_GEN:
        if (a->vlen != 4)
            return PE_ATTR_SIZE;
        m->gen = rd32(a->val);
        break;
    case PA_ACKED_SEQ:
        if (a->vlen != 4)
            return PE_ATTR_SIZE;
        m->acked_seq = rd32(a->val);
        break;
    default:
        return PE_OK;
    }
    m->has |= BIT(a->type);
    return PE_OK;
}

static void report(const struct proto_sink *s, void *arg, enum proto_err why) {
    if (s && s->bad_entry)
        s->bad_entry(arg, why);
}

static enum proto_err body(const uint8_t *p, size_t n, struct pmsg *m, const struct proto_sink *s,
                           void *arg) {
    for (;;) {
        struct pattr a;
        bool got;
        enum proto_err r = pattr_next(&p, &n, &a, &got);
        if (r != PE_OK)
            return r;
        if (!got)
            break;
        if (a.type >= 1 && a.type <= 10) {
            r = scalar(m, &a);
            if (r != PE_OK)
                return r;
        } else if (a.type == PA_ENTRY_ADD || a.type == PA_ENTRY_DEL) {
            struct pfields f;
            memset(&f, 0, sizeof f);
            r = pf_parse(a.val, a.vlen, &f);
            if (r != PE_OK)
                return r;
            r = pf_check_entry(&f, a.type == PA_ENTRY_DEL);
            if (r != PE_OK)
                report(s, arg, r);
            else if (s && s->entry)
                s->entry(arg, a.type == PA_ENTRY_DEL, &f.e);
        } else if (a.type == PA_BINDING) {
            struct pfields f;
            memset(&f, 0, sizeof f);
            r = pf_parse(a.val, a.vlen, &f);
            if (r != PE_OK)
                return r;
            bool need_port = m->type == PM_BIND;
            if (f.entry_err != PE_OK)
                report(s, arg, f.entry_err);
            else if (!(f.seen & ((uint64_t)1 << PA_VMI)) ||
                     (need_port && !(f.seen & ((uint64_t)1 << PA_PORT))))
                report(s, arg, PE_ENTRY_ATTR_MISSING);
            else if (s && s->binding) {
                struct pbinding b;
                memset(&b, 0, sizeof b);
                memcpy(b.vmi, f.vmi, sizeof b.vmi);
                b.has_port = (f.seen & ((uint64_t)1 << PA_PORT)) != 0;
                if (b.has_port)
                    memcpy(b.port, f.e.port, sizeof b.port);
                s->binding(arg, &b);
            }
        } else if (a.type == PA_ERROR) {
            struct pfields f;
            memset(&f, 0, sizeof f);
            r = pf_parse(a.val, a.vlen, &f);
            if (r != PE_OK)
                return r;
            bool has_kind = (f.seen & ((uint64_t)1 << PA_KIND)) != 0;
            enum proto_err why = f.entry_err;
            if (why == PE_OK && !(f.seen & ((uint64_t)1 << PA_ERR_CODE)))
                why = PE_ENTRY_ATTR_MISSING;
            if (why == PE_OK && has_kind)
                why = pf_check_entry(&f, true);
            if (why != PE_OK) {
                report(s, arg, why);
            } else if (s && s->error) {
                struct perror er;
                memset(&er, 0, sizeof er);
                er.has_entry = has_kind;
                er.key = f.e;
                er.has_vmi = (f.seen & ((uint64_t)1 << PA_VMI)) != 0;
                memcpy(er.vmi, f.vmi, sizeof er.vmi);
                er.code = f.code;
                memcpy(er.text, f.text, sizeof er.text);
                s->error(arg, &er);
            }
        }
        /* any other type: skipped (forward compatibility) */
    }
    uint32_t need = required_for(m->type);
    if ((m->has & need) != need)
        return PE_ATTR_MISSING;
    return PE_OK;
}

enum proto_err proto_decode(const uint8_t *buf, size_t len, struct pmsg *m,
                            const struct proto_sink *sink, void *arg) {
    memset(m, 0, sizeof *m);
    if (len < PROTO_HDR)
        return PE_TRUNCATED;
    uint32_t length;
    enum proto_err r = proto_hdr_check(buf, &m->type, &length, &m->seq);
    if (r != PE_OK)
        return r;
    if (len < length)
        return PE_TRUNCATED;
    const uint8_t *p = buf + PROTO_HDR;
    size_t n = length - PROTO_HDR;
    uint8_t type = m->type;
    uint32_t seq = m->seq;
    r = body(p, n, m, NULL, NULL); /* pass 1: structure only, nothing is delivered */
    if (r != PE_OK)
        return r;
    memset(m, 0, sizeof *m);
    m->type = type;
    m->seq = seq;
    return body(p, n, m, sink, arg); /* pass 2: same walk, now with callbacks */
}

/* ---- encoding ---- */

void penc_begin(struct penc *e, uint8_t *buf, size_t cap, enum proto_msg type, uint32_t seq) {
    e->buf = buf;
    e->cap = cap > PROTO_MAX_MSG ? PROTO_MAX_MSG : cap;
    e->len = 0;
    e->overflow = e->cap < PROTO_HDR;
    if (e->overflow)
        return;
    buf[0] = PROTO_VERSION;
    buf[1] = (uint8_t)type;
    buf[2] = buf[3] = 0;
    wr32(buf + 4, PROTO_HDR);
    wr32(buf + 8, seq);
    e->len = PROTO_HDR;
}

size_t penc_finish(struct penc *e) {
    if (e->overflow)
        return 0;
    wr32(e->buf + 4, (uint32_t)e->len);
    return e->len;
}

size_t proto_enc_keepalive(uint8_t *buf, size_t cap, uint32_t seq) {
    struct penc e;
    penc_begin(&e, buf, cap, PM_KEEPALIVE, seq);
    return penc_finish(&e);
}

size_t proto_enc_hello(uint8_t *buf, size_t cap, uint32_t seq, const char *node, uint32_t ip,
                       const uint8_t rmac[6]) {
    struct penc e;
    penc_begin(&e, buf, cap, PM_HELLO, seq);
    penc_str(&e, PA_NODE_NAME, node);
    penc_u32(&e, PA_UNDERLAY_IP, ip);
    penc_bytes(&e, PA_RMAC, rmac, 6);
    return penc_finish(&e);
}

size_t proto_enc_hello_ack(uint8_t *buf, size_t cap, uint32_t seq, uint16_t keepalive_s,
                           uint16_t hold_s) {
    struct penc e;
    penc_begin(&e, buf, cap, PM_HELLO_ACK, seq);
    penc_u16(&e, PA_KEEPALIVE_S, keepalive_s);
    penc_u16(&e, PA_HOLD_S, hold_s);
    return penc_finish(&e);
}

size_t proto_enc_reject(uint8_t *buf, size_t cap, uint32_t seq, uint16_t code, const char *text,
                        int version_supported) {
    struct penc e;
    penc_begin(&e, buf, cap, PM_REJECT, seq);
    penc_u16(&e, PA_ERR_CODE, code);
    penc_str(&e, PA_ERR_TEXT, text);
    if (version_supported >= 0)
        penc_u8(&e, PA_VERSION_SUPPORTED, (uint8_t)version_supported);
    return penc_finish(&e);
}

size_t proto_enc_gen(uint8_t *buf, size_t cap, enum proto_msg type, uint32_t seq, uint32_t gen) {
    struct penc e;
    penc_begin(&e, buf, cap, type, seq);
    penc_u32(&e, PA_GEN, gen);
    return penc_finish(&e);
}

size_t proto_enc_ack(uint8_t *buf, size_t cap, uint32_t seq, uint32_t acked_seq) {
    struct penc e;
    penc_begin(&e, buf, cap, PM_ACK, seq);
    penc_u32(&e, PA_ACKED_SEQ, acked_seq);
    return penc_finish(&e);
}
