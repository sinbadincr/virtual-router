/* Entry <-> TLV for the 7 node-state kinds (contracts/protocol.md "Entry fields per KIND"). */
#include <string.h>

#include "proto_int.h"

#define BIT(t) ((uint64_t)1 << (t))

bool proto_str_ok(const uint8_t *v, size_t n) {
    if (n < 1 || n > NE_NAME - 1)
        return false;
    for (size_t i = 0; i < n; i++) {
        uint8_t c = v[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-'))
            return false;
    }
    return true;
}

enum proto_err pattr_next(const uint8_t **p, size_t *left, struct pattr *a, bool *got) {
    *got = false;
    if (*left == 0)
        return PE_OK;
    if (*left < 4)
        return PE_ATTR_SHORT;
    const uint8_t *q = *p;
    uint16_t type = (uint16_t)((q[0] << 8) | q[1]);
    uint16_t len = (uint16_t)((q[2] << 8) | q[3]);
    if (len < 4)
        return PE_ATTR_SHORT;
    if (len > *left)
        return PE_ATTR_OVERRUN;
    size_t padded = ((size_t)len + 3) & ~(size_t)3;
    if (padded > *left)
        return PE_ATTR_OVERRUN;
    a->type = type;
    a->val = q + 4;
    a->vlen = (size_t)len - 4;
    *p += padded;
    *left -= padded;
    *got = true;
    return PE_OK;
}

static uint32_t rd32(const uint8_t *v) {
    return ((uint32_t)v[0] << 24) | ((uint32_t)v[1] << 16) | ((uint32_t)v[2] << 8) | v[3];
}

/* record the first entry-level problem */
static void note(struct pfields *f, enum proto_err why) {
    if (f->entry_err == PE_OK)
        f->entry_err = why;
}

static void copy_str(char *dst, const uint8_t *v, size_t n) {
    memcpy(dst, v, n);
    dst[n] = 0;
}

enum proto_err pf_parse(const uint8_t *p, size_t n, struct pfields *f) {
    const uint8_t *q = p;
    size_t left = n;
    for (;;) {
        struct pattr a;
        bool got;
        enum proto_err r = pattr_next(&q, &left, &a, &got);
        if (r != PE_OK)
            return r;
        if (!got)
            return PE_OK;
        if (a.type == PA_BINDING || a.type == PA_ENTRY_ADD || a.type == PA_ENTRY_DEL ||
            a.type == PA_ERROR)
            return PE_NEST_DEPTH;
        bool known = (a.type >= PA_KIND && a.type <= PA_VMI) || a.type == PA_RMAC ||
                     a.type == PA_ERR_CODE || a.type == PA_ERR_TEXT;
        if (!known)
            continue; /* unknown attribute types are skipped */
        if (f->seen & BIT(a.type)) {
            note(f, PE_ENTRY_ATTR_DUP);
            continue;
        }
        f->seen |= BIT(a.type);
        struct nentry *e = &f->e;
        switch (a.type) {
        case PA_KIND:
            if (a.vlen != 1)
                note(f, PE_ENTRY_ATTR_VALUE);
            else if (a.val[0] < 1 || a.val[0] > NE_KIND_MAX)
                note(f, PE_ENTRY_UNKNOWN_KIND);
            else
                e->kind = a.val[0];
            break;
        case PA_NAME:
        case PA_VRF:
        case PA_PORT:
        case PA_NODE:
        case PA_VMI: {
            char *dst = a.type == PA_NAME ? e->name
                      : a.type == PA_VRF  ? e->vrf
                      : a.type == PA_PORT ? e->port
                      : a.type == PA_NODE ? e->node
                                          : f->vmi;
            if (!proto_str_ok(a.val, a.vlen))
                note(f, PE_ENTRY_ATTR_VALUE);
            else
                copy_str(dst, a.val, a.vlen);
            break;
        }
        case PA_ID:
            if (a.vlen != 1 || a.val[0] < 1 || a.val[0] > 63)
                note(f, PE_ENTRY_ATTR_VALUE);
            else
                e->id = a.val[0];
            break;
        case PA_VNI:
            if (a.vlen != 4 || rd32(a.val) < 1 || rd32(a.val) > 0xffffffu)
                note(f, PE_ENTRY_ATTR_VALUE);
            else
                e->vni = rd32(a.val);
            break;
        case PA_IP:
            if (a.vlen != 4)
                note(f, PE_ENTRY_ATTR_VALUE);
            else
                e->ip = rd32(a.val);
            break;
        case PA_PREFIX:
            if (a.vlen != 5 || a.val[4] > 32) {
                note(f, PE_ENTRY_ATTR_VALUE);
            } else {
                e->prefix = rd32(a.val);
                e->plen = a.val[4];
            }
            break;
        case PA_MAC:
        case PA_RMAC:
            if (a.vlen != 6 || (a.val[0] & 1))
                note(f, PE_ENTRY_ATTR_VALUE);
            else
                memcpy(a.type == PA_MAC ? e->mac : e->rmac, a.val, 6);
            break;
        case PA_LABEL:
            if (a.vlen != 4 || rd32(a.val) < 16 || rd32(a.val) > 1048575)
                note(f, PE_ENTRY_ATTR_VALUE);
            else
                e->label = rd32(a.val);
            break;
        case PA_ENCAP:
            if (a.vlen != 1 || a.val[0] < 1 || a.val[0] > 2)
                note(f, PE_ENTRY_ATTR_VALUE);
            else
                e->encap = a.val[0];
            break;
        case PA_TAG:
            if (a.vlen != 4)
                note(f, PE_ENTRY_ATTR_VALUE);
            else
                e->tag = rd32(a.val);
            break;
        case PA_ERR_CODE:
            if (a.vlen != 2)
                note(f, PE_ENTRY_ATTR_VALUE);
            else
                f->code = (uint16_t)((a.val[0] << 8) | a.val[1]);
            break;
        case PA_ERR_TEXT: {
            bool ok = a.vlen >= 1 && a.vlen <= PROTO_TEXT_MAX;
            for (size_t i = 0; ok && i < a.vlen; i++)
                ok = a.val[i] >= 0x20 && a.val[i] != 0x7f;
            if (!ok)
                note(f, PE_ENTRY_ATTR_VALUE);
            else
                copy_str(f->text, a.val, a.vlen);
            break;
        }
        }
    }
}

/* required fields per kind: key, then everything */
static uint64_t need_key(unsigned kind) {
    switch (kind) {
    case NE_VRF: case NE_NODE: case NE_PORT: return BIT(PA_NAME);
    case NE_VNI: return BIT(PA_VNI);
    case NE_NEIGH: return BIT(PA_VRF) | BIT(PA_IP);
    case NE_LABEL: return BIT(PA_LABEL);
    case NE_ROUTE: return BIT(PA_VRF) | BIT(PA_PREFIX);
    default: return 0;
    }
}

static uint64_t need_all(unsigned kind) {
    uint64_t k = need_key(kind);
    switch (kind) {
    case NE_VRF: return k | BIT(PA_ID);
    case NE_VNI: return k | BIT(PA_VRF);
    case NE_NODE: return k | BIT(PA_IP) | BIT(PA_RMAC);
    case NE_PORT: return k | BIT(PA_VRF) | BIT(PA_PREFIX);
    case NE_NEIGH: return k | BIT(PA_MAC) | BIT(PA_PORT);
    case NE_LABEL: return k | BIT(PA_PORT);
    case NE_ROUTE: return k | BIT(PA_NODE) | BIT(PA_ENCAP) | BIT(PA_TAG);
    default: return 0;
    }
}

enum proto_err pf_check_entry(const struct pfields *f, bool is_del) {
    if (f->entry_err != PE_OK)
        return f->entry_err;
    if (!(f->seen & BIT(PA_KIND)))
        return PE_ENTRY_ATTR_MISSING;
    uint64_t need = is_del ? need_key(f->e.kind) : need_all(f->e.kind);
    if ((f->seen & need) != need)
        return PE_ENTRY_ATTR_MISSING;
    if (f->e.kind == NE_ROUTE) { /* a route prefix has no host bits (a PORT's PREFIX is its gateway) */
        uint32_t mask = f->e.plen == 0 ? 0 : ~0U << (32 - f->e.plen);
        if (f->e.prefix & ~mask)
            return PE_ENTRY_ATTR_VALUE;
    }
    return PE_OK;
}

/* ---- encoding ---- */

static void put_hdr(struct penc *e, uint16_t type, size_t vlen) {
    size_t total = 4 + vlen;
    size_t padded = (total + 3) & ~(size_t)3;
    if (e->overflow || e->len + padded > e->cap) {
        e->overflow = true;
        return;
    }
    uint8_t *q = e->buf + e->len;
    q[0] = (uint8_t)(type >> 8);
    q[1] = (uint8_t)type;
    q[2] = (uint8_t)(total >> 8);
    q[3] = (uint8_t)total;
    memset(q + 4, 0, padded - 4);
}

void penc_bytes(struct penc *e, enum proto_attr a, const void *p, size_t n) {
    size_t before = e->len;
    put_hdr(e, (uint16_t)a, n);
    if (e->overflow)
        return;
    memcpy(e->buf + e->len + 4, p, n);
    e->len = before + ((4 + n + 3) & ~(size_t)3);
}

void penc_u8(struct penc *e, enum proto_attr a, uint8_t v) {
    penc_bytes(e, a, &v, 1);
}

void penc_u16(struct penc *e, enum proto_attr a, uint16_t v) {
    uint8_t b[2] = {(uint8_t)(v >> 8), (uint8_t)v};
    penc_bytes(e, a, b, 2);
}

void penc_u32(struct penc *e, enum proto_attr a, uint32_t v) {
    uint8_t b[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
    penc_bytes(e, a, b, 4);
}

void penc_str(struct penc *e, enum proto_attr a, const char *s) {
    penc_bytes(e, a, s, strlen(s));
}

static void penc_prefix(struct penc *e, uint32_t addr, uint8_t plen) {
    uint8_t b[5] = {(uint8_t)(addr >> 24), (uint8_t)(addr >> 16), (uint8_t)(addr >> 8),
                    (uint8_t)addr, plen};
    penc_bytes(e, PA_PREFIX, b, 5);
}

/* Nested attribute: header with a patched length. Rolls back and returns -1 if it overflows. */
static size_t nest_begin(struct penc *e, enum proto_attr a) {
    size_t at = e->len;
    put_hdr(e, (uint16_t)a, 0);
    if (!e->overflow)
        e->len += 4;
    return at;
}

static int nest_end(struct penc *e, size_t at, bool was_overflow) {
    if (e->overflow && !was_overflow) {
        e->len = at;
        e->overflow = false;
        return -1;
    }
    if (e->overflow)
        return -1;
    size_t total = e->len - at;
    if (total > 0xffff) {
        e->len = at;
        return -1;
    }
    e->buf[at + 2] = (uint8_t)(total >> 8);
    e->buf[at + 3] = (uint8_t)total;
    return 0;
}

static void put_entry_fields(struct penc *e, const struct nentry *n, bool key_only) {
    penc_u8(e, PA_KIND, n->kind);
    switch (n->kind) {
    case NE_VRF:
        penc_str(e, PA_NAME, n->name);
        if (!key_only)
            penc_u8(e, PA_ID, n->id);
        break;
    case NE_VNI:
        penc_u32(e, PA_VNI, n->vni);
        if (!key_only)
            penc_str(e, PA_VRF, n->vrf);
        break;
    case NE_NODE:
        penc_str(e, PA_NAME, n->name);
        if (!key_only) {
            penc_u32(e, PA_IP, n->ip);
            penc_bytes(e, PA_RMAC, n->rmac, 6);
        }
        break;
    case NE_PORT:
        penc_str(e, PA_NAME, n->name);
        if (!key_only) {
            penc_str(e, PA_VRF, n->vrf);
            penc_prefix(e, n->prefix, n->plen);
        }
        break;
    case NE_NEIGH:
        penc_str(e, PA_VRF, n->vrf);
        penc_u32(e, PA_IP, n->ip);
        if (!key_only) {
            penc_bytes(e, PA_MAC, n->mac, 6);
            penc_str(e, PA_PORT, n->port);
        }
        break;
    case NE_LABEL:
        penc_u32(e, PA_LABEL, n->label);
        if (!key_only)
            penc_str(e, PA_PORT, n->port);
        break;
    case NE_ROUTE:
        penc_str(e, PA_VRF, n->vrf);
        penc_prefix(e, n->prefix, n->plen);
        if (!key_only) {
            penc_str(e, PA_NODE, n->node);
            penc_u8(e, PA_ENCAP, n->encap);
            penc_u32(e, PA_TAG, n->tag);
        }
        break;
    }
}

int penc_entry(struct penc *e, bool is_del, const struct nentry *n) {
    bool was = e->overflow;
    size_t at = nest_begin(e, is_del ? PA_ENTRY_DEL : PA_ENTRY_ADD);
    put_entry_fields(e, n, is_del);
    return nest_end(e, at, was);
}

int penc_binding(struct penc *e, const char *vmi, const char *port) {
    bool was = e->overflow;
    size_t at = nest_begin(e, PA_BINDING);
    penc_str(e, PA_VMI, vmi);
    if (port)
        penc_str(e, PA_PORT, port);
    return nest_end(e, at, was);
}

int penc_error(struct penc *e, const struct perror *er) {
    bool was = e->overflow;
    size_t at = nest_begin(e, PA_ERROR);
    if (er->has_entry)
        put_entry_fields(e, &er->key, true);
    if (er->has_vmi)
        penc_str(e, PA_VMI, er->vmi);
    penc_u16(e, PA_ERR_CODE, er->code);
    if (er->text[0])
        penc_str(e, PA_ERR_TEXT, er->text);
    return nest_end(e, at, was);
}
