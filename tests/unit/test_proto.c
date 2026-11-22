/* Protocol v1 codec: byte vectors, round trips and every malformed example of
 * specs/005-agent-controller/contracts/protocol.md. */
#include <string.h>

#include "minivr/proto.h"
#include "tharness.h"

static const uint8_t KEEPALIVE7[12] = {0x01, 0x0b, 0, 0, 0, 0, 0, 0x0c, 0, 0, 0, 7};
static const uint8_t HELLO_CN1[40] = {
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x00, 0x07, 0x63, 0x6e, 0x31, 0x00,
    0x00, 0x02, 0x00, 0x08, 0xac, 0x10, 0x00, 0x01,
    0x00, 0x03, 0x00, 0x0a, 0x02, 0x00, 0x00, 0xff, 0x00, 0x01, 0x00, 0x00};
static const uint8_t RMAC1[6] = {2, 0, 0, 0xff, 0, 1};

struct col { /* what a decode delivered */
    unsigned nbind, nadd, ndel, nerr, nbad;
    struct pbinding bind[8];
    struct nentry add[16], del[16];
    struct perror err[4];
    enum proto_err bad[8];
};

static void c_bind(void *a, const struct pbinding *b) {
    struct col *c = a;
    c->bind[c->nbind++] = *b;
}
static void c_entry(void *a, bool is_del, const struct nentry *e) {
    struct col *c = a;
    if (is_del)
        c->del[c->ndel++] = *e;
    else
        c->add[c->nadd++] = *e;
}
static void c_error(void *a, const struct perror *e) {
    struct col *c = a;
    c->err[c->nerr++] = *e;
}
static void c_bad(void *a, enum proto_err w) {
    struct col *c = a;
    c->bad[c->nbad++] = w;
}
static const struct proto_sink SINK = {c_bind, c_entry, c_error, c_bad};

static enum proto_err dec(const uint8_t *b, size_t n, struct pmsg *m, struct col *c) {
    memset(c, 0, sizeof *c);
    return proto_decode(b, n, m, &SINK, c);
}

/* header + body, for hand-built malformed messages */
static size_t mk(uint8_t *out, uint8_t type, uint32_t seq, const uint8_t *body, size_t n) {
    out[0] = 1;
    out[1] = type;
    out[2] = out[3] = 0;
    uint32_t len = (uint32_t)(12 + n);
    out[4] = (uint8_t)(len >> 24); out[5] = (uint8_t)(len >> 16);
    out[6] = (uint8_t)(len >> 8);  out[7] = (uint8_t)len;
    out[8] = (uint8_t)(seq >> 24); out[9] = (uint8_t)(seq >> 16);
    out[10] = (uint8_t)(seq >> 8); out[11] = (uint8_t)seq;
    memcpy(out + 12, body, n);
    return 12 + n;
}

TEST(keepalive_vector) {
    uint8_t b[64];
    CHECK_EQ_U64(proto_enc_keepalive(b, sizeof b, 7), 12);
    CHECK(memcmp(b, KEEPALIVE7, 12) == 0);
    struct pmsg m;
    struct col c;
    CHECK(dec(KEEPALIVE7, 12, &m, &c) == PE_OK);
    CHECK_EQ_U64(m.type, PM_KEEPALIVE);
    CHECK_EQ_U64(m.seq, 7);
}

TEST(hello_vector) {
    uint8_t b[128];
    CHECK_EQ_U64(proto_enc_hello(b, sizeof b, 1, "cn1", 0xac100001u, RMAC1), 40);
    CHECK(memcmp(b, HELLO_CN1, 40) == 0);
    struct pmsg m;
    struct col c;
    CHECK(dec(HELLO_CN1, 40, &m, &c) == PE_OK);
    CHECK_STR_EQ(m.node_name, "cn1");
    CHECK_EQ_U64(m.underlay_ip, 0xac100001u);
    CHECK(memcmp(m.rmac, RMAC1, 6) == 0);
}

TEST(header_errors) {
    uint8_t b[64];
    struct pmsg m;
    struct col c;
    memcpy(b, KEEPALIVE7, 12);
    b[0] = 2;
    CHECK(dec(b, 12, &m, &c) == PE_BAD_VERSION);
    memcpy(b, KEEPALIVE7, 12);
    b[3] = 1;
    CHECK(dec(b, 12, &m, &c) == PE_BAD_FLAGS);
    memcpy(b, KEEPALIVE7, 12);
    b[2] = 0x80;
    CHECK(dec(b, 12, &m, &c) == PE_BAD_FLAGS);
    memcpy(b, KEEPALIVE7, 12);
    b[1] = 99;
    CHECK(dec(b, 12, &m, &c) == PE_UNKNOWN_TYPE);
    b[1] = 0;
    CHECK(dec(b, 12, &m, &c) == PE_UNKNOWN_TYPE);
    memcpy(b, KEEPALIVE7, 12);
    b[7] = 11; /* length 11 */
    CHECK(dec(b, 12, &m, &c) == PE_BAD_LENGTH);
    memcpy(b, KEEPALIVE7, 12);
    b[5] = 1; b[6] = 0; b[7] = 1; /* 65,537 */
    CHECK(dec(b, 12, &m, &c) == PE_TOO_LARGE);
    CHECK(dec(KEEPALIVE7, 11, &m, &c) == PE_TRUNCATED);
    CHECK(dec(HELLO_CN1, 39, &m, &c) == PE_TRUNCATED); /* length 40, 39 bytes then close */
    uint8_t hdr[12], t;
    uint32_t len, seq;
    memcpy(hdr, HELLO_CN1, 12);
    CHECK(proto_hdr_check(hdr, &t, &len, &seq) == PE_OK);
    CHECK_EQ_U64(len, 40);
}

TEST(attribute_structure_errors) {
    uint8_t b[128], full[128];
    struct pmsg m;
    struct col c;
    /* NODE_NAME attr length 3 */
    memcpy(b, HELLO_CN1 + 12, 28);
    b[3] = 3;
    CHECK(dec(full, mk(full, PM_HELLO, 1, b, 28), &m, &c) == PE_ATTR_SHORT);
    /* attr length running 1 byte past the message: first attribute claims 29 bytes of 28 */
    memcpy(b, HELLO_CN1 + 12, 28);
    b[3] = 29;
    CHECK(dec(full, mk(full, PM_HELLO, 1, b, 28), &m, &c) == PE_ATTR_OVERRUN);
    /* fewer than 4 bytes left over */
    memcpy(b, HELLO_CN1 + 12, 28);
    b[28] = 0; b[29] = 9;
    CHECK(dec(full, mk(full, PM_HELLO, 1, b, 30), &m, &c) == PE_ATTR_SHORT);
    /* RMAC of 5 bytes: its attribute (body offset 16) claims length 9 */
    memcpy(b, HELLO_CN1 + 12, 28);
    b[16 + 3] = 9;
    CHECK(dec(full, mk(full, PM_HELLO, 1, b, 28), &m, &c) == PE_ATTR_SIZE);
    /* HELLO without NODE_NAME */
    CHECK(dec(full, mk(full, PM_HELLO, 1, HELLO_CN1 + 20, 20), &m, &c) == PE_ATTR_MISSING);
    /* two NODE_NAMEs */
    {
        uint8_t body[48];
        memcpy(body, HELLO_CN1 + 12, 8);
        memcpy(body + 8, HELLO_CN1 + 12, 28);
        CHECK(dec(full, mk(full, PM_HELLO, 1, body, 36), &m, &c) == PE_ATTR_DUP);
    }
    /* bad string: upper case */
    memcpy(b, HELLO_CN1 + 12, 28);
    b[4] = 'C';
    CHECK(dec(full, mk(full, PM_HELLO, 1, b, 28), &m, &c) == PE_ATTR_VALUE);
    /* multicast rmac */
    memcpy(b, HELLO_CN1 + 12, 28);
    b[20] = 0x03;
    CHECK(dec(full, mk(full, PM_HELLO, 1, b, 28), &m, &c) == PE_ATTR_VALUE);
}

/* build an UPDATE with the given raw entry attributes (already TLV encoded) */
static size_t update_with(uint8_t *out, const uint8_t *entries, size_t n) {
    uint8_t body[1024];
    const uint8_t gen[8] = {0, 9, 0, 8, 0, 0, 0, 7};
    memcpy(body, gen, 8);
    memcpy(body + 8, entries, n);
    return mk(out, PM_UPDATE, 5, body, 8 + n);
}

static void put_attr(uint8_t *p, size_t *n, uint16_t type, const void *v, size_t vl) {
    size_t total = 4 + vl;
    p[*n] = (uint8_t)(type >> 8); p[*n + 1] = (uint8_t)type;
    p[*n + 2] = (uint8_t)(total >> 8); p[*n + 3] = (uint8_t)total;
    memcpy(p + *n + 4, v, vl);
    size_t pad = (total + 3) & ~(size_t)3;
    memset(p + *n + total, 0, pad - total);
    *n += pad;
}

/* ENTRY_ADD wrapping the given field bytes */
static void put_entry(uint8_t *p, size_t *n, uint16_t type, const uint8_t *fields, size_t fl) {
    put_attr(p, n, type, fields, fl);
}

static struct nentry sample(unsigned kind) {
    struct nentry e;
    memset(&e, 0, sizeof e);
    e.kind = (uint8_t)kind;
    switch (kind) {
    case NE_VRF: strcpy(e.name, "red"); e.id = 1; break;
    case NE_VNI: e.vni = 100; strcpy(e.vrf, "red"); break;
    case NE_NODE: strcpy(e.name, "cn2"); e.ip = 0xac100002u; memcpy(e.rmac, RMAC1, 6); break;
    case NE_PORT: strcpy(e.name, "red1"); strcpy(e.vrf, "red"); e.prefix = 0x0a010101u; e.plen = 24; break;
    case NE_NEIGH: strcpy(e.vrf, "red"); e.ip = 0x0a01010bu; memcpy(e.mac, RMAC1, 6); strcpy(e.port, "red1"); break;
    case NE_LABEL: e.label = 1000; strcpy(e.port, "red1"); break;
    case NE_ROUTE: strcpy(e.vrf, "red"); e.prefix = 0x0a01010cu; e.plen = 32; strcpy(e.node, "cn2"); e.encap = NE_ENCAP_MPLSOUDP; e.tag = 1012; break;
    }
    return e;
}

TEST(every_message_type_round_trips) {
    uint8_t b[256];
    struct pmsg m;
    struct col c;
    size_t n = proto_enc_hello_ack(b, sizeof b, 2, 3, 9);
    CHECK(dec(b, n, &m, &c) == PE_OK);
    CHECK_EQ_U64(m.type, PM_HELLO_ACK);
    CHECK_EQ_U64(m.keepalive_s, 3);
    CHECK_EQ_U64(m.hold_s, 9);
    n = proto_enc_reject(b, sizeof b, 3, PC_BAD_VERSION, "version 2 not supported", 1);
    CHECK(dec(b, n, &m, &c) == PE_OK);
    CHECK_EQ_U64(m.err_code, PC_BAD_VERSION);
    CHECK_STR_EQ(m.err_text, "version 2 not supported");
    CHECK_EQ_U64(m.version_supported, 1);
    n = proto_enc_reject(b, sizeof b, 3, PC_SHUTDOWN, "bye", -1);
    CHECK(dec(b, n, &m, &c) == PE_OK);
    CHECK(!(m.has & (1u << PA_VERSION_SUPPORTED)));
    for (int t = PM_SYNC_BEGIN; t <= PM_SYNC_END; t++) {
        if (t == PM_UPDATE)
            continue;
        n = proto_enc_gen(b, sizeof b, (enum proto_msg)t, 4, 42);
        CHECK(dec(b, n, &m, &c) == PE_OK);
        CHECK_EQ_U64(m.gen, 42);
    }
    n = proto_enc_ack(b, sizeof b, 5, 77);
    CHECK(dec(b, n, &m, &c) == PE_OK);
    CHECK_EQ_U64(m.acked_seq, 77);
    /* BIND / UNBIND / BIND_END */
    struct penc e;
    penc_begin(&e, b, sizeof b, PM_BIND, 6);
    CHECK(penc_binding(&e, "red1", "tap-red1") == 0);
    CHECK(penc_binding(&e, "blue1", "tap-blue1") == 0);
    n = penc_finish(&e);
    CHECK(dec(b, n, &m, &c) == PE_OK);
    CHECK_EQ_U64(c.nbind, 2);
    CHECK_STR_EQ(c.bind[0].vmi, "red1");
    CHECK_STR_EQ(c.bind[1].port, "tap-blue1");
    penc_begin(&e, b, sizeof b, PM_UNBIND, 7);
    CHECK(penc_binding(&e, "red1", NULL) == 0);
    n = penc_finish(&e);
    CHECK(dec(b, n, &m, &c) == PE_OK);
    CHECK_EQ_U64(c.nbind, 1);
    CHECK(!c.bind[0].has_port);
    penc_begin(&e, b, sizeof b, PM_BIND_END, 8);
    n = penc_finish(&e);
    CHECK(dec(b, n, &m, &c) == PE_OK);
}

TEST(every_entry_kind_round_trips_in_update_and_ack_errors) {
    uint8_t b[2048];
    struct pmsg m;
    struct col c;
    struct penc e;
    penc_begin(&e, b, sizeof b, PM_UPDATE, 9);
    penc_u32(&e, PA_GEN, 7);
    for (unsigned k = NE_VRF; k <= NE_ROUTE; k++) {
        struct nentry ne = sample(k);
        CHECK(penc_entry(&e, true, &ne) == 0);  /* key only */
        CHECK(penc_entry(&e, false, &ne) == 0); /* full */
    }
    size_t n = penc_finish(&e);
    CHECK(n > 0);
    CHECK(dec(b, n, &m, &c) == PE_OK);
    CHECK_EQ_U64(m.gen, 7);
    CHECK_EQ_U64(c.nadd, 7);
    CHECK_EQ_U64(c.ndel, 7);
    CHECK_EQ_U64(c.nbad, 0);
    for (unsigned k = 0; k < 7; k++) {
        struct nentry want = sample(k + 1);
        CHECK(ne_key_cmp(&c.add[k], &want) == 0 && ne_val_eq(&c.add[k], &want));
        CHECK(ne_key_cmp(&c.del[k], &want) == 0);
    }
    /* ACK with errors: by entry key and by VMI */
    penc_begin(&e, b, sizeof b, PM_ACK, 10);
    penc_u32(&e, PA_ACKED_SEQ, 9);
    struct perror er;
    memset(&er, 0, sizeof er);
    er.has_entry = true;
    er.key = sample(NE_ROUTE);
    er.code = PC_ENTRY_REJECTED;
    strcpy(er.text, "unknown-vrf: no such VRF 'red'");
    CHECK(penc_error(&e, &er) == 0);
    memset(&er, 0, sizeof er);
    er.has_vmi = true;
    strcpy(er.vmi, "red9");
    er.code = PC_UNKNOWN_VMI;
    CHECK(penc_error(&e, &er) == 0);
    n = penc_finish(&e);
    CHECK(dec(b, n, &m, &c) == PE_OK);
    CHECK_EQ_U64(c.nerr, 2);
    CHECK(c.err[0].has_entry && c.err[0].key.kind == NE_ROUTE);
    CHECK_STR_EQ(c.err[0].text, "unknown-vrf: no such VRF 'red'");
    CHECK(c.err[1].has_vmi && c.err[1].code == PC_UNKNOWN_VMI);
}

TEST(nesting_depth_three_is_structural) {
    uint8_t inner[64], mid[64], ent[128], msg[256];
    size_t ni = 0, nm = 0, ne = 0;
    uint8_t kind = NE_VRF;
    put_attr(inner, &ni, PA_KIND, &kind, 1);
    put_attr(mid, &nm, PA_ENTRY_ADD, inner, ni); /* an entry inside an entry */
    put_entry(ent, &ne, PA_ENTRY_ADD, mid, nm);
    struct pmsg m;
    struct col c;
    CHECK(dec(msg, update_with(msg, ent, ne), &m, &c) == PE_NEST_DEPTH);
    CHECK_EQ_U64(c.nadd, 0);
}

TEST(entry_level_errors_keep_the_message_and_the_other_entries) {
    uint8_t f[128], ents[512], msg[700];
    size_t nf, ne = 0;
    struct pmsg m;
    struct col c;
    uint8_t kind;

    /* a good VRF entry first */
    nf = 0; kind = NE_VRF;
    put_attr(f, &nf, PA_KIND, &kind, 1);
    put_attr(f, &nf, PA_NAME, "red", 3);
    uint8_t one = 1;
    put_attr(f, &nf, PA_ID, &one, 1);
    put_entry(ents, &ne, PA_ENTRY_ADD, f, nf);

    /* ROUTE with host bits in the PREFIX */
    nf = 0; kind = NE_ROUTE;
    put_attr(f, &nf, PA_KIND, &kind, 1);
    put_attr(f, &nf, PA_VRF, "red", 3);
    const uint8_t pfx_host[5] = {10, 1, 1, 5, 24};
    put_attr(f, &nf, PA_PREFIX, pfx_host, 5);
    put_attr(f, &nf, PA_NODE, "cn2", 3);
    uint8_t enc = 1;
    put_attr(f, &nf, PA_ENCAP, &enc, 1);
    const uint8_t tag[4] = {0, 0, 3, 0xf4};
    put_attr(f, &nf, PA_TAG, tag, 4);
    put_entry(ents, &ne, PA_ENTRY_ADD, f, nf);

    /* LABEL 15 */
    nf = 0; kind = NE_LABEL;
    put_attr(f, &nf, PA_KIND, &kind, 1);
    const uint8_t l15[4] = {0, 0, 0, 15};
    put_attr(f, &nf, PA_LABEL, l15, 4);
    put_attr(f, &nf, PA_PORT, "red1", 4);
    put_entry(ents, &ne, PA_ENTRY_ADD, f, nf);

    /* ROUTE without NODE */
    nf = 0; kind = NE_ROUTE;
    put_attr(f, &nf, PA_KIND, &kind, 1);
    put_attr(f, &nf, PA_VRF, "red", 3);
    const uint8_t pfx[5] = {10, 1, 1, 12, 32};
    put_attr(f, &nf, PA_PREFIX, pfx, 5);
    put_attr(f, &nf, PA_ENCAP, &enc, 1);
    put_attr(f, &nf, PA_TAG, tag, 4);
    put_entry(ents, &ne, PA_ENTRY_ADD, f, nf);

    /* KIND 9 */
    nf = 0; kind = 9;
    put_attr(f, &nf, PA_KIND, &kind, 1);
    put_entry(ents, &ne, PA_ENTRY_DEL, f, nf);

    /* duplicate field */
    nf = 0; kind = NE_VRF;
    put_attr(f, &nf, PA_KIND, &kind, 1);
    put_attr(f, &nf, PA_NAME, "blue", 4);
    put_attr(f, &nf, PA_NAME, "blue", 4);
    put_attr(f, &nf, PA_ID, &one, 1);
    put_entry(ents, &ne, PA_ENTRY_ADD, f, nf);

    /* a good delete last */
    nf = 0; kind = NE_VRF;
    put_attr(f, &nf, PA_KIND, &kind, 1);
    put_attr(f, &nf, PA_NAME, "old", 3);
    put_entry(ents, &ne, PA_ENTRY_DEL, f, nf);

    CHECK(dec(msg, update_with(msg, ents, ne), &m, &c) == PE_OK);
    CHECK_EQ_U64(c.nadd, 1);
    CHECK_EQ_U64(c.ndel, 1);
    CHECK_STR_EQ(c.add[0].name, "red");
    CHECK_STR_EQ(c.del[0].name, "old");
    CHECK_EQ_U64(c.nbad, 5);
    CHECK_EQ_U64(c.bad[0], PE_ENTRY_ATTR_VALUE);
    CHECK_EQ_U64(c.bad[1], PE_ENTRY_ATTR_VALUE);
    CHECK_EQ_U64(c.bad[2], PE_ENTRY_ATTR_MISSING);
    CHECK_EQ_U64(c.bad[3], PE_ENTRY_UNKNOWN_KIND);
    CHECK_EQ_U64(c.bad[4], PE_ENTRY_ATTR_DUP);
    CHECK_STR_EQ(proto_err_name(PE_ENTRY_UNKNOWN_KIND), "entry-unknown-kind");
    CHECK(proto_err_is_entry(PE_ENTRY_ATTR_VALUE) && !proto_err_is_entry(PE_ATTR_VALUE));
}

TEST(unknown_attributes_are_skipped) {
    uint8_t body[64], msg[96];
    size_t n = 0;
    const uint8_t junk[3] = {1, 2, 3};
    put_attr(body, &n, 999, junk, 3);
    put_attr(body, &n, PA_GEN, "\0\0\0\x2a", 4);
    put_attr(body, &n, 1234, junk, 1);
    struct pmsg m;
    struct col c;
    CHECK(dec(msg, mk(msg, PM_SYNC_END, 3, body, n), &m, &c) == PE_OK);
    CHECK_EQ_U64(m.gen, 42);
}

TEST(structural_failure_delivers_nothing) {
    uint8_t ents[256], msg[400], f[64];
    size_t nf = 0, ne = 0;
    uint8_t kind = NE_VRF, one = 1;
    put_attr(f, &nf, PA_KIND, &kind, 1);
    put_attr(f, &nf, PA_NAME, "red", 3);
    put_attr(f, &nf, PA_ID, &one, 1);
    put_entry(ents, &ne, PA_ENTRY_ADD, f, nf);
    ents[ne] = 0; ents[ne + 1] = 99; ents[ne + 2] = 0; ents[ne + 3] = 2; /* short attribute */
    ne += 4;
    struct pmsg m;
    struct col c;
    CHECK(dec(msg, update_with(msg, ents, ne), &m, &c) == PE_ATTR_SHORT);
    CHECK_EQ_U64(c.nadd + c.nbad, 0); /* the good entry before it was not delivered either */
}

TEST(encoder_never_exceeds_the_maximum_and_reports_what_fits) {
    static uint8_t big[PROTO_MAX_MSG + 4096];
    struct penc e;
    penc_begin(&e, big, sizeof big, PM_UPDATE, 1);
    penc_u32(&e, PA_GEN, 1);
    struct nentry r = sample(NE_ROUTE);
    unsigned fit = 0;
    for (;;) {
        r.prefix = 0x0a000000u + fit;
        if (penc_entry(&e, false, &r) != 0)
            break;
        fit++;
    }
    size_t n = penc_finish(&e);
    CHECK(n > 0 && n <= PROTO_MAX_MSG);
    CHECK(fit > 1000);
    struct pmsg m;
    CHECK(proto_decode(big, n, &m, NULL, NULL) == PE_OK); /* the maximum-size message decodes */
    uint8_t tiny[16];
    penc_begin(&e, tiny, sizeof tiny, PM_UPDATE, 1);
    CHECK(penc_entry(&e, false, &r) == -1);
    CHECK_EQ_U64(penc_finish(&e), 12); /* nothing was appended, the message is still valid */
    uint8_t none[8];
    penc_begin(&e, none, sizeof none, PM_UPDATE, 1);
    CHECK_EQ_U64(penc_finish(&e), 0);
}

TEST(error_code_names) {
    CHECK_STR_EQ(proto_code_name(PC_UNKNOWN_NODE), "unknown-node");
    CHECK_STR_EQ(proto_code_name(PC_TABLE_FULL), "table-full");
    CHECK_STR_EQ(proto_code_name(99), "?");
}
