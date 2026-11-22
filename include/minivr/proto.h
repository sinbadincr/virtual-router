#ifndef MINIVR_PROTO_H
#define MINIVR_PROTO_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nodestate.h"

/* Agent <-> controller protocol v1 (contracts/protocol.md, docs/protocol.md). Pure code: every
 * function works on caller buffers, validates every length against the buffer, never allocates. */

#define PROTO_VERSION 1
#define PROTO_HDR 12
#define PROTO_MAX_MSG 65536
#define PROTO_TEXT_MAX 200

enum proto_msg {
    PM_HELLO = 1, PM_HELLO_ACK, PM_REJECT, PM_BIND, PM_UNBIND, PM_BIND_END, PM_SYNC_BEGIN,
    PM_UPDATE, PM_SYNC_END, PM_ACK, PM_KEEPALIVE, PM_MAX = PM_KEEPALIVE
};

enum proto_attr {
    PA_NODE_NAME = 1, PA_UNDERLAY_IP = 2, PA_RMAC = 3, PA_KEEPALIVE_S = 4, PA_HOLD_S = 5,
    PA_ERR_CODE = 6, PA_ERR_TEXT = 7, PA_VERSION_SUPPORTED = 8, PA_GEN = 9, PA_ACKED_SEQ = 10,
    PA_BINDING = 20, PA_ENTRY_ADD = 21, PA_ENTRY_DEL = 22, PA_ERROR = 23,
    PA_KIND = 30, PA_NAME = 31, PA_ID = 32, PA_VNI = 33, PA_VRF = 34, PA_IP = 35, PA_PREFIX = 36,
    PA_MAC = 37, PA_PORT = 38, PA_LABEL = 39, PA_ENCAP = 40, PA_TAG = 41, PA_NODE = 42, PA_VMI = 43
};

/* Decode reasons. The first group is structural (the message is undecodable, the session closes);
 * PE_ENTRY_* reject one entry and leave the session up. Each has a counter named by proto_err_name. */
enum proto_err {
    PE_OK = 0,
    PE_TRUNCATED, PE_BAD_VERSION, PE_BAD_FLAGS, PE_BAD_LENGTH, PE_TOO_LARGE, PE_UNKNOWN_TYPE,
    PE_UNEXPECTED, PE_ATTR_SHORT, PE_ATTR_OVERRUN, PE_ATTR_SIZE, PE_ATTR_VALUE, PE_ATTR_MISSING,
    PE_ATTR_DUP, PE_NEST_DEPTH, PE_HOLD_EXPIRED,
    PE_ENTRY_ATTR_VALUE, PE_ENTRY_ATTR_MISSING, PE_ENTRY_ATTR_DUP, PE_ENTRY_UNKNOWN_KIND,
    PE_COUNT
};
const char *proto_err_name(enum proto_err e);
bool proto_err_is_entry(enum proto_err e);

/* ERR_CODE values */
enum proto_code {
    PC_BAD_VERSION = 1, PC_UNKNOWN_NODE, PC_DUPLICATE_SESSION, PC_MALFORMED, PC_UNEXPECTED,
    PC_HOLD_EXPIRED, PC_SLOW_PEER, PC_UNKNOWN_VMI, PC_PORT_IN_USE, PC_ENTRY_REJECTED, PC_SHUTDOWN,
    PC_BAD_ENTRY, PC_TABLE_FULL
};
const char *proto_code_name(unsigned code); /* "bad-version", ... or "?" */

/* ---- decoding ---- */

struct pmsg {
    uint8_t type;
    uint32_t seq;
    uint32_t has; /* bit (1 << attr type) for each scalar attribute present, types 1..10 */
    char node_name[NE_NAME];
    uint32_t underlay_ip;
    uint8_t rmac[6];
    uint16_t keepalive_s, hold_s;
    uint16_t err_code;
    char err_text[PROTO_TEXT_MAX + 1];
    uint8_t version_supported;
    uint32_t gen, acked_seq;
};

struct pbinding {
    char vmi[NE_NAME];
    char port[NE_NAME];
    bool has_port;
};

struct perror {
    bool has_entry; /* key identifies an entry */
    struct nentry key;
    bool has_vmi;
    char vmi[NE_NAME];
    uint16_t code;
    char text[PROTO_TEXT_MAX + 1];
};

/* Called while a structurally valid message is walked a second time; any callback may be NULL. */
struct proto_sink {
    void (*binding)(void *arg, const struct pbinding *b);
    void (*entry)(void *arg, bool is_del, const struct nentry *e);
    void (*error)(void *arg, const struct perror *e);
    /* one entry/binding/error rejected on its own (reason is a PE_ENTRY_* value) */
    void (*bad_entry)(void *arg, enum proto_err why);
};

/* Validate the 12-byte header (version, flags, length range, type) before reading the body.
 * Returns PE_OK and fills type/length/seq. */
enum proto_err proto_hdr_check(const uint8_t hdr[PROTO_HDR], uint8_t *type, uint32_t *length,
                               uint32_t *seq);
/* Decode one whole message (len == header length). Walks it twice: first to validate every
 * attribute structurally (nothing is delivered if that fails), then to fill `m` and call `sink`. */
enum proto_err proto_decode(const uint8_t *buf, size_t len, struct pmsg *m,
                            const struct proto_sink *sink, void *arg);

/* ---- encoding ---- */

struct penc {
    uint8_t *buf;
    size_t cap, len;
    bool overflow; /* a call did not fit; the message is unusable */
};

/* Start a message; the effective capacity is min(cap, PROTO_MAX_MSG). */
void penc_begin(struct penc *e, uint8_t *buf, size_t cap, enum proto_msg type, uint32_t seq);
void penc_u8(struct penc *e, enum proto_attr a, uint8_t v);
void penc_u16(struct penc *e, enum proto_attr a, uint16_t v);
void penc_u32(struct penc *e, enum proto_attr a, uint32_t v);
void penc_str(struct penc *e, enum proto_attr a, const char *s);
void penc_bytes(struct penc *e, enum proto_attr a, const void *p, size_t n);
/* Appends an ENTRY_ADD (full) or ENTRY_DEL (key only). Returns 0, or -1 when it does not fit, in
 * which case nothing was appended and the caller finishes this message and starts the next one. */
int penc_entry(struct penc *e, bool is_del, const struct nentry *ne);
int penc_binding(struct penc *e, const char *vmi, const char *port /* NULL in UNBIND */);
int penc_error(struct penc *e, const struct perror *er);
/* Fills in the length; returns the message size, or 0 when anything overflowed. */
size_t penc_finish(struct penc *e);

/* Convenience encoders; return the message size or 0 when it does not fit. */
size_t proto_enc_keepalive(uint8_t *buf, size_t cap, uint32_t seq);
size_t proto_enc_hello(uint8_t *buf, size_t cap, uint32_t seq, const char *node, uint32_t ip,
                       const uint8_t rmac[6]);
size_t proto_enc_hello_ack(uint8_t *buf, size_t cap, uint32_t seq, uint16_t keepalive_s,
                           uint16_t hold_s);
size_t proto_enc_reject(uint8_t *buf, size_t cap, uint32_t seq, uint16_t code, const char *text,
                        int version_supported /* -1: omit */);
size_t proto_enc_gen(uint8_t *buf, size_t cap, enum proto_msg type, uint32_t seq, uint32_t gen);
size_t proto_enc_ack(uint8_t *buf, size_t cap, uint32_t seq, uint32_t acked_seq);

#endif
