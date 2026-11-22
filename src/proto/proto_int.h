#ifndef MINIVR_PROTO_INT_H
#define MINIVR_PROTO_INT_H
#include "minivr/proto.h"

/* One attribute as found by the walker. */
struct pattr {
    uint16_t type;
    const uint8_t *val;
    size_t vlen; /* length without the 4-byte header and padding */
};

/* Next attribute of a region (netlink-style TLV, 4-byte padding). Returns PE_OK with *got = true,
 * PE_OK with *got = false at the end, or a structural error (attr-short, attr-overrun). */
enum proto_err pattr_next(const uint8_t **p, size_t *left, struct pattr *a, bool *got);

/* Fields found inside a nested attribute (entry, binding or error). */
struct pfields {
    struct nentry e;
    char vmi[NE_NAME];
    uint16_t code;
    char text[PROTO_TEXT_MAX + 1];
    uint64_t seen; /* bit = attribute type (all field types are < 64) */
    enum proto_err entry_err; /* first entry-level problem, PE_OK if none so far */
};

/* Walks the fields of one nested attribute. Structural problems (short/overrun, a nested
 * attribute inside a field = nest-depth) are returned; value, duplicate and kind problems are
 * recorded in f->entry_err and the walk continues. `f` must be zeroed by the caller. */
enum proto_err pf_parse(const uint8_t *p, size_t n, struct pfields *f);
/* After pf_parse: checks KIND and the required fields (all of them for an add, the key for a
 * delete) and the value rules that need several fields. Returns PE_OK or the entry-level reason. */
enum proto_err pf_check_entry(const struct pfields *f, bool is_del);

bool proto_str_ok(const uint8_t *v, size_t n); /* 1..15 bytes of [a-z0-9_-] */
#endif
