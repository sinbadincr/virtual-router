#ifndef MINIVR_NODESTATE_H
#define MINIVR_NODESTATE_H
#include <stdbool.h>
#include <stdint.h>

/* Node state (data-model §3): a keyed set of entries, computed by the controller, sent over the
 * wire and reconciled by the agent. Pure code: caller-provided storage, no I/O, no allocation. */

#define NE_NAME 16 /* 1..15 characters plus NUL */

enum ne_kind { NE_VRF = 1, NE_VNI, NE_NODE, NE_PORT, NE_NEIGH, NE_LABEL, NE_ROUTE, NE_KIND_MAX = NE_ROUTE };
enum ne_encap { NE_ENCAP_MPLSOUDP = 1, NE_ENCAP_VXLAN = 2 };

/* Fields not used by `kind` are zero, so whole-struct comparison of the used fields is exact.
 *   VRF   key name              value id
 *   VNI   key vni               value vrf
 *   NODE  key name              value ip, rmac
 *   PORT  key name              value vrf, prefix (gateway address), plen (subnet length)
 *   NEIGH key (vrf, ip)         value mac, port
 *   LABEL key label             value port
 *   ROUTE key (vrf, prefix/plen) value node, encap, tag
 */
struct nentry {
    uint8_t kind;
    uint8_t id;
    uint8_t plen;
    uint8_t encap;
    uint8_t owner; /* enum owner of the forwarder entry this was read from (agent only; not compared) */
    uint32_t vni;
    uint32_t ip;
    uint32_t prefix;
    uint32_t label;
    uint32_t tag;
    uint8_t mac[6];
    uint8_t rmac[6];
    char name[NE_NAME];
    char vrf[NE_NAME];
    char port[NE_NAME];
    char node[NE_NAME];
};

const char *ne_kind_name(unsigned kind); /* "vrf", ... or "?" */
int ne_key_cmp(const struct nentry *a, const struct nentry *b); /* kind, then key */
bool ne_val_eq(const struct nentry *a, const struct nentry *b); /* value fields of the kind */
bool ne_name_ok(const char *s); /* 1..15 of [a-z0-9_-] */

struct nstate {
    struct nentry *e; /* sorted by ne_key_cmp */
    unsigned n, cap;
};

void ns_init(struct nstate *s, struct nentry *storage, unsigned cap);
void ns_clear(struct nstate *s);
int ns_put(struct nstate *s, const struct nentry *e); /* insert or replace by key; -1 when full */
int ns_del(struct nstate *s, const struct nentry *key); /* 0, or -1 when absent */
const struct nentry *ns_get(const struct nstate *s, const struct nentry *key);
unsigned ns_count(const struct nstate *s);
const struct nentry *ns_at(const struct nstate *s, unsigned i); /* sorted iteration */
bool ns_equal(const struct nstate *a, const struct nstate *b);
int ns_copy(struct nstate *dst, const struct nstate *src); /* -1 when dst is too small */

/* Caller-provided output arrays. dels carry the key (full entry of S); adds carry the new value. */
struct ndiff {
    struct nentry *dels, *adds;
    unsigned ndels, nadds, dcap, acap;
};
/* dels = keys in S not in D; adds = entries of D that are new or changed. -1 on overflow. */
int ns_diff(const struct nstate *have, const struct nstate *want, struct ndiff *out);
/* Apply a diff to `s` (dels first, then adds). */
int ns_apply(struct nstate *s, const struct ndiff *d);

/* dotted quad, aa:bb:cc:dd:ee:ff, a.b.c.d/len (no stdio: these live in the pure library) */
void ne_ip_str(uint32_t ip, char out[16]);
void ne_mac_str(const uint8_t m[6], char out[18]);
void ne_prefix_str(uint32_t ip, uint8_t len, char out[20]);
#endif
