#ifndef MINIVR_LPM_H
#define MINIVR_LPM_H
#include <stdint.h>

#define LPM_MAX_RULES 10000
#define LPM_MAX_ROOTS 64 /* one root per VRF */
#define LPM_MAX_NODES (LPM_MAX_RULES * 32 + LPM_MAX_ROOTS + 1)

/* 16 bytes, so a 64-byte cache line holds 4 nodes and the array is cache-line aligned below: a
 * lookup follows at most 32 dependent child links, so the layout is about keeping each hop to at
 * most one line (siblings/children allocated close together are likely to share one). */
struct lpm_node {
    uint32_t child[2]; /* 0 = none */
    uint32_t value;
    uint8_t has_value;
};
_Static_assert(sizeof(struct lpm_node) == 16, "4 trie nodes per cache line");

/* Binary trie over a pre-allocated node pool shared by every VRF (no allocation after init).
 * Each VRF owns one root; the 10,000-rule limit is per pool, i.e. across all VRFs. Node 0 is the
 * "none" link, so a root is a node index >= 1. */
struct lpm_pool {
    _Alignas(64) struct lpm_node nodes[LPM_MAX_NODES];
    uint32_t free_head; /* free list through child[0] */
    uint32_t next_unused;
    uint32_t rules; /* across all roots */
};

struct lpm_root {
    uint32_t node;  /* 0 = not allocated */
    uint32_t rules; /* rules in this root */
};

typedef void (*lpm_walk_fn)(uint32_t prefix, uint8_t len, uint32_t value, void *arg);

void lpm_pool_init(struct lpm_pool *p);
int lpm_root_init(struct lpm_pool *p, struct lpm_root *r); /* 0, -2 pool exhausted */
void lpm_root_release(struct lpm_pool *p, struct lpm_root *r); /* root must be empty */

int lpm_add(struct lpm_pool *p, struct lpm_root *r, uint32_t prefix, uint8_t len,
            uint32_t value); /* 0, -1 exists, -2 full */
int lpm_del(struct lpm_pool *p, struct lpm_root *r, uint32_t prefix, uint8_t len); /* 0, -1 not found */
int lpm_get(const struct lpm_pool *p, const struct lpm_root *r, uint32_t prefix, uint8_t len,
            uint32_t *value); /* exact, 1/0 */
int lpm_lookup(const struct lpm_pool *p, const struct lpm_root *r, uint32_t ip, uint32_t *value,
               uint8_t *len); /* 1 hit, 0 miss */
void lpm_walk(const struct lpm_pool *p, const struct lpm_root *r, lpm_walk_fn fn,
              void *arg); /* prefix order, shorter first */
uint32_t lpm_count(const struct lpm_root *r);
uint32_t lpm_pool_count(const struct lpm_pool *p);
#endif
