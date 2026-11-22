#include "minivr/lpm.h"

#include <string.h>

void lpm_pool_init(struct lpm_pool *t) {
    memset(&t->nodes[0], 0, sizeof t->nodes[0]);
    t->free_head = 0;
    t->next_unused = 1;
    t->rules = 0;
}

static uint32_t node_new(struct lpm_pool *t) {
    uint32_t i;
    if (t->free_head) {
        i = t->free_head;
        t->free_head = t->nodes[i].child[0];
    } else if (t->next_unused < LPM_MAX_NODES) {
        i = t->next_unused++;
    } else {
        return 0;
    }
    memset(&t->nodes[i], 0, sizeof t->nodes[i]);
    return i;
}

static void node_free(struct lpm_pool *t, uint32_t i) {
    t->nodes[i].child[0] = t->free_head;
    t->free_head = i;
}

int lpm_root_init(struct lpm_pool *t, struct lpm_root *r) {
    uint32_t n = node_new(t);
    if (!n)
        return -2;
    r->node = n;
    r->rules = 0;
    return 0;
}

void lpm_root_release(struct lpm_pool *t, struct lpm_root *r) {
    if (r->node)
        node_free(t, r->node);
    r->node = 0;
    r->rules = 0;
}

static unsigned bit(uint32_t ip, unsigned depth) {
    return (ip >> (31 - depth)) & 1u;
}

int lpm_add(struct lpm_pool *t, struct lpm_root *r, uint32_t prefix, uint8_t len, uint32_t value) {
    if (len > 32)
        return -2;
    /* exact-match walk first, without creating anything */
    uint32_t cur = r->node;
    unsigned d;
    for (d = 0; d < len; d++) {
        uint32_t next = t->nodes[cur].child[bit(prefix, d)];
        if (!next)
            break;
        cur = next;
    }
    if (d == len && t->nodes[cur].has_value)
        return -1;
    if (t->rules >= LPM_MAX_RULES)
        return -2;
    /* The pool holds 32 nodes per rule plus the root, so it cannot run dry before the rule
     * limit does (deletes prune unused nodes). */
    for (; d < len; d++) {
        uint32_t n = node_new(t);
        if (!n)
            return -2;
        t->nodes[cur].child[bit(prefix, d)] = n;
        cur = n;
    }
    t->nodes[cur].has_value = 1;
    t->nodes[cur].value = value;
    t->rules++;
    r->rules++;
    return 0;
}

int lpm_del(struct lpm_pool *t, struct lpm_root *r, uint32_t prefix, uint8_t len) {
    if (len > 32)
        return -1;
    uint32_t path[34];
    unsigned n = 0;
    uint32_t cur = r->node;
    path[n++] = cur;
    for (unsigned d = 0; d < len; d++) {
        cur = t->nodes[cur].child[bit(prefix, d)];
        if (!cur)
            return -1;
        path[n++] = cur;
    }
    if (!t->nodes[cur].has_value)
        return -1;
    t->nodes[cur].has_value = 0;
    t->rules--;
    r->rules--;
    while (n > 1) {
        uint32_t node = path[n - 1], parent = path[n - 2];
        if (t->nodes[node].has_value || t->nodes[node].child[0] || t->nodes[node].child[1])
            break;
        unsigned b = t->nodes[parent].child[0] == node ? 0u : 1u;
        t->nodes[parent].child[b] = 0;
        node_free(t, node);
        n--;
    }
    return 0;
}

int lpm_get(const struct lpm_pool *t, const struct lpm_root *r, uint32_t prefix, uint8_t len, uint32_t *value) {
    if (len > 32)
        return 0;
    uint32_t cur = r->node;
    for (unsigned d = 0; d < len; d++) {
        cur = t->nodes[cur].child[bit(prefix, d)];
        if (!cur)
            return 0;
    }
    if (!t->nodes[cur].has_value)
        return 0;
    *value = t->nodes[cur].value;
    return 1;
}

int lpm_lookup(const struct lpm_pool *t, const struct lpm_root *r, uint32_t ip, uint32_t *value, uint8_t *len) {
    uint32_t cur = r->node;
    int hit = 0;
    for (unsigned d = 0;; d++) {
        if (t->nodes[cur].has_value) {
            *value = t->nodes[cur].value;
            if (len)
                *len = (uint8_t)d;
            hit = 1;
        }
        if (d == 32)
            break;
        cur = t->nodes[cur].child[bit(ip, d)];
        if (!cur)
            break;
    }
    return hit;
}

void lpm_walk(const struct lpm_pool *t, const struct lpm_root *r, lpm_walk_fn fn, void *arg) {
    /* iterative pre-order: node, then 0-subtree, then 1-subtree */
    struct {
        uint32_t node, prefix;
        uint8_t depth;
    } stack[66];
    int sp = 0;
    stack[sp].node = r->node;
    stack[sp].prefix = 0;
    stack[sp].depth = 0;
    sp++;
    while (sp > 0) {
        sp--;
        uint32_t node = stack[sp].node, prefix = stack[sp].prefix;
        uint8_t depth = stack[sp].depth;
        if (t->nodes[node].has_value)
            fn(prefix, depth, t->nodes[node].value, arg);
        if (depth == 32)
            continue;
        uint32_t c1 = t->nodes[node].child[1], c0 = t->nodes[node].child[0];
        if (c1) {
            stack[sp].node = c1;
            stack[sp].prefix = prefix | (1u << (31 - depth));
            stack[sp].depth = (uint8_t)(depth + 1);
            sp++;
        }
        if (c0) {
            stack[sp].node = c0;
            stack[sp].prefix = prefix;
            stack[sp].depth = (uint8_t)(depth + 1);
            sp++;
        }
    }
}

uint32_t lpm_count(const struct lpm_root *r) {
    return r->rules;
}

uint32_t lpm_pool_count(const struct lpm_pool *t) {
    return t->rules;
}
