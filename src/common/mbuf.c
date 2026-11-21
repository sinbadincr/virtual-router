#include "minivr/mbuf.h"

#include <assert.h>
#include <stdlib.h>

static struct mbuf *pool;
static struct mbuf *free_head;
static size_t total, in_use;

int mbuf_pool_init(size_t n) {
    if (pool || n == 0)
        return -1;
    pool = aligned_alloc(64, n * sizeof(struct mbuf));
    if (!pool)
        return -1;
    total = n;
    in_use = 0;
    free_head = NULL;
    for (size_t i = n; i-- > 0;) {
        pool[i].allocated = 0;
        pool[i].next = free_head;
        free_head = &pool[i];
    }
    return 0;
}

void mbuf_pool_fini(void) {
    free(pool);
    pool = NULL;
    free_head = NULL;
    total = in_use = 0;
}

struct mbuf *mbuf_alloc(void) {
    struct mbuf *m = free_head;
    if (!m)
        return NULL;
    free_head = m->next;
    m->next = NULL;
    m->off = MBUF_HEADROOM;
    m->inner_off = 0;
    m->len = 0;
    m->in_port = MBUF_NO_PORT;
    m->allocated = 1;
    m->vlan_tagged = 0;
    in_use++;
    return m;
}

void mbuf_free(struct mbuf *m) {
    if (!m)
        return;
    assert(m->allocated && "double free of mbuf");
    m->allocated = 0;
    m->next = free_head;
    free_head = m;
    in_use--;
}

size_t mbuf_in_use(void) {
    return in_use;
}

size_t mbuf_pool_total(void) {
    return total;
}
