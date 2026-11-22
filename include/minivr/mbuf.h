#ifndef MINIVR_MBUF_H
#define MINIVR_MBUF_H
#include <stddef.h>
#include <stdint.h>

#define MBUF_POOL_SIZE 4096
#define MBUF_DATA_SIZE 2048
#define MBUF_HEADROOM 128
#define MBUF_NO_PORT 0xff

struct mbuf {
    struct mbuf *next; /* free list / hold-queue link */
    uint16_t off;      /* start of frame inside buf */
    uint16_t len;      /* frame length; off + len <= MBUF_DATA_SIZE */
    uint8_t in_port;
    uint8_t allocated;
    uint8_t vlan_tagged; /* an 802.1Q tag was stripped by the kernel before we saw the frame */
    /* Set by encap.c: the frame is a tunnel packet. inner_off = offset from the frame start to the
     * inner IPv4 header, src_mac = Ethernet source of the original (tenant) frame, kept so an ICMP
     * error for a held packet can still be built after the outer headers replaced them. */
    uint16_t inner_off;
    uint8_t src_mac[6];
    _Alignas(64) uint8_t buf[MBUF_DATA_SIZE];
};

int mbuf_pool_init(size_t n); /* allocates once; 0 on success */
void mbuf_pool_fini(void);
struct mbuf *mbuf_alloc(void); /* NULL when exhausted */
void mbuf_free(struct mbuf *m);
size_t mbuf_in_use(void);
size_t mbuf_pool_total(void);

static inline uint8_t *mbuf_data(struct mbuf *m) {
    return m->buf + m->off;
}
static inline size_t mbuf_tailroom(const struct mbuf *m) {
    return (size_t)MBUF_DATA_SIZE - m->off - m->len;
}
#endif
