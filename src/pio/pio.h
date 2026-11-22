#ifndef MINIVR_PIO_H
#define MINIVR_PIO_H
#include <stdint.h>

#include "minivr/mbuf.h"

/* Packet I/O backend interface (research R2). AF_PACKET now, DPDK later.
 * A backend owns one handle per port. Ownership rules:
 *   rx_burst: fills m[] with freshly allocated mbufs (caller frees/forwards them);
 *   tx_burst: takes ownership of all n mbufs (frees them) and returns how many were sent;
 *             the rest are counted as tx_error by the backend. */
struct pio_ops {
    const char *name;
    void *(*open)(const char *ifname);          /* NULL on failure (errno set) */
    void (*close)(void *h);
    int (*rx_burst)(void *h, struct mbuf **m, int max); /* count, 0 if none, <0 on error */
    int (*tx_burst)(void *h, struct mbuf **m, int n);
    int (*fd)(void *h);                         /* pollable fd, -1 if none */
    int (*get_mac)(void *h, uint8_t mac[6]);    /* 0 on success */
    int (*get_mtu)(void *h);                    /* MTU or <0 */
    /* Wrap an already open socket (runtime ports, phase 3); ownership of fd passes to the handle
     * on success, the caller keeps it on failure. NULL when unsupported. */
    void *(*adopt)(int fd, const char *ifname);
};

#define PIO_BURST 32

extern const struct pio_ops pio_afpacket_ops;

/* Open a bound, configured AF_PACKET socket for `ifname` (needs CAP_NET_RAW); -1 on failure. */
int afp_socket_open(const char *ifname);
#endif
