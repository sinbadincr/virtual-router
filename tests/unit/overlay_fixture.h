/* Overlay fixture: one compute node of the two-node lab, configured from the shipped
 * lab/overlay/cnN.conf (so tests and the lab cannot drift apart). */
#ifndef OVERLAY_FIXTURE_H
#define OVERLAY_FIXTURE_H
#include "fixture.h"
#include "minivr/config.h"
#include "minivr/tunnel.h"
#include "minivr/vrf.h"

static const uint8_t OV_UL_MAC1[6] = {2, 0, 0, 0xff, 0, 1};
static const uint8_t OV_UL_MAC2[6] = {2, 0, 0, 0xff, 0, 2};
/* VM (guest) MACs of contracts/lab-overlay.md */
static const uint8_t OV_RED1[6] = {2, 0, 0, 1, 1, 0x11};
static const uint8_t OV_BLUE1[6] = {2, 0, 0, 2, 1, 0x11};
static const uint8_t OV_RED2[6] = {2, 0, 0, 1, 2, 0x12};
static const uint8_t OV_RED3[6] = {2, 0, 0, 1, 2, 0x13};
static const uint8_t OV_BLUE2[6] = {2, 0, 0, 2, 2, 0x12};

/* Forwarder-side MAC of a port: 02:00:00:0a:<node>:<index>. */
static inline void ov_port_mac(uint8_t out[6], int node, int idx) {
    uint8_t m[6] = {2, 0, 0, 0x0a, (uint8_t)node, (uint8_t)idx};
    memcpy(out, m, 6);
}

static inline void ov_reset(void) {
    clock_set_fake(1000 * NS_PER_SEC);
    if (!mbuf_pool_total())
        mbuf_pool_init(MBUF_POOL_SIZE);
    stats_clear();
    port_reset();
    route_reset();
    neigh_reset();
    pio_fake_reset();
    ratelimit_configure(RL_DEFAULT_RATE, RL_DEFAULT_BURST);
}

/* node 1 = cn1 (red1, blue1), node 2 = cn2 (red2, red3, blue2). Returns config_load's result. */
static inline int ov_setup(int node, int underlay_mtu) {
    ov_reset();
    static const char *const names1[] = {"red1", "blue1"};
    static const char *const names2[] = {"red2", "red3", "blue2"};
    const char *const *names = node == 1 ? names1 : names2;
    int n = node == 1 ? 2 : 3;
    uint8_t mac[6];
    for (int i = 0; i < n; i++) {
        ov_port_mac(mac, node, i + 1);
        pio_fake_add_if(names[i], mac, 1500);
    }
    pio_fake_add_if("u0", node == 1 ? OV_UL_MAC1 : OV_UL_MAC2, underlay_mtu);
    port_set_backend(&pio_fake_ops);
    return config_load(node == 1 ? MINIVR_SOURCE_DIR "/lab/overlay/cn1.conf"
                                 : MINIVR_SOURCE_DIR "/lab/overlay/cn2.conf");
}

static inline void ov_teardown(void) {
    fx_teardown();
}

static inline int ov_cmd(enum cmd_where where, const char *line, struct cmd_err *e) {
    char buf[2048];
    struct jw w;
    jw_init(&w, buf, sizeof buf);
    return cmd_exec(line, where, &w, e);
}

static inline void ov_rx(const char *port, const uint8_t *frame, size_t len) {
    struct port *p = port_find(port);
    pio_fake_inject(p->pio, frame, len);
    struct mbuf *burst[PIO_BURST];
    int n = port_backend()->rx_burst(p->pio, burst, PIO_BURST);
    forward_burst(p, burst, n);
}
static inline size_t ov_tx_count(const char *port) {
    return pio_fake_tx_count(port_find(port)->pio);
}
static inline const uint8_t *ov_tx(const char *port, size_t idx, size_t *len) {
    return pio_fake_tx_frame(port_find(port)->pio, idx, len);
}
static inline void ov_clear_tx(void) {
    for (unsigned i = 0; i < MAX_PORTS; i++) {
        struct port *p = port_get((uint8_t)i);
        if (p)
            pio_fake_clear_tx(p->pio);
    }
}
#endif
