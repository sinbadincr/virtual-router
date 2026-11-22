#ifndef MINIVR_PORT_H
#define MINIVR_PORT_H
#include <stdbool.h>
#include <stdint.h>

#include "cmd.h"
#include "owner.h"
#include "ratelimit.h"
#include "stats.h"

struct pio_ops;

enum port_role { PORT_VM, PORT_UNDERLAY };

struct port {
    uint8_t id;
    bool in_use;
    char name[16];
    char ifname[16];
    enum port_role role;
    uint8_t owner; /* enum owner */
    uint8_t vrf; /* VM ports: VRF id; underlay: 0 and unused */
    uint8_t mac[6];
    uint32_t ip; /* host byte order */
    uint8_t prefix_len;
    uint16_t mtu;
    bool admin_up, oper_up;
    struct token_bucket icmp_bucket; /* ICMP error limiter (FR-011a) */
    void *pio; /* backend handle */
};

/* Select the packet I/O backend used by port_add (daemon: AF_PACKET, tests: fake). */
void port_set_backend(const struct pio_ops *ops);
const struct pio_ops *port_backend(void);

/* Config-time creation. Returns the port or NULL with err set:
 * table-full (>16 VM ports), exists (name taken, interface used, address shared with a different
 * prefix inside one VRF, or a second underlay), unknown-vrf, bad-syntax (name/ifname too long),
 * not-found (interface cannot be opened). A VM port gets its connected route in its VRF. */
struct port *port_add(const char *name, const char *ifname, uint32_t ip, uint8_t prefix_len,
                      enum port_role role, unsigned vrf, struct cmd_err *err);
/* Runtime creation from a socket the agent opened (phase 3). *fd is consumed (set to -1) once the
 * backend owns it; on any failure before that the caller still owns and must close it. Same
 * errors as port_add, plus bad-fd when the backend cannot wrap the socket. */
struct port *port_add_adopted(const char *name, const char *ifname, int *fd, uint32_t ip,
                              uint8_t prefix_len, unsigned vrf, struct cmd_err *err);
/* Delete a VM port with its connected/host routes, neighbours (held packets counted as
 * port_deleted) and label mappings. Errors: immutable (underlay), busy (a static route uses it). */
int port_del(struct port *p, struct cmd_err *err);
/* Move a VM port to another VRF (flushes learned neighbours; its static neighbour, /32 host
 * route and connected route move with it). Errors: bad-syntax (underlay), unknown-vrf, exists,
 * busy (a static route still names the port). */
int port_set_vrf(struct port *p, unsigned vrf, struct cmd_err *err);
struct port *port_find(const char *name);
struct port *port_by_ip(unsigned vrf, uint32_t ip); /* first VM port of the VRF with this gateway */
struct port *port_underlay(void);                   /* NULL when none is configured */
struct port *port_get(uint8_t id);
unsigned port_count(void);
unsigned port_count_in_vrf(unsigned vrf); /* VM ports only */
uint32_t port_netmask(const struct port *p);
/* Hooks for the daemon to (un)register a port's fd with its event loop when a runtime port is
 * added or deleted (the dp itself does no I/O). `removed` runs before the backend closes it. */
void port_set_hooks(void (*added)(struct port *p), void (*removed)(struct port *p));
void port_close_all(void);
void port_reset(void); /* tests: close and forget every port */
#endif
