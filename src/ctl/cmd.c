#include "minivr/cmd.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "minivr/clock.h"
#include "minivr/mbuf.h"
#include "minivr/neigh.h"
#include "minivr/owner.h"
#include "minivr/port.h"
#include "minivr/ratelimit.h"
#include "minivr/route.h"
#include "minivr/stats.h"
#include "minivr/tunnel.h"
#include "minivr/vrf.h"

#define MINIVR_VERSION "0.1.0"
#define PROTOCOL_VERSION 1

static uint64_t start_ns;

void cmd_init(void) {
    start_ns = clock_now_ns();
}

int cmd_fail(struct cmd_err *err, const char *code, const char *fmt, ...) {
    err->code = code;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err->message, sizeof err->message, fmt, ap);
    va_end(ap);
    return -1;
}

/* ---- tokenizer and typed parsers ---- */

int cmd_tokenize(char *line, char **argv, int max) {
    int n = 0;
    char *p = line;
    for (;;) {
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            return n;
        if (n == max)
            return -1;
        argv[n++] = p;
        while (*p && *p != ' ' && *p != '\t')
            p++;
        if (!*p)
            return n;
        *p++ = 0;
    }
}

/* Parses a decimal in [0, max] consuming only digits; returns pointer after it or NULL. */
static const char *scan_dec(const char *s, unsigned max, unsigned *out) {
    if (*s < '0' || *s > '9')
        return NULL;
    unsigned long v = 0;
    int digits = 0;
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (unsigned long)(*s - '0');
        if (++digits > 10 || v > max)
            return NULL;
        s++;
    }
    *out = (unsigned)v;
    return s;
}

static int parse_quad(const char *s, const char **end, uint32_t *ip) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        unsigned o;
        const char *e = scan_dec(s, 255, &o);
        if (!e || e - s > 3)
            return -1;
        v = (v << 8) | o;
        s = e;
        if (i < 3) {
            if (*s != '.')
                return -1;
            s++;
        }
    }
    *ip = v;
    *end = s;
    return 0;
}

const char *cmd_parse_ipv4(const char *s, uint32_t *ip) {
    const char *end;
    if (parse_quad(s, &end, ip) != 0 || *end)
        return "bad-address";
    return NULL;
}

static const char *parse_cidr(const char *s, uint32_t *ip, uint8_t *len, int allow_host_bits) {
    const char *end;
    uint32_t a;
    unsigned l;
    if (parse_quad(s, &end, &a) != 0 || *end != '/')
        return "bad-prefix";
    const char *e2 = scan_dec(end + 1, 32, &l);
    if (!e2 || *e2)
        return "bad-prefix";
    uint32_t mask = l == 0 ? 0 : ~0U << (32 - l);
    if (!allow_host_bits && (a & ~mask))
        return "bad-prefix";
    *ip = a;
    *len = (uint8_t)l;
    return NULL;
}

const char *cmd_parse_prefix(const char *s, uint32_t *ip, uint8_t *len) {
    return parse_cidr(s, ip, len, 0);
}

const char *cmd_parse_mac(const char *s, uint8_t mac[6]) {
    if (strlen(s) != 17)
        return "bad-mac";
    for (int i = 0; i < 6; i++) {
        unsigned v = 0;
        for (int j = 0; j < 2; j++) {
            char c = s[i * 3 + j];
            unsigned d;
            if (c >= '0' && c <= '9')
                d = (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f')
                d = (unsigned)(c - 'a') + 10;
            else if (c >= 'A' && c <= 'F')
                d = (unsigned)(c - 'A') + 10;
            else
                return "bad-mac";
            v = v * 16 + d;
        }
        if (i < 5 && s[i * 3 + 2] != ':')
            return "bad-mac";
        mac[i] = (uint8_t)v;
    }
    return NULL;
}

const char *cmd_parse_uint(const char *s, uint64_t min, uint64_t max, uint64_t *out) {
    if (*s < '0' || *s > '9')
        return "bad-syntax";
    uint64_t v = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9')
            return "bad-syntax";
        unsigned d = (unsigned)(*s - '0');
        if (v > (UINT64_MAX - d) / 10)
            return "bad-syntax";
        v = v * 10 + d;
    }
    if (v < min || v > max)
        return "bad-syntax";
    *out = v;
    return NULL;
}

/* ---- handlers ---- */

struct cmd_ctx {
    struct jw *out;
    struct cmd_err *err;
    struct cmd_session *sess; /* NULL for the config file and the plain cmd_exec() path */
    enum owner who;
    enum cmd_where where;
};

static cmd_fd_checker fd_checker;
static char boot_id[17];

void cmd_set_fd_checker(cmd_fd_checker fn) {
    fd_checker = fn;
}

void cmd_set_boot_id(const char *hex16) {
    snprintf(boot_id, sizeof boot_id, "%s", hex16);
}

/* `del`/`replace`/`set` from the agent session only touch agent-owned entries. */
static int check_owner(struct cmd_ctx *c, int entry_owner) {
    if (c->who == OWNER_AGENT && entry_owner >= 0 && entry_owner != OWNER_AGENT)
        return cmd_fail(c->err, "not-owner", "entry is owned by %s, not the agent",
                        owner_name((enum owner)entry_owner));
    return 0;
}

typedef int (*cmd_fn)(struct cmd_ctx *c, int argc, char **argv);

static int usage(struct cmd_ctx *c, const char *u) {
    return cmd_fail(c->err, "bad-syntax", "usage: %s", u);
}

static int resolve_vrf(struct cmd_ctx *c, const char *name, unsigned *id) {
    const struct vrf *v = vrf_by_name(name);
    if (!v)
        return cmd_fail(c->err, "unknown-vrf", "no such VRF '%s'", name);
    *id = v->id;
    return 0;
}

static int cmd_vrf_add(struct cmd_ctx *c, int argc, char **argv) {
    static const char *u = "vrf add <name> id <1-63>";
    if (argc != 5 || strcmp(argv[3], "id") != 0)
        return usage(c, u);
    uint64_t id;
    const char *e = cmd_parse_uint(argv[4], 0, 1000, &id);
    if (e)
        return cmd_fail(c->err, e, "VRF id must be a number 1..%d", VRF_MAX - 1);
    return vrf_add(argv[2], (unsigned)id, c->err);
}

static int cmd_vrf_del(struct cmd_ctx *c, int argc, char **argv) {
    if (argc != 3)
        return usage(c, "vrf del <name>");
    const struct vrf *old = vrf_by_name(argv[2]);
    if (old && check_owner(c, old->owner) != 0)
        return -1;
    return vrf_del(argv[2], c->err);
}

static int add_port(struct cmd_ctx *c, int argc, char **argv, enum port_role role) {
    /* port add <name> ifname <if> ip <a.b.c.d/len> [vrf <v>]    underlay add: no vrf */
    static const char *u_port = "port add <name> ifname <if> ip <a.b.c.d/len> [vrf <vrf>]";
    static const char *u_ul = "underlay add <name> ifname <if> ip <a.b.c.d/len>";
    const char *u = role == PORT_VM ? u_port : u_ul;
    int base = 7;
    bool has_fd = role == PORT_VM && argc > 2 && strcmp(argv[argc - 1], "fd") == 0;
    if (has_fd)
        argc--;
    if (c->where == CMD_CLI && !has_fd)
        return cmd_fail(c->err, "config-only", "'%s' is only valid in the config file",
                        role == PORT_VM ? "port add" : "underlay add");
    if (c->where == CMD_CONFIG && has_fd)
        return cmd_fail(c->err, "bad-syntax", "'fd' is only valid on the agent session");
    if ((argc != base && !(role == PORT_VM && argc == 9)) || strcmp(argv[3], "ifname") != 0 ||
        strcmp(argv[5], "ip") != 0 || (argc == 9 && strcmp(argv[7], "vrf") != 0))
        return usage(c, u);
    uint32_t ip;
    uint8_t len;
    const char *e = parse_cidr(argv[6], &ip, &len, 1);
    if (e)
        return cmd_fail(c->err, e, "invalid interface address '%s'", argv[6]);
    unsigned vrf = VRF_DEFAULT;
    if (argc == 9 && resolve_vrf(c, argv[8], &vrf) != 0)
        return -1;
    if (!has_fd)
        return port_add(argv[2], argv[4], ip, len, role, vrf, c->err) ? 0 : -1;
    /* runtime port: the socket arrived with the request (SCM_RIGHTS) */
    if (!c->sess || c->sess->role != CMD_ROLE_AGENT)
        return cmd_fail(c->err, "not-permitted", "'port add ... fd' needs the agent session");
    int fd = c->sess->fd_in;
    if (fd < 0)
        return cmd_fail(c->err, "bad-syntax", "'port add ... fd' needs a socket passed with the request");
    c->sess->fd_in = -1; /* consumed: closed here on any error, owned by the backend on success */
    if (fd_checker) {
        const char *bad = fd_checker(fd, argv[4]);
        if (bad) {
            close(fd);
            return cmd_fail(c->err, "bad-fd", "%s", bad);
        }
    }
    struct port *p = port_add_adopted(argv[2], argv[4], &fd, ip, len, vrf, c->err);
    if (!p) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    return 0;
}

static int cmd_port_del(struct cmd_ctx *c, int argc, char **argv) {
    if (argc != 3)
        return usage(c, "port del <name>");
    struct port *p = port_find(argv[2]);
    if (!p)
        return cmd_fail(c->err, "unknown-port", "no such port '%s'", argv[2]);
    if (check_owner(c, p->owner) != 0)
        return -1;
    return port_del(p, c->err);
}

static int cmd_port_add(struct cmd_ctx *c, int argc, char **argv) {
    return add_port(c, argc, argv, PORT_VM);
}

static int cmd_underlay_add(struct cmd_ctx *c, int argc, char **argv) {
    return add_port(c, argc, argv, PORT_UNDERLAY);
}

static int cmd_neigh_add(struct cmd_ctx *c, int argc, char **argv) {
    static const char *u = "neigh add <ip> lladdr <mac> dev <port>";
    if (argc != 7 || strcmp(argv[3], "lladdr") != 0 || strcmp(argv[5], "dev") != 0)
        return usage(c, u);
    uint32_t ip;
    uint8_t mac[6];
    const char *e = cmd_parse_ipv4(argv[2], &ip);
    if (e)
        return cmd_fail(c->err, e, "invalid address '%s'", argv[2]);
    if ((e = cmd_parse_mac(argv[4], mac)))
        return cmd_fail(c->err, e, "invalid MAC '%s'", argv[4]);
    struct port *p = port_find(argv[6]);
    if (!p)
        return cmd_fail(c->err, "unknown-port", "no such port '%s'", argv[6]);
    return neigh_add_static(ip, mac, p->id, c->err);
}

/* route add|replace <prefix> [vrf <v>] (dev <p> [via <gw>] | node <n> encap mplsoudp label <l>
 * | node <n> encap vxlan vni <id>) */
static int route_add_or_replace(struct cmd_ctx *c, int argc, char **argv, int replace) {
    static const char *u =
        "route add|replace <prefix> [vrf <vrf>] dev <port> [via <gw>] | node <node> encap "
        "mplsoudp label <l> | node <node> encap vxlan vni <id>";
    if (argc < 5)
        return usage(c, u);
    uint32_t prefix, gw = 0;
    uint8_t len;
    const char *e = cmd_parse_prefix(argv[2], &prefix, &len);
    if (e)
        return cmd_fail(c->err, e, "invalid prefix '%s' (host bits must be zero)", argv[2]);
    const char *dev = NULL, *via = NULL, *node = NULL, *encap = NULL, *label = NULL, *vni = NULL;
    unsigned vrf = VRF_DEFAULT;
    for (int i = 3; i < argc; i += 2) {
        if (i + 1 >= argc)
            return usage(c, u);
        const char *k = argv[i], *v = argv[i + 1];
        if (strcmp(k, "vrf") == 0) {
            if (resolve_vrf(c, v, &vrf) != 0)
                return -1;
        } else if (strcmp(k, "dev") == 0 && !dev) {
            dev = v;
        } else if (strcmp(k, "via") == 0 && !via) {
            via = v;
        } else if (strcmp(k, "node") == 0 && !node) {
            node = v;
        } else if (strcmp(k, "encap") == 0 && !encap) {
            encap = v;
        } else if (strcmp(k, "label") == 0 && !label) {
            label = v;
        } else if (strcmp(k, "vni") == 0 && !vni) {
            vni = v;
        } else {
            return usage(c, u);
        }
    }
    if (replace) {
        const struct route *old = route_find(vrf, prefix, len);
        if (old && check_owner(c, old->owner) != 0)
            return -1;
    }
    if (dev) { /* local */
        if (node || encap || label || vni)
            return usage(c, u);
        struct port *p = port_find(dev);
        if (!p)
            return cmd_fail(c->err, "unknown-port", "no such port '%s'", dev);
        if (via && (e = cmd_parse_ipv4(via, &gw)))
            return cmd_fail(c->err, e, "invalid gateway '%s'", via);
        return replace ? route_replace_static(vrf, prefix, len, p->id, gw, c->err)
                       : route_add_static(vrf, prefix, len, p->id, gw, c->err);
    }
    if (!node || !encap || via)
        return usage(c, u);
    const struct node *n = node_find(node);
    uint64_t tag;
    enum encap_kind kind;
    if (strcmp(encap, "mplsoudp") == 0 && label && !vni) {
        kind = ENCAP_MPLSOUDP;
        if ((e = cmd_parse_uint(label, 0, 0xffffffffu, &tag)))
            return cmd_fail(c->err, e, "label must be %d..%d", MPLS_LABEL_MIN, MPLS_LABEL_MAX);
    } else if (strcmp(encap, "vxlan") == 0 && vni && !label) {
        kind = ENCAP_VXLAN;
        if ((e = cmd_parse_uint(vni, 0, 0xffffffffu, &tag)))
            return cmd_fail(c->err, e, "VNI must be %d..%d", VNI_MIN, VNI_MAX);
    } else {
        return usage(c, u);
    }
    if (!n) {
        if (!vrf_by_id(vrf))
            return cmd_fail(c->err, "unknown-vrf", "no such VRF");
        if (!port_underlay())
            return cmd_fail(c->err, "no-underlay", "no underlay port is configured");
        return cmd_fail(c->err, "unknown-node", "no such node '%s'", node);
    }
    return replace ? route_replace_remote(vrf, prefix, len, n->id, kind, (uint32_t)tag, c->err)
                   : route_add_remote(vrf, prefix, len, n->id, kind, (uint32_t)tag, c->err);
}

static int cmd_route_add(struct cmd_ctx *c, int argc, char **argv) {
    return route_add_or_replace(c, argc, argv, 0);
}

static int cmd_route_replace(struct cmd_ctx *c, int argc, char **argv) {
    return route_add_or_replace(c, argc, argv, 1);
}

static int cmd_icmp_ratelimit(struct cmd_ctx *c, int argc, char **argv) {
    static const char *u = "icmp-ratelimit rate <1..100000> burst <1..10000>";
    if (argc != 5 || strcmp(argv[1], "rate") != 0 || strcmp(argv[3], "burst") != 0)
        return usage(c, u);
    uint64_t rate, burst;
    const char *e = cmd_parse_uint(argv[2], 1, RL_MAX_RATE, &rate);
    if (e)
        return cmd_fail(c->err, e, "rate must be 1..%d", RL_MAX_RATE);
    if ((e = cmd_parse_uint(argv[4], 1, RL_MAX_BURST, &burst)))
        return cmd_fail(c->err, e, "burst must be 1..%d", RL_MAX_BURST);
    e = ratelimit_configure(rate, burst);
    return e ? cmd_fail(c->err, e, "invalid rate limit") : 0;
}

/* ---- show / set / delete commands (US3) ---- */

static void ip_str(uint32_t ip, char out[16]) {
    snprintf(out, 16, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
}

static void mac_str(const uint8_t m[6], char out[18]) {
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void prefix_str(uint32_t ip, uint8_t len, char out[20]) {
    char a[16];
    ip_str(ip, a);
    snprintf(out, 20, "%s/%u", a, len);
}

static void json_route(struct jw *w, const char *key, const struct route *r) {
    char b[20], g[16];
    jw_obj_begin(w, key);
    prefix_str(r->prefix, r->len, b);
    const struct vrf *v = vrf_by_id(r->vrf);
    jw_str(w, "vrf", v ? v->name : "?");
    jw_str(w, "prefix", b);
    if (r->kind == NH_REMOTE) {
        const struct node *n = node_get(r->node);
        jw_null(w, "port");
        jw_null(w, "gateway");
        jw_str(w, "origin", route_origin_name(r->origin));
        jw_str(w, "node", n ? n->name : "?");
        jw_str(w, "encap", stats_encap_name(r->encap));
        jw_u64(w, "tag", r->tag);
        jw_str(w, "owner", owner_name((enum owner)r->owner));
        jw_obj_end(w);
        return;
    }
    struct port *p = r->port == ROUTE_NO_PORT ? NULL : port_get((uint8_t)r->port);
    if (p)
        jw_str(w, "port", p->name);
    else
        jw_null(w, "port");
    if (r->gateway) {
        ip_str(r->gateway, g);
        jw_str(w, "gateway", g);
    } else {
        jw_null(w, "gateway");
    }
    jw_str(w, "origin", route_origin_name(r->origin));
    jw_str(w, "owner", owner_name((enum owner)r->owner));
    jw_obj_end(w);
}

#define SHOW_DEFAULT_LIMIT 400 /* ~50 KB of JSON: always fits one 64 KiB response */

struct page {
    struct jw *w;
    uint64_t index, offset, limit, emitted;
    int more; /* an entry exists beyond this page */
};

/* "[offset <n>] [limit <n>]" starting at argv[first]. */
static int parse_page(struct cmd_ctx *c, int argc, char **argv, int first, const char *usage_line,
                      uint64_t *offset, uint64_t *limit) {
    *offset = 0;
    *limit = SHOW_DEFAULT_LIMIT;
    for (int i = first; i < argc; i += 2) {
        if (i + 1 >= argc)
            return usage(c, usage_line);
        uint64_t *dst = strcmp(argv[i], "offset") == 0  ? offset
                        : strcmp(argv[i], "limit") == 0 ? limit
                                                         : NULL;
        if (!dst)
            return usage(c, usage_line);
        const char *e = cmd_parse_uint(argv[i + 1], dst == limit ? 1 : 0, 1000000, dst);
        if (e)
            return cmd_fail(c->err, e, "%s must be a number (limit >= 1)", argv[i]);
    }
    return 0;
}

static void page_header(struct page *pg, uint64_t total) {
    jw_u64(pg->w, "total", total);
    jw_u64(pg->w, "offset", pg->offset);
}

static void page_footer(struct page *pg) {
    /* next_offset is null on the last page: vrctl follows it to print everything */
    if (pg->more)
        jw_u64(pg->w, "next_offset", pg->offset + pg->limit);
    else
        jw_null(pg->w, "next_offset");
}

static void route_show_cb(const struct route *r, void *arg) {
    struct page *pg = arg;
    uint64_t i = pg->index++;
    if (i < pg->offset)
        return;
    if (pg->emitted >= pg->limit) {
        pg->more = 1;
        return;
    }
    pg->emitted++;
    json_route(pg->w, NULL, r);
}

/* Optional "vrf <name>" at argv[from]; returns the next index or -1 on error. */
static int opt_vrf(struct cmd_ctx *c, int argc, char **argv, int from, unsigned *vrf) {
    *vrf = VRF_DEFAULT;
    if (from + 1 < argc && strcmp(argv[from], "vrf") == 0) {
        if (resolve_vrf(c, argv[from + 1], vrf) != 0)
            return -1;
        return from + 2;
    }
    return from;
}

static int cmd_route_show(struct cmd_ctx *c, int argc, char **argv) {
    static const char *u = "route show [vrf <vrf>] [offset <n>] [limit <n>]";
    struct page pg = {.w = c->out};
    unsigned vrf;
    int first = opt_vrf(c, argc, argv, 2, &vrf);
    if (first < 0 || parse_page(c, argc, argv, first, u, &pg.offset, &pg.limit))
        return -1;
    page_header(&pg, route_count_vrf(vrf));
    jw_arr_begin(c->out, "routes");
    route_walk(vrf, route_show_cb, &pg);
    jw_arr_end(c->out);
    page_footer(&pg);
    return 0;
}

static int cmd_route_del(struct cmd_ctx *c, int argc, char **argv) {
    static const char *u = "route del <prefix> [vrf <vrf>]";
    if (argc != 3 && argc != 5)
        return usage(c, u);
    uint32_t prefix;
    uint8_t len;
    const char *e = cmd_parse_prefix(argv[2], &prefix, &len);
    if (e)
        return cmd_fail(c->err, e, "invalid prefix '%s' (host bits must be zero)", argv[2]);
    unsigned vrf;
    if (opt_vrf(c, argc, argv, 3, &vrf) != argc)
        return argc == 5 && !vrf_by_name(argv[4]) ? -1 : usage(c, u);
    const struct route *old = route_find(vrf, prefix, len);
    if (old && check_owner(c, old->owner) != 0)
        return -1;
    return route_del(vrf, prefix, len, c->err);
}

static int cmd_route_lookup(struct cmd_ctx *c, int argc, char **argv) {
    static const char *u = "route lookup <ip> [vrf <vrf>]";
    if (argc != 3 && argc != 5)
        return usage(c, u);
    uint32_t ip;
    const char *e = cmd_parse_ipv4(argv[2], &ip);
    if (e)
        return cmd_fail(c->err, e, "invalid address '%s'", argv[2]);
    unsigned vrf;
    if (opt_vrf(c, argc, argv, 3, &vrf) != argc)
        return argc == 5 && !vrf_by_name(argv[4]) ? -1 : usage(c, u);
    const struct route *r = route_lookup(vrf, ip);
    if (!r)
        return cmd_fail(c->err, "not-found", "no route to %s", argv[2]);
    json_route(c->out, "route", r);
    return 0;
}

static int cmd_port_show(struct cmd_ctx *c, int argc, char **argv) {
    (void)argv;
    if (argc != 2)
        return usage(c, "port show");
    jw_arr_begin(c->out, "ports");
    for (unsigned i = 0; i < MAX_PORTS; i++) {
        const struct port *p = port_get((uint8_t)i);
        if (!p)
            continue;
        char mac[18], ip[20];
        mac_str(p->mac, mac);
        prefix_str(p->ip, p->prefix_len, ip);
        const struct port_stats *s = &g_stats.port[i];
        jw_obj_begin(c->out, NULL);
        jw_str(c->out, "name", p->name);
        jw_str(c->out, "ifname", p->ifname);
        jw_str(c->out, "role", p->role == PORT_UNDERLAY ? "underlay" : "vm");
        if (p->role == PORT_VM) {
            const struct vrf *v = vrf_by_id(p->vrf);
            jw_str(c->out, "vrf", v ? v->name : "?");
        } else {
            jw_null(c->out, "vrf");
        }
        jw_str(c->out, "mac", mac);
        jw_str(c->out, "ip", ip);
        jw_u64(c->out, "mtu", p->mtu);
        jw_str(c->out, "admin", p->admin_up ? "up" : "down");
        jw_str(c->out, "oper", p->oper_up ? "up" : "down");
        jw_u64(c->out, "rx_pkts", s->rx_pkts);
        jw_u64(c->out, "rx_bytes", s->rx_bytes);
        jw_u64(c->out, "tx_pkts", s->tx_pkts);
        jw_u64(c->out, "tx_bytes", s->tx_bytes);
        jw_u64(c->out, "drops", s->drops);
        jw_str(c->out, "owner", owner_name((enum owner)p->owner));
        jw_obj_end(c->out);
    }
    jw_arr_end(c->out);
    return 0;
}

static int cmd_port_set(struct cmd_ctx *c, int argc, char **argv) {
    static const char *u = "port set <name> admin up|down | vrf <vrf>";
    if (argc != 5)
        return usage(c, u);
    struct port *p = port_find(argv[2]);
    if (!p)
        return cmd_fail(c->err, "unknown-port", "no such port '%s'", argv[2]);
    if (check_owner(c, p->owner) != 0)
        return -1;
    if (strcmp(argv[3], "vrf") == 0) {
        unsigned vrf;
        if (resolve_vrf(c, argv[4], &vrf) != 0)
            return -1;
        return port_set_vrf(p, vrf, c->err);
    }
    if (strcmp(argv[3], "admin") != 0)
        return usage(c, u);
    if (strcmp(argv[4], "up") == 0) {
        p->admin_up = true;
    } else if (strcmp(argv[4], "down") == 0) {
        p->admin_up = false;
        neigh_port_down(p->id);
    } else {
        return usage(c, u);
    }
    return 0;
}

struct neigh_row {
    uint32_t ip;
    const struct neigh *n;
};
static struct neigh_row rows[NEIGH_CAPACITY];
static unsigned nrows;
static int row_table; /* -1 = every table */

static void neigh_collect(const struct neigh *n, void *arg) {
    (void)arg;
    if (row_table >= 0 && n->table != row_table)
        return;
    if (nrows < NEIGH_CAPACITY) {
        rows[nrows].ip = n->ip;
        rows[nrows].n = n;
        nrows++;
    }
}

static int row_cmp(const void *a, const void *b) {
    const struct neigh *p = ((const struct neigh_row *)a)->n, *q = ((const struct neigh_row *)b)->n;
    if (p->table != q->table)
        return p->table < q->table ? -1 : 1;
    return p->ip < q->ip ? -1 : p->ip > q->ip;
}

static int cmd_neigh_show(struct cmd_ctx *c, int argc, char **argv) {
    static const char *u = "neigh show [vrf <vrf> | underlay] [offset <n>] [limit <n>]";
    struct page pg = {.w = c->out};
    int first = 2;
    row_table = -1;
    if (argc > 2 && strcmp(argv[2], "underlay") == 0) {
        row_table = NEIGH_UNDERLAY;
        first = 3;
    } else if (argc > 3 && strcmp(argv[2], "vrf") == 0) {
        unsigned vrf;
        if (resolve_vrf(c, argv[3], &vrf) != 0)
            return -1;
        row_table = (int)vrf;
        first = 4;
    }
    if (parse_page(c, argc, argv, first, u, &pg.offset, &pg.limit))
        return -1;
    nrows = 0;
    neigh_walk(neigh_collect, NULL);
    qsort(rows, nrows, sizeof rows[0], row_cmp);
    page_header(&pg, nrows);
    pg.more = nrows > pg.offset + pg.limit;
    jw_arr_begin(c->out, "neighbours");
    for (uint64_t i = pg.offset; i < nrows && i < pg.offset + pg.limit; i++) {
        const struct neigh *n = rows[i].n;
        char ip[16], mac[18];
        ip_str(n->ip, ip);
        jw_obj_begin(c->out, NULL);
        if (n->table == NEIGH_UNDERLAY) {
            jw_str(c->out, "vrf", "underlay");
        } else {
            const struct vrf *v = vrf_by_id(n->table);
            jw_str(c->out, "vrf", v ? v->name : "?");
        }
        jw_str(c->out, "ip", ip);
        if (n->state == NEIGH_REACHABLE) {
            mac_str(n->mac, mac);
            jw_str(c->out, "mac", mac);
        } else {
            jw_null(c->out, "mac");
        }
        const struct port *p = port_get(n->port);
        jw_str(c->out, "port", p ? p->name : "?");
        jw_str(c->out, "kind", n->kind == NEIGH_STATIC ? "static" : "learned");
        jw_str(c->out, "state", n->state == NEIGH_REACHABLE   ? "REACHABLE"
                                : n->state == NEIGH_INCOMPLETE ? "INCOMPLETE"
                                                               : "FAILED");
        jw_u64(c->out, "held", n->nhold);
        jw_str(c->out, "owner", owner_name((enum owner)n->owner));
        jw_obj_end(c->out);
    }
    jw_arr_end(c->out);
    page_footer(&pg);
    return 0;
}

static int cmd_neigh_del(struct cmd_ctx *c, int argc, char **argv) {
    static const char *u = "neigh del <ip> [vrf <vrf>]";
    if (argc != 3 && argc != 5)
        return usage(c, u);
    uint32_t ip;
    const char *e = cmd_parse_ipv4(argv[2], &ip);
    if (e)
        return cmd_fail(c->err, e, "invalid address '%s'", argv[2]);
    unsigned vrf;
    if (opt_vrf(c, argc, argv, 3, &vrf) != argc)
        return argc == 5 && !vrf_by_name(argv[4]) ? -1 : usage(c, u);
    const struct neigh *old = neigh_lookup(vrf, ip);
    if (old && check_owner(c, old->owner) != 0)
        return -1;
    return neigh_del(vrf, ip, c->err);
}

/* ---- VRFs, nodes, tunnel mappings ---- */

static void count_neigh_cb(const struct neigh *n, void *arg) {
    unsigned *cnt = arg; /* cnt[0] = table, cnt[1] = result */
    if (n->table == cnt[0])
        cnt[1]++;
}

static int cmd_vrf_show(struct cmd_ctx *c, int argc, char **argv) {
    (void)argv;
    if (argc != 2)
        return usage(c, "vrf show");
    jw_arr_begin(c->out, "vrfs");
    for (unsigned i = 0; i < VRF_MAX; i++) {
        const struct vrf *v = vrf_by_id(i);
        if (!v)
            continue;
        unsigned cnt[2] = {i, 0};
        neigh_walk(count_neigh_cb, cnt);
        jw_obj_begin(c->out, NULL);
        jw_str(c->out, "name", v->name);
        jw_u64(c->out, "id", v->id);
        jw_arr_begin(c->out, "ports");
        for (unsigned k = 0; k < MAX_PORTS; k++) {
            const struct port *p = port_get((uint8_t)k);
            if (p && p->role == PORT_VM && p->vrf == v->id)
                jw_str(c->out, NULL, p->name);
        }
        jw_arr_end(c->out);
        jw_u64(c->out, "routes", route_count_vrf(v->id));
        jw_u64(c->out, "neighbours", cnt[1]);
        jw_u64(c->out, "labels", label_count_vrf(v->id));
        jw_u64(c->out, "vnis", tunnel_vni_count_vrf(v->id));
        jw_str(c->out, "owner", owner_name((enum owner)v->owner));
        jw_obj_end(c->out);
    }
    jw_arr_end(c->out);
    return 0;
}

static int cmd_node_add(struct cmd_ctx *c, int argc, char **argv) {
    static const char *u = "node add <name> ip <a.b.c.d> [rmac <mac>]";
    if ((argc != 5 && argc != 7) || strcmp(argv[3], "ip") != 0 ||
        (argc == 7 && strcmp(argv[5], "rmac") != 0))
        return usage(c, u);
    uint32_t ip;
    uint8_t mac[6];
    const char *e = cmd_parse_ipv4(argv[4], &ip);
    if (e)
        return cmd_fail(c->err, e, "invalid address '%s'", argv[4]);
    if (argc == 7 && (e = cmd_parse_mac(argv[6], mac)))
        return cmd_fail(c->err, e, "invalid MAC '%s'", argv[6]);
    return node_add(argv[2], ip, argc == 7 ? mac : NULL, c->err);
}

static int cmd_node_set(struct cmd_ctx *c, int argc, char **argv) {
    if (argc != 5 || strcmp(argv[3], "rmac") != 0)
        return usage(c, "node set <name> rmac <mac>");
    uint8_t mac[6];
    const char *e = cmd_parse_mac(argv[4], mac);
    if (e)
        return cmd_fail(c->err, e, "invalid MAC '%s'", argv[4]);
    const struct node *old = node_find(argv[2]);
    if (old && check_owner(c, old->owner) != 0)
        return -1;
    return node_set_rmac(argv[2], mac, c->err);
}

static int cmd_node_del(struct cmd_ctx *c, int argc, char **argv) {
    if (argc != 3)
        return usage(c, "node del <name>");
    const struct node *old = node_find(argv[2]);
    if (old && check_owner(c, old->owner) != 0)
        return -1;
    return node_del(argv[2], c->err);
}

static void json_dir(struct jw *w, const char *key, const struct dir_stats d[ENCAP_COUNT]) {
    jw_obj_begin(w, key);
    for (int k = 0; k < ENCAP_COUNT; k++) {
        jw_obj_begin(w, stats_encap_name((enum encap_kind)k));
        jw_u64(w, "pkts", d[k].pkts);
        jw_u64(w, "bytes", d[k].bytes);
        jw_obj_end(w);
    }
    jw_obj_end(w);
}

static void json_node_counters(struct jw *w, uint8_t id) {
    json_dir(w, "encap", g_stats.node[id].encap);
    json_dir(w, "decap", g_stats.node[id].decap);
}

static int cmd_node_show(struct cmd_ctx *c, int argc, char **argv) {
    (void)argv;
    if (argc != 2)
        return usage(c, "node show");
    jw_arr_begin(c->out, "nodes");
    for (unsigned i = 0; i < TUNNEL_MAX_NODES; i++) {
        const struct node *n = node_get((uint8_t)i);
        if (!n)
            continue;
        char ip[16], mac[18];
        ip_str(n->ip, ip);
        jw_obj_begin(c->out, NULL);
        jw_str(c->out, "name", n->name);
        jw_str(c->out, "ip", ip);
        if (n->has_rmac) {
            mac_str(n->rmac, mac);
            jw_str(c->out, "rmac", mac);
        } else {
            jw_null(c->out, "rmac");
        }
        const struct neigh *nb = neigh_lookup(NEIGH_UNDERLAY, n->ip);
        if (nb && nb->state == NEIGH_REACHABLE) {
            mac_str(nb->mac, mac);
            jw_str(c->out, "underlay_mac", mac);
        } else {
            jw_null(c->out, "underlay_mac");
        }
        jw_str(c->out, "state", !nb                          ? "unresolved"
                                : nb->state == NEIGH_REACHABLE   ? "reachable"
                                : nb->state == NEIGH_INCOMPLETE ? "resolving"
                                                                 : "failed");
        json_node_counters(c->out, n->id);
        jw_str(c->out, "owner", owner_name((enum owner)n->owner));
        jw_obj_end(c->out);
    }
    jw_arr_end(c->out);
    return 0;
}

static int cmd_label_add(struct cmd_ctx *c, int argc, char **argv) {
    if (argc != 5 || strcmp(argv[3], "port") != 0)
        return usage(c, "label add <label> port <port>");
    uint64_t label;
    const char *e = cmd_parse_uint(argv[2], 0, 0xffffffffu, &label);
    if (e)
        return cmd_fail(c->err, e, "label must be %d..%d", MPLS_LABEL_MIN, MPLS_LABEL_MAX);
    struct port *p = port_find(argv[4]);
    if (!p)
        return cmd_fail(c->err, "unknown-port", "no such port '%s'", argv[4]);
    return label_add((uint32_t)label, p->id, c->err);
}

static int cmd_label_del(struct cmd_ctx *c, int argc, char **argv) {
    if (argc != 3)
        return usage(c, "label del <label>");
    uint64_t label;
    const char *e = cmd_parse_uint(argv[2], 0, 0xffffffffu, &label);
    if (e)
        return cmd_fail(c->err, e, "label must be a number");
    if (check_owner(c, label_owner((uint32_t)label)) != 0)
        return -1;
    return label_del((uint32_t)label, c->err);
}

static int cmd_vni_add(struct cmd_ctx *c, int argc, char **argv) {
    if (argc != 5 || strcmp(argv[3], "vrf") != 0)
        return usage(c, "vni add <id> vrf <vrf>");
    uint64_t vni;
    const char *e = cmd_parse_uint(argv[2], 0, 0xffffffffu, &vni);
    if (e)
        return cmd_fail(c->err, e, "VNI must be %d..%d", VNI_MIN, VNI_MAX);
    unsigned vrf;
    if (resolve_vrf(c, argv[4], &vrf) != 0)
        return -1;
    return vni_add((uint32_t)vni, vrf, c->err);
}

static int cmd_vni_del(struct cmd_ctx *c, int argc, char **argv) {
    if (argc != 3)
        return usage(c, "vni del <id>");
    uint64_t vni;
    const char *e = cmd_parse_uint(argv[2], 0, 0xffffffffu, &vni);
    if (e)
        return cmd_fail(c->err, e, "VNI must be a number");
    if (check_owner(c, vni_owner((uint32_t)vni)) != 0)
        return -1;
    return vni_del((uint32_t)vni, c->err);
}

static void tunnel_label_cb(uint32_t label, uint8_t port, void *arg) {
    struct jw *w = arg;
    const struct port *p = port_get(port);
    const struct vrf *v = p ? vrf_by_id(p->vrf) : NULL;
    jw_obj_begin(w, NULL);
    jw_u64(w, "label", label);
    jw_str(w, "port", p ? p->name : "?");
    jw_str(w, "vrf", v ? v->name : "?");
    jw_str(w, "owner", owner_name((enum owner)label_owner(label)));
    jw_obj_end(w);
}

static void tunnel_vni_cb(uint32_t vni, unsigned vrf, void *arg) {
    struct jw *w = arg;
    const struct vrf *v = vrf_by_id(vrf);
    jw_obj_begin(w, NULL);
    jw_u64(w, "vni", vni);
    jw_str(w, "vrf", v ? v->name : "?");
    jw_str(w, "owner", owner_name((enum owner)vni_owner(vni)));
    jw_obj_end(w);
}

static int cmd_tunnel_show(struct cmd_ctx *c, int argc, char **argv) {
    (void)argv;
    if (argc != 2)
        return usage(c, "tunnel show");
    jw_arr_begin(c->out, "labels");
    label_walk(tunnel_label_cb, c->out);
    jw_arr_end(c->out);
    jw_arr_begin(c->out, "vnis");
    vni_walk(tunnel_vni_cb, c->out);
    jw_arr_end(c->out);
    const struct port *u = port_underlay();
    if (u) {
        char ip[20], mac[18];
        prefix_str(u->ip, u->prefix_len, ip);
        mac_str(u->mac, mac);
        jw_obj_begin(c->out, "underlay");
        jw_str(c->out, "port", u->name);
        jw_str(c->out, "ip", ip);
        jw_str(c->out, "mac", mac);
        jw_u64(c->out, "mtu", u->mtu);
        jw_obj_end(c->out);
    } else {
        jw_null(c->out, "underlay");
    }
    return 0;
}

static int cmd_stats_show(struct cmd_ctx *c, int argc, char **argv) {
    (void)argv;
    if (argc != 2)
        return usage(c, "stats show");
    jw_arr_begin(c->out, "ports");
    for (unsigned i = 0; i < MAX_PORTS; i++) {
        const struct port *p = port_get((uint8_t)i);
        if (!p)
            continue;
        const struct port_stats *s = &g_stats.port[i];
        jw_obj_begin(c->out, NULL);
        jw_str(c->out, "name", p->name);
        jw_u64(c->out, "rx_pkts", s->rx_pkts);
        jw_u64(c->out, "rx_bytes", s->rx_bytes);
        jw_u64(c->out, "tx_pkts", s->tx_pkts);
        jw_u64(c->out, "tx_bytes", s->tx_bytes);
        jw_u64(c->out, "drops", s->drops);
        jw_obj_end(c->out);
    }
    jw_arr_end(c->out);
    stats_json_drops(c->out);
    stats_json_events(c->out);
    jw_arr_begin(c->out, "nodes");
    for (unsigned i = 0; i <= TUNNEL_MAX_NODES; i++) {
        const struct node *n = node_get((uint8_t)i);
        if (!n && i != NODE_UNKNOWN)
            continue;
        jw_obj_begin(c->out, NULL);
        jw_str(c->out, "name", n ? n->name : "unknown");
        json_node_counters(c->out, (uint8_t)i);
        jw_obj_end(c->out);
    }
    jw_arr_end(c->out);
    jw_obj_begin(c->out, "mbuf");
    jw_u64(c->out, "total", mbuf_pool_total());
    jw_u64(c->out, "in_use", mbuf_in_use());
    jw_obj_end(c->out);
    return 0;
}

static int cmd_stats_clear(struct cmd_ctx *c, int argc, char **argv) {
    (void)argv;
    if (argc != 2)
        return usage(c, "stats clear");
    stats_clear();
    return 0;
}

#ifdef MINIVR_DEBUG
/* Deliberate NULL write for the crash drill (SC-009); kept out of line so it shows in backtraces. */
void cmd_debug_crash(void); /* external linkage so -rdynamic names it in backtraces */
__attribute__((noinline)) void cmd_debug_crash(void) {
    volatile int *volatile p = NULL;
    *p = 1;
}

static int cmd_debug_crash_handler(struct cmd_ctx *c, int argc, char **argv) {
    (void)argv;
    if (argc != 2)
        return usage(c, "debug crash");
    cmd_debug_crash();
    return 0;
}
#endif

static int cmd_version(struct cmd_ctx *c, int argc, char **argv) {
    (void)argv;
    if (argc != 1)
        return usage(c, "version");
    jw_str(c->out, "daemon", "minivrd");
    jw_str(c->out, "boot_id", boot_id[0] ? boot_id : "0000000000000000");
    jw_u64(c->out, "protocol", PROTOCOL_VERSION);
    jw_str(c->out, "version", MINIVR_VERSION);
#ifdef MINIVR_DEBUG
    jw_str(c->out, "build", "debug");
#else
    jw_str(c->out, "build", "release");
#endif
    jw_u64(c->out, "uptime_s", (clock_now_ns() - start_ns) / NS_PER_SEC);
    return 0;
}

/* ---- sessions ---- */

static struct cmd_session *registry[CMD_MAX_SESSIONS];
static unsigned next_session_id = 1;

void cmd_session_open(struct cmd_session *s, int peer_pid, unsigned peer_uid) {
    memset(s, 0, sizeof *s);
    s->in_use = 1;
    s->id = next_session_id++;
    s->role = CMD_ROLE_CLI;
    s->peer_pid = peer_pid;
    s->peer_uid = peer_uid;
    s->since_ns = clock_now_ns();
    s->fd_in = -1;
    for (unsigned i = 0; i < CMD_MAX_SESSIONS; i++)
        if (!registry[i]) {
            registry[i] = s;
            return;
        }
}

void cmd_session_close(struct cmd_session *s) {
    if (s->fd_in >= 0)
        close(s->fd_in);
    s->fd_in = -1;
    s->in_use = 0;
    for (unsigned i = 0; i < CMD_MAX_SESSIONS; i++)
        if (registry[i] == s)
            registry[i] = NULL;
}

static int cmd_session_agent(struct cmd_ctx *c, int argc, char **argv) {
    (void)argv;
    if (argc != 2)
        return usage(c, "session agent");
    if (!c->sess)
        return cmd_fail(c->err, "config-only", "no session");
    if (c->sess->role == CMD_ROLE_AGENT)
        return 0;
    for (unsigned i = 0; i < CMD_MAX_SESSIONS; i++)
        if (registry[i] && registry[i]->role == CMD_ROLE_AGENT)
            return cmd_fail(c->err, "busy", "another agent session is open (id %u)", registry[i]->id);
    c->sess->role = CMD_ROLE_AGENT;
    c->who = OWNER_AGENT;
    return 0;
}

static int cmd_session_show(struct cmd_ctx *c, int argc, char **argv) {
    (void)argv;
    if (argc != 2)
        return usage(c, "session show");
    jw_arr_begin(c->out, "sessions");
    for (unsigned i = 0; i < CMD_MAX_SESSIONS; i++) {
        const struct cmd_session *s = registry[i];
        if (!s)
            continue;
        jw_obj_begin(c->out, NULL);
        jw_u64(c->out, "id", s->id);
        jw_str(c->out, "role", s->role == CMD_ROLE_AGENT ? "agent" : "cli");
        jw_u64(c->out, "peer_pid", (uint64_t)s->peer_pid);
        jw_u64(c->out, "peer_uid", s->peer_uid);
        jw_u64(c->out, "since", (clock_now_ns() - s->since_ns) / NS_PER_SEC);
        jw_u64(c->out, "requests", s->requests);
        jw_obj_end(c->out);
    }
    jw_arr_end(c->out);
    return 0;
}

/* ---- dispatch ---- */

struct cmd_def {
    const char *words; /* leading words, e.g. "port add" */
    cmd_fn fn;
    enum cmd_where where;
    int debug_only;
};

static const struct cmd_def cmds[] = {
    {"vrf add", cmd_vrf_add, CMD_BOTH, 0},
    {"vrf del", cmd_vrf_del, CMD_CLI, 0},
    {"vrf show", cmd_vrf_show, CMD_CLI, 0},
    {"port add", cmd_port_add, CMD_BOTH, 0},
    {"port del", cmd_port_del, CMD_CLI, 0},
    {"session agent", cmd_session_agent, CMD_CLI, 0},
    {"session show", cmd_session_show, CMD_CLI, 0},
    {"underlay add", cmd_underlay_add, CMD_CONFIG, 0},
    {"node add", cmd_node_add, CMD_BOTH, 0},
    {"node set", cmd_node_set, CMD_CLI, 0},
    {"node del", cmd_node_del, CMD_CLI, 0},
    {"node show", cmd_node_show, CMD_CLI, 0},
    {"label add", cmd_label_add, CMD_BOTH, 0},
    {"label del", cmd_label_del, CMD_CLI, 0},
    {"vni add", cmd_vni_add, CMD_BOTH, 0},
    {"vni del", cmd_vni_del, CMD_CLI, 0},
    {"tunnel show", cmd_tunnel_show, CMD_CLI, 0},
    {"route replace", cmd_route_replace, CMD_CLI, 0},
    {"neigh add", cmd_neigh_add, CMD_BOTH, 0},
    {"route add", cmd_route_add, CMD_BOTH, 0},
    {"icmp-ratelimit", cmd_icmp_ratelimit, CMD_BOTH, 0},
    {"port show", cmd_port_show, CMD_CLI, 0},
    {"port set", cmd_port_set, CMD_CLI, 0},
    {"route show", cmd_route_show, CMD_CLI, 0},
    {"route del", cmd_route_del, CMD_CLI, 0},
    {"route lookup", cmd_route_lookup, CMD_CLI, 0},
    {"neigh show", cmd_neigh_show, CMD_CLI, 0},
    {"neigh del", cmd_neigh_del, CMD_CLI, 0},
    {"stats show", cmd_stats_show, CMD_CLI, 0},
    {"stats clear", cmd_stats_clear, CMD_CLI, 0},
#ifdef MINIVR_DEBUG
    {"debug crash", cmd_debug_crash_handler, CMD_CLI, 1},
#endif
    {"version", cmd_version, CMD_CLI, 0},
};

static const struct cmd_def *lookup(int argc, char **argv) {
    for (size_t i = 0; i < sizeof cmds / sizeof *cmds; i++) {
        const char *w = cmds[i].words;
        int k = 0;
        int match = 1;
        while (*w) {
            const char *sp = strchr(w, ' ');
            size_t n = sp ? (size_t)(sp - w) : strlen(w);
            if (k >= argc || strlen(argv[k]) != n || strncmp(argv[k], w, n) != 0) {
                match = 0;
                break;
            }
            k++;
            w += n;
            if (*w == ' ')
                w++;
        }
        if (match)
            return &cmds[i];
    }
    return NULL;
}

static void write_error(struct jw *out, const struct cmd_err *err) {
    jw_reset(out);
    jw_obj_begin(out, NULL);
    jw_bool(out, "ok", false);
    jw_obj_begin(out, "error");
    jw_str(out, "code", err->code);
    jw_str(out, "message", err->message);
    jw_obj_end(out);
    jw_obj_end(out);
}

static int exec_ctx(struct cmd_session *s, const char *line, enum cmd_where where, struct jw *out,
                    struct cmd_err *err);

int cmd_exec(const char *line, enum cmd_where where, struct jw *out, struct cmd_err *err) {
    return exec_ctx(NULL, line, where, out, err);
}

int cmd_exec_session(struct cmd_session *s, const char *line, struct jw *out, struct cmd_err *err) {
    s->requests++;
    return exec_ctx(s, line, CMD_CLI, out, err);
}

static int exec_ctx(struct cmd_session *s, const char *line, enum cmd_where where, struct jw *out,
                    struct cmd_err *err) {
    char buf[1024];
    char *argv[CMD_MAX_ARGS];
    struct cmd_ctx ctx = {.out = out, .err = err, .sess = s, .where = where};
    ctx.who = where == CMD_CONFIG ? OWNER_CONFIG : OWNER_CLI;
    err->code = NULL;
    err->message[0] = 0;

    if (strlen(line) >= sizeof buf) {
        cmd_fail(err, "bad-syntax", "command too long");
        goto fail;
    }
    strcpy(buf, line);
    int argc = cmd_tokenize(buf, argv, CMD_MAX_ARGS);
    if (argc <= 0) {
        cmd_fail(err, "bad-syntax", argc == 0 ? "empty command" : "too many arguments");
        goto fail;
    }
    const struct cmd_def *d = lookup(argc, argv);
    if (!d
#ifndef MINIVR_DEBUG
        || d->debug_only
#endif
    ) {
        cmd_fail(err, "bad-syntax", "unknown command '%s'", argv[0]);
        goto fail;
    }
    if (!(d->where & where)) {
        if (where == CMD_CLI)
            cmd_fail(err, "config-only", "'%s' is only valid in the config file", d->words);
        else
            cmd_fail(err, "bad-syntax", "'%s' is not valid in the config file", d->words);
        goto fail;
    }

    jw_reset(out);
    jw_obj_begin(out, NULL);
    jw_bool(out, "ok", true);
    jw_obj_begin(out, "data");
    if (s && s->role == CMD_ROLE_AGENT)
        ctx.who = OWNER_AGENT;
    g_owner_ctx = ctx.who;
    int rc = d->fn(&ctx, argc, argv);
    g_owner_ctx = OWNER_CONFIG;
    if (rc != 0)
        goto fail;
    jw_obj_end(out);
    jw_obj_end(out);
    return 0;

fail:
    write_error(out, err);
    return -1;
}
