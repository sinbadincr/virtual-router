/* Controller grammar (contracts/controller-cli.md): one parser for the intent file, the state file
 * and the CLI. Pure: JSON goes to a caller buffer, runtime facts come through cg_ops. */
#include <string.h>

#include "minivr/ctl_model.h"
#include "minivr/proto.h"

#define CG_VERSION "0.1.0"
#define PAGE_DEFAULT 200

#define ip_str ne_ip_str
#define mac_str ne_mac_str
#define prefix_str ne_prefix_str

void ne_json_ex(struct jw *w, const struct nentry *e, const char *owner) {
    char a[20], b[18];
    jw_obj_begin(w, NULL);
    jw_str(w, "kind", ne_kind_name(e->kind));
    switch (e->kind) {
    case NE_VRF:
        jw_str(w, "name", e->name);
        jw_u64(w, "id", e->id);
        break;
    case NE_VNI:
        jw_u64(w, "vni", e->vni);
        jw_str(w, "vrf", e->vrf);
        break;
    case NE_NODE:
        jw_str(w, "name", e->name);
        ip_str(e->ip, a);
        jw_str(w, "ip", a);
        mac_str(e->rmac, b);
        jw_str(w, "rmac", b);
        break;
    case NE_PORT:
        jw_str(w, "name", e->name);
        jw_str(w, "vrf", e->vrf);
        prefix_str(e->prefix, e->plen, a);
        jw_str(w, "prefix", a);
        break;
    case NE_NEIGH:
        jw_str(w, "vrf", e->vrf);
        ip_str(e->ip, a);
        jw_str(w, "ip", a);
        mac_str(e->mac, b);
        jw_str(w, "mac", b);
        jw_str(w, "port", e->port);
        break;
    case NE_LABEL:
        jw_u64(w, "label", e->label);
        jw_str(w, "port", e->port);
        break;
    case NE_ROUTE:
        jw_str(w, "vrf", e->vrf);
        prefix_str(e->prefix, e->plen, a);
        jw_str(w, "prefix", a);
        jw_str(w, "node", e->node);
        jw_str(w, "encap", e->encap == NE_ENCAP_VXLAN ? "vxlan" : "mplsoudp");
        jw_u64(w, "tag", e->tag);
        break;
    }
    if (owner)
        jw_str(w, "owner", owner);
    jw_obj_end(w);
}

void ne_json(struct jw *w, const struct nentry *e) {
    ne_json_ex(w, e, NULL);
}

/* ---- parsing helpers ---- */

struct ctx {
    struct cmodel *m;
    const struct cg_ops *ops;
    struct jw *out;
    struct cmd_err *err;
    enum cg_where where;
};

static int usage(struct ctx *c, const char *u) {
    return cmd_fail(c->err, "bad-syntax", "usage: %s", u);
}

static int parse_encap(const char *s, unsigned *encap) {
    if (strcmp(s, "mplsoudp") == 0)
        *encap = NE_ENCAP_MPLSOUDP;
    else if (strcmp(s, "vxlan") == 0)
        *encap = NE_ENCAP_VXLAN;
    else
        return -1;
    return 0;
}

static int parse_page(struct ctx *c, int argc, char **argv, int first, const char *u,
                      uint64_t *offset, uint64_t *limit) {
    *offset = 0;
    *limit = PAGE_DEFAULT;
    for (int i = first; i < argc; i += 2) {
        if (i + 1 >= argc)
            return usage(c, u);
        uint64_t *dst = strcmp(argv[i], "offset") == 0 ? offset
                        : strcmp(argv[i], "limit") == 0 ? limit
                                                        : NULL;
        if (!dst)
            return usage(c, u);
        const char *e = cmd_parse_uint(argv[i + 1], dst == limit ? 1 : 0, 1000000, dst);
        if (e)
            return cmd_fail(c->err, e, "%s must be a number (limit >= 1)", argv[i]);
    }
    return 0;
}

static void page_footer(struct jw *w, uint64_t offset, uint64_t limit, uint64_t total) {
    if (offset + limit < total)
        jw_u64(w, "next_offset", offset + limit);
    else
        jw_null(w, "next_offset");
}

/* ---- mutating commands ---- */

static int c_tenant_add(struct ctx *c, int argc, char **argv) {
    static const char *u = "tenant add <name> id <1-63> vni <n> encap mplsoudp|vxlan";
    if (argc != 9 || strcmp(argv[3], "id") != 0 || strcmp(argv[5], "vni") != 0 ||
        strcmp(argv[7], "encap") != 0)
        return usage(c, u);
    uint64_t id, vni;
    unsigned encap;
    const char *e;
    if ((e = cmd_parse_uint(argv[4], 0, 100000, &id)))
        return cmd_fail(c->err, e, "tenant id must be 1..63");
    if ((e = cmd_parse_uint(argv[6], 0, 0xffffffffu, &vni)))
        return cmd_fail(c->err, e, "tenant vni must be 1..16777215");
    if (parse_encap(argv[8], &encap) != 0)
        return cmd_fail(c->err, "bad-syntax", "encap must be mplsoudp or vxlan");
    return cm_tenant_add(c->m, argv[2], (unsigned)id, (uint32_t)vni, encap, c->err);
}

static int c_tenant_set(struct ctx *c, int argc, char **argv) {
    unsigned encap;
    if (argc != 5 || strcmp(argv[3], "encap") != 0)
        return usage(c, "tenant set <name> encap mplsoudp|vxlan");
    if (parse_encap(argv[4], &encap) != 0)
        return cmd_fail(c->err, "bad-syntax", "encap must be mplsoudp or vxlan");
    return cm_tenant_set_encap(c->m, argv[2], encap, c->err);
}

static int c_tenant_del(struct ctx *c, int argc, char **argv) {
    if (argc != 3)
        return usage(c, "tenant del <name>");
    return cm_tenant_del(c->m, argv[2], c->err);
}

static int c_subnet_add(struct ctx *c, int argc, char **argv) {
    uint32_t prefix, gw;
    uint8_t len;
    const char *e;
    if (argc != 6 || strcmp(argv[4], "gw") != 0)
        return usage(c, "subnet add <tenant> <a.b.c.d/len> gw <a.b.c.d>");
    if ((e = cmd_parse_prefix(argv[3], &prefix, &len)))
        return cmd_fail(c->err, e, "invalid subnet '%s'", argv[3]);
    if ((e = cmd_parse_ipv4(argv[5], &gw)))
        return cmd_fail(c->err, e, "invalid gateway '%s'", argv[5]);
    return cm_subnet_add(c->m, argv[2], prefix, len, gw, c->err);
}

static int c_subnet_del(struct ctx *c, int argc, char **argv) {
    uint32_t prefix;
    uint8_t len;
    const char *e;
    if (argc != 4)
        return usage(c, "subnet del <tenant> <a.b.c.d/len>");
    if ((e = cmd_parse_prefix(argv[3], &prefix, &len)))
        return cmd_fail(c->err, e, "invalid subnet '%s'", argv[3]);
    return cm_subnet_del(c->m, argv[2], prefix, len, c->err);
}

static int c_node_add(struct ctx *c, int argc, char **argv) {
    if (argc != 3)
        return usage(c, "node add <name>");
    return cm_node_add(c->m, argv[2], c->err);
}

static int c_node_del(struct ctx *c, int argc, char **argv) {
    if (argc != 3)
        return usage(c, "node del <name>");
    return cm_node_del(c->m, argv[2], c->err);
}

static int c_node_forget(struct ctx *c, int argc, char **argv) {
    if (argc != 3)
        return usage(c, "node forget <name>");
    return cm_node_forget(c->m, argv[2], c->err);
}

static int c_vmi_add(struct ctx *c, int argc, char **argv) {
    uint32_t ip;
    uint8_t mac[6];
    const char *e;
    if (argc != 9 || strcmp(argv[3], "tenant") != 0 || strcmp(argv[5], "ip") != 0 ||
        strcmp(argv[7], "mac") != 0)
        return usage(c, "vmi add <name> tenant <t> ip <a.b.c.d> mac <mac>");
    if ((e = cmd_parse_ipv4(argv[6], &ip)))
        return cmd_fail(c->err, e, "invalid address '%s'", argv[6]);
    if ((e = cmd_parse_mac(argv[8], mac)))
        return cmd_fail(c->err, e, "invalid MAC '%s'", argv[8]);
    return cm_vmi_add(c->m, argv[2], argv[4], ip, mac, c->err);
}

static int c_vmi_del(struct ctx *c, int argc, char **argv) {
    if (argc != 3)
        return usage(c, "vmi del <name>");
    return cm_vmi_del(c->m, argv[2], c->err);
}

/* state file only: bind <v> node <n> port <p> label <l> */
static int c_bind(struct ctx *c, int argc, char **argv) {
    uint64_t label;
    if (argc != 8 || strcmp(argv[2], "node") != 0 || strcmp(argv[4], "port") != 0 ||
        strcmp(argv[6], "label") != 0)
        return usage(c, "bind <vmi> node <n> port <p> label <l>");
    int v = cm_vmi_idx(c->m, argv[1]), n = cm_node_idx(c->m, argv[3]);
    if (v < 0)
        return cmd_fail(c->err, "not-found", "no such VM interface '%s'", argv[1]);
    if (n < 0)
        return cmd_fail(c->err, "unknown-node", "no such node '%s'", argv[3]);
    if (cmd_parse_uint(argv[7], CM_LABEL_MIN, CM_LABEL_MAX, &label))
        return cmd_fail(c->err, "bad-syntax", "label must be %d..%d", CM_LABEL_MIN, CM_LABEL_MAX);
    if (!ne_name_ok(argv[5]))
        return cmd_fail(c->err, "bad-syntax", "bad port name '%s'", argv[5]);
    struct cm_vmi *vm = &c->m->vmis[v];
    if (vm->node >= 0)
        return cmd_fail(c->err, "exists", "VM interface %s is already bound", argv[1]);
    for (int i = 0; i < CM_MAX_VMIS; i++)
        if (c->m->vmis[i].used && c->m->vmis[i].node == n &&
            (c->m->vmis[i].label == label || strcmp(c->m->vmis[i].port, argv[5]) == 0))
            return cmd_fail(c->err, "exists", "label or port already bound on node %s", argv[3]);
    vm->node = (int8_t)n;
    strncpy(vm->port, argv[5], NE_NAME - 1);
    vm->port[NE_NAME - 1] = 0;
    vm->label = (uint16_t)label;
    c->m->gen++;
    return 0;
}

static int c_quarantine(struct ctx *c, int argc, char **argv) {
    uint64_t label;
    if (argc != 5 || strcmp(argv[1], "node") != 0 || strcmp(argv[3], "label") != 0)
        return usage(c, "quarantine node <n> label <l>");
    int n = cm_node_idx(c->m, argv[2]);
    if (n < 0)
        return cmd_fail(c->err, "unknown-node", "no such node '%s'", argv[2]);
    if (cmd_parse_uint(argv[4], CM_LABEL_MIN, CM_LABEL_MAX, &label))
        return cmd_fail(c->err, "bad-syntax", "label must be %d..%d", CM_LABEL_MIN, CM_LABEL_MAX);
    for (int i = 0; i < CM_MAX_QUARANTINE; i++)
        if (!c->m->quar[i].used) {
            c->m->quar[i].used = true;
            c->m->quar[i].node = (uint8_t)n;
            c->m->quar[i].label = (uint16_t)label;
            c->m->gen++;
            return 0;
        }
    return cmd_fail(c->err, "table-full", "quarantine table full");
}

/* state file only: learned node <n> ip <a> rmac <m>  (kept so a controller restart does not
 * withdraw routes to nodes that have not reconnected yet) */
static int c_learned(struct ctx *c, int argc, char **argv) {
    uint32_t ip;
    uint8_t mac[6];
    if (argc != 7 || strcmp(argv[1], "node") != 0 || strcmp(argv[3], "ip") != 0 ||
        strcmp(argv[5], "rmac") != 0)
        return usage(c, "learned node <n> ip <a.b.c.d> rmac <mac>");
    int n = cm_node_idx(c->m, argv[2]);
    if (n < 0)
        return cmd_fail(c->err, "unknown-node", "no such node '%s'", argv[2]);
    const char *e;
    if ((e = cmd_parse_ipv4(argv[4], &ip)))
        return cmd_fail(c->err, e, "invalid address '%s'", argv[4]);
    if ((e = cmd_parse_mac(argv[6], mac)))
        return cmd_fail(c->err, e, "invalid MAC '%s'", argv[6]);
    cm_node_learn(c->m, (unsigned)n, ip, mac);
    return 0;
}

/* ---- show commands ---- */

static int c_tenant_show(struct ctx *c, int argc, char **argv) {
    (void)argv;
    if (argc != 2)
        return usage(c, "tenant show");
    struct jw *w = c->out;
    jw_arr_begin(w, "tenants");
    for (int t = 0; t < CM_MAX_TENANTS; t++) {
        const struct cm_tenant *tn = &c->m->tenants[t];
        if (!tn->used)
            continue;
        jw_obj_begin(w, NULL);
        jw_str(w, "name", tn->name);
        jw_u64(w, "id", tn->id);
        jw_u64(w, "vni", tn->vni);
        jw_str(w, "encap", tn->encap == NE_ENCAP_VXLAN ? "vxlan" : "mplsoudp");
        jw_arr_begin(w, "subnets");
        for (int i = 0; i < CM_MAX_SUBNETS; i++) {
            const struct cm_subnet *s = &c->m->subnets[i];
            if (!s->used || s->tenant != t)
                continue;
            char a[20], g[16];
            prefix_str(s->prefix, s->plen, a);
            ip_str(s->gw, g);
            jw_obj_begin(w, NULL);
            jw_str(w, "prefix", a);
            jw_str(w, "gw", g);
            jw_obj_end(w);
        }
        jw_arr_end(w);
        unsigned vmis = 0;
        bool on[CM_MAX_NODES] = {false};
        for (int i = 0; i < CM_MAX_VMIS; i++)
            if (c->m->vmis[i].used && c->m->vmis[i].tenant == t) {
                vmis++;
                if (c->m->vmis[i].node >= 0)
                    on[c->m->vmis[i].node] = true;
            }
        jw_u64(w, "vmis", vmis);
        jw_arr_begin(w, "nodes");
        for (int n = 0; n < CM_MAX_NODES; n++)
            if (on[n])
                jw_str(w, NULL, c->m->nodes[n].name);
        jw_arr_end(w);
        jw_obj_end(w);
    }
    jw_arr_end(w);
    return 0;
}

static int c_vmi_show(struct ctx *c, int argc, char **argv) {
    static const char *u = "vmi show [tenant <t>] [offset <n>] [limit <n>]";
    int first = 2, tenant = -1;
    if (argc > 3 && strcmp(argv[2], "tenant") == 0) {
        tenant = cm_tenant_idx(c->m, argv[3]);
        if (tenant < 0)
            return cmd_fail(c->err, "unknown-tenant", "no such tenant '%s'", argv[3]);
        first = 4;
    }
    uint64_t offset, limit;
    if (parse_page(c, argc, argv, first, u, &offset, &limit) != 0)
        return -1;
    uint64_t total = 0;
    for (int i = 0; i < CM_MAX_VMIS; i++)
        total += c->m->vmis[i].used && (tenant < 0 || c->m->vmis[i].tenant == tenant);
    struct jw *w = c->out;
    jw_u64(w, "total", total);
    jw_u64(w, "offset", offset);
    jw_arr_begin(w, "vmis");
    uint64_t idx = 0;
    for (int i = 0; i < CM_MAX_VMIS; i++) {
        const struct cm_vmi *v = &c->m->vmis[i];
        if (!v->used || (tenant >= 0 && v->tenant != tenant))
            continue;
        uint64_t k = idx++;
        if (k < offset || k >= offset + limit)
            continue;
        char ip[16], mac[18];
        ip_str(v->ip, ip);
        mac_str(v->mac, mac);
        jw_obj_begin(w, NULL);
        jw_str(w, "name", v->name);
        jw_str(w, "tenant", c->m->tenants[v->tenant].name);
        jw_str(w, "ip", ip);
        jw_str(w, "mac", mac);
        jw_str(w, "state", v->node >= 0 ? "bound" : "unbound");
        if (v->node >= 0) {
            jw_str(w, "node", c->m->nodes[v->node].name);
            jw_str(w, "port", v->port);
            jw_u64(w, "label", v->label);
            jw_u64(w, "since", v->since_s);
        } else {
            jw_null(w, "node");
            jw_null(w, "port");
            jw_null(w, "label");
            jw_null(w, "since");
        }
        jw_obj_end(w);
    }
    jw_arr_end(w);
    page_footer(w, offset, limit, total);
    return 0;
}

static void proto_errors_json(struct jw *w, const char *key, const uint64_t *counts) {
    jw_obj_begin(w, key);
    for (int r = PE_TRUNCATED; r < PE_COUNT; r++)
        jw_u64(w, proto_err_name((enum proto_err)r), counts[r]);
    jw_obj_end(w);
}

static int c_node_show(struct ctx *c, int argc, char **argv) {
    (void)argv;
    if (argc != 2)
        return usage(c, "node show");
    struct jw *w = c->out;
    jw_arr_begin(w, "nodes");
    for (unsigned n = 0; n < CM_MAX_NODES; n++) {
        const struct cm_node *nd = &c->m->nodes[n];
        if (!nd->used)
            continue;
        struct cg_node_info info;
        memset(&info, 0, sizeof info);
        info.state = "none";
        if (c->ops && c->ops->node_info)
            c->ops->node_info(c->ops->arg, n, &info);
        jw_obj_begin(w, NULL);
        jw_str(w, "name", nd->name);
        if (nd->addr_known) {
            char a[16], b[18];
            ip_str(nd->underlay_ip, a);
            mac_str(nd->rmac, b);
            jw_str(w, "underlay_ip", a);
            jw_str(w, "rmac", b);
        } else {
            jw_null(w, "underlay_ip");
            jw_null(w, "rmac");
        }
        jw_obj_begin(w, "session");
        jw_str(w, "state", info.state);
        if (info.peer[0])
            jw_str(w, "peer", info.peer);
        else
            jw_null(w, "peer");
        jw_u64(w, "since", info.since_s);
        if (info.last_error[0])
            jw_str(w, "last_error", info.last_error);
        else
            jw_null(w, "last_error");
        jw_u64(w, "msgs_in", info.msgs_in);
        jw_u64(w, "msgs_out", info.msgs_out);
        jw_u64(w, "bytes_in", info.bytes_in);
        jw_u64(w, "bytes_out", info.bytes_out);
        jw_u64(w, "last_seq", info.last_seq);
        jw_u64(w, "acked_seq", info.acked_seq);
        jw_obj_end(w);
        jw_bool(w, "in_sync", info.in_sync);
        jw_u64(w, "entries", info.entries);
        jw_arr_begin(w, "entry_errors");
        for (unsigned i = 0; i < info.nerr && i < 8; i++) {
            jw_obj_begin(w, NULL);
            jw_str(w, "kind", info.errs[i].kind);
            jw_str(w, "key", info.errs[i].key);
            jw_str(w, "code", info.errs[i].code);
            jw_str(w, "text", info.errs[i].text);
            jw_obj_end(w);
        }
        jw_arr_end(w);
        proto_errors_json(w, "proto_errors", info.proto_err);
        jw_obj_end(w);
    }
    jw_arr_end(w);
    return 0;
}

static struct nentry state_buf[4096]; /* scratch for node state (single-threaded caller) */

static int c_node_state(struct ctx *c, int argc, char **argv) {
    static const char *u = "node state <name> [offset <n>] [limit <n>]";
    if (argc < 3)
        return usage(c, u);
    int n = cm_node_idx(c->m, argv[2]);
    if (n < 0)
        return cmd_fail(c->err, "unknown-node", "no such node '%s'", argv[2]);
    uint64_t offset, limit;
    if (parse_page(c, argc, argv, 3, u, &offset, &limit) != 0)
        return -1;
    struct nstate s;
    ns_init(&s, state_buf, sizeof state_buf / sizeof state_buf[0]);
    if (cm_compute(c->m, (unsigned)n, &s) != 0)
        return cmd_fail(c->err, "table-full", "node state exceeds %u entries", s.cap);
    struct jw *w = c->out;
    jw_str(w, "node", argv[2]);
    jw_u64(w, "total", s.n);
    jw_u64(w, "offset", offset);
    jw_arr_begin(w, "entries");
    for (uint64_t i = offset; i < s.n && i < offset + limit; i++)
        ne_json(w, &s.e[i]);
    jw_arr_end(w);
    page_footer(w, offset, limit, s.n);
    return 0;
}

static int c_stats_show(struct ctx *c, int argc, char **argv) {
    (void)argv;
    if (argc != 2)
        return usage(c, "stats show");
    struct cg_stats st;
    memset(&st, 0, sizeof st);
    if (c->ops && c->ops->stats)
        c->ops->stats(c->ops->arg, &st);
    struct jw *w = c->out;
    jw_obj_begin(w, "sessions");
    jw_u64(w, "accepted", st.sessions_accepted);
    jw_u64(w, "rejected", st.sessions_rejected);
    jw_obj_begin(w, "rejected_by_reason");
    for (unsigned code = PC_BAD_VERSION; code <= PC_TABLE_FULL; code++)
        jw_u64(w, proto_code_name(code), st.reject[code]);
    jw_obj_end(w);
    jw_obj_end(w);
    jw_u64(w, "updates_sent", st.updates_sent);
    jw_u64(w, "entries_sent", st.entries_sent);
    jw_u64(w, "ack_errors", st.ack_errors);
    jw_u64(w, "state_writes", st.state_writes);
    proto_errors_json(w, "proto_errors", st.proto_err);
    return 0;
}

static int c_version(struct ctx *c, int argc, char **argv) {
    (void)argv;
    if (argc != 1)
        return usage(c, "version");
    jw_str(c->out, "daemon", "minivr-ctld");
    jw_u64(c->out, "protocol", 1);
    jw_u64(c->out, "wire", PROTO_VERSION);
    jw_str(c->out, "version", CG_VERSION);
    jw_u64(c->out, "uptime_s", c->ops && c->ops->uptime_s ? c->ops->uptime_s(c->ops->arg) : 0);
    return 0;
}

/* ---- dispatch ---- */

typedef int (*cg_fn)(struct ctx *c, int argc, char **argv);

struct def {
    const char *words;
    cg_fn fn;
    unsigned allowed; /* CG_* bits */
};

#define BOTH (CG_FILE | CG_CLI | CG_STATE)
static const struct def defs[] = {
    {"tenant add", c_tenant_add, BOTH},
    {"tenant set", c_tenant_set, CG_CLI},
    {"tenant del", c_tenant_del, CG_CLI},
    {"tenant show", c_tenant_show, CG_CLI},
    {"subnet add", c_subnet_add, BOTH},
    {"subnet del", c_subnet_del, CG_CLI},
    {"node add", c_node_add, BOTH},
    {"node del", c_node_del, CG_CLI},
    {"node forget", c_node_forget, CG_CLI},
    {"node show", c_node_show, CG_CLI},
    {"node state", c_node_state, CG_CLI},
    {"vmi add", c_vmi_add, BOTH},
    {"vmi del", c_vmi_del, CG_CLI},
    {"vmi show", c_vmi_show, CG_CLI},
    {"bind", c_bind, CG_STATE},
    {"quarantine", c_quarantine, CG_STATE},
    {"learned", c_learned, CG_STATE},
    {"stats show", c_stats_show, CG_CLI},
    {"version", c_version, CG_CLI},
};

static const struct def *lookup(int argc, char **argv) {
    for (size_t i = 0; i < sizeof defs / sizeof *defs; i++) {
        const char *w = defs[i].words;
        int k = 0, match = 1;
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
            return &defs[i];
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

int cg_exec(struct cmodel *m, const char *line, enum cg_where where, const struct cg_ops *ops,
            struct jw *out, struct cmd_err *err) {
    char buf[1024];
    char *argv[CMD_MAX_ARGS];
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
    const struct def *d = lookup(argc, argv);
    if (!d) {
        cmd_fail(err, "bad-syntax", "unknown command '%s'", argv[0]);
        goto fail;
    }
    if (!(d->allowed & where)) {
        if (d->allowed == CG_STATE)
            cmd_fail(err, "bad-syntax", "'%s' is only valid in the state file", d->words);
        else if (where == CG_CLI)
            cmd_fail(err, "config-only", "'%s' is only valid in a file", d->words);
        else
            cmd_fail(err, "bad-syntax", "'%s' is not valid in a file", d->words);
        goto fail;
    }
    struct ctx c = {m, ops, out, err, where};
    jw_reset(out);
    jw_obj_begin(out, NULL);
    jw_bool(out, "ok", true);
    jw_obj_begin(out, "data");
    if (d->fn(&c, argc, argv) != 0)
        goto fail;
    jw_obj_end(out);
    jw_obj_end(out);
    return 0;
fail:
    write_error(out, err);
    return -1;
}

/* ---- state file ---- */

struct wbuf {
    char *p;
    size_t cap, len;
    bool over;
};

static void put(struct wbuf *b, const char *s) {
    size_t n = strlen(s);
    if (b->len + n + 1 > b->cap) {
        b->over = true;
        return;
    }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = 0;
}

static void put_u(struct wbuf *b, uint64_t v) {
    char t[24];
    int i = 23;
    t[i] = 0;
    do {
        t[--i] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    put(b, t + i);
}

int cm_serialize(const struct cmodel *m, char *buf, size_t cap) {
    struct wbuf b = {buf, cap, 0, false};
    if (cap)
        buf[0] = 0;
    put(&b, "# minivr-ctld state: intent, bindings and label quarantine (do not edit while running)\n");
    for (int t = 0; t < CM_MAX_TENANTS; t++) {
        const struct cm_tenant *tn = &m->tenants[t];
        if (!tn->used)
            continue;
        put(&b, "tenant add ");
        put(&b, tn->name);
        put(&b, " id ");
        put_u(&b, tn->id);
        put(&b, " vni ");
        put_u(&b, tn->vni);
        put(&b, tn->encap == NE_ENCAP_VXLAN ? " encap vxlan\n" : " encap mplsoudp\n");
    }
    for (int i = 0; i < CM_MAX_SUBNETS; i++) {
        const struct cm_subnet *s = &m->subnets[i];
        if (!s->used)
            continue;
        char a[20], g[16];
        prefix_str(s->prefix, s->plen, a);
        ip_str(s->gw, g);
        put(&b, "subnet add ");
        put(&b, m->tenants[s->tenant].name);
        put(&b, " ");
        put(&b, a);
        put(&b, " gw ");
        put(&b, g);
        put(&b, "\n");
    }
    for (int i = 0; i < CM_MAX_NODES; i++)
        if (m->nodes[i].used) {
            put(&b, "node add ");
            put(&b, m->nodes[i].name);
            put(&b, "\n");
        }
    for (int i = 0; i < CM_MAX_NODES; i++)
        if (m->nodes[i].used && m->nodes[i].addr_known) {
            char a[16], r[18];
            ip_str(m->nodes[i].underlay_ip, a);
            mac_str(m->nodes[i].rmac, r);
            put(&b, "learned node ");
            put(&b, m->nodes[i].name);
            put(&b, " ip ");
            put(&b, a);
            put(&b, " rmac ");
            put(&b, r);
            put(&b, "\n");
        }
    for (int i = 0; i < CM_MAX_VMIS; i++) {
        const struct cm_vmi *v = &m->vmis[i];
        if (!v->used)
            continue;
        char ip[16], mac[18];
        ip_str(v->ip, ip);
        mac_str(v->mac, mac);
        put(&b, "vmi add ");
        put(&b, v->name);
        put(&b, " tenant ");
        put(&b, m->tenants[v->tenant].name);
        put(&b, " ip ");
        put(&b, ip);
        put(&b, " mac ");
        put(&b, mac);
        put(&b, "\n");
    }
    for (int i = 0; i < CM_MAX_VMIS; i++) {
        const struct cm_vmi *v = &m->vmis[i];
        if (!v->used || v->node < 0)
            continue;
        put(&b, "bind ");
        put(&b, v->name);
        put(&b, " node ");
        put(&b, m->nodes[v->node].name);
        put(&b, " port ");
        put(&b, v->port);
        put(&b, " label ");
        put_u(&b, v->label);
        put(&b, "\n");
    }
    for (int i = 0; i < CM_MAX_QUARANTINE; i++) {
        const struct cm_quar *q = &m->quar[i];
        if (!q->used)
            continue;
        put(&b, "quarantine node ");
        put(&b, m->nodes[q->node].name);
        put(&b, " label ");
        put_u(&b, q->label);
        put(&b, "\n");
    }
    return b.over ? -1 : (int)b.len;
}
