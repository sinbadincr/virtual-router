/* Forwarder client: synchronous commands over minivrd's control socket (framing of frame.h),
 * reading `have`, and passing sockets with SCM_RIGHTS. */
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "agent.h"
#include "minivr/frame.h"
#include "minivr/json_in.h"
#include "minivr/log.h"
#include "minivr/netio.h"
#include "minivr/owner.h"

#define FWD_TIMEOUT_MS 1000

static int fwd_fd = -1;
static struct frame_rx rx;

void fwd_close(void) {
    if (fwd_fd >= 0)
        close(fwd_fd);
    fwd_fd = -1;
    g_ag.fwd_up = false;
}

/* One request/response on the control socket. Returns the parsed envelope or NULL (I/O). */
static struct jnode *request(const char *line, int pass_fd, char **raw_out) {
    if (fwd_fd < 0)
        return NULL;
    uint8_t out[FRAME_HDR + 1100];
    size_t len = strlen(line);
    int n = frame_encode(line, len, out, sizeof out);
    if (n < 0)
        return NULL;
    struct iovec iov = {out, (size_t)n};
    union {
        struct cmsghdr align;
        uint8_t b[CMSG_SPACE(sizeof(int))];
    } ctl;
    struct msghdr mh = {.msg_iov = &iov, .msg_iovlen = 1};
    if (pass_fd >= 0) {
        mh.msg_control = ctl.b;
        mh.msg_controllen = sizeof ctl.b;
        struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
        cm->cmsg_level = SOL_SOCKET;
        cm->cmsg_type = SCM_RIGHTS;
        cm->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cm), &pass_fd, sizeof(int));
    }
    ssize_t sent = sendmsg(fwd_fd, &mh, MSG_NOSIGNAL);
    if (sent < 0)
        return NULL;
    size_t off = (size_t)sent;
    while (off < (size_t)n) { /* the fd travelled with the first byte; the rest is plain data */
        ssize_t w = send(fwd_fd, out + off, (size_t)n - off, MSG_NOSIGNAL);
        if (w <= 0)
            return NULL;
        off += (size_t)w;
    }
    frame_rx_init(&rx);
    for (;;) {
        struct pollfd p = {fwd_fd, POLLIN, 0};
        int pr = poll(&p, 1, FWD_TIMEOUT_MS);
        if (pr <= 0)
            return NULL;
        uint8_t buf[4096];
        ssize_t r = recv(fwd_fd, buf, sizeof buf, 0);
        if (r <= 0)
            return NULL;
        size_t used = 0;
        while (used < (size_t)r) {
            used += frame_rx_feed(&rx, buf + used, (size_t)r - used);
            const uint8_t *payload;
            size_t plen;
            int g = frame_rx_get(&rx, &payload, &plen);
            if (g < 0)
                return NULL;
            if (g == 1) {
                struct jnode *root = json_parse((const char *)payload, plen);
                if (raw_out) {
                    *raw_out = malloc(plen + 1);
                    if (*raw_out) {
                        memcpy(*raw_out, payload, plen);
                        (*raw_out)[plen] = 0;
                    }
                }
                return root;
            }
        }
    }
}

int fwd_exec(const char *line, int pass_fd, char code[24], char msg[160]) {
    struct jnode *root = request(line, pass_fd, NULL);
    if (!root) {
        snprintf(code, 24, "io-error");
        snprintf(msg, 160, "no response from the forwarder");
        return FWD_IO;
    }
    const struct jnode *ok = json_get(root, "ok");
    int rc = 0;
    if (!ok || ok->type != J_BOOL || !ok->b) {
        const struct jnode *e = json_get(root, "error");
        const struct jnode *c = json_get(e, "code"), *m = json_get(e, "message");
        snprintf(code, 24, "%.23s", c && c->str ? c->str : "error");
        snprintf(msg, 160, "%.159s", m && m->str ? m->str : "");
        rc = -1;
    } else {
        code[0] = msg[0] = 0;
    }
    json_free(root);
    return rc;
}

int fwd_connect(void) {
    fwd_close();
    fwd_fd = unix_connect(g_ag.fwd_sock);
    if (fwd_fd < 0) {
        snprintf(g_ag.fwd_err, sizeof g_ag.fwd_err, "connect: %s", strerror(errno));
        return FWD_UNREACHABLE;
    }
    char code[24], msg[160];
    int rc = fwd_exec("session agent", -1, code, msg);
    if (rc != 0) {
        snprintf(g_ag.fwd_err, sizeof g_ag.fwd_err, "%.20s: %.60s", code, msg);
        int busy = rc == -1 && strcmp(code, "busy") == 0;
        fwd_close();
        return busy ? FWD_BUSY : FWD_UNREACHABLE;
    }
    g_ag.fwd_up = true;
    g_ag.fwd_err[0] = 0;
    return FWD_OK;
}

/* ---- reading the forwarder ---- */

static const char *sget(const struct jnode *o, const char *k) {
    const struct jnode *n = json_get(o, k);
    return n && n->type == J_STR && n->str ? n->str : NULL;
}

static uint64_t uget(const struct jnode *o, const char *k) {
    const struct jnode *n = json_get(o, k);
    return n && n->type == J_NUM ? n->u : 0;
}

static void copy_name(char dst[NE_NAME], const char *s) {
    snprintf(dst, NE_NAME, "%.15s", s ? s : "");
}

static uint8_t owner_of(const struct jnode *o) {
    const char *s = sget(o, "owner");
    if (s && strcmp(s, "agent") == 0)
        return OWNER_AGENT;
    if (s && strcmp(s, "cli") == 0)
        return OWNER_CLI;
    return OWNER_CONFIG;
}

static int parse_ip(const char *s, uint32_t *ip, uint8_t *plen) {
    unsigned a, b, c, d, l = 32;
    char tail;
    int n = sscanf(s, "%u.%u.%u.%u/%u%c", &a, &b, &c, &d, &l, &tail);
    if (n < 4 || n > 5 || a > 255 || b > 255 || c > 255 || d > 255 || l > 32)
        return -1;
    *ip = (a << 24) | (b << 16) | (c << 8) | d;
    if (plen)
        *plen = (uint8_t)l;
    return 0;
}

static int parse_mac(const char *s, uint8_t mac[6]) {
    unsigned v[6];
    if (!s || sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++)
        mac[i] = (uint8_t)v[i];
    return 0;
}

static void put_entry(struct nstate *have, struct nstate *foreign, struct nentry *e, uint8_t owner) {
    e->owner = owner;
    struct nstate *dst = owner == OWNER_AGENT ? have : foreign;
    (void)ns_put(dst, e);
}

/* Paged show: calls fn for every element of `array` over all pages. */
typedef void (*row_fn)(const struct jnode *row, struct nstate *have, struct nstate *foreign, void *arg);
static int read_list(const char *cmd, const char *array, row_fn fn, struct nstate *have,
                     struct nstate *foreign, void *arg) {
    uint64_t offset = 0;
    for (;;) {
        char line[160];
        if (offset)
            snprintf(line, sizeof line, "%s offset %llu", cmd, (unsigned long long)offset);
        else
            snprintf(line, sizeof line, "%s", cmd);
        struct jnode *root = request(line, -1, NULL);
        if (!root)
            return FWD_IO;
        const struct jnode *ok = json_get(root, "ok");
        const struct jnode *d = json_get(root, "data");
        if (!ok || !ok->b) {
            json_free(root);
            return 0; /* e.g. the VRF vanished between two reads: treat as empty */
        }
        const struct jnode *list = json_get(d, array);
        for (const struct jnode *r = list ? list->child : NULL; r; r = r->next)
            fn(r, have, foreign, arg);
        const struct jnode *next = json_get(d, "next_offset");
        int more = next && next->type == J_NUM;
        if (more)
            offset = next->u;
        json_free(root);
        if (!more)
            return 0;
    }
}

static void row_vrf(const struct jnode *r, struct nstate *h, struct nstate *f, void *arg) {
    (void)arg;
    const char *name = sget(r, "name");
    if (!name || strcmp(name, "default") == 0)
        return;
    struct nentry e;
    memset(&e, 0, sizeof e);
    e.kind = NE_VRF;
    copy_name(e.name, name);
    e.id = (uint8_t)uget(r, "id");
    put_entry(h, f, &e, owner_of(r));
}

static void row_node(const struct jnode *r, struct nstate *h, struct nstate *f, void *arg) {
    (void)arg;
    struct nentry e;
    memset(&e, 0, sizeof e);
    e.kind = NE_NODE;
    copy_name(e.name, sget(r, "name"));
    if (!sget(r, "ip") || parse_ip(sget(r, "ip"), &e.ip, NULL) != 0)
        return;
    (void)parse_mac(sget(r, "rmac"), e.rmac);
    put_entry(h, f, &e, owner_of(r));
}

static void row_port(const struct jnode *r, struct nstate *h, struct nstate *f, void *arg) {
    (void)arg;
    const char *role = sget(r, "role");
    if (!role || strcmp(role, "vm") != 0)
        return;
    struct nentry e;
    memset(&e, 0, sizeof e);
    e.kind = NE_PORT;
    copy_name(e.name, sget(r, "name"));
    copy_name(e.vrf, sget(r, "vrf"));
    if (!sget(r, "ip") || parse_ip(sget(r, "ip"), &e.prefix, &e.plen) != 0)
        return;
    put_entry(h, f, &e, owner_of(r));
}

static void row_neigh(const struct jnode *r, struct nstate *h, struct nstate *f, void *arg) {
    (void)arg;
    const char *vrf = sget(r, "vrf"), *kind = sget(r, "kind");
    if (!vrf || strcmp(vrf, "underlay") == 0 || !kind || strcmp(kind, "static") != 0)
        return;
    struct nentry e;
    memset(&e, 0, sizeof e);
    e.kind = NE_NEIGH;
    copy_name(e.vrf, vrf);
    if (!sget(r, "ip") || parse_ip(sget(r, "ip"), &e.ip, NULL) != 0 || parse_mac(sget(r, "mac"), e.mac) != 0)
        return;
    copy_name(e.port, sget(r, "port"));
    put_entry(h, f, &e, owner_of(r));
}

static void row_route(const struct jnode *r, struct nstate *h, struct nstate *f, void *arg) {
    (void)arg;
    const char *origin = sget(r, "origin");
    if (!origin || (strcmp(origin, "remote") != 0 && strcmp(origin, "static") != 0))
        return;
    struct nentry e;
    memset(&e, 0, sizeof e);
    e.kind = NE_ROUTE;
    copy_name(e.vrf, sget(r, "vrf"));
    if (!sget(r, "prefix") || parse_ip(sget(r, "prefix"), &e.prefix, &e.plen) != 0)
        return;
    if (strcmp(origin, "remote") == 0) {
        copy_name(e.node, sget(r, "node"));
        const char *enc = sget(r, "encap");
        e.encap = enc && strcmp(enc, "vxlan") == 0 ? NE_ENCAP_VXLAN : NE_ENCAP_MPLSOUDP;
        e.tag = (uint32_t)uget(r, "tag");
    }
    put_entry(h, f, &e, owner_of(r));
}

struct vrfnames {
    char n[64][NE_NAME];
    unsigned cnt;
};

static void collect_vrf_name(const struct jnode *r, struct nstate *h, struct nstate *f, void *arg) {
    (void)h;
    (void)f;
    struct vrfnames *v = arg;
    const char *n = sget(r, "name");
    if (n && strcmp(n, "default") != 0 && v->cnt < 64)
        copy_name(v->n[v->cnt++], n);
}

int fwd_read(struct nstate *have, struct nstate *foreign) {
    ns_clear(have);
    ns_clear(foreign);
    int rc;
    if ((rc = read_list("vrf show", "vrfs", row_vrf, have, foreign, NULL)) != 0)
        return rc;
    if ((rc = read_list("node show", "nodes", row_node, have, foreign, NULL)) != 0)
        return rc;
    if ((rc = read_list("port show", "ports", row_port, have, foreign, NULL)) != 0)
        return rc;
    if ((rc = read_list("neigh show", "neighbours", row_neigh, have, foreign, NULL)) != 0)
        return rc;
    /* routes are listed per VRF */
    static struct vrfnames names;
    names.cnt = 0;
    if ((rc = read_list("vrf show", "vrfs", collect_vrf_name, have, foreign, &names)) != 0)
        return rc;
    for (unsigned i = 0; i < names.cnt; i++) {
        char cmd[64];
        snprintf(cmd, sizeof cmd, "route show vrf %s", names.n[i]);
        if ((rc = read_list(cmd, "routes", row_route, have, foreign, NULL)) != 0)
            return rc;
    }
    /* labels and VNIs */
    struct jnode *root = request("tunnel show", -1, NULL);
    if (!root)
        return FWD_IO;
    const struct jnode *d = json_get(root, "data");
    const struct jnode *labels = json_get(d, "labels"), *vnis = json_get(d, "vnis");
    for (const struct jnode *r = labels ? labels->child : NULL; r; r = r->next) {
        struct nentry e;
        memset(&e, 0, sizeof e);
        e.kind = NE_LABEL;
        e.label = (uint32_t)uget(r, "label");
        copy_name(e.port, sget(r, "port"));
        put_entry(have, foreign, &e, owner_of(r));
    }
    for (const struct jnode *r = vnis ? vnis->child : NULL; r; r = r->next) {
        struct nentry e;
        memset(&e, 0, sizeof e);
        e.kind = NE_VNI;
        e.vni = (uint32_t)uget(r, "vni");
        copy_name(e.vrf, sget(r, "vrf"));
        put_entry(have, foreign, &e, owner_of(r));
    }
    json_free(root);
    return 0;
}

int fwd_refresh_identity(void) {
    struct jnode *root = request("tunnel show", -1, NULL);
    if (!root)
        return FWD_IO;
    const struct jnode *u = json_get(json_get(root, "data"), "underlay");
    if (u && u->type == J_OBJ && sget(u, "ip") && parse_ip(sget(u, "ip"), &g_ag.underlay_ip, NULL) == 0 &&
        parse_mac(sget(u, "mac"), g_ag.underlay_mac) == 0)
        g_ag.underlay_known = true;
    json_free(root);
    root = request("version", -1, NULL);
    if (!root)
        return FWD_IO;
    const char *b = sget(json_get(root, "data"), "boot_id");
    if (b)
        snprintf(g_ag.boot_id, sizeof g_ag.boot_id, "%.16s", b);
    json_free(root);
    return 0;
}
