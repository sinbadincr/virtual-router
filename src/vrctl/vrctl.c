/* vrctl: send one command to minivrd over the control socket (contracts/cli.md). */
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include "minivr/json_in.h"
#include "minivr/frame.h"

#define EXIT_REJECTED 1
#define EXIT_USAGE 2
#define EXIT_UNREACHABLE 3
#define PROTOCOL 1

static const char *const known[] = {
    "port add", "port show", "port set", "route show", "route add", "route del", "route lookup",
    "neigh show", "neigh add", "neigh del", "stats show", "stats clear", "icmp-ratelimit",
    "version", "debug crash",
    "vrf add", "vrf del", "vrf show", "underlay add", "node add", "node set", "node del",
    "node show", "route replace", "label add", "label del", "vni add", "vni del", "tunnel show",
};

static int is_known(const char *w0, const char *w1) {
    for (size_t i = 0; i < sizeof known / sizeof *known; i++) {
        const char *k = known[i];
        const char *sp = strchr(k, ' ');
        size_t n0 = sp ? (size_t)(sp - k) : strlen(k);
        if (strlen(w0) != n0 || strncmp(w0, k, n0) != 0)
            continue;
        if (!sp)
            return 1;
        if (w1 && strcmp(w1, sp + 1) == 0)
            return 1;
    }
    return 0;
}

static int send_all(int fd, const void *p, size_t n) {
    const char *c = p;
    while (n) {
        ssize_t w = send(fd, c, n, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        c += w;
        n -= (size_t)w;
    }
    return 0;
}

static struct frame_rx rx;

/* Returns the JSON payload (malloc'ed, NUL-terminated) of the next response, or NULL. */
static char *recv_frame(int fd, size_t *len_out) {
    frame_rx_init(&rx);
    for (;;) {
        const uint8_t *p;
        size_t len;
        int g = frame_rx_get(&rx, &p, &len);
        if (g < 0)
            return NULL;
        if (g == 1) {
            char *s = malloc(len + 1);
            if (!s)
                return NULL;
            memcpy(s, p, len);
            s[len] = 0;
            *len_out = len;
            return s;
        }
        uint8_t buf[4096];
        ssize_t n = recv(fd, buf, sizeof buf, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return NULL;
        size_t off = 0;
        while (off < (size_t)n) {
            size_t used = frame_rx_feed(&rx, buf + off, (size_t)n - off);
            if (used == 0)
                break;
            off += used;
        }
    }
}

static int request(int fd, const char *cmd, char **resp, size_t *rlen) {
    uint8_t *out = malloc(FRAME_HDR + strlen(cmd));
    if (!out)
        return -1;
    int n = frame_encode(cmd, strlen(cmd), out, FRAME_HDR + strlen(cmd));
    int rc = n < 0 ? -1 : send_all(fd, out, (size_t)n);
    free(out);
    (void)rc; /* a failed send may still be followed by a server-sent error frame */
    *resp = recv_frame(fd, rlen);
    return *resp ? 0 : -1;
}

static int g_continuation; /* later pages of one listing: no repeated header */
static int g_owner;        /* show the OWNER column: some row is not owned by `config` */

static void hdr_end(void) {
    if (g_owner)
        printf("  OWNER");
    putchar('\n');
}

static const char *sval(const struct jnode *o, const char *k, const char *dflt) {
    const struct jnode *n = json_get(o, k);
    return n && n->type == J_STR && n->str ? n->str : dflt;
}

static unsigned long long uval(const struct jnode *o, const char *k) {
    const struct jnode *n = json_get(o, k);
    return n && n->type == J_NUM ? (unsigned long long)n->u : 0ULL;
}

/* Phase 1 columns stay byte-identical for a lab that only uses the default VRF; once a listing
 * shows a tenant VRF, a remote route or the underlay, columns for them are added. */
static int is_default_vrf(const struct jnode *r) {
    return strcmp(sval(r, "vrf", "default"), "default") == 0;
}

static void row_end(const struct jnode *r) {
    if (g_owner) {
        const struct jnode *o = json_get(r, "owner");
        printf("  %s", o && o->str ? o->str : "config");
    }
    putchar('\n');
}

/* Phase 1 and 2 tables stay byte-identical while every entry is owned by `config`. */
static int owners_shown(const struct jnode *list) {
    for (const struct jnode *r = list ? list->child : NULL; r; r = r->next) {
        const struct jnode *o = json_get(r, "owner");
        if (o && o->str && strcmp(o->str, "config") != 0)
            return 1;
    }
    return 0;
}

static int routes_extended(const struct jnode *list) {
    for (const struct jnode *r = list ? list->child : NULL; r; r = r->next)
        if (!is_default_vrf(r) || strcmp(sval(r, "origin", ""), "remote") == 0)
            return 1;
    return 0;
}

static void render_route_row(const struct jnode *r, int ext) {
    if (!ext) {
        printf("%-16s%-6s%-12s%s", sval(r, "prefix", "?"), sval(r, "port", "-"),
               sval(r, "gateway", "-"), sval(r, "origin", "?"));
        row_end(r);
        return;
    }
    char nh[48] = "";
    if (strcmp(sval(r, "origin", ""), "remote") == 0)
        snprintf(nh, sizeof nh, "%s %s %llu", sval(r, "node", "?"), sval(r, "encap", "?"),
                 uval(r, "tag"));
    printf("%-10s%-16s%-6s%-12s%-10s%s", sval(r, "vrf", "default"), sval(r, "prefix", "?"),
           sval(r, "port", "-"), sval(r, "gateway", "-"), sval(r, "origin", "?"), nh);
    row_end(r);
}

static void route_header(int ext) {
    if (ext)
        printf("%-10s%-16s%-6s%-12s%-10s%s", "VRF", "PREFIX", "PORT", "GATEWAY", "ORIGIN",
               "REMOTE");
    else
        printf("%-16s%-6s%-12s%s", "PREFIX", "PORT", "GATEWAY", "ORIGIN");
    hdr_end();
}

/* Commands without a table renderer (controller and agent views, session show, ...). */
static void print_json(const struct jnode *n, int depth) {
    if (!n) {
        fputs("null", stdout);
        return;
    }
    switch (n->type) {
    case J_NULL: fputs("null", stdout); break;
    case J_BOOL: fputs(n->b ? "true" : "false", stdout); break;
    case J_NUM:
        if (n->is_int)
            printf("%llu", (unsigned long long)n->u);
        else
            printf("%g", n->d);
        break;
    case J_STR: printf("\"%s\"", n->str ? n->str : ""); break;
    case J_ARR:
    case J_OBJ: {
        char open = n->type == J_ARR ? '[' : '{', close = n->type == J_ARR ? ']' : '}';
        if (!n->child) {
            printf("%c%c", open, close);
            break;
        }
        printf("%c\n", open);
        for (const struct jnode *c = n->child; c; c = c->next) {
            printf("%*s", (depth + 1) * 2, "");
            if (n->type == J_OBJ)
                printf("\"%s\": ", c->key ? c->key : "");
            print_json(c, depth + 1);
            puts(c->next ? "," : "");
        }
        printf("%*s%c", depth * 2, "", close);
        break;
    }
    }
}

static void render_table(const char *cmd, const struct jnode *d) {
    if (strcmp(cmd, "route show") == 0) {
        const struct jnode *list = json_get(d, "routes");
        int ext = routes_extended(list);
        g_owner = owners_shown(list);
        if (!g_continuation)
            route_header(ext);
        for (const struct jnode *r = list ? list->child : NULL; r; r = r->next)
            render_route_row(r, ext);
    } else if (strcmp(cmd, "route lookup") == 0) {
        const struct jnode *r = json_get(d, "route");
        g_owner = owners_shown(NULL) || (json_get(r, "owner") && strcmp(sval(r, "owner", "config"), "config") != 0);
        int ext = !is_default_vrf(r) || strcmp(sval(r, "origin", ""), "remote") == 0;
        route_header(ext);
        render_route_row(r, ext);
    } else if (strcmp(cmd, "port show") == 0) {
        const struct jnode *list = json_get(d, "ports");
        int ext = 0;
        for (const struct jnode *r = list ? list->child : NULL; r; r = r->next)
            ext |= !is_default_vrf(r);
        for (const struct jnode *r = list ? list->child : NULL; r; r = r->next)
            ext |= strcmp(sval(r, "role", "vm"), "underlay") == 0;
        g_owner = owners_shown(list);
        printf("%-6s%-8s%s%-19s%-17s%-6s%-6s%-6s%10s%12s%10s%12s%8s", "NAME", "IFNAME",
               ext ? "ROLE      VRF       " : "", "MAC", "IP", "MTU", "ADMIN", "OPER", "RX_PKTS",
               "RX_BYTES", "TX_PKTS", "TX_BYTES", "DROPS");
        hdr_end();
        for (const struct jnode *r = list ? list->child : NULL; r; r = r->next) {
            char rv[32] = "";
            if (ext)
                snprintf(rv, sizeof rv, "%-10s%-10s", sval(r, "role", "vm"), sval(r, "vrf", "-"));
            printf("%-6s%-8s%s%-19s%-17s%-6llu%-6s%-6s%10llu%12llu%10llu%12llu%8llu",
                   sval(r, "name", "?"), sval(r, "ifname", "?"), rv, sval(r, "mac", "?"),
                   sval(r, "ip", "?"), uval(r, "mtu"), sval(r, "admin", "?"), sval(r, "oper", "?"),
                   uval(r, "rx_pkts"), uval(r, "rx_bytes"), uval(r, "tx_pkts"), uval(r, "tx_bytes"),
                   uval(r, "drops"));
            row_end(r);
        }
    } else if (strcmp(cmd, "neigh show") == 0) {
        const struct jnode *list = json_get(d, "neighbours");
        int ext = 0;
        for (const struct jnode *r = list ? list->child : NULL; r; r = r->next)
            ext |= !is_default_vrf(r);
        g_owner = owners_shown(list);
        if (!g_continuation) {
            printf("%s%-16s%-19s%-6s%-9s%-12s%s", ext ? "VRF       " : "", "IP", "MAC", "PORT",
                   "KIND", "STATE", "HELD");
            hdr_end();
        }
        for (const struct jnode *r = list ? list->child : NULL; r; r = r->next) {
            if (ext)
                printf("%-10s", sval(r, "vrf", "?"));
            printf("%-16s%-19s%-6s%-9s%-12s%llu", sval(r, "ip", "?"), sval(r, "mac", "-"),
                   sval(r, "port", "?"), sval(r, "kind", "?"), sval(r, "state", "?"),
                   uval(r, "held"));
            row_end(r);
        }
    } else if (strcmp(cmd, "vrf show") == 0) {
        const struct jnode *list = json_get(d, "vrfs");
        g_owner = owners_shown(list);
        printf("%-16s%-4s%-24s%7s%12s%8s%6s", "NAME", "ID", "PORTS", "ROUTES", "NEIGHBOURS",
               "LABELS", "VNIS");
        hdr_end();
        for (const struct jnode *r = list ? list->child : NULL; r; r = r->next) {
            char ports[96] = "";
            const struct jnode *pl = json_get(r, "ports");
            for (const struct jnode *p = pl ? pl->child : NULL; p; p = p->next) {
                size_t l = strlen(ports);
                snprintf(ports + l, sizeof ports - l, "%s%s", l ? "," : "", p->str ? p->str : "?");
            }
            printf("%-16s%-4llu%-24s%7llu%12llu%8llu%6llu", sval(r, "name", "?"), uval(r, "id"),
                   ports[0] ? ports : "-", uval(r, "routes"), uval(r, "neighbours"),
                   uval(r, "labels"), uval(r, "vnis"));
            row_end(r);
        }
    } else if (strcmp(cmd, "node show") == 0) {
        const struct jnode *list = json_get(d, "nodes");
        g_owner = owners_shown(list);
        printf("%-10s%-14s%-19s%-19s%-12s%s", "NAME", "IP", "RMAC", "UNDERLAY_MAC", "STATE",
               "ENCAP(pkts/bytes) DECAP(pkts/bytes)  [mplsoudp | vxlan]");
        hdr_end();
        for (const struct jnode *r = list ? list->child : NULL; r; r = r->next) {
            const struct jnode *en = json_get(r, "encap"), *de = json_get(r, "decap");
            const struct jnode *em = json_get(en, "mplsoudp"), *ev = json_get(en, "vxlan");
            const struct jnode *dm = json_get(de, "mplsoudp"), *dv = json_get(de, "vxlan");
            printf("%-10s%-14s%-19s%-19s%-12s%llu/%llu | %llu/%llu   %llu/%llu | %llu/%llu",
                   sval(r, "name", "?"), sval(r, "ip", "?"), sval(r, "rmac", "-"),
                   sval(r, "underlay_mac", "-"), sval(r, "state", "?"), uval(em, "pkts"),
                   uval(em, "bytes"), uval(ev, "pkts"), uval(ev, "bytes"), uval(dm, "pkts"),
                   uval(dm, "bytes"), uval(dv, "pkts"), uval(dv, "bytes"));
            row_end(r);
        }
    } else if (strcmp(cmd, "tunnel show") == 0) {
        const struct jnode *u = json_get(d, "underlay");
        if (u && u->type == J_OBJ)
            printf("underlay %s %s mac %s mtu %llu\n", sval(u, "port", "?"), sval(u, "ip", "?"),
                   sval(u, "mac", "?"), uval(u, "mtu"));
        else
            puts("underlay none");
        const struct jnode *ll = json_get(d, "labels"), *vl = json_get(d, "vnis");
        g_owner = owners_shown(ll) || owners_shown(vl);
        printf("\n%-10s%-8s%s", "LABEL", "PORT", "VRF");
        hdr_end();
        for (const struct jnode *r = ll ? ll->child : NULL; r; r = r->next) {
            printf("%-10llu%-8s%s", uval(r, "label"), sval(r, "port", "?"), sval(r, "vrf", "?"));
            row_end(r);
        }
        printf("\n%-10s%s", "VNI", "VRF");
        hdr_end();
        for (const struct jnode *r = vl ? vl->child : NULL; r; r = r->next) {
            printf("%-10llu%s", uval(r, "vni"), sval(r, "vrf", "?"));
            row_end(r);
        }
    } else if (strcmp(cmd, "stats show") == 0) {
        printf("%-6s%10s%12s%10s%12s%8s\n", "PORT", "RX_PKTS", "RX_BYTES", "TX_PKTS", "TX_BYTES",
               "DROPS");
        for (const struct jnode *r = json_get(d, "ports") ? json_get(d, "ports")->child : NULL; r;
             r = r->next)
            printf("%-6s%10llu%12llu%10llu%12llu%8llu\n", sval(r, "name", "?"), uval(r, "rx_pkts"),
                   uval(r, "rx_bytes"), uval(r, "tx_pkts"), uval(r, "tx_bytes"), uval(r, "drops"));
        const struct jnode *dr = json_get(d, "drops");
        printf("\nDROPS total %llu\n", uval(dr, "total"));
        const struct jnode *reasons = json_get(dr, "reasons");
        for (const struct jnode *r = reasons ? reasons->child : NULL; r; r = r->next)
            printf("  %-24s%llu\n", r->key ? r->key : "?", (unsigned long long)r->u);
        const struct jnode *ev = json_get(d, "events");
        printf("\nEVENTS\n");
        for (const struct jnode *r = ev ? ev->child : NULL; r; r = r->next)
            printf("  %-24s%llu\n", r->key ? r->key : "?", (unsigned long long)r->u);
        const struct jnode *nodes = json_get(d, "nodes");
        if (nodes && nodes->child && nodes->child->next) { /* more than the `unknown` pseudo-node */
            printf("\nNODES (encap/decap pkts, mplsoudp | vxlan)\n");
            for (const struct jnode *r = nodes->child; r; r = r->next) {
                const struct jnode *en = json_get(r, "encap"), *de = json_get(r, "decap");
                printf("  %-12s%llu/%llu | %llu/%llu\n", sval(r, "name", "?"),
                       uval(json_get(en, "mplsoudp"), "pkts"), uval(json_get(de, "mplsoudp"), "pkts"),
                       uval(json_get(en, "vxlan"), "pkts"), uval(json_get(de, "vxlan"), "pkts"));
            }
        }
        const struct jnode *mb = json_get(d, "mbuf");
        printf("\nMBUF in_use %llu / %llu\n", uval(mb, "in_use"), uval(mb, "total"));
    } else {
        print_json(d, 0);
        putchar('\n');
    }
}

static int render(const char *cmd, const struct jnode *root, const char *raw, int json) {
    const struct jnode *ok = json_get(root, "ok");
    if (!ok || ok->type != J_BOOL) {
        fprintf(stderr, "vrctl: malformed response\n");
        return EXIT_UNREACHABLE;
    }
    if (json) {
        puts(raw);
        return ok->b ? 0 : EXIT_REJECTED;
    }
    if (!ok->b) {
        const struct jnode *e = json_get(root, "error");
        const struct jnode *code = json_get(e, "code"), *msg = json_get(e, "message");
        fprintf(stderr, "%s: %s\n", code && code->str ? code->str : "error",
                msg && msg->str ? msg->str : "");
        return EXIT_REJECTED;
    }
    const struct jnode *d = json_get(root, "data");
    char key[32];
    {
        const char *sp = strchr(cmd, ' ');
        const char *sp2 = sp ? strchr(sp + 1, ' ') : NULL;
        size_t n = sp2 ? (size_t)(sp2 - cmd) : strlen(cmd);
        snprintf(key, sizeof key, "%.*s", (int)(n < sizeof key - 1 ? n : sizeof key - 1), cmd);
        cmd = key;
    }
    if (strcmp(cmd, "version") == 0) {
        const struct jnode *v = json_get(d, "version"), *b = json_get(d, "build"),
                           *p = json_get(d, "protocol"), *u = json_get(d, "uptime_s");
        const struct jnode *dm = json_get(d, "daemon");
        printf("%s %s (%s build) protocol %llu uptime %llus\n", dm && dm->str ? dm->str : "minivrd",
               v && v->str ? v->str : "?",
               b && b->str ? b->str : "?", p ? (unsigned long long)p->u : 0ULL,
               u ? (unsigned long long)u->u : 0ULL);
        return 0;
    }
    (void)raw;
    render_table(cmd, d);
    return 0;
}

int main(int argc, char **argv) {
    const char *sock = getenv("MINIVR_SOCK");
    if (!sock || !*sock)
        sock = "/run/minivr/minivr.sock";
    int json = 0, o;
    while ((o = getopt(argc, argv, "+s:j")) != -1) {
        if (o == 's')
            sock = optarg;
        else if (o == 'j')
            json = 1;
        else {
            fprintf(stderr, "usage: vrctl [-s <socket>] [-j] <command> [args...]\n");
            return EXIT_USAGE;
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "usage: vrctl [-s <socket>] [-j] <command> [args...]\n");
        return EXIT_USAGE;
    }
    if (!is_known(argv[optind], optind + 1 < argc ? argv[optind + 1] : NULL)) {
        fprintf(stderr, "vrctl: unknown command '%s'\n", argv[optind]);
        return EXIT_USAGE;
    }
    char cmd[1024];
    size_t n = 0;
    for (int i = optind; i < argc; i++) {
        size_t l = strlen(argv[i]);
        if (n + l + 2 > sizeof cmd) {
            fprintf(stderr, "vrctl: command too long\n");
            return EXIT_USAGE;
        }
        if (i > optind)
            cmd[n++] = ' ';
        memcpy(cmd + n, argv[i], l);
        n += l;
    }
    cmd[n] = 0;

    struct sockaddr_un addr;
    if (strlen(sock) >= sizeof addr.sun_path) {
        fprintf(stderr, "vrctl: socket path too long\n");
        return EXIT_USAGE;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, sock);
    if (fd < 0 || connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        fprintf(stderr, "vrctl: cannot connect to %s: %s\n", sock, strerror(errno));
        return EXIT_UNREACHABLE;
    }
    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    /* Handshake: refuse a server speaking another protocol version. */
    char *resp;
    size_t rlen;
    if (request(fd, "version", &resp, &rlen) != 0) {
        fprintf(stderr, "vrctl: no response from forwarder\n");
        return EXIT_UNREACHABLE;
    }
    struct jnode *root = json_parse(resp, rlen);
    const struct jnode *ok = json_get(root, "ok");
    if (!root || !ok || ok->type != J_BOOL) {
        fprintf(stderr, "vrctl: malformed response from forwarder\n");
        return EXIT_UNREACHABLE;
    }
    if (!ok->b) { /* e.g. not-permitted, busy */
        const struct jnode *e = json_get(root, "error");
        const struct jnode *code = json_get(e, "code"), *msg = json_get(e, "message");
        fprintf(stderr, "vrctl: forwarder refused the connection: %s: %s\n",
                code && code->str ? code->str : "error", msg && msg->str ? msg->str : "");
        return EXIT_UNREACHABLE;
    }
    const struct jnode *proto = json_get(json_get(root, "data"), "protocol");
    if (!proto || !proto->is_int || proto->u != PROTOCOL) {
        fprintf(stderr, "vrctl: protocol mismatch (client speaks %d)\n", PROTOCOL);
        return EXIT_UNREACHABLE;
    }
    int rc;
    if (strcmp(cmd, "version") == 0) {
        rc = render(cmd, root, resp, json);
    } else {
        json_free(root);
        free(resp);
        if (request(fd, cmd, &resp, &rlen) != 0) {
            fprintf(stderr, "vrctl: no response from forwarder\n");
            return EXIT_UNREACHABLE;
        }
        root = json_parse(resp, rlen);
        if (!root) {
            fprintf(stderr, "vrctl: malformed response from forwarder\n");
            return EXIT_UNREACHABLE;
        }
        rc = render(cmd, root, resp, json);
        /* listings are paged by the server; in table mode follow next_offset to the end
         * (with -j the caller gets one page and pages itself) */
        int paged = !json && (strncmp(cmd, "route show", 10) == 0 || strncmp(cmd, "neigh show", 10) == 0);
        while (paged && rc == 0) {
            const struct jnode *next = json_get(json_get(root, "data"), "next_offset");
            if (!next || next->type != J_NUM)
                break;
            char page_cmd[1100];
            snprintf(page_cmd, sizeof page_cmd, "%s offset %llu", cmd, (unsigned long long)next->u);
            json_free(root);
            free(resp);
            if (request(fd, page_cmd, &resp, &rlen) != 0 || !(root = json_parse(resp, rlen))) {
                fprintf(stderr, "vrctl: no response from forwarder\n");
                return EXIT_UNREACHABLE;
            }
            g_continuation = 1;
            rc = render(cmd, root, resp, json);
        }
    }
    json_free(root);
    free(resp);
    close(fd);
    return rc;
}
