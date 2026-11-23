/* Local VM-interface bindings (plug/unplug), persisted in <state-dir>/bindings. */
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "agent.h"
#include "minivr/log.h"

static char path[200];

int bindings_save(void) {
    char tmp[220];
    snprintf(path, sizeof path, "%s/bindings", g_ag.state_dir);
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f)
        return -1;
    fputs("# minivr-agent local bindings (plug <vmi> port <port>)\n", f);
    for (int i = 0; i < AG_MAX_BINDINGS; i++)
        if (g_ag.bind[i].used)
            fprintf(f, "plug %s port %s\n", g_ag.bind[i].vmi, g_ag.bind[i].port);
    if (fflush(f) != 0 || fsync(fileno(f)) != 0) {
        fclose(f);
        unlink(tmp);
        return -1;
    }
    fclose(f);
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

int bindings_load(void) {
    if (mkdir(g_ag.state_dir, 0700) < 0 && errno != EEXIST) {
        fprintf(stderr, "minivr-agent: cannot create %s: %s\n", g_ag.state_dir, strerror(errno));
        return -1;
    }
    snprintf(path, sizeof path, "%s/bindings", g_ag.state_dir);
    FILE *f = fopen(path, "r");
    if (!f)
        return errno == ENOENT ? 0 : -1;
    char line[256];
    int lineno = 0;
    while (fgets(line, sizeof line, f)) {
        lineno++;
        char *h = strchr(line, '#');
        if (h)
            *h = 0;
        char a[32], vmi[64], b[32], port[64], extra[8];
        int n = sscanf(line, "%31s %63s %31s %63s %7s", a, vmi, b, port, extra);
        if (n <= 0)
            continue;
        if (n != 4 || strcmp(a, "plug") != 0 || strcmp(b, "port") != 0 || !ne_name_ok(vmi) ||
            !ne_name_ok(port)) {
            fprintf(stderr, "minivr-agent: %s:%d: unparsable binding\n", path, lineno);
            fclose(f);
            return -1;
        }
        int slot = -1;
        for (int i = 0; i < AG_MAX_BINDINGS && slot < 0; i++)
            if (!g_ag.bind[i].used)
                slot = i;
        if (slot < 0) {
            fprintf(stderr, "minivr-agent: %s:%d: too many bindings\n", path, lineno);
            fclose(f);
            return -1;
        }
        g_ag.bind[slot].used = true;
        snprintf(g_ag.bind[slot].vmi, NE_NAME, "%.15s", vmi);
        snprintf(g_ag.bind[slot].port, NE_NAME, "%.15s", port);
        g_ag.bind[slot].reported = false;
    }
    fclose(f);
    return 0;
}

static void err(char code[24], char msg[160], const char *c, const char *m) {
    snprintf(code, 24, "%s", c);
    snprintf(msg, 160, "%s", m);
}

int bindings_plug(const char *vmi, const char *port, char code[24], char msg[160]) {
    if (!ne_name_ok(vmi) || !ne_name_ok(port)) {
        err(code, msg, "bad-syntax", "names are 1..15 characters of [a-z0-9_-]");
        return -1;
    }
    for (int i = 0; i < AG_MAX_BINDINGS; i++) {
        struct ag_binding *b = &g_ag.bind[i];
        if (!b->used)
            continue;
        if (strcmp(b->vmi, vmi) == 0 && strcmp(b->port, port) == 0)
            return 0; /* identical plug: idempotent */
        if (strcmp(b->vmi, vmi) == 0 || strcmp(b->port, port) == 0) {
            err(code, msg, "exists", "the VM interface or the port is already plugged here");
            return -1;
        }
    }
    if (if_nametoindex(port) == 0) {
        err(code, msg, "unknown-port", "no such interface in this node");
        return -1;
    }
    int slot = -1;
    for (int i = 0; i < AG_MAX_BINDINGS && slot < 0; i++)
        if (!g_ag.bind[i].used)
            slot = i;
    if (slot < 0) {
        err(code, msg, "table-full", "too many bindings");
        return -1;
    }
    struct ag_binding *b = &g_ag.bind[slot];
    b->used = true;
    snprintf(b->vmi, NE_NAME, "%.15s", vmi);
    snprintf(b->port, NE_NAME, "%.15s", port);
    b->reported = false;
    if (bindings_save() != 0) { /* persisted before the reply */
        b->used = false;
        err(code, msg, "io-error", "cannot persist the binding");
        return -1;
    }
    return 1; /* new binding */
}

int bindings_unplug(const char *vmi, char code[24], char msg[160]) {
    for (int i = 0; i < AG_MAX_BINDINGS; i++)
        if (g_ag.bind[i].used && strcmp(g_ag.bind[i].vmi, vmi) == 0) {
            struct ag_binding saved = g_ag.bind[i];
            g_ag.bind[i].used = false;
            if (bindings_save() != 0) {
                g_ag.bind[i] = saved;
                err(code, msg, "io-error", "cannot persist the removal");
                return -1;
            }
            return 0;
        }
    err(code, msg, "not-found", "no such binding");
    return -1;
}
