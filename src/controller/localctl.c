/* Local control socket of minivr-ctld: same framing and peer check as minivrd (usrv). */
#include <string.h>

#include "ctl.h"
#include "minivr/clock.h"
#include "minivr/log.h"
#include "minivr/netio.h"

static void node_info_cb(void *arg, unsigned node, struct cg_node_info *out) {
    (void)arg;
    sess_node_info(node, out);
}

static void stats_cb(void *arg, struct cg_stats *out) {
    (void)arg;
    *out = g_ctl.stats;
}

static uint64_t uptime_cb(void *arg) {
    (void)arg;
    return (clock_now_ns() - g_ctl.start_ns) / NS_PER_SEC;
}

static const struct cg_ops ops = {node_info_cb, stats_cb, uptime_cb, NULL};

static void handle(void *arg, const char *line, struct jw *out) {
    (void)arg;
    struct cmd_err err;
    ctl_now_s();
    uint64_t gen = g_ctl.m.gen;
    if (cg_exec(&g_ctl.m, line, CG_CLI, &ops, out, &err) == 0 && g_ctl.m.gen != gen)
        ctl_commit(); /* the state file first, then the diffs to the nodes */
}

int localctl_init(const char *path, unsigned allowed_uid) {
    return usrv_init(path, allowed_uid, handle, NULL);
}
