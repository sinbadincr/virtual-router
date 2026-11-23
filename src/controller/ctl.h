#ifndef MINIVR_CTL_INTERNAL_H
#define MINIVR_CTL_INTERNAL_H
#include <stdint.h>

#include "minivr/ctl_model.h"
#include "minivr/ctl_store.h"
#include "minivr/netio.h"

/* Shared between session.c, localctl.c and main.c of minivr-ctld. */
struct ctl {
    struct cmodel m;
    struct cg_stats stats;
    uint64_t start_ns;
    const char *state_path;
    uint64_t saved_gen;
};
extern struct ctl g_ctl;

uint64_t ctl_now_s(void); /* seconds since start, also stamps m.clock_s */

/* session.c */
int sess_listen(const char *ip, uint16_t port);
void sess_tick(uint64_t now_ns);          /* keepalive, hold timer */
void sess_push_all(void);                 /* recompute every node, send the diffs */
void sess_shutdown(void);                 /* REJECT(shutdown) to every session, close */
void sess_node_info(unsigned node, struct cg_node_info *out);
bool sess_node_live(unsigned node);

/* main.c: persist the model if it changed, then push the diffs (state is written first) */
void ctl_commit(void);

/* localctl.c */
int localctl_init(const char *path, unsigned allowed_uid);
#endif
