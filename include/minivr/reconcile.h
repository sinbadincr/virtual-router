#ifndef MINIVR_RECONCILE_H
#define MINIVR_RECONCILE_H
#include <stdbool.h>
#include <stdint.h>

#include "nodestate.h"

/* Agent reconcile (data-model §5, R5, contracts/agent-cli.md). Pure: want/pending bookkeeping
 * and the ordered list of forwarder commands that turns `have` into `want`. */

#define RC_CAP 4096

struct reconciler {
    struct nstate want, pending, foreign;
    struct nentry want_s[RC_CAP], pending_s[RC_CAP], foreign_s[RC_CAP];
    bool want_valid; /* a full sync has completed at least once */
    bool syncing;
    uint32_t gen;
};

void rc_init(struct reconciler *rc);
void rc_sync_begin(struct reconciler *rc, uint32_t gen);
/* Entries of an UPDATE: into `pending` while a full sync runs, else straight into `want`.
 * dels first, then adds. -1 when the set is full. */
int rc_update(struct reconciler *rc, const struct nentry *dels, unsigned ndels,
              const struct nentry *adds, unsigned nadds);
/* SYNC_END with the same GEN makes pending the new want. 0, or -1 for a wrong GEN / no sync. */
int rc_sync_end(struct reconciler *rc, uint32_t gen);
/* Session lost: a sync in progress is discarded, want stays. */
void rc_session_lost(struct reconciler *rc);

struct rc_cmd {
    char text[192];
    bool is_del;
    bool is_port_add; /* the agent opens an AF_PACKET socket for `entry.name` and passes it */
    struct nentry entry;
};

struct rc_conflict {
    struct nentry entry; /* wanted by the controller, but the key is held by config or cli */
};

/* Ordered commands: deletes route -> label, vni -> neigh -> port -> node -> vrf, then adds
 * vrf -> node -> port -> neigh -> label, vni -> route. A PORT (or NODE, VRF) whose value changes
 * is deleted and re-added with its dependents. `have` = agent-owned entries of the forwarder,
 * `rc->foreign` = keys it holds for other owners (their adds become conflicts). Nothing is
 * produced before the first complete sync (a fresh agent never deletes). Returns the command
 * count, or -1 when `cap` is too small. *nconf receives the conflict count. */
int rc_plan(const struct reconciler *rc, const struct nstate *have, struct rc_cmd *out,
            unsigned cap, struct rc_conflict *conf, unsigned conf_cap, unsigned *nconf);

/* Reconnect backoff 0.5 -> 1 -> 2 -> 4 -> 5 s (cap), reset once a session is established. */
struct backoff {
    unsigned ms;
};
void backoff_reset(struct backoff *b);
unsigned backoff_next(struct backoff *b); /* the delay to wait now, then advances */
#endif
