#ifndef MINIVR_CTL_MODEL_H
#define MINIVR_CTL_MODEL_H
#include <stdbool.h>
#include <stdint.h>

#include "cmd.h"
#include "json_out.h"
#include "nodestate.h"

/* Controller model (data-model §1-3): intent, bindings, label allocation, compute(). Pure code,
 * fixed capacities, no heap, no I/O. */

#define CM_MAX_NODES 16
#define CM_MAX_TENANTS 64
#define CM_MAX_SUBNETS 256
#define CM_MAX_VMIS 1024
#define CM_MAX_BOUND_PER_NODE 16
#define CM_LABEL_MIN 1000
#define CM_LABEL_MAX 1999
#define CM_MAX_QUARANTINE 1024
#define CM_NAME_MAX 15

struct cm_tenant {
    bool used;
    char name[NE_NAME];
    uint8_t id;
    uint32_t vni;
    uint8_t encap; /* enum ne_encap */
};

struct cm_subnet {
    bool used;
    uint8_t tenant; /* index */
    uint32_t prefix, gw;
    uint8_t plen;
};

struct cm_node {
    bool used;
    char name[NE_NAME];
    bool addr_known; /* learned from HELLO: underlay_ip and rmac are valid */
    uint32_t underlay_ip;
    uint8_t rmac[6];
    bool connected; /* a live session (set by the session layer) */
};

struct cm_vmi {
    bool used;
    char name[NE_NAME];
    uint8_t tenant; /* index */
    uint32_t ip;
    uint8_t mac[6];
    int8_t node; /* index, or -1 when unbound */
    char port[NE_NAME];
    uint16_t label;
    uint64_t since_s;
};

struct cm_quar {
    bool used;
    uint8_t node;
    uint16_t label;
};

struct cmodel {
    struct cm_tenant tenants[CM_MAX_TENANTS];
    struct cm_subnet subnets[CM_MAX_SUBNETS];
    struct cm_node nodes[CM_MAX_NODES];
    struct cm_vmi vmis[CM_MAX_VMIS];
    struct cm_quar quar[CM_MAX_QUARANTINE];
    uint64_t gen;     /* +1 on every change that can alter a node's state or the state file */
    uint64_t clock_s; /* set by the caller; stamps binding `since` */
};

/* BIND outcomes (map to protocol ERR_CODEs in the session layer). */
enum cm_bind_res { CM_BIND_OK = 0, CM_BIND_UNKNOWN_VMI, CM_BIND_PORT_IN_USE, CM_BIND_TABLE_FULL };

void cm_init(struct cmodel *m);

/* Intent. Every function returns 0 or -1 with err filled in; an error leaves the model unchanged. */
int cm_tenant_add(struct cmodel *m, const char *name, unsigned id, uint32_t vni, unsigned encap,
                  struct cmd_err *err);
int cm_tenant_set_encap(struct cmodel *m, const char *name, unsigned encap, struct cmd_err *err);
int cm_tenant_del(struct cmodel *m, const char *name, struct cmd_err *err);
int cm_subnet_add(struct cmodel *m, const char *tenant, uint32_t prefix, uint8_t plen, uint32_t gw,
                  struct cmd_err *err);
int cm_subnet_del(struct cmodel *m, const char *tenant, uint32_t prefix, uint8_t plen,
                  struct cmd_err *err);
int cm_node_add(struct cmodel *m, const char *name, struct cmd_err *err);
int cm_node_del(struct cmodel *m, const char *name, struct cmd_err *err);
int cm_node_forget(struct cmodel *m, const char *name, struct cmd_err *err);
int cm_vmi_add(struct cmodel *m, const char *name, const char *tenant, uint32_t ip,
               const uint8_t mac[6], struct cmd_err *err);
int cm_vmi_del(struct cmodel *m, const char *name, struct cmd_err *err);

int cm_tenant_idx(const struct cmodel *m, const char *name); /* -1 */
int cm_node_idx(const struct cmodel *m, const char *name);
int cm_vmi_idx(const struct cmodel *m, const char *name);
const struct cm_subnet *cm_vmi_subnet(const struct cmodel *m, const struct cm_vmi *v);
unsigned cm_bound_count(const struct cmodel *m, unsigned node);

/* Node-reported facts and bindings. */
void cm_node_learn(struct cmodel *m, unsigned node, uint32_t underlay_ip, const uint8_t rmac[6]);
/* Binds `vmi` to `node` at `port` (a bind on another node moves it). On CM_BIND_OK *label is the
 * VMI's label on `node`; *moved_from is the node it left, or -1. */
enum cm_bind_res cm_bind(struct cmodel *m, unsigned node, const char *vmi, const char *port,
                         unsigned *label, int *moved_from);
/* Removes the binding if it is on `node`; the label goes into quarantine. 0 if it was bound. */
int cm_unbind(struct cmodel *m, unsigned node, const char *vmi);
/* The node ACKed the update that deleted its mapping: the label may be reused. */
void cm_label_release(struct cmodel *m, unsigned node, unsigned label);
bool cm_label_quarantined(const struct cmodel *m, unsigned node, unsigned label);
unsigned cm_quarantine_count(const struct cmodel *m, unsigned node);

/* ---- compute (data-model §3) ---- */
/* Fills `out` with the state node `node` must have. -1 when `out` is too small. */
int cm_compute(const struct cmodel *m, unsigned node, struct nstate *out);

/* ---- grammar (contracts/controller-cli.md) ---- */
enum cg_where { CG_FILE = 1, CG_CLI = 2, CG_STATE = 4 };

struct cg_node_info {
    const char *state; /* "none", "hello", "syncing", "in-sync", "out-of-sync" */
    char peer[24];
    uint64_t since_s;
    char last_error[48];
    uint64_t msgs_in, msgs_out, bytes_in, bytes_out;
    uint32_t last_seq, acked_seq;
    bool in_sync;
    unsigned entries;
    unsigned nerr;
    struct {
        char kind[8];
        char key[48];
        char code[24];
        char text[80];
    } errs[8];
    uint64_t proto_err[24]; /* indexed by enum proto_err */
};

struct cg_stats {
    uint64_t sessions_accepted, sessions_rejected, updates_sent, entries_sent, ack_errors, state_writes;
    uint64_t proto_err[24];
    uint64_t reject[16]; /* indexed by ERR_CODE */
};

struct cg_ops { /* what only the running controller knows; tests pass fakes */
    void (*node_info)(void *arg, unsigned node, struct cg_node_info *out);
    void (*stats)(void *arg, struct cg_stats *out);
    uint64_t (*uptime_s)(void *arg);
    void *arg;
};

/* Run one line. `where` says where it came from (file lines may not use CLI-only commands and the
 * other way round; bind/quarantine are state-only). Writes the response envelope into `out` for
 * CLI lines; file/state callers pass a scratch jw. */
int cg_exec(struct cmodel *m, const char *line, enum cg_where where, const struct cg_ops *ops,
            struct jw *out, struct cmd_err *err);
/* One entry as JSON (shared with the agent's `want show`). */
void ne_json(struct jw *w, const struct nentry *e);
void ne_json_ex(struct jw *w, const struct nentry *e, const char *owner); /* + "owner" when set */
/* Serialise intent + bindings + quarantine in the grammar (the state file). Writes into buf;
 * returns the length or -1 if cap is too small. */
int cm_serialize(const struct cmodel *m, char *buf, size_t cap);
#endif
