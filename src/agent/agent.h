#ifndef MINIVR_AGENT_INTERNAL_H
#define MINIVR_AGENT_INTERNAL_H
#include <stdbool.h>
#include <stdint.h>

#include "minivr/json_out.h"
#include "minivr/netio.h"
#include "minivr/reconcile.h"

/* Shared between fwd.c, bindings.c, session.c, localctl.c and main.c of minivr-agent. */

#include "minivr/proto.h"
#define AG_MAX_BINDINGS 64
#define AG_MAX_FAILED 32

struct ag_binding {
    bool used;
    char vmi[NE_NAME], port[NE_NAME];
    bool reported;
};

struct ag_failed {
    struct nentry e;
    char cmd[192], code[24], msg[160];
};

enum ag_sess { AS_CONNECTING, AS_HELLO, AS_SYNCING, AS_IN_SYNC };

struct agent {
    char node[NE_NAME];
    char ctrl_ip[16], bind_ip[16];
    uint16_t ctrl_port;
    char fwd_sock[108], sock[108], state_dir[160];
    uint64_t start_ns;

    struct ag_binding bind[AG_MAX_BINDINGS];

    /* forwarder */
    bool fwd_up;
    char boot_id[17], fwd_err[96];
    bool underlay_known;
    uint32_t underlay_ip;
    uint8_t underlay_mac[6];

    /* reconcile */
    struct reconciler rc;
    struct ag_failed failed[AG_MAX_FAILED];
    unsigned nfailed;
    unsigned nconflicts;
    bool dirty; /* something changed: reconcile at the next opportunity */

    /* controller session */
    enum ag_sess sess;
    char last_error[64];
    uint64_t sess_since_ns;
    uint64_t msgs_in, msgs_out, bytes_in, bytes_out;
    uint64_t proto_err[PE_COUNT];
    unsigned backoff_ms;
    uint32_t gen;
    uint16_t keepalive_s, hold_s;

    /* BIND answers (unknown-vmi, port-in-use, table-full) shown by `status` */
    struct {
        char vmi[NE_NAME], code[24], text[80];
    } bind_err[8];
    unsigned nbind_err;
    struct nentry conflicts[16]; /* wanted by the controller, held by config or cli */
    unsigned nconf;
    bool adopted_logged;
};
extern struct agent g_ag;
extern struct nstate g_have; /* agent-owned entries read from the forwarder at the last reconcile */
extern struct nentry g_have_s[RC_CAP];

/* fwd.c */
enum fwd_res { FWD_OK = 0, FWD_UNREACHABLE = -1, FWD_BUSY = -2, FWD_IO = -3 };
int fwd_connect(void);          /* connect + `session agent`; FWD_OK, FWD_UNREACHABLE, FWD_BUSY */
void fwd_close(void);
/* One command. 0 ok; -1 refused (code/msg filled); FWD_IO on a broken connection. pass_fd >= 0
 * travels with the request (SCM_RIGHTS). */
int fwd_exec(const char *line, int pass_fd, char code[24], char msg[160]);
int fwd_refresh_identity(void); /* underlay ip/mac from `tunnel show`, boot_id from `version` */
int fwd_read(struct nstate *have, struct nstate *foreign); /* 0 or FWD_IO */

/* bindings.c */
int bindings_load(void);       /* -1 on an unparsable file */
int bindings_save(void);
int bindings_plug(const char *vmi, const char *port, char code[24], char msg[160]);
int bindings_unplug(const char *vmi, char code[24], char msg[160]);

/* session.c */
void agent_session_start(void);
void agent_session_tick(uint64_t now_ns);
void agent_session_close(const char *why);
void agent_report_bind(const char *vmi, const char *port); /* NULL port = UNBIND */
bool agent_session_up(void);
void agent_sess_counters(uint64_t out[4]);
void agent_reconcile(void);   /* read have, plan, execute; fills g_ag.failed */
void agent_diff_json(struct jw *w); /* missing / stale / conflicts for `diff show` */

/* localctl.c */
int agent_localctl_init(const char *path);
#endif
