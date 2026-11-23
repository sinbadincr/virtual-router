#include <stdio.h>
#include <string.h>

#include "agent.h"
#include "minivr/ctl_model.h"
#include "minivr/clock.h"
#include "minivr/log.h"

static void fail(struct jw *w, const char *code, const char *msg) {
    jw_reset(w);
    jw_obj_begin(w, NULL);
    jw_bool(w, "ok", false);
    jw_obj_begin(w, "error");
    jw_str(w, "code", code);
    jw_str(w, "message", msg);
    jw_obj_end(w);
    jw_obj_end(w);
}

static void begin(struct jw *w) {
    jw_reset(w);
    jw_obj_begin(w, NULL);
    jw_bool(w, "ok", true);
    jw_obj_begin(w, "data");
}

static void end(struct jw *w) {
    jw_obj_end(w);
    jw_obj_end(w);
}

static const char *sync_name(void) {
    if (g_ag.sess == AS_IN_SYNC)
        return "in-sync";
    if (g_ag.sess == AS_SYNCING || g_ag.sess == AS_HELLO)
        return "syncing";
    return g_ag.rc.want_valid ? "headless" : "connecting";
}

static void status(struct jw *w) {
    static const char *const sess[] = {"connecting", "hello", "syncing", "in-sync"};
    begin(w);
    jw_str(w, "node", g_ag.node);
    jw_obj_begin(w, "session");
    jw_str(w, "state", sess[g_ag.sess]);
    char ctl[40];
    snprintf(ctl, sizeof ctl, "%s:%u", g_ag.ctrl_ip, g_ag.ctrl_port);
    jw_str(w, "controller", ctl);
    jw_u64(w, "since", g_ag.sess >= AS_HELLO ? (clock_now_ns() - g_ag.sess_since_ns) / NS_PER_SEC : 0);
    if (g_ag.last_error[0])
        jw_str(w, "last_error", g_ag.last_error);
    else
        jw_null(w, "last_error");
    uint64_t cnt[4];
    agent_sess_counters(cnt);
    jw_u64(w, "msgs_in", cnt[0]);
    jw_u64(w, "msgs_out", cnt[1]);
    jw_u64(w, "bytes_in", cnt[2]);
    jw_u64(w, "bytes_out", cnt[3]);
    jw_u64(w, "backoff_s", g_ag.backoff_ms / 1000);
    jw_obj_begin(w, "proto_errors");
    for (int r = PE_TRUNCATED; r < PE_COUNT; r++)
        jw_u64(w, proto_err_name((enum proto_err)r), g_ag.proto_err[r]);
    jw_obj_end(w);
    jw_obj_end(w);
    jw_str(w, "sync", sync_name());
    jw_u64(w, "gen", g_ag.gen);
    jw_obj_begin(w, "forwarder");
    jw_str(w, "state", g_ag.fwd_up ? "up" : "down");
    jw_str(w, "boot_id", g_ag.boot_id[0] ? g_ag.boot_id : "");
    if (g_ag.fwd_err[0])
        jw_str(w, "last_error", g_ag.fwd_err);
    else
        jw_null(w, "last_error");
    jw_obj_end(w);
    jw_obj_begin(w, "entries");
    for (unsigned k = NE_VRF; k <= NE_ROUTE; k++) {
        unsigned want = 0, have = 0;
        for (unsigned i = 0; i < g_ag.rc.want.n; i++)
            want += g_ag.rc.want.e[i].kind == k;
        for (unsigned i = 0; i < g_have.n; i++)
            have += g_have.e[i].kind == k;
        jw_obj_begin(w, ne_kind_name(k));
        jw_u64(w, "want", want);
        jw_u64(w, "have", have);
        jw_obj_end(w);
    }
    jw_obj_end(w);
    jw_arr_begin(w, "failed");
    for (unsigned i = 0; i < g_ag.nfailed; i++) {
        jw_obj_begin(w, NULL);
        jw_str(w, "kind", ne_kind_name(g_ag.failed[i].e.kind));
        jw_str(w, "command", g_ag.failed[i].cmd);
        jw_str(w, "code", g_ag.failed[i].code);
        jw_str(w, "message", g_ag.failed[i].msg);
        jw_obj_end(w);
    }
    jw_arr_end(w);
    jw_arr_begin(w, "bind_errors");
    for (unsigned i = 0; i < g_ag.nbind_err; i++) {
        jw_obj_begin(w, NULL);
        jw_str(w, "vmi", g_ag.bind_err[i].vmi);
        jw_str(w, "code", g_ag.bind_err[i].code);
        jw_str(w, "message", g_ag.bind_err[i].text);
        jw_obj_end(w);
    }
    jw_arr_end(w);
    end(w);
}

static void handle(void *arg, const char *line, struct jw *w) {
    (void)arg;
    char buf[256], *argv[8];
    snprintf(buf, sizeof buf, "%s", line);
    int argc = 0;
    for (char *t = strtok(buf, " \t"); t && argc < 8; t = strtok(NULL, " \t"))
        argv[argc++] = t;
    char code[24], msg[160];
    if (argc == 0) {
        fail(w, "bad-syntax", "empty command");
    } else if (strcmp(argv[0], "plug") == 0) {
        if (argc != 4 || strcmp(argv[2], "port") != 0) {
            fail(w, "bad-syntax", "usage: plug <vmi> port <port>");
            return;
        }
        int rc = bindings_plug(argv[1], argv[3], code, msg);
        if (rc < 0) {
            fail(w, code, msg);
            return;
        }
        g_ag.nbind_err = 0;
        if (rc == 1)
            agent_report_bind(argv[1], argv[3]);
        begin(w);
        bool rep = false;
        for (int i = 0; i < AG_MAX_BINDINGS; i++)
            if (g_ag.bind[i].used && strcmp(g_ag.bind[i].vmi, argv[1]) == 0)
                rep = g_ag.bind[i].reported;
        jw_bool(w, "reported", rep);
        end(w);
    } else if (strcmp(argv[0], "unplug") == 0) {
        if (argc != 2) {
            fail(w, "bad-syntax", "usage: unplug <vmi>");
            return;
        }
        if (bindings_unplug(argv[1], code, msg) != 0) {
            fail(w, code, msg);
            return;
        }
        agent_report_bind(argv[1], NULL);
        begin(w);
        end(w);
    } else if (strcmp(argv[0], "status") == 0) {
        status(w);
    } else if (strcmp(argv[0], "bindings") == 0 && argc == 2 && strcmp(argv[1], "show") == 0) {
        begin(w);
        jw_arr_begin(w, "bindings");
        for (int i = 0; i < AG_MAX_BINDINGS; i++)
            if (g_ag.bind[i].used) {
                jw_obj_begin(w, NULL);
                jw_str(w, "vmi", g_ag.bind[i].vmi);
                jw_str(w, "port", g_ag.bind[i].port);
                jw_bool(w, "reported", g_ag.bind[i].reported);
                jw_obj_end(w);
            }
        jw_arr_end(w);
        end(w);
    } else if (strcmp(argv[0], "want") == 0 && argc >= 2 && strcmp(argv[1], "show") == 0) {
        begin(w);
        jw_u64(w, "total", g_ag.rc.want.n);
        jw_arr_begin(w, "entries");
        for (unsigned i = 0; i < g_ag.rc.want.n && i < 400; i++)
            ne_json(w, &g_ag.rc.want.e[i]);
        jw_arr_end(w);
        end(w);
    } else if (strcmp(argv[0], "diff") == 0 && argc == 2 && strcmp(argv[1], "show") == 0) {
        begin(w);
        agent_diff_json(w);
        end(w);
    } else if (strcmp(argv[0], "version") == 0) {
        begin(w);
        jw_str(w, "daemon", "minivr-agent");
        jw_u64(w, "protocol", 1);
        jw_u64(w, "wire", 1);
        jw_str(w, "version", "0.1.0");
        jw_u64(w, "uptime_s", (clock_now_ns() - g_ag.start_ns) / NS_PER_SEC);
        end(w);
    } else {
        fail(w, "bad-syntax", "unknown command");
    }
}

int agent_localctl_init(const char *path) {
    return usrv_init(path, 0, handle, NULL);
}
