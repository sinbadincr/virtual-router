/* minivr-agent: per-node agent. Start-up order (contracts/agent-cli.md): bindings -> local socket
 * -> forwarder -> drop all capabilities except CAP_NET_RAW -> loop. */
#include <errno.h>
#include <getopt.h>
#include <linux/capability.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "../daemon/evloop.h"
#include "agent.h"
#include "minivr/clock.h"
#include "minivr/log.h"
#include "minivr/privdrop.h"

struct agent g_ag;
static volatile int stop;
static struct evsrc sig_src, timer_src;
static unsigned tick_n;
static uint64_t next_fwd_try_ns;

static void usage(FILE *f) {
    fprintf(f, "usage: minivr-agent --node <name> --controller <ip:port> --bind <ip> --fwd-sock <path>\n"
               "                    --sock <path> --state-dir <dir>\n");
}

/* Keep CAP_NET_RAW only (R15): the agent opens the AF_PACKET sockets it hands to the forwarder. */
static int drop_caps(void) {
    for (int c = 0; c <= CAP_LAST_CAP + 8 && c < 64; c++)
        if (prctl(PR_CAPBSET_DROP, c, 0, 0, 0) < 0 && errno == EINVAL)
            break;
    struct __user_cap_header_struct h = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct d[2];
    memset(d, 0, sizeof d);
    d[0].effective = d[0].permitted = 1u << CAP_NET_RAW;
    if (syscall(SYS_capset, &h, d) < 0) {
        log_error("agent", "capset failed", "errno=%d", errno);
        return -1;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -1;
    FILE *f = fopen("/proc/self/status", "r");
    if (!f)
        return -1;
    char line[256];
    int ok_eff = 0, ok_prm = 0, ok_nnp = 0;
    while (fgets(line, sizeof line, f)) {
        char v[32];
        int n;
        if (sscanf(line, "CapEff: %31s", v) == 1)
            ok_eff = strtoull(v, NULL, 16) == (1ull << CAP_NET_RAW);
        else if (sscanf(line, "CapPrm: %31s", v) == 1)
            ok_prm = strtoull(v, NULL, 16) == (1ull << CAP_NET_RAW);
        else if (sscanf(line, "NoNewPrivs: %d", &n) == 1)
            ok_nnp = n == 1;
    }
    fclose(f);
    if (!ok_eff || !ok_prm || !ok_nnp) {
        log_error("agent", "capability self-verification failed", "eff=%d prm=%d nnp=%d", ok_eff, ok_prm, ok_nnp);
        return -1;
    }
    return 0;
}

static void on_signal(struct evsrc *s, uint32_t ev) {
    (void)ev;
    struct signalfd_siginfo si;
    if (read(s->fd, &si, sizeof si) != (ssize_t)sizeof si)
        return;
    if (si.ssi_signo != SIGHUP)
        stop = 1;
}

static void fwd_maintain(uint64_t now) {
    if (!g_ag.fwd_up) {
        if (now < next_fwd_try_ns)
            return;
        next_fwd_try_ns = now + 500 * NS_PER_MS;
        int rc = fwd_connect();
        if (rc != FWD_OK)
            return;
        char old[17];
        snprintf(old, sizeof old, "%s", g_ag.boot_id);
        if (fwd_refresh_identity() != 0) {
            fwd_close();
            return;
        }
        log_info("agent", "forwarder connected", "boot_id=%s%s", g_ag.boot_id,
                 old[0] && strcmp(old, g_ag.boot_id) ? " (restarted)" : "");
        g_ag.dirty = true;
        return;
    }
    char old[17];
    snprintf(old, sizeof old, "%s", g_ag.boot_id);
    if (fwd_refresh_identity() != 0) {
        snprintf(g_ag.fwd_err, sizeof g_ag.fwd_err, "connection lost");
        fwd_close();
        return;
    }
    if (strcmp(old, g_ag.boot_id) != 0)
        g_ag.dirty = true;
}

static void on_tick(struct evsrc *s, uint32_t ev) {
    (void)ev;
    uint64_t exp;
    if (read(s->fd, &exp, sizeof exp) != (ssize_t)sizeof exp)
        return;
    uint64_t now = clock_now_ns();
    tick_n++;
    if (tick_n % 2 == 0 || !g_ag.fwd_up)
        fwd_maintain(now);
    agent_session_tick(now);
    if (g_ag.fwd_up && g_ag.rc.want_valid && (g_ag.dirty || tick_n % 2 == 0))
        agent_reconcile();
}

int main(int argc, char **argv) {
    static const struct option opts[] = {{"node", required_argument, 0, 'n'},
                                         {"controller", required_argument, 0, 'c'},
                                         {"bind", required_argument, 0, 'b'},
                                         {"fwd-sock", required_argument, 0, 'f'},
                                         {"sock", required_argument, 0, 's'},
                                         {"state-dir", required_argument, 0, 'd'},
                                         {"help", no_argument, 0, 'h'},
                                         {0, 0, 0, 0}};
    const char *node = NULL, *ctl = NULL, *bind = NULL, *fwd = NULL, *sock = NULL, *dir = NULL;
    int o;
    while ((o = getopt_long(argc, argv, "n:c:b:f:s:d:h", opts, NULL)) != -1) {
        switch (o) {
        case 'n': node = optarg; break;
        case 'c': ctl = optarg; break;
        case 'b': bind = optarg; break;
        case 'f': fwd = optarg; break;
        case 's': sock = optarg; break;
        case 'd': dir = optarg; break;
        case 'h': usage(stdout); return 0;
        default: usage(stderr); return 2;
        }
    }
    if (!node || !ctl || !bind || !fwd || !sock || !dir || !ne_name_ok(node) ||
        parse_hostport(ctl, g_ag.ctrl_ip, &g_ag.ctrl_port) != 0) {
        usage(stderr);
        return 2;
    }
    snprintf(g_ag.node, sizeof g_ag.node, "%s", node);
    snprintf(g_ag.bind_ip, sizeof g_ag.bind_ip, "%s", bind);
    snprintf(g_ag.fwd_sock, sizeof g_ag.fwd_sock, "%s", fwd);
    snprintf(g_ag.sock, sizeof g_ag.sock, "%s", sock);
    snprintf(g_ag.state_dir, sizeof g_ag.state_dir, "%s", dir);
    g_ag.start_ns = clock_now_ns();
    rc_init(&g_ag.rc);
    ns_init(&g_have, g_have_s, RC_CAP);

    if (bindings_load() != 0) /* an unparsable bindings file is a start-up error */
        return 1;
    if (ev_init() != 0)
        return 1;
    if (agent_localctl_init(g_ag.sock) != 0)
        return 1;

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGHUP);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    signal(SIGPIPE, SIG_IGN);
    sig_src.fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    sig_src.cb = on_signal;
    timer_src.fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    timer_src.cb = on_tick;
    struct itimerspec its = {.it_interval = {1, 0}, .it_value = {0, 200 * 1000000L}};
    if (sig_src.fd < 0 || timer_src.fd < 0 || timerfd_settime(timer_src.fd, 0, &its, NULL) < 0 ||
        ev_add(&sig_src, EPOLLIN) < 0 || ev_add(&timer_src, EPOLLIN) < 0)
        return 1;

    /* the forwarder may not be up yet: the loop keeps trying */
    fwd_maintain(clock_now_ns());

    if (drop_caps() != 0)
        return 1;
    log_info("agent", "started", "node=%s controller=%s:%u fwd=%s", g_ag.node, g_ag.ctrl_ip,
             g_ag.ctrl_port, g_ag.fwd_sock);
    while (!stop) {
        if (ev_wait(500) < 0)
            break;
    }
    agent_session_close("shutdown");
    fwd_close();
    usrv_close();
    ev_fini();
    return 0;
}
