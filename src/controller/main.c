/* minivr-ctld: the controller. Start-up order is fixed (contracts/controller-cli.md): state ->
 * TCP listener -> control socket -> drop privileges (verified) -> epoll loop. */
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "../daemon/evloop.h"
#include "ctl.h"
#include "minivr/clock.h"
#include "minivr/log.h"
#include "minivr/netio.h"
#include "minivr/privdrop.h"

struct ctl g_ctl;
static volatile int stop;
static struct evsrc sig_src, timer_src;

uint64_t ctl_now_s(void) {
    uint64_t s = (clock_now_ns() - g_ctl.start_ns) / NS_PER_SEC;
    g_ctl.m.clock_s = s;
    return s;
}

void ctl_commit(void) {
    ctl_now_s();
    if (g_ctl.m.gen != g_ctl.saved_gen) {
        if (store_save(&g_ctl.m, g_ctl.state_path) != 0) {
            g_ctl.stats.state_write_errors++;
            log_error("ctl", "cannot write state file", "path=%s errno=%d", g_ctl.state_path, errno);
        } else
            g_ctl.stats.state_writes++;
        g_ctl.saved_gen = g_ctl.m.gen;
    }
    sess_push_all();
    if (g_ctl.m.gen != g_ctl.saved_gen) { /* releases on ACK changed the state file content */
        if (store_save(&g_ctl.m, g_ctl.state_path) == 0)
            g_ctl.stats.state_writes++;
        else
            g_ctl.stats.state_write_errors++;
        g_ctl.saved_gen = g_ctl.m.gen;
    }
}

static void usage(FILE *f) {
    fprintf(f, "usage: minivr-ctld --state <file> [--init <intent-file>] [--listen <ip:port>]\n"
               "                   [--sock <path>] [--user <name>]\n"
               "  --state   state file (intent, bindings, label quarantine); replaced atomically\n"
               "  --init    intent file used when the state file does not exist yet\n"
               "  --listen  agent listener (default 10.98.0.254:7700)\n"
               "  --sock    control socket (default /run/mvr-ctl/ctld.sock)\n"
               "  --user    identity to drop to (default nobody)\n");
}

static void on_signal(struct evsrc *s, uint32_t ev) {
    (void)ev;
    struct signalfd_siginfo si;
    if (read(s->fd, &si, sizeof si) != (ssize_t)sizeof si)
        return;
    if (si.ssi_signo == SIGHUP)
        return;
    log_info("main", "termination signal", "signo=%u", si.ssi_signo);
    stop = 1;
}

static void on_tick(struct evsrc *s, uint32_t ev) {
    (void)ev;
    uint64_t exp;
    if (read(s->fd, &exp, sizeof exp) != (ssize_t)sizeof exp)
        return;
    uint64_t now = clock_now_ns();
    ctl_now_s();
    sess_tick(now);
    usrv_tick(now);
}

int main(int argc, char **argv) {
    const char *state = NULL, *init = NULL, *listen_addr = "10.98.0.254:7700";
    const char *sock = "/run/mvr-ctl/ctld.sock", *user = "nobody";
    static const struct option opts[] = {{"state", required_argument, 0, 's'},
                                         {"init", required_argument, 0, 'i'},
                                         {"listen", required_argument, 0, 'l'},
                                         {"sock", required_argument, 0, 'k'},
                                         {"user", required_argument, 0, 'u'},
                                         {"help", no_argument, 0, 'h'},
                                         {0, 0, 0, 0}};
    int o;
    while ((o = getopt_long(argc, argv, "s:i:l:k:u:h", opts, NULL)) != -1) {
        switch (o) {
        case 's': state = optarg; break;
        case 'i': init = optarg; break;
        case 'l': listen_addr = optarg; break;
        case 'k': sock = optarg; break;
        case 'u': user = optarg; break;
        case 'h': usage(stdout); return 0;
        default: usage(stderr); return 2;
        }
    }
    if (!state) {
        usage(stderr);
        return 2;
    }
    char lip[16];
    uint16_t lport;
    if (parse_hostport(listen_addr, lip, &lport) != 0) {
        fprintf(stderr, "minivr-ctld: bad --listen '%s' (want a.b.c.d:port)\n", listen_addr);
        return 2;
    }

    g_ctl.start_ns = clock_now_ns();
    g_ctl.state_path = state;
    unsigned launch_uid = (unsigned)getuid();

    /* 1. state: parse it all or refuse to start (FR-009) */
    char err[512] = "";
    if (store_load(&g_ctl.m, state, init, err, sizeof err) != 0) {
        fprintf(stderr, "minivr-ctld: %s\n", err);
        return 1;
    }
    g_ctl.saved_gen = g_ctl.m.gen;
    if (ev_init() != 0) {
        log_error("main", "epoll", "errno=%d", errno);
        return 1;
    }
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
    struct itimerspec its = {.it_interval = {1, 0}, .it_value = {1, 0}};
    if (sig_src.fd < 0 || timer_src.fd < 0 || timerfd_settime(timer_src.fd, 0, &its, NULL) < 0 ||
        ev_add(&sig_src, EPOLLIN) < 0 || ev_add(&timer_src, EPOLLIN) < 0) {
        log_error("main", "cannot set up signalfd/timerfd", "errno=%d", errno);
        return 1;
    }

    /* 2-3. TCP listener, then the control socket */
    if (sess_listen(lip, lport) != 0)
        return 1;
    if (localctl_init(sock, launch_uid) != 0)
        return 1;

    /* 4. drop privileges and verify */
    if (privdrop(user) != 0)
        return 1;

    /* the state file is rewritten for the whole life of the process, as the unprivileged user:
     * prove now that this works, not at the first restart that needs the file (incident 0003) */
    if (store_save(&g_ctl.m, g_ctl.state_path) != 0) {
        fprintf(stderr, "minivr-ctld: cannot write the state file %s as uid %u after dropping privileges: %s\n"
                        "  (the user must be able to reach and write its directory; see --user)\n",
                state, (unsigned)getuid(), strerror(errno));
        return 1;
    }
    log_info("main", "controller started", "state=%s listen=%s sock=%s tenants_nodes=%d", state,
             listen_addr, sock, 0);
    while (!stop) {
        if (ev_wait(1000) < 0) {
            log_error("main", "epoll failed", "errno=%d", errno);
            break;
        }
    }
    sess_shutdown();
    usrv_close();
    ev_fini();
    log_info("main", "shutdown complete");
    return 0;
}
