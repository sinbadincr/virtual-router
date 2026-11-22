/* minivrd: single-threaded L3 forwarder. Start-up order is fixed (plan.md):
 * parse config -> open ports -> (rtnetlink, US4) -> control socket -> dump dir ->
 * drop privileges + verify -> epoll loop. */
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/random.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "crash.h"
#include "evloop.h"
#include "linkmon.h"
#include "minivr/clock.h"
#include "minivr/cmd.h"
#include "minivr/config.h"
#include "minivr/ctl_server.h"
#include "minivr/fdcheck.h"
#include "minivr/forward.h"
#include "minivr/log.h"
#include "minivr/mbuf.h"
#include "minivr/neigh.h"
#include "minivr/port.h"
#include "minivr/privdrop.h"
#include "pio.h"

#define TICK_NS (10 * NS_PER_MS)

static volatile int stop;
static struct evsrc sig_src, timer_src;
static struct evsrc port_src[MAX_PORTS];

static void usage(FILE *f) {
    fprintf(f, "usage: minivrd --config <file> [--sock <path>] [--user <name>] [--foreground]\n"
               "  --sock   control socket (default /run/minivr/minivr.sock)\n"
               "  --user   identity to drop to after start-up (default nobody)\n"
               "  --foreground  accepted for compatibility; minivrd never daemonizes\n");
}

static void on_signal(struct evsrc *s, uint32_t ev) {
    (void)ev;
    struct signalfd_siginfo si;
    if (read(s->fd, &si, sizeof si) != (ssize_t)sizeof si)
        return;
    if (si.ssi_signo == SIGHUP) {
        log_warn("main", "SIGHUP ignored: configuration reload is not supported");
        return;
    }
    log_info("main", "termination signal", "signo=%u", si.ssi_signo);
    stop = 1;
}

static void on_tick(struct evsrc *s, uint32_t ev) {
    (void)ev;
    uint64_t exp;
    if (read(s->fd, &exp, sizeof exp) != (ssize_t)sizeof exp)
        return;
    uint64_t now = clock_now_ns();
    ctl_server_tick(now);
    neigh_tick(now);
}

static void on_port(struct evsrc *s, uint32_t ev) {
    (void)ev;
    struct port *p = s->arg;
    const struct pio_ops *ops = port_backend();
    struct mbuf *burst[PIO_BURST];
    int n = ops->rx_burst(p->pio, burst, PIO_BURST);
    if (n > 0) {
        for (int i = 0; i < n; i++)
            burst[i]->in_port = p->id;
        forward_burst(p, burst, n);
    }
}

/* Runtime ports (agent session): watch the new fd, stop watching before the port closes. */
static void port_added(struct port *p) {
    struct evsrc *s = &port_src[p->id];
    s->fd = port_backend()->fd(p->pio);
    s->cb = on_port;
    s->arg = p;
    if (ev_add(s, EPOLLIN) < 0) {
        log_error("ctl", "cannot watch runtime port", "port=%s errno=%d", p->name, errno);
        return;
    }
    log_info("ctl", "runtime port added", "port=%s ifname=%s", p->name, p->ifname);
}

static void port_removed(struct port *p) {
    ev_del(&port_src[p->id]);
    port_src[p->id].fd = -1;
    log_info("ctl", "runtime port deleted", "port=%s", p->name);
}

static void make_boot_id(void) {
    uint8_t r[8];
    char hex[17];
    if (getrandom(r, sizeof r, 0) != (ssize_t)sizeof r)
        memset(r, 0, sizeof r);
    for (int i = 0; i < 8; i++)
        snprintf(hex + 2 * i, 3, "%02x", r[i]);
    cmd_set_boot_id(hex);
}

int main(int argc, char **argv) {
    const char *config = NULL, *sock = "/run/minivr/minivr.sock", *user = "nobody";
    static const struct option opts[] = {{"config", required_argument, 0, 'c'},
                                         {"sock", required_argument, 0, 's'},
                                         {"user", required_argument, 0, 'u'},
                                         {"foreground", no_argument, 0, 'f'},
                                         {"help", no_argument, 0, 'h'},
                                         {0, 0, 0, 0}};
    int o;
    while ((o = getopt_long(argc, argv, "c:s:u:fh", opts, NULL)) != -1) {
        switch (o) {
        case 'c': config = optarg; break;
        case 's': sock = optarg; break;
        case 'u': user = optarg; break;
        case 'f': break;
        case 'h': usage(stdout); return 0;
        default: usage(stderr); return 2;
        }
    }
    if (!config) {
        usage(stderr);
        return 2;
    }

    uid_t launch_uid = getuid(); /* recorded before the privilege drop (FR-022) */
    cmd_init();
    make_boot_id();
    cmd_set_fd_checker(fd_check_afpacket);
    if (mbuf_pool_init(MBUF_POOL_SIZE) != 0 || ev_init() != 0) {
        log_error("main", "initialisation failed", "errno=%d", errno);
        return 1;
    }

    /* 1-2. config -> opens port sockets */
    port_set_backend(&pio_afpacket_ops);
    if (config_load(config) != 0)
        return 1;
    if (port_count() == 0)
        log_warn("main", "no ports configured");

    /* signals and tick timer */
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
    struct itimerspec its = {.it_interval = {0, (long)TICK_NS}, .it_value = {0, (long)TICK_NS}};
    if (sig_src.fd < 0 || timer_src.fd < 0 || timerfd_settime(timer_src.fd, 0, &its, NULL) < 0 ||
        ev_add(&sig_src, EPOLLIN) < 0 || ev_add(&timer_src, EPOLLIN) < 0) {
        log_error("main", "cannot set up signalfd/timerfd", "errno=%d", errno);
        return 1;
    }

    /* port fds */
    const struct pio_ops *ops = port_backend();
    for (unsigned i = 0; i < MAX_PORTS; i++) {
        struct port *p = port_get((uint8_t)i);
        if (!p)
            continue;
        port_src[i].fd = ops->fd(p->pio);
        port_src[i].cb = on_port;
        port_src[i].arg = p;
        if (ev_add(&port_src[i], EPOLLIN) < 0) {
            log_error("main", "cannot watch port", "port=%s errno=%d", p->name, errno);
            return 1;
        }
    }

    port_set_hooks(port_added, port_removed); /* only runtime ports reach them from here on */

    /* 3. rtnetlink, then the control socket */
    crash_install();
    if (linkmon_init() != 0)
        return 1;
    if (ctl_server_init(sock, launch_uid) != 0)
        return 1;

    /* 4-5. dump dir + drop privileges, verified */
    if (privdrop(user) != 0)
        return 1;
    crash_enter_dumpdir();

    log_info("main", "forwarding started", "ports=%u sock=%s", port_count(), sock);
    while (!stop) {
        if (ev_wait(1000) < 0) {
            log_error("main", "epoll failed", "errno=%d", errno);
            break;
        }
    }

    ctl_server_close();
    linkmon_close();
    port_close_all();
    ev_fini();
    log_info("main", "shutdown complete");
    return 0;
}
