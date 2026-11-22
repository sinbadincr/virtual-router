/* AF_PACKET backend: raw socket bound to one interface, recvmmsg/sendmmsg bursts. */
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "minivr/log.h"
#include "minivr/stats.h"
#include "pio.h"

struct afp {
    int fd;
    int ifindex;
    int mtu;
    uint8_t mac[6];
};

/* Open, bind and configure an AF_PACKET socket for `ifname`; returns the fd or -1 (errno set).
 * Needs CAP_NET_RAW: the agent calls this and passes the fd to the unprivileged forwarder. */
int afp_socket_open(const char *ifname) {
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (fd < 0)
        return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
        goto err;
    int ifindex = ifr.ifr_ifindex;

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof sll);
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof sll) < 0)
        goto err;

    int one = 1;
    /* Best effort: older kernels lack these; the forwarder still works without them. */
    if (setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &one, sizeof one) < 0)
        log_warn("pio", "PACKET_IGNORE_OUTGOING unsupported", "ifname=%s", ifname);
    if (setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, &one, sizeof one) < 0)
        log_warn("pio", "PACKET_QDISC_BYPASS unsupported", "ifname=%s", ifname);
    /* The kernel strips 802.1Q tags before a raw socket sees the frame; AUXDATA tells us. */
    if (setsockopt(fd, SOL_PACKET, PACKET_AUXDATA, &one, sizeof one) < 0)
        goto err;
    struct packet_mreq mr;
    memset(&mr, 0, sizeof mr);
    mr.mr_ifindex = ifindex;
    mr.mr_type = PACKET_MR_PROMISC;
    if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof mr) < 0)
        goto err;
    return fd;
err : {
    int e = errno;
    close(fd);
    errno = e;
    return -1;
}
}

/* Wrap an already open and bound socket (ownership of fd passes to the handle on success). */
static void *afp_adopt(int fd, const char *ifname) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    struct afp *a = calloc(1, sizeof *a);
    if (!a)
        return NULL;
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
        goto err;
    a->ifindex = ifr.ifr_ifindex;
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
        goto err;
    memcpy(a->mac, ifr.ifr_hwaddr.sa_data, 6);
    if (ioctl(fd, SIOCGIFMTU, &ifr) < 0)
        goto err;
    a->mtu = ifr.ifr_mtu;
    a->fd = fd;
    return a;
err : {
    int e = errno;
    free(a);
    errno = e;
    return NULL;
}
}

static void *afp_open(const char *ifname) {
    int fd = afp_socket_open(ifname);
    if (fd < 0)
        return NULL;
    void *h = afp_adopt(fd, ifname);
    if (!h) {
        int e = errno;
        close(fd);
        errno = e;
    }
    return h;
}

static void afp_close(void *h) {
    struct afp *a = h;
    if (!a)
        return;
    close(a->fd);
    free(a);
}

static int afp_rx(void *h, struct mbuf **m, int max) {
    struct afp *a = h;
    struct mmsghdr msgs[PIO_BURST];
    struct iovec iov[PIO_BURST];
    static union {
        struct cmsghdr align;
        uint8_t buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
    } ctl[PIO_BURST];
    if (max > PIO_BURST)
        max = PIO_BURST;
    int n = 0;
    while (n < max) {
        struct mbuf *b = mbuf_alloc();
        if (!b)
            break;
        m[n++] = b;
    }
    if (n == 0) {
        /* pool exhausted: drain the socket so it does not stay readable forever */
        static uint8_t scratch[MBUF_DATA_SIZE];
        int drained = 0;
        while (drained < max && recv(a->fd, scratch, sizeof scratch, MSG_DONTWAIT) >= 0) {
            stats_drop(DROP_NOBUF);
            drained++;
        }
        return 0;
    }
    memset(msgs, 0, sizeof msgs[0] * (size_t)n);
    for (int i = 0; i < n; i++) {
        m[i]->off = MBUF_HEADROOM;
        iov[i].iov_base = mbuf_data(m[i]);
        iov[i].iov_len = MBUF_DATA_SIZE - MBUF_HEADROOM;
        msgs[i].msg_hdr.msg_iov = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_control = ctl[i].buf;
        msgs[i].msg_hdr.msg_controllen = sizeof ctl[i].buf;
    }
    int r = recvmmsg(a->fd, msgs, (unsigned)n, MSG_DONTWAIT, NULL);
    if (r < 0) {
        for (int i = 0; i < n; i++)
            mbuf_free(m[i]);
        return (errno == EAGAIN || errno == EINTR) ? 0 : -1;
    }
    for (int i = r; i < n; i++)
        mbuf_free(m[i]);
    int out = 0;
    for (int i = 0; i < r; i++) {
        if (msgs[i].msg_hdr.msg_flags & MSG_TRUNC) {
            stats_drop(DROP_TRUNCATED);
            mbuf_free(m[i]);
            continue;
        }
        m[i]->len = (uint16_t)msgs[i].msg_len;
        for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msgs[i].msg_hdr); cm;
             cm = CMSG_NXTHDR(&msgs[i].msg_hdr, cm)) {
            if (cm->cmsg_level == SOL_PACKET && cm->cmsg_type == PACKET_AUXDATA) {
                const struct tpacket_auxdata *aux = (const struct tpacket_auxdata *)CMSG_DATA(cm);
                if ((aux->tp_status & TP_STATUS_VLAN_VALID) || aux->tp_vlan_tci)
                    m[i]->vlan_tagged = 1;
            }
        }
        m[out++] = m[i];
    }
    return out;
}

static int afp_tx(void *h, struct mbuf **m, int n) {
    struct afp *a = h;
    struct mmsghdr msgs[PIO_BURST];
    struct iovec iov[PIO_BURST];
    int sent = 0;
    while (n > 0) {
        int chunk = n > PIO_BURST ? PIO_BURST : n;
        memset(msgs, 0, sizeof msgs[0] * (size_t)chunk);
        for (int i = 0; i < chunk; i++) {
            iov[i].iov_base = mbuf_data(m[i]);
            iov[i].iov_len = m[i]->len;
            msgs[i].msg_hdr.msg_iov = &iov[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
        }
        int done = 0;
        while (done < chunk) {
            int r = sendmmsg(a->fd, msgs + done, (unsigned)(chunk - done), MSG_DONTWAIT);
            if (r <= 0)
                break;
            done += r;
        }
        sent += done;
        for (int i = done; i < chunk; i++)
            stats_drop(DROP_TX_ERROR);
        for (int i = 0; i < chunk; i++)
            mbuf_free(m[i]);
        m += chunk;
        n -= chunk;
    }
    return sent;
}

static int afp_fd(void *h) {
    return ((struct afp *)h)->fd;
}

static int afp_mac(void *h, uint8_t mac[6]) {
    memcpy(mac, ((struct afp *)h)->mac, 6);
    return 0;
}

static int afp_mtu(void *h) {
    return ((struct afp *)h)->mtu;
}

const struct pio_ops pio_afpacket_ops = {"af_packet", afp_open, afp_close, afp_rx,
                                         afp_tx,      afp_fd,   afp_mac,   afp_mtu, afp_adopt};
