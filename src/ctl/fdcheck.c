#include "minivr/fdcheck.h"

#include <linux/if_packet.h>
#include <net/if.h>
#include <string.h>
#include <sys/socket.h>

const char *fd_check_afpacket(int fd, const char *ifname) {
    if (fd < 0)
        return "no file descriptor";
    int v = 0;
    socklen_t l = sizeof v;
    if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &v, &l) < 0 || v != AF_PACKET)
        return "not an AF_PACKET socket";
    l = sizeof v;
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &v, &l) < 0 || v != SOCK_RAW)
        return "not a SOCK_RAW socket";
    struct sockaddr_ll sll;
    l = sizeof sll;
    memset(&sll, 0, sizeof sll);
    if (getsockname(fd, (struct sockaddr *)&sll, &l) < 0 || l < sizeof sll - sizeof sll.sll_addr)
        return "socket is not bound";
    unsigned idx = if_nametoindex(ifname);
    if (idx == 0 || sll.sll_ifindex < 0 || (unsigned)sll.sll_ifindex != idx)
        return "socket is not bound to the requested interface";
    return NULL;
}
