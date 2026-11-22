#ifndef MINIVR_FDCHECK_H
#define MINIVR_FDCHECK_H

/* Validate a socket received over SCM_RIGHTS before the forwarder adopts it (contracts/forwarder.md):
 * AF_PACKET, SOCK_RAW, bound to if_nametoindex(ifname). Returns NULL when acceptable, otherwise a
 * short reason (the command reports it as `bad-fd`). Never reads from, writes to or closes `fd`. */
const char *fd_check_afpacket(int fd, const char *ifname);
#endif
