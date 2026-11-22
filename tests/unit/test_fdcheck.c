#include <sys/socket.h>
#include <unistd.h>

#include "minivr/fdcheck.h"
#include "tharness.h"

TEST(non_packet_fds_are_refused) {
    int sv[2], p[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    CHECK(pipe(p) == 0);
    CHECK(fd_check_afpacket(sv[0], "lo") != NULL);
    CHECK(fd_check_afpacket(p[0], "lo") != NULL);
    CHECK(fd_check_afpacket(-1, "lo") != NULL);
    /* the function neither reads nor closes: both ends still work */
    CHECK(write(sv[1], "x", 1) == 1);
    char c;
    CHECK(read(sv[0], &c, 1) == 1);
    CHECK(write(p[1], "y", 1) == 1);
    CHECK(read(p[0], &c, 1) == 1);
    close(sv[0]);
    close(sv[1]);
    close(p[0]);
    close(p[1]);
}
