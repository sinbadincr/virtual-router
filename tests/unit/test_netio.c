#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

#include "minivr/netio.h"
#include "tharness.h"

static const uint8_t HELLO[40] = {
    0x01, 0x01, 0, 0, 0, 0, 0, 0x28, 0, 0, 0, 1, 0, 1, 0, 7, 0x63, 0x6e, 0x31, 0,
    0, 2, 0, 8, 0xac, 0x10, 0, 1, 0, 3, 0, 0x0a, 2, 0, 0, 0xff, 0, 1, 0, 0};

static void pair(int sv[2]) {
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) == 0);
}

TEST(whole_split_and_back_to_back_messages) {
    int sv[2];
    pair(sv);
    static struct msgconn c;
    CHECK(mc_init(&c, sv[0], 4096) == 0);
    size_t len;
    enum proto_err why = PE_OK;
    CHECK(mc_recv(&c, &len, &why) == MC_MORE);
    /* header only, then the body in two pieces */
    CHECK(write(sv[1], HELLO, 12) == 12);
    CHECK(mc_recv(&c, &len, &why) == MC_MORE);
    CHECK(write(sv[1], HELLO + 12, 10) == 10);
    CHECK(mc_recv(&c, &len, &why) == MC_MORE);
    CHECK(write(sv[1], HELLO + 22, 18) == 18);
    CHECK(mc_recv(&c, &len, &why) == MC_MSG);
    CHECK_EQ_U64(len, 40);
    CHECK(memcmp(c.rx, HELLO, 40) == 0);
    mc_consume(&c, len);
    /* two messages in one write: the second stays buffered after the first is consumed */
    uint8_t two[80];
    memcpy(two, HELLO, 40);
    memcpy(two + 40, HELLO, 40);
    CHECK(write(sv[1], two, 80) == 80);
    CHECK(mc_recv(&c, &len, &why) == MC_MSG);
    mc_consume(&c, len);
    CHECK(mc_recv(&c, &len, &why) == MC_MSG);
    mc_consume(&c, len);
    CHECK(mc_recv(&c, &len, &why) == MC_MORE);
    CHECK_EQ_U64(c.msgs_in, 3);
    close(sv[1]);
    mc_close(&c);
}

TEST(a_bad_header_is_refused_before_the_body_is_read) {
    int sv[2];
    pair(sv);
    static struct msgconn c;
    CHECK(mc_init(&c, sv[0], 4096) == 0);
    uint8_t hdr[12] = {1, 11, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1}; /* length 65,537 */
    CHECK(write(sv[1], hdr, 12) == 12);
    size_t len;
    enum proto_err why = PE_OK;
    CHECK(mc_recv(&c, &len, &why) == MC_BAD_HEADER);
    CHECK(why == PE_TOO_LARGE);
    hdr[5] = 0; hdr[6] = 0; hdr[7] = 11; /* length 11 */
    c.rx_have = 0;
    CHECK(write(sv[1], hdr, 12) == 12);
    CHECK(mc_recv(&c, &len, &why) == MC_BAD_HEADER);
    CHECK(why == PE_BAD_LENGTH);
    close(sv[1]);
    mc_close(&c);
}

TEST(eof_inside_a_message_is_truncated_and_clean_eof_is_not) {
    int sv[2];
    pair(sv);
    static struct msgconn c;
    CHECK(mc_init(&c, sv[0], 4096) == 0);
    CHECK(write(sv[1], HELLO, 39) == 39);
    size_t len;
    enum proto_err why = PE_OK;
    CHECK(mc_recv(&c, &len, &why) == MC_MORE);
    close(sv[1]);
    CHECK(mc_recv(&c, &len, &why) == MC_EOF);
    CHECK(why == PE_TRUNCATED);
    mc_close(&c);
    pair(sv);
    CHECK(mc_init(&c, sv[0], 4096) == 0);
    close(sv[1]);
    why = PE_OK;
    CHECK(mc_recv(&c, &len, &why) == MC_EOF);
    CHECK(why == PE_OK);
    mc_close(&c);
}

TEST(send_buffer_is_capped) {
    int sv[2];
    pair(sv);
    static struct msgconn c;
    CHECK(mc_init(&c, sv[0], 1024) == 0);
    int sent = 0, failed = 0;
    for (int i = 0; i < 200 && !failed; i++) { /* nobody reads: the kernel buffer fills, then ours */
        static uint8_t big[600];
        memset(big, 0, sizeof big);
        if (mc_send(&c, big, sizeof big) == 0)
            sent++;
        else {
            failed = 1;
            CHECK(errno == ENOBUFS);
        }
    }
    CHECK(failed);
    CHECK(sent > 0);
    CHECK(mc_pending(&c) <= 1024);
    close(sv[1]);
    mc_close(&c);
}

TEST(hostport_parsing) {
    char ip[16];
    uint16_t port;
    CHECK(parse_hostport("10.98.0.254:7700", ip, &port) == 0);
    CHECK_STR_EQ(ip, "10.98.0.254");
    CHECK_EQ_U64(port, 7700);
    CHECK(parse_hostport("10.98.0.254", ip, &port) == -1);
    CHECK(parse_hostport("10.98.0.254:0", ip, &port) == -1);
    CHECK(parse_hostport("10.98.0.254:70000", ip, &port) == -1);
    CHECK(parse_hostport("host:7700", ip, &port) == -1);
}
