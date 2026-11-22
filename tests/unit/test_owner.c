/* Phase 3 forwarder contract (contracts/forwarder.md): session roles, owner, runtime ports. */
#include <string.h>
#include <unistd.h>

#include "fixture.h"
#include "minivr/owner.h"
#include "minivr/tunnel.h"
#include "minivr/vrf.h"
#include "overlay_fixture.h"
#include "tharness.h"

static char out[65536];
static struct cmd_err err;

static int sess_cmd(struct cmd_session *s, const char *line) {
    struct jw w;
    jw_init(&w, out, sizeof out);
    memset(&err, 0, sizeof err);
    int rc = cmd_exec_session(s, line, &w, &err);
    jw_finish(&w);
    return rc;
}

static void agent_open(struct cmd_session *s) {
    cmd_session_open(s, 100, 0);
    CHECK(sess_cmd(s, "session agent") == 0);
}

TEST(second_agent_session_is_busy) {
    ov_setup(1, 1500);
    struct cmd_session a, b, c;
    agent_open(&a);
    cmd_session_open(&b, 101, 0);
    CHECK(sess_cmd(&b, "session agent") == -1);
    CHECK_STR_EQ(err.code, "busy");
    cmd_session_close(&a);
    CHECK(sess_cmd(&b, "session agent") == 0); /* closing the agent frees the role */
    cmd_session_open(&c, 102, 0);
    CHECK(sess_cmd(&c, "session show") == 0);
    CHECK(strstr(out, "\"role\":\"agent\"") != NULL);
    CHECK(strstr(out, "\"role\":\"cli\"") != NULL);
    CHECK(strstr(out, "\"peer_pid\":101") != NULL);
    CHECK(strstr(out, "\"requests\"") != NULL && strstr(out, "\"since\"") != NULL);
    cmd_session_close(&b);
    cmd_session_close(&c);
    ov_teardown();
}

TEST(owner_follows_the_creating_context) {
    ov_setup(1, 1500);
    struct cmd_session cli, agent;
    cmd_session_open(&cli, 1, 0);
    agent_open(&agent);
    CHECK(sess_cmd(&cli, "vrf add cliv id 5") == 0);
    CHECK(sess_cmd(&agent, "vrf add agv id 6") == 0);
    CHECK(sess_cmd(&cli, "vrf show") == 0);
    CHECK(strstr(out, "\"name\":\"red\",\"id\":1,\"ports\":[\"red1\"],\"routes\":4,\"neighbours\":1,"
                      "\"labels\":1,\"vnis\":0,\"owner\":\"config\"}"));
    CHECK(strstr(out, "\"name\":\"cliv\",\"id\":5,\"ports\":[],\"routes\":0,\"neighbours\":0,"
                      "\"labels\":0,\"vnis\":0,\"owner\":\"cli\"}"));
    CHECK(strstr(out, "\"name\":\"agv\",\"id\":6,\"ports\":[],\"routes\":0,\"neighbours\":0,"
                      "\"labels\":0,\"vnis\":0,\"owner\":\"agent\"}"));
    CHECK(sess_cmd(&agent, "node add cnx ip 172.16.0.9") == 0);
    CHECK(sess_cmd(&agent, "label add 1500 port red1") == 0);
    CHECK(sess_cmd(&agent, "vni add 700 vrf agv") == 0);
    CHECK(sess_cmd(&agent, "route add 10.9.9.9/32 vrf agv node cnx encap mplsoudp label 1600") == 0);
    CHECK(sess_cmd(&cli, "route show vrf agv") == 0);
    CHECK(strstr(out, "\"origin\":\"remote\",\"node\":\"cnx\",\"encap\":\"mplsoudp\",\"tag\":1600,"
                      "\"owner\":\"agent\"}"));
    CHECK(sess_cmd(&cli, "node show") == 0);
    CHECK(strstr(out, "\"owner\":\"agent\"") != NULL);
    CHECK(sess_cmd(&cli, "tunnel show") == 0);
    CHECK(strstr(out, "{\"label\":1500,\"port\":\"red1\",\"vrf\":\"red\",\"owner\":\"agent\"}"));
    CHECK(strstr(out, "{\"vni\":700,\"vrf\":\"agv\",\"owner\":\"agent\"}"));
    /* phase 1/2 origin values stay */
    CHECK(sess_cmd(&cli, "route show vrf red") == 0);
    CHECK(strstr(out, "\"origin\":\"connected\",\"owner\":\"config\"}"));
    CHECK(strstr(out, "\"origin\":\"host\",\"owner\":\"config\"}"));
    cmd_session_close(&cli);
    cmd_session_close(&agent);
    ov_teardown();
}

TEST(agent_cannot_change_foreign_entries_but_cli_can_delete_agent_entries) {
    ov_setup(1, 1500);
    struct cmd_session cli, agent;
    cmd_session_open(&cli, 1, 0);
    agent_open(&agent);
    static char digest_before[65536], digest_after[65536];
    CHECK(sess_cmd(&cli, "route show vrf red") == 0);
    strcpy(digest_before, out);
    const char *foreign[] = {"vrf del red",
                             "node del cn2",
                             "node set cn2 rmac 02:00:00:ff:00:09",
                             "label del 1011",
                             "route del 10.1.1.12/32 vrf red",
                             "route replace 10.1.1.12/32 vrf red node cn2 encap vxlan vni 100",
                             "neigh del 10.1.1.11 vrf red",
                             "port set red1 admin down",
                             "port set red1 vrf blue",
                             "port del red1"};
    for (size_t i = 0; i < sizeof foreign / sizeof *foreign; i++) {
        CHECK(sess_cmd(&agent, foreign[i]) == -1);
        CHECK_STR_EQ(err.code, "not-owner");
    }
    /* an agent add of an existing key is `exists`, not `not-owner` */
    CHECK(sess_cmd(&agent, "vrf add red id 9") == -1);
    CHECK_STR_EQ(err.code, "exists");
    CHECK(sess_cmd(&cli, "route show vrf red") == 0);
    strcpy(digest_after, out);
    CHECK(strstr(digest_after, "\"prefix\":\"10.1.1.12/32\"") != NULL);
    CHECK(strstr(digest_before, "10.1.1.12/32") != NULL);
    /* a CLI session may delete an agent entry */
    CHECK(sess_cmd(&agent, "vrf add tmp id 8") == 0);
    CHECK(sess_cmd(&cli, "vrf del tmp") == 0);
    cmd_session_close(&cli);
    cmd_session_close(&agent);
    ov_teardown();
}

TEST(version_has_daemon_and_boot_id) {
    struct cmd_session s;
    cmd_session_open(&s, 1, 0);
    cmd_set_boot_id("0123456789abcdef");
    CHECK(sess_cmd(&s, "version") == 0);
    CHECK(strstr(out, "\"daemon\":\"minivrd\"") != NULL);
    CHECK(strstr(out, "\"boot_id\":\"0123456789abcdef\"") != NULL);
    cmd_session_close(&s);
}

/* ---- runtime ports ---- */

static int pipe_fd(void) {
    int p[2];
    CHECK(pipe(p) == 0);
    close(p[1]);
    return p[0];
}

static int add_rt(struct cmd_session *s, const char *line) {
    s->fd_in = pipe_fd();
    return sess_cmd(s, line);
}

TEST(runtime_port_add_adopts_the_fd) {
    ov_setup(1, 1500);
    uint8_t mac[6] = {2, 0, 0, 0x0a, 1, 9};
    pio_fake_add_if("red9", mac, 1500);
    struct cmd_session cli, agent;
    cmd_session_open(&cli, 1, 0);
    agent_open(&agent);
    /* without an agent session: config-only */
    cli.fd_in = pipe_fd();
    CHECK(sess_cmd(&cli, "port add red9 ifname red9 ip 10.1.9.1/24 vrf red fd") == -1);
    CHECK(cli.fd_in >= 0); /* the server closes it, not the command */
    close(cli.fd_in);
    cli.fd_in = -1;
    CHECK(sess_cmd(&cli, "port add red9 ifname red9 ip 10.1.9.1/24 vrf red") == -1);
    CHECK_STR_EQ(err.code, "config-only");
    /* agent: missing fd -> bad-syntax */
    CHECK(sess_cmd(&agent, "port add red9 ifname red9 ip 10.1.9.1/24 vrf red fd") == -1);
    CHECK_STR_EQ(err.code, "bad-syntax");
    CHECK(add_rt(&agent, "port add red9 ifname red9 ip 10.1.9.1/24 vrf red fd") == 0);
    CHECK(agent.fd_in == -1);
    CHECK(port_find("red9") != NULL);
    CHECK_EQ_U64(port_find("red9")->owner, OWNER_AGENT);
    CHECK(sess_cmd(&cli, "route show vrf red") == 0);
    CHECK(strstr(out, "\"prefix\":\"10.1.9.0/24\",\"port\":\"red9\",\"gateway\":null,"
                      "\"origin\":\"connected\",\"owner\":\"agent\"}"));
    /* errors close the fd and leave state unchanged */
    CHECK(add_rt(&agent, "port add red9 ifname red9 ip 10.1.9.1/24 vrf red fd") == -1);
    CHECK_STR_EQ(err.code, "exists");
    CHECK(agent.fd_in == -1);
    CHECK(add_rt(&agent, "port add redx ifname red9x ip 10.1.9.1/24 vrf nosuch fd") == -1);
    CHECK_STR_EQ(err.code, "unknown-vrf");
    cmd_session_close(&cli);
    cmd_session_close(&agent);
    ov_teardown();
}

static const char *refuse_all(int fd, const char *ifname) {
    (void)fd;
    (void)ifname;
    return "not an AF_PACKET socket";
}

TEST(runtime_port_add_runs_the_fd_checker) {
    ov_setup(1, 1500);
    uint8_t mac[6] = {2, 0, 0, 0x0a, 1, 9};
    pio_fake_add_if("red9", mac, 1500);
    struct cmd_session agent;
    agent_open(&agent);
    cmd_set_fd_checker(refuse_all);
    CHECK(add_rt(&agent, "port add red9 ifname red9 ip 10.1.9.1/24 vrf red fd") == -1);
    CHECK_STR_EQ(err.code, "bad-fd");
    CHECK(agent.fd_in == -1);
    CHECK(port_find("red9") == NULL);
    cmd_set_fd_checker(NULL);
    cmd_session_close(&agent);
    ov_teardown();
}

TEST(port_del_cascades) {
    ov_setup(1, 1500);
    struct cmd_session cli, agent;
    cmd_session_open(&cli, 1, 0);
    agent_open(&agent);
    uint8_t mac[6] = {2, 0, 0, 0x0a, 1, 9};
    pio_fake_add_if("red9", mac, 1500);
    CHECK(add_rt(&agent, "port add red9 ifname red9 ip 10.1.9.1/24 vrf red fd") == 0);
    CHECK(sess_cmd(&agent, "neigh add 10.1.9.11 lladdr 02:00:00:01:09:11 dev red9") == 0);
    CHECK(sess_cmd(&agent, "label add 1900 port red9") == 0);
    CHECK(sess_cmd(&cli, "route add 10.7.7.0/24 vrf red dev red9 via 10.1.9.254") == 0);
    CHECK(sess_cmd(&agent, "port del red9") == -1); /* a static route still uses it */
    CHECK_STR_EQ(err.code, "busy");
    CHECK(sess_cmd(&cli, "route del 10.7.7.0/24 vrf red") == 0);
    CHECK(sess_cmd(&agent, "port del red1") == -1);
    CHECK_STR_EQ(err.code, "not-owner");
    CHECK(sess_cmd(&agent, "port del red9") == 0);
    CHECK(port_find("red9") == NULL);
    CHECK(label_lookup(1900) < 0);
    CHECK(neigh_lookup(1, 0x0a010b0bU) == NULL);
    CHECK(route_find(1, 0x0a010900U, 24) == NULL);
    CHECK(sess_cmd(&cli, "port del nosuch") == -1);
    CHECK_STR_EQ(err.code, "unknown-port");
    CHECK(sess_cmd(&cli, "port del u0") == -1);
    CHECK_STR_EQ(err.code, "immutable");
    cmd_session_close(&cli);
    cmd_session_close(&agent);
    ov_teardown();
}
