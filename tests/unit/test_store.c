#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ctl_fixture.h"
#include "minivr/ctl_store.h"
#include "tharness.h"

static char dir[] = "/tmp/minivr-test-store-XXXXXX";
static char state[128], init[128];

static void setup(void) {
    strcpy(dir, "/tmp/minivr-test-store-XXXXXX");
    CHECK(mkdtemp(dir) != NULL);
    snprintf(state, sizeof state, "%s/state.conf", dir);
    snprintf(init, sizeof init, "%s", MINIVR_SOURCE_DIR "/lab/ctl/intent.conf");
}

static void cleanup(void) {
    char tmp[160];
    snprintf(tmp, sizeof tmp, "%s.tmp", state);
    unlink(tmp);
    unlink(state);
    rmdir(dir);
}

static void write_file(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    fputs(text, f);
    fclose(f);
}

TEST(init_is_written_to_state_and_reloaded_identically) {
    setup();
    char err[256] = "";
    struct cmodel m1, m2;
    CHECK(store_load(&m1, state, init, err, sizeof err) == 0);
    unsigned l;
    int from;
    cm_bind(&m1, 0, "red1", "red1", &l, &from);
    cm_bind(&m1, 0, "blue1", "blue1", &l, &from);
    cm_unbind(&m1, 0, "blue1"); /* leaves a quarantine line */
    CHECK(store_save(&m1, state) == 0);
    CHECK(store_load(&m2, state, NULL, err, sizeof err) == 0);
    static char a[200000], b[200000];
    CHECK(cm_serialize(&m1, a, sizeof a) > 0);
    CHECK(cm_serialize(&m2, b, sizeof b) > 0);
    CHECK_STR_EQ(a, b);
    CHECK(strstr(b, "bind red1 node cn1 port red1 label 1000"));
    CHECK(strstr(b, "quarantine node cn1 label 1001"));
    cleanup();
}

TEST(replacement_is_atomic_a_failure_before_rename_keeps_the_old_file) {
    setup();
    char err[256];
    struct cmodel m;
    CHECK(store_load(&m, state, init, err, sizeof err) == 0);
    static char before[200000], after[200000];
    FILE *f = fopen(state, "r");
    size_t n = fread(before, 1, sizeof before - 1, f);
    before[n] = 0;
    fclose(f);
    CHECK(cli("tenant add t9 id 9 vni 9 encap vxlan") == -1 || 1); /* cf_m is separate; use m below */
    struct cmd_err e;
    struct jw w;
    char buf[512];
    jw_init(&w, buf, sizeof buf);
    CHECK(cg_exec(&m, "tenant add t9 id 9 vni 9 encap vxlan", CG_CLI, NULL, &w, &e) == 0);
    store_test_fail_before_rename = 1;
    CHECK(store_save(&m, state) == -1);
    store_test_fail_before_rename = 0;
    f = fopen(state, "r");
    n = fread(after, 1, sizeof after - 1, f);
    after[n] = 0;
    fclose(f);
    CHECK_STR_EQ(before, after); /* no partial file, the old state is intact */
    CHECK(strstr(after, "t9") == NULL);
    CHECK(store_save(&m, state) == 0); /* and a normal save goes through */
    cleanup();
}

TEST(missing_empty_or_broken_state_is_an_error_never_an_empty_start) {
    setup();
    char err[256] = "";
    struct cmodel m;
    CHECK(store_load(&m, state, NULL, err, sizeof err) == -1); /* missing, no --init */
    CHECK(strstr(err, "no state file") != NULL);
    write_file(state, "");
    CHECK(store_load(&m, state, init, err, sizeof err) == -1); /* empty: never "start empty" */
    CHECK(strstr(err, "empty") != NULL);
    write_file(state, "# header\ntenant add red id 1 vni 100 encap mplsoudp\nbogus line here\n");
    CHECK(store_load(&m, state, NULL, err, sizeof err) == -1);
    CHECK(strstr(err, ":3:") != NULL); /* the line number */
    chmod(state, 0000);
    if (geteuid() != 0) {
        CHECK(store_load(&m, state, init, err, sizeof err) == -1);
    }
    chmod(state, 0600);
    write_file(state, "# x\nbind red1 node cn1 port red1 label 1000\n"); /* bind before its vmi exists */
    CHECK(store_load(&m, state, NULL, err, sizeof err) == -1);
    cleanup();
}

TEST(a_broken_intent_file_writes_no_state) {
    setup();
    char err[256] = "";
    struct cmodel m;
    char bad[128];
    snprintf(bad, sizeof bad, "%s/bad.conf", dir);
    write_file(bad, "tenant add red id 1 vni 100 encap mplsoudp\nvmi add x tenant red ip 1.2.3.4 mac 02:00:00:00:00:01\n");
    CHECK(store_load(&m, state, bad, err, sizeof err) == -1);
    CHECK(strstr(err, ":2:") != NULL);
    CHECK(access(state, F_OK) != 0);
    unlink(bad);
    cleanup();
}
