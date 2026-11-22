#include "ctl_fixture.h"
#include "tharness.h"

static unsigned bind1(unsigned node, const char *vmi, const char *port) {
    unsigned l = 0;
    int from;
    CHECK(cm_bind(&cf_m, node, vmi, port, &l, &from) == CM_BIND_OK);
    return l;
}

TEST(lowest_free_label_per_node_starting_at_1000) {
    CHECK_EQ_U64(cf_load_intent(), 15);
    CHECK_EQ_U64(bind1(0, "red1", "red1"), 1000);
    CHECK_EQ_U64(bind1(0, "blue1", "blue1"), 1001);
    CHECK_EQ_U64(bind1(1, "red2", "red2"), 1000); /* labels are per node */
    CHECK_EQ_U64(bind1(1, "red3", "red3"), 1001);
}

TEST(a_binding_kept_on_its_node_keeps_its_label_across_save_and_load) {
    CHECK_EQ_U64(cf_load_intent(), 15);
    bind1(0, "red1", "red1");
    bind1(0, "blue1", "blue1");
    CHECK_EQ_U64(bind1(0, "red1", "red1"), 1000); /* idempotent */
    char text[8192];
    CHECK(cm_serialize(&cf_m, text, sizeof text) > 0);
    CHECK(strstr(text, "bind red1 node cn1 port red1 label 1000"));
    CHECK(strstr(text, "bind blue1 node cn1 port blue1 label 1001"));
    /* reload into a fresh model and bind again: same labels */
    struct cmodel saved = cf_m;
    cm_init(&cf_m);
    char *save = NULL;
    for (char *l = strtok_r(text, "\n", &save); l; l = strtok_r(NULL, "\n", &save))
        if (l[0] != '#')
            CHECK(cf_run(l, CG_FILE | CG_STATE) == 0);
    CHECK_EQ_U64(bind1(0, "red1", "red1"), 1000);
    CHECK_EQ_U64(bind1(0, "blue1", "blue1"), 1001);
    CHECK_EQ_U64(cm_bound_count(&cf_m, 0), cm_bound_count(&saved, 0));
}

TEST(unbind_and_move_quarantine_the_label_until_released) {
    CHECK_EQ_U64(cf_load_intent(), 15);
    bind1(0, "red1", "red1");
    CHECK(cm_unbind(&cf_m, 0, "red1") == 0);
    CHECK(cm_unbind(&cf_m, 0, "red1") == -1);
    CHECK(cm_label_quarantined(&cf_m, 0, 1000));
    CHECK_EQ_U64(bind1(0, "red1", "red1"), 1001); /* 1000 is never handed out while quarantined */
    CHECK(cm_label_quarantined(&cf_m, 0, 1000));
    cm_label_release(&cf_m, 0, 1000); /* the ACK of the deleting update */
    CHECK(!cm_label_quarantined(&cf_m, 0, 1000));
    CHECK_EQ_U64(bind1(0, "blue1", "blue1"), 1000);
    /* a move quarantines the label on the node it left */
    unsigned l;
    int from;
    CHECK(cm_bind(&cf_m, 1, "red1", "red1", &l, &from) == CM_BIND_OK);
    CHECK_EQ_U64(from, 0);
    CHECK_EQ_U64(l, 1000);
    CHECK(cm_label_quarantined(&cf_m, 0, 1001));
    CHECK_EQ_U64(cf_m.vmis[cm_vmi_idx(&cf_m, "red1")].node, 1);
    /* quarantine survives a save/load */
    char text[8192];
    CHECK(cm_serialize(&cf_m, text, sizeof text) > 0);
    CHECK(strstr(text, "quarantine node cn1 label 1001"));
}

TEST(node_forget_releases_labels_and_quarantine) {
    CHECK_EQ_U64(cf_load_intent(), 15);
    bind1(0, "red1", "red1");
    bind1(0, "blue1", "blue1");
    cm_unbind(&cf_m, 0, "blue1");
    CHECK(cli("node forget cn1") == 0);
    CHECK_EQ_U64(cm_quarantine_count(&cf_m, 0), 0);
    CHECK_EQ_U64(bind1(0, "red1", "red1"), 1000);
}

TEST(bind_errors) {
    CHECK_EQ_U64(cf_load_intent(), 15);
    unsigned l;
    int from;
    CHECK(cm_bind(&cf_m, 0, "nosuch", "p", &l, &from) == CM_BIND_UNKNOWN_VMI);
    bind1(0, "red1", "tap0");
    CHECK(cm_bind(&cf_m, 0, "blue1", "tap0", &l, &from) == CM_BIND_PORT_IN_USE);
    CHECK(cm_bind(&cf_m, 1, "blue1", "tap0", &l, &from) == CM_BIND_OK); /* ports are per node */
    CHECK_EQ_U64(cm_bound_count(&cf_m, 0), 1);
}

TEST(at_most_sixteen_bound_vmis_per_node) {
    cm_init(&cf_m);
    CHECK(cli("tenant add t id 1 vni 1 encap vxlan") == 0);
    CHECK(cli("subnet add t 10.0.0.0/16 gw 10.0.0.1") == 0);
    CHECK(cli("node add n") == 0);
    for (unsigned i = 0; i < 17; i++) {
        char line[128];
        snprintf(line, sizeof line, "vmi add v%u tenant t ip 10.0.1.%u mac 02:00:00:00:01:%02x", i, i + 1, i);
        CHECK(cli(line) == 0);
    }
    unsigned l;
    int from;
    for (unsigned i = 0; i < 16; i++) {
        char v[16], p[16];
        snprintf(v, sizeof v, "v%u", i);
        snprintf(p, sizeof p, "p%u", i);
        CHECK(cm_bind(&cf_m, 0, v, p, &l, &from) == CM_BIND_OK);
    }
    uint64_t gen = cf_m.gen;
    CHECK(cm_bind(&cf_m, 0, "v16", "p16", &l, &from) == CM_BIND_TABLE_FULL);
    CHECK_EQ_U64(cf_m.gen, gen); /* not recorded */
    CHECK_EQ_U64(cm_bound_count(&cf_m, 0), 16);
}

TEST(bind_then_unbind_before_any_ack_leaves_the_node_state_as_before) {
    CHECK_EQ_U64(cf_load_intent(), 15);
    bind1(0, "red1", "red1");
    cm_node_learn(&cf_m, 0, 0xac100001u, (const uint8_t[]){2, 0, 0, 0xff, 0, 1});
    cm_node_learn(&cf_m, 1, 0xac100002u, (const uint8_t[]){2, 0, 0, 0xff, 0, 2});
    static struct nentry a[4096], b[4096], dels[4096], adds[4096];
    struct nstate before, after;
    ns_init(&before, a, 4096);
    ns_init(&after, b, 4096);
    CHECK(cm_compute(&cf_m, 0, &before) == 0);
    bind1(1, "red2", "red2");
    cm_unbind(&cf_m, 1, "red2");
    CHECK(cm_compute(&cf_m, 0, &after) == 0);
    struct ndiff d = {dels, adds, 0, 0, 4096, 4096};
    CHECK(ns_diff(&before, &after, &d) == 0);
    CHECK_EQ_U64(d.ndels + d.nadds, 0); /* D[n] equals the state before the BIND: nothing to send */
}
