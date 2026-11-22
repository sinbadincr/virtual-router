/* Controller test fixture: the shipped lab intent loaded through the real grammar. */
#ifndef CTL_FIXTURE_H
#define CTL_FIXTURE_H
#include <stdio.h>
#include <string.h>

#include "minivr/ctl_model.h"

static struct cmodel cf_m;
static char cf_out[65536];
static struct cmd_err cf_err;

__attribute__((unused)) static int cf_run(const char *line, enum cg_where where) {
    struct jw w;
    jw_init(&w, cf_out, sizeof cf_out);
    memset(&cf_err, 0, sizeof cf_err);
    int rc = cg_exec(&cf_m, line, where, NULL, &w, &cf_err);
    jw_finish(&w);
    return rc;
}
__attribute__((unused)) static int cli(const char *line) { return cf_run(line, CG_CLI); }

/* intent file from lab/ctl/intent.conf; returns the number of lines executed, -1 on error */
__attribute__((unused)) static int cf_load_intent(void) {
    cm_init(&cf_m);
    FILE *f = fopen(MINIVR_SOURCE_DIR "/lab/ctl/intent.conf", "r");
    if (!f)
        return -1;
    char line[256];
    int n = 0;
    while (fgets(line, sizeof line, f)) {
        char *h = strchr(line, '#');
        if (h)
            *h = 0;
        size_t l = strlen(line);
        while (l && (line[l - 1] == '\n' || line[l - 1] == ' '))
            line[--l] = 0;
        if (!l)
            continue;
        if (cf_run(line, CG_FILE) != 0) {
            fprintf(stderr, "  intent line failed: %s -> %s: %s\n", line, cf_err.code, cf_err.message);
            fclose(f);
            return -1;
        }
        n++;
    }
    fclose(f);
    return n;
}

/* phase 2 bindings: red1, blue1 on cn1; red2, red3, blue2 on cn2; both nodes reported */
__attribute__((unused)) static void cf_phase2_bindings(void) {
    static const uint8_t rm1[6] = {2, 0, 0, 0xff, 0, 1}, rm2[6] = {2, 0, 0, 0xff, 0, 2};
    cm_node_learn(&cf_m, 0, 0xac100001u, rm1);
    cm_node_learn(&cf_m, 1, 0xac100002u, rm2);
    unsigned l;
    int from;
    cm_bind(&cf_m, 0, "red1", "red1", &l, &from);
    cm_bind(&cf_m, 0, "blue1", "blue1", &l, &from);
    cm_bind(&cf_m, 1, "red2", "red2", &l, &from);
    cm_bind(&cf_m, 1, "red3", "red3", &l, &from);
    cm_bind(&cf_m, 1, "blue2", "blue2", &l, &from);
}
#endif
