/* Per-node label allocator, quarantine and bind/unbind (data-model §2, research R10). Pure. */
#include <string.h>

#include "minivr/ctl_model.h"

static void cpy(char *dst, const char *src) {
    strncpy(dst, src, NE_NAME - 1);
    dst[NE_NAME - 1] = 0;
}

/* ---- labels: per node 1000..1999, lowest free first, quarantine ---- */

bool cm_label_quarantined(const struct cmodel *m, unsigned node, unsigned label) {
    for (int i = 0; i < CM_MAX_QUARANTINE; i++)
        if (m->quar[i].used && m->quar[i].node == node && m->quar[i].label == label)
            return true;
    return false;
}

static bool label_in_use(const struct cmodel *m, unsigned node, unsigned label) {
    for (int i = 0; i < CM_MAX_VMIS; i++)
        if (m->vmis[i].used && m->vmis[i].node == (int8_t)node && m->vmis[i].label == label)
            return true;
    return cm_label_quarantined(m, node, label);
}

static int label_alloc(const struct cmodel *m, unsigned node) {
    for (unsigned l = CM_LABEL_MIN; l <= CM_LABEL_MAX; l++)
        if (!label_in_use(m, node, l))
            return (int)l;
    return -1;
}

static void quarantine(struct cmodel *m, unsigned node, unsigned label) {
    for (int i = 0; i < CM_MAX_QUARANTINE; i++)
        if (!m->quar[i].used) {
            m->quar[i].used = true;
            m->quar[i].node = (uint8_t)node;
            m->quar[i].label = (uint16_t)label;
            return;
        }
    /* full: unreachable with 16 nodes x 16 bound VMIs (the table is larger than any reachable
     * state); the label then stays unusable until `node forget` */
}

void cm_label_release(struct cmodel *m, unsigned node, unsigned label) {
    for (int i = 0; i < CM_MAX_QUARANTINE; i++)
        if (m->quar[i].used && m->quar[i].node == node && m->quar[i].label == label) {
            memset(&m->quar[i], 0, sizeof m->quar[i]);
            m->gen++; /* the state file changes */
        }
}

int cm_unbind(struct cmodel *m, unsigned node, const char *vmi) {
    int i = cm_vmi_idx(m, vmi);
    if (i < 0 || m->vmis[i].node != (int8_t)node)
        return -1;
    quarantine(m, node, m->vmis[i].label);
    m->vmis[i].node = -1;
    m->vmis[i].port[0] = 0;
    m->vmis[i].label = 0;
    m->gen++;
    return 0;
}

enum cm_bind_res cm_bind(struct cmodel *m, unsigned node, const char *vmi, const char *port,
                         unsigned *label, int *moved_from) {
    *moved_from = -1;
    int i = cm_vmi_idx(m, vmi);
    if (i < 0)
        return CM_BIND_UNKNOWN_VMI;
    struct cm_vmi *v = &m->vmis[i];
    for (int k = 0; k < CM_MAX_VMIS; k++) /* port names are unique per node */
        if (m->vmis[k].used && k != i && m->vmis[k].node == (int8_t)node &&
            strcmp(m->vmis[k].port, port) == 0)
            return CM_BIND_PORT_IN_USE;
    if (v->node == (int8_t)node) { /* same node again: keep the label (survives restarts) */
        if (strcmp(v->port, port) != 0) {
            cpy(v->port, port);
            m->gen++;
        }
        *label = v->label;
        return CM_BIND_OK;
    }
    if (cm_bound_count(m, node) >= CM_MAX_BOUND_PER_NODE)
        return CM_BIND_TABLE_FULL;
    int l = label_alloc(m, node);
    if (l < 0)
        return CM_BIND_TABLE_FULL;
    if (v->node >= 0) { /* a later plug wins: it moves */
        *moved_from = v->node;
        quarantine(m, (unsigned)v->node, v->label);
    }
    v->node = (int8_t)node;
    cpy(v->port, port);
    v->label = (uint16_t)l;
    v->since_s = m->clock_s;
    *label = (unsigned)l;
    m->gen++;
    return CM_BIND_OK;
}
