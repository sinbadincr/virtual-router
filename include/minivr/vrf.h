#ifndef MINIVR_VRF_H
#define MINIVR_VRF_H
#include <stdbool.h>
#include <stdint.h>

#include "cmd.h"
#include "lpm.h"
#include "owner.h"

#define VRF_MAX 64
#define VRF_DEFAULT 0
#define VRF_NAME_MAX 15

/* One routing table per VRF: a root in the shared LPM pool (data-model "VRF"). Id 0 is `default`,
 * always present, and holds everything a phase 1 config describes. */
struct vrf {
    uint8_t id;
    bool in_use;
    uint8_t owner; /* enum owner */
    char name[VRF_NAME_MAX + 1];
    struct lpm_root root;
};

struct lpm_pool *vrf_pool(void);

/* Errors: bad-syntax (name or id), exists (name or id taken), table-full (64 VRFs). */
int vrf_add(const char *name, unsigned id, struct cmd_err *err);
/* Errors: not-found, immutable (default), busy (a port, route, label or VNI references it). */
int vrf_del(const char *name, struct cmd_err *err);

struct vrf *vrf_by_id(unsigned id);
struct vrf *vrf_by_name(const char *name);
unsigned vrf_count(void);
void vrf_reset(void); /* tests: pool and every VRF back to just `default` */
#endif
