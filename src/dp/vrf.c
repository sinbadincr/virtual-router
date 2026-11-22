#include "minivr/vrf.h"

#include <string.h>

#include "minivr/port.h"
#include "minivr/tunnel.h"

static struct lpm_pool pool;
static struct vrf vrfs[VRF_MAX];
static int inited;

void vrf_reset(void) {
    inited = 1;
    lpm_pool_init(&pool);
    memset(vrfs, 0, sizeof vrfs);
    vrfs[0].in_use = true;
    strcpy(vrfs[0].name, "default");
    lpm_root_init(&pool, &vrfs[0].root); /* a fresh pool cannot be exhausted */
}

static void ensure(void) {
    if (!inited)
        vrf_reset();
}

struct lpm_pool *vrf_pool(void) {
    ensure();
    return &pool;
}

struct vrf *vrf_by_id(unsigned id) {
    ensure();
    return (id < VRF_MAX && vrfs[id].in_use) ? &vrfs[id] : NULL;
}

struct vrf *vrf_by_name(const char *name) {
    ensure();
    for (unsigned i = 0; i < VRF_MAX; i++)
        if (vrfs[i].in_use && strcmp(vrfs[i].name, name) == 0)
            return &vrfs[i];
    return NULL;
}

unsigned vrf_count(void) {
    ensure();
    unsigned n = 0;
    for (unsigned i = 0; i < VRF_MAX; i++)
        n += vrfs[i].in_use;
    return n;
}

static bool name_ok(const char *s) {
    size_t n = strlen(s);
    if (n < 1 || n > VRF_NAME_MAX)
        return false;
    for (; *s; s++)
        if (!((*s >= 'a' && *s <= 'z') || (*s >= '0' && *s <= '9') || *s == '_' || *s == '-'))
            return false;
    return true;
}

int vrf_add(const char *name, unsigned id, struct cmd_err *err) {
    ensure();
    if (!name_ok(name))
        return cmd_fail(err, "bad-syntax", "VRF name must be 1..%d characters of [a-z0-9_-]",
                        VRF_NAME_MAX);
    if (id < 1 || id >= VRF_MAX)
        return cmd_fail(err, "bad-syntax", "VRF id must be 1..%d (0 is `default`)", VRF_MAX - 1);
    if (vrf_by_name(name))
        return cmd_fail(err, "exists", "VRF %s already exists", name);
    if (vrf_count() >= VRF_MAX)
        return cmd_fail(err, "table-full", "at most %d VRFs", VRF_MAX);
    if (vrfs[id].in_use)
        return cmd_fail(err, "exists", "VRF id %u already used by %s", id, vrfs[id].name);
    struct vrf *v = &vrfs[id];
    if (lpm_root_init(&pool, &v->root) != 0)
        return cmd_fail(err, "table-full", "route table full");
    v->id = (uint8_t)id;
    v->in_use = true;
    v->owner = (uint8_t)g_owner_ctx;
    strcpy(v->name, name);
    return 0;
}

int vrf_del(const char *name, struct cmd_err *err) {
    struct vrf *v = vrf_by_name(name);
    if (!v)
        return cmd_fail(err, "not-found", "no such VRF '%s'", name);
    if (v->id == VRF_DEFAULT)
        return cmd_fail(err, "immutable", "the default VRF cannot be deleted");
    /* A port's connected and host routes go with the port, so any route left in the root is a
     * static or remote one. */
    if (port_count_in_vrf(v->id) || lpm_count(&v->root) || tunnel_vni_count_vrf(v->id))
        return cmd_fail(err, "busy", "VRF %s is still referenced by ports, routes or VNIs", name);
    lpm_root_release(&pool, &v->root);
    memset(v, 0, sizeof *v);
    return 0;
}
