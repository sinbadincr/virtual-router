#include "minivr/pkt.h"

int pkt_vxlan_parse(const uint8_t *p, size_t avail, uint32_t *vni) {
    if (avail < VXLAN_HDR_LEN || !(p[0] & VXLAN_FLAG_I))
        return -1;
    *vni = rd32(p + 4) >> 8;
    return 0;
}

void pkt_vxlan_build(uint8_t *out, uint32_t vni) {
    wr32(out, (uint32_t)VXLAN_FLAG_I << 24); /* flags 0x08, reserved 0 */
    wr32(out + 4, vni << 8);                 /* VNI, reserved 0 */
}
