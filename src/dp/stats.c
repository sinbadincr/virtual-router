#include "minivr/stats.h"

#include <string.h>

struct stats g_stats;

static const char *const reason_names[DROP_COUNT] = {
#define X(id, name) [DROP_##id] = name,
    DROP_REASONS(X)
#undef X
};

const char *stats_reason_name(enum drop_reason r) {
    return (unsigned)r < DROP_COUNT ? reason_names[r] : "?";
}

void stats_drop(enum drop_reason r) {
    g_stats.reasons[r]++;
    g_stats.drop_total++;
}

void stats_drop_port(uint8_t port, enum drop_reason r) {
    stats_drop(r);
    if (port < MAX_PORTS)
        g_stats.port[port].drops++;
}

void stats_node_encap(uint8_t node, enum encap_kind k, uint64_t bytes) {
    if (node > NODE_UNKNOWN || k >= ENCAP_COUNT)
        return;
    g_stats.node[node].encap[k].pkts++;
    g_stats.node[node].encap[k].bytes += bytes;
}

void stats_node_decap(uint8_t node, enum encap_kind k, uint64_t bytes) {
    if (node > NODE_UNKNOWN || k >= ENCAP_COUNT)
        return;
    g_stats.node[node].decap[k].pkts++;
    g_stats.node[node].decap[k].bytes += bytes;
}

const char *stats_encap_name(enum encap_kind k) {
    return k == ENCAP_VXLAN ? "vxlan" : "mplsoudp";
}

void stats_clear(void) {
    memset(&g_stats, 0, sizeof g_stats);
}

uint64_t stats_reason_sum(void) {
    uint64_t s = 0;
    for (int i = 0; i < DROP_COUNT; i++)
        s += g_stats.reasons[i];
    return s;
}

void stats_json_drops(struct jw *w) {
    jw_obj_begin(w, "drops");
    jw_u64(w, "total", g_stats.drop_total);
    jw_obj_begin(w, "reasons");
    for (int i = 0; i < DROP_COUNT; i++)
        jw_u64(w, reason_names[i], g_stats.reasons[i]);
    jw_obj_end(w);
    jw_obj_end(w);
}

void stats_json_events(struct jw *w) {
    jw_obj_begin(w, "events");
    jw_u64(w, "icmp_ratelimited", g_stats.icmp_ratelimited);
    jw_u64(w, "neighbour_table_full", g_stats.neighbour_table_full);
    jw_u64(w, "arp_replies_sent", g_stats.arp_replies_sent);
    jw_u64(w, "icmp_sent", g_stats.icmp_sent);
    jw_obj_end(w);
}
