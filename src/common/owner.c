#include "minivr/owner.h"

enum owner g_owner_ctx = OWNER_CONFIG;

const char *owner_name(enum owner o) {
    switch (o) {
    case OWNER_CLI:
        return "cli";
    case OWNER_AGENT:
        return "agent";
    case OWNER_CONFIG:
    default:
        return "config";
    }
}
