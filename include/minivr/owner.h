#ifndef MINIVR_OWNER_H
#define MINIVR_OWNER_H
#include <stdint.h>

/* Who created an entry (phase 3 contracts/forwarder.md). Set at creation, never changes. */
enum owner { OWNER_CONFIG = 0, OWNER_CLI = 1, OWNER_AGENT = 2 };

/* Owner stamped on every entry created while this value is set. cmd_exec sets it per command
 * (config file -> config, CLI session -> cli, agent session -> agent); unit tests that call the
 * dp tables directly get OWNER_CONFIG. */
extern enum owner g_owner_ctx;

const char *owner_name(enum owner o);
#endif
