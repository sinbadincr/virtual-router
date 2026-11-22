#ifndef MINIVR_CTL_STORE_H
#define MINIVR_CTL_STORE_H
#include <stddef.h>

#include "ctl_model.h"

/* Controller state file (research R11): the grammar of contracts/controller-cli.md, replaced
 * atomically (temp file, fsync, rename, fsync of the directory). */

/* Load `state_path` (intent, bind, quarantine lines). When it does not exist and `init_path` is
 * given, load the intent file and write the state file. A missing state file without init, an
 * empty or unreadable one, or any parse error is a failure: `err` gets "file:line: code: msg". */
int store_load(struct cmodel *m, const char *state_path, const char *init_path, char *err,
               size_t errcap);
/* Serialise and replace the state file atomically. 0, or -1 (errno). */
int store_save(const struct cmodel *m, const char *path);

extern int store_test_fail_before_rename; /* unit tests: simulate a crash between write and rename */
#endif
