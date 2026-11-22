#include "minivr/ctl_store.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define STATE_MAX (1 << 20)

int store_test_fail_before_rename;

static int slurp(const char *path, char **out, size_t *len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size > STATE_MAX) {
        close(fd);
        errno = EFBIG;
        return -1;
    }
    char *buf = malloc((size_t)st.st_size + 1);
    if (!buf) {
        close(fd);
        return -1;
    }
    size_t got = 0;
    while (got < (size_t)st.st_size) {
        ssize_t n = read(fd, buf + got, (size_t)st.st_size - got);
        if (n <= 0)
            break;
        got += (size_t)n;
    }
    close(fd);
    if (got != (size_t)st.st_size) {
        free(buf);
        errno = EIO;
        return -1;
    }
    buf[got] = 0;
    *out = buf;
    *len = got;
    return 0;
}

static int parse_text(struct cmodel *m, char *text, enum cg_where where, const char *path,
                      char *err, size_t errcap) {
    char resp[512];
    int lineno = 0;
    char *save = NULL;
    for (char *line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        lineno++;
        char *hash = strchr(line, '#');
        if (hash)
            *hash = 0;
        size_t n = strlen(line);
        while (n > 0 && (line[n - 1] == '\r' || line[n - 1] == ' ' || line[n - 1] == '\t'))
            line[--n] = 0;
        char *s = line;
        while (*s == ' ' || *s == '\t')
            s++;
        if (!*s)
            continue;
        struct jw w;
        struct cmd_err e;
        jw_init(&w, resp, sizeof resp);
        if (cg_exec(m, s, where, NULL, &w, &e) != 0) {
            snprintf(err, errcap, "%s:%d: %s: %s", path, lineno, e.code ? e.code : "error", e.message);
            return -1;
        }
    }
    return 0;
}

int store_load(struct cmodel *m, const char *state_path, const char *init_path, char *err,
               size_t errcap) {
    char *text;
    size_t len;
    cm_init(m);
    if (slurp(state_path, &text, &len) == 0) {
        if (len == 0) {
            snprintf(err, errcap, "%s: state file is empty", state_path);
            free(text);
            return -1;
        }
        int rc = parse_text(m, text, CG_FILE | CG_STATE, state_path, err, errcap);
        free(text);
        if (rc != 0)
            cm_init(m);
        m->gen = 0;
        return rc;
    }
    if (errno != ENOENT) {
        snprintf(err, errcap, "%s: cannot read state file: %s", state_path, strerror(errno));
        return -1;
    }
    if (!init_path) {
        snprintf(err, errcap, "%s: no state file and no --init intent", state_path);
        return -1;
    }
    if (slurp(init_path, &text, &len) != 0) {
        snprintf(err, errcap, "%s: cannot read intent file: %s", init_path, strerror(errno));
        return -1;
    }
    int rc = parse_text(m, text, CG_FILE, init_path, err, errcap);
    free(text);
    if (rc != 0) {
        cm_init(m);
        return -1;
    }
    if (store_save(m, state_path) != 0) {
        snprintf(err, errcap, "%s: cannot write state file: %s", state_path, strerror(errno));
        return -1;
    }
    m->gen = 0;
    return 0;
}

int store_save(const struct cmodel *m, const char *path) {
    char *buf = malloc(STATE_MAX);
    if (!buf)
        return -1;
    int len = cm_serialize(m, buf, STATE_MAX);
    if (len < 0) {
        free(buf);
        errno = EFBIG;
        return -1;
    }
    char tmp[512];
    if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp) {
        free(buf);
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        free(buf);
        return -1;
    }
    size_t off = 0;
    int rc = 0;
    while (off < (size_t)len) {
        ssize_t n = write(fd, buf + off, (size_t)len - off);
        if (n <= 0) {
            rc = -1;
            break;
        }
        off += (size_t)n;
    }
    free(buf);
    if (rc == 0 && fsync(fd) < 0)
        rc = -1;
    int e = errno;
    close(fd);
    if (rc == 0 && store_test_fail_before_rename) {
        errno = EIO;
        return -1; /* the temp file stays behind, the state file is untouched */
    }
    if (rc == 0 && rename(tmp, path) < 0) {
        rc = -1;
        e = errno;
    }
    if (rc != 0) {
        unlink(tmp);
        errno = e;
        return -1;
    }
    char dir[512];
    snprintf(dir, sizeof dir, "%s", path);
    char *slash = strrchr(dir, '/');
    const char *d = slash ? (slash == dir ? "/" : (*slash = 0, dir)) : ".";
    int dfd = open(d, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd >= 0) {
        (void)!fsync(dfd);
        close(dfd);
    }
    return 0;
}
