#include "minivr/json_in.h"

#include <stdlib.h>
#include <string.h>

#define MAX_DEPTH 32

struct ps {
    const char *p, *end;
    int depth;
};

static void ws(struct ps *s) {
    while (s->p < s->end && (*s->p == ' ' || *s->p == '\t' || *s->p == '\n' || *s->p == '\r'))
        s->p++;
}

static struct jnode *node(enum jtype t) {
    struct jnode *n = calloc(1, sizeof *n);
    if (n)
        n->type = t;
    return n;
}

void json_free(struct jnode *n) {
    while (n) {
        struct jnode *next = n->next;
        json_free(n->child);
        free(n->key);
        free(n->str);
        free(n);
        n = next;
    }
}

static int hex4(const char *p, unsigned *out) {
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        char c = p[i];
        unsigned d;
        if (c >= '0' && c <= '9')
            d = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f')
            d = (unsigned)(c - 'a') + 10;
        else if (c >= 'A' && c <= 'F')
            d = (unsigned)(c - 'A') + 10;
        else
            return -1;
        v = v * 16 + d;
    }
    *out = v;
    return 0;
}

static char *parse_string(struct ps *s) {
    if (s->p >= s->end || *s->p != '"')
        return NULL;
    s->p++;
    char *out = malloc((size_t)(s->end - s->p) + 1);
    size_t n = 0;
    if (!out)
        return NULL;
    while (s->p < s->end && *s->p != '"') {
        unsigned char c = (unsigned char)*s->p++;
        if (c < 0x20)
            goto bad;
        if (c != '\\') {
            out[n++] = (char)c;
            continue;
        }
        if (s->p >= s->end)
            goto bad;
        char e = *s->p++;
        switch (e) {
        case '"': case '\\': case '/': out[n++] = e; break;
        case 'n': out[n++] = '\n'; break;
        case 't': out[n++] = '\t'; break;
        case 'r': out[n++] = '\r'; break;
        case 'b': out[n++] = '\b'; break;
        case 'f': out[n++] = '\f'; break;
        case 'u': {
            unsigned cp;
            if (s->end - s->p < 4 || hex4(s->p, &cp) != 0)
                goto bad;
            s->p += 4;
            if (cp < 0x80) {
                out[n++] = (char)cp;
            } else if (cp < 0x800) {
                out[n++] = (char)(0xc0 | (cp >> 6));
                out[n++] = (char)(0x80 | (cp & 0x3f));
            } else {
                out[n++] = (char)(0xe0 | (cp >> 12));
                out[n++] = (char)(0x80 | ((cp >> 6) & 0x3f));
                out[n++] = (char)(0x80 | (cp & 0x3f));
            }
            break;
        }
        default: goto bad;
        }
    }
    if (s->p >= s->end)
        goto bad;
    s->p++;
    out[n] = 0;
    return out;
bad:
    free(out);
    return NULL;
}

static struct jnode *parse_value(struct ps *s);

static struct jnode *parse_container(struct ps *s, enum jtype t) {
    char close = t == J_ARR ? ']' : '}';
    if (++s->depth > MAX_DEPTH)
        return NULL;
    s->p++; /* opener */
    struct jnode *n = node(t);
    struct jnode **tail = n ? &n->child : NULL;
    if (!n)
        return NULL;
    ws(s);
    if (s->p < s->end && *s->p == close) {
        s->p++;
        s->depth--;
        return n;
    }
    for (;;) {
        ws(s);
        char *key = NULL;
        if (t == J_OBJ) {
            key = parse_string(s);
            ws(s);
            if (!key || s->p >= s->end || *s->p != ':') {
                free(key);
                goto bad;
            }
            s->p++;
        }
        struct jnode *v = parse_value(s);
        if (!v) {
            free(key);
            goto bad;
        }
        v->key = key;
        *tail = v;
        tail = &v->next;
        ws(s);
        if (s->p >= s->end)
            goto bad;
        if (*s->p == ',') {
            s->p++;
            continue;
        }
        if (*s->p == close) {
            s->p++;
            s->depth--;
            return n;
        }
        goto bad;
    }
bad:
    json_free(n);
    return NULL;
}

static struct jnode *parse_value(struct ps *s) {
    ws(s);
    if (s->p >= s->end)
        return NULL;
    char c = *s->p;
    if (c == '{')
        return parse_container(s, J_OBJ);
    if (c == '[')
        return parse_container(s, J_ARR);
    if (c == '"') {
        char *str = parse_string(s);
        if (!str)
            return NULL;
        struct jnode *n = node(J_STR);
        if (!n) {
            free(str);
            return NULL;
        }
        n->str = str;
        return n;
    }
    size_t left = (size_t)(s->end - s->p);
    if (left >= 4 && strncmp(s->p, "true", 4) == 0) {
        s->p += 4;
        struct jnode *n = node(J_BOOL);
        if (n)
            n->b = 1;
        return n;
    }
    if (left >= 5 && strncmp(s->p, "false", 5) == 0) {
        s->p += 5;
        return node(J_BOOL);
    }
    if (left >= 4 && strncmp(s->p, "null", 4) == 0) {
        s->p += 4;
        return node(J_NULL);
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
        char buf[64];
        size_t n = 0;
        while (s->p < s->end && n < sizeof buf - 1 &&
               (strchr("+-.eE", *s->p) || (*s->p >= '0' && *s->p <= '9')))
            buf[n++] = *s->p++;
        buf[n] = 0;
        struct jnode *v = node(J_NUM);
        if (!v)
            return NULL;
        char *e;
        v->d = strtod(buf, &e);
        if (*e) {
            free(v);
            return NULL;
        }
        if (buf[0] != '-' && strspn(buf, "0123456789") == n) {
            v->is_int = 1;
            v->u = strtoull(buf, NULL, 10);
        }
        return v;
    }
    return NULL;
}

struct jnode *json_parse(const char *str, size_t n) {
    struct ps s = {str, str + n, 0};
    struct jnode *v = parse_value(&s);
    if (!v)
        return NULL;
    ws(&s);
    if (s.p != s.end) {
        json_free(v);
        return NULL;
    }
    return v;
}

const struct jnode *json_get(const struct jnode *obj, const char *key) {
    if (!obj || obj->type != J_OBJ)
        return NULL;
    for (const struct jnode *c = obj->child; c; c = c->next)
        if (c->key && strcmp(c->key, key) == 0)
            return c;
    return NULL;
}
