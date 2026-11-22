#ifndef MINIVR_JSON_IN_H
#define MINIVR_JSON_IN_H
#include <stdint.h>
#include <stddef.h>

enum jtype { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ };

/* Small DOM for the fixed response shapes. Children of arrays/objects are a linked list. */
struct jnode {
    enum jtype type;
    char *key;           /* member name when parent is an object */
    char *str;           /* J_STR */
    uint64_t u;          /* J_NUM when is_int (non-negative integer) */
    double d;            /* J_NUM */
    int is_int;
    int b;               /* J_BOOL */
    struct jnode *child; /* first child */
    struct jnode *next;  /* next sibling */
};

struct jnode *json_parse(const char *s, size_t n); /* NULL on syntax error */
void json_free(struct jnode *n);
const struct jnode *json_get(const struct jnode *obj, const char *key); /* NULL if absent */
#endif
