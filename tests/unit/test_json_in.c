#include <stdlib.h>
#include <string.h>

#include "minivr/json_in.h"
#include "tharness.h"

static struct jnode *parse(const char *s) {
    return json_parse(s, strlen(s));
}

TEST(parses_the_shapes_the_daemon_sends) {
    const char *doc = "{\"ok\":true,\"data\":{\"total\":3,\"offset\":0,\"next_offset\":null,"
                      "\"routes\":[{\"prefix\":\"10.0.1.0/24\",\"port\":null,\"origin\":\"connected\"},"
                      "{\"prefix\":\"10.0.9.0/24\",\"port\":\"p3\",\"gateway\":\"10.0.2.13\"}],"
                      "\"big\":18446744073709551615,\"neg\":-5,\"frac\":1.5e2}}";
    struct jnode *r = parse(doc);
    CHECK(r != NULL);
    if (!r)
        return;
    CHECK(json_get(r, "ok")->type == J_BOOL && json_get(r, "ok")->b == 1);
    const struct jnode *d = json_get(r, "data");
    CHECK_EQ_U64(json_get(d, "total")->u, 3);
    CHECK(json_get(d, "next_offset")->type == J_NULL);
    CHECK_EQ_U64(json_get(d, "big")->u, 18446744073709551615ULL);
    CHECK(json_get(d, "neg")->type == J_NUM && !json_get(d, "neg")->is_int);
    CHECK(json_get(d, "frac")->d == 150.0);
    const struct jnode *routes = json_get(d, "routes");
    CHECK(routes->type == J_ARR);
    CHECK_STR_EQ(json_get(routes->child, "prefix")->str, "10.0.1.0/24");
    CHECK_STR_EQ(json_get(routes->child->next, "gateway")->str, "10.0.2.13");
    CHECK(routes->child->next->next == NULL);
    CHECK(json_get(d, "missing") == NULL);
    CHECK(json_get(routes, "x") == NULL); /* not an object */
    CHECK(json_get(NULL, "x") == NULL);
    json_free(r);
}

TEST(string_escapes) {
    struct jnode *r = parse("[\"a\\\"b\\\\c\\n\\t\\/\",\"\\u0041\\u00e9\\u20ac\"]");
    CHECK(r != NULL);
    if (!r)
        return;
    CHECK_STR_EQ(r->child->str, "a\"b\\c\n\t/");
    CHECK_STR_EQ(r->child->next->str, "A\xc3\xa9\xe2\x82\xac"); /* A, e-acute, euro sign */
    json_free(r);
}

TEST(whitespace_and_scalars) {
    struct jnode *r = parse(" \n\t{ \"a\" : [ ] , \"b\" : { } , \"c\" : false } \r\n");
    CHECK(r != NULL);
    if (!r)
        return;
    CHECK(json_get(r, "a")->type == J_ARR && json_get(r, "a")->child == NULL);
    CHECK(json_get(r, "b")->type == J_OBJ);
    CHECK(json_get(r, "c")->b == 0);
    json_free(r);
    const char *scalars[] = {"true", "null", "\"s\"", "0", "[]"};
    for (size_t i = 0; i < sizeof scalars / sizeof *scalars; i++) {
        struct jnode *v = parse(scalars[i]);
        CHECK(v != NULL);
        json_free(v);
    }
}

TEST(malformed_documents_are_rejected) {
    const char *bad[] = {
        "",           " ",          "{",          "}",          "[",          "]",
        "{\"a\"}",    "{\"a\":}",   "{\"a\":1,}", "{,}",        "{\"a\":1 \"b\":2}",
        "{a:1}",      "[1,]",       "[,1]",       "[1 2]",      "[1,,2]",     "\"abc",
        "\"a\\q\"",   "\"\\u12\"",  "\"\\u12g4\"","\"\\",       "\"tab\there\"",
        "tru",        "nul",        "fals",       "truee",      "-",          "+1",
        "1.2.3",      "--1",        "1e",         "[1]x",       "{} {}",      "{\"a\":1}}",
        "'single'",   "{\"a\":\"b\"",             "[[[]]",      "\x01",
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        struct jnode *r = parse(bad[i]);
        if (r) {
            TH_FAIL("accepted malformed document #%zu: %s", i, bad[i]);
            json_free(r);
        }
    }
}

TEST(every_truncation_of_a_valid_document_is_rejected_without_overreads) {
    const char *doc = "{\"ok\":true,\"data\":{\"routes\":[{\"p\":\"10.0.1.0/24\",\"n\":null,"
                      "\"u\":\"\\u00e9\\n\"}],\"total\":12}}";
    size_t n = strlen(doc);
    for (size_t len = 0; len < n; len++) {
        char *copy = malloc(len ? len : 1); /* exact size: ASan flags any read past the end */
        memcpy(copy, doc, len);
        struct jnode *r = json_parse(copy, len);
        if (r) {
            TH_FAIL("prefix of %zu bytes was accepted", len);
            json_free(r);
        }
        free(copy);
    }
    struct jnode *whole = json_parse(doc, n);
    CHECK(whole != NULL);
    json_free(whole);
}

TEST(nesting_depth_is_limited) {
    char deep[200];
    memset(deep, '[', 100);
    memset(deep + 100, ']', 100);
    CHECK(json_parse(deep, 200) == NULL); /* deeper than the parser allows */
    memset(deep, 0, sizeof deep);
    memset(deep, '[', 30);
    memset(deep + 30, ']', 30);
    struct jnode *ok = json_parse(deep, 60);
    CHECK(ok != NULL);
    json_free(ok);
}

TEST(long_input_does_not_overflow) {
    size_t n = 200000;
    char *big = malloc(n + 3);
    big[0] = '"';
    memset(big + 1, 'x', n);
    big[n + 1] = '"';
    struct jnode *r = json_parse(big, n + 2);
    CHECK(r != NULL && strlen(r->str) == n);
    json_free(r);
    free(big);
}
