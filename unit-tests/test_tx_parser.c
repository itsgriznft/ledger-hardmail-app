#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "transaction/serialize.h"
#include "transaction/deserialize.h"
#include "types.h"

// Helpers to build an email payload the way the host does:
//   challenge(16) | from | to | subject | body_len:u16be|body
//                 | att_count:u8 [ name | size:u32be | sha256(32) ]
typedef struct {
    uint8_t buf[MAX_TX_LEN + 64];
    size_t len;
} builder_t;

static void put(builder_t *b, const void *src, size_t n) {
    memcpy(b->buf + b->len, src, n);
    b->len += n;
}
static void put_u8(builder_t *b, uint8_t v) {
    b->buf[b->len++] = v;
}
static void put_text(builder_t *b, const char *s) {
    size_t n = strlen(s);
    put_u8(b, (uint8_t) n);
    put(b, s, n);
}
static void put_body(builder_t *b, const char *s, size_t n) {
    put_u8(b, (uint8_t) (n >> 8));
    put_u8(b, (uint8_t) (n & 0xff));
    put(b, s, n);
}

static const uint8_t CHALLENGE[CHALLENGE_LEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                                 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};
static const uint8_t ATT_HASH[ATT_HASH_LEN] = {
    0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0,    0,    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

// A well-formed message with no attachment.
static void build_valid(builder_t *b) {
    b->len = 0;
    put(b, CHALLENGE, CHALLENGE_LEN);
    put_text(b, "agent@hardmail.local");
    put_text(b, "boss@example.com");
    put_text(b, "Q3 report");
    put_body(b, "Hi,\nnumbers attached.\n", 22);
    put_u8(b, 0);  // no attachment
}

static parser_status_e parse(builder_t *b, transaction_t *tx) {
    buffer_t buf = {.ptr = b->buf, .size = b->len, .offset = 0};
    return transaction_deserialize(&buf, tx, false);
}

// ── happy paths ─────────────────────────────────────────────────────────────

static void test_parse_valid(void **state) {
    (void) state;
    builder_t b;
    transaction_t tx;
    build_valid(&b);

    assert_int_equal(parse(&b, &tx), PARSING_OK);
    assert_memory_equal(tx.challenge, CHALLENGE, CHALLENGE_LEN);
    assert_int_equal(tx.from_len, 20);
    assert_memory_equal(tx.from, "agent@hardmail.local", 20);
    assert_int_equal(tx.to_len, 16);
    assert_memory_equal(tx.to, "boss@example.com", 16);
    assert_int_equal(tx.subject_len, 9);
    assert_memory_equal(tx.subject, "Q3 report", 9);
    assert_int_equal(tx.body_len, 22);
    assert_memory_equal(tx.body, "Hi,\nnumbers attached.\n", 22);
    assert_int_equal(tx.has_attachment, 0);
}

static void test_parse_with_attachment(void **state) {
    (void) state;
    builder_t b;
    transaction_t tx;
    build_valid(&b);
    b.len--;  // drop the "no attachment" marker
    put_u8(&b, 1);
    put_text(&b, "q3-summary.txt");
    put_u8(&b, 0);
    put_u8(&b, 0);
    put_u8(&b, 0x01);
    put_u8(&b, 0x2c);  // size = 300
    put(&b, ATT_HASH, ATT_HASH_LEN);

    assert_int_equal(parse(&b, &tx), PARSING_OK);
    assert_int_equal(tx.has_attachment, 1);
    assert_int_equal(tx.att_name_len, 14);
    assert_memory_equal(tx.att_name, "q3-summary.txt", 14);
    assert_int_equal(tx.att_size, 300);
    assert_memory_equal(tx.att_hash, ATT_HASH, ATT_HASH_LEN);
}

// Serializing a parsed message must reproduce the original bytes exactly —
// otherwise host and device would disagree about what was signed.
static void test_round_trip(void **state) {
    (void) state;
    builder_t b;
    transaction_t tx;
    uint8_t out[MAX_TX_LEN];
    build_valid(&b);
    assert_int_equal(parse(&b, &tx), PARSING_OK);

    int n = transaction_serialize(&tx, out, sizeof(out));
    assert_int_equal(n, (int) b.len);
    assert_memory_equal(out, b.buf, b.len);
}

static void test_body_max_length_accepted(void **state) {
    (void) state;
    builder_t b;
    transaction_t tx;
    char big[MAX_BODY_LEN];
    memset(big, 'a', sizeof(big));

    b.len = 0;
    put(&b, CHALLENGE, CHALLENGE_LEN);
    put_text(&b, "a@b.co");
    put_text(&b, "c@d.co");
    put_text(&b, "s");
    put_body(&b, big, MAX_BODY_LEN);
    put_u8(&b, 0);

    assert_int_equal(parse(&b, &tx), PARSING_OK);
    assert_int_equal(tx.body_len, MAX_BODY_LEN);
}

// ── fail-closed paths ───────────────────────────────────────────────────────
// Security overrides availability: anything malformed must be REFUSED, never
// coerced, truncated or silently accepted.

static void test_reject_empty_from(void **state) {
    (void) state;
    builder_t b;
    transaction_t tx;
    b.len = 0;
    put(&b, CHALLENGE, CHALLENGE_LEN);
    put_u8(&b, 0);  // zero-length from
    assert_int_equal(parse(&b, &tx), FROM_PARSING_ERROR);
}

static void test_reject_control_char_in_subject(void **state) {
    (void) state;
    builder_t b;
    transaction_t tx;
    b.len = 0;
    put(&b, CHALLENGE, CHALLENGE_LEN);
    put_text(&b, "a@b.co");
    put_text(&b, "c@d.co");
    put_text(&b, "bad\nsubject");  // newline is a control char outside the body
    put_body(&b, "x", 1);
    put_u8(&b, 0);
    assert_int_equal(parse(&b, &tx), SUBJECT_PARSING_ERROR);
}

// A CR in the body could confuse downstream mail handling — only \n is allowed.
static void test_reject_cr_in_body(void **state) {
    (void) state;
    builder_t b;
    transaction_t tx;
    b.len = 0;
    put(&b, CHALLENGE, CHALLENGE_LEN);
    put_text(&b, "a@b.co");
    put_text(&b, "c@d.co");
    put_text(&b, "s");
    put_body(&b, "line\r\nline", 10);
    put_u8(&b, 0);
    assert_int_equal(parse(&b, &tx), FIELD_ENCODING_ERROR);
}

static void test_reject_empty_body(void **state) {
    (void) state;
    builder_t b;
    transaction_t tx;
    b.len = 0;
    put(&b, CHALLENGE, CHALLENGE_LEN);
    put_text(&b, "a@b.co");
    put_text(&b, "c@d.co");
    put_text(&b, "s");
    put_body(&b, "", 0);
    put_u8(&b, 0);
    assert_int_equal(parse(&b, &tx), BODY_PARSING_ERROR);
}

// The device must never sign a message longer than it can display.
static void test_reject_oversized_body(void **state) {
    (void) state;
    builder_t b;
    transaction_t tx;
    b.len = 0;
    put(&b, CHALLENGE, CHALLENGE_LEN);
    put_text(&b, "a@b.co");
    put_text(&b, "c@d.co");
    put_text(&b, "s");
    // claim one byte more than the device can render
    put_u8(&b, (uint8_t) ((MAX_BODY_LEN + 1) >> 8));
    put_u8(&b, (uint8_t) ((MAX_BODY_LEN + 1) & 0xff));
    assert_int_equal(parse(&b, &tx), BODY_PARSING_ERROR);
}

static void test_reject_truncated_challenge(void **state) {
    (void) state;
    builder_t b;
    transaction_t tx;
    b.len = 0;
    put(&b, CHALLENGE, CHALLENGE_LEN - 1);  // one byte short
    assert_int_equal(parse(&b, &tx), CHALLENGE_PARSING_ERROR);
}

static void test_reject_trailing_bytes(void **state) {
    (void) state;
    builder_t b;
    transaction_t tx;
    build_valid(&b);
    put_u8(&b, 0x41);  // one byte too many
    assert_int_equal(parse(&b, &tx), WRONG_LENGTH_ERROR);
}

static void test_reject_multiple_attachments(void **state) {
    (void) state;
    builder_t b;
    transaction_t tx;
    build_valid(&b);
    b.len--;
    put_u8(&b, 2);  // more than one attachment
    assert_int_equal(parse(&b, &tx), ATTACHMENT_PARSING_ERROR);
}

static void test_reject_truncated_attachment_hash(void **state) {
    (void) state;
    builder_t b;
    transaction_t tx;
    build_valid(&b);
    b.len--;
    put_u8(&b, 1);
    put_text(&b, "f.txt");
    put_u8(&b, 0);
    put_u8(&b, 0);
    put_u8(&b, 0);
    put_u8(&b, 10);
    put(&b, ATT_HASH, ATT_HASH_LEN - 1);  // hash cut short
    assert_int_equal(parse(&b, &tx), ATTACHMENT_PARSING_ERROR);
}

static void test_reject_payload_over_max(void **state) {
    (void) state;
    builder_t b;
    transaction_t tx;
    build_valid(&b);
    buffer_t buf = {.ptr = b.buf, .size = MAX_TX_LEN + 1, .offset = 0};
    assert_int_equal(transaction_deserialize(&buf, &tx, false), WRONG_LENGTH_ERROR);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_valid),
        cmocka_unit_test(test_parse_with_attachment),
        cmocka_unit_test(test_round_trip),
        cmocka_unit_test(test_body_max_length_accepted),
        cmocka_unit_test(test_reject_empty_from),
        cmocka_unit_test(test_reject_control_char_in_subject),
        cmocka_unit_test(test_reject_cr_in_body),
        cmocka_unit_test(test_reject_empty_body),
        cmocka_unit_test(test_reject_oversized_body),
        cmocka_unit_test(test_reject_truncated_challenge),
        cmocka_unit_test(test_reject_trailing_bytes),
        cmocka_unit_test(test_reject_multiple_attachments),
        cmocka_unit_test(test_reject_truncated_attachment_hash),
        cmocka_unit_test(test_reject_payload_over_max),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
