/*****************************************************************************
 *   HardMail — email clear-signing app (based on Ledger App Boilerplate).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *****************************************************************************/
#include "buffer.h"

#include "deserialize.h"
#include "utils.h"
#include "types.h"

#if defined(TEST) || defined(FUZZ)
#include "assert.h"
#define LEDGER_ASSERT(x, y) assert(x)
#else
#include "ledger_assert.h"
#endif

// Printable ASCII only (optionally allowing newlines, for the body). No control
// characters means the value is safe to render as a C string and cannot smuggle
// mail headers. Anything else fails closed.
static bool text_ok(const uint8_t *p, size_t len, bool allow_newline) {
    for (size_t i = 0; i < len; i++) {
        uint8_t c = p[i];
        if (allow_newline && c == '\n') {
            continue;
        }
        if (c < 0x20 || c > 0x7e) {
            return false;
        }
    }
    return true;
}

// Read a u8-length-prefixed text field.
static bool read_text_field(buffer_t *buf, uint8_t **field, uint8_t *field_len, uint8_t max_len) {
    uint8_t len;
    if (!buffer_read_u8(buf, &len)) {
        return false;
    }
    if (len == 0 || len > max_len) {
        return false;
    }
    *field = (uint8_t *) (buf->ptr + buf->offset);
    if (!buffer_seek_cur(buf, len)) {
        return false;
    }
    if (!text_ok(*field, len, false)) {
        return false;
    }
    *field_len = len;
    return true;
}

parser_status_e transaction_deserialize(buffer_t *buf,
                                        transaction_t *tx,
                                        bool is_token_transaction) {
    (void) is_token_transaction;  // HardMail has no token flow
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(tx != NULL, "NULL tx");

    if (buf->size > MAX_TX_LEN) {
        PRINTF("WRONG_LENGTH_ERROR\n");
        return WRONG_LENGTH_ERROR;
    }

    // Relay-issued challenge — binds this approval to one short-lived request.
    tx->challenge = (uint8_t *) (buf->ptr + buf->offset);
    if (!buffer_seek_cur(buf, CHALLENGE_LEN)) {
        PRINTF("CHALLENGE_PARSING_ERROR\n");
        return CHALLENGE_PARSING_ERROR;
    }

    if (!read_text_field(buf, &tx->from, &tx->from_len, MAX_FROM_LEN)) {
        PRINTF("FROM_PARSING_ERROR\n");
        return FROM_PARSING_ERROR;
    }
    if (!read_text_field(buf, &tx->to, &tx->to_len, MAX_TO_LEN)) {
        PRINTF("TO_PARSING_ERROR\n");
        return TO_PARSING_ERROR;
    }
    if (!read_text_field(buf, &tx->subject, &tx->subject_len, MAX_SUBJECT_LEN)) {
        PRINTF("SUBJECT_PARSING_ERROR\n");
        return SUBJECT_PARSING_ERROR;
    }

    // Body: u16 length, rendered IN FULL on the device. A body too long to show
    // is refused rather than truncated — the human must see everything that is
    // signed, so we fail closed instead of silently hiding text.
    uint16_t body_len;
    if (!buffer_read_u16(buf, &body_len, BE)) {
        PRINTF("BODY_PARSING_ERROR (len)\n");
        return BODY_PARSING_ERROR;
    }
    if (body_len == 0 || body_len > MAX_BODY_LEN) {
        PRINTF("BODY_PARSING_ERROR (bounds)\n");
        return BODY_PARSING_ERROR;
    }
    tx->body = (uint8_t *) (buf->ptr + buf->offset);
    if (!buffer_seek_cur(buf, body_len)) {
        PRINTF("BODY_PARSING_ERROR (seek)\n");
        return BODY_PARSING_ERROR;
    }
    if (!text_ok(tx->body, body_len, true)) {
        PRINTF("FIELD_ENCODING_ERROR (body)\n");
        return FIELD_ENCODING_ERROR;
    }
    tx->body_len = body_len;

    // Exact-fit: no trailing bytes allowed.
    return (buf->offset == buf->size) ? PARSING_OK : WRONG_LENGTH_ERROR;
}
