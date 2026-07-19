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

// Read a length-prefixed, printable-ASCII field (no control chars → no header
// injection, and it is safe to render as a C string). Fails closed on anything
// malformed — security strictly overrides availability.
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
    for (uint8_t i = 0; i < len; i++) {
        uint8_t c = (*field)[i];
        if (c < 0x20 || c > 0x7e) {
            return false;  // not printable ASCII
        }
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

    tx->body_hash = (uint8_t *) (buf->ptr + buf->offset);
    if (!buffer_seek_cur(buf, BODY_HASH_LEN)) {
        PRINTF("BODY_HASH_PARSING_ERROR\n");
        return BODY_HASH_PARSING_ERROR;
    }

    // Exact-fit: no trailing bytes allowed.
    return (buf->offset == buf->size) ? PARSING_OK : WRONG_LENGTH_ERROR;
}
