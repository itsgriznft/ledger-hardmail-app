/*****************************************************************************
 *   HardMail — email clear-signing app (based on Ledger App Boilerplate).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *****************************************************************************/

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // memmove

#include "serialize.h"
#include "types.h"

#if defined(TEST) || defined(FUZZ)
#include "assert.h"
#define LEDGER_ASSERT(x, y) assert(x)
#else
#include "ledger_assert.h"
#endif

// Serialize the email wire format (mirror of transaction_deserialize). Used by
// the test/fuzz harnesses to build payloads.
int transaction_serialize(const transaction_t *tx, uint8_t *out, size_t out_len) {
    size_t offset = 0;

    LEDGER_ASSERT(tx != NULL, "NULL tx");
    LEDGER_ASSERT(out != NULL, "NULL out");

    size_t need = 1 + tx->from_len + 1 + tx->to_len + 1 + tx->subject_len + BODY_HASH_LEN;
    if (need > out_len) {
        return -1;
    }

    out[offset++] = tx->from_len;
    memmove(out + offset, tx->from, tx->from_len);
    offset += tx->from_len;

    out[offset++] = tx->to_len;
    memmove(out + offset, tx->to, tx->to_len);
    offset += tx->to_len;

    out[offset++] = tx->subject_len;
    memmove(out + offset, tx->subject, tx->subject_len);
    offset += tx->subject_len;

    memmove(out + offset, tx->body_hash, BODY_HASH_LEN);
    offset += BODY_HASH_LEN;

    return (int) offset;
}
