/*****************************************************************************
 *   HardMail — email clear-signing app (based on Ledger App Boilerplate).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *****************************************************************************/

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // memset, explicit_bzero

#include "os.h"
#include "cx.h"
#include "buffer.h"

#include "sign_tx.h"
#include "sw.h"
#include "globals.h"
#include "display.h"
#include "tx_types.h"
#include "deserialize.h"
#include "validate.h"

// Streaming clear-signing.
//
// The device never holds the whole message. It buffers only the small header,
// then takes the body chunk by chunk: each chunk is hashed, DISPLAYED, and its
// APDU is answered only once the human has swiped past that page. The host
// therefore cannot outrun the review, and every byte under the final signature
// has been on screen.

static int fail(uint16_t sw) {
    G_context.state = STATE_NONE;
    return io_send_sw(sw);
}

static int init_transaction_context(buffer_t *cdata, uint8_t req_type) {
    explicit_bzero(&G_context, sizeof(G_context));
    G_context.req_type = req_type;
    G_context.state = STATE_NONE;

    if (!buffer_read_u8(cdata, &G_context.bip32_path_len) ||
        !buffer_read_bip32_path(cdata, G_context.bip32_path, (size_t) G_context.bip32_path_len)) {
        return io_send_sw(SWO_WRONG_DATA_LENGTH);
    }
    if (cx_sha256_init_no_throw(&G_context.tx_info.hash_ctx) != CX_OK) {
        return io_send_sw(SWO_INCORRECT_DATA);
    }
    return io_send_sw(SWO_SUCCESS);
}

// Parse and display the header once it has fully arrived.
static int start_review(void) {
    buffer_t buf = {.ptr = G_context.tx_info.header,
                    .size = G_context.tx_info.header_len,
                    .offset = 0};
    if (transaction_deserialize(&buf, &G_context.tx_info.transaction, false) != PARSING_OK) {
        return fail(SWO_INCORRECT_DATA);
    }
    G_context.tx_info.header_done = true;
    G_context.state = STATE_PARSED;
    // Deferred reply: the page callback answers this APDU once the human has
    // seen the header.
    return ui_stream_header();
}

// Consume one APDU worth of payload.
static int consume(buffer_t *cdata, bool more) {
    transaction_ctx_t *tx = &G_context.tx_info;

    // Everything that arrives goes into the digest, framing included, so host
    // and device agree byte for byte on what is being signed.
    if (cx_hash_no_throw((cx_hash_t *) &tx->hash_ctx,
                         0,
                         cdata->ptr + cdata->offset,
                         cdata->size - cdata->offset,
                         NULL,
                         0) != CX_OK) {
        return fail(SWO_INCORRECT_DATA);
    }

    // 1. The 2-byte frame telling us how long the header is.
    if (!tx->frame_len_known) {
        uint16_t len;
        if (!buffer_read_u16(cdata, &len, BE)) {
            return fail(SWO_WRONG_DATA_LENGTH);
        }
        if (len == 0 || len > MAX_HEADER_LEN) {
            return fail(SWO_INCORRECT_DATA);
        }
        tx->header_len = len;
        tx->frame_len_known = true;
    }

    // 2. Buffer the header until it is complete, then review it.
    if (!tx->header_done) {
        size_t want = tx->header_len - tx->header_seen;
        size_t avail = cdata->size - cdata->offset;
        size_t take = (avail < want) ? avail : want;
        memmove(tx->header + tx->header_seen, cdata->ptr + cdata->offset, take);
        tx->header_seen += take;
        cdata->offset += take;

        if (tx->header_seen < tx->header_len) {
            if (!more) {
                return fail(SWO_WRONG_DATA_LENGTH);  // truncated header
            }
            return io_send_sw(SWO_SUCCESS);  // still collecting, nothing to show yet
        }
        if (cdata->offset != cdata->size) {
            // Keep the framing simple and unambiguous: a chunk ends with the
            // header, body slices start on the next one.
            return fail(SWO_INCORRECT_DATA);
        }
        return start_review();
    }

    // 3. Body: hash it (done above), show it, and answer only after the human
    //    has read this page.
    size_t avail = cdata->size - cdata->offset;
    if (avail == 0 || avail > MAX_PAGE_LEN) {
        return fail(SWO_INCORRECT_DATA);
    }
    if (tx->body_seen + avail > tx->transaction.body_len) {
        return fail(SWO_INCORRECT_DATA);  // more body than was declared
    }
    if (!text_is_displayable(cdata->ptr + cdata->offset, avail, true)) {
        return fail(SWO_INCORRECT_DATA);
    }

    memmove(tx->page, cdata->ptr + cdata->offset, avail);
    tx->page[avail] = '\0';
    tx->body_seen += avail;

    if (!more) {
        if (tx->body_seen != tx->transaction.body_len) {
            return fail(SWO_INCORRECT_DATA);  // short of what was declared
        }
        // Last slice: once the human has read it, the UI moves straight on to
        // the signing page — which is what finally answers this APDU.
        return ui_stream_body_page((const char *) tx->page, true);
    }
    return ui_stream_body_page((const char *) tx->page, false);
}

int handler_sign_tx(buffer_t *cdata, uint8_t chunk, bool more, bool is_token_tx) {
    (void) is_token_tx;  // HardMail has no token flow
    if (chunk == 0) {
        return init_transaction_context(cdata, CONFIRM_TRANSACTION);
    }
    if (G_context.req_type != CONFIRM_TRANSACTION) {
        return fail(SWO_CONDITIONS_NOT_SATISFIED);
    }
    return consume(cdata, more);
}
