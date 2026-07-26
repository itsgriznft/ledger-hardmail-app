/*****************************************************************************
 *   HardMail — email clear-signing app (based on Ledger App Boilerplate).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *****************************************************************************/

#include <stdbool.h>  // bool
#include <string.h>   // memset, memmove

#include "os.h"
#include "glyphs.h"
#include "os_io_seproxyhal.h"
#include "nbgl_use_case.h"
#include "io.h"
#include "bip32.h"
#include "format.h"

#include "display.h"
#include "constants.h"
#include "globals.h"
#include "sw.h"
#include "address.h"
#include "validate.h"
#include "tx_types.h"
#include "menu.h"

// Null-terminated copies for display (NBGL renders C strings). Static, not stack.
static char g_from[MAX_FROM_LEN + 1];
static char g_to[MAX_TO_LEN + 1];
static char g_subject[MAX_SUBJECT_LEN + 1];
static char g_body[MAX_BODY_LEN + 1];
static char g_request[2 * CHALLENGE_LEN + 1];
static char g_attachment[MAX_ATT_NAME_LEN + 40];   // "name (12345 bytes)"
static char g_att_hash[2 * ATT_HASH_LEN + 1];

// From / To / Subject / Message / [Attachment / Attachment SHA-256 /] Request ID
static nbgl_contentTagValue_t pairs[7];
static nbgl_contentTagValueList_t pairList;

// Copy a bounded, non-terminated field into a null-terminated display buffer.
static void copy_field(char *dst, size_t dst_sz, const uint8_t *src, size_t len) {
    explicit_bzero(dst, dst_sz);
    size_t n = (len < dst_sz - 1) ? len : dst_sz - 1;
    memmove(dst, src, n);
    dst[n] = '\0';
}

// Called when the review is approved (long-press) or rejected.
static void review_choice(bool confirm) {
    validate_transaction(confirm);
    if (confirm) {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
    } else {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
    }
}

// Build the review of the email and start the clear-sign flow.
int ui_display_transaction(void) {
    if (G_context.req_type != CONFIRM_TRANSACTION || G_context.state != STATE_PARSED) {
        G_context.state = STATE_NONE;
        return io_send_sw(SWO_CONDITIONS_NOT_SATISFIED);
    }

    const transaction_t *email = &G_context.tx_info.transaction;

    copy_field(g_from, sizeof(g_from), email->from, email->from_len);
    copy_field(g_to, sizeof(g_to), email->to, email->to_len);
    copy_field(g_subject, sizeof(g_subject), email->subject, email->subject_len);
    // The body is displayed IN FULL — the parser already refused anything that
    // would not fit, so nothing signed is ever hidden from the human.
    copy_field(g_body, sizeof(g_body), email->body, email->body_len);
    if (format_hex(email->challenge, CHALLENGE_LEN, g_request, sizeof(g_request)) == -1) {
        return io_send_sw(SWO_INCORRECT_DATA);
    }

    int n = 0;
    pairs[n].item = "From";
    pairs[n++].value = g_from;
    pairs[n].item = "To";
    pairs[n++].value = g_to;
    pairs[n].item = "Subject";
    pairs[n++].value = g_subject;
    pairs[n].item = "Message";
    pairs[n++].value = g_body;

    // An attachment cannot be read on this screen, but the human decides on its
    // name and size, and the signature pins its exact content hash.
    if (email->has_attachment) {
        char name[MAX_ATT_NAME_LEN + 1];
        copy_field(name, sizeof(name), email->att_name, email->att_name_len);
        snprintf(g_attachment, sizeof(g_attachment), "%s (%u bytes)", name, (unsigned) email->att_size);
        if (format_hex(email->att_hash, ATT_HASH_LEN, g_att_hash, sizeof(g_att_hash)) == -1) {
            return io_send_sw(SWO_INCORRECT_DATA);
        }
        pairs[n].item = "Attachment";
        pairs[n++].value = g_attachment;
        pairs[n].item = "Attachment SHA-256";
        pairs[n++].value = g_att_hash;
    }

    pairs[n].item = "Request ID";
    pairs[n++].value = g_request;

    pairList.nbMaxLinesForValue = 0;  // no truncation: show the whole value
    pairList.nbPairs = n;
    pairList.pairs = pairs;
    pairList.wrapping = true;

    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &pairList,
                       &ICON_APP_BOILERPLATE,
                       "Review email\nto send",
                       NULL,
                       "Sign to send\nthis email?",
                       review_choice);
    return 0;
}

// HardMail has no blind-sign or token flows; keep the symbols so the shared
// handler links, but they clear-sign the same email (never blind).
int ui_display_blind_signed_transaction(void) {
    return ui_display_transaction();
}

int ui_display_token_transaction(void) {
    return ui_display_transaction();
}
