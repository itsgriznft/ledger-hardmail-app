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

// The review is STREAMED: the header is shown first, then each slice of the
// body as it arrives, and only at the end the sign page. The APDU that carried
// a slice is answered from the page callback — so the host cannot run ahead of
// what the human has actually seen.

// Null-terminated copies for display (NBGL renders C strings). Static, not stack.
static char g_from[MAX_FROM_LEN + 1];
static char g_to[MAX_TO_LEN + 1];
static char g_subject[MAX_SUBJECT_LEN + 1];
static char g_request[2 * CHALLENGE_LEN + 1];
static char g_attachment[MAX_ATT_NAME_LEN + 40];  // "name (12345 bytes)"
static char g_att_hash[2 * ATT_HASH_LEN + 1];

// From / To / Subject / [Attachment / Attachment SHA-256 /] Request ID
static nbgl_contentTagValue_t header_pairs[6];
static nbgl_contentTagValueList_t header_list;
// One body slice per page.
static nbgl_contentTagValue_t body_pair[1];
static nbgl_contentTagValueList_t body_list;

static void copy_field(char *dst, size_t dst_sz, const uint8_t *src, size_t len) {
    explicit_bzero(dst, dst_sz);
    size_t n = (len < dst_sz - 1) ? len : dst_sz - 1;
    memmove(dst, src, n);
    dst[n] = '\0';
}

// The user swiped past a page (confirm) or rejected. On confirm we release the
// APDU so the host may send the next slice; on rejection the whole review dies.
static void page_choice(bool confirm) {
    if (confirm) {
        io_send_sw(SWO_SUCCESS);
    } else {
        G_context.state = STATE_NONE;
        validate_transaction(false);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
    }
}

// Final hold-to-sign.
static void review_choice(bool confirm) {
    validate_transaction(confirm);
    if (confirm) {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
    } else {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
    }
}

// Start the review and show who the mail is from, to whom, and about what.
int ui_stream_header(void) {
    if (G_context.req_type != CONFIRM_TRANSACTION || G_context.state != STATE_PARSED) {
        G_context.state = STATE_NONE;
        return io_send_sw(SWO_CONDITIONS_NOT_SATISFIED);
    }

    const transaction_t *email = &G_context.tx_info.transaction;

    copy_field(g_from, sizeof(g_from), email->from, email->from_len);
    copy_field(g_to, sizeof(g_to), email->to, email->to_len);
    copy_field(g_subject, sizeof(g_subject), email->subject, email->subject_len);
    if (format_hex(email->challenge, CHALLENGE_LEN, g_request, sizeof(g_request)) == -1) {
        return io_send_sw(SWO_INCORRECT_DATA);
    }

    int n = 0;
    header_pairs[n].item = "From";
    header_pairs[n++].value = g_from;
    header_pairs[n].item = "To";
    header_pairs[n++].value = g_to;
    header_pairs[n].item = "Subject";
    header_pairs[n++].value = g_subject;

    // An attachment cannot be read on this screen, but the human decides on its
    // name and size, and the signature pins its exact content hash.
    if (email->has_attachment) {
        char name[MAX_ATT_NAME_LEN + 1];
        copy_field(name, sizeof(name), email->att_name, email->att_name_len);
        snprintf(g_attachment,
                 sizeof(g_attachment),
                 "%s (%u bytes)",
                 name,
                 (unsigned) email->att_size);
        if (format_hex(email->att_hash, ATT_HASH_LEN, g_att_hash, sizeof(g_att_hash)) == -1) {
            return io_send_sw(SWO_INCORRECT_DATA);
        }
        header_pairs[n].item = "Attachment";
        header_pairs[n++].value = g_attachment;
        header_pairs[n].item = "Attachment SHA-256";
        header_pairs[n++].value = g_att_hash;
    }

    header_pairs[n].item = "Request ID";
    header_pairs[n++].value = g_request;

    header_list.nbMaxLinesForValue = 0;  // no truncation: show the whole value
    header_list.nbPairs = n;
    header_list.pairs = header_pairs;
    header_list.wrapping = true;

    nbgl_useCaseReviewStreamingStart(TYPE_TRANSACTION,
                                     &ICON_APP_BOILERPLATE,
                                     "Review email\nto send",
                                     NULL,
                                     page_choice);
    nbgl_useCaseReviewStreamingContinue(&header_list, page_choice);
    return 0;
}

// Show one slice of the message. `text` is the null-terminated slice held in
// the context, so it stays valid while NBGL renders the page.
int ui_stream_body_page(const char *text) {
    body_pair[0].item = "Message";
    body_pair[0].value = text;

    body_list.nbMaxLinesForValue = 0;
    body_list.nbPairs = 1;
    body_list.pairs = body_pair;
    body_list.wrapping = true;

    nbgl_useCaseReviewStreamingContinue(&body_list, page_choice);
    return 0;
}

// The whole message has been shown — ask for the signature.
int ui_stream_finish(void) {
    nbgl_useCaseReviewStreamingFinish("Sign to send\nthis email?", review_choice);
    return 0;
}
