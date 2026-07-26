#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

// HardMail email-approval payload, v2.
//
// The device clear-signs an email: it renders From / To / Subject AND the full
// message body on the trusted screen, so the human physically confirms exactly
// what is being sent — no hash to take on faith. A relay-issued challenge is
// part of the signed payload, binding the approval to one short-lived request
// (so a withheld or stale approval cannot be used later).
//
// Wire format:
//   challenge     | CHALLENGE_LEN bytes (relay-issued, single-use)
//   from_len:u8   | from bytes
//   to_len:u8     | to bytes
//   subject_len:u8| subject bytes
//   body_len:u16be| body bytes  (rendered in full; too long => REFUSED)
//   att_count:u8  | 0 or 1
//     [ name_len:u8 | name | size:u32be | sha256(32) ]   (if att_count == 1)
//
// An attachment cannot be *read* on a device screen — no hardware wallet can
// render a PDF. What the device can do is bind it: the human sees the file NAME
// and SIZE and a short hash, and the signature covers the file's sha256, so the
// exact bytes are pinned. The decision the human makes is "am I sending this
// file?", and nothing can swap the contents afterwards.
#define MAX_TX_LEN      2600
#define ADDRESS_LEN     20  // public-key-derived address length (address.c)
#define CHALLENGE_LEN   16
#define MAX_FROM_LEN    128
#define MAX_TO_LEN      128
#define MAX_SUBJECT_LEN 200
#define MAX_BODY_LEN    2048
#define MAX_ATT_NAME_LEN 64
#define ATT_HASH_LEN    32
#define MAX_MEMO_LEN    465  // legacy helper bound (transaction_utils_format_memo)

typedef enum {
    PARSING_OK = 1,
    FROM_PARSING_ERROR = -1,
    TO_PARSING_ERROR = -2,
    SUBJECT_PARSING_ERROR = -3,
    BODY_PARSING_ERROR = -4,
    FIELD_ENCODING_ERROR = -5,
    CHALLENGE_PARSING_ERROR = -6,
    WRONG_LENGTH_ERROR = -7,
    ATTACHMENT_PARSING_ERROR = -8
} parser_status_e;

// Pointers reference into the raw payload buffer (not copied here).
typedef struct {
    uint8_t *challenge;  /// relay-issued request id, CHALLENGE_LEN bytes
    uint8_t *from;       /// sender identity (printable ASCII)
    uint8_t from_len;
    uint8_t *to;         /// recipient (printable ASCII)
    uint8_t to_len;
    uint8_t *subject;    /// subject (printable ASCII)
    uint8_t subject_len;
    uint8_t *body;       /// message body (printable ASCII + newlines)
    uint16_t body_len;
    uint8_t has_attachment;
    uint8_t *att_name;   /// attachment file name (printable ASCII)
    uint8_t att_name_len;
    uint32_t att_size;   /// attachment size in bytes
    uint8_t *att_hash;   /// sha256 of the attachment bytes, ATT_HASH_LEN
} email_t;

// Kept as an alias so the shared boilerplate context/type names still resolve.
typedef email_t transaction_t;
