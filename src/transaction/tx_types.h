#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

// HardMail email-approval payload. The device clear-signs an email: it shows the
// From / To / Subject on the trusted screen and commits to the body via a hash,
// so a human physically confirms exactly what is being sent — not a blind hash.
//
// Wire format (after the BIP32 path chunk), all lengths are single bytes:
//   from_len:u8  | from bytes
//   to_len:u8    | to bytes
//   subject_len:u8 | subject bytes
//   body_hash    | 32 bytes (sha256 of the email body)
#define MAX_TX_LEN       510
#define ADDRESS_LEN      20  // public-key-derived address length (get_public_key/address.c)
#define MAX_FROM_LEN     128
#define MAX_TO_LEN       128
#define MAX_SUBJECT_LEN  200
#define BODY_HASH_LEN    32
#define MAX_MEMO_LEN     465  // legacy helper bound (transaction_utils_format_memo)

typedef enum {
    PARSING_OK = 1,
    FROM_PARSING_ERROR = -1,
    TO_PARSING_ERROR = -2,
    SUBJECT_PARSING_ERROR = -3,
    BODY_HASH_PARSING_ERROR = -4,
    FIELD_ENCODING_ERROR = -5,
    WRONG_LENGTH_ERROR = -7
} parser_status_e;

// Pointers reference into the raw payload buffer (not copied here).
typedef struct {
    uint8_t *from;       /// sender identity (printable ASCII)
    uint8_t from_len;
    uint8_t *to;         /// recipient (printable ASCII)
    uint8_t to_len;
    uint8_t *subject;    /// subject (printable ASCII)
    uint8_t subject_len;
    uint8_t *body_hash;  /// sha256(body), BODY_HASH_LEN bytes
} email_t;

// Kept as an alias so the shared boilerplate context/type names still resolve.
typedef email_t transaction_t;
