#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

// HardMail email-approval payload, streamed.
//
// The device never buffers the whole message. It reads a small HEADER (who the
// mail is from, who it goes to, the subject, an optional attachment descriptor
// and the body length), displays it, and then takes the BODY chunk by chunk —
// hashing and DISPLAYING each slice as it arrives. So the message can be any
// length, RAM use stays constant, and every byte that ends up under the
// signature has been shown to the human first.
//
// Wire format (after the BIP32 path APDU), split across 255-byte chunks:
//
//   header_len:u16be
//   header  = challenge(16)
//           | from_len:u8    | from
//           | to_len:u8      | to
//           | subject_len:u8 | subject
//           | att_count:u8   [ name_len:u8 | name | size:u32be | sha256(32) ]
//           | body_len:u32be
//   body    = body_len bytes  (printable ASCII, newlines allowed)
//
// The signature covers sha256 of everything above, framing included.
#define CHALLENGE_LEN    16
#define ADDRESS_LEN      20  // public-key-derived address length (address.c)
#define MAX_FROM_LEN     128
#define MAX_TO_LEN       128
#define MAX_SUBJECT_LEN  200
#define MAX_ATT_NAME_LEN 64
#define ATT_HASH_LEN     32
#define MAX_MEMO_LEN     465  // legacy helper bound (transaction_utils_format_memo)

// Bound on the buffered header: challenge + three text fields + attachment
// descriptor + body length, with room to spare.
#define MAX_HEADER_LEN 640
// One APDU's worth of body is shown per page.
#define MAX_PAGE_LEN 255
// Sanity bound on a message — not a display limit, just a refusal to sit in a
// review loop forever. Roughly 256 KB of text.
#define MAX_BODY_LEN 262144

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

// Header fields. Pointers reference into the buffered header (not copied).
typedef struct {
    uint8_t *challenge;  /// verifier-issued request id, CHALLENGE_LEN bytes
    uint8_t *from;       /// sender identity (printable ASCII)
    uint8_t from_len;
    uint8_t *to;         /// recipient (printable ASCII)
    uint8_t to_len;
    uint8_t *subject;    /// subject (printable ASCII)
    uint8_t subject_len;
    uint32_t body_len;   /// total body length, streamed separately
    uint8_t has_attachment;
    uint8_t *att_name;   /// attachment file name (printable ASCII)
    uint8_t att_name_len;
    uint32_t att_size;   /// attachment size in bytes
    uint8_t *att_hash;   /// sha256 of the attachment bytes, ATT_HASH_LEN
} email_t;

// Kept as an alias so the shared boilerplate context/type names still resolve.
typedef email_t transaction_t;

// True iff every byte is printable ASCII (newlines optionally allowed, for the
// body). Anything else is refused — that is also what makes header injection
// impossible.
bool text_is_displayable(const uint8_t *p, size_t len, bool allow_newline);
