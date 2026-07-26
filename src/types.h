#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

#include "bip32.h"
#include "cx.h"  // cx_sha256_t — the streaming digest

#include "constants.h"
#include "tx_types.h"

/**
 * Enumeration with expected INS of APDU commands.
 */
typedef enum {
    GET_VERSION = 0x03,        /// version of the application
    GET_APP_NAME = 0x04,       /// name of the application
    GET_PUBLIC_KEY = 0x05,     /// public key of corresponding BIP32 path
    SIGN_TX = 0x06,            /// sign transaction with BIP32 path
    SIGN_TOKEN_TX = 0x07,      /// sign token transaction with BIP32 path and token address
    PROVIDE_TOKEN_INFO = 0x22  /// provide dynamic token info via CAL TLV descriptor
} command_e;
/**
 * Enumeration with parsing state.
 */
typedef enum {
    STATE_NONE,     /// No state
    STATE_PARSED,   /// Transaction data parsed
    STATE_APPROVED  /// Transaction data approved
} state_e;

/**
 * Enumeration with user request type.
 */
typedef enum {
    CONFIRM_ADDRESS,           /// confirm address derived from public key
    CONFIRM_TRANSACTION,       /// confirm transaction information
    CONFIRM_TOKEN_TRANSACTION  /// confirm token transaction information
} request_type_e;

/**
 * Structure for public key context information.
 */
typedef struct {
    uint8_t raw_public_key[65];  /// format (1), x-coordinate (32), y-coodinate (32)
    uint8_t chain_code[32];      /// for public key derivation
} pubkey_ctx_t;

#define TOKEN_ADDRESS_LEN 32

/**
 * Structure for token information.
 */
typedef struct {
    const char *ticker;  /// token ticker
    uint8_t decimals;    /// number of decimals
} token_info_t;

/**
 * Structure for transaction information context.
 */
typedef struct {
    // The message is STREAMED: only the header is buffered, while the body is
    // hashed and displayed chunk by chunk as it arrives. That keeps RAM use
    // constant no matter how long the email is — and, crucially, means every
    // byte that is hashed has just been shown to the human.
    uint8_t header[MAX_HEADER_LEN];  /// buffered header (small, bounded)
    uint16_t header_len;             /// expected header length (from the frame)
    uint16_t header_seen;            /// header bytes received so far
    uint32_t body_seen;              /// body bytes received so far
    bool frame_len_known;            /// have we read the 2-byte header length?
    bool header_done;                /// header parsed and displayed?
    cx_sha256_t hash_ctx;            /// running digest over the whole payload

    uint8_t page[MAX_PAGE_LEN + 1];  /// current body slice, null-terminated for display
    transaction_t transaction;       /// parsed header fields

    // Token related
    bool is_token_tx;         /// flag to indicate if this is a token transaction
    token_info_t token_info;  /// token information retrieved using the token address

    // Signature related
    uint8_t m_hash[32];                  /// message hash digest
    uint8_t signature[MAX_DER_SIG_LEN];  /// transaction signature encoded in DER
    uint8_t signature_len;               /// length of transaction signature
    uint8_t v;                           /// parity of y-coordinate of R in ECDSA signature
} transaction_ctx_t;

/**
 * Structure for global context.
 */
typedef struct {
    state_e state;  /// state of the context
    union {
        pubkey_ctx_t pk_info;       /// public key context
        transaction_ctx_t tx_info;  /// transaction context
    };
    request_type_e req_type;              /// user request
    uint32_t bip32_path[MAX_BIP32_PATH];  /// BIP32 path
    uint8_t bip32_path_len;               /// length of BIP32 path
} global_ctx_t;
