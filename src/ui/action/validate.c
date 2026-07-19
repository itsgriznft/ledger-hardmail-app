/*****************************************************************************
 *   Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdbool.h>  // bool

#include "crypto_helpers.h"

#include "validate.h"
#include "menu.h"
#include "sw.h"
#include "globals.h"
#include "send_response.h"

void validate_pubkey(bool choice) {
    if (choice) {
        helper_send_response_pubkey();
    } else {
        io_send_sw(SWO_CONDITIONS_NOT_SATISFIED);
    }
}

static int crypto_sign_message(void) {
    size_t sig_len = sizeof(G_context.tx_info.signature);

    // ed25519 (the Stellar curve): sign the sha256(email payload) directly, so
    // the 64-byte signature is verifiable by the relay against the enrolled
    // device public key with a standard ed25519 verify.
    cx_err_t error = bip32_derive_eddsa_sign_hash_256(CX_CURVE_Ed25519,
                                                      G_context.bip32_path,
                                                      G_context.bip32_path_len,
                                                      CX_SHA512,
                                                      G_context.tx_info.m_hash,
                                                      sizeof(G_context.tx_info.m_hash),
                                                      G_context.tx_info.signature,
                                                      &sig_len);
    if (error != CX_OK) {
        return -1;
    }

    PRINTF("Signature: %.*H\n", sig_len, G_context.tx_info.signature);

    G_context.tx_info.signature_len = (uint8_t) sig_len;  // 64 for ed25519
    G_context.tx_info.v = 0;

    return 0;
}

void validate_transaction(bool choice) {
    if (choice) {
        G_context.state = STATE_APPROVED;

        if (crypto_sign_message() != 0) {
            G_context.state = STATE_NONE;
            io_send_sw(SWO_SECURITY_ISSUE);
        } else {
            helper_send_response_sig();
        }
    } else {
        G_context.state = STATE_NONE;
        io_send_sw(SWO_CONDITIONS_NOT_SATISFIED);
    }
}
