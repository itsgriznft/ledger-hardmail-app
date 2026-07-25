# HardMail — a clear-signing Ledger app for email

A Ledger device application that **clear-signs email**. It renders the actual
message fields — **From / To / Subject** (plus the body SHA-256) — on the
device's own trusted screen, and signs that commitment with **ed25519**.

The point: a human approves an email having *read it on hardware*, not by
blindly confirming a hash. Change any field afterwards and the signature stops
verifying.

Built from [LedgerHQ/app-boilerplate](https://github.com/LedgerHQ/app-boilerplate)
(Apache-2.0, see [LICENSE.md](LICENSE.md)) with Ledger's own toolchain.

Companion host software (agent + verifying relay):
**[ledger-hardmail](https://github.com/itsgriznft/ledger-hardmail)**.

## What the user sees (Stax)

```
1 of 4   Review email to send                    [Reject]
2 of 4   From     HardMail Agent <agent@hardmail.local>
         To       boss@example.com
         Subject  Q3 report is ready for review
3 of 4   Body (SHA-256)  D2E2670BD9386BB733CC538297BD3DF7D…
4 of 4   Sign to send this email?      [ Hold to sign ]
```

## Protocol

`CLA = 0xE0`. Derivation path prefix `44'/1'`.

| INS | Name | Notes |
|---|---|---|
| `0x03` | GET_VERSION | |
| `0x04` | GET_APP_NAME | |
| `0x05` | GET_PUBLIC_KEY | ed25519; the compressed 32-byte key sits at `raw_public_key[1..33]` (a valid Stellar `G…` address when encoded) |
| `0x06` | SIGN | two chunks, see below |

**SIGN** — chunk 0 (`P1=0x00, P2=0x80`): BIP32 path. Chunk 1 (`P1=0x01, P2=0x00`):
the email payload:

```
from_len:u8 | from | to_len:u8 | to | subject_len:u8 | subject | body_hash(32)
```

Every text field must be **printable ASCII** (`0x20..0x7e`), non-empty, and
within bounds (from ≤ 128, to ≤ 128, subject ≤ 200) — anything else is refused,
which is also what makes header injection impossible. No trailing bytes are
allowed.

Response: `sig_len(1) || signature(64) || v(1)` — an ed25519 signature over
`sha256(payload)`, i.e. over exactly the bytes the device displayed.

## Build

```bash
docker run --rm -e BOLOS_SDK=/opt/stax-secure-sdk -v "$(pwd)":/app \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest \
  bash -c 'cd /app && make -j'
# -> bin/app.elf
```

Other targets: `$NANOX_SDK`, `$NANOSP_SDK`, `$FLEX_SDK`, `$APEX_P_SDK`.

## Run in the emulator

```bash
docker run -d --name hardmail-app -v "$(pwd)/bin":/apps -p 5002:5000 -p 40002:40000 \
  ghcr.io/ledgerhq/speculos:latest --model stax --display headless \
  --api-port 5000 --apdu-port 40000 /apps/app.elf
```

Open <http://localhost:5002> to see the screen. Speculos uses a **public test
seed** — never send real value to keys derived from it.

## Security notes

- **Never blind-signs.** There is no blind-sign path: the app parses the fields
  and displays them, or it refuses.
- **Fails closed.** Any malformed length, non-printable byte, or trailing data
  aborts with an error rather than proceeding.
- **The signature binds the display.** It covers `sha256(payload)`, and the
  payload *is* what was rendered — so a verifier that recomputes the payload
  from an email proves the human saw that exact email.
- The signing key never leaves the secure element; approval requires the
  physical hold-to-sign gesture.

## Status

Proof of concept. Not audited, not a production Ledger app, not submitted to
Ledger's app store. The upstream boilerplate's own tests/CI still reference the
original example transaction format and have not been ported to the email
payload.
