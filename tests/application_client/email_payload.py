"""Build the streamed email payload the HardMail app parses, displays and signs.

Mirrors app-hardmail/src/transaction/deserialize.c and sign_tx.c:

    header_len:u16be
    header = challenge(16) | from_len:u8|from | to_len:u8|to | subj_len:u8|subj
             | att_count:u8 [ name_len:u8|name | size:u32be | sha256(32) ]
             | body_len:u32be
    body   = body_len bytes

The header must end exactly on a chunk boundary; body slices follow in their own
chunks, each of which the device displays before answering. Nothing is hashed
away and nothing is buffered whole: the message can be any length.

The signature covers sha256 of the entire frame, length prefix included.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import List, Optional

CHALLENGE_LEN = 16
MAX_FROM_LEN = 128
MAX_TO_LEN = 128
MAX_SUBJECT_LEN = 200
MAX_ATT_NAME_LEN = 64
MAX_HEADER_LEN = 640
MAX_PAGE_LEN = 255


@dataclass(frozen=True)
class Attachment:
    """A file bound by name, size and content hash — never rendered on screen."""

    name: str
    size: int
    sha256_hex: str

    @classmethod
    def of(cls, name: str, content: bytes) -> "Attachment":
        return cls(name=name, size=len(content), sha256_hex=sha256(content).hexdigest())

    def serialize(self) -> bytes:
        name = self.name.encode("ascii")
        assert 1 <= len(name) <= MAX_ATT_NAME_LEN
        return (
            bytes([1, len(name)])
            + name
            + self.size.to_bytes(4, byteorder="big")
            + bytes.fromhex(self.sha256_hex)
        )


def _text_field(value: str, max_len: int) -> bytes:
    raw = value.encode("ascii")
    assert 1 <= len(raw) <= max_len, f"field length 1..{max_len}"
    return bytes([len(raw)]) + raw


@dataclass(frozen=True)
class Email:
    challenge: bytes
    sender: str
    recipient: str
    subject: str
    body: str
    attachment: Optional[Attachment] = None

    def header(self) -> bytes:
        assert len(self.challenge) == CHALLENGE_LEN
        body_len = len(self.body.encode("ascii"))
        assert body_len > 0
        return (
            self.challenge
            + _text_field(self.sender, MAX_FROM_LEN)
            + _text_field(self.recipient, MAX_TO_LEN)
            + _text_field(self.subject, MAX_SUBJECT_LEN)
            + (self.attachment.serialize() if self.attachment else bytes([0]))
            + body_len.to_bytes(4, byteorder="big")
        )

    def chunks(self) -> List[bytes]:
        """APDU-sized pieces: the header (ending on a boundary), then body slices."""
        header = self.header()
        assert len(header) <= MAX_HEADER_LEN
        framed = len(header).to_bytes(2, byteorder="big") + header

        pieces: List[bytes] = [framed[i : i + MAX_PAGE_LEN] for i in range(0, len(framed), MAX_PAGE_LEN)]
        body = self.body.encode("ascii")
        pieces += [body[i : i + MAX_PAGE_LEN] for i in range(0, len(body), MAX_PAGE_LEN)]
        return pieces

    def signed_digest(self) -> bytes:
        """What the device signs: sha256 over the whole streamed frame."""
        return sha256(b"".join(self.chunks())).digest()


def sample_email(challenge: bytes = b"\x11" * CHALLENGE_LEN, **overrides) -> Email:
    fields = {
        "challenge": challenge,
        "sender": "agent@hardmail.local",
        "recipient": "boss@example.com",
        "subject": "Q3 report is ready for review",
        "body": "Hi,\n\nThe Q3 report is finalized.\n\n-- HardMail",
    }
    fields.update(overrides)
    return Email(**fields)  # type: ignore[arg-type]
