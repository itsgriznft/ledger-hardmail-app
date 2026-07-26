"""Build the email payload the HardMail app parses, displays and signs.

Mirrors app-hardmail/src/transaction/deserialize.c exactly:

    challenge(16) | from_len:u8|from | to_len:u8|to | subj_len:u8|subj
                  | body_len:u16be|body
                  | att_count:u8 [ name_len:u8|name | size:u32be | sha256(32) ]

Nothing is hashed away: the body travels as text so the device can render it.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Optional

CHALLENGE_LEN = 16
MAX_FROM_LEN = 128
MAX_TO_LEN = 128
MAX_SUBJECT_LEN = 200
MAX_BODY_LEN = 2048
MAX_ATT_NAME_LEN = 64


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

    def serialize(self) -> bytes:
        assert len(self.challenge) == CHALLENGE_LEN
        body = self.body.encode("ascii")
        assert 1 <= len(body) <= MAX_BODY_LEN
        return (
            self.challenge
            + _text_field(self.sender, MAX_FROM_LEN)
            + _text_field(self.recipient, MAX_TO_LEN)
            + _text_field(self.subject, MAX_SUBJECT_LEN)
            + len(body).to_bytes(2, byteorder="big")
            + body
            + (self.attachment.serialize() if self.attachment else bytes([0]))
        )

    def signed_digest(self) -> bytes:
        """What the device signs: sha256 over exactly the displayed payload."""
        return sha256(self.serialize()).digest()


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
