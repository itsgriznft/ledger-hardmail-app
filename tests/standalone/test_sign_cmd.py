"""Functional tests for email clear-signing.

The guarantee under test: the device shows the real message — From, To, Subject
and the body in full — and its signature covers exactly those bytes. So the
tests check both halves: what appears on screen (snapshot navigation) and that
the returned ed25519 signature verifies over the payload that was displayed.
"""

import pytest
from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.boilerplate_command_sender import (
    BoilerplateCommandSender,
    Errors,
)
from application_client.boilerplate_response_unpacker import (
    unpack_get_public_key_response,
    unpack_sign_tx_response,
)
from application_client.email_payload import (
    Attachment,
    MAX_BODY_LEN,
    MAX_SUBJECT_LEN,
    sample_email,
)

from .utils import check_signature_validity

PATH = "m/44'/1'/0'/0/0"


def _device_key(client: BoilerplateCommandSender) -> bytes:
    rapdu = client.get_public_key(path=PATH)
    _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)
    return public_key


def _signature(client: BoilerplateCommandSender) -> bytes:
    _, signature, _ = unpack_sign_tx_response(client.get_async_response().data)
    return signature


# ── happy paths ─────────────────────────────────────────────────────────────


def test_sign_email_short(backend: BackendInterface, scenario_navigator: NavigateWithScenario) -> None:
    """A one-chunk message: approve it, and the signature must cover the payload."""
    client = BoilerplateCommandSender(backend)
    public_key = _device_key(client)
    email = sample_email()

    with client.sign_tx(path=PATH, transaction=email.serialize()):
        scenario_navigator.review_approve()

    assert check_signature_validity(public_key, _signature(client), email.signed_digest())


def test_sign_email_long_body(backend: BackendInterface, scenario_navigator: NavigateWithScenario) -> None:
    """A message spanning several APDU chunks is still displayed and signed whole."""
    client = BoilerplateCommandSender(backend)
    public_key = _device_key(client)
    email = sample_email(body="All of this text is shown on the device.\n" * 20)

    with client.sign_tx(path=PATH, transaction=email.serialize()):
        scenario_navigator.review_approve()

    assert check_signature_validity(public_key, _signature(client), email.signed_digest())


def test_sign_email_with_attachment(backend: BackendInterface, scenario_navigator: NavigateWithScenario) -> None:
    """An attachment is bound by name, size and content hash — all shown on screen."""
    client = BoilerplateCommandSender(backend)
    public_key = _device_key(client)
    email = sample_email(attachment=Attachment.of("q3-summary.txt", b"revenue: 4.2M\n"))

    with client.sign_tx(path=PATH, transaction=email.serialize()):
        scenario_navigator.review_approve()

    assert check_signature_validity(public_key, _signature(client), email.signed_digest())


def test_signature_does_not_cover_a_different_email(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario
) -> None:
    """The whole point of clear signing: change one field, the signature stops verifying."""
    client = BoilerplateCommandSender(backend)
    public_key = _device_key(client)
    email = sample_email()

    with client.sign_tx(path=PATH, transaction=email.serialize()):
        scenario_navigator.review_approve()
    signature = _signature(client)

    tampered = sample_email(subject="URGENT: wire transfer")
    assert not check_signature_validity(public_key, signature, tampered.signed_digest())


def test_sign_subject_at_max_length(backend: BackendInterface, scenario_navigator: NavigateWithScenario) -> None:
    """Boundary case: exactly at the limit must still be accepted."""
    client = BoilerplateCommandSender(backend)
    public_key = _device_key(client)
    email = sample_email(subject="s" * MAX_SUBJECT_LEN)

    with client.sign_tx(path=PATH, transaction=email.serialize()):
        scenario_navigator.review_approve()

    assert check_signature_validity(public_key, _signature(client), email.signed_digest())


# ── user rejection ──────────────────────────────────────────────────────────


def test_sign_email_refused(backend: BackendInterface, scenario_navigator: NavigateWithScenario) -> None:
    """Rejecting on the device produces a denial, never a signature."""
    client = BoilerplateCommandSender(backend)
    email = sample_email()

    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_tx(path=PATH, transaction=email.serialize()):
            scenario_navigator.review_reject()

    assert e.value.status == Errors.SWO_CONDITIONS_NOT_SATISFIED
    assert len(e.value.data) == 0


# ── malformed input: the device must fail closed ────────────────────────────


@pytest.mark.parametrize(
    "mutator",
    [
        # A zero-length sender is not a message, it is a malformed buffer.
        pytest.param(lambda p: p[:16] + bytes([0]), id="empty_from"),
        # Trailing bytes mean host and device disagree about what is being signed.
        pytest.param(lambda p: p + b"\x41", id="trailing_bytes"),
        # Truncated payload: a field never arrives.
        pytest.param(lambda p: p[:-4], id="truncated"),
        # More than one attachment is unsupported — and must not be silently ignored.
        pytest.param(lambda p: p[:-1] + bytes([2]), id="two_attachments"),
    ],
)
def test_sign_malformed_payload_is_refused(backend: BackendInterface, mutator) -> None:
    """Malformed payloads are rejected outright — no prompt, no signature."""
    client = BoilerplateCommandSender(backend)
    payload = mutator(sample_email().serialize())

    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_tx(path=PATH, transaction=payload):
            pass

    assert e.value.status == Errors.SWO_INCORRECT_DATA


def test_sign_body_too_long_is_refused(backend: BackendInterface) -> None:
    """A body the device cannot display in full is refused, never truncated."""
    client = BoilerplateCommandSender(backend)
    # Built by hand: a well-behaved client would refuse to compose this at all,
    # so we bypass it to check the DEVICE fails closed on its own.
    oversized = MAX_BODY_LEN + 1
    payload = sample_email().serialize()
    head = payload[: 16 + 1 + 20 + 1 + 16 + 1 + 29]  # challenge + from + to + subject
    payload = head + oversized.to_bytes(2, "big") + b"a" * oversized + bytes([0])

    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_tx(path=PATH, transaction=payload):
            pass

    assert e.value.status == Errors.SWO_INCORRECT_DATA


def test_sign_control_character_in_subject_is_refused(backend: BackendInterface) -> None:
    """Control characters could smuggle mail headers — the device refuses them."""
    client = BoilerplateCommandSender(backend)
    email = sample_email(subject="innocent\nBcc: attacker@evil.com")

    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_tx(path=PATH, transaction=email.serialize()):
            pass

    assert e.value.status == Errors.SWO_INCORRECT_DATA
