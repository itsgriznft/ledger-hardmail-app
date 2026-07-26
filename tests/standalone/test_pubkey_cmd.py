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
)

from .utils import compressed_public_key, is_valid_ed25519_key


# In this test we check that the GET_PUBLIC_KEY works in non-confirmation mode
def test_get_public_key_no_confirm(backend: BackendInterface) -> None:
    path_list = [
        "m/44'/1'/0'/0/0",
        "m/44'/1'/0/0/0",
        "m/44'/1'/911'/0/0",
        "m/44'/1'/255/255/255",
        "m/44'/1'/2147483647/0/0/0/0/0/0/0",
    ]
    keys = []
    for path in path_list:
        client = BoilerplateCommandSender(backend)
        response = client.get_public_key(path=path).data
        _, public_key, _, chain_code = unpack_get_public_key_response(response)

        # The app derives on Ed25519 (the Stellar curve) and returns the
        # compressed point, so check that shape rather than a secp256k1 reference.
        assert is_valid_ed25519_key(compressed_public_key(public_key))
        assert len(chain_code) == 32
        # Derivation must be deterministic: asking twice gives the same key.
        again = client.get_public_key(path=path).data
        assert unpack_get_public_key_response(again)[1] == public_key
        keys.append(compressed_public_key(public_key))

    # Distinct derivation paths must yield distinct keys.
    assert len(set(keys)) == len(keys)


# In this test we check that the GET_PUBLIC_KEY works in confirmation mode
def test_get_public_key_confirm_accepted(backend: BackendInterface, scenario_navigator: NavigateWithScenario) -> None:
    client = BoilerplateCommandSender(backend)
    path = "m/44'/1'/0'/0/0"
    with client.get_public_key_with_confirmation(path=path):
        scenario_navigator.address_review_approve()

    response = client.get_async_response().data
    _, public_key, _, chain_code = unpack_get_public_key_response(response)


    assert is_valid_ed25519_key(compressed_public_key(public_key))
    assert len(chain_code) == 32


# In this test we check that the GET_PUBLIC_KEY in confirmation mode replies an error if the user refuses
def test_get_public_key_confirm_refused(backend: BackendInterface, scenario_navigator: NavigateWithScenario) -> None:
    client = BoilerplateCommandSender(backend)
    path = "m/44'/1'/0'/0/0"

    with pytest.raises(ExceptionRAPDU) as e:
        with client.get_public_key_with_confirmation(path=path):
            scenario_navigator.address_review_reject()

    # Assert that we have received a refusal
    assert e.value.status == Errors.SWO_CONDITIONS_NOT_SATISFIED
    assert len(e.value.data) == 0
