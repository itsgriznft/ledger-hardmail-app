import re
from pathlib import Path

from Crypto.Signature import eddsa


def compressed_public_key(raw_public_key: bytes) -> bytes:
    """The 32-byte ed25519 key inside the SDK's raw public-key buffer."""
    return raw_public_key[1:33]


def is_valid_ed25519_key(compressed_key: bytes) -> bool:
    """True iff these 32 bytes decode as a point on Ed25519."""
    if len(compressed_key) != 32:
        return False
    try:
        eddsa.import_public_key(compressed_key)
        return True
    except ValueError:
        return False


def check_signature_validity(raw_public_key: bytes, signature: bytes, digest: bytes) -> bool:
    """True iff `signature` is the device's ed25519 signature over `digest`.

    The device signs sha256(payload) — the payload being exactly the bytes it
    rendered — so verifying here proves the signature covers what was displayed.
    """
    if len(signature) != 64:
        return False
    verifier = eddsa.new(eddsa.import_public_key(compressed_public_key(raw_public_key)), "rfc8032")
    try:
        verifier.verify(digest, signature)
        return True
    except ValueError:
        return False


def verify_name(name: str) -> None:
    """Verify the app name, based on defines in Makefile

    Args:
        name (str): Name to be checked
    """

    name_str = ""
    lines = _read_makefile()
    name_re = re.compile(r"^APPNAME\s?=\s?\"?(?P<val>\w+)\"?", re.I)
    for line in lines:
        info = name_re.match(line)
        if info:
            dinfo = info.groupdict()
            name_str = dinfo["val"]
    assert name_str == name, f"Expected name {name_str!r}, got {name!r}"


def verify_version(version: str) -> None:
    """Verify the app version, based on defines in Makefile

    Args:
        Version (str): Version to be checked
    """

    vers_dict = {}
    vers_str = ""
    lines = _read_makefile()
    version_re = re.compile(r"^APPVERSION_(?P<part>\w)\s?=\s?(?P<val>\d*)", re.I)
    for line in lines:
        info = version_re.match(line)
        if info:
            dinfo = info.groupdict()
            vers_dict[dinfo["part"]] = dinfo["val"]
    try:
        vers_str = f"{vers_dict['M']}.{vers_dict['N']}.{vers_dict['P']}"
    except KeyError:
        pass
    assert version == vers_str


def _read_makefile() -> list[str]:
    """Read lines from the parent Makefile"""

    parent = Path(__file__).parent.parent.parent.resolve()
    makefile = f"{parent}/Makefile"
    with open(makefile, encoding="utf-8") as f_p:
        lines = f_p.readlines()
    return lines
