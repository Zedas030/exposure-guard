"""End-to-end protection of probe results (independent of the SSH transport):

probe -> guard : zlib(JSON) sealed to the guard's Curve25519 key (only the guard can read it),
                 then signed with the probe's Ed25519 key (the guard only accepts the pinned probe).
guard -> probe : target list signed with the guard's Ed25519 key (the probe scans nothing else)."""
from __future__ import annotations

import base64
import json
import os
import zlib

from nacl.encoding import RawEncoder
from nacl.exceptions import BadSignatureError, CryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.signing import SigningKey, VerifyKey


class EnvelopeError(Exception):
    pass


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(text: str) -> bytes:
    return base64.b64decode(text.strip())


class GuardKeys:
    """Key material of the guard (Pi side), stored as raw 32-byte files with mode 600."""

    def __init__(self, directory: str):
        self.dir = directory
        self.sign_path = os.path.join(directory, "guard_sign.key")
        self.box_path = os.path.join(directory, "guard_box.key")

    def exists(self) -> bool:
        return os.path.exists(self.sign_path) and os.path.exists(self.box_path)

    def init(self) -> bool:
        if self.exists():
            return False
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        for path, raw in ((self.sign_path, bytes(SigningKey.generate())), (self.box_path, bytes(PrivateKey.generate()))):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(raw)
        return True

    def signing(self) -> SigningKey:
        with open(self.sign_path, "rb") as fh:
            return SigningKey(fh.read())

    def box(self) -> PrivateKey:
        with open(self.box_path, "rb") as fh:
            return PrivateKey(fh.read())

    def public(self) -> dict:
        return {"guard_verify_key": b64(bytes(self.signing().verify_key)),
                "guard_box_public_key": b64(bytes(self.box().public_key))}


def sign_json(obj: dict, key: SigningKey) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    return b64(key.sign(raw))


def verify_json(text: str, verify_key_b64: str) -> dict:
    try:
        raw = VerifyKey(unb64(verify_key_b64)).verify(unb64(text))
    except (BadSignatureError, ValueError) as exc:
        raise EnvelopeError(f"bad signature: {exc}") from exc
    return json.loads(raw)


def seal(obj: dict, recipient_pub_b64: str, signer: SigningKey) -> str:
    raw = zlib.compress(json.dumps(obj, separators=(",", ":")).encode(), 9)
    sealed = SealedBox(PublicKey(unb64(recipient_pub_b64))).encrypt(raw)
    return b64(signer.sign(sealed))


def open_envelope(text: str, sender_verify_b64: str, recipient: PrivateKey) -> dict:
    if not sender_verify_b64:
        raise EnvelopeError("probe verify key not configured (external.probe_verify_key)")
    try:
        sealed = VerifyKey(unb64(sender_verify_b64)).verify(unb64(text), encoder=RawEncoder)
    except (BadSignatureError, ValueError) as exc:
        raise EnvelopeError(f"signature check failed - not from the pinned probe: {exc}") from exc
    try:
        raw = SealedBox(recipient).decrypt(sealed)
        return json.loads(zlib.decompress(raw))
    except (CryptoError, zlib.error, ValueError) as exc:
        raise EnvelopeError(f"cannot decrypt: {exc}") from exc
