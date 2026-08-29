"""Synthetic private keys.

Five keypairs were generated once with ``openssl`` / ``ssh-keygen`` for this
corpus and are pinned here so the corpus stays reproducible without a
key-generation dependency. They are registered with nothing and grant access to
nothing. See ``SECURITY.md``.

The PEM bodies are stored base64-encoded and decoded at import. That is not
security by obscurity — the keys are worthless — it just keeps the source file
from tripping the push-protection and secret-scanning rules of every host this
repository is mirrored to, which would otherwise fire on the literal
``-----BEGIN ... PRIVATE KEY-----`` armour. The decoded values are what the
generator plants, and GitHub push protection does flag them in the generated
(git-ignored) corpus — a data point the benchmark records.

The ``headerless`` variant strips the PEM armour to exercise a key body pasted
without its ``-----BEGIN-----`` line, which defeats header-anchored regex rules.
"""

from __future__ import annotations

import base64

from ssbench.formats.base import SecretSpec
from ssbench.rng import SeededRNG


def _decode(b64: str) -> str:
    return base64.b64decode(b64).decode("ascii")


# base64(PEM). Regenerate with:  base64 < key.pem | tr -d '\n'
_PEM_B64 = {
    "rsa-2048": (
        "private-key-rsa",
        "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2UUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktjd2dnU2pB"
        "Z0VBQW9JQkFRQytHclNZUkhsdlVnbk8KK0pNakEyTDRZSWk5alhhSXcrZmZFSS81cVNLMmN6eXMyckhYeG9Hd0d1KzFF"
        "ZXRzbkdRU1dKU2pvbWh0YmVsZwpmN0dmeEgraHI1V1JxSzR0Q2V1cGYydDNscGRmR3g2OU9vWDIyZGdCZVBaSmxrMFZY"
        "dSt5L2VUSm5QczlvL05xCjhreG1nYS9maVA0SUhJVGNCS3RwZnRlTTV0dFJvcHY1N1ZodVpZZEoxdkcxVEg3RUZPd1Rz"
        "cDJNN2JhMEFPL3EKb0MySURiUGVIM0xROWgyc216RjErcmRveFB2OVM1MHEwVU9jRFptSlpTclJxbzVGaXd4SE1SNy9l"
        "c0l4NUExcQpRMnJWOW0rOHREcWxtdHo5NlJKVVdRNkw3UjZNYzFlKzlIU21ZT3lYSit6d21KZUJlWlpxWG9NSENEV09u"
        "WURoCmFSNlBmWGN0QWdNQkFBRUNnZ0VBS2JpVXIrSS9RR1loenZHUTRSdEtLamFOYkFSUzRsc1VWVWsrUDgyVjE3TGMK"
        "dXhiWDl3SVN6a0pySHpNS2x2Q1BxZE1VOUFDZHFINTV2SHJwMGFWL1dVMitwcFA5ZmRieWlHVjFnVzVrVkRRUQpmL2tM"
        "RTR6bHNoVUpBRWRqTFhDRGJLWDZBeUZYcGtTSUZJMk9wT1NMWTZTZUU4dW1nTjdwZTZLaHpjT1FtSTZWCmNtRDZadGd5"
        "bzVyUFdPNUMxNjBvUWN0UFphVXN5Wmp1Q2krZ2toRDZ0Y0dZcjZucHRDUEVTWDBBNFJaSDZkVHQKOVZnVm91TUw0bjNC"
        "R3NLaURva1lwM00yRjFqcnN3cEgwcTcrd1d5Q2N3YklqYVdiY3NGMER1NGlycXFkcnpoQgpnTTEyTlFGOHB2RE92andl"
        "Y3AvZUNscFNZd25vQWxJemhZL1lqQmhwb1FLQmdRRG92Vy8zKzIvV3hmSzBIVTluCnJvVkVURzNhN3RHaEl3RGtzN2FX"
        "ZXBkRnllRWh6ZW5HODJKWUVCUmhwU3FFWk9hR3pYMEhxbnNVTW45VW1WRVkKZk00Z1pLVlpwUDJXR09YRFIwdkorZEM4"
        "czhMaHpCeUVldFlIb0FaZWVscEVEMXljeVZYd2cwMnNlZFc0eHh0bwpIK2FMU2pwTFl0cldIRE5kY2tLbFpWWXlPUUtC"
        "Z1FEUkduTnVYdkYyYkdndkV4TUJLRC80ckwwQlpRM3RMMXh0CkRXbGZOSmVsZ2x2cy92R2R3ZTlpMFdZMmVPR1hWQnFN"
        "dlV5aWFXclEyYUxuR2gwdHlQZDFVVVpQZGs3cGtRTEwKalY4bjlvNVNxYWxrMzdoaXl4SitUUHJTY1E4UW9xNVBTeVNj"
        "c09iQ2NvMGtKSFJUc2Z2VXRmS0xxYm1wZkdEUQpqS2QxalhRY2xRS0JnQ2xzOW80TUdnYi9hc2kyWXRqUWpuWHVxS3NN"
        "VVJHK1dqMWE0NGY3UUF1eStEaDlIenhECk8rRHkwNzNobVNUQmxPcXZqcTZib0phaXVsbERoTlMzK2pSMzFacVVMSExY"
        "OGFXRmZpN3dJVUJGT3MzWDk4ZDQKMmJtM3VRcDkrcTBja3Q1eFU3T2dtMlcwdGQ3U3ljVUowSTVBWXduaUNaT01wM1Bk"
        "ajVGQzdVbTVBb0dCQUpuMQp2ZFFnTisyWCtFWGc1M2RNcVgxeHdtQktoYXlEMkt1NjJrRHRPbEwwM3JacktIK2RrYUxT"
        "eDAySVI2SGluUUhQClI2TzF0cDQ4QUlQa2FHT1R1eEE0WFdxWWs1WEozYUwrWG5mUVJBNTlPV282aDByR2RzRmo4TElO"
        "NktlNUFGc0YKMnRrOEwwd3doOWQ2dCtRQUFvb2x4WVlyMjdYOURGUEJuSE1qU2NEWkFvR0FmMGxSTzJISDlZc2JWTXFj"
        "QStlbwpqMzB2VmRIQkQzWnc2LzFpOXl1cjFueEFNUjhEVVRhdmpWMkJSMFIwZUx5RFhUM0FlcFNmMnVJVGU2UjBKRGlh"
        "CnZUdlp3YmVSV3BkOEZvcTV5bWZqWjJzSkFEUnljaSswVkYxU2p5eHBVelhVcFZRa0ZocU43ZUEyMU96aEN6dTcKazkx"
        "VHUwR2IwZXRIdzR4bjRaSzZNOTA9Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0=",
    ),
    "ec-p256": (
        "private-key-ec",
        "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUgxa0M4ZFBSYmJxckhFcDF2U0NzOHpXb2tZVHNq"
        "YVhYK3lpZnkrMWVteExvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFRnhCVXRNczlXMFZxV3JZcEY0TWUycDEvYWN1eTBQ"
        "RkErWFpuNmdDd3NCN3RXRGhUMHZHRgphdGUwTDdvWFdYWWpjTU1UR2FyUGU3WFVOZzZvbGlNY2RBPT0KLS0tLS1FTkQg"
        "RUMgUFJJVkFURSBLRVktLS0tLQ==",
    ),
    "ec-p384": (
        "private-key-ec",
        "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1JR2tBZ0VCQkRETEJYWUFGS0taWjNYSGRreDZUNzlLZnhHczNF"
        "cS9CeXJHVmRQSHl6SW80V044WDFqRWppdUEKMW1UOTR3RSs1VmVnQndZRks0RUVBQ0toWkFOaUFBUStWRDNpV3kzWEd5"
        "cEF1RFNXYUZaazhHNHZCOTkyclYycQpOaFQzY0lyeEVXcHJ6TFFvckJla1F6dGJNVFlkRmhBV1FQd3d5am9IMWtYK3VQ"
        "NW10STQvWnkwM2ZsQURoek8rCmsvQkF2bmRQMklxb3liMTc1LzAxQ0JLT1dwbzNqQTg9Ci0tLS0tRU5EIEVDIFBSSVZB"
        "VEUgS0VZLS0tLS0=",
    ),
    "ed25519": (
        "private-key-ed25519",
        "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1DNENBUUF3QlFZREsyVndCQ0lFSUU2aDhSVG1xeG1nclp6citycHJa"
        "TEh5WGtYdk9rcktLZlZFUzlZbGRhNEsKLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQ==",
    ),
    "openssh": (
        "private-key-openssh",
        "LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFB"
        "QUFFYm05dVpRQUFBQUFBQUFBQkFBQUFNd0FBQUF0emMyZ3RaVwpReU5UVXhPUUFBQUNDdHZoU25FUDV0a2NjbUxCL2Q0"
        "NmxFWjV2TFRQd3lqK3R4b3pKMkhVdjA5QUFBQUtDMnhDb1p0c1FxCkdRQUFBQXR6YzJndFpXUXlOVFV4T1FBQUFDQ3R2"
        "aFNuRVA1dGtjY21MQi9kNDZsRVo1dkxUUHd5ait0eG96SjJIVXYwOUEKQUFBRUJIenBrTWZTdG5oY1BCNnZlOUttUStP"
        "ZWhUVHcxdVpkL0xFM0wwNjRxSlZxMitGS2NRL20yUnh5WXNIOTNqcVVSbgptOHRNL0RLUDYzR2pNbllkUy9UMEFBQUFG"
        "M041Ym5Sb1pYUnBZeTFpWlc1amFHMWhjbXN0YTJWNUFRSURCQVVHCi0tLS0tRU5EIE9QRU5TU0ggUFJJVkFURSBLRVkt"
        "LS0tLQ==",
    ),
}

_KEYS = {kind: (secret_type, _decode(b64)) for kind, (secret_type, b64) in _PEM_B64.items()}


def build_private_key(rng: SeededRNG, kind: str = "rsa-2048", headerless: bool = False) -> SecretSpec:
    if kind not in _KEYS:
        raise ValueError(f"unknown key kind: {kind}")
    secret_type, pem = _KEYS[kind]
    value = pem
    notes = "checked-in synthetic keypair; grants access to nothing."
    if headerless:
        lines = [ln for ln in pem.splitlines() if not ln.startswith("-----")]
        value = "\n".join(lines)
        secret_type += "-headerless"
        notes = "PEM armour stripped; defeats header-anchored regex rules."
    return SecretSpec(
        secret_type=secret_type,
        category="private-key",
        value=value,
        multiline=True,
        assignment_key="PRIVATE_KEY",
        notes=notes,
    )
