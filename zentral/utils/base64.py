import base64


def trimmed_urlsafe_b64decode(encoded):
    if isinstance(encoded, str):
        encoded = encoded.encode("ascii")
    encoded += b"=" * (-len(encoded) % 4)
    return base64.urlsafe_b64decode(encoded)
