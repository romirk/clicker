def varint(u: int) -> bytes:
    """Encode a varint"""
    if u < 251:
        return bytes([u])
    elif u < 2 ** 16:
        return b"\xfb" + u.to_bytes(2, "little")
    elif u < 2 ** 32:
        return b"\xfc" + u.to_bytes(4, "little")
    elif u < 2 ** 64:
        return b"\xfd" + u.to_bytes(8, "little")
    elif u < 2 ** 128:
        return b"\xfe" + u.to_bytes(16, "little")

    raise ValueError("Integer too large: %d" % u)
