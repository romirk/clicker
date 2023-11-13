def trail_off(msg: str, length: int = 40):
    if len(msg) > length:
        msg = msg[:length - 3] + "..."
    return msg
