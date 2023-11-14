from logging import DEBUG, basicConfig


def trail_off(msg: str, length: int = 40):
    if len(msg) > length:
        msg = msg[:length - 3] + "..."
    return msg


def logger_config():
    basicConfig(level=DEBUG, format="%(asctime)s | %(name)s - %(levelname)8s : %(message)s")
