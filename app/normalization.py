def normalize_username(username: str) -> str:
    if not username.isascii():
        raise ValueError("Username must contain ASCII characters only")
    return username.strip().casefold()
