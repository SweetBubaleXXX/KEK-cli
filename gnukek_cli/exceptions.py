class KeyNotFoundError(Exception):
    def __init__(self, key_id: str, *args: object) -> None:
        super().__init__(f"Key {key_id} not found", *args)
