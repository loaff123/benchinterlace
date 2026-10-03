"""Bounded, machine-classifiable diagnostics, with no implicit terminal output."""
from .constants import MAX_DETAIL_BYTES


class ValidationError(ValueError):
    """A validation failure with a closed reason code and bounded detail."""

    def __init__(self, code: str, detail: str):
        self.code = code
        self.detail = str(detail).encode('utf-8', 'backslashreplace')[:MAX_DETAIL_BYTES].decode('utf-8', 'ignore')
        super().__init__(f'{self.code}: {self.detail}')
