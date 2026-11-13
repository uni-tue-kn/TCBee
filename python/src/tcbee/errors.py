"""Exceptions raised by the public API."""


class TCBeeError(Exception):
    """Base class for TCBee reader errors (driver and OS errors remain unchanged)."""


class UnsupportedDatabase(TCBeeError):
    """The file is neither SQLite nor DuckDB."""


class UnsupportedSchema(TCBeeError):
    """Reprocess the recording with a current tcbee-process."""


class MissingCapability(TCBeeError):
    """The file lacks optional metadata required by the requested operation."""


class NotFound(TCBeeError):
    """A selection has no matches."""


class AmbiguousSelection(TCBeeError):
    """A selection has more than one match."""


class ClosedDatabase(TCBeeError):
    """The database was closed before the operation completed."""
