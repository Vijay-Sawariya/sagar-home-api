"""Process-local schema metadata only; never cache lead data or permissions."""
from functools import wraps
from threading import RLock
from time import monotonic

_lock = RLock()
_ready = set()
_metadata = {}


def ensure_once(name, setup):
    with _lock:
        if name not in _ready:
            setup()
            _metadata.clear()
            _ready.add(name)  # Failed setup remains retryable.


def cache_metadata(function):
    @wraps(function)
    def cached(cursor, table_name):
        key = (function.__name__, table_name)
        with _lock:
            entry = _metadata.get(key)
            if entry and monotonic() - entry[0] < 60:
                return entry[1].copy() if isinstance(entry[1], set) else entry[1]
            value = function(cursor, table_name)
            _metadata[key] = (monotonic(), value)
            return value.copy() if isinstance(value, set) else value
    return cached
