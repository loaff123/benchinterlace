"""Strict bounded JSON and canonical hashing. No filesystem or process access."""
import hashlib
import json

from .constants import MAX_INTEGER_DIGITS, MAX_JSON_NODES, MAX_JSON_STRING_BYTES, MAX_NESTING
from .errors import ValidationError


def _fail(detail):
    raise ValidationError('invalid_schema', detail)


def _check_value(value):
    """Reject non-JSON Python values before serialization, including float/bool confusion."""
    nodes = 0

    def visit(item, depth):
        nonlocal nodes
        nodes += 1
        if nodes > MAX_JSON_NODES:
            _fail('JSON node limit exceeded')
        kind = type(item)
        if kind in (dict, list):
            if depth >= MAX_NESTING:
                _fail('JSON nesting limit exceeded')
            if kind is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        _fail('JSON object keys must be strings')
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
        elif kind is str:
            if len(item) > MAX_JSON_STRING_BYTES:
                _fail('JSON string byte limit exceeded')
            if '\x00' in item:
                _fail('embedded NUL is forbidden')
            try:
                if len(item.encode('utf-8', 'strict')) > MAX_JSON_STRING_BYTES:
                    _fail('JSON string byte limit exceeded')
            except UnicodeEncodeError:
                _fail('unpaired Unicode surrogate is forbidden')
        elif kind is int:
            if not -(10 ** MAX_INTEGER_DIGITS) < item < 10 ** MAX_INTEGER_DIGITS:
                _fail('JSON integer digit limit exceeded')
        elif item is None or kind is bool:
            return
        else:
            _fail('only JSON objects, arrays, strings, integers, booleans and null are allowed')
    visit(value, 0)


def canonical_bytes(value) -> bytes:
    """Sorted compact ASCII-escaped UTF-8 JSON, followed by exactly one LF."""
    _check_value(value)
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode('ascii')


def _depth_check(text):
    # Bound nesting before the standard parser can recurse or allocate deep containers.
    depth = 0
    quoted = False
    escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '[{':
            depth += 1
            if depth > MAX_NESTING:
                _fail('JSON nesting limit exceeded')
        elif char in ']}':
            depth -= 1


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail('duplicate JSON object key')
        result[key] = value
    return result


def _integer(text):
    if len(text.lstrip('-')) > MAX_INTEGER_DIGITS:
        _fail('JSON integer digit limit exceeded')
    return int(text)


def _not_integer(_text):
    _fail('floating-point and nonfinite JSON numbers are forbidden')


def parse_json(raw: bytes, limit: int, canonical: bool = False):
    """Parse bytes under an explicit cap; sealed artifacts require exact canonical bytes."""
    if type(raw) is not bytes or type(limit) is not int or limit < 1:
        _fail('parse_json requires bytes and a positive integer byte limit')
    if type(canonical) is not bool:
        _fail('canonical flag must be a boolean')
    if len(raw) > limit:
        raise ValidationError('resource_limit', 'JSON byte limit exceeded')
    try:
        text = raw.decode('utf-8', 'strict')
        _depth_check(text)
        value = json.loads(text, object_pairs_hook=_pairs, parse_int=_integer,
                           parse_float=_not_integer, parse_constant=_not_integer)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValidationError('invalid_schema', 'invalid UTF-8 JSON document') from exc
    _check_value(value)
    if canonical and canonical_bytes(value) != raw:
        _fail('sealed JSON is not canonically encoded')
    return value


def digest(raw: bytes) -> str:
    """SHA-256 of literal bytes; callers choose canonical JSON or original file bytes."""
    if type(raw) is not bytes:
        _fail('digest requires bytes')
    return hashlib.sha256(raw).hexdigest()
