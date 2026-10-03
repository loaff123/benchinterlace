"""Bounded reads of declared files, without following the final path component.

These checks detect ordinary mutation, not hostile parent-directory races or
changes restored between checks. A digest does not prove which bytes executed.
"""
import hashlib
import os
import stat

from .constants import MAX_INPUT_BYTES
from .errors import ValidationError


_CHUNK_BYTES = 65536


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _check_deadline(check):
    if check is not None:
        check()


def read_regular(path, limit, deadline_check=None, buffer=False):
    """Return optional bytes and {bytes, sha256} for one stable regular file.

The size cap is checked before allocation and throughout streaming. Filesystem
errors propagate; callers can distinguish them from stable-read validation.
A deadline callback may raise to stop a read, with its descriptor still closed.
"""
    return _read_regular(path, limit, deadline_check, buffer)


def read_executable(path, limit):
    """Fingerprint a permitted executable, rejecting direct shebang execution."""
    return _read_regular(path, limit, None, False, executable=True)


def _read_regular(path, limit, deadline_check, buffer, executable=False):
    if type(limit) is not int or limit < 0 or type(buffer) is not bool:
        raise ValidationError('invalid_schema', 'invalid regular-file read options')
    if not getattr(os, 'O_NOFOLLOW', 0) or not getattr(os, 'O_NONBLOCK', 0):
        raise ValidationError('unsupported_primitive', 'safe regular-file open is unavailable')
    _check_deadline(deadline_check)
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise ValidationError('invalid_path', 'declared path is not a regular file')
    if before.st_size > limit:
        raise ValidationError('resource_limit', 'declared file exceeds its byte limit')
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, 'O_CLOEXEC', 0)
    fd = os.open(path, flags)
    try:
        _check_deadline(deadline_check)
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or _signature(opened) != _signature(before):
            raise ValidationError('unstable_read', 'declared file changed while opening')
        if executable:
            effective = os.access in os.supports_effective_ids
            if not opened.st_mode & 0o111 or not os.access(path, os.X_OK, effective_ids=effective):
                raise ValidationError('invalid_path', 'command file is not executable')
        prefix = b''
        hasher = hashlib.sha256()
        chunks = []
        length = 0
        while True:
            _check_deadline(deadline_check)
            chunk = os.read(fd, min(_CHUNK_BYTES, limit + 1 - length))
            if not chunk:
                break
            length += len(chunk)
            if length > limit:
                raise ValidationError('resource_limit', 'declared file grew past its byte limit')
            if executable and len(prefix) < 2:
                prefix += chunk[:2 - len(prefix)]
            hasher.update(chunk)
            if buffer:
                chunks.append(chunk)
        _check_deadline(deadline_check)
        after = os.fstat(fd)
        try:
            named = os.lstat(path)
        except OSError as exc:
            raise ValidationError('unstable_read', 'declared file disappeared while reading') from exc
        if (_signature(opened) != _signature(after) or
                _signature(opened) != _signature(named) or length != opened.st_size):
            raise ValidationError('unstable_read', 'declared file changed while reading')
        if executable and prefix == b'#!':
            raise ValidationError('invalid_path', 'name the interpreter explicitly and declare the script file')
        _check_deadline(deadline_check)
        return (b''.join(chunks) if buffer else None,
                {'bytes':length, 'sha256':hasher.hexdigest()})
    finally:
        os.close(fd)


def fingerprint_records(files, deadline_check=None):
    """Check every declared file in ID order, retaining each actual observation.

A changed digest retains its real successful-read record and adds a failure
reason. Read failures retain a classified error record instead of a fake hash.
A run_timeout/interrupted callback failure stops reading, retaining earlier
observations and explicit error records for the current and remaining IDs.
Other callback exceptions propagate.
"""
    records = []
    reasons = []
    ordered = sorted(files, key=lambda item: item['id'])
    total = 0
    callback_error = None

    def check():
        nonlocal callback_error
        try:
            _check_deadline(deadline_check)
        except Exception as exc:
            callback_error = exc
            raise

    for index, entry in enumerate(ordered):
        identifier = entry['id']
        try:
            _, actual = read_regular(entry['path'], MAX_INPUT_BYTES - total, check)
        except ValidationError as exc:
            if exc.code in ('run_timeout', 'interrupted'):
                records.extend({'id':pending['id'], 'error_code':exc.code}
                               for pending in ordered[index:])
                reasons.append({'code':exc.code, 'detail':exc.detail})
                break
            if callback_error is exc:
                raise
            records.append({'id':identifier, 'error_code':exc.code})
            reasons.append({'code':exc.code, 'detail':'file ' + identifier})
        except OSError as exc:
            if callback_error is exc:
                raise
            records.append({'id':identifier, 'error_code':'input_changed'})
            reasons.append({'code':'input_changed', 'detail':'file ' + identifier + ' is unreadable'})
        else:
            total += actual['bytes']
            records.append({'id':identifier, **actual, 'stable_read':True})
            if actual['bytes'] != entry['bytes'] or actual['sha256'] != entry['sha256']:
                reasons.append({'code':'input_changed', 'detail':'file ' + identifier})
    return records, reasons
