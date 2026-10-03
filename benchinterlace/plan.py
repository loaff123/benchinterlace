"""Freeze a bounded command plan without executing or discovering commands."""
import copy
import os
import secrets
import stat

from .canonical import canonical_bytes, digest, parse_json
from .constants import (
    DEFAULT_CAPTURE_BYTES_PER_STREAM, DEFAULT_CAPTURE_BYTES_TOTAL, MAX_FILES,
    MAX_INPUT_BYTES, MAX_PATH_BYTES, MAX_PLAN_BYTES, MAX_SPEC_BYTES, VERSION,
)
from .errors import ValidationError
from .fingerprint import read_executable, read_regular
from .schema import validate_plan, validate_spec


def _resolved(path):
    """Resolve aliases only at initial planning; readers never repeat resolution."""
    resolved = os.path.realpath(path, strict=True)
    try:
        encoded_length = len(resolved.encode('utf-8', 'strict'))
    except UnicodeEncodeError as exc:
        raise ValidationError('invalid_path', 'resolved path is not valid Unicode') from exc
    if (not resolved.startswith('/') or resolved.startswith('//') or
            os.path.normpath(resolved) != resolved or
            encoded_length > MAX_PATH_BYTES):
        raise ValidationError('invalid_path', 'resolved path exceeds the normalized path contract')
    return resolved


def _orders(count):
    # Independent OS-backed bits. Deliberately no seed or user order override.
    return ['BA' if secrets.randbits(1) else 'AB' for _ in range(count)]


def make_plan(spec):
    """Validate, normalize, fingerprint and draw one immutable plan object.

Only argv[0] is resolved. All other argument text is retained literally, without
PATH lookup, a shell, dependency discovery, command execution or environment
serialization. Symlink aliases in the initial spec freeze their current target.
"""
    validate_spec(spec)
    payload = copy.deepcopy(spec)
    payload['schema'] = 'benchinterlace.plan.v1'
    payload['cwd'] = _resolved(spec['cwd'])
    if not stat.S_ISDIR(os.stat(payload['cwd']).st_mode):
        raise ValidationError('invalid_path', 'cwd must be an existing directory')
    payload.setdefault('capture_bytes_per_stream', DEFAULT_CAPTURE_BYTES_PER_STREAM)
    payload.setdefault('capture_bytes_total', DEFAULT_CAPTURE_BYTES_TOTAL)
    declared = []
    by_path = {}
    command_files = {}
    for arm, identifier in (('A', 'executable_a'), ('B', 'executable_b')):
        path = _resolved(spec['commands'][arm]['argv'][0])
        payload['commands'][arm]['argv'][0] = path
        if path not in by_path:
            by_path[path] = identifier
            declared.append({'id':identifier, 'path':path})
        command_files[arm] = by_path[path]
    for entry in spec['files']:
        path = _resolved(entry['path'])
        if path not in by_path:
            by_path[path] = entry['id']
            declared.append({'id':entry['id'], 'path':path})
    if len(declared) > MAX_FILES:
        raise ValidationError('resource_limit', 'declared files including executables exceed count limit')
    # Reject an oversized manifest before hashing any content. The streaming
    # reads below also enforce the remaining aggregate cap against growth.
    total = 0
    for entry in declared:
        info = os.lstat(entry['path'])
        if not stat.S_ISREG(info.st_mode):
            raise ValidationError('invalid_path', 'declared path is not a regular file')
        total += info.st_size
        if total > MAX_INPUT_BYTES:
            raise ValidationError('resource_limit', 'declared files exceed aggregate byte limit')
    files = []
    total = 0
    for entry in declared:
        read = read_executable if entry['id'] in command_files.values() else read_regular
        _, record = read(entry['path'], MAX_INPUT_BYTES - total)
        total += record['bytes']
        files.append({**entry, **record})
    payload['files'] = sorted(files, key=lambda entry: entry['id'])
    payload['command_files'] = command_files
    payload['assignments'] = {'method':'independent-os-bits-v1',
                              'warmup':_orders(spec['warmup_pairs']),
                              'measured':_orders(spec['measured_pairs'])}
    payload.update(runner_contract='linux-foreground-v1',
                   timer_contract='spawn-to-observed-leader-exit-v1',
                   capture_contract='bounded-pipes-v1',
                   fingerprint_contract='declared-before-after-v1',
                   generator_version=VERSION)
    plan = {'plan_id':'sha256:' + digest(canonical_bytes(payload)), 'payload':payload}
    validate_plan(plan)
    if len(canonical_bytes(plan)) > MAX_PLAN_BYTES:
        raise ValidationError('resource_limit', 'canonical plan exceeds its byte limit')
    return plan


def load_plan(path):
    """Read a stable, canonical frozen plan; never follow its command paths."""
    raw, _ = read_regular(path, MAX_PLAN_BYTES, buffer=True)
    plan = parse_json(raw, MAX_PLAN_BYTES, canonical=True)
    validate_plan(plan)
    return plan, raw


def publish_plan(spec_path, out_path):
    """Read a user spec and durably publish one new owner-private plan file."""
    from .publication import publish_create_only
    raw, _ = read_regular(spec_path, MAX_SPEC_BYTES, buffer=True)
    spec = parse_json(raw, MAX_SPEC_BYTES)
    plan = make_plan(spec)
    publish_create_only(out_path, canonical_bytes(plan))
    return plan
