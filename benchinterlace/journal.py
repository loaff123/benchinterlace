"""One-shot, private, append-only evidence and exhaustive v1 seals.

This writer records facts; the unchanged offline reader/state machine decides
whether those facts describe an eligible experiment. Publication failures poison
this instance rather than attempting recovery writes or deleting partial tails.
"""
import hashlib
import os
from pathlib import Path
import re
import stat

from .bundle import signature
from .canonical import canonical_bytes, digest, parse_json
from .constants import (MAX_BUNDLE_BYTES, MAX_CAPTURE_FILES, MAX_EVENT_BYTES,
                        MAX_EVENTS, MAX_EVENT_TOTAL_BYTES, MAX_PLAN_BYTES)
from .errors import ValidationError
from .publication import fsync_directory, publish_create_only
from .schema import validate_event, validate_plan, validate_seal


def fault_hook(stage, path):
    """Internal journal fault injection; not exposed by the production CLI."""


class Journal:
    """Create one private bundle and retain every successfully durable artifact."""

    def __init__(self, root, plan, raw):
        validate_plan(plan)
        if type(raw) is not bytes or raw != canonical_bytes(plan):
            raise ValidationError('plan_mismatch', 'Plan bytes do not match the canonical validated plan')
        self.root = Path(root)
        self.plan = parse_json(raw, MAX_PLAN_BYTES, canonical=True)
        self.event_count = 0
        self.last_event_sha256 = None
        self.capture_bytes = 0
        self._event_bytes = 0
        self._total_bytes = 0
        self._artifacts = {}
        self._signatures = {}
        self._directories = {}
        self._timed_slots = set()
        self._failed = False
        self._sealed = False
        self._slot_count = 2 * (self.plan['payload']['warmup_pairs'] +
                                self.plan['payload']['measured_pairs'])
        fault_hook('before_root_mkdir', self.root)
        os.mkdir(self.root, 0o700)
        os.chmod(self.root, 0o700, follow_symlinks=False)
        fault_hook('after_root_mkdir', self.root)
        fsync_directory(self.root.parent)
        self._directories[self.root] = signature(self.root.lstat())[:3]
        for name in ('events', 'captures'):
            path = self.root / name
            fault_hook('before_child_mkdir', path)
            os.mkdir(path, 0o700)
            os.chmod(path, 0o700, follow_symlinks=False)
            fault_hook('after_child_mkdir', path)
            self._directories[path] = signature(path.lstat())[:3]
            fsync_directory(path)
        fsync_directory(self.root)
        self._publish('plan.json', raw)

    @property
    def artifacts(self):
        """Defensive snapshot of the exhaustive records accumulated so far."""
        return {path: dict(info) for path, info in self._artifacts.items()}

    def _writable(self):
        if self._failed:
            raise ValidationError('capture_io', 'Journal previously failed; preserve its existing prefix')
        if self._sealed:
            raise ValidationError('order_mismatch', 'A sealed journal cannot be extended')

    def _publish(self, relative, raw):
        if self._total_bytes + len(raw) > MAX_BUNDLE_BYTES:
            raise ValidationError('resource_limit', 'Bundle byte cap exceeded')
        info = {'path': relative, 'bytes': len(raw), 'sha256': digest(raw)}
        try:
            publish_create_only(self.root / relative, raw)
            saved = (self.root / relative).lstat()
            if not stat.S_ISREG(saved.st_mode):
                raise ValidationError('unstable_read', 'Published artifact is no longer a regular file')
            self._signatures[relative] = signature(saved)
        except BaseException:
            self._failed = True
            raise
        self._artifacts[relative] = info
        self._total_bytes += len(raw)
        return dict(info)

    def append(self, kind, data):
        """Validate then durably append one canonical event and advance its chain."""
        self._writable()
        event = {'schema': 'benchinterlace.event.v1', 'seq': self.event_count,
                 'previous_sha256': self.last_event_sha256,
                 'plan_id': self.plan['plan_id'], 'kind': kind, 'data': data}
        validate_event(event)
        raw = canonical_bytes(event)
        event = parse_json(raw, MAX_EVENT_BYTES, canonical=True)
        if self.event_count >= MAX_EVENTS or self._event_bytes + len(raw) > MAX_EVENT_TOTAL_BYTES:
            raise ValidationError('resource_limit', 'Event count or aggregate bytes exceed the cap')
        info = self._publish(f'events/{self.event_count:06d}.json', raw)
        self.last_event_sha256 = info['sha256']
        self.event_count += 1
        self._event_bytes += len(raw)
        if kind == 'slot_timing':
            self._timed_slots.add(event['data']['slot'])
        return event

    def capture(self, slot, stream, data):
        """Publish and hash a capture only after its timing event is durable."""
        self._writable()
        if type(slot) is not int or not 0 <= slot < self._slot_count or stream not in ('stdout', 'stderr'):
            raise ValidationError('invalid_path', 'Capture slot or stream is outside the frozen plan')
        if slot not in self._timed_slots:
            raise ValidationError('order_mismatch', 'Capture publication requires durable slot timing')
        if type(data) is not bytes:
            raise ValidationError('invalid_schema', 'Capture publication requires immutable bytes')
        payload = self.plan['payload']
        if (len(data) > payload['capture_bytes_per_stream'] or
                self.capture_bytes + len(data) > payload['capture_bytes_total']):
            raise ValidationError('resource_limit', 'Capture bytes exceed the frozen plan cap')
        info = self._publish(f'captures/{slot:06d}.{stream}', data)
        self.capture_bytes += len(data)
        return info

    def _names(self, path, limit):
        before = path.lstat()
        if (not stat.S_ISDIR(before.st_mode) or
                signature(before)[:3] != self._directories[path]):
            raise ValidationError('invalid_path', 'Bundle directory identity changed')
        names = set()
        with os.scandir(path) as entries:
            for entry in entries:
                if len(names) >= limit:
                    raise ValidationError('resource_limit', 'Bundle directory entry cap exceeded')
                names.add(entry.name)
        if signature(path.lstat()) != signature(before):
            raise ValidationError('unstable_read', 'Bundle directory changed during enumeration')
        return names, signature(before)

    def _inventory(self, checkpoint=None):
        snapshots = {}
        for directory, wanted, limit in (
                (self.root, {'plan.json', 'events', 'captures'}, 3),
                (self.root / 'events', {path.split('/')[1] for path in self._artifacts
                                        if path.startswith('events/')}, MAX_EVENTS),
                (self.root / 'captures', {path.split('/')[1] for path in self._artifacts
                                          if path.startswith('captures/')}, MAX_CAPTURE_FILES)):
            if checkpoint is not None:
                checkpoint()
            names, snapshot = self._names(directory, limit)
            if checkpoint is not None:
                checkpoint()
            if names != wanted:
                raise ValidationError('unexpected_artifact', 'Bundle contains missing or unrecorded entries')
            snapshots[directory] = snapshot
        return snapshots

    def _hash_stable(self, relative, expected, checkpoint=None):
        path = self.root / relative
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise ValidationError('invalid_path', 'Sealed artifacts must be regular files')
        if signature(before) != self._signatures[relative]:
            raise ValidationError('unstable_read', 'Recorded artifact changed before finalization')
        if before.st_size != expected['bytes']:
            raise ValidationError('hash_mismatch', 'Recorded artifact length changed')
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                             getattr(os, 'O_CLOEXEC', 0))
        try:
            opened = os.fstat(descriptor)
            if signature(opened) != signature(before):
                raise ValidationError('unstable_read', 'Recorded artifact changed during open')
            hasher = hashlib.sha256()
            length = 0
            while True:
                if checkpoint is not None:
                    checkpoint()
                chunk = os.read(descriptor, min(65536, expected['bytes'] + 1 - length))
                if not chunk:
                    break
                length += len(chunk)
                if length > expected['bytes']:
                    raise ValidationError('resource_limit', 'Recorded artifact grew during finalization')
                hasher.update(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        named = path.lstat()
        if (signature(opened) != signature(after) or signature(opened) != signature(named) or
                length != opened.st_size):
            raise ValidationError('unstable_read', 'Recorded artifact changed during hashing')
        actual = {'path': relative, 'bytes': length, 'sha256': hasher.hexdigest()}
        if actual != expected:
            raise ValidationError('hash_mismatch', 'Recorded artifact bytes changed')
        return actual

    def seal(self, checkpoint=None, before_link=None):
        """Publish an exhaustive seal only after a bounded stable tree scan.

        ``checkpoint`` may interrupt scanning between bounded reads and files.
        ``before_link`` is the final deadline/cancellation admission decision.
        Once the seal's final hard link exists, later durability/return failures
        cannot retroactively invalidate a structurally complete sealed bundle.
        """
        self._writable()
        if self.last_event_sha256 is None:
            raise ValidationError('missing_record', 'A seal requires at least one event')
        try:
            snapshots = self._inventory(checkpoint=checkpoint)
            files = []
            for relative in sorted(self._artifacts):
                if checkpoint is not None:
                    checkpoint()
                fault_hook('before_seal_hash', self.root / relative)
                files.append(self._hash_stable(relative, self._artifacts[relative], checkpoint=checkpoint))
                fault_hook('after_seal_hash', self.root / relative)
                if checkpoint is not None:
                    checkpoint()
            for path, saved in snapshots.items():
                if checkpoint is not None:
                    checkpoint()
                if signature(path.lstat()) != saved:
                    raise ValidationError('unstable_read', 'Bundle directory changed during finalization')
            for relative, saved in self._signatures.items():
                if checkpoint is not None:
                    checkpoint()
                if signature((self.root / relative).lstat()) != saved:
                    raise ValidationError('unstable_read', 'Bundle artifact changed during finalization')
            seal = {'schema': 'benchinterlace.seal.v1', 'plan_id': self.plan['plan_id'],
                    'last_event_sha256': self.last_event_sha256, 'files': files}
            validate_seal(seal)
            if checkpoint is not None:
                checkpoint()
            def admit():
                # The publisher has introduced its single private seal temporary.
                # Every preexisting name and hashed object must still be intact.
                if checkpoint is not None:
                    checkpoint()
                names, _ = self._names(self.root, 4)
                pending = names - {'plan.json', 'events', 'captures'}
                if (not {'plan.json', 'events', 'captures'} <= names or len(pending) != 1 or
                        not re.fullmatch(r'\.seal\.json\.[0-9a-f]{32}\.tmp', next(iter(pending)))):
                    raise ValidationError('unexpected_artifact', 'Unexpected finalization entry')
                for path, saved in snapshots.items():
                    if checkpoint is not None:
                        checkpoint()
                    if path != self.root and signature(path.lstat()) != saved:
                        raise ValidationError('unstable_read', 'Bundle directory changed before seal admission')
                for relative, saved in self._signatures.items():
                    if checkpoint is not None:
                        checkpoint()
                    if signature((self.root / relative).lstat()) != saved:
                        raise ValidationError('unstable_read', 'Bundle artifact changed before seal admission')
                if before_link is not None:
                    before_link()
            publish_create_only(self.root / 'seal.json', canonical_bytes(seal), before_link=admit)
            self._sealed = True
            return seal
        except BaseException:
            self._failed = True
            raise
