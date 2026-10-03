"""Bounded create-only publication with explicit local-filesystem durability.

A failure deliberately retains every name already created. Callers must stop
writing after I/O failure; a temporary tail is evidence, never garbage to repair.
"""
import errno
import os
from pathlib import Path
import secrets

from .constants import (MAX_CAPTURE_BYTES_PER_STREAM, MAX_EVENT_BYTES,
                        MAX_PLAN_BYTES, MAX_SEAL_BYTES)
from .errors import ValidationError

MAX_PUBLICATION_BYTES = max(MAX_CAPTURE_BYTES_PER_STREAM, MAX_EVENT_BYTES,
                            MAX_PLAN_BYTES, MAX_SEAL_BYTES)


def fault_hook(stage, path):
    """Internal injection boundary; production has no fault-control CLI options."""


def _directory_flags():
    if not hasattr(os, 'O_DIRECTORY') or not hasattr(os, 'O_NOFOLLOW'):
        raise ValidationError('unsupported_primitive', 'Directory and no-follow opens are required')
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)


def fsync_directory(path):
    """Synchronize a real directory, refusing a final symlink component."""
    path = Path(path)
    fault_hook('before_directory_open', path)
    descriptor = os.open(path, _directory_flags())
    try:
        fault_hook('after_directory_open', path)
        fault_hook('before_directory_fsync', path)
        os.fsync(descriptor)
        fault_hook('after_directory_fsync', path)
    finally:
        os.close(descriptor)


def publish_create_only(path, data, before_link=None):
    """Publish bounded bytes without replacing any final or temporary name.

    The optional admission callback runs after the temporary is fully written,
    fsynced and closed, immediately before its hard link becomes the final name.
    For a seal, that link is the logical commit. Later fsync/cleanup failures can
    still fail the operation; they do not undo an already published final name.
    """
    if type(data) is not bytes:
        raise ValidationError('invalid_schema', 'Publication requires immutable bytes')
    if len(data) > MAX_PUBLICATION_BYTES:
        raise ValidationError('resource_limit', 'Publication exceeds the artifact byte cap')
    path = Path(path)
    if not path.name or path.name in ('.', '..'):
        raise ValidationError('invalid_path', 'Publication requires a file name')
    temporary = '.' + path.name + '.' + secrets.token_hex(16) + '.tmp'
    descriptor = None
    fault_hook('before_dir_open', path)
    directory = os.open(path.parent, _directory_flags())
    try:
        fault_hook('after_dir_open', path)
        fault_hook('before_temp_open', path)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0),
                             0o600, dir_fd=directory)
        os.fchmod(descriptor, 0o600)
        fault_hook('after_temp_open', path)
        position = 0
        view = memoryview(data)
        while position < len(data):
            fault_hook('before_write', path)
            count = os.write(descriptor, view[position:position + 65536])
            if count <= 0:
                raise OSError(errno.EIO, 'Publication write made no progress')
            position += count
            fault_hook('after_write', path)
        fault_hook('before_file_fsync', path)
        os.fsync(descriptor)
        fault_hook('after_file_fsync', path)
        fault_hook('before_file_close', path)
        closing, descriptor = descriptor, None
        os.close(closing)
        fault_hook('after_file_close', path)
        fault_hook('before_link', path)
        if before_link is not None:
            before_link()
        os.link(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory,
                follow_symlinks=False)
        fault_hook('after_link', path)
        fault_hook('before_publish_dir_fsync', path)
        os.fsync(directory)
        fault_hook('after_publish_dir_fsync', path)
        fault_hook('before_unlink', path)
        os.unlink(temporary, dir_fd=directory)
        fault_hook('after_unlink', path)
        fault_hook('before_cleanup_dir_fsync', path)
        os.fsync(directory)
        fault_hook('after_cleanup_dir_fsync', path)
    finally:
        try:
            if descriptor is not None:
                os.close(descriptor)
        finally:
            os.close(directory)
