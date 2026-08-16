"""Descriptor-first helpers for trusted runtime files and locks."""

import fcntl
import os
import stat
import tempfile
from contextlib import contextmanager


def _open_regular(path, flags, mode=0o640):
    descriptor = os.open(
        path,
        flags | os.O_CLOEXEC | getattr(os, 'O_NOFOLLOW', 0),
        mode,
    )
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_nlink != 1:
            raise OSError('Runtime path must be a regular, singly linked file')
        if flags & os.O_ACCMODE != os.O_RDONLY:
            os.fchmod(descriptor, mode)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


@contextmanager
def file_lock(path, blocking=True, mode=0o640):
    descriptor = _open_regular(path, os.O_RDWR | os.O_CREAT, mode)
    operation = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
    try:
        fcntl.flock(descriptor, operation)
        yield descriptor
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def atomic_write(path, data, mode=0o640):
    directory = os.path.dirname(path) or '.'
    directory_stat = os.lstat(directory)
    if not stat.S_ISDIR(directory_stat.st_mode):
        raise OSError('Runtime parent must be a directory, not a symlink')
    descriptor, temporary_path = tempfile.mkstemp(prefix='.strfrygui-', dir=directory)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), mode)
        os.replace(temporary_path, path)
        directory_descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except Exception:
        try:
            os.unlink(temporary_path)
        except OSError:
            pass
        raise


def read_bounded(path, maximum, encoding='utf-8'):
    descriptor = _open_regular(path, os.O_RDONLY)
    try:
        data = os.read(descriptor, maximum + 1)
        if len(data) > maximum:
            raise OSError('Runtime file exceeds its size limit')
        return data.decode(encoding)
    finally:
        os.close(descriptor)
