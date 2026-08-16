import os

import pytest

from utils.runtime_files import atomic_write, file_lock, read_bounded


def test_lock_rejects_symlink_without_changing_target(tmp_path):
    victim = tmp_path / 'victim'
    victim.write_text('unchanged')
    lock_path = tmp_path / 'unsafe.lock'
    lock_path.symlink_to(victim)

    with pytest.raises(OSError):
        with file_lock(lock_path):
            pass

    assert victim.read_text() == 'unchanged'


def test_atomic_write_replaces_destination_symlink_without_following_it(tmp_path):
    victim = tmp_path / 'victim'
    victim.write_text('unchanged')
    destination = tmp_path / 'policy.json'
    destination.symlink_to(victim)

    atomic_write(destination, b'{"safe":true}')

    assert victim.read_text() == 'unchanged'
    assert destination.is_symlink() is False
    assert destination.read_bytes() == b'{"safe":true}'


def test_bounded_reader_rejects_symlink_and_oversized_file(tmp_path):
    data = tmp_path / 'data'
    data.write_text('123456')
    link = tmp_path / 'link'
    link.symlink_to(data)

    with pytest.raises(OSError):
        read_bounded(link, 10)
    with pytest.raises(OSError, match='size limit'):
        read_bounded(data, 5)


def test_file_lock_is_nonblocking_across_descriptors(tmp_path):
    path = tmp_path / 'operation.lock'

    with file_lock(path):
        with pytest.raises(BlockingIOError):
            with file_lock(path, blocking=False):
                pass

    assert os.stat(path).st_mode & 0o777 == 0o640
