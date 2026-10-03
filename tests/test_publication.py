"""Durability boundaries use original bounded bytes and real temporary files."""
import errno
import importlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from benchinterlace.canonical import canonical_bytes, digest
from benchinterlace.errors import ValidationError
from tests.fixtures import make_plan


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def module(self):
        try:
            return importlib.import_module('benchinterlace.publication')
        except ModuleNotFoundError:
            self.fail('the create-only publication module is missing')

    def test_publish_is_private_and_has_no_temporary_tail(self):
        publisher = self.module()
        target = self.root / 'artifact'
        publisher.publish_create_only(target, b'complete bytes')
        self.assertEqual(target.read_bytes(), b'complete bytes')
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(list(self.root.iterdir()), [target])

    def test_existing_final_and_symlink_are_never_replaced(self):
        publisher = self.module()
        existing = self.root / 'artifact'
        existing.write_bytes(b'old bytes')
        with self.assertRaises(FileExistsError):
            publisher.publish_create_only(existing, b'new bytes')
        self.assertEqual(existing.read_bytes(), b'old bytes')
        alias = self.root / 'alias'
        alias.symlink_to(existing)
        with self.assertRaises(FileExistsError):
            publisher.publish_create_only(alias, b'new bytes')
        self.assertTrue(alias.is_symlink())
        self.assertEqual(existing.read_bytes(), b'old bytes')

    def test_short_writes_are_completed(self):
        publisher = self.module()
        real_write = os.write
        with patch.object(publisher.os, 'write', side_effect=lambda fd, data: real_write(fd, data[:3])):
            publisher.publish_create_only(self.root / 'artifact', b'0123456789')
        self.assertEqual((self.root / 'artifact').read_bytes(), b'0123456789')

    def test_zero_write_and_enospc_preserve_partial_tail(self):
        publisher = self.module()
        for failure in (0, OSError(errno.ENOSPC, 'full')):
            with self.subTest(failure=failure):
                directory = self.root / str(len(list(self.root.iterdir())))
                directory.mkdir()
                real_write = os.write
                calls = 0
                def cut(fd, data):
                    nonlocal calls
                    calls += 1
                    if calls == 1:
                        return real_write(fd, data[:3])
                    if isinstance(failure, Exception):
                        raise failure
                    return failure
                with patch.object(publisher.os, 'write', side_effect=cut):
                    with self.assertRaises(OSError):
                        publisher.publish_create_only(directory / 'artifact', b'0123456789')
                self.assertFalse((directory / 'artifact').exists())
                tails = list(directory.iterdir())
                self.assertEqual(len(tails), 1)
                self.assertEqual(tails[0].read_bytes(), b'012')

    def test_fault_at_each_boundary_preserves_honest_prefix(self):
        publisher = self.module()
        stages = []
        with patch.object(publisher, 'fault_hook', side_effect=lambda stage, path: stages.append(stage)):
            publisher.publish_create_only(self.root / 'probe', b'payload')
        required = {'before_temp_open', 'after_temp_open', 'before_write', 'after_write',
                    'before_file_fsync', 'after_file_fsync', 'before_link', 'after_link',
                    'before_publish_dir_fsync', 'after_publish_dir_fsync', 'before_unlink',
                    'after_unlink', 'before_cleanup_dir_fsync', 'after_cleanup_dir_fsync'}
        self.assertTrue(required <= set(stages))
        for index, cut in enumerate(stages):
            with self.subTest(cut=cut):
                directory = self.root / f'cut-{index}'
                directory.mkdir()
                reached = []
                def stop(stage, path):
                    reached.append(stage)
                    if stage == cut:
                        raise OSError(errno.EIO, 'injected cut')
                with patch.object(publisher, 'fault_hook', side_effect=stop):
                    with self.assertRaises(OSError):
                        publisher.publish_create_only(directory / 'artifact', b'payload')
                final = directory / 'artifact'
                published = 'after_link' in reached
                self.assertEqual(final.exists(), published)
                tails = [entry for entry in directory.iterdir() if entry.name != 'artifact']
                self.assertEqual(len(tails), int('after_temp_open' in reached and 'after_unlink' not in reached))
                for entry in directory.iterdir():
                    self.assertIn(entry.read_bytes(), (b'', b'payload'))
                    self.assertEqual(stat.S_IMODE(entry.stat().st_mode), 0o600)
                if published:
                    self.assertEqual(final.read_bytes(), b'payload')

    def test_pre_link_abort_has_durable_temporary_and_no_final(self):
        publisher = self.module()
        stages = []
        def abort():
            self.assertIn('after_file_fsync', stages)
            self.assertFalse((self.root / 'artifact').exists())
            raise RuntimeError('cancelled before admission')
        with patch.object(publisher, 'fault_hook', side_effect=lambda stage, path: stages.append(stage)):
            with self.assertRaisesRegex(RuntimeError, 'cancelled'):
                publisher.publish_create_only(self.root / 'artifact', b'payload', before_link=abort)
        self.assertNotIn('after_link', stages)
        self.assertEqual([path.read_bytes() for path in self.root.iterdir()], [b'payload'])

    def test_oversized_or_nonbytes_data_is_refused_without_artifacts(self):
        publisher = self.module()
        for value in ('text', bytearray(b'bytes'), b'x' * (publisher.MAX_PUBLICATION_BYTES + 1)):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises((ValidationError, TypeError)):
                    publisher.publish_create_only(self.root / 'artifact', value)
                self.assertEqual(list(self.root.iterdir()), [])

    def test_actual_fsync_link_and_unlink_failures_preserve_prefixes(self):
        publisher = self.module()
        for step in ('file-fsync', 'publish-fsync', 'cleanup-fsync', 'link', 'unlink'):
            with self.subTest(step=step):
                directory = self.root / step
                directory.mkdir()
                real_fsync = os.fsync
                count = 0
                def sync(fd):
                    nonlocal count
                    count += 1
                    if step == {1: 'file-fsync', 2: 'publish-fsync', 3: 'cleanup-fsync'}[count]:
                        raise OSError(errno.ENOSPC, 'no space')
                    real_fsync(fd)
                operation = step if step in ('link', 'unlink') else 'fsync'
                injected = sync if operation == 'fsync' else OSError(errno.ENOSPC, 'no space')
                with patch.object(publisher.os, operation, side_effect=injected):
                    with self.assertRaises(OSError):
                        publisher.publish_create_only(directory / 'artifact', b'payload')
                final = directory / 'artifact'
                self.assertEqual(final.exists(), step in ('publish-fsync', 'cleanup-fsync', 'unlink'))
                tails = [entry for entry in directory.iterdir() if entry != final]
                self.assertEqual(len(tails), int(step != 'cleanup-fsync'))
                for entry in directory.iterdir():
                    self.assertEqual(entry.read_bytes(), b'payload')

    def test_each_short_write_cut_preserves_exact_byte_prefix(self):
        publisher = self.module()
        data = b'0123456789'
        real_write = os.write
        for offset in range(len(data)):
            directory = self.root / str(offset)
            directory.mkdir()
            count = 0
            def cut(fd, chunk):
                nonlocal count
                if count == offset:
                    raise OSError(errno.ENOSPC, 'full')
                count += 1
                return real_write(fd, chunk[:1])
            with patch.object(publisher.os, 'write', side_effect=cut):
                with self.assertRaises(OSError):
                    publisher.publish_create_only(directory / 'artifact', data)
            self.assertFalse((directory / 'artifact').exists())
            self.assertEqual([path.read_bytes() for path in directory.iterdir()], [data[:offset]])

    def test_file_mode_is_owner_read_write_even_with_restrictive_umask(self):
        publisher = self.module()
        previous = os.umask(0o777)
        try:
            publisher.publish_create_only(self.root / 'artifact', b'payload')
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE((self.root / 'artifact').stat().st_mode), 0o600)

    def test_symlink_parent_is_refused(self):
        publisher = self.module()
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            publisher.publish_create_only(alias / 'artifact', b'payload')
        self.assertFalse((self.root / 'artifact').exists())


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.plan = make_plan(n=2)

    def tearDown(self):
        self.temp.cleanup()

    def module(self):
        try:
            return importlib.import_module('benchinterlace.journal')
        except ModuleNotFoundError:
            self.fail('the durable journal module is missing')

    def journal(self, name='run'):
        return self.module().Journal(self.directory / name, self.plan, canonical_bytes(self.plan))

    def start(self, journal):
        return journal.append('run_start', dict(runner_version='test', python_version='test',
            platform='linux', machine='test', timer_name='test', timer_resolution_ns=1,
            expected_slots=4))

    def timing(self, journal, slot=0):
        return journal.append('slot_timing', dict(slot=slot, elapsed_ns=10, exit_code=0,
            termination='exited', timeout_requested_ns=None,
            elapsed_exceeded_timeout=False, issues=[]))

    def test_private_exclusive_root_and_canonical_plan(self):
        journal = self.journal()
        for path in (journal.root, journal.root / 'events', journal.root / 'captures'):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        self.assertEqual((journal.root / 'plan.json').read_bytes(), canonical_bytes(self.plan))
        self.assertEqual(stat.S_IMODE((journal.root / 'plan.json').stat().st_mode), 0o600)
        before = (journal.root / 'plan.json').read_bytes()
        with self.assertRaises(FileExistsError):
            self.journal()
        self.assertEqual((journal.root / 'plan.json').read_bytes(), before)
        alias = self.directory / 'alias'
        alias.symlink_to(journal.root, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            self.journal('alias')
        self.assertTrue(alias.is_symlink())

    def test_plan_mismatch_and_invalid_event_do_not_publish(self):
        module = self.module()
        with self.assertRaises(ValidationError):
            module.Journal(self.directory / 'bad', self.plan, b'{}\n')
        self.assertFalse((self.directory / 'bad').exists())
        journal = self.journal()
        with self.assertRaises(ValidationError):
            journal.append('run_start', {'unknown': True})
        self.assertEqual(list((journal.root / 'events').iterdir()), [])
        self.assertEqual(journal.event_count, 0)

    def test_events_are_canonical_and_chain_exact_bytes(self):
        journal = self.journal()
        first = self.start(journal)
        second = self.timing(journal)
        self.assertEqual(first['previous_sha256'], None)
        self.assertEqual(second['previous_sha256'], digest(canonical_bytes(first)))
        for index, event in enumerate((first, second)):
            raw = (journal.root / 'events' / f'{index:06d}.json').read_bytes()
            self.assertEqual(raw, canonical_bytes(event))
            self.assertEqual(event['seq'], index)
            self.assertEqual(event['plan_id'], self.plan['plan_id'])
        self.assertEqual(journal.event_count, 2)
        self.assertEqual(journal.last_event_sha256, digest(canonical_bytes(second)))

    def test_capture_requires_durable_timing_before_hash_or_write(self):
        journal = self.journal()
        module = self.module()
        with patch.object(module, 'digest', side_effect=AssertionError('early hashing')):
            with self.assertRaises(ValidationError):
                journal.capture(0, 'stdout', b'bytes')
        self.assertEqual(list((journal.root / 'captures').iterdir()), [])
        self.timing(journal)
        info = journal.capture(0, 'stdout', b'bytes')
        self.assertEqual(info, {'path': 'captures/000000.stdout', 'bytes': 5,
                                'sha256': digest(b'bytes')})
        self.assertEqual(journal.capture_bytes, 5)
        self.assertEqual((journal.root / info['path']).read_bytes(), b'bytes')

    def test_timing_authorization_uses_durable_bytes_not_mutated_input_object(self):
        journal = self.journal()
        publisher = importlib.import_module('benchinterlace.publication')
        timing = dict(slot=0, elapsed_ns=10, exit_code=0, termination='exited',
                      timeout_requested_ns=None, elapsed_exceeded_timeout=False, issues=[])
        def change_input(stage, path):
            if stage == 'after_cleanup_dir_fsync' and path.parent.name == 'events':
                timing['slot'] = 1
        with patch.object(publisher, 'fault_hook', side_effect=change_input):
            durable = journal.append('slot_timing', timing)
        self.assertEqual(durable['data']['slot'], 0)
        with self.assertRaises(ValidationError):
            journal.capture(1, 'stdout', b'untimed')
        self.assertEqual(journal.capture(0, 'stdout', b'timed')['bytes'], 5)

    def test_capture_enospc_preserves_durable_timing_and_partial_capture(self):
        journal = self.journal()
        self.start(journal)
        timing = self.timing(journal)
        publisher = importlib.import_module('benchinterlace.publication')
        def cut(stage, path):
            if stage == 'after_write' and path.parent.name == 'captures':
                raise OSError(errno.ENOSPC, 'full')
        with patch.object(publisher, 'fault_hook', side_effect=cut):
            with self.assertRaises(OSError):
                journal.capture(0, 'stdout', b'partial')
        self.assertEqual((journal.root / 'events/000001.json').read_bytes(), canonical_bytes(timing))
        self.assertEqual(journal.event_count, 2)
        self.assertEqual(journal.capture_bytes, 0)
        self.assertFalse((journal.root / 'captures/000000.stdout').exists())
        self.assertEqual([p.read_bytes() for p in (journal.root / 'captures').iterdir()], [b'partial'])

    def test_capture_collision_retains_both_original_and_honest_tail(self):
        journal = self.journal()
        self.timing(journal)
        journal.capture(0, 'stdout', b'original')
        with self.assertRaises(FileExistsError):
            journal.capture(0, 'stdout', b'colliding')
        self.assertEqual((journal.root / 'captures/000000.stdout').read_bytes(), b'original')
        self.assertEqual(sorted(p.read_bytes() for p in (journal.root / 'captures').iterdir()),
                         [b'colliding', b'original'])
        with self.assertRaises(ValidationError):
            journal.seal()

    def test_capture_bounds_and_identity_rejected_before_writes(self):
        journal = self.journal()
        self.timing(journal)
        for args in ((True, 'stdout', b'x'), (4, 'stdout', b'x'),
                     (0, '../evil', b'x'), (0, 'stderr', 'text'),
                     (0, 'stderr', b'x' * (self.plan['payload']['capture_bytes_per_stream'] + 1))):
            with self.subTest(args=(args[0], args[1])):
                with self.assertRaises(ValidationError):
                    journal.capture(*args)
        self.assertEqual(list((journal.root / 'captures').iterdir()), [])

    def test_failed_event_publication_poison_stops_later_writes(self):
        journal = self.journal()
        publisher = importlib.import_module('benchinterlace.publication')
        def cut(stage, path):
            if path.parent.name == 'events' and stage == 'after_link':
                raise OSError(errno.ENOSPC, 'full')
        with patch.object(publisher, 'fault_hook', side_effect=cut):
            with self.assertRaises(OSError):
                self.timing(journal)
        before = {str(p): p.read_bytes() for p in journal.root.rglob('*') if p.is_file()}
        self.assertEqual(journal.event_count, 0)
        for operation in (lambda: self.start(journal),
                          lambda: journal.capture(0, 'stdout', b'x'), journal.seal):
            with self.assertRaises((ValidationError, OSError)):
                operation()
        after = {str(p): p.read_bytes() for p in journal.root.rglob('*') if p.is_file()}
        self.assertEqual(before, after)

    def test_seal_exhaustively_matches_actual_files_and_offline_reader(self):
        from benchinterlace.bundle import read_bundle
        journal = self.journal()
        self.start(journal)
        self.timing(journal)
        journal.capture(0, 'stdout', b'bytes')
        journal.capture(0, 'stderr', b'')
        seal = journal.seal()
        self.assertEqual((journal.root / 'seal.json').read_bytes(), canonical_bytes(seal))
        expected = []
        for path in sorted(journal.root.rglob('*')):
            if path.is_file() and path.name != 'seal.json':
                raw = path.read_bytes()
                expected.append({'path': path.relative_to(journal.root).as_posix(),
                                 'bytes': len(raw), 'sha256': digest(raw)})
        self.assertEqual(seal['files'], sorted(expected, key=lambda item: item['path']))
        self.assertEqual(seal['last_event_sha256'], journal.last_event_sha256)
        self.assertFalse(read_bundle(journal.root).problems)
        with self.assertRaises((ValidationError, FileExistsError)):
            journal.seal()
        with self.assertRaises(ValidationError):
            self.start(journal)

    def test_seal_refuses_extra_files_temporary_tails_mutation_and_symlinks(self):
        changes = ('extra-root', 'extra-event', 'extra-capture', 'temporary',
                   'mutated-plan', 'mutated-event', 'mutated-capture',
                   'symlink-file', 'symlink-directory', 'missing-capture')
        for change in changes:
            with self.subTest(change=change):
                journal = self.journal(change)
                self.start(journal)
                self.timing(journal)
                info = journal.capture(0, 'stdout', b'bytes')
                target = journal.root / info['path']
                if change == 'extra-root':
                    (journal.root / 'unknown').write_bytes(b'x')
                elif change == 'extra-event':
                    (journal.root / 'events/000010.json').write_bytes(b'x')
                elif change == 'extra-capture':
                    (journal.root / 'captures/000001.stdout').write_bytes(b'x')
                elif change == 'temporary':
                    (journal.root / 'captures/.000000.stdout.tail.tmp').write_bytes(b'x')
                elif change == 'mutated-plan':
                    (journal.root / 'plan.json').write_bytes(b'x')
                elif change == 'mutated-event':
                    (journal.root / 'events/000000.json').write_bytes(b'x')
                elif change == 'mutated-capture':
                    target.write_bytes(b'other')
                elif change == 'symlink-file':
                    target.unlink(); target.symlink_to(journal.root / 'plan.json')
                elif change == 'symlink-directory':
                    saved = journal.root / 'saved'
                    (journal.root / 'captures').rename(saved)
                    (journal.root / 'captures').symlink_to(saved, target_is_directory=True)
                else:
                    target.unlink()
                with self.assertRaises((ValidationError, OSError)):
                    journal.seal()
                self.assertFalse((journal.root / 'seal.json').exists())

    def test_creation_fsyncs_parent_and_all_private_directories(self):
        module = self.module()
        publisher = importlib.import_module('benchinterlace.publication')
        synced = []
        real = os.fsync
        def sync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                synced.append((os.fstat(fd).st_dev, os.fstat(fd).st_ino))
            real(fd)
        with patch.object(publisher.os, 'fsync', side_effect=sync):
            journal = self.journal()
        for path in (self.directory, journal.root, journal.root / 'events', journal.root / 'captures'):
            info = path.stat()
            self.assertIn((info.st_dev, info.st_ino), synced)

    def test_root_and_children_modes_survive_restrictive_umask(self):
        previous = os.umask(0o777)
        try:
            try:
                journal = self.journal()
            except OSError as exc:
                self.fail(f'private journal creation must tolerate restrictive umask: {exc}')
        finally:
            os.umask(previous)
        for path in (journal.root, journal.root / 'events', journal.root / 'captures'):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)

    def test_seal_does_not_ignore_mutation_after_a_file_was_hashed(self):
        journal = self.journal()
        self.start(journal)
        self.timing(journal)
        journal.capture(0, 'stdout', b'bytes')
        module = self.module()
        def mutate(stage, path):
            if stage == 'after_seal_hash' and path.name == 'plan.json':
                (journal.root / 'captures/000000.stdout').write_bytes(b'other')
        with patch.object(module, 'fault_hook', side_effect=mutate):
            with self.assertRaises(ValidationError):
                journal.seal()
        self.assertFalse((journal.root / 'seal.json').exists())

    def test_seal_rechecks_objects_before_final_admission(self):
        publisher = importlib.import_module('benchinterlace.publication')
        for change in ('mutated', 'extra'):
            with self.subTest(change=change):
                journal = self.journal(change)
                self.start(journal)
                def mutate(stage, path):
                    if stage == 'before_link' and path.name == 'seal.json':
                        if change == 'mutated':
                            (journal.root / 'plan.json').write_bytes(b'changed')
                        else:
                            (journal.root / 'unknown').write_bytes(b'extra')
                with patch.object(publisher, 'fault_hook', side_effect=mutate):
                    with self.assertRaises(ValidationError):
                        journal.seal()
                self.assertFalse((journal.root / 'seal.json').exists())

    def test_post_link_error_never_rewrites_or_invalidates_complete_seal(self):
        from benchinterlace.bundle import read_bundle
        publisher = importlib.import_module('benchinterlace.publication')
        journal = self.journal()
        self.start(journal)
        def cut(stage, path):
            if stage == 'after_cleanup_dir_fsync' and path.name == 'seal.json':
                raise OSError(errno.EIO, 'after logical commit')
        with patch.object(publisher, 'fault_hook', side_effect=cut):
            with self.assertRaises(OSError):
                journal.seal()
        self.assertTrue((journal.root / 'seal.json').exists())
        self.assertFalse(read_bundle(journal.root).problems)
        self.assertEqual(set(path.name for path in journal.root.iterdir()),
                         {'plan.json', 'events', 'captures', 'seal.json'})

    def test_event_and_total_capture_bounds_fail_before_publication(self):
        module = self.module()
        journal = self.journal()
        with patch.object(module, 'MAX_EVENTS', 0):
            with self.assertRaises(ValidationError):
                self.start(journal)
        self.assertEqual(list((journal.root / 'events').iterdir()), [])
        self.timing(journal)
        journal.plan['payload']['capture_bytes_total'] = 3
        journal.capture(0, 'stdout', b'abc')
        with self.assertRaises(ValidationError):
            journal.capture(0, 'stderr', b'd')
        self.assertFalse((journal.root / 'captures/000000.stderr').exists())

    def test_seal_checkpoint_interrupts_between_capture_hash_chunks(self):
        import inspect
        journal = self.journal()
        self.start(journal)
        self.timing(journal)
        journal.capture(0, 'stdout', b'x' * 262144)
        self.assertIn('checkpoint', inspect.signature(journal.seal).parameters,
                      'seal needs cooperative cancellation during its bounded scan')
        module = self.module()
        capture = (journal.root / 'captures/000000.stdout').stat()
        reads = []
        real_read = os.read
        def read(fd, count):
            result = real_read(fd, count)
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == (capture.st_dev, capture.st_ino):
                reads.append(len(result))
            return result
        def checkpoint():
            if reads:
                raise RuntimeError('interrupted scan')
        with patch.object(module.os, 'read', side_effect=read):
            with self.assertRaisesRegex(RuntimeError, 'interrupted scan'):
                journal.seal(checkpoint=checkpoint)
        self.assertEqual(reads, [65536])
        self.assertFalse((journal.root / 'seal.json').exists())
        self.assertEqual(list(journal.root.glob('.seal.json.*.tmp')), [])
        self.assertEqual((journal.root / 'captures/000000.stdout').stat().st_size, 262144)

    def test_seal_checkpoint_can_abort_before_inventory_io(self):
        import inspect
        journal = self.journal()
        self.start(journal)
        self.assertIn('checkpoint', inspect.signature(journal.seal).parameters)
        module = self.module()
        def checkpoint():
            raise RuntimeError('deadline before inventory')
        with patch.object(module.os, 'scandir', side_effect=AssertionError('late inventory IO')):
            with self.assertRaisesRegex(RuntimeError, 'deadline before inventory'):
                journal.seal(checkpoint=checkpoint)
        self.assertFalse((journal.root / 'seal.json').exists())

    def test_seal_checkpoint_is_never_called_after_final_admission(self):
        import inspect
        journal = self.journal()
        self.start(journal)
        self.assertIn('checkpoint', inspect.signature(journal.seal).parameters)
        admitted = False
        checkpoints = 0
        def checkpoint():
            nonlocal checkpoints
            self.assertFalse(admitted, 'final admission must be the last callback before commit')
            checkpoints += 1
        def admit():
            nonlocal admitted
            admitted = True
        journal.seal(checkpoint=checkpoint, before_link=admit)
        self.assertTrue(admitted)
        self.assertGreater(checkpoints, 1)
        self.assertTrue((journal.root / 'seal.json').exists())

    def test_seal_pre_link_abort_never_commits(self):
        journal = self.journal()
        self.start(journal)
        def abort():
            raise RuntimeError('deadline')
        with self.assertRaisesRegex(RuntimeError, 'deadline'):
            journal.seal(before_link=abort)
        self.assertFalse((journal.root / 'seal.json').exists())
        self.assertEqual(len(list(journal.root.glob('.seal.json.*.tmp'))), 1)


if __name__ == '__main__':
    unittest.main()
