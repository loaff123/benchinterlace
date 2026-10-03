"""Original filesystem-only planner tests; no declared executable is launched."""
import copy
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

from benchinterlace.canonical import canonical_bytes, digest
from benchinterlace.errors import ValidationError
from benchinterlace.schema import validate_plan


@unittest.skipUnless(sys.platform == 'linux', 'Linux safe-file boundary')
class FingerprintTests(unittest.TestCase):
    def setUp(self):
        try:
            self.f = importlib.import_module('benchinterlace.fingerprint')
        except ModuleNotFoundError as exc:
            self.fail('fingerprint implementation is missing: ' + str(exc))
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'input'
        self.path.write_bytes(b'original\x00\xffbytes')

    def test_streaming_and_buffered_reads_have_literal_digest(self):
        content = self.path.read_bytes()
        record = {'bytes':len(content), 'sha256':hashlib.sha256(content).hexdigest()}
        self.assertEqual(self.f.read_regular(self.path, 100), (None, record))
        self.assertEqual(self.f.read_regular(self.path, 100, buffer=True), (content, record))
        self.path.write_bytes(b'')
        self.assertEqual(self.f.read_regular(self.path, 0, buffer=True),
                         (b'', {'bytes':0, 'sha256':digest(b'')}))

    def test_rejects_symlink_directory_and_fifo_without_blocking(self):
        alias = self.root / 'alias'; alias.symlink_to(self.path)
        fifo = self.root / 'fifo'; os.mkfifo(fifo)
        for path in (alias, fifo, self.root):
            with self.subTest(path=path), self.assertRaises(ValidationError) as cm:
                self.f.read_regular(path, 100)
            self.assertEqual(cm.exception.code, 'invalid_path')

    def test_limit_rejected_before_content_read(self):
        with mock.patch.object(self.f.os, 'read', side_effect=AssertionError('must not read')):
            with self.assertRaises(ValidationError) as cm:
                self.f.read_regular(self.path, 2)
        self.assertEqual(cm.exception.code, 'resource_limit')

    def test_requires_nofollow_and_nonblock_primitives(self):
        for name in ('O_NOFOLLOW', 'O_NONBLOCK'):
            with self.subTest(name=name), mock.patch.object(self.f.os, name, 0):
                with self.assertRaises(ValidationError) as cm:
                    self.f.read_regular(self.path, 100)
                self.assertEqual(cm.exception.code, 'unsupported_primitive')

    def test_open_uses_both_safety_flags(self):
        original_open = os.open
        seen = []
        def opening(path, flags, *args, **kwargs):
            seen.append(flags)
            return original_open(path, flags, *args, **kwargs)
        with mock.patch.object(self.f.os, 'open', side_effect=opening):
            self.f.read_regular(self.path, 100)
        self.assertTrue(seen[0] & os.O_NOFOLLOW)
        self.assertTrue(seen[0] & os.O_NONBLOCK)

    def test_mutation_during_read_fails_closed(self):
        original_read = os.read
        mutated = False
        def reading(fd, count):
            nonlocal mutated
            chunk = original_read(fd, count)
            if chunk and not mutated:
                mutated = True
                self.path.write_bytes(b'replaced contents')
            return chunk
        with mock.patch.object(self.f.os, 'read', side_effect=reading):
            with self.assertRaises(ValidationError) as cm:
                self.f.read_regular(self.path, 100)
        self.assertEqual(cm.exception.code, 'unstable_read')

    def test_named_entry_replacement_during_read_fails_closed(self):
        original_read = os.read
        replaced = False
        def reading(fd, count):
            nonlocal replaced
            chunk = original_read(fd, count)
            if chunk and not replaced:
                replaced = True
                self.path.rename(self.root / 'old')
                self.path.write_bytes(chunk)
            return chunk
        with mock.patch.object(self.f.os, 'read', side_effect=reading):
            with self.assertRaises(ValidationError) as cm:
                self.f.read_regular(self.path, 100)
        self.assertEqual(cm.exception.code, 'unstable_read')

    def test_named_entry_disappearance_during_read_is_unstable(self):
        original_read = os.read
        def reading(fd, count):
            chunk = original_read(fd, count)
            if chunk:
                self.path.unlink()
            return chunk
        with mock.patch.object(self.f.os, 'read', side_effect=reading):
            with self.assertRaises(ValidationError) as cm:
                self.f.read_regular(self.path, 100)
        self.assertEqual(cm.exception.code, 'unstable_read')

    def test_regular_replaced_before_open_is_unstable(self):
        original_open = os.open
        def opening(path, flags, *args, **kwargs):
            self.path.rename(self.root / 'old')
            self.path.write_bytes(b'other')
            return original_open(path, flags, *args, **kwargs)
        with mock.patch.object(self.f.os, 'open', side_effect=opening):
            with self.assertRaises(ValidationError) as cm:
                self.f.read_regular(self.path, 100)
        self.assertEqual(cm.exception.code, 'unstable_read')

    def test_reads_are_chunk_bounded_and_deadlines_checked(self):
        self.path.write_bytes(b'x' * (2 * 65536 + 3))
        original_read = os.read
        counts = []
        checks = []
        def reading(fd, count):
            counts.append(count)
            return original_read(fd, count)
        with mock.patch.object(self.f.os, 'read', side_effect=reading):
            self.f.read_regular(self.path, 200000, lambda: checks.append(True))
        self.assertTrue(all(0 < count <= 65536 for count in counts))
        self.assertGreaterEqual(len(checks), len(counts))

    def test_deadline_exception_propagates_and_descriptor_is_closed(self):
        calls = 0
        def deadline():
            nonlocal calls
            calls += 1
            if calls == 3:
                raise TimeoutError('deadline')
        with mock.patch.object(self.f.os, 'close', wraps=os.close) as close:
            with self.assertRaises(TimeoutError):
                self.f.read_regular(self.path, 100, deadline)
        self.assertEqual(close.call_count, 1)

    def test_all_records_checked_sorted_even_after_missing_or_changed_file(self):
        other = self.root / 'other'; other.write_bytes(b'new')
        records = [
            {'id':'z','path':str(self.path),'bytes':15,'sha256':digest(self.path.read_bytes())},
            {'id':'a','path':str(self.root/'missing'),'bytes':0,'sha256':digest(b'')},
            {'id':'b','path':str(other),'bytes':3,'sha256':digest(b'old')},
        ]
        records[0]['bytes'] = self.path.stat().st_size
        observed, reasons = self.f.fingerprint_records(records)
        self.assertEqual([entry['id'] for entry in observed], ['a','b','z'])
        self.assertIn('error_code', observed[0])
        self.assertEqual(observed[1], {'id':'b','bytes':3,'sha256':digest(b'new'),'stable_read':True})
        self.assertEqual(observed[2]['sha256'], digest(self.path.read_bytes()))
        self.assertTrue(all(reason['code'] == 'input_changed' for reason in reasons))
        self.assertEqual(len(reasons), 2)

    def test_changed_final_path_symlink_is_never_followed(self):
        original = self.path.read_bytes()
        target = self.root/'target'; target.write_bytes(original)
        self.path.unlink(); self.path.symlink_to(target)
        observed, reasons = self.f.fingerprint_records([
            {'id':'input','path':str(self.path),'bytes':len(original),'sha256':digest(original)}])
        self.assertEqual(observed, [{'id':'input','error_code':'invalid_path'}])
        self.assertEqual(reasons[0]['code'], 'invalid_path')


    def test_deadline_records_unchecked_ids_without_losing_real_observations(self):
        entries = [{'id':identifier, 'path':str(self.path), 'bytes':self.path.stat().st_size,
                    'sha256':digest(self.path.read_bytes())} for identifier in ('a','b','c')]
        original = self.f.read_regular
        reads = []
        def limited(path, limit, deadline_check=None, buffer=False):
            reads.append(path)
            if len(reads) == 2:
                raise ValidationError('run_timeout', 'run deadline expired')
            return original(path, limit, deadline_check, buffer)
        with mock.patch.object(self.f, 'read_regular', side_effect=limited):
            observed, reasons = self.f.fingerprint_records(entries)
        self.assertEqual(observed[0]['sha256'], entries[0]['sha256'])
        self.assertEqual(observed[1:], [{'id':'b','error_code':'run_timeout'},
                                      {'id':'c','error_code':'run_timeout'}])
        self.assertEqual([reason['code'] for reason in reasons], ['run_timeout'])
        self.assertEqual(len(reads), 2)

    def test_cancellation_records_current_and_remaining_files(self):
        entries = [{'id':identifier, 'path':str(self.path), 'bytes':0,
                    'sha256':digest(b'')} for identifier in ('b','a')]
        def cancelled():
            raise ValidationError('interrupted', 'signal received')
        observed, reasons = self.f.fingerprint_records(entries, cancelled)
        self.assertEqual(observed, [{'id':'a','error_code':'interrupted'},
                                    {'id':'b','error_code':'interrupted'}])
        self.assertEqual(reasons, [{'code':'interrupted','detail':'signal received'}])


    def test_generic_deadline_filesystem_exception_propagates(self):
        entry = {'id':'input','path':str(self.path),'bytes':self.path.stat().st_size,
                 'sha256':digest(self.path.read_bytes())}
        for error in (PermissionError('callback'), ValidationError('internal_error', 'callback')):
            def deadline():
                raise error
            with self.subTest(error=error), self.assertRaises(type(error)):
                self.f.fingerprint_records([entry], deadline)

    def test_record_batch_enforces_aggregate_actual_bytes(self):
        entries = [{'id':identifier, 'path':str(self.path), 'bytes':self.path.stat().st_size,
                    'sha256':digest(self.path.read_bytes())} for identifier in ('a','b')]
        with mock.patch.object(self.f, 'MAX_INPUT_BYTES', self.path.stat().st_size):
            observed, reasons = self.f.fingerprint_records(entries)
        self.assertEqual(observed[0]['sha256'], entries[0]['sha256'])
        self.assertEqual(observed[1], {'id':'b','error_code':'resource_limit'})
        self.assertEqual(reasons[0]['code'], 'resource_limit')


@unittest.skipUnless(sys.platform == 'linux', 'Linux planner filesystem contract')
class PlannerTests(unittest.TestCase):
    def setUp(self):
        try:
            self.p = importlib.import_module('benchinterlace.plan')
        except ModuleNotFoundError as exc:
            self.fail('planner implementation is missing: ' + str(exc))
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.a = self.root/'a'; self.a.write_bytes(b'original binary A')
        self.b = self.root/'b'; self.b.write_bytes(b'original binary B')
        self.a.chmod(0o700); self.b.chmod(0o700)
        self.data = self.root/'data'; self.data.write_bytes(b'fixture')

    def spec(self):
        return {'schema':'benchinterlace.spec.v1','workload':'original planning fixture',
                'cwd':str(self.root), 'commands':{'A':{'argv':[str(self.a)]},
                'B':{'argv':[str(self.b)]}},'files':[], 'measured_pairs':2,
                'warmup_pairs':0,'alternative':'two-sided',
                'command_timeout_ns':1000000,'run_timeout_ns':1000000000,
                'output_check':{'mode':'equal-within-pair'}}

    def test_plan_has_closed_normalized_contract_and_does_not_mutate_spec(self):
        spec = self.spec(); original = copy.deepcopy(spec)
        plan = self.p.make_plan(spec)
        validate_plan(plan)
        self.assertEqual(spec, original)
        payload = plan['payload']
        self.assertEqual(payload['capture_bytes_per_stream'], 262144)
        self.assertEqual(payload['capture_bytes_total'], 67108864)
        self.assertEqual(payload['command_files'], {'A':'executable_a','B':'executable_b'})
        self.assertEqual(payload['files'], [
            {'id':'executable_a','path':str(self.a),'bytes':17,'sha256':digest(self.a.read_bytes())},
            {'id':'executable_b','path':str(self.b),'bytes':17,'sha256':digest(self.b.read_bytes())}])
        self.assertEqual(plan['plan_id'], 'sha256:' + digest(canonical_bytes(payload)))

    def test_resolves_aliases_once_and_first_declaration_retains_its_id(self):
        cwd_alias = self.root/'cwd-alias'; cwd_alias.symlink_to(self.root, target_is_directory=True)
        a_alias = self.root/'a-alias'; a_alias.symlink_to(self.a)
        data_alias = self.root/'data-alias'; data_alias.symlink_to(self.data)
        spec = self.spec(); spec['cwd'] = str(cwd_alias)
        spec['commands']['B']['argv'][0] = str(a_alias)
        spec['files'] = [{'id':'zeta','path':str(data_alias)}, {'id':'alpha','path':str(self.data)},
                         {'id':'same_executable','path':str(a_alias)}]
        plan = self.p.make_plan(spec); payload = plan['payload']
        self.assertEqual(payload['cwd'], str(self.root))
        self.assertEqual(payload['commands']['B']['argv'], [str(self.a)])
        self.assertEqual(payload['command_files'], {'A':'executable_a','B':'executable_a'})
        self.assertEqual([entry['id'] for entry in payload['files']], ['executable_a','zeta'])
        self.assertEqual(payload['files'][1]['path'], str(self.data))
        data_alias.unlink(); data_alias.symlink_to(self.b)
        self.assertEqual(payload['files'][1]['path'], str(self.data))

    def test_normalizes_only_executable_not_other_literal_arguments(self):
        spec = self.spec()
        literal = ['$(touch harmless)', ';', '*', '../file', '', 'two words', '$HOME', '|']
        spec['commands']['A']['argv'] = [str(self.root) + '/./a', *literal]
        with mock.patch('subprocess.Popen', side_effect=AssertionError('execution forbidden')), \
                mock.patch('os.system', side_effect=AssertionError('shell forbidden')):
            plan = self.p.make_plan(spec)
        self.assertEqual(plan['payload']['commands']['A']['argv'], [str(self.a), *literal])

    def test_no_path_lookup_and_no_shell_string(self):
        for command in ('a', 'a arg', str(self.a)):
            spec = self.spec()
            spec['commands']['A']['argv'] = command if command == str(self.a) else [command]
            with self.subTest(command=command), self.assertRaises(ValidationError):
                self.p.make_plan(spec)

    def test_duplicate_and_reserved_user_ids_fail_before_file_access(self):
        for files in ([{'id':'x','path':str(self.data)}]*2,
                      [{'id':'executable_a','path':str(self.data)}],
                      [{'id':'executable_b','path':str(self.data)}]):
            spec = self.spec(); spec['files'] = files
            with self.subTest(files=files), mock.patch.object(self.p, 'read_regular',
                    side_effect=AssertionError('invalid spec must not read files')):
                with self.assertRaises(ValidationError) as cm:
                    self.p.make_plan(spec)
                self.assertEqual(cm.exception.code, 'duplicate_record')

    def test_invalid_cwd_missing_file_and_file_types_rejected(self):
        fifo = self.root/'fifo'; os.mkfifo(fifo)
        for path in (str(self.root/'missing'), str(self.data), str(fifo)):
            spec = self.spec(); spec['cwd'] = path
            with self.subTest(cwd=path), self.assertRaises((ValidationError, OSError)):
                self.p.make_plan(spec)
        for path in (str(self.root/'missing'), str(self.root), str(fifo)):
            spec = self.spec(); spec['files'] = [{'id':'data','path':path}]
            with self.subTest(file=path), self.assertRaises((ValidationError, OSError)):
                self.p.make_plan(spec)

    def test_non_executable_file_and_direct_shebang_are_rejected(self):
        self.a.chmod(0o600)
        with self.assertRaises(ValidationError):
            self.p.make_plan(self.spec())
        self.a.chmod(0o700)
        self.a.write_bytes(b'#!/an/interpreter\noriginal harmless text\n')
        with self.assertRaises(ValidationError) as cm:
            self.p.make_plan(self.spec())
        self.assertIn('interpreter', cm.exception.detail)

    def test_explicit_interpreter_and_declared_script_are_supported(self):
        script = self.root/'script'; script.write_bytes(b'#!/an/interpreter\npass\n')
        spec = self.spec(); spec['commands']['A']['argv'].append(str(script))
        spec['files'] = [{'id':'script','path':str(script)}]
        plan = self.p.make_plan(spec)
        self.assertIn('script', [entry['id'] for entry in plan['payload']['files']])

    def test_random_bits_are_distinct_unbalanced_draws_with_no_seed_argument(self):
        spec = self.spec(); spec['warmup_pairs'] = 2; spec['measured_pairs'] = 4
        with mock.patch.object(self.p.secrets, 'randbits', side_effect=[0,1,1,1,1,1]) as bits:
            plan = self.p.make_plan(spec)
        self.assertEqual(bits.call_args_list, [mock.call(1)] * 6)
        self.assertEqual(plan['payload']['assignments'], {'method':'independent-os-bits-v1',
            'warmup':['AB','BA'], 'measured':['BA']*4})
        self.assertEqual(list(inspect.signature(self.p.make_plan).parameters), ['spec'])

    def test_resolved_non_unicode_target_is_a_classified_invalid_path(self):
        path = self.root/os.fsdecode(b'nonunicode-\xff')
        path.write_bytes(b'data')
        alias = self.root/'unicode-alias'; alias.symlink_to(path)
        spec = self.spec(); spec['files'] = [{'id':'data','path':str(alias)}]
        with self.assertRaises(ValidationError) as cm:
            self.p.make_plan(spec)
        self.assertEqual(cm.exception.code, 'invalid_path')

    def test_final_file_count_includes_implicit_executables(self):
        spec = self.spec()
        for i in range(63):
            path = self.root/f'file{i}'; path.write_bytes(b'')
            spec['files'].append({'id':f'f{i}','path':str(path)})
        with self.assertRaises(ValidationError) as cm:
            self.p.make_plan(spec)
        self.assertEqual(cm.exception.code, 'resource_limit')

    def test_aggregate_bytes_are_limited_and_duplicates_count_once(self):
        spec = self.spec(); spec['files'] = [{'id':'data','path':str(self.data)}]
        with mock.patch.object(self.p, 'MAX_INPUT_BYTES', 40):
            with self.assertRaises(ValidationError) as cm:
                self.p.make_plan(spec)
        self.assertEqual(cm.exception.code, 'resource_limit')
        spec['commands']['B']['argv'] = [str(self.a)]
        spec['files'] = [{'id':'same','path':str(self.a)}]
        with mock.patch.object(self.p, 'MAX_INPUT_BYTES', 17):
            plan = self.p.make_plan(spec)
        self.assertEqual(len(plan['payload']['files']), 1)

    def test_final_plan_canonical_byte_limit_enforced(self):
        with mock.patch.object(self.p, 'MAX_PLAN_BYTES', 100):
            with self.assertRaises(ValidationError) as cm:
                self.p.make_plan(self.spec())
        self.assertEqual(cm.exception.code, 'resource_limit')

    def test_spec_paths_and_argv_limits_rejected_before_output(self):
        mutations = [lambda s:s.update(seed=1), lambda s:s.update(cwd='relative'),
                     lambda s:s['commands']['A'].update(argv=[str(self.a), 'x'*4097]),
                     lambda s:s['files'].append({'id':'long','path':'/'+'x'*4096})]
        for mutate in mutations:
            spec = self.spec(); mutate(spec)
            with self.subTest(spec=spec), self.assertRaises(ValidationError):
                self.p.make_plan(spec)

    def test_load_plan_requires_canonical_regular_stable_file(self):
        plan = self.p.make_plan(self.spec()); path = self.root/'plan.json'
        raw = canonical_bytes(plan); path.write_bytes(raw)
        self.assertEqual(self.p.load_plan(path), (plan, raw))
        path.write_text(json.dumps(plan))
        with self.assertRaises(ValidationError):
            self.p.load_plan(path)
        path.write_bytes(raw)
        alias = self.root/'plan-alias'; alias.symlink_to(path)
        with self.assertRaises(ValidationError):
            self.p.load_plan(alias)
        changed = copy.deepcopy(plan); changed['payload']['workload'] = 'edited'
        path.write_bytes(canonical_bytes(changed))
        with self.assertRaises(ValidationError) as cm:
            self.p.load_plan(path)
        self.assertEqual(cm.exception.code, 'hash_mismatch')

    def test_publish_reads_ordinary_json_and_is_create_only_private(self):
        path = self.root/'spec.json'; path.write_text(json.dumps(self.spec(), indent=2))
        out = self.root/'plan.json'
        self.p.publish_plan(path, out)
        plan, raw = self.p.load_plan(out)
        self.assertEqual(raw, canonical_bytes(plan))
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
        with self.assertRaises((ValidationError, OSError)):
            self.p.publish_plan(path, out)
        self.assertEqual(out.read_bytes(), raw)
        alias = self.root/'output-alias'; alias.symlink_to(out)
        with self.assertRaises((ValidationError, OSError)):
            self.p.publish_plan(path, alias)
        self.assertEqual(out.read_bytes(), raw)

    def test_invalid_spec_leaves_no_plan_output(self):
        path = self.root/'spec.json'; path.write_bytes(b'{"schema":1,"schema":2}')
        out = self.root/'plan.json'
        with self.assertRaises(ValidationError):
            self.p.publish_plan(path, out)
        self.assertFalse(out.exists())



if __name__ == '__main__':
    unittest.main()
