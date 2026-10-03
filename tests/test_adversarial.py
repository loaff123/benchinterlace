"""Independent fail-closed integration tests against synthetic inert bundles.

Every mutation is isolated. Re-sealing attacks deliberately repair the byte
chain so semantic validation, rather than an incidental stale digest, must
reject the forged claim. No recorded command is ever executed by these tests.
"""
import copy
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from benchinterlace.bundle import read_bundle
from benchinterlace.eligibility import interpret
from benchinterlace.errors import ValidationError
from benchinterlace import report
from tests.fixtures import encode, load_events, make_bundle, reseal, sha, write_events


class AdversarialTests(unittest.TestCase):
    """Two measured pairs plus a warmup cover every protocol boundary cheaply."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.root = make_bundle(self.home / 'bundle', n=2, warmups=1)

    def tearDown(self):
        self.temp.cleanup()

    def inspect(self):
        return interpret(read_bundle(self.root))

    def rewrite(self, change):
        events = load_events(self.root)
        change(events)
        write_events(self.root, events)
        reseal(self.root)

    def change_plan(self, change):
        plan = json.loads((self.root / 'plan.json').read_bytes())
        change(plan['payload'])
        plan['plan_id'] = 'sha256:' + sha(encode(plan['payload']))
        (self.root / 'plan.json').write_bytes(encode(plan))
        events = load_events(self.root)
        for event in events:
            event['plan_id'] = plan['plan_id']
        write_events(self.root, events)
        reseal(self.root)

    def rejected(self, *, status=None, code=None, report_check=True):
        evidence = self.inspect()
        self.assertNotEqual(evidence.status, 'complete')
        self.assertIsNone(evidence.a)
        self.assertIsNone(evidence.b)
        self.assertTrue(evidence.reasons, 'Rejection must explain itself')
        self.assertLessEqual(len(evidence.reasons), 100)
        for reason in evidence.reasons:
            self.assertLessEqual(len(reason.get('detail', '').encode('utf-8')), 1024)
        if status:
            self.assertEqual(evidence.status, status)
        if code:
            self.assertIn(code, {reason['code'] for reason in evidence.reasons})
        if report_check:
            # Ineligible data must not be sent to an exact worker at all.
            with patch.object(report, 'run_exact', side_effect=AssertionError('ineligible data reached worker')):
                result = report.analyze(self.root)
            self.assertEqual(result['inference_status'], 'withheld')
            self.assertIsNone(result['descriptive'])
            self.assertIsNone(result['test'])
        return evidence

    def final_event(self, events, kind):
        return next(event for event in reversed(events) if event['kind'] == kind)

    def abort(self, events, code):
        events[-1]['data'].update(state='aborted', reasons=[{'code': code}])

    def test_baseline_has_all_warmup_and_measured_slots(self):
        result = self.inspect()
        self.assertEqual(result.status, 'complete')
        self.assertEqual(result.a, [100_000_000, 120_000_000])
        self.assertEqual(result.b, [110_000_000, 130_000_000])
        for phase, planned in [('warmup', 2), ('measured', 4)]:
            self.assertEqual(result.counts[phase], dict(planned=planned, started=planned,
                timed=planned, validated=planned, unstarted=0))

    def test_missing_capture_hash_resealed(self):
        self.rewrite(lambda events: self.final_event(events, 'slot_evidence')['data']['streams']['stdout'].pop('sha256'))
        self.rejected(status='malformed', code='invalid_schema')

    def test_failed_final_fingerprint_differs_from_crash_prefix(self):
        def fail(events):
            final = self.final_event(events, 'fingerprint_check')['data']
            final.update(status='failed', reasons=[{'code': 'input_changed'}])
            final['files'][0]['sha256'] = 'f' * 64
            self.abort(events, 'input_changed')
        self.rewrite(fail)
        failed = self.rejected(status='failed', code='input_changed')
        self.assertEqual(failed.counts['measured']['timed'], 4)
        self.assertIsNotNone(failed.bundle_sha256)
        events = load_events(self.root)
        write_events(self.root, events[:-2])
        (self.root / 'seal.json').unlink()
        crashed = self.rejected(status='incomplete', code='missing_seal')
        self.assertEqual(crashed.counts['measured']['timed'], 4)
        self.assertIsNone(crashed.bundle_sha256)

    def test_unresolved_start_preserves_started_but_not_invented_timing(self):
        events = load_events(self.root)
        last_start = max(i for i, event in enumerate(events) if event['kind'] == 'slot_start')
        write_events(self.root, events[:last_start + 1])
        for path in (self.root / 'captures').glob('000005.*'):
            path.unlink()
        (self.root / 'seal.json').unlink()
        result = self.rejected(status='incomplete', code='execution_outcome_unknown')
        self.assertEqual(result.counts['measured']['started'], 4)
        self.assertEqual(result.counts['measured']['timed'], 3)
        self.assertEqual(result.counts['measured']['unstarted'], 0)

    def test_failed_first_warmup_cannot_be_discarded(self):
        def fail(events):
            timing = next(event for event in events if event['kind'] == 'slot_timing')['data']
            timing.update(exit_code=1, issues=[{'code': 'nonzero_exit'}])
            self.abort(events, 'nonzero_exit')
        self.rewrite(fail)
        self.rejected(status='malformed', code='nonzero_exit')

    def test_assignment_method_cannot_be_replaced_by_alternation(self):
        self.change_plan(lambda payload: payload['assignments'].update(method='alternating-v1'))
        self.rejected(status='malformed')

    def test_rehashed_plan_does_not_reorder_observed_slots(self):
        self.change_plan(lambda payload: payload['assignments']['measured'].__setitem__(0, 'BA'))
        self.rejected(status='malformed', code='order_mismatch')

    def test_untrusted_phase_nulls_counts(self):
        self.rewrite(lambda events: next(event for event in events if event['kind'] == 'slot_start')['data'].update(phase='measured'))
        result = self.rejected(status='malformed', code='order_mismatch')
        self.assertIsNone(result.counts, 'Malformed phase identity cannot expose trustworthy phase counts')

    def test_resealed_pair_success_cannot_hide_changed_output(self):
        changed = b'forged but consistently hashed output\n'
        (self.root / 'captures/000005.stdout').write_bytes(changed)
        def alter(events):
            stream = self.final_event(events, 'slot_evidence')['data']['streams']['stdout']
            stream.update(sha256=sha(changed), retained_bytes=len(changed), observed_bytes=len(changed))
        self.rewrite(alter)
        self.rejected(status='malformed', code='output_mismatch')

    def test_pair_equality_is_within_each_pair_not_across_pairs(self):
        events = load_events(self.root)
        for event in events:
            if event['kind'] != 'slot_evidence':
                continue
            slot = event['data']['slot']
            content = f'pair {slot // 2}\n'.encode()
            path = self.root / f'captures/{slot:06d}.stdout'
            path.write_bytes(content)
            event['data']['streams']['stdout'].update(sha256=sha(content),
                retained_bytes=len(content), observed_bytes=len(content))
        write_events(self.root, events)
        reseal(self.root)
        self.assertEqual(self.inspect().status, 'complete')

    def test_stderr_is_integrity_checked_but_not_equality_checked(self):
        content = b'distinct stderr\x00\xff\x1b[31m'
        (self.root / 'captures/000005.stderr').write_bytes(content)
        def alter(events):
            stream = self.final_event(events, 'slot_evidence')['data']['streams']['stderr']
            stream.update(sha256=sha(content), retained_bytes=len(content), observed_bytes=len(content))
        self.rewrite(alter)
        self.assertEqual(self.inspect().status, 'complete')

    def test_exact_capture_cap_is_not_itself_truncation(self):
        self.change_plan(lambda payload: payload.update(capture_bytes_per_stream=len(b'synthetic output\n')))
        self.assertEqual(self.inspect().status, 'complete')

    def test_frozen_total_capture_cap_enforced_after_reseal(self):
        self.change_plan(lambda payload: payload.update(capture_bytes_total=1))
        self.rejected(status='malformed', code='resource_limit')

    def test_none_mode_allows_different_outputs_and_warns(self):
        self.change_plan(lambda payload: payload.update(output_check={'mode': 'none'}))
        changed = b'no equality claim'
        (self.root / 'captures/000005.stdout').write_bytes(changed)
        def alter(events):
            for event in events:
                if event['kind'] == 'slot_evidence':
                    event['data']['output_check'] = 'not-requested'
                elif event['kind'] == 'pair_check':
                    event['data']['status'] = 'not-requested'
            self.final_event(events, 'slot_evidence')['data']['streams']['stdout'].update(
                sha256=sha(changed), retained_bytes=len(changed), observed_bytes=len(changed))
        self.rewrite(alter)
        result = report.analyze(self.root)
        self.assertEqual(result['inference_status'], 'available')
        self.assertIn('output_not_checked', {warning['code'] for warning in result['warnings']})

    def configure_expected_output(self):
        content = b'synthetic output\n'
        self.change_plan(lambda payload: payload.update(output_check={
            'mode': 'expected-sha256', 'sha256': sha(content), 'bytes': len(content)}))
        def alter(events):
            for event in events:
                if event['kind'] == 'slot_evidence':
                    event['data']['output_check'] = 'passed'
        self.rewrite(alter)

    def test_expected_output_success(self):
        self.configure_expected_output()
        self.assertEqual(self.inspect().status, 'complete')

    def test_expected_output_false_success_rejected(self):
        self.configure_expected_output()
        self.change_plan(lambda payload: payload['output_check'].update(sha256='1' * 64))
        self.rejected(status='malformed', code='output_mismatch')

    def test_expected_output_length_false_success_rejected(self):
        self.configure_expected_output()
        self.change_plan(lambda payload: payload['output_check'].update(bytes=1))
        self.rejected(status='malformed', code='output_mismatch')

    def test_orphan_capture_not_silently_filtered(self):
        (self.root / 'captures/000006.stdout').write_bytes(b'extra successful sample')
        reseal(self.root)
        self.rejected(code='unexpected_artifact')

    def test_late_truncated_event_not_ignored(self):
        path = self.root / 'events/000036.json'
        path.write_bytes(path.read_bytes()[:-8])
        reseal(self.root)
        self.rejected(status='malformed')

    def test_inconsistent_event_filename_not_sorted_into_validity(self):
        (self.root / 'events/000002.json').rename(self.root / 'events/000099.json')
        reseal(self.root)
        self.rejected(status='malformed', code='order_mismatch')

    def test_record_after_terminal_event_rejected(self):
        self.rewrite(lambda events: events.append(copy.deepcopy(events[4])))
        self.rejected(status='malformed', code='order_mismatch')

    def test_extra_successful_slot_before_finalization_rejected(self):
        self.rewrite(lambda events: events.__setitem__(slice(-2, -2), copy.deepcopy(events[24:29])))
        self.rejected(status='malformed')

    def test_resealed_swapped_adjacent_protocol_events_rejected(self):
        def alter(events):
            events[4], events[5] = events[5], events[4]
        self.rewrite(alter)
        self.rejected(status='malformed', code='order_mismatch')

    def test_duplicate_slot_identity_rejected(self):
        def alter(events):
            starts = [event for event in events if event['kind'] == 'slot_start']
            starts[-1]['data'] = copy.deepcopy(starts[-2]['data'])
        self.rewrite(alter)
        self.rejected(status='malformed', code='duplicate_record')

    def test_foreign_event_plan_resealed(self):
        self.rewrite(lambda events: events[-1].update(plan_id='sha256:' + 'f' * 64))
        self.rejected(status='malformed', code='plan_mismatch')

    def test_foreign_seal_plan(self):
        path = self.root / 'seal.json'
        seal = json.loads(path.read_bytes())
        seal['plan_id'] = 'sha256:' + 'f' * 64
        path.write_bytes(encode(seal))
        self.rejected(status='malformed', code='plan_mismatch')

    def test_plan_byte_change_without_rehashed_plan_id(self):
        path = self.root / 'plan.json'
        plan = json.loads(path.read_bytes())
        plan['payload']['workload'] += ' changed'
        path.write_bytes(encode(plan))
        reseal(self.root)
        self.rejected(status='malformed', code='hash_mismatch')

    def test_chain_byte_change_even_with_consistent_seal(self):
        path = self.root / 'events/000035.json'
        event = json.loads(path.read_bytes())
        event['previous_sha256'] = 'f' * 64
        path.write_bytes(encode(event))
        reseal(self.root)
        self.rejected(status='malformed', code='hash_mismatch')

    def test_seal_duplicate_entry(self):
        path = self.root / 'seal.json'
        seal = json.loads(path.read_bytes())
        seal['files'].insert(0, copy.deepcopy(seal['files'][0]))
        path.write_bytes(encode(seal))
        self.rejected(status='malformed', code='duplicate_record')

    def test_seal_unknown_field(self):
        path = self.root / 'seal.json'
        seal = json.loads(path.read_bytes())
        seal['metadata'] = {}
        path.write_bytes(encode(seal))
        self.rejected(status='malformed', code='invalid_schema')

    def test_bundle_snapshot_unchanged_by_analyze_and_verify(self):
        result = report.analyze(self.root)
        saved = self.home / 'report.json'
        saved.write_bytes(encode(result))
        def snapshot():
            records = {}
            for path in [self.root, *self.root.rglob('*'), saved]:
                info = path.lstat()
                records[str(path)] = (stat.S_IFMT(info.st_mode), info.st_size,
                    info.st_mtime_ns, info.st_ctime_ns, path.read_bytes() if path.is_file() else None)
            return records
        before = snapshot()
        self.assertEqual(report.analyze(self.root), result)
        self.assertEqual(report.verify(self.root, saved), result)
        self.assertEqual(snapshot(), before)

    def test_failed_bundle_diagnosis_does_not_repair_unknown_tail(self):
        (self.root / 'events/.private-tmp-tail').write_bytes(b'incomplete publication')
        (self.root / 'seal.json').unlink()
        before = {str(path): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in self.root.rglob('*') if path.is_file()}
        self.rejected(status='malformed')
        report.verify(self.root)
        after = {str(path): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in self.root.rglob('*') if path.is_file()}
        self.assertEqual(after, before)

    def test_rejects_same_user_mutation_during_final_stability_check(self):
        from benchinterlace.bundle import Reader
        stable = Reader.stable
        def mutate_then_check(reader):
            path = self.root / 'captures/000005.stdout'
            path.write_bytes(b'changed after capture was read')
            return stable(reader)
        with patch.object(Reader, 'stable', mutate_then_check):
            result = self.inspect()
        self.assertNotEqual(result.status, 'complete')
        self.assertIn('unstable_read', {reason['code'] for reason in result.reasons})
        self.assertIsNone(result.a)
        self.assertIsNone(result.bundle_sha256)

    def test_analyzer_never_opens_recorded_absolute_input_paths(self):
        recorded = {file['path'] for file in json.loads((self.root / 'plan.json').read_bytes())['payload']['files']}
        opened = []
        real_open = os.open
        def guard(path, *args, **kwargs):
            self.assertNotIn(os.fspath(path), recorded)
            opened.append(os.fspath(path))
            return real_open(path, *args, **kwargs)
        with patch('os.open', side_effect=guard):
            result = report.analyze(self.root)
        self.assertEqual(result['inference_status'], 'available')
        self.assertTrue(opened)

    def test_symlink_root_rejected_before_opening_content(self):
        alias = self.home / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with patch('os.open', side_effect=AssertionError('symlink root content opened')):
            evidence = interpret(read_bundle(alias))
        self.assertEqual(evidence.status, 'malformed')
        self.assertIsNone(evidence.a)

    def test_report_old_version_same_semantics_is_explicitly_unsupported(self):
        result = report.analyze(self.root)
        old = copy.deepcopy(result)
        old['analysis_version'] = '0.0.1'
        saved = self.home / 'report.json'
        saved.write_bytes(encode(old))
        with self.assertRaises(ValidationError) as caught:
            report.verify(self.root, saved)
        self.assertEqual(caught.exception.code, 'unsupported_primitive')

    def test_report_old_version_changed_wording_is_explicitly_unsupported(self):
        result = report.analyze(self.root)
        old = copy.deepcopy(result)
        old['analysis_version'] = '0.0.1'
        old['warnings'][0]['text'] = 'Earlier analysis wording; same assumption warning code.'
        saved = self.home / 'report.json'
        saved.write_bytes(encode(old))
        with self.assertRaises(ValidationError) as caught:
            report.verify(self.root, saved)
        self.assertEqual(caught.exception.code, 'unsupported_primitive')

    def test_report_same_version_changed_wording_is_tampering(self):
        result = report.analyze(self.root)
        result['warnings'][0]['text'] = 'Changed current-version wording.'
        saved = self.home / 'report.json'
        saved.write_bytes(encode(result))
        with self.assertRaises(ValidationError):
            report.verify(self.root, saved)

    def test_report_old_version_cannot_change_exact_tail(self):
        result = report.analyze(self.root)
        result['analysis_version'] = '0.0.1'
        result['test'].update(tail_count=4, p_decimal='1.000000000000')
        saved = self.home / 'report.json'
        saved.write_bytes(encode(result))
        with self.assertRaises(ValidationError):
            report.verify(self.root, saved)

    def test_report_success_cannot_be_reused_for_failed_finalization(self):
        result = report.analyze(self.root)
        saved = self.home / 'report.json'
        saved.write_bytes(encode(result))
        def alter(events):
            final = self.final_event(events, 'fingerprint_check')['data']
            final.update(status='failed', reasons=[{'code': 'input_changed'}])
            final['files'][0]['sha256'] = 'f' * 64
            self.abort(events, 'input_changed')
        self.rewrite(alter)
        with self.assertRaises(ValidationError):
            report.verify(self.root, saved)

    def test_report_success_cannot_be_reused_for_crash_prefix(self):
        result = report.analyze(self.root)
        saved = self.home / 'report.json'
        saved.write_bytes(encode(result))
        events = load_events(self.root)
        last_timer = max(i for i, event in enumerate(events) if event['kind'] == 'slot_timing')
        write_events(self.root, events[:last_timer + 1])
        (self.root / 'seal.json').unlink()
        with self.assertRaises(ValidationError):
            report.verify(self.root, saved)


    def test_resealed_event_sequence_number_not_filename(self):
        path = self.root / 'events/000031.json'
        event = json.loads(path.read_bytes())
        event['seq'] = 30
        path.write_bytes(encode(event))
        reseal(self.root)
        self.rejected(status='malformed', code='order_mismatch')

    def test_completed_slot_count_cannot_invent_missing_evidence(self):
        self.rewrite(lambda events: events[-1]['data'].update(completed_slots=7))
        self.rejected(status='malformed', code='order_mismatch')

    def test_not_run_slots_cannot_hide_already_started_slot(self):
        self.rewrite(lambda events: events[-1]['data'].update(not_run_slots=[5]))
        self.rejected(status='malformed', code='order_mismatch')

    def test_whole_run_timeout_includes_required_cleanup(self):
        # Six 250-ms cleanup grace intervals already exceed this frozen budget.
        self.change_plan(lambda payload: payload.update(run_timeout_ns=1_000_000_000))
        self.rejected(status='malformed', code='run_timeout')

    def test_abort_without_failure_fact_is_not_a_valid_failed_bundle(self):
        self.rewrite(lambda events: events[-1]['data'].update(state='aborted'))
        self.rejected(status='malformed', code='invalid_schema')

    def test_pair_check_mode_cannot_be_downgraded_after_collection(self):
        self.rewrite(lambda events: self.final_event(events, 'pair_check')['data'].update(status='not-requested'))
        self.rejected(status='malformed')

    def test_slot_check_mode_cannot_be_downgraded_after_collection(self):
        self.rewrite(lambda events: self.final_event(events, 'slot_evidence')['data'].update(output_check='not-requested'))
        self.rejected(status='malformed')

    def test_unknown_files_cannot_force_unbounded_directory_inventory(self):
        for index in range(37, 1025):
            (self.root / f'events/{index:06d}.json').write_bytes(b'')
        self.rejected(status='malformed', code='resource_limit')

    def test_capture_directory_inventory_bound(self):
        for index in range(189):
            (self.root / f'captures/extra-{index:06d}').write_bytes(b'')
        self.rejected(status='malformed', code='resource_limit')

    def test_unknown_root_entries_bound(self):
        (self.root / 'one-extra').write_bytes(b'')
        self.rejected(status='malformed', code='resource_limit')

    def test_seal_traversal_does_not_open_outside_bundle(self):
        outside = self.home / 'outside'
        outside.write_bytes(b'private sentinel')
        path = self.root / 'seal.json'
        seal = json.loads(path.read_bytes())
        seal['files'][0]['path'] = '../outside'
        path.write_bytes(encode(seal))
        opened = []
        real_open = os.open
        def guard(name, *args, **kwargs):
            self.assertNotEqual(Path(name).resolve(), outside)
            opened.append(os.fspath(name))
            return real_open(name, *args, **kwargs)
        with patch('os.open', side_effect=guard):
            self.rejected(status='malformed')
        self.assertTrue(opened)

    def test_report_oversize_rejected_with_bounded_diagnostic(self):
        saved = self.home / 'report.json'
        saved.write_bytes(b'x' * (1048576 + 1))
        with self.assertRaises(ValidationError) as caught:
            report.verify(self.root, saved)
        self.assertEqual(caught.exception.code, 'report_mismatch')

    def test_report_symlink_is_not_followed(self):
        result = report.analyze(self.root)
        target = self.home / 'actual-report.json'
        target.write_bytes(encode(result))
        alias = self.home / 'report.json'
        alias.symlink_to(target)
        with self.assertRaises(ValidationError) as caught:
            report.verify(self.root, alias)
        self.assertEqual(caught.exception.code, 'report_mismatch')

    def test_report_fifo_rejected_without_open(self):
        if not hasattr(os, 'mkfifo'):
            self.skipTest('POSIX FIFO unavailable')
        saved = self.home / 'report.json'
        os.mkfifo(saved)
        real_open = os.open
        def guard(name, *args, **kwargs):
            self.assertNotEqual(os.fspath(name), str(saved), 'Report FIFO opened')
            return real_open(name, *args, **kwargs)
        with patch('os.open', side_effect=guard), self.assertRaises(ValidationError) as caught:
            report.verify(self.root, saved)
        self.assertEqual(caught.exception.code, 'report_mismatch')

    def test_report_unknown_field_rejected(self):
        result = report.analyze(self.root)
        result['metadata'] = {}
        saved = self.home / 'report.json'
        saved.write_bytes(encode(result))
        with self.assertRaises(ValidationError) as caught:
            report.verify(self.root, saved)
        self.assertEqual(caught.exception.code, 'report_mismatch')

    def test_report_duplicate_json_key_rejected(self):
        raw = encode(report.analyze(self.root))
        saved = self.home / 'report.json'
        saved.write_bytes(raw.replace(b'{', b'{"test":null,', 1))
        with self.assertRaises(ValidationError) as caught:
            report.verify(self.root, saved)
        self.assertEqual(caught.exception.code, 'report_mismatch')

    def test_report_noncanonical_representation_rejected(self):
        raw = encode(report.analyze(self.root))
        saved = self.home / 'report.json'
        saved.write_bytes(b' ' + raw)
        with self.assertRaises(ValidationError) as caught:
            report.verify(self.root, saved)
        self.assertEqual(caught.exception.code, 'report_mismatch')

    def test_reports_do_not_render_capture_control_bytes(self):
        content = b'UNIQUE-CAPTURE-SENTINEL\x1b[31m\xff'
        events = load_events(self.root)
        for event in events:
            if event['kind'] == 'slot_evidence':
                stream = event['data']['streams']['stdout']
                (self.root / stream['path']).write_bytes(content)
                stream.update(sha256=sha(content), retained_bytes=len(content), observed_bytes=len(content))
        write_events(self.root, events)
        reseal(self.root)
        result = report.analyze(self.root)
        text = report.render_text(result)
        self.assertNotIn('UNIQUE-CAPTURE-SENTINEL', text)
        self.assertNotIn('\x1b', text)
        self.assertEqual(result['inference_status'], 'available')


# Independently enumerated file inventory for n=2 measured pairs and one warmup:
# start/pre-run + 6*(pre/start/timing/evidence/post) + 3 pair checks + final/end.
MISSING_PATHS = ([f'events/{index:06d}.json' for index in range(37)] +
    [f'captures/{slot:06d}.{stream}' for slot in range(6) for stream in ('stdout', 'stderr')] +
    ['seal.json', 'plan.json'])


def add_missing_test(path):
    def test(self):
        (self.root / path).unlink()
        # Replay the full integrity/eligibility boundary; no exact worker needed.
        evidence = self.rejected(report_check=False)
        if path.startswith('captures/') or path == 'seal.json':
            self.assertEqual(evidence.counts['measured']['timed'], 4)
            self.assertEqual(evidence.counts['warmup']['timed'], 2)
    test.__doc__ = f'Missing {path} cannot yield a repaired or filtered vector.'
    name = 'test_missing_' + path.replace('/', '_').replace('.', '_')
    setattr(AdversarialTests, name, test)


for missing_path in MISSING_PATHS:
    add_missing_test(missing_path)


EVENT_MUTATIONS = {
    'unknown_envelope_field': lambda event: event.update(extra=1),
    'unknown_data_field': lambda event: event['data'].update(extra=1),
    'foreign_event_schema': lambda event: event.update(schema='benchinterlace.event.v2'),
    'sequence_boolean': lambda event: event.update(seq=True),
    'elapsed_boolean': lambda event: event['data'].update(elapsed_ns=True),
    'elapsed_float': lambda event: event['data'].update(elapsed_ns=1.0),
    'elapsed_negative': lambda event: event['data'].update(elapsed_ns=-1),
    'elapsed_over_int64': lambda event: event['data'].update(elapsed_ns=1 << 63),
    'elapsed_zero': lambda event: event['data'].update(elapsed_ns=0),
    'elapsed_at_timeout': lambda event: event['data'].update(elapsed_ns=30_000_000_000, elapsed_exceeded_timeout=True),
    'elapsed_past_timeout_flag_false': lambda event: event['data'].update(elapsed_ns=30_000_000_001),
    'elapsed_unknown_with_nonnull_flag': lambda event: event['data'].update(elapsed_ns=None),
    'exit_signal_with_zero_status': lambda event: event['data'].update(termination='signal'),
    'exit_negative_with_normal_termination': lambda event: event['data'].update(exit_code=-9),
    'launch_failure_with_successful_measurement': lambda event: event['data'].update(termination='launch-failed'),
    'timeout_request_cannot_be_erased_by_exit_zero': lambda event: event['data'].update(timeout_requested_ns=1),
    'late_issue_despite_exit_zero': lambda event: event['data'].update(issues=[{'code': 'capture_io'}]),
    'unknown_reason_code': lambda event: event['data'].update(issues=[{'code': 'unknown_failure'}]),
    'unknown_reason_field': lambda event: event['data'].update(issues=[{'code': 'capture_io', 'metadata': {}}]),
    'surrogate_detail': lambda event: event['data'].update(issues=[{'code': 'capture_io', 'detail': '\ud800'}]),
    'nul_detail': lambda event: event['data'].update(issues=[{'code': 'capture_io', 'detail': '\x00'}]),
    'unicode_detail_byte_limit': lambda event: event['data'].update(issues=[{'code': 'capture_io', 'detail': 'λ' * 513}]),
    'excessive_reason_array': lambda event: event['data'].update(issues=[{'code': 'capture_io'}] * 101),
}


def add_event_mutation_test(name, mutation):
    def test(self):
        events = load_events(self.root)
        mutation(self.final_event(events, 'slot_timing'))
        # Preserve an explicitly forged seq rather than repairing it in write_events.
        if name == 'sequence_boolean':
            path = self.root / 'events/000031.json'
            path.write_bytes(encode(self.final_event(events, 'slot_timing')))
            reseal(self.root)
        else:
            write_events(self.root, events)
            reseal(self.root)
        self.rejected()
    setattr(AdversarialTests, 'test_resealed_' + name, test)


for mutation_name, mutation in EVENT_MUTATIONS.items():
    add_event_mutation_test(mutation_name, mutation)


RAW_MUTATIONS = {
    'duplicate_key': lambda raw: raw.replace(b'{', b'{"schema":"benchinterlace.event.v1",', 1),
    'invalid_utf8': lambda raw: raw.replace(b'"exited"', b'"\xff"'),
    'nan_duration': lambda raw: raw.replace(b'"elapsed_ns":120000000', b'"elapsed_ns":NaN'),
    'infinity_duration': lambda raw: raw.replace(b'"elapsed_ns":120000000', b'"elapsed_ns":Infinity'),
    'exponent_duration': lambda raw: raw.replace(b'"elapsed_ns":120000000', b'"elapsed_ns":12e7'),
    'oversized_integer': lambda raw: raw.replace(b'"elapsed_ns":120000000', b'"elapsed_ns":' + b'9' * 1000),
    'trailing_garbage': lambda raw: raw + b'garbage',
    'extra_lf': lambda raw: raw + b'\n',
    'bom': lambda raw: b'\xef\xbb\xbf' + raw,
    'noncanonical_whitespace': lambda raw: b' ' + raw,
    'missing_final_lf': lambda raw: raw[:-1],
    'excess_nesting': lambda raw: b'[' * 13 + b'0' + b']' * 13 + b'\n',
}


def add_raw_mutation_test(name, mutation):
    def test(self):
        # Slot 5 is A in measured BA pair 1: its known duration is 120 ms.
        path = self.root / 'events/000031.json'
        before = path.read_bytes()
        after = mutation(before)
        self.assertNotEqual(after, before, 'Mutation must affect the target bytes')
        path.write_bytes(after)
        reseal(self.root)
        self.rejected(status='malformed')
    setattr(AdversarialTests, 'test_raw_' + name, test)


for mutation_name, mutation in RAW_MUTATIONS.items():
    add_raw_mutation_test(mutation_name, mutation)


STREAM_MUTATIONS = {
    'path_traversal': lambda stream: stream.update(path='captures/../plan.json'),
    'absolute_path': lambda stream: stream.update(path='/tmp/outside'),
    'wrong_slot_path': lambda stream: stream.update(path='captures/000004.stdout'),
    'wrong_stream_path': lambda stream: stream.update(path='captures/000005.stderr'),
    'missing_hash': lambda stream: stream.pop('sha256'),
    'uppercase_hash': lambda stream: stream.update(sha256=stream['sha256'].upper()),
    'invented_hash': lambda stream: stream.update(sha256='0' * 64),
    'invented_length': lambda stream: stream.update(retained_bytes=0),
    'retained_boolean': lambda stream: stream.update(retained_bytes=True),
    'observed_less_than_retained': lambda stream: stream.update(observed_bytes=0),
    'truncated_without_extra_byte': lambda stream: stream.update(truncated=True),
    'extra_byte_with_no_truncation': lambda stream: stream.update(observed_bytes=18),
    'false_eof': lambda stream: stream.update(eof=False),
    'unavailable_with_published_fields': lambda stream: stream.update(state='unavailable', reason={'code': 'capture_io'}),
}


def add_stream_mutation_test(name, mutation):
    def test(self):
        self.rewrite(lambda events: mutation(self.final_event(events, 'slot_evidence')['data']['streams']['stdout']))
        self.rejected()
    setattr(AdversarialTests, 'test_stream_' + name, test)


for mutation_name, mutation in STREAM_MUTATIONS.items():
    add_stream_mutation_test(mutation_name, mutation)


def add_unavailable_test(slot, stream_name):
    def test(self):
        events = load_events(self.root)
        evidence_index = next(i for i, event in enumerate(events)
            if event['kind'] == 'slot_evidence' and event['data']['slot'] == slot)
        event = events[evidence_index]
        event['data']['streams'][stream_name] = {'state': 'unavailable', 'reason': {'code': 'capture_io'}}
        event['data']['issues'] = [{'code': 'capture_io'}]
        event['data']['output_check'] = 'failed'
        # A failed run stops here. A second-slot failure still owes a pair check.
        end_index = evidence_index + 2
        if slot % 2:
            events[end_index]['data'].update(status='failed', reasons=[{'code': 'output_mismatch'}])
            end_index += 1
        ending = copy.deepcopy(events[-2:])
        ending[-1]['data'].update(state='aborted', completed_slots=slot + 1,
            not_run_slots=list(range(slot + 1, 6)), reasons=[{'code': 'capture_io'}])
        write_events(self.root, events[:end_index] + ending)
        for path in (self.root / 'captures').iterdir():
            cap_slot = int(path.name[:6])
            if cap_slot > slot or (cap_slot == slot and path.suffix == '.' + stream_name):
                path.unlink()
        reseal(self.root)
        result = self.rejected(status='failed', code='capture_io')
        self.assertEqual(result.counts['warmup']['timed'], min(slot + 1, 2))
        self.assertEqual(result.counts['measured']['timed'], max(0, slot - 1))
    setattr(AdversarialTests, f'test_unavailable_slot_{slot}_{stream_name}_preserves_timings', test)


for unavailable_slot in (0, 1, 4, 5):
    for unavailable_stream in ('stdout', 'stderr'):
        add_unavailable_test(unavailable_slot, unavailable_stream)


FINGERPRINT_MUTATIONS = {
    'missing_file': lambda data: data['files'].pop(),
    'duplicate_file': lambda data: data['files'].append(copy.deepcopy(data['files'][0])),
    'unknown_id': lambda data: data['files'][0].update(id='unlisted'),
    'changed_hash_claimed_ok': lambda data: data['files'][0].update(sha256='0' * 64),
    'changed_length_claimed_ok': lambda data: data['files'][0].update(bytes=1),
    'unstable_claimed_ok': lambda data: data['files'][0].update(stable_read=False),
    'error_claimed_ok': lambda data: data['files'].__setitem__(0, {'id': 'executable_a', 'error_code': 'capture_io'}),
    'success_with_failure_reason': lambda data: data.update(reasons=[{'code': 'input_changed'}]),
    'failed_without_failure_fact': lambda data: data.update(status='failed'),
    'wrong_stage_slot': lambda data: data.update(slot=5),
    'wrong_order': lambda data: data['files'].reverse(),
}


def add_fingerprint_test(name, mutation):
    def test(self):
        self.rewrite(lambda events: mutation(self.final_event(events, 'fingerprint_check')['data']))
        self.rejected(status='malformed')
    setattr(AdversarialTests, 'test_final_fingerprint_' + name, test)


for mutation_name, mutation in FINGERPRINT_MUTATIONS.items():
    add_fingerprint_test(mutation_name, mutation)


OVERSIZE_FILES = {'plan.json': 65536, 'events/000031.json': 16384,
    'seal.json': 262144, 'captures/000005.stdout': 262144}


def add_oversize_test(path, cap):
    def test(self):
        (self.root / path).write_bytes(b'x' * (cap + 1))
        self.rejected(status='malformed', code='resource_limit')
    setattr(AdversarialTests, 'test_oversize_' + path.replace('/', '_').replace('.', '_'), test)


for oversize_path, cap in OVERSIZE_FILES.items():
    add_oversize_test(oversize_path, cap)


UNKNOWN_FILES = ['unknown', 'events/000000.json.bak', 'captures/000005.stdout.tmp',
    'events/.pending', 'captures/../extra']


def add_unknown_test(path):
    def test(self):
        (self.root / path).write_bytes(b'not recognized')
        self.rejected(status='malformed')
    setattr(AdversarialTests, 'test_unknown_' + path.replace('/', '_').replace('.', '_'), test)


for unknown_path in UNKNOWN_FILES:
    add_unknown_test(unknown_path)


def add_nonregular_test(path, kind):
    def test(self):
        target = self.root / path
        target.unlink()
        if kind == 'symlink':
            outside = self.home / 'outside'
            outside.write_bytes(b'private sentinel; must never be opened')
            target.symlink_to(outside)
        elif kind == 'fifo':
            if not hasattr(os, 'mkfifo'):
                self.skipTest('POSIX FIFO unavailable')
            os.mkfifo(target)
        else:
            target.mkdir()
        opened = []
        real_open = os.open
        def guard(name, *args, **kwargs):
            opened.append(os.fspath(name))
            return real_open(name, *args, **kwargs)
        with patch('os.open', side_effect=guard):
            self.rejected(status='malformed')
        self.assertNotIn(str(target), opened, 'Nonregular content must be rejected before open')
    setattr(AdversarialTests, 'test_' + kind + '_' + path.replace('/', '_').replace('.', '_'), test)


for nonregular_path in ('plan.json', 'events/000031.json', 'captures/000005.stdout', 'seal.json'):
    for nonregular_kind in ('symlink', 'fifo', 'directory'):
        add_nonregular_test(nonregular_path, nonregular_kind)



def add_resealed_missing_event_test(index):
    def test(self):
        self.rewrite(lambda events: events.pop(index))
        self.rejected(report_check=False)
    setattr(AdversarialTests, f'test_resealed_missing_event_{index:06d}', test)


for removed_index in range(37):
    add_resealed_missing_event_test(removed_index)


def add_final_crash_boundary_test(last_index):
    def test(self):
        events = load_events(self.root)
        write_events(self.root, events[:last_index + 1])
        if last_index < 32:
            for path in (self.root / 'captures').glob('000005.*'):
                path.unlink()
        (self.root / 'seal.json').unlink()
        result = self.rejected(status='incomplete', code='missing_seal')
        self.assertEqual(result.counts['measured']['timed'], 4)
        self.assertEqual(result.counts['warmup']['timed'], 2)
        self.assertEqual(result.counts['measured']['started'], 4)
    setattr(AdversarialTests, f'test_final_crash_after_event_{last_index:06d}', test)


for crash_last_index in range(31, 37):
    add_final_crash_boundary_test(crash_last_index)


def add_directory_symlink_test(name):
    def test(self):
        directory = self.root / name
        outside = self.home / ('original-' + name)
        directory.rename(outside)
        directory.symlink_to(outside, target_is_directory=True)
        opened = []
        real_open = os.open
        def guard(path, *args, **kwargs):
            self.assertFalse(os.fspath(path).startswith(str(directory) + os.sep))
            opened.append(os.fspath(path))
            return real_open(path, *args, **kwargs)
        with patch('os.open', side_effect=guard):
            self.rejected(status='malformed')
        self.assertTrue(opened)
    setattr(AdversarialTests, 'test_directory_symlink_' + name + '_does_not_open_content', test)


for directory_name in ('events', 'captures'):
    add_directory_symlink_test(directory_name)


def add_late_failure_test(kind):
    def test(self):
        def alter(events):
            last = self.final_event(events, 'slot_evidence')['data']
            if kind == 'cleanup':
                last.update(cleanup='unconfirmed', issues=[{'code': 'cleanup_unconfirmed'}])
                self.final_event(events, 'pair_check')['data'].update(status='failed', reasons=[{'code': 'cleanup_unconfirmed'}])
                code = 'cleanup_unconfirmed'
            elif kind == 'capture_io':
                last['issues'] = [{'code': 'capture_io'}]
                self.final_event(events, 'pair_check')['data'].update(status='failed', reasons=[{'code': 'capture_io'}])
                code = 'capture_io'
            elif kind == 'output_check':
                last['output_check'] = 'failed'
                self.final_event(events, 'pair_check')['data'].update(status='failed', reasons=[{'code': 'output_mismatch'}])
                code = 'output_mismatch'
            else:
                self.final_event(events, 'pair_check')['data'].update(status='failed', reasons=[{'code': 'output_mismatch'}])
                code = 'output_mismatch'
            self.abort(events, code)
        self.rewrite(alter)
        result = self.rejected(status='failed')
        self.assertEqual(result.counts['measured']['timed'], 4)
        self.assertEqual(result.counts['warmup']['timed'], 2)
    setattr(AdversarialTests, 'test_late_' + kind + '_failure_keeps_last_measurement', test)


for late_failure_kind in ('cleanup', 'capture_io', 'output_check', 'pair_check'):
    add_late_failure_test(late_failure_kind)


if __name__ == '__main__':
    unittest.main()
