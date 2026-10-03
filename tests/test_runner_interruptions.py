"""Signal, cancellation and final-seal boundaries against real Linux execution.

These tests create only their own bounded original helpers. They never scan
processes, signal stored/reused process groups, repair a bundle, or execute a
command extracted from evidence. Each signal targets a live Popen child owned
by the test; the independent sentinel must survive. Runner SIGKILL has no
cleanup guarantee: the before-spawn case has no helper, and running fixtures
are naturally bounded and are allowed to finish without numeric-PID signals.
"""
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from benchinterlace import journal as journal_module
from benchinterlace import publication
from benchinterlace import runner_linux as runner
from benchinterlace.canonical import canonical_bytes
from benchinterlace.journal import Journal
from benchinterlace.plan import make_plan
from benchinterlace.report import analyze, verify


DRIVER = Path(__file__).with_name('owned_signal_driver.py').resolve()
REPOSITORY = DRIVER.parents[1]


class OffsetClock:
    """Keep actual elapsed collection; advance only at a final-seal boundary."""
    def __init__(self):
        self.offset = 0

    def __call__(self):
        return time.perf_counter_ns() + self.offset


@unittest.skipUnless(sys.platform == 'linux', 'Linux signal and ownership contract')
class RunnerInterruptionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def plan(self, name, mode='normal'):
        directory = self.root / name
        directory.mkdir()
        argv = [sys.executable, str(DRIVER), 'helper', mode,
                str(directory / 'helper-ready'), str(directory / 'helper-finished')]
        spec = dict(schema='benchinterlace.spec.v1', workload='Owned interruption fixture',
                    cwd=str(directory), commands={arm: {'argv': argv} for arm in ('A', 'B')},
                    files=[{'id': 'owned-driver', 'path': str(DRIVER)}],
                    measured_pairs=2, warmup_pairs=0, alternative='two-sided',
                    command_timeout_ns=5_000_000_000, run_timeout_ns=30_000_000_000,
                    output_check={'mode': 'equal-within-pair'})
        plan = directory / 'plan.json'
        plan.write_bytes(canonical_bytes(make_plan(spec)))
        return directory, plan, directory / 'bundle'

    def events(self, bundle):
        return [json.loads(path.read_bytes()) for path in sorted((bundle / 'events').glob('*.json'))]

    def snapshot(self, bundle):
        result = {}
        for path in [bundle, *sorted(bundle.rglob('*'))]:
            info = path.lstat()
            result[str(path.relative_to(bundle))] = (
                info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
                hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None)
        return result

    def read_only_report(self, bundle):
        before = self.snapshot(bundle)
        # Offline readers must neither launch workload slots nor re-fingerprint
        # inert executable/input paths from the bundle's saved plan.
        with patch.object(runner, 'collect_slot', side_effect=AssertionError('offline launch')):
            with patch('benchinterlace.fingerprint.fingerprint_records',
                       side_effect=AssertionError('offline source access')):
                report = analyze(bundle)
                self.assertEqual(verify(bundle), report)
        self.assertEqual(self.snapshot(bundle), before)
        return report

    def assert_withheld(self, report, started, timed, evidence_status='failed'):
        self.assertEqual(report['evidence_status'], evidence_status, report['reasons'])
        self.assertEqual(report['inference_status'], 'withheld')
        self.assertIsNone(report['descriptive'])
        self.assertIsNone(report['test'])
        self.assertIsNotNone(report['counts'], report['reasons'])
        counts = report['counts']['measured']
        self.assertEqual(counts['started'], started)
        self.assertEqual(counts['timed'], timed)
        self.assertEqual(counts['unstarted'], 4 - started)

    def wait_marker(self, path, child=None, timeout=8):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            if path.exists() and path.read_bytes().endswith(b'\n'):
                return
            if child is not None and child.poll() is not None:
                self.fail('Owned child exited before synchronization marker: ' + str(child.returncode))
            time.sleep(.005)
        self.fail('Timed out waiting for owned synchronization marker: ' + path.name)

    def stop_child(self, child):
        if child.poll() is None:
            child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)

    def test_real_signals_preserve_durable_prefix_and_unrelated_sentinel(self):
        # Signal timing is determined by a durable marker, never a sleep guess.
        for boundary in ('slot-start', 'bounded-sleep', 'bounded-output'):
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
                with self.subTest(boundary=boundary, signum=signum.name):
                    mode = 'normal' if boundary == 'slot-start' else boundary
                    directory, plan, bundle = self.plan(boundary + '-' + signum.name, mode)
                    sentinel = subprocess.Popen(
                        [sys.executable, str(DRIVER), 'sentinel', str(directory / 'sentinel-ready')],
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, start_new_session=True)
                    child = None
                    try:
                        self.wait_marker(directory / 'sentinel-ready', sentinel)
                        child = subprocess.Popen(
                            [sys.executable, str(DRIVER), 'run', str(plan), str(bundle),
                             boundary, str(directory / 'runner-ready')], cwd=REPOSITORY,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE, start_new_session=True)
                        ready = directory / ('runner-ready' if boundary == 'slot-start' else 'helper-ready')
                        self.wait_marker(ready, child)
                        prefix = {p: p.read_bytes() for p in (bundle / 'events').glob('*.json')}
                        self.assertEqual(sum(json.loads(raw)['kind'] == 'slot_start'
                                             for raw in prefix.values()), 1)
                        # Popen retains ownership; this cannot target a recycled PID.
                        child.send_signal(signum)
                        unused, errors = child.communicate(timeout=8)
                        expected = -signum if signum == signal.SIGKILL else 128 + signum
                        self.assertEqual(child.returncode, expected, errors)
                        self.assertIsNone(sentinel.poll(), 'unrelated owned sentinel was signaled')
                        for path, raw in prefix.items():
                            self.assertEqual(path.read_bytes(), raw, 'durable prefix changed')
                        events = self.events(bundle)
                        starts = [e['data']['slot'] for e in events if e['kind'] == 'slot_start']
                        self.assertEqual(starts, [0], 'cancellation must prevent the next slot')
                        if signum == signal.SIGKILL:
                            self.assertFalse((bundle / 'seal.json').exists())
                            self.assertEqual(events[-1]['kind'], 'slot_start')
                            if boundary == 'slot-start':
                                self.assertFalse((directory / 'helper-ready').exists())
                            else:
                                # No universal cleanup claim for runner SIGKILL.
                                # Wait for the owned bounded helper's own completion.
                                self.wait_marker(directory / 'helper-finished', timeout=6)
                            expected_timed = 0
                        else:
                            timing = next(e['data'] for e in events if e['kind'] == 'slot_timing')
                            self.assertIn('interrupted', {r['code'] for r in timing['issues']})
                            if boundary == 'slot-start':
                                expected_timed = 0
                                self.assertFalse((directory / 'helper-ready').exists())
                                self.assertIsNone(timing['elapsed_ns'])
                                self.assertIsNone(timing['exit_code'])
                                self.assertEqual(timing['termination'], 'unknown')
                            else:
                                expected_timed = 1
                                self.assertEqual(timing['termination'], 'interrupted')
                                if boundary == 'bounded-output':
                                    self.assertGreater((bundle / 'captures/000000.stdout').stat().st_size, 0)
                                    self.assertGreater((bundle / 'captures/000000.stderr').stat().st_size, 0)
                        report = self.read_only_report(bundle)
                        expected_status = 'incomplete' if signum == signal.SIGKILL else 'failed'
                        self.assert_withheld(report, 1, expected_timed, expected_status)
                    finally:
                        if child is not None:
                            self.stop_child(child)
                            if child.stderr is not None:
                                child.stderr.close()
                            if (child.returncode == -signal.SIGKILL and boundary != 'slot-start'
                                    and (directory / 'helper-ready').exists()):
                                self.wait_marker(directory / 'helper-finished', timeout=6)
                        self.stop_child(sentinel)

    def test_cancellation_after_leader_exit_preserves_prior_timed_slots(self):
        directory, plan, bundle = self.plan('after-leader-exit')
        cancellation = runner.Cancellation()
        published = []
        original = runner.ExitObservation.publish

        def publish(observation, code):
            original(observation, code)
            published.append(code)
            if len(published) == 3:
                cancellation(signal.SIGTERM, None)

        with patch.object(runner.ExitObservation, 'publish', publish):
            self.assertEqual(runner.run_plan(plan, bundle, cancellation=cancellation), 143)
        events = self.events(bundle)
        timings = [e['data'] for e in events if e['kind'] == 'slot_timing']
        self.assertEqual(len(timings), 3)
        self.assertEqual([t['exit_code'] for t in timings], [0, 0, 0])
        self.assertTrue(all(t['elapsed_ns'] > 0 for t in timings))
        self.assertIn('interrupted', {r['code'] for r in timings[-1]['issues']})
        self.assertEqual([e['data']['slot'] for e in events if e['kind'] == 'slot_start'], [0, 1, 2])
        self.assert_withheld(self.read_only_report(bundle), 3, 3)

    def test_cancellation_during_post_slot_check_stops_next_slot(self):
        directory, plan, bundle = self.plan('during-check')
        cancellation = runner.Cancellation()
        original = Journal.append
        injected = []

        def append(journal, kind, data):
            result = original(journal, kind, data)
            if kind == 'slot_evidence' and data['slot'] == 2:
                # The next operation is post-slot checking, after both captures
                # and the full timing event are durably retained.
                injected.append(data['slot'])
                cancellation(signal.SIGINT, None)
            return result

        with patch.object(Journal, 'append', append):
            self.assertEqual(runner.run_plan(plan, bundle, cancellation=cancellation), 130)
        self.assertEqual(injected, [2])
        self.assertEqual([e['data']['slot'] for e in self.events(bundle)
                          if e['kind'] == 'slot_start'], [0, 1, 2])
        self.assert_withheld(self.read_only_report(bundle), 3, 3)

    def test_late_capture_io_failure_retains_all_previous_timing(self):
        directory, plan, bundle = self.plan('late-capture-error')
        original = Journal.capture
        reached = []

        def capture(journal, slot, stream, data):
            if slot == 2:
                reached.append((slot, stream))
                raise OSError(errno.ENOSPC, 'owned injected disk-full boundary')
            return original(journal, slot, stream, data)

        with patch.object(Journal, 'capture', capture):
            self.assertEqual(runner.run_plan(plan, bundle), 5)
        self.assertEqual(reached, [(2, 'stdout')])
        self.assertEqual(self.events(bundle)[-1]['kind'], 'slot_timing')
        report = self.read_only_report(bundle)
        self.assert_withheld(report, 3, 3, 'incomplete')
        self.assertEqual(report['counts']['measured']['validated'], 2)

    def test_cancel_and_deadline_before_seal_admission_withhold_inference(self):
        for condition in ('cancel', 'deadline'):
            for boundary in ('finalization', 'inside-temp-fsync', 'before-gate'):
                with self.subTest(condition=condition, boundary=boundary):
                    directory, plan, bundle = self.plan(condition + '-' + boundary)
                    cancellation = runner.Cancellation()
                    clock = OffsetClock()
                    reached = []
                    in_seal_sync = False
                    original_fsync = os.fsync

                    def inject():
                        if not reached:
                            reached.append(boundary)
                            if condition == 'cancel':
                                cancellation(signal.SIGTERM, None)
                            else:
                                clock.offset = 60_000_000_000

                    def journal_hook(stage, path):
                        if boundary == 'finalization' and stage == 'before_seal_hash':
                            inject()

                    def publish_hook(stage, path):
                        nonlocal in_seal_sync
                        if path.name != 'seal.json':
                            return
                        in_seal_sync = stage == 'before_file_fsync'
                        if boundary == 'before-gate' and stage == 'before_link':
                            inject()

                    def fsync(fd):
                        if boundary == 'inside-temp-fsync' and in_seal_sync:
                            inject()
                        return original_fsync(fd)

                    with patch.object(journal_module, 'fault_hook', journal_hook), \
                         patch.object(publication, 'fault_hook', publish_hook), \
                         patch.object(publication.os, 'fsync', fsync):
                        code = runner.run_plan(plan, bundle, cancellation=cancellation, clock=clock)
                    self.assertEqual(reached, [boundary])
                    self.assertEqual(code, 143 if condition == 'cancel' else 3)
                    self.assertFalse((bundle / 'seal.json').exists())
                    temporary_count = 0 if boundary == 'finalization' else 1
                    self.assertEqual(len(list(bundle.glob('.seal.json.*.tmp'))), temporary_count)
                    self.assertEqual(self.events(bundle)[-1]['kind'], 'run_end')
                    status = 'incomplete' if boundary == 'finalization' else 'malformed'
                    self.assert_withheld(self.read_only_report(bundle), 4, 4, status)

    def test_admitted_seal_link_commits_despite_later_cancel_or_deadline(self):
        # The approved cutoff is the observed before-link admission gate. An
        # interruption inside its admitted link or durability tail cannot revoke
        # the complete seal. Process cancellation exit status can still be 143.
        for condition in ('cancel', 'deadline'):
            for boundary in ('inside-admitted-link', 'inside-directory-fsync'):
                with self.subTest(condition=condition, boundary=boundary):
                    directory, plan, bundle = self.plan(condition + '-' + boundary)
                    cancellation = runner.Cancellation()
                    clock = OffsetClock()
                    reached = []
                    seal_directory_sync = False
                    original_link, original_fsync = os.link, os.fsync

                    def inject():
                        if not reached:
                            reached.append(boundary)
                            if condition == 'cancel':
                                cancellation(signal.SIGTERM, None)
                            else:
                                clock.offset = 60_000_000_000

                    def link(source, destination, **kwargs):
                        if boundary == 'inside-admitted-link' and destination == 'seal.json':
                            self.assertFalse((bundle / 'seal.json').exists())
                            inject()
                        return original_link(source, destination, **kwargs)

                    def hook(stage, path):
                        nonlocal seal_directory_sync
                        if path.name == 'seal.json':
                            seal_directory_sync = stage == 'before_publish_dir_fsync'

                    def fsync(fd):
                        if boundary == 'inside-directory-fsync' and seal_directory_sync:
                            self.assertTrue((bundle / 'seal.json').exists())
                            inject()
                        return original_fsync(fd)

                    with patch.object(publication, 'fault_hook', hook), \
                         patch.object(publication.os, 'link', link), \
                         patch.object(publication.os, 'fsync', fsync):
                        code = runner.run_plan(plan, bundle, cancellation=cancellation, clock=clock)
                    self.assertEqual(reached, [boundary])
                    self.assertEqual(code, 143 if condition == 'cancel' else 0)
                    self.assertTrue((bundle / 'seal.json').is_file())
                    self.assertFalse(list(bundle.glob('.seal.json.*.tmp')))
                    report = self.read_only_report(bundle)
                    self.assertEqual(report['evidence_status'], 'complete', report['reasons'])
                    self.assertEqual(report['inference_status'], 'available')
                    self.assertIsNotNone(report['test'])
                    self.assertEqual(report['counts']['measured']['timed'], 4)


if __name__ == '__main__':
    unittest.main()
