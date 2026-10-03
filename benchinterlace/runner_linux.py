"""Linux foreground lifecycle: WNOWAIT observation, pinned group, bounded cleanup.

Only the dedicated CLI owns child reaping. This is not a process sandbox or a
containment claim for daemonized/escaped/credential-changing descendants.
"""
from dataclasses import dataclass
import os
import signal
import subprocess
import threading
import time

from .capture import Capture, Stream
from .constants import MAX_DURATION_NS

DRAIN_NS = 250_000_000
GRACE_NS = 250_000_000
OBSERVE_NS = 1_000_000_000
# Keep stuck/unowned Popen objects alive, avoiding helper/destructor reaping.
_UNREAPED = []


class Cancellation:
    signum = None
    def __call__(self, signum, _frame):
        self.signum = signum


class ExitObservation:
    def __init__(self, clock=time.perf_counter_ns):
        self.clock = clock
        self.lock = threading.Lock()
        self.exit = None
        self.timeout_requested_ns = None
        self.ownership_lost = False
        self.error = None

    def publish(self, code):
        with self.lock:
            if self.exit is None:
                self.exit = (self.clock(), code)

    def snapshot(self):
        with self.lock:
            return self.exit

    def request_timeout(self, start, deadline):
        with self.lock:
            now = self.clock()
            if self.exit is None and now >= deadline:
                if self.timeout_requested_ns is None:
                    self.timeout_requested_ns = max(0, now-start)
                return True
            return False


def _decode(info):
    if info.si_code == os.CLD_EXITED:
        return info.si_status
    if info.si_code in (os.CLD_KILLED, os.CLD_DUMPED):
        return -info.si_status
    raise RuntimeError('Unexpected waitid exit status')


class OwnedGroup:
    def __init__(self, process, observation):
        self.process = process
        self.observation = observation
        self.reaped = False
        self.signaling_finished = False
        self.issues = []
        self.thread = threading.Thread(target=self._observe, daemon=True)

    def _observe(self):
        try:
            info = os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOWAIT)
            self.observation.publish(_decode(info))
        except ChildProcessError:
            self.observation.ownership_lost = True
        except BaseException as error:
            self.observation.error = type(error).__name__

    def signal(self, signum):
        if self.reaped or self.signaling_finished:
            raise RuntimeError('Group signaling after ownership phase')
        if self.observation.ownership_lost:
            return
        try:
            # Nonreaping ownership probe, never an existence/descendant test.
            os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
        except ChildProcessError:
            self.observation.ownership_lost = True
            return
        except OSError:
            self.issues.append({'code': 'cleanup_unconfirmed'})
            return
        try:
            os.killpg(self.process.pid, signum)
        except ProcessLookupError:
            pass
        except OSError:
            self.issues.append({'code': 'cleanup_unconfirmed'})

    def reap(self):
        if not self.signaling_finished:
            raise RuntimeError('Reap before group signaling finished')
        if self.observation.ownership_lost or self.observation.snapshot() is None:
            _UNREAPED.append(self.process)
            return False
        self.thread.join(timeout=0)
        try:
            pid, status = os.waitpid(self.process.pid, os.WNOHANG)
            if pid != self.process.pid:
                _UNREAPED.append(self.process)
                return False
            self.reaped = True
            self.process.returncode = os.waitstatus_to_exitcode(status)
            return True
        except ChildProcessError:
            self.observation.ownership_lost = True
            _UNREAPED.append(self.process)
            return False


@dataclass
class SlotResult:
    timing: dict
    streams: dict
    cleanup: str
    issues: list
    launch_failed: bool = False


def collect_slot(argv, cwd, environment, *, command_timeout_ns, run_deadline_ns,
                 per_stream_cap, total_remaining, cancellation, clock=time.perf_counter_ns):
    """Execute one trusted explicit argv; all elapsed endpoints are exit observations."""
    issues = []
    def issue(code, detail=None):
        item = {'code': code}
        if detail:
            item['detail'] = detail
        if item not in issues:
            issues.append(item)
    observation = ExitObservation(clock)
    group = OwnedGroup(None, observation)
    start = clock()
    if cancellation.signum or start >= run_deadline_ns:
        code='interrupted' if cancellation.signum else 'run_timeout'
        pending=[{'code':code}]
        return SlotResult(dict(elapsed_ns=None,exit_code=None,termination='unknown',
            timeout_requested_ns=None,elapsed_exceeded_timeout=None,issues=pending),
            {name:Stream() for name in ('stdout','stderr')},'completed',pending,True)
    try:
        process = subprocess.Popen(argv, shell=False, cwd=cwd, env=environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True, start_new_session=True)
    except (OSError, ValueError) as error:
        return SlotResult(dict(elapsed_ns=None, exit_code=None, termination='launch-failed',
            timeout_requested_ns=None, elapsed_exceeded_timeout=None,
            issues=[{'code':'launch_failed','detail':type(error).__name__}]),
            {name:Stream() for name in ('stdout','stderr')}, 'completed', [], True)
    group.process = process
    capture = None
    forced = None
    try:
        group.thread.start()
        capture = Capture(process, per_stream_cap, total_remaining)
        while True:
            if cancellation.signum:
                issue('interrupted'); forced = 'interrupted'; break
            if clock() >= run_deadline_ns:
                issue('run_timeout'); forced = 'timeout'; break
            if observation.request_timeout(start, start+command_timeout_ns):
                issue('command_timeout'); forced = 'timeout'; break
            if observation.ownership_lost or observation.error:
                issue('ownership_lost' if observation.ownership_lost else 'internal_error')
                break
            observed = observation.snapshot()
            if observed is not None:
                # The deadline applies to observed elapsed too, even if no timer request won.
                if observed[0]-start >= command_timeout_ns:
                    issue('command_timeout')
                drain_until = clock()+DRAIN_NS
                while not capture.eof and clock() < drain_until:
                    capture.drain(min(.01, max(0, (drain_until-clock())/1e9)))
                    if cancellation.signum:
                        issue('interrupted'); forced='interrupted'; break
                    if clock() >= run_deadline_ns:
                        issue('run_timeout'); forced='timeout'; break
                    if capture.issues:
                        break
                if not capture.eof:
                    issue('capture_incomplete')
                break
            capture.drain(.01)
            if capture.issues:
                break
    except Exception as error:
        issue('internal_error', type(error).__name__)
    finally:
        # Every path after successful Popen enters the same bounded owner cleanup.
        group.signal(signal.SIGTERM)
        grace_until = clock()+GRACE_NS
        while clock() < grace_until:
            delay = min(.01, max(0, (grace_until-clock())/1e9))
            try:
                if capture is not None:
                    capture.drain(delay)
                else:
                    time.sleep(delay)
            except Exception:
                issue('capture_io')
                time.sleep(delay)
        group.signal(signal.SIGKILL)
        group.signaling_finished = True
        until = clock()+OBSERVE_NS
        while observation.snapshot() is None and not observation.ownership_lost and clock() < until:
            try:
                if capture is not None:
                    capture.drain(.01)
                else:
                    time.sleep(.01)
            except Exception:
                issue('capture_io'); time.sleep(.01)
        reaped = group.reap()
        if capture is not None:
            try:
                capture.drain(0)
            except Exception:
                issue('capture_io')
            for record in capture.issues:
                issue(record['code'])
            if not capture.eof:
                issue('capture_incomplete')
            try:
                capture.close()
            except Exception:
                issue('capture_io')
        else:
            for pipe in (process.stdout, process.stderr):
                try:
                    pipe.close()
                except Exception:
                    issue('capture_io')
            issue('capture_incomplete')
    if cancellation.signum:
        issue('interrupted'); forced='interrupted'
    if clock() >= run_deadline_ns:
        issue('run_timeout')
    if observation.ownership_lost:
        issue('ownership_lost')
    for record in group.issues:
        issue(record['code'])
    cleanup = 'completed' if reaped and not group.issues else 'unconfirmed'
    if cleanup != 'completed':
        issue('cleanup_unconfirmed')
    observed = observation.snapshot()
    elapsed, code = (observed[0]-start, observed[1]) if observed else (None, None)
    if elapsed is not None and not 0 <= elapsed <= MAX_DURATION_NS:
        issue('resource_limit', 'Raw elapsed_ns='+str(elapsed)); elapsed=None
    if elapsed == 0:
        issue('invalid_duration')
    if code != 0:
        issue('nonzero_exit' if code is not None else 'execution_outcome_unknown')
    termination = forced or ('exited' if code is not None and code>=0 else 'signal' if code is not None else 'unknown')
    timing = dict(elapsed_ns=elapsed, exit_code=code, termination=termination,
        timeout_requested_ns=observation.timeout_requested_ns,
        elapsed_exceeded_timeout=None if elapsed is None else elapsed>=command_timeout_ns,
        issues=list(issues))
    return SlotResult(timing, capture.streams if capture else {n:Stream() for n in ('stdout','stderr')}, cleanup, issues)

# Imported only on explicit run; analyzer/verify never import this module.
import math
from pathlib import Path
import platform
import sys
from .constants import VERSION, MAX_PLAN_BYTES
from .eligibility import planned_slots
from .errors import ValidationError


def check_plan_copies(original, saved, raw, deadline_check):
    from .fingerprint import read_regular
    for path in (original, saved):
        deadline_check()
        try:
            current, _ = read_regular(path, MAX_PLAN_BYTES, deadline_check, buffer=True)
        except (OSError, ValidationError) as error:
            if isinstance(error, ValidationError) and error.code in {'run_timeout','interrupted'}:
                raise
            raise ValidationError('plan_changed', 'Frozen plan path is unavailable or changed') from error
        if current != raw:
            raise ValidationError('plan_changed', 'Frozen plan bytes changed')


def run_plan(plan_path, output_path, *, cancellation=None, clock=time.perf_counter_ns):
    """Dedicated CLI entry implementation; never resume, repair, or retry an attempt.

    The final seal gate is an observed admission cutoff. An admitted link and its
    durability tail may cross the deadline; a committed artifact is not revoked.
    """
    from .fingerprint import fingerprint_records
    from .plan import load_plan
    from .journal import Journal
    required = ('waitid','WNOWAIT','WEXITED','WNOHANG','P_PID','killpg','O_NOFOLLOW')
    if sys.platform != 'linux' or any(not hasattr(os, name) for name in required):
        return 4
    if threading.current_thread() is not threading.main_thread():
        return 4
    plan, raw = load_plan(plan_path)
    p = plan['payload']
    cancellation = cancellation or Cancellation()
    old_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGCHLD)}
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    signal.signal(signal.SIGINT, cancellation)
    signal.signal(signal.SIGTERM, cancellation)
    environment = dict(os.environ)  # This snapshot is never serialized or hashed.
    reasons = []
    started = []
    completed = 0
    outputs = []
    journal = None
    def add(items):
        for item in items:
            if item not in reasons and len(reasons) < 100:
                reasons.append(item)
    start = clock()  # Immediately before exclusive directory creation.
    deadline = start+p['run_timeout_ns']
    def gate():
        if cancellation.signum:
            raise ValidationError('interrupted', 'Cancellation observed before seal admission')
        if clock() >= deadline:
            raise ValidationError('run_timeout', 'Whole-run observed deadline reached')
    def check(stage, slot=None):
        extra = []
        try:
            check_plan_copies(plan_path, Path(output_path)/'plan.json', raw, gate)
        except ValidationError as error:
            extra.append({'code':error.code})
        files, found = fingerprint_records(p['files'], gate)
        add(extra+found)
        data=dict(stage=stage,slot=slot,files=files,status='failed' if extra or found else 'ok',reasons=extra+found)
        journal.append('fingerprint_check',data)
        return not (extra or found)
    def result_code():
        codes={r['code'] for r in reasons}
        if cancellation.signum:
            return 128+cancellation.signum
        if codes & {'ownership_lost','cleanup_unconfirmed','unsupported_primitive','resource_limit'}:
            return 4
        if codes & {'launch_failed','capture_io','internal_error'}:
            return 5
        return 3 if reasons else 0
    try:
        journal = Journal(output_path, plan, raw)
        slots = planned_slots(p)
        timer = time.get_clock_info('perf_counter')
        journal.append('run_start',dict(runner_version=VERSION,python_version=platform.python_version(),
            platform='linux',machine=platform.machine() or 'unknown',timer_name=timer.implementation,
            timer_resolution_ns=max(1, math.ceil(timer.resolution*1e9)),expected_slots=len(slots)))
        check('pre-run')
        for slot in slots:
            if reasons:
                break
            if not check('pre-slot',slot['slot']):
                break
            try:
                gate()
            except ValidationError as error:
                add([{'code':error.code}]); break
            journal.append('slot_start',slot)
            started.append(slot['slot'])
            collected = collect_slot(p['commands'][slot['arm']]['argv'],p['cwd'],environment,
                command_timeout_ns=p['command_timeout_ns'],run_deadline_ns=deadline,
                per_stream_cap=p['capture_bytes_per_stream'],
                total_remaining=p['capture_bytes_total']-journal.capture_bytes,
                cancellation=cancellation,clock=clock)
            add(collected.timing['issues']); add(collected.issues)
            journal.append('slot_timing',dict(slot=slot['slot'],**collected.timing))
            streams = {}
            for name, capture in collected.streams.items():
                if collected.launch_failed:
                    streams[name]=dict(state='unavailable',reason=collected.timing['issues'][0])
                else:
                    record=journal.capture(slot['slot'],name,bytes(capture.data))
                    streams[name]=dict(state='published',path=record['path'],retained_bytes=record['bytes'],
                        observed_bytes=capture.observed,sha256=record['sha256'],eof=capture.eof,truncated=capture.truncated)
            clean = all(s['state']=='published' and s['eof'] and not s['truncated'] for s in streams.values())
            mode=p['output_check']['mode']
            output_state = 'not-requested' if mode=='none' else 'pending-pair'
            if mode=='expected-sha256':
                expected=p['output_check']; out=streams['stdout']
                correct=clean and out['sha256']==expected['sha256'] and out['retained_bytes']==expected['bytes']
                output_state='passed' if correct else 'failed'
                if not correct:
                    add([{'code':'output_mismatch'}])
            journal.append('slot_evidence',dict(slot=slot['slot'],streams=streams,output_check=output_state,
                cleanup=collected.cleanup,issues=collected.issues))
            completed += 1
            outputs.append((streams,clean and not collected.issues and collected.cleanup=='completed'))
            check('post-slot',slot['slot'])
            if slot['position']==1:
                pair_issues=[]
                passed=all(x[1] for x in outputs[-2:])
                if mode=='equal-within-pair' and passed:
                    a,b=[x[0]['stdout'] for x in outputs[-2:]]
                    passed=(a['sha256'],a['retained_bytes'])==(b['sha256'],b['retained_bytes'])
                if mode=='expected-sha256':
                    passed=passed and output_state=='passed' and not any(r['code']=='output_mismatch' for r in reasons)
                if mode!='none' and not passed:
                    pair_issues=[{'code':'output_mismatch'}]; add(pair_issues)
                status='not-requested' if mode=='none' else ('passed' if passed else 'failed')
                journal.append('pair_check',dict(phase=slot['phase'],pair=slot['pair'],status=status,reasons=pair_issues))
        check('post-run')
        try:
            gate()
        except ValidationError as error:
            add([{'code':error.code}])
        journal.append('run_end',dict(state='aborted' if reasons else 'complete',completed_slots=completed,
            not_run_slots=[s['slot'] for s in slots if s['slot'] not in started],reasons=reasons))
        # Failed attempts may finish their bounded evidence tail after the budget.
        # Successful attempts have a final guard immediately before the seal link.
        journal.seal(checkpoint=gate if not reasons else None, before_link=gate if not reasons else None)
        return result_code()
    except FileExistsError:
        return 2 if journal is None else 5
    except ValidationError as error:
        add([{'code':error.code}])
        return result_code()
    except OSError:
        return 5
    except Exception:
        return 5
    finally:
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)
