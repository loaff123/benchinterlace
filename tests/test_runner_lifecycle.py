import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from benchinterlace.runner_linux import Cancellation, ExitObservation, collect_slot

HELPER = str(Path(__file__).with_name('owned_helper.py'))

@unittest.skipUnless(sys.platform == 'linux', 'Linux process ownership contract')
class LifecycleTests(unittest.TestCase):
    def collect(self, mode='normal', *args, **kw):
        return collect_slot([sys.executable, HELPER, mode, *args], os.getcwd(), dict(os.environ),
            command_timeout_ns=kw.pop('command_timeout_ns', 2_000_000_000),
            run_deadline_ns=time.perf_counter_ns()+5_000_000_000,
            per_stream_cap=kw.pop('per_stream_cap', 262144), total_remaining=kw.pop('total_remaining', 1048576),
            cancellation=Cancellation(), **kw)

    def test_real_normal_and_byte_capture(self):
        result=self.collect()
        self.assertEqual(result.timing['exit_code'],0)
        self.assertGreater(result.timing['elapsed_ns'],0)
        self.assertEqual(result.timing['issues'],[])
        self.assertEqual(result.cleanup,'completed')
        self.assertEqual(bytes(result.streams['stdout'].data),b'owned payload\n')
        self.assertTrue(all(s.eof for s in result.streams.values()))
        self.assertEqual(bytes(self.collect('bytes').streams['stdout'].data),b'\xff\x00\x1b[31m')

    def test_nonzero_is_retained(self):
        result=self.collect('nonzero')
        self.assertEqual(result.timing['exit_code'],7)
        self.assertIn('nonzero_exit',[x['code'] for x in result.timing['issues']])

    def test_concurrent_flood_and_exact_cap(self):
        result=self.collect('flood')
        self.assertEqual([len(s.data) for s in result.streams.values()],[163840,163840])
        self.assertEqual(result.issues,[])
        exact=self.collect(per_stream_cap=14)
        self.assertFalse(exact.streams['stdout'].truncated)
        self.assertTrue(exact.streams['stdout'].eof)

    def test_cap_and_global_cap_fail_closed(self):
        for kw in ({'per_stream_cap':4096},{'total_remaining':4096}):
            result=self.collect('flood', **kw)
            self.assertIn('output_limit',[x['code'] for x in result.issues])
            self.assertLessEqual(sum(len(s.data) for s in result.streams.values()),kw.get('total_remaining',8192))
            self.assertTrue(any(s.truncated for s in result.streams.values()))

    def test_timeout_term_ignore_and_sentinel(self):
        sentinel=subprocess.Popen([sys.executable, HELPER,'sleep','10'], start_new_session=True)
        try:
            for mode in ('sleep','ignore-term','wait-child'):
                args=('3',) if mode=='sleep' else ()
                result=self.collect(mode,*args,command_timeout_ns=100_000_000)
                self.assertEqual(result.timing['termination'],'timeout')
                self.assertIsNotNone(result.timing['timeout_requested_ns'])
                self.assertEqual(result.cleanup,'completed')
                self.assertIsNone(sentinel.poll())
        finally:
            sentinel.terminate(); sentinel.wait(timeout=3)

    def test_leader_exit_pipe_holder_and_silent_child(self):
        result=self.collect('pipe-child')
        self.assertEqual(result.timing['exit_code'],0)
        self.assertIn('capture_incomplete',[x['code'] for x in result.issues])
        self.assertEqual(result.cleanup,'completed')
        silent=self.collect('silent-child')
        self.assertEqual(silent.cleanup,'completed')
        self.assertEqual(silent.timing['exit_code'],0)
        # No claim that a silent descendant was detected or contained after escape.

    def test_group_signals_precede_reap(self):
        trace=[]
        real_signal=os.killpg; real_reap=os.waitpid
        def send(pid,sig): trace.append(('signal',sig)); return real_signal(pid,sig)
        def reap(pid,flags): trace.append(('reap',flags)); return real_reap(pid,flags)
        with patch('benchinterlace.runner_linux.os.killpg',send), patch('benchinterlace.runner_linux.os.waitpid',reap):
            self.collect()
        self.assertEqual([x[0] for x in trace],['signal','signal','reap'])
        self.assertEqual([x[1] for x in trace[:2]],[signal.SIGTERM,signal.SIGKILL])

    def test_literal_metacharacters(self):
        args=['; touch /tmp/never-run-benchinterlace','$(echo secret)','*','a b']
        result=self.collect('args',*args)
        self.assertEqual(bytes(result.streams['stdout'].data),'\n'.join(args).encode())

    def test_launch_failure_has_no_invented_measurement(self):
        with patch('benchinterlace.runner_linux.subprocess.Popen',side_effect=OSError('owned injected failure')):
            result=self.collect()
        self.assertIsNone(result.timing['elapsed_ns'])
        self.assertIsNone(result.timing['exit_code'])
        self.assertEqual(result.timing['termination'],'launch-failed')

    def test_controller_construction_failure_never_launches(self):
        with patch('benchinterlace.runner_linux.ExitObservation',side_effect=RuntimeError('allocation')):
            with patch('benchinterlace.runner_linux.subprocess.Popen') as launch:
                with self.assertRaises(RuntimeError): self.collect()
                self.assertFalse(launch.called)

    def test_capture_close_failure_preserves_timing(self):
        from benchinterlace.capture import Capture
        original=Capture.close
        def fail_close(capture):
            original(capture)
            raise OSError('injected close failure')
        with patch.object(Capture,'close',fail_close):
            result=self.collect()
        self.assertGreater(result.timing['elapsed_ns'],0)
        self.assertIn('capture_io',[r['code'] for r in result.issues])

    def test_expired_admission_never_launches(self):
        with patch('benchinterlace.runner_linux.subprocess.Popen') as launch:
            result=collect_slot([sys.executable,HELPER,'normal'],os.getcwd(),{},
                command_timeout_ns=100,run_deadline_ns=0,per_stream_cap=10,total_remaining=20,
                cancellation=Cancellation())
        self.assertFalse(launch.called)
        self.assertIsNone(result.timing['elapsed_ns'])
        self.assertIn('run_timeout',[r['code'] for r in result.issues])

    def test_fallback_pipe_close_failures_preserve_timing(self):
        from benchinterlace import runner_linux as runner
        real_popen=subprocess.Popen
        class Pipe:
            def __init__(self,pipe): self.pipe=pipe
            def close(self): self.pipe.close(); raise OSError('injected close')
        def launch(*args,**kw):
            process=real_popen(*args,**kw)
            process.stdout=Pipe(process.stdout); process.stderr=Pipe(process.stderr)
            return process
        with patch.object(runner.subprocess,'Popen',launch), patch.object(runner,'Capture',side_effect=OSError('injected setup')):
            result=self.collect()
        self.assertGreater(result.timing['elapsed_ns'],0)
        self.assertIn('capture_io',[r['code'] for r in result.issues])

    def test_fake_observation_boundary(self):
        observation=ExitObservation(clock=lambda:150)
        observation.publish(0)
        self.assertEqual(observation.snapshot(),(150,0))
        observation.clock=lambda:90000
        self.assertEqual(observation.snapshot(),(150,0))
        self.assertFalse(observation.request_timeout(100,200))
        observation=ExitObservation(clock=lambda:250)
        self.assertTrue(observation.request_timeout(100,200))
        observation.publish(0)
        self.assertEqual(observation.timeout_requested_ns,150)
        self.assertEqual(observation.snapshot(),(250,0))

class OwnershipFaultTests(unittest.TestCase):
    def group(self):
        from types import SimpleNamespace
        from benchinterlace.runner_linux import OwnedGroup
        return OwnedGroup(SimpleNamespace(pid=987654321),ExitObservation())

    def test_ownership_lost_prevents_both_signals(self):
        group=self.group()
        with patch('benchinterlace.runner_linux.os.waitid',side_effect=ChildProcessError),patch('benchinterlace.runner_linux.os.killpg') as send:
            group.signal(signal.SIGTERM); group.signal(signal.SIGKILL)
        self.assertTrue(group.observation.ownership_lost)
        self.assertFalse(send.called)

    def test_esrch_harmless_eperm_unconfirmed(self):
        for error,expected in [(ProcessLookupError(),[]),(PermissionError(),[{'code':'cleanup_unconfirmed'}])]:
            group=self.group()
            with patch('benchinterlace.runner_linux.os.waitid',return_value=None) as probe,patch('benchinterlace.runner_linux.os.killpg',side_effect=error):
                group.signal(signal.SIGTERM)
            self.assertEqual(group.issues,expected)
            self.assertEqual(probe.call_args.args[2],os.WEXITED|os.WNOWAIT|os.WNOHANG)

    def test_signaling_after_reap_or_final_phase_forbidden(self):
        for name in ('reaped','signaling_finished'):
            group=self.group(); setattr(group,name,True)
            with patch('benchinterlace.runner_linux.os.killpg') as send:
                with self.assertRaises(RuntimeError): group.signal(signal.SIGKILL)
            self.assertFalse(send.called)

    def test_decode_normal_signal_and_dump(self):
        from types import SimpleNamespace
        from benchinterlace.runner_linux import _decode
        for kind,code,expected in [(os.CLD_EXITED,7,7),(os.CLD_KILLED,15,-15),(os.CLD_DUMPED,11,-11)]:
            self.assertEqual(_decode(SimpleNamespace(si_code=kind,si_status=code)),expected)

    def test_observer_and_thread_failure_have_bounded_unconfirmed_cleanup(self):
        from types import SimpleNamespace
        from benchinterlace import runner_linux as runner
        class Clock:
            value=0
            def __call__(self): self.value+=100_000_000; return self.value
        class FakeCapture:
            def __init__(self,*args): self.streams={n:runner.Stream(eof=True) for n in ('stdout','stderr')}; self.issues=[]
            eof=True
            def drain(self,seconds): pass
            def close(self): pass
        for fail_start in (False,True):
            process=SimpleNamespace(pid=987654321)
            thread=SimpleNamespace(start=lambda:None,join=lambda **kw:None)
            if fail_start:
                def failure(): raise RuntimeError('injected thread start failure')
                thread.start=failure
            before=len(runner._UNREAPED)
            with patch.object(runner.threading,'Thread',return_value=thread),patch.object(runner.subprocess,'Popen',return_value=process),patch.object(runner,'Capture',FakeCapture),patch.object(runner.os,'waitid',return_value=None),patch.object(runner.os,'killpg') as send,patch.object(runner.os,'waitpid') as reap:
                # Thread failure takes the pipe-close fallback; use harmless wrappers.
                process.stdout=SimpleNamespace(close=lambda:None); process.stderr=SimpleNamespace(close=lambda:None)
                result=runner.collect_slot(['/owned'], '/', {},command_timeout_ns=1_000_000_000,
                    run_deadline_ns=10_000_000_000,per_stream_cap=1,total_remaining=2,
                    cancellation=runner.Cancellation(),clock=Clock())
            self.assertEqual(result.cleanup,'unconfirmed')
            self.assertIsNone(result.timing['elapsed_ns'])
            self.assertEqual(send.call_count,2)
            self.assertFalse(reap.called)
            self.assertEqual(len(runner._UNREAPED),before+1)
            runner._UNREAPED.pop()

    def test_ready_term_ignorer_requires_kill(self):
        from benchinterlace.capture import Capture
        from benchinterlace.runner_linux import Cancellation
        cancellation=Cancellation(); original=Capture.drain
        def ready(capture,seconds):
            original(capture,seconds)
            if b'ready\n' in capture.streams['stdout'].data:
                cancellation.signum=signal.SIGTERM
        with patch.object(Capture,'drain',ready):
            result=collect_slot([sys.executable,HELPER,'ignore-term'],os.getcwd(),dict(os.environ),
                command_timeout_ns=3_000_000_000,run_deadline_ns=time.perf_counter_ns()+5_000_000_000,
                per_stream_cap=100,total_remaining=200,cancellation=cancellation)
        self.assertIn(b'ready\n',result.streams['stdout'].data)
        self.assertEqual(result.timing['exit_code'],-signal.SIGKILL)
        self.assertEqual(result.cleanup,'completed')

    def test_exact_fake_clock_excludes_cleanup_and_late_work(self):
        from types import SimpleNamespace
        from benchinterlace import runner_linux as runner
        class Clock:
            calls=0
            def __call__(self):
                self.calls+=1
                return self.calls*100 if self.calls<=2 else (self.calls-2)*100_000_000
        class Thread:
            def __init__(self,target,**kw): self.target=target
            def start(self): self.target()
            def join(self,**kw): pass
        class FakeCapture:
            def __init__(self,*args): self.streams={n:runner.Stream(eof=True) for n in ('stdout','stderr')}; self.issues=[]
            eof=True
            def drain(self,seconds): pass
            def close(self): pass
        process=SimpleNamespace(pid=987654321)
        info=SimpleNamespace(si_code=os.CLD_EXITED,si_status=0)
        with patch.object(runner.threading,'Thread',Thread),patch.object(runner.subprocess,'Popen',return_value=process),patch.object(runner,'Capture',FakeCapture),patch.object(runner.os,'waitid',return_value=info),patch.object(runner.os,'killpg'),patch.object(runner.os,'waitpid',return_value=(process.pid,0)):
            result=runner.collect_slot(['/owned'], '/', {},command_timeout_ns=10_000_000_000,
                run_deadline_ns=100_000_000_000,per_stream_cap=1,total_remaining=2,
                cancellation=runner.Cancellation(),clock=Clock())
        self.assertEqual(result.timing['elapsed_ns'],100)
        self.assertEqual(result.timing['exit_code'],0)
        self.assertEqual(result.cleanup,'completed')
