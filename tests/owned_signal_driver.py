"""Original bounded signal fixtures; no untrusted bundle command is executed here.

The driver wraps real runner APIs only in this test process. Benchmark helpers
have no descendants and use a fixed, approximately three-second work budget. SIGKILL of a
runner cannot promise cleanup: the tests wait for these bounded helpers instead.
"""
import os
from pathlib import Path
import sys
import time
from unittest.mock import patch


def marker(path, content=b'ready\n'):
    with open(path, 'xb') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def helper(mode, ready, finished):
    if mode == 'normal':
        with open(ready, 'ab') as stream:
            stream.write((str(os.getpid()) + '\n').encode('ascii'))
            stream.flush()
            os.fsync(stream.fileno())
        os.write(1, b'owned signal fixture\n')
        return
    if mode == 'bounded-output':
        os.write(1, b'o' * 1024)
        os.write(2, b'e' * 1024)
    marker(ready, (str(os.getpid()) + '\n').encode('ascii'))
    try:
        if mode == 'bounded-sleep':
            time.sleep(3)
        elif mode == 'bounded-output':
            # At most 302 KiB over approximately three seconds, on both streams.
            for unused in range(150):
                os.write(1, b'o' * 1024)
                os.write(2, b'e' * 1024)
                time.sleep(.02)
        else:
            raise ValueError('unknown owned fixture mode')
    except BrokenPipeError:
        # A SIGKILLed runner may close the only readers. Never retry indefinitely.
        pass
    finally:
        marker(finished, b'finished\n')


def run(plan, bundle, boundary, ready):
    # This driver is invoked by absolute repository path, independently of cwd.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from benchinterlace.journal import Journal
    from benchinterlace.runner_linux import Cancellation, run_plan
    cancellation = Cancellation()
    original_append = Journal.append

    def append(journal, kind, data):
        event = original_append(journal, kind, data)
        if boundary == 'slot-start' and kind == 'slot_start':
            marker(ready)
            until = time.monotonic() + 8
            # The durable event is visible before parent sends its signal. KILL
            # pauses before any spawn; INT/TERM are handled by the real runner.
            while cancellation.signum is None:
                if time.monotonic() >= until:
                    raise RuntimeError('parent did not signal owned runner')
                time.sleep(.005)
        return event

    with patch.object(Journal, 'append', append):
        return run_plan(plan, bundle, cancellation=cancellation)


def main():
    mode = sys.argv[1]
    if mode == 'run':
        return run(*sys.argv[2:])
    if mode == 'helper':
        helper(*sys.argv[2:])
        return 0
    if mode == 'sentinel':
        marker(sys.argv[2])
        time.sleep(20)
        return 0
    raise ValueError('unknown owned driver mode')


if __name__ == '__main__':
    raise SystemExit(main())
