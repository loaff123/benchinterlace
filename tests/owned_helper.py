"""Original bounded, harmless subprocess fixtures. Not benchmark evidence."""
import os
import signal
import subprocess
import sys
import time

mode = sys.argv[1]
if mode == 'normal':
    os.write(1, b'owned payload\n')
elif mode == 'args':
    os.write(1, '\n'.join(sys.argv[2:]).encode())
elif mode == 'sleep':
    time.sleep(float(sys.argv[2]))
elif mode == 'nonzero':
    sys.exit(7)
elif mode == 'flood':
    for _ in range(20):
        os.write(1, b'a' * 8192)
        os.write(2, b'b' * 8192)
elif mode == 'bytes':
    os.write(1, b'\xff\x00\x1b[31m')
elif mode == 'ignore-term':
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    os.write(1, b'ready\n')
    time.sleep(10)
elif mode in ('pipe-child', 'silent-child', 'wait-child'):
    child = subprocess.Popen([sys.executable, __file__, 'sleep', '3'],
        stdout=subprocess.DEVNULL if mode == 'silent-child' else None,
        stderr=subprocess.DEVNULL if mode == 'silent-child' else None)
    os.write(1, str(child.pid).encode() + b'\n')
    if mode == 'wait-child':
        child.wait()
else:
    raise SystemExit('unknown owned fixture')
