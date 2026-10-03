"""Concurrent bounded pipe collection. No decoding, hashing or disk writes."""
from dataclasses import dataclass, field
import os
import selectors
from .constants import MAX_DURATION_NS


@dataclass
class Stream:
    data: bytearray = field(default_factory=bytearray)
    observed: int = 0
    eof: bool = False
    truncated: bool = False


class Capture:
    def __init__(self, process, per_stream_cap, total_remaining):
        self.selector = selectors.DefaultSelector()
        self.streams = {name: Stream() for name in ('stdout', 'stderr')}
        self.per_stream_cap = per_stream_cap
        self.remaining = total_remaining
        self.issues = []
        self.pipes = []
        for name in self.streams:
            pipe = getattr(process, name)
            self.pipes.append(pipe)
            os.set_blocking(pipe.fileno(), False)
            self.selector.register(pipe, selectors.EVENT_READ, name)

    def issue(self, code):
        item = {'code': code}
        if item not in self.issues:
            self.issues.append(item)

    @property
    def eof(self):
        return all(s.eof for s in self.streams.values())

    def drain(self, seconds):
        # One chunk per ready descriptor, followed by an owner deadline check.
        for key, _ in self.selector.select(max(0, seconds)):
            stream = self.streams[key.data]
            try:
                chunk = os.read(key.fd, 65536)
            except BlockingIOError:
                continue
            except OSError:
                self.issue('capture_io')
                self.selector.unregister(key.fileobj)
                continue
            if not chunk:
                stream.eof = True
                self.selector.unregister(key.fileobj)
                continue
            stream.observed = min(MAX_DURATION_NS, stream.observed + len(chunk))
            take = min(len(chunk), self.per_stream_cap - len(stream.data), self.remaining)
            stream.data.extend(chunk[:take])
            self.remaining -= take
            if take < len(chunk):
                stream.truncated = True
                self.issue('output_limit')

    def close(self):
        self.selector.close()
        for pipe in self.pipes:
            pipe.close()
