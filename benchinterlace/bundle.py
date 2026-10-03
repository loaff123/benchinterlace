"""Bounded, read-only bundle integrity checks. Recorded input paths are inert."""
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
import stat

from .canonical import parse_json, digest
from .schema import validate_plan, validate_event, validate_seal
from .errors import ValidationError

PLAN_CAP=65536
EVENT_CAP=16384
EVENT_TOTAL_CAP=16777216
SEAL_CAP=262144
BUNDLE_CAP=301989888
CAPTURE_CAP=1048576


def signature(s):
    return (s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)


@dataclass
class Bundle:
    plan: dict | None = None
    events: list = field(default_factory=list)
    captures: dict = field(default_factory=dict)
    seal_sha256: str | None = None
    reasons: list = field(default_factory=list)
    problems: list = field(default_factory=list)
    def add(self,code,detail='',category='malformed'):
        r={'code':code}
        if detail: r['detail']=str(detail).encode('utf-8',errors='backslashreplace')[:900].decode('utf-8',errors='ignore')
        if r not in self.reasons and len(self.reasons)<100: self.reasons.append(r)
        self.problems.append(category)
    @property
    def malformed(self): return 'malformed' in self.problems


class Reader:
    def __init__(self,root,bundle):
        self.root=Path(root); self.bundle=bundle; self.records={}; self.snapshots={}; self.total=0; self.directories=set()
    def names(self,path,limit):
        try:
            s=path.lstat()
            if not stat.S_ISDIR(s.st_mode): raise ValidationError('invalid_path','Expected a real directory')
            self.directories.add(path)
            self.snapshots[path]=signature(s)
            result=[]
            with os.scandir(path) as entries:
                for entry in entries:
                    if len(result)>=limit: raise ValidationError('resource_limit','Directory entry limit exceeded')
                    result.append(entry.name)
            return sorted(result)
        except (OSError,ValidationError) as e:
            self.bundle.add(getattr(e,'code','missing_record'),str(e), 'incomplete' if isinstance(e,FileNotFoundError) else 'malformed')
            return []
    def read(self,relative,limit,buffer=True):
        path=self.root/relative
        try:
            before=path.lstat()
            if not stat.S_ISREG(before.st_mode): raise ValidationError('invalid_path','Not a regular file: '+relative)
            if before.st_size>limit or self.total+before.st_size>BUNDLE_CAP: raise ValidationError('resource_limit','File or bundle size limit: '+relative)
            flags=os.O_RDONLY | getattr(os,'O_NOFOLLOW',0) | getattr(os,'O_NONBLOCK',0)
            fd=os.open(path,flags)
            with os.fdopen(fd,'rb') as stream:
                opened=os.fstat(stream.fileno())
                if signature(opened)!=signature(before): raise ValidationError('unstable_read','Changed while opening: '+relative)
                h=hashlib.sha256(); chunks=[]; length=0
                while True:
                    chunk=stream.read(min(65536,limit+1-length))
                    if not chunk: break
                    length+=len(chunk)
                    if length>limit: raise ValidationError('resource_limit','File grew over limit: '+relative)
                    h.update(chunk)
                    if buffer: chunks.append(chunk)
                after=os.fstat(stream.fileno())
            named=path.lstat()
            if signature(opened)!=signature(after) or signature(opened)!=signature(named) or length!=opened.st_size:
                raise ValidationError('unstable_read','Changed while reading: '+relative)
            self.total+=length; self.snapshots[path]=signature(named)
            self.records[relative]={'path':relative,'bytes':length,'sha256':h.hexdigest()}
            return b''.join(chunks) if buffer else self.records[relative]
        except (OSError,ValidationError) as e:
            code=getattr(e,'code','missing_record' if isinstance(e,FileNotFoundError) else 'capture_io')
            self.bundle.add(code,str(e),'incomplete' if isinstance(e,FileNotFoundError) else 'malformed')
            return None
    def stable(self):
        for path,saved in self.snapshots.items():
            try:
                if signature(path.lstat())!=saved: self.bundle.add('unstable_read','Bundle changed during verification')
            except OSError: self.bundle.add('unstable_read','Bundle entry disappeared during verification')


def read_bundle(path):
    """Read bounded evidence without executing or opening any recorded command/input."""
    b=Bundle(); r=Reader(path,b)
    root_names=r.names(r.root,4)
    if r.root not in r.directories: return b
    for name in root_names:
        if name not in {'plan.json','events','captures','seal.json'}: b.add('unexpected_artifact','Unexpected root entry: '+name)
    raw=r.read('plan.json',PLAN_CAP)
    if raw is not None:
        try:
            plan=parse_json(raw,PLAN_CAP,canonical=True); validate_plan(plan); b.plan=plan
        except (ValidationError,ValueError) as e: b.add(getattr(e,'code','invalid_schema'),str(e))
    event_names=r.names(r.root/'events',1024)
    previous=None; aggregate=0
    for index,name in enumerate(event_names):
        if not re.fullmatch(r'[0-9]{6}\.json',name):
            b.add('unexpected_artifact','Unexpected event file: '+name); continue
        if name!=f'{index:06d}.json': b.add('order_mismatch','Events must be contiguous from zero')
        raw=r.read('events/'+name,EVENT_CAP)
        if raw is None: continue
        aggregate+=len(raw)
        if aggregate>EVENT_TOTAL_CAP:
            b.add('resource_limit','Aggregate event byte limit'); break
        try:
            event=parse_json(raw,EVENT_CAP,canonical=True); validate_event(event)
            if event['seq']!=index or name!=f"{event['seq']:06d}.json": b.add('order_mismatch','Sequence/filename mismatch')
            if event['previous_sha256']!=previous: b.add('hash_mismatch','Broken event chain')
            if b.plan and event['plan_id']!=b.plan['plan_id']: b.add('plan_mismatch','Foreign event plan')
            b.events.append(event)
        except (ValidationError,ValueError) as e: b.add(getattr(e,'code','invalid_schema'),str(e))
        previous=digest(raw)
    capture_names=r.names(r.root/'captures',200)
    capture_total=0
    for name in capture_names:
        if not re.fullmatch(r'[0-9]{6}\.(stdout|stderr)',name):
            b.add('unexpected_artifact','Unexpected capture file: '+name); continue
        cap=b.plan['payload']['capture_bytes_per_stream'] if b.plan else CAPTURE_CAP
        info=r.read('captures/'+name,cap,False)
        if info:
            b.captures['captures/'+name]=info; capture_total+=info['bytes']
    total_cap=b.plan['payload']['capture_bytes_total'] if b.plan else 268435456
    if capture_total>total_cap: b.add('resource_limit','Total capture bytes exceed frozen cap')
    if 'seal.json' not in root_names:
        b.add('missing_seal','No terminal seal','incomplete')
    else:
        raw=r.read('seal.json',SEAL_CAP)
        if raw is not None:
            try:
                seal=parse_json(raw,SEAL_CAP,canonical=True); validate_seal(seal)
                if b.plan and seal['plan_id']!=b.plan['plan_id']: b.add('plan_mismatch','Seal plan mismatch')
                if seal['last_event_sha256']!=previous: b.add('hash_mismatch','Seal final event mismatch')
                actual=[r.records[k] for k in sorted(r.records) if k!='seal.json']
                listed={x['path'] for x in seal['files']}; present={x['path'] for x in actual}
                if listed-present:
                    b.add('missing_record','Sealed files are missing','incomplete')
                if present-listed: b.add('unexpected_artifact','Files absent from seal')
                actual_map={x['path']:x for x in actual}
                for item in seal['files']:
                    if item['path'] in actual_map and item!=actual_map[item['path']]: b.add('hash_mismatch','Seal content mismatch: '+item['path'])
                if not b.problems: b.seal_sha256=digest(raw)
            except (ValidationError,ValueError) as e: b.add(getattr(e,'code','invalid_schema'),str(e))
    r.stable()
    if b.problems: b.seal_sha256=None
    return b
