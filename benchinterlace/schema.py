"""Closed v1 inventories and handwritten bounded validators.

The same declarative inventories produce the checked-in JSON Schema documents.
The runtime implements only this module's small fixed rule set, never schemas
supplied by a bundle. JSON Schema describes shape; pure cross-field checks below
add identities, normalized paths, arithmetic, and field-dependent byte limits.
Recorded paths are inert POSIX text. No validator opens or resolves a path.
"""
import math
import posixpath
import re

from .canonical import canonical_bytes, digest
from .constants import *
from .errors import ValidationError


def _object(properties, optional=()):
    return {'type':'object', 'properties':properties,
            'required':[key for key in properties if key not in optional],
            'additionalProperties':False}


def _array(items, minimum=0, maximum=MAX_REASONS):
    return {'type':'array', 'items':items, 'minItems':minimum, 'maxItems':maximum}


def _int(minimum=0, maximum=MAX_DURATION_NS):
    return {'type':'integer', 'minimum':minimum, 'maximum':maximum}


def _str(maximum=MAX_LABEL_BYTES, minimum=0, pattern=None):
    result = {'type':'string', 'minLength':minimum, 'maxLength':maximum,
              'x-maxUtf8Bytes':maximum, 'pattern':r'^[^\u0000\ud800-\udfff]*$'}
    if pattern is not None:
        result['pattern'] = pattern
    return result


def _enum(*values):
    return {'enum':list(values)}


def _const(value):
    return {'const':value}


def _union(*variants):
    return {'oneOf':list(variants)}


def _nullable(rule):
    return _union(rule, {'type':'null'})


DIGEST = _str(64, 64, r'^[0-9a-f]{64}$')
PLAN_ID = _str(71, 71, r'^sha256:[0-9a-f]{64}$')
FILE_ID = _str(32, 1, r'^[a-z][a-z0-9_-]{0,31}$')
ABS_PATH = _str(MAX_PATH_BYTES, 1, r'^/[^\u0000\ud800-\udfff]*$')
PHASE = _enum('warmup','measured')
SLOT = _int(0, MAX_SLOTS - 1)
PAIR = _int(0, SUPPORTED_MAX_PAIRS - 1)
BOOLEAN = {'type':'boolean'}
REASON = _object({'code':_enum(*REASON_CODES),'detail':_str(MAX_DETAIL_BYTES)}, ('detail',))
REASONS = _array(REASON)
COMMANDS = _object({arm:_object({'argv':_array(_str(MAX_ARGUMENT_BYTES), 1, MAX_ARGS)})
                    for arm in ('A','B')})
OUTPUT_CHECK = _union(
    _object({'mode':_const('equal-within-pair')}),
    _object({'mode':_const('none')}),
    _object({'mode':_const('expected-sha256'),'sha256':DIGEST,
             'bytes':_int(0, MAX_CAPTURE_BYTES_PER_STREAM)}))
BASE = {
    'workload':_str(), 'cwd':ABS_PATH, 'commands':COMMANDS,
    'measured_pairs':_int(2, SUPPORTED_MAX_PAIRS),
    'warmup_pairs':_int(0, MAX_WARMUP_PAIRS),
    'alternative':_enum('two-sided','B-slower'),
    'command_timeout_ns':_int(MIN_COMMAND_TIMEOUT_NS, MAX_COMMAND_TIMEOUT_NS),
    'run_timeout_ns':_int(MIN_RUN_TIMEOUT_NS, MAX_RUN_TIMEOUT_NS),
    'capture_bytes_per_stream':_int(1, MAX_CAPTURE_BYTES_PER_STREAM),
    'capture_bytes_total':_int(1, MAX_CAPTURE_BYTES_TOTAL),
    'output_check':OUTPUT_CHECK,
}
SPEC_SCHEMA = _object({'schema':_const('benchinterlace.spec.v1'), **BASE,
                      'files':_array(_object({'id':FILE_ID,'path':ABS_PATH}),0,MAX_FILES)},
                     ('capture_bytes_per_stream','capture_bytes_total'))
FILE = _object({'id':FILE_ID,'path':ABS_PATH,'bytes':_int(0,MAX_INPUT_BYTES),'sha256':DIGEST})
PLAN_PAYLOAD = _object({'schema':_const('benchinterlace.plan.v1'), **BASE,
    'files':_array(FILE,1,MAX_FILES),
    'command_files':_object({'A':FILE_ID,'B':FILE_ID}),
    'assignments':_object({'method':_const('independent-os-bits-v1'),
        'measured':_array(_enum('AB','BA'),2,SUPPORTED_MAX_PAIRS),
        'warmup':_array(_enum('AB','BA'),0,MAX_WARMUP_PAIRS)}),
    'runner_contract':_const('linux-foreground-v1'),
    'timer_contract':_const('spawn-to-observed-leader-exit-v1'),
    'capture_contract':_const('bounded-pipes-v1'),
    'fingerprint_contract':_const('declared-before-after-v1'),
    'generator_version':_str(MAX_LABEL_BYTES,1),
})
PLAN_SCHEMA = _object({'plan_id':PLAN_ID, 'payload':PLAN_PAYLOAD})
FINGERPRINT = _union(
    _object({'id':FILE_ID,'bytes':_int(0,MAX_INPUT_BYTES),'sha256':DIGEST,'stable_read':BOOLEAN}),
    _object({'id':FILE_ID,'error_code':_enum(*REASON_CODES)}))
STREAM = _union(
    _object({'state':_const('published'),
        'path':_str(22, 22, r'^captures/[0-9]{6}\.(stdout|stderr)$'),
        'retained_bytes':_int(0,MAX_CAPTURE_BYTES_PER_STREAM), 'observed_bytes':_int(),
        'sha256':DIGEST,'eof':BOOLEAN,'truncated':BOOLEAN}),
    _object({'state':_const('unavailable'),'reason':REASON}))
EVENT_DATA = {
    'run_start':_object({'runner_version':_str(MAX_LABEL_BYTES,1),
        'python_version':_str(MAX_LABEL_BYTES,1), 'platform':_const('linux'),
        'machine':_str(MAX_LABEL_BYTES,1),'timer_name':_str(MAX_LABEL_BYTES,1),
        'timer_resolution_ns':_int(1), 'expected_slots':_int(4,MAX_SLOTS)}),
    'fingerprint_check':_object({'stage':_enum('pre-run','pre-slot','post-slot','post-run'),
        'slot':_nullable(SLOT),'files':_array(FINGERPRINT,0,MAX_FILES),
        'status':_enum('ok','failed'),'reasons':REASONS}),
    'slot_start':_object({'slot':SLOT,'phase':PHASE,'pair':PAIR,
        'position':_int(0,1),'arm':_enum('A','B')}),
    'slot_timing':_object({'slot':SLOT,'elapsed_ns':_nullable(_int()),
        'exit_code':_nullable(_int(MIN_EXIT_CODE,MAX_EXIT_CODE)),
        'termination':_enum('exited','signal','launch-failed','timeout','interrupted','unknown'),
        'timeout_requested_ns':_nullable(_int()),
        'elapsed_exceeded_timeout':_nullable(BOOLEAN),'issues':REASONS}),
    'slot_evidence':_object({'slot':SLOT,'streams':_object({'stdout':STREAM,'stderr':STREAM}),
        'output_check':_enum('pending-pair','passed','not-requested','failed'),
        'cleanup':_enum('completed','unconfirmed','failed'),'issues':REASONS}),
    'pair_check':_object({'phase':PHASE,'pair':PAIR,
        'status':_enum('passed','not-requested','failed'),'reasons':REASONS}),
    'run_end':_object({'state':_enum('complete','aborted'),
        'completed_slots':_int(0,MAX_SLOTS),'not_run_slots':_array(SLOT,0,MAX_SLOTS),
        'reasons':REASONS}),
}
EVENT_SCHEMA = _union(*[
    _object({'schema':_const('benchinterlace.event.v1'),'seq':_int(0,MAX_EVENTS-1),
        'previous_sha256':_nullable(DIGEST),'plan_id':PLAN_ID,
        'kind':_const(kind),'data':data}) for kind,data in EVENT_DATA.items()])
BUNDLE_PATH_PATTERN = r'^(plan\.json|events/[0-9]{6}\.json|captures/[0-9]{6}\.(stdout|stderr))$'
SEAL_SCHEMA = _object({'schema':_const('benchinterlace.seal.v1'),'plan_id':PLAN_ID,
    'last_event_sha256':DIGEST,'files':_array(_object({
        'path':_str(22,1,BUNDLE_PATH_PATTERN), 'bytes':_int(0,MAX_BUNDLE_BYTES),
        'sha256':DIGEST}),1,1+MAX_EVENTS+MAX_CAPTURE_FILES)})
MAX_SUM = SUPPORTED_MAX_PAIRS * MAX_DURATION_NS
RATIONAL = _object({'numerator':_int(-MAX_SUM,MAX_SUM),'denominator':_int(1,MAX_SUM)})
COUNTS = _object({name:_int(0,MAX_SLOTS) for name in ('planned','started','timed','validated','unstarted')})
DESCRIPTIVE = _object({'n':_int(2,SUPPORTED_MAX_PAIRS),'sum_a_ns':_int(2,MAX_SUM),
    'sum_b_ns':_int(2,MAX_SUM),'mean_a_ns':RATIONAL,'mean_b_ns':RATIONAL,
    'mean_difference_ns':RATIONAL,'ratio_b_over_a':RATIONAL})
TEST = _object({'method':_const('exact-paired-assignment-v1'),
    'alternative':_enum('two-sided','B-slower'),'statistic_sum_difference_ns':_int(-MAX_SUM,MAX_SUM),
    'tail_count':_int(1,1<<SUPPORTED_MAX_PAIRS),'assignment_count':_int(4,1<<SUPPORTED_MAX_PAIRS),
    'p_decimal':_str(14,14,r'^[01]\.[0-9]{12}$')})
REPORT_SCHEMA = _object({'schema':_const('benchinterlace.report.v1'),
    'plan_id':_nullable(PLAN_ID),'bundle_sha256':_nullable(DIGEST),
    'analysis_version':_str(MAX_LABEL_BYTES,1),'evidence_status':_enum('complete','incomplete','failed','malformed'),
    'inference_status':_enum('available','withheld','unsupported'), 'reasons':REASONS,
    'warnings':_array(_object({'code':_enum(*WARNING_CODES),'text':_str(MAX_DETAIL_BYTES)}),0,len(WARNING_CODES)),
    'counts':_nullable(_object({'warmup':COUNTS,'measured':COUNTS})),
    'descriptive':_nullable(DESCRIPTIVE),'test':_nullable(TEST)})
SCHEMAS = {'spec':SPEC_SCHEMA,'plan':PLAN_SCHEMA,'event':EVENT_SCHEMA,
           'seal':SEAL_SCHEMA,'report':REPORT_SCHEMA}


def schema_document(name):
    """Return a standalone JSON Schema document for one fixed inventory."""
    return {'$schema':'https://json-schema.org/draft/2020-12/schema',
            '$id':f'urn:benchinterlace:{name}:v1',
            'title':f'BenchInterlace v1 {name}',
            '$comment':('Strict JSON parsing additionally rejects float/exponent integer spellings, '
                'duplicate keys, unpaired surrogates and NUL. x-maxUtf8Bytes is enforced by '
                'the handwritten validator. Cross-field identity, canonical-byte and aggregate '
                'limits require the corresponding runtime validator.'), **SCHEMAS[name]}


def _fail(detail, code='invalid_schema'):
    raise ValidationError(code, detail)


def _check(value, rule, path='$'):
    """Validate only the trusted, bounded rule vocabulary defined above."""
    if 'oneOf' in rule:
        count = 0
        for variant in rule['oneOf']:
            try:
                _check(value, variant, path)
                count += 1
            except ValidationError:
                pass
        if count != 1:
            _fail(f'{path}: value does not match exactly one permitted variant')
        return
    if 'const' in rule:
        if type(value) is not type(rule['const']) or value != rule['const']:
            _fail(f'{path}: unsupported constant value')
        return
    if 'enum' in rule:
        if not any(type(value) is type(item) and value == item for item in rule['enum']):
            _fail(f'{path}: unsupported enumeration value')
        return
    kind = rule['type']
    if kind == 'object':
        if type(value) is not dict:
            _fail(f'{path}: object required')
        keys = value.keys()
        if not set(rule['required']) <= keys or not keys <= rule['properties'].keys():
            _fail(f'{path}: missing or unknown fields')
        for name, child in value.items():
            _check(child, rule['properties'][name], f'{path}.{name}')
    elif kind == 'array':
        if type(value) is not list or not rule['minItems'] <= len(value) <= rule['maxItems']:
            _fail(f'{path}: array length or type invalid')
        for index, item in enumerate(value):
            _check(item, rule['items'], f'{path}[{index}]')
    elif kind == 'integer':
        if type(value) is not int or not rule['minimum'] <= value <= rule['maximum']:
            _fail(f'{path}: integer required within declared bounds')
    elif kind == 'string':
        if type(value) is not str:
            _fail(f'{path}: string required')
        if (not rule['minLength'] <= len(value) <= rule['maxLength'] or
                len(value.encode('utf-8')) > rule['x-maxUtf8Bytes'] or
                re.fullmatch(rule['pattern'], value) is None):
            _fail(f'{path}: invalid string value or byte length')
    elif kind == 'boolean':
        if type(value) is not bool:
            _fail(f'{path}: boolean required')
    elif kind == 'null':
        if value is not None:
            _fail(f'{path}: null required')
    else:
        raise RuntimeError('unsupported internal validation rule')


def _validate(value, rule, limit):
    # This also protects direct Python callers against floats, surrogates and
    # cyclic/deep containers before the fixed recursive shape validator runs.
    if len(canonical_bytes(value)) > limit:
        _fail('canonical document exceeds its byte limit', 'resource_limit')
    _check(value, rule)


def _absolute(path, normalized=False):
    if not path.startswith('/'):
        _fail('an absolute POSIX path is required', 'invalid_path')
    if normalized and (path.startswith('//') or posixpath.normpath(path) != path):
        _fail('frozen paths must be normalized absolute POSIX paths', 'invalid_path')


def _common(obj, normalized=False):
    _absolute(obj['cwd'], normalized)
    for command in obj['commands'].values():
        argv = command['argv']
        _absolute(argv[0], normalized)
        if sum(len(arg.encode('utf-8')) for arg in argv) > MAX_ARGV_BYTES:
            _fail('argument bytes exceed per-arm bound', 'resource_limit')
    check = obj['output_check']
    if check['mode'] == 'expected-sha256' and check['bytes'] > obj.get(
            'capture_bytes_per_stream', DEFAULT_CAPTURE_BYTES_PER_STREAM):
        _fail('expected stdout bytes exceed per-stream capture cap')


def validate_spec(obj) -> None:
    """Validate shape only; file existence/permissions belong to Stage 2 planning."""
    _validate(obj, SPEC_SCHEMA, MAX_SPEC_BYTES)
    _common(obj)
    ids = [entry['id'] for entry in obj['files']]
    if len(set(ids)) != len(ids) or {'executable_a','executable_b'} & set(ids):
        _fail('user file IDs must be unique and nonreserved', 'duplicate_record')
    for entry in obj['files']:
        _absolute(entry['path'])


def validate_plan(obj) -> None:
    _validate(obj, PLAN_SCHEMA, MAX_PLAN_BYTES)
    payload = obj['payload']
    _common(payload, normalized=True)
    files = payload['files']
    ids = [entry['id'] for entry in files]
    paths = [entry['path'] for entry in files]
    if ids != sorted(set(ids)) or len(set(paths)) != len(paths):
        _fail('frozen files must have unique paths and sorted unique IDs', 'duplicate_record')
    if sum(entry['bytes'] for entry in files) > MAX_INPUT_BYTES:
        _fail('declared file bytes exceed total cap', 'resource_limit')
    for path in paths:
        _absolute(path, normalized=True)
        if path == '/':
            _fail('a frozen file path cannot be the filesystem root', 'invalid_path')
    by_id = {entry['id']:entry for entry in files}
    for arm in ('A','B'):
        identifier = payload['command_files'][arm]
        if identifier not in by_id or by_id[identifier]['path'] != payload['commands'][arm]['argv'][0]:
            _fail('command executable and declared file identity differ', 'plan_mismatch')
    same = payload['commands']['A']['argv'][0] == payload['commands']['B']['argv'][0]
    expected = {'A':'executable_a', 'B':'executable_a' if same else 'executable_b'}
    if payload['command_files'] != expected or (same and 'executable_b' in by_id):
        _fail('executable retained IDs violate normalization order', 'plan_mismatch')
    for phase in ('warmup','measured'):
        if len(payload['assignments'][phase]) != payload[phase+'_pairs']:
            _fail('assignment length differs from frozen pair count', 'plan_mismatch')
    if obj['plan_id'] != 'sha256:' + digest(canonical_bytes(payload)):
        _fail('plan_id does not hash the canonical payload', 'hash_mismatch')


def validate_event(obj) -> None:
    _validate(obj, EVENT_SCHEMA, MAX_EVENT_BYTES)
    if (obj['seq'] == 0) != (obj['previous_sha256'] is None):
        _fail('only event zero has a null previous hash', 'order_mismatch')
    kind, data = obj['kind'], obj['data']
    if kind == 'fingerprint_check':
        if (data['stage'] in ('pre-run','post-run')) != (data['slot'] is None):
            _fail('fingerprint stage and slot disagree')
        ids = [entry['id'] for entry in data['files']]
        if len(set(ids)) != len(ids):
            _fail('duplicate fingerprint ID', 'duplicate_record')
    elif kind in ('slot_start','pair_check'):
        if data['phase'] == 'warmup' and data['pair'] >= MAX_WARMUP_PAIRS:
            _fail('warmup pair exceeds phase bound')
    elif kind == 'slot_timing':
        if (data['elapsed_ns'] is None) != (data['elapsed_exceeded_timeout'] is None):
            _fail('elapsed timeout flag must be null exactly when elapsed duration is null')
    elif kind == 'slot_evidence':
        for stream_name, stream in data['streams'].items():
            if stream['state'] == 'published':
                if stream['path'] != f"captures/{data['slot']:06d}.{stream_name}":
                    _fail('capture path differs from slot and stream identity', 'invalid_path')
                if stream['observed_bytes'] < stream['retained_bytes']:
                    _fail('observed bytes cannot be less than retained bytes')
                if stream['truncated'] and stream['observed_bytes'] <= stream['retained_bytes']:
                    _fail('truncation requires an observed extra byte')
    elif kind == 'run_end':
        if data['not_run_slots'] != sorted(set(data['not_run_slots'])):
            _fail('not-run slots must be increasing and unique', 'order_mismatch')


def validate_seal(obj) -> None:
    _validate(obj, SEAL_SCHEMA, MAX_SEAL_BYTES)
    paths = [entry['path'] for entry in obj['files']]
    if paths != sorted(set(paths)):
        _fail('seal paths must be sorted and unique', 'duplicate_record')
    total = 0
    for entry in obj['files']:
        path = entry['path']
        if path == 'plan.json':
            limit = MAX_PLAN_BYTES
        elif path.startswith('events/'):
            if int(path[7:13]) >= MAX_EVENTS:
                _fail('event path sequence exceeds limit', 'invalid_path')
            limit = MAX_EVENT_BYTES
        else:
            if int(path[9:15]) >= MAX_SLOTS:
                _fail('capture path slot exceeds limit', 'invalid_path')
            limit = MAX_CAPTURE_BYTES_PER_STREAM
        if entry['bytes'] > limit:
            _fail('seal entry exceeds artifact byte limit', 'resource_limit')
        total += entry['bytes']
    if total > MAX_BUNDLE_BYTES:
        _fail('seal content total exceeds bundle byte limit', 'resource_limit')


def _rational(value, numerator, denominator, name):
    divisor = math.gcd(numerator, denominator)
    if value != {'numerator':numerator // divisor,'denominator':denominator // divisor}:
        _fail(f'{name}: incorrect or unreduced exact rational', 'report_mismatch')


def validate_report(obj) -> None:
    _validate(obj, REPORT_SCHEMA, MAX_REPORT_BYTES)
    warnings = [warning['code'] for warning in obj['warnings']]
    if len(set(warnings)) != len(warnings):
        _fail('duplicate warning code', 'duplicate_record')
    counts = obj['counts']
    if counts is not None:
        for phase, count in counts.items():
            if (not count['validated'] <= count['timed'] <= count['started'] <= count['planned'] or
                    count['unstarted'] != count['planned'] - count['started'] or count['planned'] % 2):
                _fail(f'{phase}: impossible report counts', 'report_mismatch')
        if counts['warmup']['planned'] > 2 * MAX_WARMUP_PAIRS or counts['measured']['planned'] > 2 * SUPPORTED_MAX_PAIRS:
            _fail('planned counts exceed phase bounds', 'report_mismatch')
    available = obj['inference_status'] == 'available'
    if available:
        if (obj['evidence_status'] != 'complete' or obj['descriptive'] is None or obj['test'] is None
                or counts is None or obj['plan_id'] is None or obj['bundle_sha256'] is None or obj['reasons']):
            _fail('available inference requires complete identified evidence and no reasons', 'report_mismatch')
        desc, test = obj['descriptive'], obj['test']
        n, a, b = desc['n'], desc['sum_a_ns'], desc['sum_b_ns']
        if counts['measured']['planned'] != 2*n:
            _fail('descriptive sample size differs from planned measured slots', 'report_mismatch')
        for count in counts.values():
            if count['planned'] != count['validated']:
                _fail('available inference requires every planned slot validated', 'report_mismatch')
        if not n <= a <= n*MAX_DURATION_NS or not n <= b <= n*MAX_DURATION_NS:
            _fail('duration sums inconsistent with positive bounded durations', 'report_mismatch')
        _rational(desc['mean_a_ns'], a, n, 'mean_a_ns')
        _rational(desc['mean_b_ns'], b, n, 'mean_b_ns')
        _rational(desc['mean_difference_ns'], b-a, n, 'mean_difference_ns')
        _rational(desc['ratio_b_over_a'], b, a, 'ratio_b_over_a')
        if test['statistic_sum_difference_ns'] != b-a or test['assignment_count'] != 1 << n:
            _fail('test statistic or assignment count inconsistent', 'report_mismatch')
        tail, total = test['tail_count'], test['assignment_count']
        if tail > total:
            _fail('tail count exceeds assignment count', 'report_mismatch')
        whole, remainder = divmod(tail * 10**12, total)
        if 2*remainder > total or (2*remainder == total and whole % 2):
            whole += 1
        expected = f'{whole // 10**12}.{whole % 10**12:012d}'
        if test['p_decimal'] != expected:
            _fail('p_decimal differs from exact half-even 12-place rounding', 'report_mismatch')
    elif obj['descriptive'] is not None or obj['test'] is not None:
        _fail('withheld or unsupported inference requires null descriptive and test', 'report_mismatch')
    if obj['inference_status'] == 'unsupported' and obj['evidence_status'] != 'complete':
        _fail('unsupported inference requires complete evidence', 'report_mismatch')
