"""Version-frozen bounds shared by collection and offline analysis."""
VERSION = '0.1.0a2'
SUPPORTED_MAX_PAIRS = 40
MAX_WARMUP_PAIRS = 10
MAX_SLOTS = 100
MAX_CAPTURE_FILES = 200
MAX_FILES = 64
MAX_INPUT_BYTES = 1 << 30
MAX_SPEC_BYTES = 64 << 10
MAX_PLAN_BYTES = 64 << 10
MAX_EVENT_BYTES = 16 << 10
MAX_EVENTS = 1024
MAX_EVENT_TOTAL_BYTES = 16 << 20
MAX_SEAL_BYTES = 256 << 10
MAX_REPORT_BYTES = 1 << 20
MAX_BUNDLE_BYTES = 288 << 20
MAX_CAPTURE_BYTES_PER_STREAM = 1 << 20
MAX_CAPTURE_BYTES_TOTAL = 256 << 20
DEFAULT_CAPTURE_BYTES_PER_STREAM = 256 << 10
DEFAULT_CAPTURE_BYTES_TOTAL = 64 << 20
MAX_DURATION_NS = (1 << 63) - 1
MIN_COMMAND_TIMEOUT_NS = 1_000_000
MAX_COMMAND_TIMEOUT_NS = 3_600_000_000_000
MIN_RUN_TIMEOUT_NS = 1_000_000_000
MAX_RUN_TIMEOUT_NS = 86_400_000_000_000
MAX_PATH_BYTES = 4096
MAX_ARGUMENT_BYTES = 4096
MAX_ARGV_BYTES = 16 << 10
MAX_ARGS = 64
MAX_LABEL_BYTES = 128
MAX_DETAIL_BYTES = 1024
MAX_NESTING = 12
MAX_INTEGER_DIGITS = 64
MAX_JSON_NODES = 100_000
MAX_JSON_STRING_BYTES = MAX_PATH_BYTES
MAX_REASONS = 100
MIN_EXIT_CODE = -64
MAX_EXIT_CODE = 255
REASON_CODES = (
    'input_changed', 'unstable_read', 'launch_failed', 'nonzero_exit',
    'command_timeout', 'run_timeout', 'output_limit', 'output_mismatch',
    'capture_incomplete', 'capture_io', 'cleanup_unconfirmed', 'interrupted',
    'plan_changed', 'internal_error', 'ownership_lost', 'unsupported_primitive',
    'resource_limit', 'invalid_schema', 'invalid_path', 'invalid_duration',
    'duplicate_record', 'order_mismatch', 'plan_mismatch', 'hash_mismatch',
    'missing_record', 'missing_seal', 'unexpected_artifact',
    'execution_outcome_unknown', 'report_mismatch',
)
WARNING_CODES = (
    'assumptions_unverified', 'output_not_checked', 'no_semantic_equivalence_proof',
    'repeated_attempts_uncontrolled', 'selection_not_adjusted', 'no_complete_provenance',
    'no_microbenchmark_accuracy_claim', 'structural_memory_cap_only', 'small_n_resolution',
)
