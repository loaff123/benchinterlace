"""Bounded, product-owned subprocess for the exact integer calculation.

Only this package's Python module is launched. Recorded benchmark commands,
paths, and environment data never enter the subprocess argument vector. The
isolated interpreter ignores caller PYTHONPATH and current-directory imports;
its package parent comes solely from this installed module's __file__.

The structural estimate covers algorithm allocations, not interpreter RSS.
RLIMIT_AS limits virtual address space, not resident memory. Platforms without
that primitive retain the allocation preflight and wall watchdog and explicitly
report "structural allocation cap only".
"""

import json
import os
from pathlib import Path
import struct
import subprocess
import sys

from .exact import _validate_alternative, _validated_differences, exact_counts

try:
    import resource as _resource
except ImportError:  # Windows and other runtimes without POSIX resource limits.
    _resource = None


ALLOCATION_CAP_BYTES = 128 * 1024 * 1024
ADDRESS_SPACE_CAP_BYTES = 256 * 1024 * 1024
WALL_SECONDS = 30
CPU_SECONDS = 30
REQUEST_CAP_BYTES = 64 * 1024
RESPONSE_CAP_BYTES = 16 * 1024


def resource_estimate(differences):
    """Conservatively bound stored integers, list storage, overlap, and sorting.

    A distinct allocation is charged even for equal or interned integer values.
    Integer objects are rounded to a 16-byte allocation quantum. The bound
    includes two full pointer arrays plus ceil(m/2) sort pointers, 64 temporary
    integers, input/slice pointers, and 1 MiB additional allocator overhead.
    The integer-size bound uses twice the complete absolute sum, covering Gray
    increments and binary-search thresholds as well as stored right sums.

    Object-size accounting is supported on CPython only until another runtime
    has its allocation model reviewed and maximum-pair resource gate measured.
    """
    values = _validated_differences(differences)
    n = len(values)
    entries = 1 << (n - n // 2)
    pointer = struct.calcsize("P")
    supported = sys.implementation.name == "cpython"
    magnitude = 2 * sum(abs(value) for value in values)
    try:
        integer_size = ((sys.getsizeof(magnitude) + 15) // 16) * 16
        list_header = sys.getsizeof([])
    except (TypeError, ValueError):
        supported = False
        integer_size = 0
        list_header = 0
    estimate = (
        entries * integer_size
        + 2 * entries * pointer
        + ((entries + 1) // 2) * pointer
        + 64 * integer_size
        + 8 * n * pointer
        + 4 * list_header
        + 1024 * 1024
    )
    return {
        "n": n,
        "right_entries": entries,
        "pointer_bytes": pointer,
        "integer_bytes": integer_size,
        "estimated_bytes": estimate,
        "cap_bytes": ALLOCATION_CAP_BYTES,
        "within_cap": supported and estimate <= ALLOCATION_CAP_BYTES,
        "supported": supported,
    }


def _empty_limits():
    return {
        "wall_seconds": WALL_SECONDS,
        "cpu_seconds": None,
        "address_space_bytes": None,
        "memory_enforcement": "structural allocation cap only",
    }


def _unsupported(code, detail, estimate=None, limits=None):
    return {
        "status": "unsupported",
        "tail_count": None,
        "assignment_count": None,
        "reason": {"code": code, "detail": detail},
        "resource": estimate,
        "limits": limits if limits is not None else _empty_limits(),
    }


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate worker protocol field")
        result[key] = value
    return result


def _configure_limits():
    """Apply hard ceilings without increasing any inherited soft/hard limit."""
    limits = _empty_limits()
    if os.name != "posix" or _resource is None:
        return limits
    for name, requested, field in (
        ("RLIMIT_CPU", CPU_SECONDS, "cpu_seconds"),
        ("RLIMIT_AS", ADDRESS_SPACE_CAP_BYTES, "address_space_bytes"),
    ):
        if not hasattr(_resource, name):
            continue
        primitive = getattr(_resource, name)
        soft, hard = _resource.getrlimit(primitive)
        bounds = [requested]
        bounds.extend(value for value in (soft, hard) if value != _resource.RLIM_INFINITY)
        bound = min(bounds)
        if bound <= 0:
            raise OSError("inherited resource limit does not admit analysis")
        _resource.setrlimit(primitive, (bound, bound))
        actual_soft, actual_hard = _resource.getrlimit(primitive)
        if actual_soft != bound or actual_hard != bound:
            raise OSError("resource ceiling could not be verified")
        limits[field] = bound
    if limits["address_space_bytes"] is not None:
        limits["memory_enforcement"] = "address-space"
    return limits


def _execute_request(request):
    """Worker-side execution; private entry point also permits fault testing."""
    estimate = None
    limits = _empty_limits()
    try:
        limits = _configure_limits()
    except MemoryError:
        return _unsupported("resource_limit", "analysis worker exhausted memory")
    except (OSError, ValueError):
        return _unsupported("unsupported_primitive", "worker resource limits unavailable")
    try:
        if type(request) is not dict or set(request) != {"differences", "alternative"}:
            raise ValueError("invalid worker request")
        values = _validated_differences(request["differences"])
        _validate_alternative(request["alternative"])
        estimate = resource_estimate(values)
        if not estimate["supported"]:
            return _unsupported("unsupported_primitive", "interpreter allocation model unverified", estimate, limits)
        if not estimate["within_cap"]:
            return _unsupported("resource_limit", "structural allocation estimate exceeds 128 MiB", estimate, limits)
        tail, assignments = exact_counts(values, request["alternative"])
        return {
            "status": "available",
            "tail_count": tail,
            "assignment_count": assignments,
            "reason": None,
            "resource": estimate,
            "limits": limits,
        }
    except MemoryError:
        return _unsupported("resource_limit", "analysis worker exhausted memory", estimate, limits)
    except Exception:
        return _unsupported("internal_error", "analysis worker could not compute exact counts", estimate, limits)


def _valid_response(result, estimate):
    """Fail closed on malformed or inconsistent replies from the worker."""
    fields = {"status", "tail_count", "assignment_count", "reason", "resource", "limits"}
    if type(result) is not dict or set(result) != fields:
        return False
    if result["resource"] != estimate and result["resource"] is not None:
        return False
    limits = result["limits"]
    if type(limits) is not dict or set(limits) != set(_empty_limits()):
        return False
    if type(limits["wall_seconds"]) is not int or limits["wall_seconds"] != WALL_SECONDS:
        return False
    for field, maximum in (("cpu_seconds", CPU_SECONDS), ("address_space_bytes", ADDRESS_SPACE_CAP_BYTES)):
        value = limits[field]
        if value is not None and (type(value) is not int or not 0 < value <= maximum):
            return False
    enforcement = "address-space" if limits["address_space_bytes"] is not None else "structural allocation cap only"
    if limits["memory_enforcement"] != enforcement:
        return False
    if result["status"] == "available":
        return (
            result["resource"] == estimate
            and result["reason"] is None
            and type(result["tail_count"]) is int
            and type(result["assignment_count"]) is int
            and result["assignment_count"] == 1 << estimate["n"]
            and 1 <= result["tail_count"] <= result["assignment_count"]
        )
    reason = result["reason"]
    return (
        result["status"] == "unsupported"
        and result["tail_count"] is None
        and result["assignment_count"] is None
        and type(reason) is dict
        and set(reason) == {"code", "detail"}
        and reason["code"] in ("resource_limit", "unsupported_primitive", "internal_error")
        and type(reason["detail"]) is str
        and len(reason["detail"]) <= 256
    )


def run_exact(differences, alternative):
    """Run the fixed product worker with a 30-second parent wall watchdog.

    Malformed API arguments raise ValueError. Capability, allocation, launch,
    timeout, protocol, and worker failures return unsupported with null counts.
    No approximate method or reduced-n retry exists.
    """
    values = _validated_differences(differences)
    _validate_alternative(alternative)
    try:
        estimate = resource_estimate(values)
    except MemoryError:
        return _unsupported("resource_limit", "analysis preflight exhausted memory")
    if not estimate["supported"]:
        return _unsupported("unsupported_primitive", "interpreter allocation model unverified", estimate)
    if not estimate["within_cap"]:
        return _unsupported("resource_limit", "structural allocation estimate exceeds 128 MiB", estimate)
    try:
        payload = json.dumps({"differences": values, "alternative": alternative}, separators=(",", ":")).encode("ascii")
    except (MemoryError, ValueError):
        return _unsupported("resource_limit", "worker request exceeds serialization capability", estimate)
    if len(payload) > REQUEST_CAP_BYTES:
        return _unsupported("resource_limit", "worker request exceeds 64 KiB", estimate)
    package_parent = str(Path(__file__).resolve().parent.parent)
    bootstrap = (
        "import runpy,sys;"
        f"sys.path.insert(0,{package_parent!r});"
        "runpy.run_module('benchinterlace.analysis_worker',run_name='__main__')"
    )
    try:
        completed = subprocess.run(
            [sys.executable, "-I", "-c", bootstrap],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=WALL_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        # subprocess.run kills and waits for its owned child before raising.
        return _unsupported("resource_limit", "analysis worker exceeded 30-second wall limit", estimate)
    except OSError:
        return _unsupported("unsupported_primitive", "analysis worker could not be started", estimate)
    except MemoryError:
        return _unsupported("resource_limit", "analysis parent exhausted memory", estimate)
    if completed.returncode != 0:
        return _unsupported("resource_limit", "analysis worker exited without a usable result", estimate)
    if len(completed.stdout) > RESPONSE_CAP_BYTES or completed.stderr:
        return _unsupported("internal_error", "analysis worker returned an invalid response", estimate)
    try:
        result = json.loads(completed.stdout, object_pairs_hook=_unique_object)
        if not _valid_response(result, estimate):
            raise ValueError("invalid worker response")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return _unsupported("internal_error", "analysis worker returned an invalid response", estimate)
    return result


def _worker_main():
    """Private bounded-JSON protocol; it never opens paths from the payload."""
    try:
        raw = sys.stdin.buffer.read(REQUEST_CAP_BYTES + 1)
        if len(raw) > REQUEST_CAP_BYTES:
            result = _unsupported("resource_limit", "worker request exceeds 64 KiB")
        else:
            result = _execute_request(json.loads(raw, object_pairs_hook=_unique_object))
        sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    except MemoryError:
        return 2
    except Exception:
        return 3


if __name__ == "__main__":
    raise SystemExit(_worker_main())
