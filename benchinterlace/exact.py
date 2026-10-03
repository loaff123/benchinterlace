"""Exact, inclusive paired-assignment tails using integer meet-in-the-middle.

This pure kernel does not claim to enforce process resource limits. Product
analysis must invoke it through :mod:`benchinterlace.analysis_worker`.
"""

from bisect import bisect_left, bisect_right


def _validated_differences(differences):
    """Read a bounded list/tuple; neither coerce numeric types nor drop zeros."""
    if type(differences) not in (list, tuple):
        raise ValueError("differences must be a list or tuple of integers")
    if not 2 <= len(differences) <= 40:
        raise ValueError("exact analysis requires 2 through 40 differences")
    result = []
    for value in differences:
        if type(value) is not int:
            raise ValueError("each difference must be an integer, not a boolean or float")
        result.append(value)
    return tuple(result)


def _validate_alternative(alternative):
    if type(alternative) is not str or alternative not in ("two-sided", "B-slower"):
        raise ValueError("alternative must be 'two-sided' or 'B-slower'")


def _gray_sums(values):
    """Stream all signed sums, preserving distinct assignments with equal sums."""
    current = -sum(values)
    yield current
    for index in range(1, 1 << len(values)):
        changed = index & -index
        delta = values[changed.bit_length() - 1] * 2
        # At transition index, its least significant set bit changes in Gray
        # order. The next higher binary bit determines its new Gray polarity.
        if index & (changed << 1):
            current -= delta
        else:
            current += delta
        yield current


def exact_counts(differences, alternative):
    """Return the unreduced (tail_count, 2**n), with inclusive boundary ties.

    All sums, thresholds, and counts remain Python integers. Arbitrarily large
    integers are valid here; accepted duration bounds belong to the evidence
    schema, and allocation limits belong to the isolated analysis worker.
    """
    differences = _validated_differences(differences)
    _validate_alternative(alternative)
    n = len(differences)
    assignments = 1 << n
    observed = sum(differences)
    if alternative == "two-sided" and observed == 0:
        return assignments, assignments

    split = n // 2
    right_count = 1 << (n - split)
    # Preallocation avoids doubling-list construction overlap. The resource
    # estimate still reserves a complete extra pointer array conservatively.
    right = [0] * right_count
    for index, value in enumerate(_gray_sums(differences[split:])):
        right[index] = value
    right.sort()

    tail = 0
    if alternative == "B-slower":
        for left in _gray_sums(differences[:split]):
            tail += right_count - bisect_left(right, observed - left)
    else:
        threshold = abs(observed)
        for left in _gray_sums(differences[:split]):
            tail += bisect_right(right, -threshold - left)
            tail += right_count - bisect_left(right, threshold - left)
    return tail, assignments
