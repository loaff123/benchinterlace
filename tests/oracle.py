"""Independent, deliberately direct enumeration for small exact-test fixtures.

This test-only module depends solely on the standard library. It neither imports
the implementation nor uses meet-in-the-middle, sorting/bisection, Gray codes,
or the production implementation's tail-count routine.
"""

from itertools import product


def sign_assignments(differences):
    """Yield each labeled sign assignment, including both choices for zeros."""
    for signs in product((-1, 1), repeat=len(differences)):
        yield tuple(sign * value for sign, value in zip(signs, differences))


def signed_sums(differences):
    """Return the complete reference multiset by enumerating full assignments."""
    return tuple(sum(assignment) for assignment in sign_assignments(differences))


def brute_force_counts(differences, alternative):
    """Count qualifying assignments directly; bounded to n<=12 for tests."""
    if not isinstance(differences, (tuple, list)):
        raise ValueError("oracle requires a tuple or list")
    if not 2 <= len(differences) <= 12:
        raise ValueError("oracle is deliberately bounded to 2..12 differences")
    if any(type(value) is not int for value in differences):
        raise ValueError("oracle requires ordinary Python integers")
    if alternative not in ("B-slower", "two-sided"):
        raise ValueError("unknown alternative")
    observed = sum(differences)
    tail_count = 0
    assignment_count = 0
    for assignment in sign_assignments(differences):
        candidate = sum(assignment)
        assignment_count += 1
        if alternative == "B-slower":
            qualifies = candidate >= observed
        else:
            qualifies = abs(candidate) >= abs(observed)
        if qualifies:
            tail_count += 1
    return tail_count, assignment_count
