"""Exact statistical acceptance tests; run with python -m unittest tests.test_exact.

The stdlib exhaustive oracle is authoritative. An explicitly requested SciPy
cross-check is development-only and is never a runtime dependency.
"""

import importlib
import os
import random
import time
import unittest
from collections import Counter
from fractions import Fraction
from itertools import product
from math import comb

from tests.oracle import brute_force_counts, sign_assignments, signed_sums


ALTERNATIVES = ("two-sided", "B-slower")


def differences_for_slots(slot_pairs, assignment):
    """Assign labels to already fixed slot outcomes: +1 is AB; -1 is BA."""
    differences = []
    for (first, second), order in zip(slot_pairs, assignment):
        if order == 1:
            a, b = first, second
        else:
            b, a = first, second
        differences.append(b - a)
    return tuple(differences)


class IndependentOracleTests(unittest.TestCase):
    def test_full_assignments_include_zero_multiplicities(self):
        self.assertEqual(signed_sums((1, 2)), (-3, 1, -1, 3))
        self.assertEqual(Counter(signed_sums((0, 1))), {-1: 2, 1: 2})
        self.assertEqual(len(tuple(sign_assignments((0, 0, 0)))), 8)

    def test_oracle_has_hand_counted_inclusive_ties(self):
        for differences, expected_upper, expected_two in (
            ((1, -1), 3, 4),
            ((1, 1), 1, 2),
            ((-1, -1), 4, 2),
            ((0, 0), 4, 4),
            ((0, 0, 1), 4, 8),
            ((2**80, 1, 1 - 2**80), 3, 6),
        ):
            with self.subTest(differences=differences):
                denominator = 2 ** len(differences)
                self.assertEqual(brute_force_counts(differences, "B-slower"), (expected_upper, denominator))
                self.assertEqual(brute_force_counts(differences, "two-sided"), (expected_two, denominator))


class ExactKernelTests(unittest.TestCase):
    def setUp(self):
        try:
            self.exact_counts = importlib.import_module("benchinterlace.exact").exact_counts
        except (ImportError, AttributeError) as error:
            self.fail(f"The production exact_counts kernel is missing: {error}")

    def test_teaching_fixture(self):
        a = tuple(value * 1_000_000 for value in range(100, 241, 20))
        b = tuple(value + 10_000_000 for value in a)
        differences = tuple(right - left for left, right in zip(a, b))
        self.assertEqual(sum(differences), 80_000_000)
        self.assertEqual(Fraction(sum(a), len(a)), 170_000_000)
        self.assertEqual(Fraction(sum(b), len(b)), 180_000_000)
        self.assertEqual(Fraction(sum(b), sum(a)), Fraction(18, 17))
        self.assertEqual(Fraction(sum(differences), len(a)), 10_000_000)
        for alternative, expected in (("two-sided", (2, 256)), ("B-slower", (1, 256))):
            with self.subTest(alternative=alternative):
                self.assertEqual(brute_force_counts(differences, alternative), expected)
                self.assertEqual(self.exact_counts(differences, alternative), expected)

    def test_exhaustive_vectors_n2_through_n6_against_independent_oracle(self):
        # Detects strict boundaries, sign errors, dropped zero multiplicities,
        # wrong denominator, and mistakes in either half of the enumeration.
        started = time.perf_counter()
        vector_count = comparison_count = assignment_count = 0
        for n in range(2, 7):
            for differences in product(range(-2, 3), repeat=n):
                vector_count += 1
                for alternative in ALTERNATIVES:
                    expected = brute_force_counts(differences, alternative)
                    actual = self.exact_counts(differences, alternative)
                    self.assertEqual(actual, expected, (differences, alternative))
                    comparison_count += 1
                    assignment_count += expected[1]
        self.assertEqual(vector_count, 19_525)
        self.assertEqual(comparison_count, 39_050)
        self.assertEqual(assignment_count, 2_222_200)
        print(
            "EXACT_ORACLE_AUDIT "
            f"exhaustive_vectors={vector_count} comparisons={comparison_count} "
            f"enumerated_assignments={assignment_count} "
            f"elapsed_seconds={time.perf_counter() - started:.6f}",
            flush=True,
        )

    def test_deterministic_generated_vectors_through_n12(self):
        rng = random.Random(20261003)
        vector_count = comparison_count = assignment_count = 0
        started = time.perf_counter()
        for n in range(2, 13):
            for _ in range(12):
                differences = tuple(rng.randint(-10_000, 10_000) for _ in range(n))
                vector_count += 1
                for alternative in ALTERNATIVES:
                    expected = brute_force_counts(differences, alternative)
                    self.assertEqual(self.exact_counts(differences, alternative), expected, (differences, alternative))
                    comparison_count += 1
                    assignment_count += expected[1]
        self.assertEqual((vector_count, comparison_count, assignment_count), (132, 264, 196_512))
        print(
            "EXACT_ORACLE_AUDIT "
            f"generated_vectors={vector_count} comparisons={comparison_count} "
            f"enumerated_assignments={assignment_count} "
            f"elapsed_seconds={time.perf_counter() - started:.6f}",
            flush=True,
        )

    def test_equal_positive_negative_and_all_zero_vectors(self):
        for n in (2, 3, 8, 12, 40):
            denominator = 2**n
            for alternative in ALTERNATIVES:
                with self.subTest(n=n, alternative=alternative):
                    self.assertEqual(self.exact_counts((0,) * n, alternative), (denominator, denominator))
                    expected = 1 if alternative == "B-slower" else 2
                    self.assertEqual(self.exact_counts((7,) * n, alternative), (expected, denominator))
            # Negative observed T must not silently be turned into |T| for the
            # one-sided alternative. Small n avoids redundant n40 work.
            if n <= 12:
                self.assertEqual(self.exact_counts((-7,) * n, "B-slower"), (denominator, denominator))
                self.assertEqual(self.exact_counts((-7,) * n, "two-sided"), (2, denominator))

    def test_zero_statistic_uses_alternative_specific_tail(self):
        for differences, upper_count in (((1, -1), 3), ((1, -1, 0), 6), ((2, -2, 1, -1), 10)):
            denominator = 2 ** len(differences)
            with self.subTest(differences=differences):
                self.assertEqual(self.exact_counts(differences, "B-slower"), (upper_count, denominator))
                self.assertEqual(self.exact_counts(differences, "two-sided"), (denominator, denominator))

    def test_single_positive_with_zeros_preserves_multiplicities(self):
        for n in range(2, 13):
            differences = (5,) + (0,) * (n - 1)
            self.assertEqual(self.exact_counts(differences, "B-slower"), (2 ** (n - 1), 2**n))
            self.assertEqual(self.exact_counts(differences, "two-sided"), (2**n, 2**n))

    def test_python_integer_precision_and_cancellation(self):
        large = 2**80
        differences = (large, 1, 1 - large)
        self.assertEqual(sum(differences), 2)
        self.assertEqual(self.exact_counts(differences, "B-slower"), (3, 8))
        self.assertEqual(self.exact_counts(differences, "two-sided"), (6, 8))
        for differences in (
            (large, -large, 0, 1, -1),
            (-(2**63), 2**63 - 1),
            (2**53 + 1, -2**53, -2),
            (1, 30_000_000_000 - 1, -30_000_000_000 + 2),
        ):
            for alternative in ALTERNATIVES:
                self.assertEqual(self.exact_counts(differences, alternative), brute_force_counts(differences, alternative))

    def test_exact_count_return_contract_and_input_not_mutated(self):
        differences = [2, 0, -1, 7]
        before = differences.copy()
        for alternative in ALTERNATIVES:
            actual = self.exact_counts(differences, alternative)
            self.assertIs(type(actual), tuple)
            self.assertEqual(len(actual), 2)
            self.assertTrue(all(type(value) is int for value in actual))
            self.assertEqual(actual[1], 16)
            self.assertEqual(differences, before)
            self.assertEqual(actual, self.exact_counts(tuple(differences), alternative))

    def test_invalid_inputs_raise_value_error(self):
        invalid_differences = (
            None, 2, "12", b"12", {1, 2}, {0: 1, 1: 2}, iter((1, 2)),
            (), (1,), (0,) * 41, (True, 1), (1, False), (1, 1.0),
            (1, float("nan")), (1, float("inf")), (1, None), (1, "2"),
        )
        for differences in invalid_differences:
            with self.subTest(differences=repr(differences)):
                with self.assertRaises(ValueError):
                    self.exact_counts(differences, "two-sided")
        for alternative in (None, "", "greater", "less", "b-slower", "Two-sided", True, 2, [], {}):
            with self.subTest(alternative=repr(alternative)):
                with self.assertRaises(ValueError):
                    self.exact_counts((1, 2), alternative)

    def test_positive_scaling_and_pair_permutation_preserve_counts(self):
        for differences in ((1, -1), (0, 2, 2, -1), (-7, -5, 2, 0, 9), (2**80, 1, 1 - 2**80)):
            permuted = list(differences)
            random.Random(617).shuffle(permuted)
            for alternative in ALTERNATIVES:
                expected = self.exact_counts(differences, alternative)
                for changed in (tuple(reversed(differences)), permuted, tuple(13 * value for value in differences)):
                    self.assertEqual(self.exact_counts(changed, alternative), expected)

    def test_arm_swap_uses_inclusive_lower_tail_and_tie_identity(self):
        for differences in ((1, -1), (0, 0), (0, 2, 2, -1), (-7, -5, 2, 0, 9), (1, 2, 4)):
            swapped = tuple(-value for value in differences)
            observed = sum(differences)
            reference = signed_sums(differences)
            ties = sum(candidate == observed for candidate in reference)
            lower_count = sum(candidate <= observed for candidate in reference)
            upper, denominator = self.exact_counts(differences, "B-slower")
            swapped_upper, swapped_denominator = self.exact_counts(swapped, "B-slower")
            self.assertEqual(swapped_denominator, denominator)
            self.assertEqual(swapped_upper, lower_count)
            self.assertEqual(upper + swapped_upper, denominator + ties)
            self.assertEqual(self.exact_counts(differences, "two-sided"), self.exact_counts(swapped, "two-sided"))
        # Inclusive ties explicitly disprove an unqualified complement rule.
        self.assertEqual(self.exact_counts((1, -1), "B-slower"), (3, 4))

    def test_appending_zero_doubles_both_counts(self):
        for differences in ((1, -1), (0, 0), (2, 2, -1), (2**80, 1, 1 - 2**80)):
            for alternative in ALTERNATIVES:
                count, denominator = self.exact_counts(differences, alternative)
                self.assertEqual(self.exact_counts(differences + (0,), alternative), (2 * count, 2 * denominator))

    def test_within_pair_offsets_preserve_test_but_can_change_ratio(self):
        a, b = (10, 20, 30), (12, 25, 31)
        offsets = (100, 7, 900)
        shifted_a = tuple(value + offset for value, offset in zip(a, offsets))
        shifted_b = tuple(value + offset for value, offset in zip(b, offsets))
        differences = tuple(right - left for left, right in zip(a, b))
        shifted = tuple(right - left for left, right in zip(shifted_a, shifted_b))
        self.assertEqual(differences, shifted)
        self.assertNotEqual(Fraction(sum(b), sum(a)), Fraction(sum(shifted_b), sum(shifted_a)))
        self.assertEqual(Fraction(sum(b), sum(a)) * Fraction(sum(a), sum(b)), 1)
        for alternative in ALTERNATIVES:
            self.assertEqual(self.exact_counts(differences, alternative), self.exact_counts(shifted, alternative))

    def test_individual_sign_flip_preserves_distribution_not_observed_p(self):
        original, flipped = (1, 2, 4), (-1, 2, 4)
        self.assertEqual(Counter(signed_sums(original)), Counter(signed_sums(flipped)))
        for alternative in ALTERNATIVES:
            self.assertNotEqual(self.exact_counts(original, alternative), self.exact_counts(flipped, alternative))

    def test_eight_pair_fixed_slot_trend_exact_counts_and_rejection_rates(self):
        slots = tuple((1000 + 20 * pair, 1010 + 20 * pair) for pair in range(8))
        expected_upper = (256, 255, 247, 219, 163, 93, 37, 9, 1)
        expected_two = (2, 18, 74, 186, 256, 186, 74, 18, 2)
        multiplicities = Counter()
        rejected = Counter()
        for assignment in product((-1, 1), repeat=8):
            differences = differences_for_slots(slots, assignment)
            k = assignment.count(1)
            multiplicities[k] += 1
            self.assertEqual(sum(differences), 10 * (2 * k - 8))
            for alternative, expected in (("B-slower", expected_upper[k]), ("two-sided", expected_two[k])):
                actual = self.exact_counts(differences, alternative)
                self.assertEqual(actual, (expected, 256))
                self.assertEqual(actual, brute_force_counts(differences, alternative))
                if actual[0] * 20 <= actual[1]:
                    rejected[alternative] += 1
        self.assertEqual(multiplicities, {k: comb(8, k) for k in range(9)})
        self.assertEqual(rejected, {"B-slower": 9, "two-sided": 2})

    def test_uniform_assignment_error_bound_at_every_attainable_threshold(self):
        schedules = {
            "increasing": ((10, 11), (13, 15), (18, 22), (25, 33), (40, 56)),
            "decreasing": ((90, 81), (80, 76), (70, 68), (60, 59)),
            "oscillating": ((100, 109), (105, 98), (100, 107), (102, 97), (90, 93)),
            "tied": ((10, 10), (20, 20), (30, 30), (40, 40)),
            "partly_tied": ((10, 10), (20, 22), (30, 28), (40, 40), (50, 52), (60, 58)),
            "irregular": ((100, 119), (130, 123), (110, 111), (200, 200), (95, 82), (70, 74)),
        }
        for name, slots in schedules.items():
            denominator = 2 ** len(slots)
            numerators = {alternative: [] for alternative in ALTERNATIVES}
            for assignment in product((-1, 1), repeat=len(slots)):
                differences = differences_for_slots(slots, assignment)
                for alternative in ALTERNATIVES:
                    actual = self.exact_counts(differences, alternative)
                    self.assertEqual(actual, brute_force_counts(differences, alternative))
                    self.assertEqual(actual[1], denominator)
                    numerators[alternative].append(actual[0])
            # Check the entire integer grid, which includes all attainable
            # p-value thresholds, without rounding alpha through a float.
            for alternative in ALTERNATIVES:
                for threshold_numerator in range(denominator + 1):
                    rejected = sum(value <= threshold_numerator for value in numerators[alternative])
                    self.assertLessEqual(rejected, threshold_numerator, (name, alternative, threshold_numerator))

    def test_assignment_dependent_eligibility_can_destroy_conditional_validity(self):
        # All potential outcomes are defined under the sharp null. Publishing
        # only assignments with at least seven AB pairs selects favorable tails.
        slots = tuple((1000 + 20 * pair, 1010 + 20 * pair) for pair in range(8))
        eligible = 0
        eligible_rejections = Counter()
        all_attempt_rejections = Counter()
        for assignment in product((-1, 1), repeat=8):
            is_eligible = assignment.count(1) >= 7
            eligible += is_eligible
            differences = differences_for_slots(slots, assignment)
            for alternative in ALTERNATIVES:
                numerator, denominator = self.exact_counts(differences, alternative)
                rejects = numerator * 20 <= denominator
                all_attempt_rejections[alternative] += rejects
                eligible_rejections[alternative] += is_eligible and rejects
        self.assertEqual(eligible, 9)
        self.assertEqual(all_attempt_rejections, {"B-slower": 9, "two-sided": 2})
        self.assertEqual(eligible_rejections, {"B-slower": 9, "two-sided": 1})
        for alternative in ALTERNATIVES:
            # Unconditional no-rejection-on-failure remains <= 1/20.
            self.assertLessEqual(20 * eligible_rejections[alternative], 256)
            # Conditional on eligibility both alternatives exceed 1/20.
            self.assertGreater(20 * eligible_rejections[alternative], eligible)


@unittest.skipUnless(os.environ.get("BENCHINTERLACE_SCIPY_CROSSCHECK") == "1", "optional development-only SciPy cross-check")
class OptionalScipyTests(unittest.TestCase):
    def test_exhaustive_paired_sample_reference_distribution_and_tails(self):
        import numpy as np
        import scipy
        from scipy.stats import permutation_test

        exact_counts = importlib.import_module("benchinterlace.exact").exact_counts
        fixtures = ((1, -1), (0, 0), (1, 2, 4), (0, 2, -3, 5), (3, -1, 3, -1, 0, 0), (5,) * 8)
        for differences in fixtures:
            reference = Counter(signed_sums(differences))
            a = np.arange(100, 100 + len(differences), dtype=np.int64)
            b = a + np.asarray(differences, dtype=np.int64)
            for alternative, scipy_alternative in (("B-slower", "greater"), ("two-sided", "two-sided")):
                with self.subTest(differences=differences, alternative=alternative):
                    result = permutation_test(
                        (a, b),
                        lambda left, right: int(sum(right - left)),
                        permutation_type="samples",
                        vectorized=False,
                        n_resamples=np.inf,
                        alternative=scipy_alternative,
                    )
                    self.assertEqual(Counter(int(value) for value in result.null_distribution), reference)
                    expected = brute_force_counts(differences, alternative)
                    self.assertEqual(exact_counts(differences, alternative), expected)
                    self.assertEqual(result.pvalue, expected[0] / expected[1])
        print(f"EXACT_SCIPY_AUDIT scipy={scipy.__version__} numpy={np.__version__} fixtures={len(fixtures)} comparisons={2 * len(fixtures)}", flush=True)


if __name__ == "__main__":
    unittest.main()
