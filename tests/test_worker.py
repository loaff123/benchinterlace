"""Resource and isolation contracts, independent of statistical oracle tests."""

import importlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


class WorkerTests(unittest.TestCase):
    def setUp(self):
        try:
            self.worker = importlib.import_module("benchinterlace.analysis_worker")
        except ImportError as exc:
            self.fail(f"The product-owned analysis worker is missing: {exc}")

    def assertUnsupported(self, result, code=None):
        self.assertEqual(result["status"], "unsupported")
        self.assertIsNone(result["tail_count"])
        self.assertIsNone(result["assignment_count"])
        self.assertNotIn("p", result)
        self.assertNotIn("p_decimal", result)
        if code:
            self.assertEqual(result["reason"]["code"], code)

    def test_structural_estimate_covers_integer_objects_overlap_and_sort(self):
        estimate = self.worker.resource_estimate([(1 << 63) - 1] * 40)
        self.assertEqual(estimate["n"], 40)
        self.assertEqual(estimate["right_entries"], 1 << 20)
        self.assertEqual(estimate["cap_bytes"], 128 * 1024 * 1024)
        self.assertGreaterEqual(estimate["integer_bytes"], sys.getsizeof(20 * ((1 << 63) - 1)))
        self.assertGreaterEqual(
            estimate["estimated_bytes"],
            (1 << 20) * (estimate["integer_bytes"] + 2 * estimate["pointer_bytes"])
            + (1 << 19) * estimate["pointer_bytes"],
        )
        self.assertTrue(estimate["within_cap"])

    def test_integer_magnitude_is_included_in_estimate(self):
        small = self.worker.resource_estimate([1] * 40)
        large = self.worker.resource_estimate([1 << 4096] * 40)
        self.assertGreater(large["estimated_bytes"], small["estimated_bytes"])
        self.assertFalse(large["within_cap"])

    def test_resource_rejection_occurs_before_process_launch(self):
        with mock.patch.object(self.worker.subprocess, "run") as launch:
            result = self.worker.run_exact([1 << 4096] * 40, "two-sided")
        launch.assert_not_called()
        self.assertUnsupported(result, "resource_limit")

    def test_parent_preflight_memory_error_is_explicit(self):
        with mock.patch.object(self.worker, "resource_estimate", side_effect=MemoryError):
            result = self.worker.run_exact([1, 1], "two-sided")
        self.assertUnsupported(result, "resource_limit")

    def test_limit_setup_memory_error_is_explicit(self):
        with mock.patch.object(self.worker, "_configure_limits", side_effect=MemoryError):
            result = self.worker._execute_request({"differences": [1, 2], "alternative": "two-sided"})
        self.assertUnsupported(result, "resource_limit")

    def test_invalid_input_is_not_launched_or_coerced(self):
        invalid = ([], [1], [1] * 41, [True, 1], [1.0, 1], ["1", 1], None)
        with mock.patch.object(self.worker.subprocess, "run") as launch:
            for differences in invalid:
                with self.subTest(differences=str(differences)[:80]):
                    with self.assertRaises(ValueError):
                        self.worker.run_exact(differences, "two-sided")
            with self.assertRaises(ValueError):
                self.worker.run_exact([1, 2], "greater")
        launch.assert_not_called()

    def test_real_worker_preserves_counts_and_reports_actual_limits(self):
        result = self.worker.run_exact([1, -1], "B-slower")
        self.assertEqual(result["status"], "available", result)
        self.assertEqual((result["tail_count"], result["assignment_count"]), (3, 4))
        self.assertIsNone(result["reason"])
        limits = result["limits"]
        self.assertEqual(limits["wall_seconds"], 30)
        if os.name == "posix" and self.worker._resource is not None:
            if hasattr(self.worker._resource, "RLIMIT_CPU"):
                self.assertLessEqual(limits["cpu_seconds"], 30)
            if hasattr(self.worker._resource, "RLIMIT_AS"):
                self.assertLessEqual(limits["address_space_bytes"], 256 * 1024 * 1024)
                self.assertEqual(limits["memory_enforcement"], "address-space")

    def test_worker_imports_from_product_path_not_caller_directory(self):
        original = Path.cwd()
        with tempfile.TemporaryDirectory() as temporary:
            Path(temporary, "benchinterlace.py").write_text("raise AssertionError('shadowed')\n")
            try:
                os.chdir(temporary)
                with mock.patch.dict(os.environ, {"PYTHONPATH": temporary}):
                    result = self.worker.run_exact([2, 2], "two-sided")
            finally:
                os.chdir(original)
        self.assertEqual(result["status"], "available", result)
        self.assertEqual(result["tail_count"], 2)

    def test_launch_is_owned_fixed_python_and_wall_bounded(self):
        real_run = subprocess.run
        captured = []

        def recording_run(*args, **kwargs):
            captured.append((args, kwargs))
            return real_run(*args, **kwargs)

        with mock.patch.object(self.worker.subprocess, "run", side_effect=recording_run):
            result = self.worker.run_exact([1, 1], "B-slower")
        self.assertEqual(result["status"], "available", result)
        argv = captured[0][0][0]
        self.assertEqual(argv[0], sys.executable)
        self.assertEqual(argv[1:3], ["-I", "-c"])
        self.assertEqual(captured[0][1]["timeout"], 30)
        self.assertFalse(captured[0][1].get("shell", False))

    def test_worker_timeout_withholds_all_inference(self):
        with mock.patch.object(self.worker.subprocess, "run", side_effect=subprocess.TimeoutExpired("owned worker", 30)):
            result = self.worker.run_exact([1, 1], "two-sided")
        self.assertUnsupported(result, "resource_limit")

    def test_real_wall_watchdog_kills_and_reaps_only_owned_worker(self):
        real_popen = subprocess.Popen
        children = []

        def record_child(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            children.append(process)
            return process

        with mock.patch.object(self.worker.subprocess, "Popen", side_effect=record_child):
            with mock.patch.object(self.worker, "WALL_SECONDS", 0.001):
                result = self.worker.run_exact([1] * 40, "B-slower")
        self.assertUnsupported(result, "resource_limit")
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        if os.name == "posix":
            with self.assertRaises(ChildProcessError):
                os.waitpid(children[0].pid, os.WNOHANG)

    def test_worker_death_withholds_all_inference(self):
        dead = subprocess.CompletedProcess([sys.executable], -9, b"", b"")
        with mock.patch.object(self.worker.subprocess, "run", return_value=dead):
            result = self.worker.run_exact([1, 1], "two-sided")
        self.assertUnsupported(result, "resource_limit")

    def test_worker_unavailable_withholds_all_inference(self):
        with mock.patch.object(self.worker.subprocess, "run", side_effect=OSError("unavailable")):
            result = self.worker.run_exact([1, 1], "two-sided")
        self.assertUnsupported(result, "unsupported_primitive")

    def test_untrusted_worker_output_is_rejected(self):
        bad_outputs = (b"not json", b"{}", b'{"tail_count":true,"assignment_count":4}', b"x" * 16385, b"[" * 1500 + b"]" * 1500)
        for output in bad_outputs:
            with self.subTest(output=output[:80]):
                reply = subprocess.CompletedProcess([sys.executable], 0, output, b"")
                with mock.patch.object(self.worker.subprocess, "run", return_value=reply):
                    result = self.worker.run_exact([1, 1], "two-sided")
                self.assertUnsupported(result, "internal_error")

    def test_duplicate_worker_fields_are_rejected(self):
        result = self.worker.run_exact([1, 1], "two-sided")
        self.assertEqual(result["status"], "available", result)
        output = json.dumps(result).replace('"tail_count": 2', '"tail_count": 4, "tail_count": 2').encode()
        reply = subprocess.CompletedProcess([sys.executable], 0, output, b"")
        with mock.patch.object(self.worker.subprocess, "run", return_value=reply):
            result = self.worker.run_exact([1, 1], "two-sided")
        self.assertUnsupported(result, "internal_error")

    def test_existing_stricter_limits_are_never_relaxed(self):
        class ResourceModel:
            RLIMIT_CPU = 0
            RLIMIT_AS = 1
            RLIM_INFINITY = -1

            def __init__(self):
                self.limits = {0: (10, 20), 1: (128 * 1024 * 1024, -1)}

            def getrlimit(self, primitive):
                return self.limits[primitive]

            def setrlimit(self, primitive, limits):
                self.limits[primitive] = limits

        model = ResourceModel()
        with mock.patch.object(self.worker, "_resource", model):
            with mock.patch.object(self.worker.os, "name", "posix"):
                result = self.worker._configure_limits()
        self.assertEqual(model.limits[0], (10, 10))
        self.assertEqual(model.limits[1], (128 * 1024 * 1024,) * 2)
        self.assertEqual(result["cpu_seconds"], 10)
        self.assertEqual(result["address_space_bytes"], 128 * 1024 * 1024)

    def test_memory_error_in_worker_has_no_counts(self):
        with mock.patch.object(self.worker, "_configure_limits", return_value=self.worker._empty_limits()):
            with mock.patch.object(self.worker, "exact_counts", side_effect=MemoryError):
                result = self.worker._execute_request({"differences": [1, 2], "alternative": "two-sided"})
        self.assertUnsupported(result, "resource_limit")

    def test_limit_setup_failure_does_not_start_computation(self):
        with mock.patch.object(self.worker, "_configure_limits", side_effect=OSError("not supported")):
            with mock.patch.object(self.worker, "exact_counts") as kernel:
                result = self.worker._execute_request({"differences": [1, 2], "alternative": "two-sided"})
        kernel.assert_not_called()
        self.assertUnsupported(result, "unsupported_primitive")

    def test_missing_os_memory_enforcement_is_explicit(self):
        with mock.patch.object(self.worker, "_resource", None):
            limits = self.worker._configure_limits()
        self.assertIsNone(limits["address_space_bytes"])
        self.assertIsNone(limits["cpu_seconds"])
        self.assertEqual(limits["memory_enforcement"], "structural allocation cap only")


if __name__ == "__main__":
    unittest.main()
