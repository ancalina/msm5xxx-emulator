import unittest

from msm5xxx_emulator.detection.fact_cache import facts_for, with_fact_scope


class FactCachePressureTests(unittest.TestCase):
    def test_discard_cached_releases_previous_facts(self):
        image = b"firmware"
        previous = facts_for(image)

        @with_fact_scope(discard_cached=True)
        def current():
            return facts_for(image)

        self.assertIsNot(current(), previous)

    def test_memory_error_inside_function_is_not_retried(self):
        calls = []

        @with_fact_scope
        def fail():
            calls.append(1)
            raise MemoryError

        with self.assertRaises(MemoryError):
            fail()
        self.assertEqual(calls, [1])
