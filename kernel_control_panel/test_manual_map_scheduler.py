"""Kernel mapping participates in mutation admission; no device/target access."""
import unittest

from request_scheduler import Scheduler, priority


class ManualMapSchedulerTests(unittest.TestCase):
    def driver(self, fail=False):
        class Driver:
            def read_process_memory_snapshot(self, *args):
                return {'success': True, 'data_hex': ''}

            def manual_map_dll(self, pid, path):
                self.observed = (priority.get(), self._lock._is_owned(), self.scheduler.epoch)
                if fail:
                    raise RuntimeError('transport result unknown')
                return {'success': True}

        driver = Driver()
        driver.scheduler = Scheduler(driver)
        return driver

    def test_map_admits_as_write_and_invalidates_inflight_read_epoch(self):
        driver = self.driver()
        self.assertEqual(driver.manual_map_dll(42, r'C:\Example.dll'), {'success': True})
        self.assertEqual(driver.observed, (0, True, 1))
        self.assertEqual(driver.scheduler.epoch, 2)
        self.assertFalse(driver._lock._is_owned())

    def test_unknown_result_still_advances_epoch_and_releases_admission(self):
        driver = self.driver(fail=True)
        with self.assertRaisesRegex(RuntimeError, 'unknown'):
            driver.manual_map_dll(42, r'C:\Example.dll')
        self.assertEqual(driver.observed, (0, True, 1))
        self.assertEqual(driver.scheduler.epoch, 2)
        self.assertFalse(driver._lock._is_owned())


if __name__ == '__main__':
    unittest.main()
