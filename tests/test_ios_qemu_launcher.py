"""In-process launcher contract, without starting QEMU or loading firmware."""
import subprocess
import unittest
from unittest.mock import Mock, patch

from msm5xxx_emulator.qemu.transport import IOSLauncher, Transport, launch_qemu


class IOSLauncherTests(unittest.TestCase):
    def setUp(self):
        self.host = Mock()
        self.host.poll.return_value = None
        self.host.wait.return_value = 0
        self.launcher = IOSLauncher(self.host)
        self.argv = ["QEMUTCI", "-M", "msm5xxx", "-chardev",
                     "socket,id=lcd,host=127.0.0.1,port=12345,server=off,nodelay=on",
                     "-no-shutdown"]

    def test_default_keeps_subprocess_options_and_argv(self):
        with patch("msm5xxx_emulator.qemu.transport.subprocess.Popen") as popen:
            process = launch_qemu(self.argv, stderr="log", text=True,
                                  pass_fds=(17,))
        popen.assert_called_once_with(self.argv, stderr="log", text=True,
                                      pass_fds=(17,))
        self.assertIs(process, popen.return_value)

    def test_ios_delivers_identical_argv_without_spawning(self):
        with patch("msm5xxx_emulator.qemu.transport.subprocess.Popen") as popen:
            process = launch_qemu(self.argv, launcher=self.launcher,
                                  stdout=subprocess.DEVNULL, stderr="log", text=True)
        popen.assert_not_called()
        self.host.start.assert_called_once_with(self.argv)
        self.assertIsNone(process.poll())
        self.host.poll.return_value = 7
        self.assertEqual(process.poll(), 7)
        self.assertEqual(process.wait(0.1), 0)
        self.host.wait.assert_called_once_with(0.1)

    def test_host_timeout_uses_transport_timeout_contract(self):
        process = self.launcher(self.argv)
        self.host.wait.side_effect = TimeoutError("still running")
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            process.wait(2)
        self.assertEqual(caught.exception.cmd, self.argv)
        self.assertEqual(caught.exception.timeout, 2)

    def test_transport_shutdown_calls_host_only(self):
        value = Transport.__new__(Transport)
        value.process = self.launcher(self.argv)
        value._finish_native_nand = Mock()
        self.host.wait.side_effect = [TimeoutError(), 0]
        value._terminate_process()
        self.host.terminate.assert_called_once_with()
        self.host.kill.assert_called_once_with()
        self.assertEqual(self.host.wait.call_count, 2)

    def test_finished_host_is_not_terminated(self):
        value = Transport.__new__(Transport)
        value.process = self.launcher(self.argv)
        value._finish_native_nand = Mock()
        self.host.poll.return_value = 0
        value._terminate_process()
        self.host.terminate.assert_not_called()
        self.host.kill.assert_not_called()

    def test_invalid_arguments_and_fd_inheritance_fail_before_host(self):
        for argv, options in [(self.argv, {"pass_fds": (17,)}),
                              ([], {}), (["qemu", "bad\0arg"], {}),
                              (["qemu", 1], {})]:
            with self.subTest(argv=argv, options=options):
                with self.assertRaises(ValueError):
                    self.launcher(argv, **options)
        self.host.start.assert_not_called()
        self.assertFalse(self.launcher.supports_pass_fds)

    def test_start_failure_propagates_without_a_process(self):
        self.host.start.side_effect = RuntimeError("QEMU already used")
        with self.assertRaisesRegex(RuntimeError, "already used"):
            self.launcher(self.argv)


if __name__ == "__main__":
    unittest.main()
