import unittest

from msm5xxx_emulator.qemu.transport import qemu_uart_console_property


class UARTConsoleTransportTests(unittest.TestCase):
    def profile(self):
        return dict(signature="thumb-uart-sync-console-v1",
                    admission="temporary-evidence-gated",
                    policy="provisional-synchronous-null-console",
                    base=0x03000F0C, status_address=0x03000F14,
                    fifo_address=0x03000F18, control_address=0x03000F1C,
                    isr_address=0x03000F20, pulse_address=0x03000700,
                    primary_entry=0x100, init_entry=0x200, tx_entry=0x300)

    def test_tfwr_halfword_is_a_distinct_contract(self):
        profile = self.profile()
        profile.update(signature="thumb-uart-byte-tfwr16-sync-console-v1",
                       register_width=1, csr_value=0xff)
        self.assertEqual(qemu_uart_console_property(profile, 0x400),
                         ("uart-console=3000f0c:1:ff:2", None))
        profile['register_width'] = 2
        self.assertEqual(qemu_uart_console_property(profile, 0x400),
                         (None, "unsupported-register-wire"))

    def test_contract_and_alias_boundaries(self):
        self.assertEqual(qemu_uart_console_property(None, 0), (None, None))
        self.assertEqual(qemu_uart_console_property(self.profile(), 0x400),
                         ("uart-console=3000f0c", None))
        cases = (("signature", "unknown"), ("admission", "accepted"),
                 ("policy", "physical-serial"), ("base", True),
                 ("base", 0x03000F0D), ("base", 0x04000000),
                 ("status_address", 0x03000F20), ("fifo_address", None),
                 ("control_address", 0x03000F18), ("isr_address", True),
                 ("pulse_address", 0x03000F10), ("pulse_address", 0),
                 ("primary_entry", -2), ("init_entry", 0x400),
                 ("tx_entry", 0x301), ("tx_entry", 0x100),
                 ("tx_entry", []))
        for field, value in cases:
            with self.subTest(field=field, value=value):
                profile = self.profile(); profile[field] = value
                argument, reason = qemu_uart_console_property(profile, 0x400)
                self.assertIsNone(argument); self.assertIsNotNone(reason)
        for malformed in ([], True, "3000f0c", {}):
            self.assertIsNone(qemu_uart_console_property(malformed, 0x400)[0])
        for size in (0, -1, True):
            self.assertIsNone(qemu_uart_console_property(self.profile(), size)[0])

    def test_typed_byte_wire_and_modern_compatibility(self):
        profile = self.profile()
        profile.update(signature="thumb-uart-byte-sync-console-v1", register_width=1,
                       csr_value=0xFF, base=0x030007AC, status_address=0x030007B4,
                       fifo_address=0x030007B8, control_address=0x030007BC,
                       isr_address=0x030007C0, pulse_address=0x03000600)
        self.assertEqual(qemu_uart_console_property(profile, 0x400),
                         ("uart-console=30007ac:1:ff", None))
        for field, value in (("register_width", True), ("register_width", 2),
                             ("csr_value", 0x99), ("csr_value", 255.0)):
            bad = dict(profile); bad[field] = value
            self.assertEqual(qemu_uart_console_property(bad, 0x400),
                             (None, "unsupported-register-wire"))
        missing = dict(profile); del missing["register_width"]
        self.assertIsNone(qemu_uart_console_property(missing, 0x400)[0])
        modern = self.profile()
        modern.update(register_width=2, csr_value=0x99)
        self.assertEqual(qemu_uart_console_property(modern, 0x400),
                         ("uart-console=3000f0c", None))
        modern.update(register_width=1, csr_value=0xFF)
        self.assertEqual(qemu_uart_console_property(modern, 0x400),
                         (None, "unsupported-register-wire"))

    def test_dd_requires_its_own_complete_typed_contract(self):
        profile = self.profile()
        profile.update(signature="thumb-uart-sync-console-dd-v1", register_width=2,
                       csr_value=0xDD)
        self.assertEqual(qemu_uart_console_property(profile, 0x400),
                         ("uart-console=3000f0c:2:dd", None))
        for field, value in (("register_width", 1), ("register_width", True),
                             ("csr_value", 0x99), ("csr_value", 221.0),
                             ("signature", "thumb-uart-sync-console-v1"),
                             ("signature", []), ("status_address", 0x030007B4),
                             ("pulse_address", 0x03000F18)):
            with self.subTest(field=field, value=value):
                bad = dict(profile); bad[field] = value
                self.assertIsNone(qemu_uart_console_property(bad, 0x400)[0])
        for field in ("register_width", "csr_value"):
            bad = dict(profile); del bad[field]
            self.assertEqual(qemu_uart_console_property(bad, 0x400),
                             (None, "unsupported-register-wire"))
