"""Synthetic reset, device decoding and persistence without a CPU backend."""
from copy import deepcopy
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch, Mock

from msm5xxx_emulator.core.config import LinkerLayout, BoardStatusInput
from msm5xxx_emulator.core.initial_state import initial_register_state
from msm5xxx_emulator.detection.firmware import detect
from msm5xxx_emulator.qemu.decoder import QemuDecoder
from msm5xxx_emulator.qemu.transport import qemu_memory_profile


class QemuDecoderTests(unittest.TestCase):
    def config(self, directory):
        # Same exception-vector fixture as test_eeprom, with a patterned RAM seed.
        raw = bytearray(b'\xff' * 0x3000)
        for offset in range(0, 32, 4):
            struct.pack_into('<I', raw, offset, 0xEA000000)
        raw[0x400:0x1400] = bytes(range(256)) * 16
        path = Path(directory) / 'synthetic.bin'
        path.write_bytes(raw)
        config = detect(path)
        config.width = config.height = 32
        config.flash_size = 0x4000
        config.ram_base, config.ram_size = 0x01000000, 0x400000
        config.ram_image_offset, config.ram_image_size = 0x400, 0x1000
        config.flash_state = str(Path(directory) / 'flash.json')
        config.secondary_flash_state = str(Path(directory) / 'secondary.json')
        return config

    def decoder(self, config):
        decoder = QemuDecoder(config)
        self.addCleanup(decoder.close)
        return decoder

    def test_initial_registers_memory_profile_and_memory_bytes(self):
        for linker in (False, True):
            with self.subTest(linker=linker), tempfile.TemporaryDirectory() as directory:
                config = self.config(directory)
                if linker:
                    config.linker = LinkerLayout(0, 0x400, config.ram_base + 0x100,
                                                0x40, config.ram_base + 0x140, 0x200)
                config.key_register = 0x03000738
                config.board_revision_register = 0x03000740
                config.board_revision_value = 0x12345678
                config.board_status_input = BoardStatusInput(0x03000744, 8, 8)
                decoder = self.decoder(config)
                registers = initial_register_state(config)
                self.assertEqual(registers["sp"], 0x01100ffc if linker else 0x013ffffc)
                self.assertEqual(registers["cpsr"], 0xd3)
                self.assertTrue(all(value == 0 for key, value in registers.items()
                                    if key not in ("sp", "cpsr")))
                self.assertEqual(qemu_memory_profile(config, registers),
                                 "4000:1000000:1100ffc" if linker else "4000:1000000:13ffffc")
                self.assertEqual(decoder.initial_memory.read(config.load_address, 4),
                                 struct.pack('<I', 0xEA000000))
                self.assertEqual(decoder.initial_memory.read(config.ram_base, 256),
                                 bytes(range(256)))
                self.assertEqual(decoder.initial_memory.read(0xfffff000, 0x1000),
                                 b'\xff' * 0x1000)
                self.assertIsNone(decoder.uc)

    def test_framebuffer_initial_render_and_format_changes(self):
        for seeded in (False, True):
            with self.subTest(seeded=seeded), tempfile.TemporaryDirectory() as directory:
                config = self.config(directory)
                if not seeded:
                    config.ram_image_size = 0
                config.framebuffer_address = config.ram_base + 0x100
                config.framebuffer_stride = 68
                config.framebuffer_format = "rgb565le"
                decoder = self.decoder(config)
                for fmt in ('rgb565le', 'bgr565be', 'rgb565be', 'bgr565le'):
                    decoder.set_framebuffer_format(fmt)
                    width, height, pixels = decoder.display_snapshot()
                    self.assertEqual((width, height, len(pixels)), (32, 32, 32 * 32 * 3))
                    self.assertEqual(decoder.firmware_frame_sequence, 0)
                if seeded:
                    self.assertTrue(any(decoder.display_snapshot()[-1]))

    def test_lcd_write_and_audio_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            decoder = self.decoder(self.config(directory))
            # Exercise the shared ownership decision with a recording transport.
            decoder.audio_transport = Mock(static_status='accepted', base=0x02000000,
                                          data_offset=2)
            decoder.audio_transport.owns_write.return_value = False
            decoder._lcd_write(decoder.uc, 0, 0x02000000, 1, 0x22, None)
            decoder.audio_transport.owns_write.assert_called_once_with(0, 0x02000000, 1)
            decoder.audio_transport.owns_write.return_value = True
            decoder._lcd_write(decoder.uc, 0, 0x02000002, 1, 0xff, None)
            self.assertEqual(decoder.lcd_writes, 1)
            decoder._lcd_write(decoder.uc, 0, 0x02000000, 2, 0x22, None)
            for value in (0xf800, 0x07e0, 0x001f) * 342:
                decoder._lcd_write(decoder.uc, 0, 0x02000002, 2, value, None)
            decoder._flush_indexed_frame()
            decoder._lcd_page_flush_current()
            self.assertGreater(decoder.frame_sequence, 0)

    def test_descriptor_input_config_side_effects(self):
        # Exercise the accepted descriptor branch, including IRQ metadata mutation.
        descriptor = dict(function=0x100, prologue=0x100, sense_site=0x110,
                          raw_enqueue=0x200, raw_enqueue_callsite=0x120,
                          sense_sites=[0x108, 0x110], global_sense_sites=[0x108],
                          row_sense_sites=[0x110], raw_enqueue_callsites=[0x120],
                          row_state_evidence='synthetic', row_state_site=0x114,
                          absolute_roles={'sense': 0x0300072c}, family='synthetic',
                          grammar_fingerprint='synthetic-descriptor', rows=1, columns=2,
                          event_codes=[0x50, 0x52], no_key=0x1f, senses=[0x1e, 0x1d])
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(directory)
            config.rex_idle_address = 0x300
            bridge = dict(scanner=0x100, outer_callback=0x400)
            route = dict(controller_class='legacy-c80-two-bank-group10-v1',
                         outer_callback=0x400, vector_target=config.ram_base,
                         handler_slot=config.ram_base + 4, callback_slot=config.ram_base + 8,
                         wrapper=0x500, handler=0x600, status=0x03000c80,
                         enable=0x03000ca0, mask=1, status_bank_count=2,
                         status_banks=(0x03000c80, 0x03000c84),
                         clear_banks=(0x03000c80, 0x03000c84),
                         controller_write_banks=(0x03000ca0, 0x03000ca4),
                         group_row_size=10, controller_aperture=(0x03000c80, 0x03000ca6))
            prefix = 'msm5xxx_emulator.devices.input.'
            with patch(prefix + 'resolve_direct_matrix_input', return_value=(None, 'not-found', [])), \
                 patch(prefix + 'resolve_lg_descriptor_input', side_effect=lambda _: (deepcopy(descriptor), 'accepted', [])), \
                 patch(prefix + 'find_rex_legacy_5ms_timer_bridge', return_value=bridge), \
                 patch(prefix + 'find_rex_legacy_5ms_irq_route', return_value=route):
                decoder = self.decoder(config)
            self.assertEqual(decoder.direct_input_detection, 'accepted')
            self.assertTrue(decoder.direct_input_positions)
            self.assertEqual(decoder.direct_input_profile['grammar_fingerprint'],
                             'synthetic-descriptor')
            self.assertEqual(decoder.config.rex_tick_ms, 5)
            self.assertEqual(decoder.config.rex_irq_status_address, route['status'])

    def test_storage_close_save_and_native_nand_ownership(self):
        for native in (False, True):
            with self.subTest(native=native), tempfile.TemporaryDirectory() as directory:
                config = self.config(directory)
                config.secondary_flash_address = 0x80000000
                config.secondary_flash_size = 0x1000
                config.upper_flash_address = 0x02800000
                config.upper_flash_size = 0x00800000
                config.eeprom_static_capacity = 0x2000
                config.eeprom_read_address, config.eeprom_write_address = 0x100, 0x200
                config.nand_enabled = True
                config.nand_data_size, config.nand_page_size = 512, 256
                config.nand_spare_size, config.nand_pages_per_block = 16, 2
                state = Path(directory) / 'state'
                state.mkdir()
                selected = deepcopy(config)
                selected.flash_state = str(state / 'flash.json')
                selected.secondary_flash_state = str(state / 'secondary.json')
                selected.upper_flash_state = str(state / 'upper.json')
                device = QemuDecoder(selected, native_nand=native)
                try:
                    self.assertEqual(bool(device.nand_image), not native)
                    for flash in (device.flash, device.secondary_flash, device.upper_flash):
                        flash.program(0x2000 if flash is device.flash else 0, b'\x5a\xa5')
                    device.eeprom_data[:] = bytes(0x2000)
                    device.eeprom_data[3:5] = b'\x12\x34'
                    if not native:
                        device.nand_image[1] = 0x50
                finally:
                    device.close()
                saved = {path.name: path.read_bytes() for path in state.iterdir()
                         if path.suffix in ('.json', '.bin')}
                self.assertIn('flash.json', saved)
                self.assertIn('secondary.json', saved)
                self.assertIn('upper.json', saved)
                self.assertIn('flash.json.eeprom.bin', saved)
                eeprom = saved['flash.json.eeprom.bin']
                self.assertEqual((len(eeprom), eeprom[3:5]), (0x2000, b'\x12\x34'))
                self.assertEqual('flash.json.nand.bin' in saved, not native)
