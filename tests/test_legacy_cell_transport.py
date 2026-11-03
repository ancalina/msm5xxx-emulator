"""Bind the opt-in legacy cell to instruction signatures, not image names."""
from pathlib import Path
import unittest
from corpus import firmware_path
from msm5xxx_emulator.detection import detect
from msm5xxx_emulator.detection.baseband import find_legacy_cdma_profile
from msm5xxx_emulator.qemu.transport import qemu_virtual_cell_property
from msm5xxx_emulator.qemu.virtual_cell import virtual_cell_scenario


class LegacyCellTransportTests(unittest.TestCase):
    def test_profiles_and_default_scenarios(self):
        cases = [
            (firmware_path('T030TEDT09_5.177_JTAG - Old Phone Preservation.bin'),22,17500,750),
            (firmware_path('incoming-msm5xxx-all-manufacturers-20260726','Audiovox','CDM-8500',
                           'T050VMDM01_3.191_JTAG','T050VMDM01_3.191_JTAG.bin'),24,4120,625),
        ]
        for image, bits, sid, channel in cases:
            with self.subTest(image=image.name):
                data=image.read_bytes(); profile=find_legacy_cdma_profile(data)
                self.assertTrue(profile['accepted'],profile)
                self.assertEqual(profile['pll_bits'],bits)
                config=detect(image)
                self.assertEqual(qemu_virtual_cell_property(data,config,None),(None,None))
                prop,reason=qemu_virtual_cell_property(data,config,virtual_cell_scenario(True))
                self.assertEqual(reason,'legacy-receive-only')
                values=dict(item.split('=',1) for item in prop.split(','))
                self.assertEqual(values['legacy-cdma'],'on')
                self.assertEqual(int(values['legacy-search'].split(':')[-1],16),channel)
                parts=values['legacy-decoder'].split(':')
                sync=int(parts[1],16); neighbor=bytes.fromhex(parts[4]); paging=int(parts[5],16)
                self.assertEqual((sync>>(208-32-15))&0x7fff,sid)
                self.assertEqual((sync>>(208-167-11))&0x7ff,channel)
                self.assertEqual(neighbor[1],14)
                self.assertEqual((paging>>(72-31-11))&0x7ff,channel)
                for key in ('writer','consumer','descriptor','decoder','sync_mode','paging_mode','pll'):
                    changed=bytearray(data); changed[profile[key]]^=1
                    self.assertFalse(find_legacy_cdma_profile(bytes(changed))['accepted'],key)
