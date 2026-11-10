"""Synthetic source relocation and loaded-image/ownership admission checks."""
import hashlib,struct,unittest
from types import SimpleNamespace
from unittest.mock import patch
from msm5xxx_emulator.detection.registry import device_domain
_arm_shape = device_domain('external_bus.boot_contact_5100')._arm_shape
from msm5xxx_emulator.qemu.transport import qemu_boot_contact_property


class BootContactBindingTests(unittest.TestCase):
    def test_arm_normalization_retains_internal_edges_and_operands(self):
        image=bytearray(0x300)
        struct.pack_into('<4I',image,0x100,0xe59f0018,0xeaffffff,0xea00003c,0xe1a00000)
        struct.pack_into('<I',image,0x120,0x1234)
        digest=hashlib.sha256(struct.pack('<4I',0xe59f0000,0xeaffffff,0xea000000,0xe1a00000)).hexdigest()
        def find(data):return _arm_shape(bytes(data),0x100,16,digest,((0,0xe59f0000),),(8,))
        result=find(image);self.assertEqual(result[0],{0:0x1234});self.assertEqual(result[2],{8:0x200})
        relocated=bytearray(image);struct.pack_into('<I',relocated,0x100,0xe59f0028);struct.pack_into('<I',relocated,0x130,0x1234)
        self.assertEqual(find(relocated)[1],[(0x130,0x134)])
        for at,word in [(0x104,0xeafffffe),(0x100,0xe59f1018),(0x108,0xeb00003c)]:
            bad=bytearray(image);struct.pack_into('<I',bad,at,word);self.assertIsNone(find(bad))

    def test_loaded_source_config_and_port_owners(self):
        profile=dict(address=0x0300066c,mask=4,width=1,read_pcs=[0x80],
            code_intervals=[[0,4]],literal_intervals=[[8,12]],display_source_intervals=[[16,20]],
            ram_intervals=[[0x01000000,0x01000040]],display_ram_intervals=[[0x01000100,0x01000200]])
        cfg=SimpleNamespace(load_address=0,image_offset=0,entry=0,flash_size=256,
            ram_base=0x01000000,ram_size=0x1000,image_kind='firmware',chipset='MSM5105')
        original=bytes(256)
        with patch('msm5xxx_emulator.detection.devices.external_bus.boot_contact_5100.find_boot_contact_release',return_value=(profile,'synthetic')):
            def bind(**kw):return qemu_boot_contact_property(cfg,original,original,**kw)
            self.assertEqual(bind()[0],'experimental-boot-contact=300066c:80:4:1')
            for options in [dict(input_claimed=True),dict(layout_claimed=True),dict(eeprom_window=(0x03000660,32)),dict(eeprom_window=(0x0300066f,1))]:
                self.assertIsNone(bind(**options)[0])
            self.assertIsNotNone(bind(eeprom_window=(0x03000670,32))[0])
            self.assertIsNone(qemu_boot_contact_property(cfg,original,original[:-1]+b'1')[0])
            short=original[:128];padded=short.ljust(256,b'\xff')
            self.assertIsNotNone(qemu_boot_contact_property(cfg,short,padded)[0])
            self.assertIsNone(qemu_boot_contact_property(cfg,short,padded[:-1]+b'1')[0])
            for field,value in [('ram_size',16),('entry',4),('board_status_input',object()),('spi_nv_profile',{}),('boot_keysense_release',{'mask':2}),('chipset','MSM6000')]:
                setattr(cfg,field,value);self.assertIsNone(bind()[0]);delattr(cfg,field)
                if field=='ram_size':cfg.ram_size=0x1000
                if field=='entry':cfg.entry=0
