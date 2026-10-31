"""Actual CFI02 map admission preserves default containment and disjoint owners."""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

class AMDAdjacentNativeTests(unittest.TestCase):
 def test_explicit_lower_bank_and_conflicts(self):
  source=(Path(__file__).resolve().parents[1]/'native/qemu/msm5xxx-poc.c').read_text()
  name='msm5xxx_poc_amd_mapping_valid';match=re.search(r'^static [^\n]*(?:\n[^\n]*)?\b'+name+r'\(',source,re.M)
  self.assertIsNotNone(match);brace=source.index('{',match.end());depth=1;end=brace+1
  while depth:
   depth+=(source[end]=='{')-(source[end]=='}');end+=1
  code='''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#define MSM5XXX_POC_LCD_APERTURE_BASE 0x02000000
 typedef struct {
 bool amd_x16_nor_enabled,amd_adjacent_nv,memory_profile_enabled;
 uint32_t intel_x16_nor_base,intel_x16_nor_size,ram_base,primary_nor_size,audio_base,audio_data_offset;
 bool intel_x16_nor_enabled,fujitsu_x16_nor_enabled,primary_x16_nor_enabled,record_x16_nor_enabled;
 bool mapped_primary_x16_nor_enabled,whole_primary_x16_enabled,protected_nor_enabled;
 bool upper_x8_nor_enabled,upper_x16_nor_enabled,raw_nand_main_enabled,small_nand_enabled,audio_enabled;
} MSM5xxxPOCMachineState;
'''+source[match.start():end]+'''
int main(void) {
 MSM5xxxPOCMachineState s={0};s.ram_base=0x1000000;
 assert(msm5xxx_poc_amd_mapping_valid(&s,0x800000));
 s.amd_adjacent_nv=true;assert(!msm5xxx_poc_amd_mapping_valid(&s,0x800000));
 s.amd_adjacent_nv=false;s.amd_x16_nor_enabled=true;
 s.intel_x16_nor_base=0x1000000;s.intel_x16_nor_size=0x200000;
 assert(msm5xxx_poc_amd_mapping_valid(&s,0x800000));
 s.intel_x16_nor_base=0x400000;s.primary_nor_size=0x400000;
 assert(!msm5xxx_poc_amd_mapping_valid(&s,0x800000));
 s.amd_adjacent_nv=true;assert(!msm5xxx_poc_amd_mapping_valid(&s,0x800000));
 s.memory_profile_enabled=true;assert(msm5xxx_poc_amd_mapping_valid(&s,0x800000));
 s.intel_x16_nor_base=0x300000;assert(!msm5xxx_poc_amd_mapping_valid(&s,0x800000));
 s.intel_x16_nor_base=0x500000;assert(!msm5xxx_poc_amd_mapping_valid(&s,0x800000));
 s.intel_x16_nor_base=s.primary_nor_size=0x800000;s.intel_x16_nor_size=0x800000;
 assert(msm5xxx_poc_amd_mapping_valid(&s,0x800000));
 s.intel_x16_nor_size++;assert(!msm5xxx_poc_amd_mapping_valid(&s,0x800000));
 s.intel_x16_nor_base=s.primary_nor_size=0x400000;s.intel_x16_nor_size=0x200000;
 bool *conflicts[]={&s.intel_x16_nor_enabled,&s.fujitsu_x16_nor_enabled,&s.primary_x16_nor_enabled,
 &s.record_x16_nor_enabled,&s.mapped_primary_x16_nor_enabled,&s.whole_primary_x16_enabled,
 &s.protected_nor_enabled,&s.upper_x8_nor_enabled,&s.upper_x16_nor_enabled,&s.raw_nand_main_enabled,&s.small_nand_enabled};
 for(unsigned i=0;i<sizeof(conflicts)/sizeof(conflicts[0]);i++) {
  *conflicts[i]=true;assert(!msm5xxx_poc_amd_mapping_valid(&s,0x800000));*conflicts[i]=false;
 }
 s.audio_enabled=true;s.audio_base=0x5fffff;s.audio_data_offset=0;
 assert(!msm5xxx_poc_amd_mapping_valid(&s,0x800000));
 s.audio_base=0x600000;assert(msm5xxx_poc_amd_mapping_valid(&s,0x800000));
 s.audio_base=0x2800000;s.audio_data_offset=4;
 assert(msm5xxx_poc_amd_mapping_valid(&s,0x800000));
 s.primary_nor_size=s.intel_x16_nor_base=0x1f00000;s.intel_x16_nor_size=0x200000;s.ram_base=0x4000000;
 assert(!msm5xxx_poc_amd_mapping_valid(&s,0x800000));
 return 0;
}
'''
  with tempfile.TemporaryDirectory() as directory:
   p=Path(directory);(p/'test.c').write_text(code)
   subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',str(p/'test.c'),'-o',str(p/'test')],check=True,capture_output=True)
   subprocess.run([str(p/'test')],check=True,capture_output=True)
