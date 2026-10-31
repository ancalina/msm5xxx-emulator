"""Actual native map admission for the optional two-x8 Intel experiment."""
import re,subprocess,tempfile,unittest
from pathlib import Path
class IntelAdjacentNativeTests(unittest.TestCase):
 def test_disjoint_compatible_bank_and_all_owner_exclusions(self):
  source=(Path(__file__).resolve().parents[1]/'native/qemu/msm5xxx-poc.c').read_text()
  match=re.search(r'^static bool msm5xxx_poc_intel_adjacent_valid\(',source,re.M);self.assertIsNotNone(match)
  brace=source.index('{',match.end());depth=1;end=brace+1
  while depth:
   depth+=(source[end]=='{')-(source[end]=='}');end+=1
  code='''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#define MSM5XXX_POC_LCD_APERTURE_BASE 0x02000000
 typedef struct {
 bool intel_adjacent_nv,intel_x16_nor_enabled,memory_profile_enabled;
 uint32_t intel_x16_nor_base,intel_x16_nor_size,ram_base,primary_nor_size,audio_base,audio_data_offset;
 bool amd_x16_nor_enabled,amd_adjacent_nv,fujitsu_x16_nor_enabled,primary_x16_nor_enabled;
 bool record_x16_nor_enabled,mapped_primary_x16_nor_enabled,whole_primary_x16_enabled,protected_nor_enabled;
 bool upper_x8_nor_enabled,upper_x16_nor_enabled,raw_nand_main_enabled,small_nand_enabled,audio_enabled;
} MSM5xxxPOCMachineState;
'''+source[match.start():end]+'''
int main(void) {
 MSM5xxxPOCMachineState s={0};assert(!msm5xxx_poc_intel_adjacent_valid(&s));
 s.intel_adjacent_nv=s.intel_x16_nor_enabled=s.memory_profile_enabled=true;
 s.intel_x16_nor_base=s.primary_nor_size=0x800000;s.intel_x16_nor_size=0x800000;s.ram_base=0x1000000;
 assert(msm5xxx_poc_intel_adjacent_valid(&s));
 s.intel_x16_nor_size++;assert(!msm5xxx_poc_intel_adjacent_valid(&s));s.intel_x16_nor_size--;
 s.primary_nor_size--;assert(!msm5xxx_poc_intel_adjacent_valid(&s));s.primary_nor_size++;
 bool *owners[]={&s.amd_x16_nor_enabled,&s.amd_adjacent_nv,&s.fujitsu_x16_nor_enabled,
 &s.primary_x16_nor_enabled,&s.record_x16_nor_enabled,&s.mapped_primary_x16_nor_enabled,
 &s.whole_primary_x16_enabled,&s.protected_nor_enabled,&s.upper_x8_nor_enabled,
 &s.upper_x16_nor_enabled,&s.raw_nand_main_enabled,&s.small_nand_enabled};
 for(unsigned i=0;i<sizeof(owners)/sizeof(owners[0]);i++) {
  *owners[i]=true;assert(!msm5xxx_poc_intel_adjacent_valid(&s));*owners[i]=false;
 }
 s.audio_enabled=true;s.audio_base=0xffffff;s.audio_data_offset=0;
 assert(!msm5xxx_poc_intel_adjacent_valid(&s));s.audio_base=0x1000000;
 assert(msm5xxx_poc_intel_adjacent_valid(&s));
 s.intel_x16_nor_enabled=false;assert(!msm5xxx_poc_intel_adjacent_valid(&s));
 s.intel_x16_nor_enabled=true;s.memory_profile_enabled=false;assert(!msm5xxx_poc_intel_adjacent_valid(&s));
 s.memory_profile_enabled=true;s.intel_x16_nor_size=0;assert(!msm5xxx_poc_intel_adjacent_valid(&s));
 s.intel_x16_nor_base=s.primary_nor_size=0x1f00000;s.intel_x16_nor_size=0x200000;s.ram_base=0x4000000;
 assert(!msm5xxx_poc_intel_adjacent_valid(&s));return 0;
}
'''
  with tempfile.TemporaryDirectory() as directory:
   p=Path(directory);(p/'test.c').write_text(code)
   subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',str(p/'test.c'),'-o',str(p/'test')],check=True,capture_output=True)
   subprocess.run([str(p/'test')],check=True,capture_output=True)
