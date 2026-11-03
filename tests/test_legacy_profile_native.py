"""Cross-check native legacy admission against the original ROM signatures."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from corpus import firmware_path
from msm5xxx_emulator.detection.baseband import find_legacy_cdma_profile


class LegacyProfileNativeTests(unittest.TestCase):
    def test_rom_profiles_and_mutations(self):
        native=Path(__file__).resolve().parents[1]/'native/qemu'
        source=(native/'msm5xxx-poc.c').read_text()
        def extract(name, after=0):
            at=source.index('static bool '+name+'(',after);start=source.index('{',at)
            depth=1;end=start+1
            while depth:
                depth+=(source[end]=='{')-(source[end]=='}');end+=1
            return source[at:end]
        begin=source.index('static bool msm5xxx_poc_decoder_bl(',source.index('static bool msm5xxx_poc_class_literal('))
        harness=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct {bool legacy_cdma,legacy_profile_enabled,legacy_profile_checked,legacy_profile_valid;uint32_t legacy_profile[9],legacy_masks_i,legacy_masks_q,primary_nor_size;} MSM5xxxPOCMachineState;
static uint8_t *rom;static uint32_t rom_size;
static void cpu_physical_memory_read(uint32_t a,void *out,size_t n){assert(a+n<=rom_size);memcpy(out,rom+a,n);}
static uint16_t lduw_le_p(const uint8_t*p){return p[0]|((uint16_t)p[1]<<8);}
static uint32_t msm5xxx_poc_guest_u32(uint32_t a){assert(a+4<=rom_size);return rom[a]|((uint32_t)rom[a+1]<<8)|((uint32_t)rom[a+2]<<16)|((uint32_t)rom[a+3]<<24);}
'''
        harness += extract('msm5xxx_poc_thumb_literal')
        harness += extract('msm5xxx_poc_decoder_bl',begin)
        harness += extract('msm5xxx_poc_legacy_gate',source.index('static uint64_t msm5xxx_poc_sbi_read(')-20000)
        harness += r'''
int main(int argc,char **argv){
 assert(argc==13);FILE *f=fopen(argv[1],"rb");assert(f);fseek(f,0,SEEK_END);rom_size=ftell(f);rewind(f);rom=malloc(rom_size);assert(rom&&fread(rom,1,rom_size,f)==rom_size);fclose(f);
 MSM5xxxPOCMachineState s={0};s.primary_nor_size=rom_size;s.legacy_cdma=s.legacy_profile_enabled=true;
 for(unsigned i=0;i<9;i++)s.legacy_profile[i]=strtoul(argv[i+2],0,16);
 s.legacy_masks_i=strtoul(argv[11],0,16);s.legacy_masks_q=strtoul(argv[12],0,16);
 assert(msm5xxx_poc_legacy_gate(&s));
 unsigned positions[]={s.legacy_profile[0]+2,s.legacy_profile[1]+4,s.legacy_profile[2]+8,s.legacy_profile[3]+6,s.legacy_profile[4]+6,s.legacy_profile[5]+4,s.legacy_profile[6]+4,s.legacy_profile[8]};
 for(unsigned i=0;i<sizeof(positions)/sizeof(positions[0]);i++){
  rom[positions[i]]^=1;s.legacy_profile_checked=s.legacy_profile_valid=false;
  assert(!msm5xxx_poc_legacy_gate(&s));rom[positions[i]]^=1;
 }
 free(rom);return 0;
}
'''
        images=[firmware_path('T030TEDT09_5.177_JTAG - Old Phone Preservation.bin'),
                firmware_path('incoming-msm5xxx-all-manufacturers-20260726','Audiovox','CDM-8500',
                              'T050VMDM01_3.191_JTAG','T050VMDM01_3.191_JTAG.bin')]
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory);(p/'test.c').write_text(harness)
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',str(p/'test.c'),'-o',str(p/'test')],check=True)
            for image in images:
                profile=find_legacy_cdma_profile(image.read_bytes())
                self.assertTrue(profile['accepted'],profile)
                fields=('writer','consumer','descriptor','decoder','fifo_copy','sync_mode','paging_mode','pll_bits','pll','mask_i','mask_q')
                subprocess.run([str(p/'test'),str(image),*(format(profile[k],'x') for k in fields)],check=True)
