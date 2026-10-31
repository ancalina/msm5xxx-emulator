"""Exercise standalone MA2 bus routing and aperture validation."""
from pathlib import Path
import re,subprocess,tempfile,unittest

class DirectMA2Native(unittest.TestCase):
 def test_owned_access_and_address_validation(self):
  root=Path(__file__).resolve().parents[1]
  source=(root/'native/qemu/msm5xxx-poc.c').read_text()
  def function(name):
   m=re.search(r'^static [^\n]*(?:\n[^\n]*)?\b'+name+r'\(',source,re.M);self.assertIsNotNone(m,name)
   brace=source.index('{',m.end());depth=1;i=brace+1
   while depth:depth+=(source[i]=='{')-(source[i]=='}');i+=1
   return source[m.start():i]
  names=('msm5xxx_poc_ma2_direct_read','msm5xxx_poc_ma2_direct_write','msm5xxx_poc_set_audio_aperture')
  harness=r'''
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#define MSM5XXX_POC_LCD_APERTURE_BASE 0x02000000u
#define MSM5XXX_POC_LCD_APERTURE_SIZE 0x00800000u
#define MSM5XXX_POC_LCD_SIZE 0x1000u
#define MEMTX_OK 0
#define MEMTX_ERROR 1
static const uint32_t msm5xxx_poc_lcd_bases[]={0x02000000,0x02800000,0x02c00000,0x02200000};
typedef uint64_t hwaddr;typedef int MemTxResult;typedef int MemTxAttrs;typedef struct {int bad;} Error;
typedef struct {uint32_t audio_base,audio_data_offset;bool audio_ma2,audio_ma5,audio_enabled,allow;} MSM5xxxPOCMachineState;
typedef MSM5xxxPOCMachineState Object;
#define MSM5XXX_POC_MACHINE(obj) (obj)
static void error_setg(Error **e,const char *fmt,...){(void)fmt;if(e&&*e)(*e)->bad=1;}
static bool msm5xxx_poc_audio_read_owned(MSM5xxxPOCMachineState *s,hwaddr offset,unsigned size,uint64_t *value){if(!s->allow||offset!=2||size!=1)return false;*value=0x5a;return true;}
static bool msm5xxx_poc_audio_write_owned(MSM5xxxPOCMachineState *s,hwaddr offset,uint64_t value,unsigned size){return s->allow&&size==1&&(offset==0||offset==2)&&value<=255;}
'''
  harness+='\n'.join(function(n) for n in names)+r'''
int main(void){
 MSM5xxxPOCMachineState s={0};Error err={0},*e=&err;uint64_t value=0xdead;
 msm5xxx_poc_set_audio_aperture(&s,"2880000:2:ma2",&e);
 assert(!err.bad&&s.audio_enabled&&s.audio_ma2&&s.audio_base==0x2880000&&s.audio_data_offset==2);
 assert(msm5xxx_poc_ma2_direct_read(&s,2,&value,1,0)==MEMTX_ERROR&&value==0xdead);
 assert(msm5xxx_poc_ma2_direct_write(&s,0,0x0f,1,0)==MEMTX_ERROR);
 s.allow=true;assert(msm5xxx_poc_ma2_direct_read(&s,2,&value,1,0)==MEMTX_OK&&value==0x5a);
 assert(msm5xxx_poc_ma2_direct_write(&s,0,0x0f,1,0)==MEMTX_OK);
 assert(msm5xxx_poc_ma2_direct_write(&s,2,0xff,1,0)==MEMTX_OK);
 assert(msm5xxx_poc_ma2_direct_write(&s,1,0xff,1,0)==MEMTX_ERROR);
 assert(msm5xxx_poc_ma2_direct_write(&s,2,0xff,2,0)==MEMTX_ERROR);
 err.bad=0;msm5xxx_poc_set_audio_aperture(&s,"2880004:2:ma2",&e);assert(err.bad);
 err.bad=0;msm5xxx_poc_set_audio_aperture(&s,"2080000:2:ma2",&e);assert(!err.bad&&s.audio_base==0x2080000);
 return 0;
}
'''
  with tempfile.TemporaryDirectory() as tmp:
   path=Path(tmp)/'test.c';exe=Path(tmp)/'test';path.write_text(harness)
   subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',str(path),'-o',str(exe)],check=True)
   subprocess.run([str(exe)],check=True)
if __name__=='__main__':unittest.main()
