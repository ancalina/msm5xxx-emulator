"""Actual PC-bound TX sink readiness and property parser, without a VM."""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

class UART2NativeTests(unittest.TestCase):
 def test_source_pc_width_foreign_backing_and_parser(self):
  source=(Path(__file__).resolve().parents[1]/'native/qemu/msm5xxx-poc.c').read_text()
  def function(name):
   match=re.search(r'^static [^\n]*(?:\n[^\n]*)?\b'+name+r'\(',source,re.M)
   self.assertIsNotNone(match,name)
   brace=source.index('{',match.end());depth=1;end=brace+1
   while depth:
    depth+=(source[end]=='{')-(source[end]=='}');end+=1
   return source[match.start():end]
  harness='''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
typedef uint64_t hwaddr;
typedef struct {bool uart2_tx_ready_enabled;uint32_t uart2_tx_ready_pc;uint8_t uart2_tx_ready_backing;
 bool uart_console_enabled,ready_poll_enabled,board_status_input_enabled;
 uint32_t ready_status_address,ready_pulse_address,board_status_input_address;} MSM5xxxPOCMachineState;
static uint32_t test_pc;
static bool io;
static bool msm5xxx_poc_mmio_access_pc(MSM5xxxPOCMachineState *s,uint32_t *pc) {(void)s;*pc=test_pc;return io;}
#define g_ascii_isxdigit(c) isxdigit((unsigned char)(c))
static int qemu_strtoul(const char *v,const char **end,int base,unsigned long *out) {
 char *p;errno=0;*out=strtoul(v,&p,base);if(end)*end=p;return errno || *p;
}
'''+ '\n'.join(function(n) for n in ('msm5xxx_poc_uart2_tx_ready_conflict','msm5xxx_poc_uart2_tx_ready_read','msm5xxx_poc_uart2_tx_ready_write','msm5xxx_poc_parse_uart2_tx_ready'))+'''
int main(void) {
 MSM5xxxPOCMachineState s={0};test_pc=0x1f3e;io=true;
 assert(!msm5xxx_poc_uart2_tx_ready_read(&s,0,1));
 s.uart2_tx_ready_enabled=true;s.uart2_tx_ready_pc=test_pc;
 assert(msm5xxx_poc_uart2_tx_ready_read(&s,0,1)==1);
 test_pc+=2;assert(!msm5xxx_poc_uart2_tx_ready_read(&s,0,1));
 msm5xxx_poc_uart2_tx_ready_write(&s,0,0xa0,1);
 assert(msm5xxx_poc_uart2_tx_ready_read(&s,0,1)==0xa0);
 test_pc-=2;assert(msm5xxx_poc_uart2_tx_ready_read(&s,0,1)==0xa1);
 io=false;assert(msm5xxx_poc_uart2_tx_ready_read(&s,0,1)==0xa0);
 io=true;
 assert(!msm5xxx_poc_uart2_tx_ready_read(&s,0,2));
 assert(!msm5xxx_poc_uart2_tx_ready_read(&s,1,1));
 msm5xxx_poc_uart2_tx_ready_write(&s,0,0xff,2);
 msm5xxx_poc_uart2_tx_ready_write(&s,1,0xff,1);
 assert(s.uart2_tx_ready_backing==0xa0);
 msm5xxx_poc_uart2_tx_ready_write(&s,0,0,1);
 assert(msm5xxx_poc_uart2_tx_ready_read(&s,0,1)==1);
 s.ready_poll_enabled=true;s.ready_status_address=0x30007b4;s.ready_pulse_address=0x3000600;
 assert(!msm5xxx_poc_uart2_tx_ready_conflict(&s));
 s.ready_pulse_address=0x30007c0;assert(msm5xxx_poc_uart2_tx_ready_conflict(&s));
 s.ready_pulse_address=0x3000600;s.ready_status_address=0x30007c0;
 assert(msm5xxx_poc_uart2_tx_ready_conflict(&s));
 s.ready_status_address=0x30007b4;s.uart_console_enabled=true;
 assert(msm5xxx_poc_uart2_tx_ready_conflict(&s));
 s.uart_console_enabled=false;s.board_status_input_enabled=true;s.board_status_input_address=0x30007bd;
 assert(msm5xxx_poc_uart2_tx_ready_conflict(&s));
 s.board_status_input_address=0x30007c1;assert(!msm5xxx_poc_uart2_tx_ready_conflict(&s));
 uint32_t pc=0;
 assert(msm5xxx_poc_parse_uart2_tx_ready("1f3e",&pc) && pc==0x1f3e);
 assert(msm5xxx_poc_parse_uart2_tx_ready("1FFFFFE",&pc) && pc==0x1fffffe);
 const char *bad[]={NULL,"","0","1f3f","2000000","ffffffff","123456789","-2","+2"," 2","2 ","2x","0x20","1f3e:1"};
 for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++) assert(!msm5xxx_poc_parse_uart2_tx_ready(bad[i],&pc));
 return 0;
}
'''
  with tempfile.TemporaryDirectory() as directory:
   p=Path(directory);(p/'test.c').write_text(harness)
   subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',str(p/'test.c'),'-o',str(p/'test')],check=True,capture_output=True)
   subprocess.run([str(p/'test')],check=True,capture_output=True)
