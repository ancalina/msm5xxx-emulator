"""Extract actual limited raw-input SBI helpers; no QEMU or physical ADC claim."""
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path


class SBIRawInputNativeTests(unittest.TestCase):
    def test_actual_c_raw_input_guards_peeks_and_reset(self):
        repo=Path(__file__).resolve().parents[1]
        source=(repo/'native/qemu/msm5xxx-poc.c').read_text()
        def function(name):
            match=re.search(r'^static [^\n]*(?:\n[^\n]*)?\b'+name+r'\(',source,re.M)
            self.assertIsNotNone(match,name)
            brace=source.index('{',match.end());depth=1;end=brace+1
            while depth:
                depth+=(source[end]=='{')-(source[end]=='}');end+=1
            return source[match.start():end]
        a=source.index('typedef enum MSM5xxxPOCSBIStatus {')
        b=source.index('} MSM5xxxPOCSBIStatus;',a)+len('} MSM5xxxPOCSBIStatus;')
        fields=source[source.index('    bool sbi_enabled;'):source.index('    uint8_t dc0_backing[')]
        constant=re.search(r'^#define MSM5XXX_POC_SBI_SIZE .+$',source,re.M).group()
        harness=r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <glib.h>
typedef uint64_t hwaddr;
typedef struct {uint32_t pc;bool running;struct {bool can_do_io;} neg;} CPUState;
typedef struct {CPUState parent;} ARMCPU;
typedef struct {uint64_t (*get_pc)(CPUState*);} CPUClass;
static uint64_t get_pc(CPUState *cpu){return cpu->pc;}
static CPUClass cpu_class={get_pc};
#define CPU(cpu) (&(cpu)->parent)
#define CPU_GET_CLASS(cpu) ((void)(cpu),&cpu_class)
static CPUState *current_cpu;
static bool in_vcpu;
static bool qemu_in_vcpu_thread(void){return in_vcpu;}
typedef struct {int marker;} Error;
static Error failure;
static void error_setg(Error **error,const char *format,...){(void)format;*error=&failure;}
static int qemu_strtoul(const char *text,const char **end,int base,unsigned long *value){
    char *tail;errno=0;*value=strtoul(text,&tail,base);*end=tail;
    return errno?-errno:tail==text?-EINVAL:0;
}
''' + constant + '\n' + source[a:b] + r'''
typedef struct {
    ARMCPU *cpu;uint32_t primary_nor_size;
''' + fields + r'''
} MSM5xxxPOCMachineState;
typedef MSM5xxxPOCMachineState Object;
#define MSM5XXX_POC_MACHINE(obj) (obj)
''' + '\n'.join(function(n) for n in (
            'msm5xxx_poc_backing_read','msm5xxx_poc_backing_write',
            'msm5xxx_poc_sbi_raw_input_valid','msm5xxx_poc_sbi_raw_input_reset','msm5xxx_poc_sbi_raw_input_guest',
            'msm5xxx_poc_sbi_raw_input_selected','msm5xxx_poc_sbi_raw_input_read_allowed',
            'msm5xxx_poc_sbi_raw_input_write_allowed','msm5xxx_poc_sbi_status_value',
            'msm5xxx_poc_sbi_raw_input_peek','msm5xxx_poc_sbi_reject',
            'msm5xxx_poc_sbi_read','msm5xxx_poc_sbi_write',
            'msm5xxx_poc_set_sbi','msm5xxx_poc_get_sbi_raw_input_profile',
            'msm5xxx_poc_set_sbi_raw_input_profile','msm5xxx_poc_get_sbi_raw_input_status',
            'msm5xxx_poc_get_sbi_bootstrap_only','msm5xxx_poc_set_sbi_bootstrap_only')) + r'''
static ARMCPU cpu;
static void guest(void){in_vcpu=true;cpu.parent.running=true;cpu.parent.neg.can_do_io=true;current_cpu=&cpu.parent;cpu.parent.pc=0x1d22a;}
static MSM5xxxPOCMachineState empty(void){
    MSM5xxxPOCMachineState s={0};s.cpu=&cpu;s.primary_nor_size=0x40000;
    s.sbi_enabled=true;s.board_adc_value=194;s.sbi_status=MSM5XXX_POC_SBI_OBSERVING;guest();return s;
}
static MSM5xxxPOCMachineState fresh(unsigned raw){
    MSM5xxxPOCMachineState s=empty();Error *error=NULL;s.board_adc_value=raw;
    msm5xxx_poc_set_sbi_raw_input_profile(&s,"1d22a:60:40",&error);assert(!error);
    s.sbi_raw_input_realized=true;msm5xxx_poc_sbi_raw_input_reset(&s);return s;
}
static void wr(MSM5xxxPOCMachineState *s,unsigned off,unsigned value,unsigned size){msm5xxx_poc_sbi_write(s,off,value,size);}
static uint64_t rd(MSM5xxxPOCMachineState *s,unsigned off,unsigned size){return msm5xxx_poc_sbi_read(s,off,size);}
static void boot(MSM5xxxPOCMachineState *s){
    const unsigned off[]={0,0,4,12,16,16},val[]={0x45,0xc5,0x085f,0x041f,0,1},width[]={1,1,2,2,1,1};
    for(unsigned i=0;i<6;i++)wr(s,off[i],val[i],width[i]);
    assert(s->sbi_status==MSM5XXX_POC_SBI_CANDIDATE);
}
static void accept(MSM5xxxPOCMachineState *s){
    guest();boot(s);assert(rd(s,0,2)==0x5f20);wr(s,12,0x0900,2);assert(rd(s,0,2)==0x5f20);
    assert(s->sbi_status==MSM5XXX_POC_SBI_ACCEPTED);
}
static void ordinary_prefix(MSM5xxxPOCMachineState *s){
    wr(s,4,0x0800,2);
    assert(s->sbi_status==MSM5XXX_POC_SBI_ACCEPTED && s->sbi_control==0x0800);
    assert(!s->sbi_board_adc_phase && !s->sbi_board_adc_selector && !s->sbi_board_adc_responses);
    assert(rd(s,0,2)==msm5xxx_poc_sbi_status_value(s));
    wr(s,0,0x4a,1);wr(s,0,0xca,1);
    assert(s->sbi_status==MSM5XXX_POC_SBI_ACCEPTED && !s->sbi_read_full && !s->sbi_board_adc_responses);
    assert(s->sbi_backing[0]==0xca && rd(s,0,2)==0x20); /* Status derives from0800, not clockCA. */
}
static void select_channel(MSM5xxxPOCMachineState *s,unsigned selector,bool extended){
    wr(s,4,0x086a,2);wr(s,12,selector,2);wr(s,16,0,1);wr(s,16,1,1);rd(s,0,2);
    wr(s,12,selector&~0x80,2);rd(s,0,2);assert(s->sbi_board_adc_phase==7);
    if(extended){wr(s,12,0x0c80,2);rd(s,0,2);assert(s->sbi_board_adc_phase==11);}
}
static void request(MSM5xxxPOCMachineState *s){
    wr(s,12,0x8b00,2);assert(s->sbi_status==MSM5XXX_POC_SBI_ACCEPTED);
    assert(rd(s,0,2)&2);assert(s->sbi_board_adc_phase==9 && s->sbi_read_full);
}
int main(void){
    Error *error=NULL;
    const char *bad[]={"-1:60:40"," 100:60:40","100:60:40 ","100:60:40:0","100:60", "100::40", "100:60:",
        "101:60:40","100000000:60:40","100:0:0","100:80:0","100:60:80","100:60:41","100:60:400000000000000000000",
        "100:60:4.0","100:+60:40"};
    for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++){
        MSM5xxxPOCMachineState s=empty(),before=s;
        msm5xxx_poc_set_sbi_raw_input_profile(&s,bad[i],&error);
        assert(error && memcmp(&s,&before,sizeof(s))==0);error=NULL;
    }
    for(unsigned mode=0;mode<4;mode++){
        MSM5xxxPOCMachineState s=empty();
        if(mode==0){s.sbi_enabled=false;}
        if(mode==1){s.sbi_bootstrap_only=true;}
        if(mode==2){s.board_adc_value=256;}
        if(mode==3){s.primary_nor_size=1;}
        msm5xxx_poc_set_sbi_raw_input_profile(&s,"100:60:40",&error);
        assert(!error && s.sbi_raw_input_enabled && !msm5xxx_poc_sbi_raw_input_valid(&s));
    }
    /* QOM property order must not inspect default-dependent SBI/ADC/NOR state. */
    MSM5xxxPOCMachineState first=empty(),last=empty();
    first.sbi_enabled=false;first.board_adc_value=256;first.primary_nor_size=0x1000000;
    last=first;
    msm5xxx_poc_set_sbi_raw_input_profile(&first,"1d22a:60:40",&error);
    assert(!error && first.sbi_raw_input_enabled && !msm5xxx_poc_sbi_raw_input_valid(&first));
    msm5xxx_poc_set_sbi(&first,true,&error);assert(!error);
    first.board_adc_value=194;first.primary_nor_size=0x200000;
    msm5xxx_poc_set_sbi(&last,true,&error);assert(!error);
    last.board_adc_value=194;last.primary_nor_size=0x200000;
    msm5xxx_poc_set_sbi_raw_input_profile(&last,"1d22a:60:40",&error);
    assert(!error && memcmp(&first,&last,sizeof(first))==0);
    assert(msm5xxx_poc_sbi_raw_input_valid(&first));
    first.primary_nor_size=first.sbi_raw_input_pc+1;
    assert(!msm5xxx_poc_sbi_raw_input_valid(&first));
    first.primary_nor_size=first.sbi_raw_input_pc+2;
    assert(msm5xxx_poc_sbi_raw_input_valid(&first));
    /* A valid final geometry may be larger than the constructor default. */
    first=empty();first.sbi_enabled=false;first.board_adc_value=256;
    first.primary_nor_size=0x1000000;
    msm5xxx_poc_set_sbi_raw_input_profile(&first,"2000000:60:40",&error);
    assert(!error && !msm5xxx_poc_sbi_raw_input_valid(&first));
    msm5xxx_poc_set_sbi(&first,true,&error);first.board_adc_value=194;first.primary_nor_size=0x4000000;
    assert(!error && msm5xxx_poc_sbi_raw_input_valid(&first));
    MSM5xxxPOCMachineState s=empty();
    msm5xxx_poc_set_sbi_raw_input_profile(&s,"0:1:0",&error);assert(!error);
    MSM5xxxPOCMachineState configured=s;
    msm5xxx_poc_set_sbi_raw_input_profile(&s,"100:60:40",&error);
    assert(error&&memcmp(&s,&configured,sizeof(s))==0);error=NULL;
    s=empty();msm5xxx_poc_set_sbi_raw_input_profile(&s,"3fffe:7f:7f",&error);assert(!error);
    s=empty();msm5xxx_poc_set_sbi_raw_input_profile(&s,"",&error);assert(!error&&!s.sbi_raw_input_enabled);
    s.sbi_raw_input_realized=true;MSM5xxxPOCMachineState before=s;
    msm5xxx_poc_set_sbi_raw_input_profile(&s,"100:60:40",&error);assert(error&&memcmp(&s,&before,sizeof(s))==0);error=NULL;
    const unsigned rawvalues[]={0,66,194,255};
    for(unsigned i=0;i<4;i++){
        s=fresh(rawvalues[i]);accept(&s);ordinary_prefix(&s);select_channel(&s,0x0ac5,false);request(&s);
        assert(rd(&s,12,2)==(0x8b00|rawvalues[i]));
        assert(s.sbi_board_adc_responses==1 && !s.sbi_read_full && !s.sbi_board_adc_phase);
        assert(s.sbi_raw_input_last_pc==s.sbi_raw_input_pc && !s.sbi_raw_input_reject_reason);
        assert(rd(&s,12,2)==0x8b00 && s.sbi_status==MSM5XXX_POC_SBI_REJECTED && s.sbi_board_adc_responses==1);
        assert(s.sbi_raw_input_reject_reason);
        uint32_t pc=s.sbi_raw_input_pc;uint8_t mask=s.sbi_raw_input_mask,value=s.sbi_raw_input_value;
        msm5xxx_poc_sbi_raw_input_reset(&s);
        assert(s.sbi_raw_input_pc==pc && s.sbi_raw_input_mask==mask && s.sbi_raw_input_value==value);
        assert(s.sbi_raw_input_realized && !s.sbi_raw_input_last_pc && !s.sbi_raw_input_reject_reason);
        assert(!s.sbi_board_adc_responses && s.board_adc_value==rawvalues[i] && s.sbi_status==MSM5XXX_POC_SBI_OBSERVING);
    }
    s=fresh(194);accept(&s);ordinary_prefix(&s);wr(&s,12,0x8b00,2);
    assert(s.sbi_status==MSM5XXX_POC_SBI_REJECTED && !s.sbi_board_adc_responses);
    msm5xxx_poc_sbi_raw_input_reset(&s);
    assert(s.sbi_control==0 && !s.sbi_raw_input_reject_reason && s.sbi_raw_input_pc==0x1d22a);
    accept(&s);ordinary_prefix(&s);select_channel(&s,0x0ac0,false);request(&s);
    assert(rd(&s,12,2)==0x8bc2 && s.sbi_board_adc_responses==1);
    s=fresh(66);accept(&s);select_channel(&s,0x0ac0,true);request(&s);
    cpu.parent.pc=0x1d22b;assert(rd(&s,12,2)==0x8b42); /* Thumbbit normalization. */
    char *text=msm5xxx_poc_get_sbi_raw_input_profile(&s,&error);assert(!strcmp(text,"1d22a:60:40"));g_free(text);
    text=msm5xxx_poc_get_sbi_raw_input_status(&s,&error);
    assert(strstr(text,"uncalibrated") && strstr(text,"\"responsecount\":1") && strstr(text,"\"lastreadpc\":119338"));g_free(text);
    before=s;msm5xxx_poc_set_sbi_raw_input_profile(&s,"100:60:40",&error);assert(error&&memcmp(&s,&before,sizeof(s))==0);error=NULL;
    msm5xxx_poc_set_sbi(&s,false,&error);assert(error&&s.sbi_enabled);error=NULL;
    msm5xxx_poc_set_sbi_bootstrap_only(&s,true,&error);assert(error&&!msm5xxx_poc_get_sbi_bootstrap_only(&s,&error));error=NULL;
    /* A nonselected channel cannot request any synthesized sample. */
    s=fresh(194);accept(&s);select_channel(&s,0x0aa0,false);wr(&s,12,0x8b00,2);
    assert(s.sbi_status==MSM5XXX_POC_SBI_REJECTED && !s.sbi_board_adc_responses);
    const unsigned wrongrequests[]={0x8c00,0x8b01};
    for(unsigned i=0;i<2;i++){
        s=fresh(194);accept(&s);select_channel(&s,0x0ac0,false);
        wr(&s,12,wrongrequests[i],2);
        assert(s.sbi_status==MSM5XXX_POC_SBI_REJECTED && !s.sbi_read_full && !s.sbi_board_adc_responses);
    }
    for(unsigned badread=0;badread<3;badread++){
        s=fresh(194);accept(&s);select_channel(&s,0x0ac0,false);request(&s);
        if(badread==0)cpu.parent.pc+=2;
        if(badread==1)s.board_adc_value=256;
        if(badread==2)s.sbi_read_full=false;
        assert(rd(&s,12,2)==0x8b00 && s.sbi_status==MSM5XXX_POC_SBI_REJECTED && !s.sbi_board_adc_responses);
    }
    const struct {unsigned off,val,width;} invalidwrites[]={
        {0,0x44,1},{0,0x4b,1},{0,0xcb,1},{0,0x4a,2},{0,0xca,2},
        {4,0x0801,2},{4,0,1},{4,0x0800,4},{4,0x086b,2},{16,2,1},{8,0x1234,2},{12,0x8c00,2},{12,0x8b00,2},{12,0x8b,1},{4,0x6a,1}};
    for(unsigned i=0;i<sizeof(invalidwrites)/sizeof(invalidwrites[0]);i++){
        s=fresh(194);accept(&s);
        wr(&s,invalidwrites[i].off,invalidwrites[i].val,invalidwrites[i].width);
        assert(s.sbi_status==MSM5XXX_POC_SBI_REJECTED && !s.sbi_board_adc_responses && s.sbi_raw_input_reject_reason);
        assert(msm5xxx_poc_backing_read(s.sbi_backing,invalidwrites[i].off,invalidwrites[i].width)==invalidwrites[i].val);
    }
    const struct {unsigned off,width;} invalidreads[]={{0,1},{4,2},{8,2},{12,1},{16,1}};
    for(unsigned i=0;i<sizeof(invalidreads)/sizeof(invalidreads[0]);i++){
        s=fresh(194);accept(&s);uint64_t backing=msm5xxx_poc_backing_read(s.sbi_backing,invalidreads[i].off,invalidreads[i].width);
        assert(rd(&s,invalidreads[i].off,invalidreads[i].width)==backing);
        assert(s.sbi_status==MSM5XXX_POC_SBI_REJECTED && s.sbi_raw_input_reject_reason);
    }
    s=fresh(194);accept(&s);wr(&s,0,0x45,1);wr(&s,0,0xc5,1);wr(&s,12,0x1234,2);
    assert(s.sbi_status==MSM5XXX_POC_SBI_ACCEPTED && !s.sbi_board_adc_responses);
    /* Monitor/QTest reads are peeks: no admission, phase/counter/FIFO changes. */
    s=fresh(194);boot(&s);in_vcpu=false;before=s;
    assert(rd(&s,0,2)==0x5f20 && rd(&s,12,2)==0x041f && rd(&s,4,1)==0x5f);
    assert(memcmp(&s,&before,sizeof(s))==0);
    wr(&s,12,0x0900,2);assert(s.sbi_status==MSM5XXX_POC_SBI_REJECTED); /* Peek did not validate. */
    for(unsigned nonlive=0;nonlive<4;nonlive++){
        s=fresh(194);accept(&s);select_channel(&s,0x0ac0,false);request(&s);
        if(nonlive==0){in_vcpu=false;}
        if(nonlive==1){current_cpu=NULL;}
        if(nonlive==2){cpu.parent.running=false;}
        if(nonlive==3){cpu.parent.neg.can_do_io=false;}
        before=s;assert(rd(&s,0,2)==msm5xxx_poc_sbi_status_value(&s));
        assert(rd(&s,12,2)==0x8b00 && rd(&s,4,1)==0x6a && memcmp(&s,&before,sizeof(s))==0);
        guest();assert(rd(&s,12,2)==0x8bc2 && s.sbi_board_adc_responses==1);
    }
    /* With the new profile disabled, old full and bootstrap-only paths remain unchanged. */
    s=empty();accept(&s);select_channel(&s,0x0aa0,false);request(&s);in_vcpu=false;
    assert(rd(&s,12,2)==0x8bc2 && s.sbi_board_adc_responses==1);
    s=empty();s.sbi_bootstrap_only=true;accept(&s);
    for(unsigned i=0;i<4;i++)assert(rd(&s,0,2)==0x5f20);
    wr(&s,4,0x086a,2);assert(s.sbi_status==MSM5XXX_POC_SBI_REJECTED);
    puts("SBI raw actual-C PC/channel/phase/byte/peek/reset/property/fallback PASS");return 0;
}
'''
        flags=shlex.split(subprocess.check_output(['pkg-config','--cflags','--libs','glib-2.0'],text=True,timeout=10))
        with tempfile.TemporaryDirectory(prefix='.sbi-raw-native-',dir=repo) as directory:
            path=Path(directory);(path/'check.c').write_text(harness)
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-parameter',
                            '-fsanitize=undefined','-fno-sanitize-recover=undefined',
                            str(path/'check.c'),'-o',str(path/'check'),*flags],check=True,timeout=30)
            subprocess.run([str(path/'check')],check=True,timeout=10)
        self.assertIn('if (!msm5xxx_poc_sbi_raw_input_valid(s)) {',source)
        self.assertIn('msm5xxx_poc_get_sbi_raw_input_status, NULL);',source)
        self.assertIn('qemu_register_reset(msm5xxx_poc_sbi_raw_input_reset, s);',source)
        self.assertIn('qemu_unregister_reset(msm5xxx_poc_sbi_raw_input_reset, s);',source)


if __name__=='__main__':unittest.main()
