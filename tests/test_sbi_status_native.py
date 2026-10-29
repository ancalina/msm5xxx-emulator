"""Compile actual SBI state helpers; read-only status precision, no VM."""
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path


class SBIStatusNativeTests(unittest.TestCase):
    def test_bootstrap_status_poll_and_full_mode_boundaries(self):
        repo=Path(__file__).resolve().parents[1]
        source=(repo/'experiments/qemu-tcg/msm5xxx-poc.c').read_text()
        def function(name):
            match=re.search(r'^static [^\n]*(?:\n[^\n]*)?\b'+name+r'\(',source,re.M)
            self.assertIsNotNone(match,name)
            brace=source.index('{',match.end());depth=1;end=brace+1
            while depth:
                depth+=(source[end]=='{')-(source[end]=='}');end+=1
            return source[match.start():end]
        enum_start=source.index('typedef enum MSM5xxxPOCSBIStatus {')
        enum_end=source.index('} MSM5xxxPOCSBIStatus;',enum_start)+len('} MSM5xxxPOCSBIStatus;')
        fields=source[source.index('    bool sbi_enabled;'):source.index('    uint8_t dc0_backing[')]
        size=re.search(r'^#define MSM5XXX_POC_SBI_SIZE .+$',source,re.M).group()
        harness=r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>
typedef uint64_t hwaddr;
''' + size + '\n' + source[enum_start:enum_end] + r'''
typedef struct {
''' + fields + r'''
} MSM5xxxPOCMachineState;
/* This fixture verifies the legacy modes with raw-input capability disabled. */
static bool msm5xxx_poc_sbi_raw_input_peek(MSM5xxxPOCMachineState *s, hwaddr o,
                                        unsigned n, uint64_t *v) {
    (void)s; (void)o; (void)n; (void)v; assert(false); return false;
}
static bool msm5xxx_poc_sbi_raw_input_read_allowed(MSM5xxxPOCMachineState *s,
                                                 hwaddr o, unsigned n) {
    (void)s; (void)o; (void)n; assert(false); return false;
}
static bool msm5xxx_poc_sbi_raw_input_write_allowed(MSM5xxxPOCMachineState *s,
                                                  hwaddr o, uint64_t v, unsigned n) {
    (void)s; (void)o; (void)v; (void)n; assert(false); return false;
}
''' + '\n'.join(function(n) for n in (
            'msm5xxx_poc_backing_read','msm5xxx_poc_backing_write',
            'msm5xxx_poc_sbi_status_value','msm5xxx_poc_sbi_reject',
            'msm5xxx_poc_sbi_read','msm5xxx_poc_sbi_write')) + r'''
static MSM5xxxPOCMachineState fresh(bool bootstrap_only) {
    MSM5xxxPOCMachineState s={0};s.sbi_enabled=true;s.sbi_bootstrap_only=bootstrap_only;
    s.sbi_status=MSM5XXX_POC_SBI_OBSERVING;s.board_adc_value=194;return s;
}
static void write_at(MSM5xxxPOCMachineState *s,unsigned off,unsigned value,unsigned size) {
    msm5xxx_poc_sbi_write(s,off,value,size);
}
static uint64_t read_at(MSM5xxxPOCMachineState *s,unsigned off,unsigned size) {
    return msm5xxx_poc_sbi_read(s,off,size);
}
static const unsigned offsets[]={0,0,4,0x0c,0x10,0x10};
static const unsigned sizes[]={1,1,2,2,1,1};
static const unsigned values[]={0x45,0xc5,0x085f,0x041f,0,1};
static void bootstrap(MSM5xxxPOCMachineState *s) {
    for(unsigned i=0;i<6;i++)write_at(s,offsets[i],values[i],sizes[i]);
    assert(s->sbi_status==MSM5XXX_POC_SBI_CANDIDATE && s->sbi_bootstrap_phase==6);
}
static void accept(MSM5xxxPOCMachineState *s) {
    bootstrap(s);assert(read_at(s,0,2)==0x5f20 && s->sbi_validation_phase==1);
    write_at(s,0x0c,0x0900,2);assert(s->sbi_validation_phase==2);
    assert(read_at(s,0,2)==0x5f20);
    assert(s->sbi_status==MSM5XXX_POC_SBI_ACCEPTED && s->sbi_validation_phase==3);
}
int main(void) {
    MSM5xxxPOCMachineState s=fresh(true);accept(&s);
    unsigned reads=s.sbi_reads,writes=s.sbi_writes;
    for(unsigned i=0;i<16;i++) {
        uint64_t status=read_at(&s,0,2);
        assert(status==msm5xxx_poc_sbi_status_value(&s) && status==0x5f20 && !(status&4));
        assert(s.sbi_status==MSM5XXX_POC_SBI_ACCEPTED && s.sbi_validation_phase==3);
        assert(!s.sbi_board_adc_phase && !s.sbi_board_adc_responses && !s.sbi_read_full);
    }
    assert(s.sbi_reads==reads+16 && s.sbi_writes==writes && s.sbi_control==0x085f);
    s.sbi_read_full=true;
    assert(read_at(&s,0,2)==0x5f22 && s.sbi_read_full);
    assert(s.sbi_status==MSM5XXX_POC_SBI_ACCEPTED);
    const struct {unsigned off,size;} bad_reads[]={{0,1},{0,4},{4,2},{0x0c,2},{0x10,1},{1,2}};
    for(unsigned i=0;i<sizeof(bad_reads)/sizeof(bad_reads[0]);i++) {
        s=fresh(true);accept(&s);
        uint64_t backing=msm5xxx_poc_backing_read(s.sbi_backing,bad_reads[i].off,bad_reads[i].size);
        assert(read_at(&s,bad_reads[i].off,bad_reads[i].size)==backing);
        assert(s.sbi_status==MSM5XXX_POC_SBI_REJECTED && !s.sbi_read_full && !s.sbi_board_adc_responses);
    }
    /* No post-validation writes are granted, including writes to status itself. */
    for(unsigned i=0;i<6;i++) {
        s=fresh(true);accept(&s);
        write_at(&s,offsets[i],values[i],sizes[i]);
        assert(s.sbi_status==MSM5XXX_POC_SBI_REJECTED && !s.sbi_board_adc_responses);
        assert(msm5xxx_poc_backing_read(s.sbi_backing,offsets[i],sizes[i])==values[i]);
    }
    s=fresh(true);accept(&s);write_at(&s,4,0x086a,2);
    assert(s.sbi_status==MSM5XXX_POC_SBI_REJECTED && s.sbi_control==0x085f);
    /* Existing malformed prefix behavior restarts observation; never admits. */
    for(unsigned bad=0;bad<6;bad++) {
        s=fresh(true);
        for(unsigned i=0;i<6;i++)write_at(&s,offsets[i],values[i]^(i==bad?0x80:0),sizes[i]);
        assert(s.sbi_status!=MSM5XXX_POC_SBI_CANDIDATE && s.sbi_status!=MSM5XXX_POC_SBI_ACCEPTED);
        assert(read_at(&s,0,2)==msm5xxx_poc_backing_read(s.sbi_backing,0,2));
    }
    s=fresh(true);bootstrap(&s);read_at(&s,0,1);assert(s.sbi_status==MSM5XXX_POC_SBI_REJECTED);
    s=fresh(true);bootstrap(&s);read_at(&s,0,2);read_at(&s,0,2);
    assert(s.sbi_status==MSM5XXX_POC_SBI_REJECTED); /* Missing0900. */
    s=fresh(true);bootstrap(&s);read_at(&s,0,2);write_at(&s,0x0c,0x0901,2);
    assert(s.sbi_status==MSM5XXX_POC_SBI_REJECTED);
    s=fresh(true);bootstrap(&s);write_at(&s,0x0c,0x0900,2);
    assert(s.sbi_status==MSM5XXX_POC_SBI_REJECTED); /* Write before first status. */
    /* Mirror existing check_sbi_native.py full-mode ADC cases, without a VM. */
    for(unsigned mode=0;mode<5;mode++) {
        s=fresh(false);accept(&s);
        write_at(&s,4,0x086a,2);write_at(&s,0x0c,0x0aa0,2);
        write_at(&s,0x10,0,1);write_at(&s,0x10,1,1);read_at(&s,0,2);
        write_at(&s,0x0c,0x0a20,2);read_at(&s,0,2);
        if(mode!=0) {
            write_at(&s,0x0c,mode==2?0x0c81:0x0c80,2);
            if(mode!=3)read_at(&s,0,mode==4?1:2);
        }
        write_at(&s,0x0c,0x8b00,2);read_at(&s,0,2);
        uint64_t value=read_at(&s,0x0c,2);
        assert(value==(mode<2?0x8bc2:0x8b00));
        assert(s.sbi_board_adc_responses==(mode<2?1:0));
        assert(read_at(&s,0x0c,2)==0x8b00); /* Never a second synthesized response. */
    }
    puts("SBI actual-C repeatedstatus/strictvalidation/reject/fullADC PASS");return 0;
}
'''
        flags=shlex.split(subprocess.check_output(['pkg-config','--cflags','--libs','glib-2.0'],text=True,timeout=10))
        with tempfile.TemporaryDirectory(prefix='.sbi-status-native-',dir=repo) as directory:
            path=Path(directory);(path/'check.c').write_text(harness)
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-parameter',
                            '-fsanitize=undefined','-fno-sanitize-recover=undefined',
                            str(path/'check.c'),'-o',str(path/'check'),*flags],check=True,timeout=30)
            subprocess.run([str(path/'check')],check=True,timeout=10)


if __name__=='__main__':unittest.main()
