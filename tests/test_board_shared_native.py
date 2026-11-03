"""Compile the shared GPIO read and independent peer input implementations."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


class BoardSharedNativeTests(unittest.TestCase):
    def test_shared_ready_and_peer_pins(self):
        source = (Path(__file__).resolve().parents[1] / 'native/qemu/msm5xxx-poc.c').read_text()
        def function(name):
            match = re.search(r'^static [^\n]*(?:\n[^\n]*)?\b' + name + r'\(', source, re.M)
            at = source.index('{', match.end())
            depth, end = 1, at + 1
            while depth:
                depth += (source[end] == '{') - (source[end] == '}')
                end += 1
            return source[match.start():end]
        harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
typedef uint64_t hwaddr;
#define MSM5XXX_POC_MSM_BASE 0x03000000
#define MSM5XXX_POC_EEPROM_GPIO_SIZE 0x20
typedef struct { uint8_t bytes[4096]; } MemoryRegion;
typedef struct {
  MemoryRegion msm; bool eeprom_gpio_enabled, raw_nand_main_enabled;
  uint32_t eeprom_gpio_base, board_status_input_address, raw_nand_ready_address;
  uint8_t board_status_input_backing, board_status_input_mask, raw_nand_ready_mask, raw_nand_status;
  uint32_t board_status_peer_address; uint8_t board_status_peer_mask, board_status_peer_level;
} MSM5xxxPOCMachineState;
static void *memory_region_get_ram_ptr(MemoryRegion *r) { return r->bytes; }
static uint64_t msm5xxx_poc_eeprom_gpio_read(void *p, hwaddr a, unsigned n) { (void)p; (void)a; (void)n; return 0; }
static void msm5xxx_poc_eeprom_gpio_write(void *p, hwaddr a, uint64_t v, unsigned n) { (void)p; (void)a; (void)v; (void)n; }
''' + '\n'.join(function(n) for n in (
    'msm5xxx_poc_board_status_input_read', 'msm5xxx_poc_board_status_input_write',
    'msm5xxx_poc_board_status_peer_read', 'msm5xxx_poc_board_status_peer_write')) + r'''
int main(void) {
  MSM5xxxPOCMachineState s={0};
  s.board_status_input_address=0x3000720; s.board_status_input_mask=4;
  s.board_status_input_backing=4; s.raw_nand_main_enabled=true;
  s.raw_nand_ready_address=0x3000720; s.raw_nand_ready_mask=2; s.raw_nand_status=0xc0;
  msm5xxx_poc_board_status_input_write(&s,0,0xa0,1);
  assert(msm5xxx_poc_board_status_input_read(&s,0,1)==0xa6);
  s.raw_nand_status=0x80;
  assert(msm5xxx_poc_board_status_input_read(&s,0,1)==0xa4);
  s.board_status_input_address=0x3000728; s.board_status_input_mask=2;
  s.board_status_input_backing=2; s.raw_nand_ready_address=0x3000728; s.raw_nand_ready_mask=1;
  s.raw_nand_status=0xc0; msm5xxx_poc_board_status_input_write(&s,0,0x80,1);
  assert(msm5xxx_poc_board_status_input_read(&s,0,1)==0x83);
  s.board_status_peer_address=0x300066c; s.board_status_peer_mask=0x20; s.board_status_peer_level=0x20;
  msm5xxx_poc_board_status_peer_write(&s,0,0x83,1);
  assert(s.msm.bytes[0x66c]==0x83 && msm5xxx_poc_board_status_peer_read(&s,0,1)==0xa3);
  assert(msm5xxx_poc_board_status_peer_read(&s,1,1)==0);
  return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'check.c').write_text(harness)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            str(root / 'check.c'), '-o', str(root / 'check')], check=True)
            subprocess.run([str(root / 'check')], check=True)

    def test_dc0_start_transition_asserts_controller_pending(self):
        source = (Path(__file__).resolve().parents[1] / 'native/qemu/msm5xxx-poc.c').read_text()
        start = source.index('static void msm5xxx_poc_dc0_write(')
        end = source.index('\nstatic const MemoryRegionOps msm5xxx_poc_dc0_ops', start)
        code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
typedef uint64_t hwaddr;
#define MSM5XXX_POC_DC0_SIZE 0xe
#define MSM5XXX_POC_DC0_DATA_OFFSET 8
#define MSM5XXX_POC_DC0_START_OFFSET 12
typedef struct { uint8_t dc0_backing[14], dc0_board_adc_phase, dc0_board_adc_value;
  bool rex_irq_enabled; uint32_t rex_irq_status_address, rex_irq_pending[3], dc0_board_adc_responses;
} MSM5xxxPOCMachineState;
static unsigned updates;
static uint64_t msm5xxx_poc_backing_read(uint8_t *b, unsigned o, unsigned n) {
  uint64_t v=0; memcpy(&v,b+o,n); return v;
}
static void msm5xxx_poc_backing_write(uint8_t *b, unsigned o, uint64_t v, unsigned n) { memcpy(b+o,&v,n); }
static void msm5xxx_poc_rex_irq_update(MSM5xxxPOCMachineState *s) { (void)s; updates++; }
''' + source[start:end] + r'''
int main(void) {
  MSM5xxxPOCMachineState s={0}; s.rex_irq_enabled=true; s.rex_irq_status_address=0x3000c80;
  msm5xxx_poc_dc0_write(&s,12,1,2); assert(s.rex_irq_pending[1]==1 && updates==1);
  msm5xxx_poc_dc0_write(&s,12,1,2); assert(updates==1);
  msm5xxx_poc_dc0_write(&s,12,0,2); s.rex_irq_enabled=false;
  msm5xxx_poc_dc0_write(&s,12,1,2); assert(updates==1);
  msm5xxx_poc_dc0_write(&s,12,0,2); s.rex_irq_enabled=true;
  s.rex_irq_status_address=0x3000620; msm5xxx_poc_dc0_write(&s,12,1,2); assert(updates==1);
  return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'check.c').write_text(code)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            str(root / 'check.c'), '-o', str(root / 'check')], check=True)
            subprocess.run([str(root / 'check')], check=True)

    def test_matrix_property_can_precede_matrix_configuration(self):
        source = (Path(__file__).resolve().parents[1] / 'native/qemu/msm5xxx-poc.c').read_text()
        start = source.index('static bool msm5xxx_poc_get_matrix_electrical(')
        end = source.index('static bool msm5xxx_poc_get_sharp_nv_wp_high(', start)
        code = r'''
#include <assert.h>
#include <stdbool.h>
typedef int Error;
typedef struct { void *cpu; bool matrix_input_electrical; } MSM5xxxPOCMachineState;
typedef MSM5xxxPOCMachineState Object;
#define MSM5XXX_POC_MACHINE(o) (o)
static void error_setg(Error **err, const char *message) { static Error e; (void)message; *err=&e; }
''' + source[start:end] + r'''
int main(void) {
  Object s={0}; Error *err=0;
  msm5xxx_poc_set_matrix_electrical(&s,true,&err);
  assert(!err && msm5xxx_poc_get_matrix_electrical(&s,&err));
  s.cpu=&s; msm5xxx_poc_set_matrix_electrical(&s,false,&err);
  assert(err && s.matrix_input_electrical);
  return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'check.c').write_text(code)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-Wno-unused-parameter', str(root / 'check.c'), '-o', str(root / 'check')], check=True)
            subprocess.run([str(root / 'check')], check=True)
