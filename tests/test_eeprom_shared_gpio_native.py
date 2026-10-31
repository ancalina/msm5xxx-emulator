"""Shared-register preservation and same-byte SDA/SCL in the actual native GPIO."""
import subprocess
import tempfile
import unittest
from pathlib import Path


class SharedEEPROMGPIOTests(unittest.TestCase):
    def test_lines_direction_and_unrelated_register_bytes(self):
        source = (Path(__file__).resolve().parents[1] /
                  'native/qemu/msm5xxx-poc.c').read_text()

        def function(name):
            start = source.index(name + '(')
            # The GPIO handlers also have forward declarations.
            while source.find(';', start) < source.find('{', start):
                start = source.index(name + '(', start + len(name))
            start = source.rfind('static ', 0, start)
            brace = source.index('{', start)
            end, depth = brace + 1, 1
            while depth:
                depth += (source[end] == '{') - (source[end] == '}')
                end += 1
            return source[start:end]

        code = r'''
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
typedef uint64_t hwaddr;
#define MSM5XXX_POC_EEPROM_GPIO_SIZE 32
#define MSM5XXX_POC_MSM_BASE 0x03000000
#define BITBANG_I2C_SDA 0
#define BITBANG_I2C_SCL 1
typedef struct CPUState { bool running; struct { bool can_do_io; } neg; } CPUState;
typedef struct { uint64_t (*get_pc)(CPUState *); } CPUClass;
static uint64_t get_pc(CPUState *cpu) { (void)cpu; return 0; }
static CPUClass cpu_class={get_pc};
#define CPU_GET_CLASS(cpu) (&cpu_class)
#define CPU(cpu) (cpu)
static CPUState *current_cpu;
static bool qemu_in_vcpu_thread(void) { return false; }
typedef struct {
 uint8_t eeprom_gpio_backing[32];
 unsigned eeprom_direction_offset,eeprom_data_offset,eeprom_data_mask;
 unsigned eeprom_clock_offset,eeprom_clock_mask,eeprom_gpio_base;
 unsigned experimental_matrix_status_site,matrix_input_descriptor;
 unsigned experimental_matrix_status_level,matrix_input_rejections;
 bool experimental_matrix_status_enabled;
 int eeprom_sda,eeprom_i2c;
 CPUState *cpu;
} MSM5xxxPOCMachineState;
static uint32_t msm5xxx_poc_guest_u32(unsigned address) { (void)address; return 0; }
static bool external_sda, lines[2];
static unsigned calls;
static int bitbang_i2c_set(int *bus,unsigned pin,bool value) {
 (void)bus; assert(pin<2); lines[pin]=value; calls++; return external_sda;
}
''' + '\n'.join(function(name) for name in (
            'msm5xxx_poc_backing_read', 'msm5xxx_poc_backing_write',
            'msm5xxx_poc_eeprom_gpio_update', 'msm5xxx_poc_eeprom_gpio_read',
            'msm5xxx_poc_eeprom_gpio_write')) + r'''
int main(void) {
 MSM5xxxPOCMachineState s={.eeprom_data_offset=8,.eeprom_data_mask=0x10,
  .eeprom_clock_offset=8,.eeprom_clock_mask=8,.eeprom_direction_offset=28};
 for(unsigned i=0;i<32;i++) s.eeprom_gpio_backing[i]=(uint8_t)(i*7);
 for(unsigned output=0;output<2;output++) {
  s.eeprom_gpio_backing[28]=output?0x91:0x81;
  for(unsigned value=0;value<256;value++) {
   uint8_t before[32];memcpy(before,s.eeprom_gpio_backing,32);
   calls=0;msm5xxx_poc_eeprom_gpio_write(&s,8,value,1);
   assert(calls==2 && lines[0]==(!output || !!(value&0x10)));
   assert(lines[1]==!!(value&8));
   before[8]=value;assert(!memcmp(before,s.eeprom_gpio_backing,32));
   for(unsigned level=0;level<2;level++) {
    s.eeprom_sda=level;calls=0;
    for(unsigned width=1;width<=4;width*=2) {
     for(unsigned at=0;at<=32-width;at++) {
      uint64_t expected=msm5xxx_poc_backing_read(before,at,width);
      if(at<=8 && 8<at+width) {
       uint64_t bit=(uint64_t)0x10<<((8-at)*8);
       expected=(expected&~bit)|(level?bit:0);
      }
      assert(msm5xxx_poc_eeprom_gpio_read(&s,at,width)==expected);
     }
    }
    assert(!calls && !memcmp(before,s.eeprom_gpio_backing,32));
   }
  }
 }
 msm5xxx_poc_eeprom_gpio_write(&s,8,0xc0ffee34,4);
 assert(msm5xxx_poc_backing_read(s.eeprom_gpio_backing,8,4)==0xc0ffee34);
 assert(lines[0] && !lines[1]);
 msm5xxx_poc_eeprom_gpio_write(&s,9,0x1234,2);
 assert(msm5xxx_poc_backing_read(s.eeprom_gpio_backing,8,4)==0xc0123434);
 msm5xxx_poc_eeprom_gpio_write(&s,28,0,1);
 msm5xxx_poc_eeprom_gpio_write(&s,8,0x88,1);
 assert(lines[0] && lines[1]); /* Input releases SDA despite output latch zero. */
 msm5xxx_poc_eeprom_gpio_write(&s,28,0x10,1);
 assert(!lines[0] && lines[1]);
 uint8_t before[32];memcpy(before,s.eeprom_gpio_backing,32);calls=0;
 msm5xxx_poc_eeprom_gpio_write(&s,31,0xdead,2);
 assert(!calls && !memcmp(before,s.eeprom_gpio_backing,32));
 assert(msm5xxx_poc_eeprom_gpio_read(&s,31,2)==0);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            (path / 'test.c').write_text(code)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            str(path / 'test.c'), '-o', str(path / 'test')],
                           check=True)
            subprocess.run([str(path / 'test')], check=True)
