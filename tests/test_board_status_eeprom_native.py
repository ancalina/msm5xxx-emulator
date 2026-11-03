"""Execute actual native byte-overlay functions against a synthetic GPIO bus."""
from pathlib import Path
import unittest
from test_matrix_row734_native import native_function, compile_and_run


class BoardStatusEEPROMTests(unittest.TestCase):
    def test_shared_clock_bus_and_lid_mask_are_independent(self):
        source = (Path(__file__).resolve().parents[1] / 'native/qemu/msm5xxx-poc.c').read_text()
        functions = ''.join(native_function(source, name) for name in (
            'msm5xxx_poc_board_status_input_read', 'msm5xxx_poc_board_status_input_write'))
        compile_and_run(r'''
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#define MSM5XXX_POC_EEPROM_GPIO_SIZE 32
#define hwaddr uint64_t
struct State {
    bool eeprom_gpio_enabled, raw_nand_main_enabled;
    uint32_t board_status_input_address, eeprom_gpio_base, raw_nand_ready_address;
    uint32_t raw_nand_ready_mask, raw_nand_status;
    uint8_t board_status_input_backing, board_status_input_mask;
    uint8_t pins[32]; unsigned reads, writes;
};
typedef struct State MSM5xxxPOCMachineState;
static uint64_t msm5xxx_poc_eeprom_gpio_read(void *opaque, hwaddr offset, unsigned size) {
    MSM5xxxPOCMachineState *s=opaque; assert(size==1 && offset<32);
    s->reads++; return s->pins[offset];
}
static void msm5xxx_poc_eeprom_gpio_write(void *opaque, hwaddr offset, uint64_t value, unsigned size) {
    MSM5xxxPOCMachineState *s=opaque; assert(size==1 && offset<32);
    s->writes++; s->pins[offset]=value;
}
''' + functions + r'''
int main(void) {
    MSM5xxxPOCMachineState s={.eeprom_gpio_enabled=true,
        .eeprom_gpio_base=0x03000660,.board_status_input_address=0x03000660,
        .board_status_input_mask=1,.board_status_input_backing=1};
    for (unsigned level=0;level<2;level++) {
        s.board_status_input_backing=level;
        for (unsigned value=0;value<256;value++) {
            msm5xxx_poc_board_status_input_write(&s,0,value,1);
            assert(s.pins[0]==value);
            assert(msm5xxx_poc_board_status_input_read(&s,0,1)==((value&254)|level));
            /* Bus readback, not stale overlay storage, owns the other bits. */
            s.pins[0]^=0x20;
            assert(msm5xxx_poc_board_status_input_read(&s,0,1)==(((value^0x20)&254)|level));
        }
    }
    unsigned writes=s.writes,reads=s.reads;
    s.board_status_input_address=s.eeprom_gpio_base+32;
    msm5xxx_poc_board_status_input_write(&s,0,0xa5,1);
    assert(msm5xxx_poc_board_status_input_read(&s,0,1)==0xa5);
    assert(s.reads==reads && s.writes==writes);
    s.board_status_input_address=s.eeprom_gpio_base;
    s.eeprom_gpio_enabled=false;
    msm5xxx_poc_board_status_input_write(&s,0,0x20,1);
    assert(msm5xxx_poc_board_status_input_read(&s,0,1)==0x21);
    assert(s.reads==reads && s.writes==writes);
    assert(msm5xxx_poc_board_status_input_read(&s,1,1)==0);
    msm5xxx_poc_board_status_input_write(&s,1,0,1);
    assert(s.board_status_input_backing==0x21);
}
''')
