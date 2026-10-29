"""Exercise the extracted native row734 plane; no QEMU guest is launched."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


def native_function(source, name):
    match = re.search(r"^static [^\n]*\b" + re.escape(name) + r"\(", source, re.M)
    if match is None:
        raise AssertionError("native function missing: " + name)
    opening = source.index("{", match.start())
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


def compile_and_run(code):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory)
        (path / "check.c").write_text(code)
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                        str(path / "check.c"), "-o", str(path / "check")], check=True)
        subprocess.run([str(path / "check")], check=True)


class MatrixRow734Tests(unittest.TestCase):
    def source(self):
        return (Path(__file__).resolve().parents[1] /
                "experiments/qemu-tcg/msm5xxx-poc.c").read_text()

    def test_actual_combiner_all_rows_senses_and_invalid_drives(self):
        helper = native_function(self.source(), "msm5xxx_poc_row734_sense")
        compile_and_run("#include <stdint.h>\n#include <stdbool.h>\n#include <assert.h>\n" + helper + r'''
int main(void) {
    const unsigned rows[] = {1,2,4,8,16,128};
    const unsigned senses[] = {30,29,27,23,15};
    uint16_t result;
    for (unsigned backing = 0; backing <= 0xffff; backing++) {
        assert(msm5xxx_poc_row734_sense(backing,0,0x9f,true,false,false,0,0,&result));
        assert(result == ((backing & 0xffe0) | 31));
        assert(msm5xxx_poc_row734_sense(backing,0,0x1f,false,true,false,0,0,&result));
        assert(result == ((backing & 0xffe0) | 31));
    }
    for (unsigned held = 0; held < 6; held++) {
        for (unsigned col = 0; col < 5; col++) {
            assert(msm5xxx_poc_row734_sense(0xa5e2,0,0x9f,true,false,true,
                                          held,senses[col],&result));
            assert(result == (0xa5e0 | senses[col]));
            for (unsigned selected = 0; selected < 6; selected++) {
                assert(msm5xxx_poc_row734_sense(0xa5e2,0,rows[selected],false,false,true,
                                              held,senses[col],&result));
                assert(result == (0xa5e0 | (held == selected ? senses[col] : 31)));
                assert(msm5xxx_poc_row734_sense(0xa5e2,0,rows[selected],false,false,false,
                                              held,senses[col],&result));
                assert(result == 0xa5ff);
            }
            assert(!msm5xxx_poc_row734_sense(0xa5e2,0,0x1f,false,true,true,
                                           held,senses[col],&result));
            assert(result == 0xa5e2);
        }
    }
    for (unsigned output = 0; output < 256; output++) {
        unsigned masked = output & 0x9f;
        bool single = false;
        for (unsigned i=0;i<6;i++) single |= masked == rows[i];
        assert(msm5xxx_poc_row734_sense(0xa5e2,0,output,false,false,false,0,0,&result) == single);
        assert(result == (single ? 0xa5ff : 0xa5e2));
        assert(msm5xxx_poc_row734_sense(0xa5e2,0,output,true,false,false,0,0,&result) == (masked == 0x9f));
        assert(result == (masked == 0x9f ? 0xa5ff : 0xa5e2));
        assert(msm5xxx_poc_row734_sense(0xa5e2,0,output,false,true,false,0,0,&result) == (masked == 0x1f));
        assert(result == (masked == 0x1f ? 0xa5ff : 0xa5e2));
    }
    for (unsigned bit=0;bit<8;bit++) if ((1U<<bit)&0x9f) {
        assert(!msm5xxx_poc_row734_sense(0xa5e2,1U<<bit,1,false,false,false,0,0,&result));
        assert(result == 0xa5e2);
    }
    assert(msm5xxx_poc_row734_sense(0xa5e2,0x6060,0x6061,false,false,false,0,0,&result));
    assert(result == 0xa5ff);
    for (unsigned row=6;row<8;row++) {
        assert(!msm5xxx_poc_row734_sense(0xa5e2,0,1,false,false,true,row,30,&result));
        assert(result == 0xa5e2);
    }
    assert(!msm5xxx_poc_row734_sense(0xa5e2,0,0x1f,true,true,false,0,0,&result));
    assert(result == 0xa5e2);
    const unsigned invalid[] = {0,1,3,14,16,31,32,255};
    for (unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++) {
        assert(!msm5xxx_poc_row734_sense(0xa5e2,0,1,false,false,true,0,invalid[i],&result));
        assert(result == 0xa5e2);
    }
}
''')

    def test_actual_callback_property_host_reset_and_fallback(self):
        source = self.source()
        names = ("msm5xxx_poc_halfword_sense", "msm5xxx_poc_mapped_halfword_sense",
                 "msm5xxx_poc_low5_sense", "msm5xxx_poc_row734_sense", "msm5xxx_poc_loop_sense",
                 "msm5xxx_poc_row734_u16", "msm5xxx_poc_matrix_row734_reset",
                 "msm5xxx_poc_matrix_row734_read", "msm5xxx_poc_matrix_halfword_read",
                 "msm5xxx_poc_matrix_halfword_write", "msm5xxx_poc_loop_status_matches",
                 "msm5xxx_poc_board_status_halfword_read", "msm5xxx_poc_board_status_halfword_write",
                 "msm5xxx_poc_boot_storage_hex", "msm5xxx_poc_set_matrix_row734",
                 "msm5xxx_poc_get_matrix_row734", "msm5xxx_poc_get_matrix_row734_state")
        functions = "\n".join(native_function(source, name) for name in names)
        final_start = source.index("    if (s->matrix_input_row734) {",
                                   source.index("    /* Reject an EEPROM boundary"))
        final_end = source.index("    /* Final property ordering must preserve GPIO owners and code bounds. */", final_start)
        functions += ("\n#define error_report(...) ((void)0)\n#define exit(code) return true\n"
                      "static bool final_rejected(MSM5xxxPOCMachineState *s) {\n" +
                      source[final_start:final_end] +
                      "return false; }\n#undef exit\n#undef error_report\n")
        start = source.index("        if (!s->matrix_input_host_enabled ||")
        end = source.index("            s->matrix_input_rejections++;", start)
        host = source[start:end].replace("        if (", "return (", 1).replace(" {\n", ";\n")
        harness = r'''
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <inttypes.h>
#include <ctype.h>
#include <errno.h>
#define MSM5XXX_POC_MSM_BASE 0x03000000u
#define MSM5XXX_POC_HOST_INPUT 0x80
#define MSM5XXX_POC_EEPROM_GPIO_SIZE 0x20
#define MSM5XXX_POC_HOST_INPUT_SIDEBAND_ROW UINT8_MAX
#define D 0x01001000u
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
typedef uint64_t hwaddr;
typedef struct { bool running; struct { bool can_do_io; } neg;
    struct { bool thumb; uint32_t regs[16]; } env; } CPUState;
static CPUState cpu_state = {.running=true,.neg={true},.env={.thumb=true}};
static CPUState *current_cpu=&cpu_state;
static bool vcpu=true;
static uint32_t pc;
static uint32_t get_pc(CPUState *cpu) { (void)cpu; return pc; }
typedef struct { uint32_t (*get_pc)(CPUState *); } CPUClass;
static CPUClass cpu_class={get_pc};
#define CPU_GET_CLASS(cpu) (&cpu_class)
#define CPU(cpu) ((CPUState *)(cpu))
static bool qemu_in_vcpu_thread(void) { return vcpu; }
static uint8_t backing[0x1000], rom[0x1000], descriptor[0x40], row_maps[2][12];
static void *memory_region_get_ram_ptr(void *mr) { (void)mr; return backing; }
static uint64_t msm5xxx_poc_backing_read(uint8_t *memory, hwaddr offset, unsigned size) {
    uint64_t result=0; assert(size<=8 && offset+size<=sizeof(backing));
    memcpy(&result,memory+offset,size);return result;
}
static void msm5xxx_poc_backing_write(uint8_t *memory, hwaddr offset,uint64_t value,unsigned size) {
    assert(size<=8 && offset+size<=sizeof(backing));memcpy(memory+offset,&value,size);
}
static uint32_t msm5xxx_poc_guest_u32(hwaddr address) {
    uint32_t value; assert(!(address&3));
    if (address < sizeof(rom)-3) memcpy(&value,rom+address,4);
    else if (0x1001100<=address && address<=0x1001108)
        memcpy(&value,row_maps[0]+address-0x1001100,4);
    else if (0x1001120<=address && address<=0x1001128)
        memcpy(&value,row_maps[1]+address-0x1001120,4);
    else { assert(D<=address && address<=D+sizeof(descriptor)-4);
           memcpy(&value,descriptor+address-D,4); }
    return value;
}
typedef struct {
    CPUState *cpu; int msm;
    bool matrix_input_enabled,matrix_input_host_enabled,matrix_input_pressed;
    bool matrix_input_halfword,matrix_input_low5,matrix_input_loop,matrix_input_row734;
    bool matrix_row734_boot_seen;
    uint32_t matrix_input_descriptor,matrix_input_presence_site,matrix_input_sense_site;
    uint32_t matrix_input_contact_site,matrix_row734_presence2,matrix_row734_sense2,matrix_row734_boot_site;
    uint32_t matrix_row734_row_tables[2],ram_base;
    uint32_t matrix_input_address,matrix_input_no_key,matrix_input_rows,matrix_input_sideband_mask;
    uint32_t matrix_input_sense_bitmap,matrix_input_row,matrix_input_sense,primary_nor_size;
    uint16_t matrix_input_row_mask;
    uint64_t matrix_input_rejections,matrix_input_active_reads;
    uint64_t matrix_row734_boot_reads,matrix_row734_normal_reads;
    uint8_t matrix_row734_reason;
    bool experimental_matrix_contact_enabled;
    uint32_t experimental_matrix_contact_site; uint8_t experimental_matrix_contact_level;
    bool eeprom_gpio_enabled; uint32_t eeprom_gpio_base;
    bool board_status_input_enabled;
    uint32_t board_status_input_descriptor,board_status_input_address;
    uint32_t board_status_input_mask,board_status_input_default,board_status_input_level;
    uint64_t board_status_input_rejections;
} MSM5xxxPOCMachineState;
typedef struct { uint64_t ram_size; } MachineState;
static MachineState machine_state={.ram_size=0x800000};
static MachineState *machine=&machine_state;
static uint64_t msm5xxx_poc_halfword_backing_read(MSM5xxxPOCMachineState *s,hwaddr off,unsigned size) {
    (void)s;return msm5xxx_poc_backing_read(backing,off,size);
}
static void msm5xxx_poc_halfword_backing_write(MSM5xxxPOCMachineState *s,hwaddr off,uint64_t value,unsigned size) {
    (void)s;msm5xxx_poc_backing_write(backing,off,value,size);
}
typedef MSM5xxxPOCMachineState Object;
typedef int Error;
#define MSM5XXX_POC_MACHINE(obj) (obj)
static Error error_value;
static void error_setg(Error **errp,const char *format,...) { (void)format;*errp=&error_value; }
static int qemu_strtou64(const char *text,const char **end,int base,uint64_t *value) {
    char *last;errno=0;*value=strtoull(text,&last,base);if(end)*end=last;
    return errno==ERANGE || last==text ? -1:0;
}
#define g_ascii_isxdigit(c) isxdigit((unsigned char)(c))
static char *g_strdup(const char *text) { char *r=malloc(strlen(text)+1);assert(r);return strcpy(r,text); }
static char *g_strdup_printf(const char *format,...) {
    va_list ap;char text[1024];va_start(ap,format);int n=vsnprintf(text,sizeof(text),format,ap);va_end(ap);
    assert(n>=0 && n<(int)sizeof(text));return g_strdup(text);
}
''' + functions + "\nstatic bool host_rejected(MSM5xxxPOCMachineState *s,uint8_t *record) {\n" + host + r'''
}
static void put(unsigned offset,uint16_t value) { memcpy(backing+offset,&value,2); }
static void word(unsigned offset,uint32_t value) { memcpy(descriptor+offset,&value,4); }
static void code_base(uint32_t site,unsigned reg,unsigned base) {
    uint16_t load=0x6800|(13<<6)|(base<<3)|reg;
    uint16_t read=0x8800|(reg<<3)|reg;
    memcpy(rom+site-2,&load,2);memcpy(rom+site,&read,2);
    cpu_state.env.regs[base]=D;cpu_state.env.regs[reg]=0x0300072c;
}
static void code(uint32_t site,unsigned reg) { code_base(site,reg,6); }
static void drive(unsigned selected) {
    put(0x728,0);put(0x734,selected);
    uint16_t zero=0,value=selected;memcpy(descriptor+0x2c,&zero,2);memcpy(descriptor+0x2e,&value,2);
}
static MSM5xxxPOCMachineState setup(void) {
    memset(backing,0,sizeof(backing));memset(rom,0,sizeof(rom));memset(descriptor,0,sizeof(descriptor));
    uint16_t initial_rows[]={1,2,4,8,16,128};
    memcpy(row_maps[0],initial_rows,12);memcpy(row_maps[1],initial_rows,12);
    cpu_state.env.thumb=true;cpu_state.running=true;cpu_state.neg.can_do_io=true;current_cpu=&cpu_state;vcpu=true;
    MSM5xxxPOCMachineState s={.primary_nor_size=sizeof(rom),.ram_base=0x1000000};Error *err=NULL;
    msm5xxx_poc_set_matrix_row734(&s,"1001000:102:122:142:162:182:1001100:1001120",&err);assert(!err);s.cpu=&cpu_state;
    word(4,0x03000720);word(0x20,0x03000728);word(0x28,0x03000734);word(0x34,0x0300072c);
    code(0x102,0);code(0x122,1);code(0x142,2);code(0x162,3);
    uint16_t pointer=0x4807,read=0x8980;uint32_t base=0x03000720;
    memcpy(rom+0x180,&pointer,2);memcpy(rom+0x182,&read,2);memcpy(rom+0x1a0,&base,4);
    put(0x72c,0xa5e2);drive(1);pc=0x102;return s;
}
int main(void) {
    const unsigned rows[]={1,2,4,8,16,128},senses[]={30,29,27,23,15};
    const uint32_t presence[]={0x102,0x142},rowpc[]={0x122,0x162};
    MSM5xxxPOCMachineState s=setup();Error *err=NULL;char *text;
    assert(s.matrix_input_row734 && s.matrix_input_halfword && s.matrix_input_host_enabled);
    assert(s.board_status_input_enabled && s.board_status_input_mask==4 && s.board_status_input_level==4);
    text=msm5xxx_poc_get_matrix_row734(&s,&err);assert(!strcmp(text,"1001000:102:122:142:162:182:1001100:1001120"));free(text);
    assert(!msm5xxx_poc_loop_status_matches(&s));
    assert(!final_rejected(&s));
    const unsigned ports[]={0x720,0x728,0x72c,0x734};
    for(unsigned i=0;i<ARRAY_SIZE(ports);i++) {
        s.eeprom_gpio_enabled=true;s.eeprom_gpio_base=MSM5XXX_POC_MSM_BASE+ports[i]+1;
        assert(final_rejected(&s));
    }
    s.eeprom_gpio_base=0x03000736;assert(!final_rejected(&s));
    s.eeprom_gpio_base=0x03000700;assert(!final_rejected(&s));
    s.eeprom_gpio_base++;assert(final_rejected(&s));s.eeprom_gpio_enabled=false;
    s.matrix_row734_presence2=s.primary_nor_size-2;assert(final_rejected(&s));s.matrix_row734_presence2=0x142;
    s.matrix_row734_boot_site=s.primary_nor_size-4;assert(!final_rejected(&s));s.matrix_row734_boot_site=0x182;
    for(unsigned plane=0;plane<2;plane++) for(unsigned held=0;held<6;held++) for(unsigned col=0;col<5;col++) {
        s.matrix_input_pressed=true;s.matrix_input_row=held;s.matrix_input_sense=senses[col];
        pc=presence[plane];drive(0x9f);assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==(0xa5e0|senses[col]));
        pc=rowpc[plane];
        for(unsigned selected=0;selected<6;selected++) {
            drive(rows[selected]);assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==
                                        (0xa5e0|(selected==held?senses[col]:31)));
        }
    }
    s.matrix_input_pressed=false;pc=0x122;drive(1);
    for (unsigned plane=0;plane<2;plane++) {
        pc=rowpc[plane];row_maps[plane][0]^=1;
        assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5e2 && s.matrix_row734_reason==7);
        row_maps[plane][0]^=1;
        assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5ff);
    }
    pc=0x122;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5ff);
    uint64_t reads=s.matrix_row734_normal_reads,rejects=s.matrix_input_rejections;
    pc=0x200;assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5e2);
    pc=0x122;assert(msm5xxx_poc_matrix_halfword_read(&s,0,1)==0xe2);
    assert(msm5xxx_poc_matrix_halfword_read(&s,1,1)==0xa5);
    vcpu=false;assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5e2);vcpu=true;
    current_cpu=NULL;assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5e2);current_cpu=&cpu_state;
    cpu_state.running=false;assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5e2);cpu_state.running=true;
    cpu_state.neg.can_do_io=false;assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5e2);cpu_state.neg.can_do_io=true;
    assert(s.matrix_row734_normal_reads==reads && s.matrix_input_rejections==rejects);
    cpu_state.env.thumb=false;assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5e2);assert(s.matrix_row734_reason==1);cpu_state.env.thumb=true;
    cpu_state.env.regs[6]=D+4;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5e2 && s.matrix_row734_reason==6);
    cpu_state.env.regs[6]=D;cpu_state.env.regs[1]=0x03000720;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5e2 && s.matrix_row734_reason==6);
    code_base(pc,1,5);assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5ff);
    code_base(pc,1,1);assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5ff);
    cpu_state.env.regs[1]=D;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5e2 && s.matrix_row734_reason==6);
    code(pc,1);
    for(unsigned off=0;off<4;off++) {
        unsigned at=(unsigned[]){4,0x20,0x28,0x34}[off];uint32_t old;memcpy(&old,descriptor+at,4);word(at,0);
        assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5e2 && s.matrix_row734_reason==2);word(at,old);
    }
    descriptor[0x2c]^=1;assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5e2 && s.matrix_row734_reason==3);descriptor[0x2c]^=1;
    descriptor[0x2e]^=1;assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5e2 && s.matrix_row734_reason==3);descriptor[0x2e]^=1;
    for(unsigned at=pc-2;at<=pc;at+=2) { rom[at]^=1;assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5e2 && s.matrix_row734_reason==1);rom[at]^=1; }
    drive(3);assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5e2 && s.matrix_row734_reason==4);
    drive(1);put(0x728,1);descriptor[0x2c]=1;assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5e2 && s.matrix_row734_reason==4);
    /* Boot admission precedes descriptor materialization, unlike normal scans. */
    s=setup();memset(descriptor,0,sizeof(descriptor));pc=0x182;drive(0x1f);
    cpu_state.env.regs[0]=0;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5e2 && s.matrix_row734_reason==1);
    cpu_state.env.regs[0]=0x03000720;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5ff);
    assert(s.matrix_row734_boot_seen && s.matrix_row734_boot_reads==1);
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5e2 && s.matrix_row734_boot_reads==1);
    s.matrix_input_pressed=true;s.matrix_input_row=5;s.matrix_input_sense=15;s.matrix_row734_reason=4;
    s.matrix_input_active_reads=41;s.matrix_input_rejections=42;
    msm5xxx_poc_matrix_row734_reset(&s);
    assert(s.matrix_input_pressed && s.matrix_input_row==5 && s.matrix_input_sense==15);
    assert(s.matrix_input_active_reads==41 && s.matrix_input_rejections==42);
    assert(!s.matrix_row734_boot_seen && !s.matrix_row734_boot_reads && !s.matrix_row734_normal_reads && !s.matrix_row734_reason);
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5e2 && s.matrix_row734_reason==5 && !s.matrix_row734_boot_seen);
    s.matrix_input_pressed=false;rom[0x1a0]^=1;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5e2 && s.matrix_row734_reason==1);rom[0x1a0]^=1;
    drive(0x9f);assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5e2 && s.matrix_row734_reason==4);
    drive(0x1f);assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0xa5ff);
    /* All writes retain their real backing bytes, independently of the plane. */
    msm5xxx_poc_matrix_halfword_write(&s,0,0x7352,2);assert(msm5xxx_poc_backing_read(backing,0x72c,2)==0x7352);
    s=setup();pc=0x122;drive(1);put(0x720,0xa5a2);
    assert(msm5xxx_poc_board_status_halfword_read(&s,0,2)==0xa5a6);
    /* The source-qualified auxiliary plane is HALF-only as well. */
    assert(msm5xxx_poc_board_status_halfword_read(&s,0,1)==0xa2);
    assert(msm5xxx_poc_board_status_halfword_read(&s,1,1)==0xa5);
    uint16_t saved_opcode, word_opcode=0x6809;
    memcpy(&saved_opcode,rom+pc,2);memcpy(rom+pc,&word_opcode,2);
    assert(msm5xxx_poc_board_status_halfword_read(&s,0,2)==0xa5a2);
    memcpy(rom+pc,&saved_opcode,2);cpu_state.env.thumb=false;
    assert(msm5xxx_poc_board_status_halfword_read(&s,0,2)==0xa5a2);cpu_state.env.thumb=true;
    word(4,0);assert(msm5xxx_poc_board_status_halfword_read(&s,0,2)==0xa5a2);word(4,0x03000720);
    msm5xxx_poc_board_status_halfword_write(&s,0,0x1234,2);assert(msm5xxx_poc_backing_read(backing,0x720,2)==0x1234);
    text=msm5xxx_poc_get_matrix_row734_state(&s,&err);assert(strstr(text,"\"configured\":true") && strstr(text,"\"reason\":"));free(text);
    for(unsigned held=0;held<6;held++) for(unsigned col=0;col<5;col++) {
        uint8_t record[]={0x80,1,held,senses[col]};s.matrix_input_pressed=false;assert(!host_rejected(&s,record));
    }
    uint8_t bad[]={0x80,1,6,30};assert(host_rejected(&s,bad));bad[2]=0;bad[3]=31;assert(host_rejected(&s,bad));
    bad[3]=32;assert(host_rejected(&s,bad));bad[2]=255;bad[3]=1;assert(host_rejected(&s,bad));
    s.matrix_input_pressed=true;uint8_t release[]={0x80,0,0,0};assert(!host_rejected(&s,release));release[2]=1;assert(host_rejected(&s,release));
    const char *invalid[]={"",
        "1001001:102:122:142:162:182:1001100:1001120",
        "1001000:103:122:142:162:182:1001100:1001120",
        "1001000:102:102:142:162:182:1001100:1001120",
        "1001000:102:122:142:162:1001100:1001120",
        "1001000:102:122:142:162:182:2:1001100:1001120",
        "1001000:102:122:142:162:182 :1001100:1001120",
        "-1:102:122:142:162:182:1001100:1001120",
        "100000000:102:122:142:162:182:1001100:1001120",
        "fffffff0:102:122:142:162:182:1001100:1001120",
        "1001000:0:122:142:162:182:1001100:1001120",
        "1001000:102:122:142:162:fffffffe:1001100:1001120"};
    for(unsigned i=0;i<ARRAY_SIZE(invalid);i++) { s=(MSM5xxxPOCMachineState){0};MSM5xxxPOCMachineState before=s;err=NULL;
        msm5xxx_poc_set_matrix_row734(&s,invalid[i],&err);assert(err && !memcmp(&s,&before,sizeof(s))); }
    const char *bad_tables[]={"1001000:102:122:142:162:182:0:1001120",
        "1001000:102:122:142:162:182:1001101:1001120",
        "1001000:102:122:142:162:182:fffffff8:1001120"};
    for (unsigned i=0;i<ARRAY_SIZE(bad_tables);i++) {
        s=(MSM5xxxPOCMachineState){0};MSM5xxxPOCMachineState before=s;err=NULL;
        msm5xxx_poc_set_matrix_row734(&s,bad_tables[i],&err);
        assert(err && !memcmp(&s,&before,sizeof(s)));
    }
    for(unsigned conflict=0;conflict<4;conflict++) { s=(MSM5xxxPOCMachineState){0};err=NULL;
        if(conflict==0)s.matrix_input_enabled=true;
        if(conflict==1)s.board_status_input_enabled=true;
        if(conflict==2)s.board_status_input_descriptor=D;
        if(conflict==3)s.cpu=&cpu_state; /* Machine already initialized. */
        MSM5xxxPOCMachineState before=s;msm5xxx_poc_set_matrix_row734(&s,"1001000:102:122:142:162:182:1001100:1001120",&err);
        assert(err && !memcmp(&s,&before,sizeof(s))); }
}
'''
        compile_and_run(harness)


if __name__ == "__main__":
    unittest.main()
