# Firmware watchdog

The watchdog detector recognizes instruction and literal relationships, never a
filename or model string. Admission requires one unambiguous service/task pair.
The service conditionally returns when its RAM suppression byte is nonzero;
otherwise it updates a RAM halfword shadow, setting and then clearing one bit,
and writes both shadow values to the same byte MMIO port. The periodic task
calls that service after its timed signal wait and has assertions linked to
`dog.c`. Two report tails are supported: paired report checks/assertions, or a
single missing-report check guarded by a RAM inhibit byte. The latter must use
the same timer/report object at the wait and both report-clear exits; both
exits restart the same pet loop. Instruction/control-flow contracts, resolved
call targets and literal relationships are checked for each complete form.
Unsupported compiler forms and ambiguous ownership remain disabled, including
multiple owners across the two forms. A downloader pulse alone is insufficient.

The QEMU watchdog uses virtual clock time, including icount time, independently
of guest IRQ/FIQ masks. The first completed high-to-low pulse starts the timer;
subsequent completed pulses restart it. Its register, bit mask, and timeout are
machine properties. A watchdog reset uses the existing machine reset path,
retaining NOR, EEPROM, and NAND backing rather than recreating seed images.

## Static timing evidence and timeout policy

Evidence was read from
`work/bootlogo-analysis/ida3-X7700/analysis.out` and checked by static Thumb
instruction decoding of the supplied image. Addresses below describe that
witness; they are not detector admission constants.

* `0x951C6` supplies timeout 100 in r2, and `0x951CE` calls `0xB8358`;
  `0x951D4` pets at `0x950A0` immediately after that wait returns.
* `0xB8358` forwards r2 to the timer setter `0xB826A` as r1, then calls the
  signal wait `0xB8318`. The setter stores the count at timer offset 8
  (`0xB828C`). The timer walker `0xB82C8` expires timers whose remaining count
  is at most its r0 argument, otherwise subtracts that argument
  (`0xB82DC..0xB82FE`).
* The tick callback supplies 5 to that walker at `0x3C524..0x3C526`.
  The same callback supplies 5 to the clock accumulator at `0x3C506..0x3C50A`;
  `0x3D288..0x3D2A4` carries at 1000 (literal `0xFFFFFC18` at `0x3D2A8`).
  This agrees with the emulator's virtual 5 ms REX tick policy: timeout 100
  represents 20 callbacks, or 100 ms of scheduled virtual time. It is not a
  physical oscillator measurement.
* Startup uses the same timer and count 100 (`0x95138..0x9513C`), pets at
  `0x95140`, and waits on signal mask `0xC800` (`0x95146..0x9514C`). This
  includes its timer signal `0x0800`, registered at `0x95124..0x9512C`.
  On that signal it pets (`0x95156`) and rearms 100 (`0x9515A..0x9515E`).
  Its total startup/report counter is not a single interval between pets.
* Rebuild's final 100000 calls (`0x110A4E..0x110A58`) are a tight loop with
  a pet on every iteration. Then `0xA15FC` masks IRQ/FIQ and reaches the
  unconditional self-branch at `0xA1608`, with no further pet.

The default **30000 ms** is an emulator policy: 300 times the longest explicit
scheduled pet wait established above (100 ms). `watchdog-timeout-ms` allows it
to be changed. Static analysis does not establish a global worst-case latency
through every task, flash operation, or masked-interrupt region, and does not
recover the physical watchdog's timeout. The conservative margin therefore
reduces false expiry risk but cannot prove its absence for all workloads.

The control routine at `0x9502C` pets once, pulses bit 4 of the shared port, and
sets the software suppression byte. The physical semantics of bit 4 are not
established; this implementation does not infer a hardware disable operation
from it. A long intentional suppression period can therefore expire the
emulated watchdog. Likewise, supported detection is deliberately narrower than
all possible firmware watchdog implementations. No firmware execution was used
to establish the timing evidence.

## Alternate report-tail static witness

IDA 9.1/idalib analysis of the external SPH-X8500 copy confirms the same
shadow-pulse service at `0x6335C`: suppression byte `0x01001C90`, halfword shadow
`0x010E097C`, and byte MMIO `0x03000700` with mask 1. Its periodic owner at
`0x63478` supplies count 100 (`0x63486`), calls the timed-wait wrapper at
`0x88890` (`0x6348E`), then pets at `0x63494`. The wrapper forwards the timer
and count to `0x887A2`, then waits at `0x88850`. The setter stores the count at
timer offset 8 (`0x887C4`); the walker at `0x88800` expires or subtracts its
argument. The tick supplies 5 at `0xA088..0xA08A`. This retains the existing
conservative timeout policy; it does not recover a physical timeout.

The alternate report tail checks the report word at timer `0x010B863C` offset
`0x14`, consults RAM byte `0x01014F08`, and asserts with line number and `dog.c`
(`0x634D4..0x634D8`). Both exits clear that report word and branch back to reset
the loop counter. These are grammar/data-flow relationships, not admission
addresses or model identifiers.

The rebuild completion path pets 100000 times (`0xEEEAA..0xEEEB4`) and calls
`0x6F94C` at `0xEEEBE`. That routine calls `0x1660E8`, masks IRQ/FIQ through
`0x2324D0`, then self-branches forever at `0x6F956`, with no more pets. The mask
helper switches to ARM and ORs `0xC0` into CPSR control (`0x2324D4..0x2324E4`).
Together with the periodic dog owner, this establishes the watchdog-reset
dependency statically. The downloader's direct high/low writes at
`0x10F4..0x1122` corroborate the port but are not used for admission.

The IDA transcript is external at
`work/bootlogo-analysis/ida3-X8500/watchdog-check.txt`; databases and firmware
bytes are not repository fixtures.

## Configuration and validation

`FirmwareConfig.watchdog` carries the detected register/mask, service/task
addresses and primary scan length. Watchdog detection runs after layout and
override finalization, scanning the final NOR window so appended dump/RAM
bytes cannot enlarge it and descriptor-based NOR extensions are included.
Transport repeats detection on exactly that
window of the loaded NOR and emits `watchdog-register`, `watchdog-mask`, and
`watchdog-timeout-ms` only when all evidence fields still agree. The profile's
`timeout_ms` is independently tunable (1000 through 3600000 ms in transport);
the native timeout property defaults to 30000 ms. Omitted register/mask leaves
the native device disabled. Reset cancels the timer until a new complete pulse.
The shared ready-poll port continues to receive writes and supply its readback.

Tests compile the actual native watchdog helpers in a small C harness and
exercise synthetic relocated Thumb graphs, rejection mutations, source binding,
and detection-to-property emission. The real-image integration checks read the
external corpus and skip when absent. No firmware-derived byte snippets are
checked into the repository.
