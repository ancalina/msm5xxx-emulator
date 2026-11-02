# MSM5000 two-channel tone generator

The supported firmware driver writes ten byte registers at four-byte spacing.
Channel A uses `0x030006b8`, `0x030006bc` (q low and high),
`0x030006c0`, `0x030006c4` (reload low and high), and `0x030006c8`
(control). Channel B uses the same layout starting at `0x030006cc`.
The stop routine writes zero to both controls and retains the other bytes.

The driver clamps frequency to 100–4000 Hz and calculates `period = K / f`
using integer division. Its `(selector, K)` pairs are `(1, 307500)`,
`(7, 2152500)`, `(14, 4305000)` and `(28, 8610000)`. It writes
`q = period * a3 / 10000`, `reload = ~(period - selector)`, and
`control = selector | 0x40`. All four constants imply a 307500 Hz base
clock, with the selected counter clock `307500 * selector`. The modeled
period is `(~reload & 0xffff) + selector` ticks. Integer division in the
driver causes a small quantization difference between the requested frequency
and the programmed frequency.

The available driver code does not establish the electrical output polarity,
compare semantics, hardware reset values, or register readback. The model
assumes q is the high-time compare, clamps it to the period, initializes the
registers to zero, and reads back the last byte written. A firmware output
profile uses values from 0 to 9800 on the 10000 scale, supporting a fractional
compare interpretation but not proving the output waveform. These are model
assumptions rather than recovered hardware specifications.

Only images whose converter and ten-register writer match the static signature
are admitted. An already admitted Yamaha or opaque audio transport excludes
this tone profile. The two channel waveforms are mixed and rendered against
QEMU virtual time; guest register writes advance the old state before changing
it. The bounded PCM queue feeds the existing host and M5P2 output paths.
