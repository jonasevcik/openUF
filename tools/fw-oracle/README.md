# fw-oracle

Executes a function from a plaintext UniFi MIPS16e firmware library in Unicorn, so a
formula read from a disassembly (`mips-linux-gnu-objdump -D -b binary -m mips:16 -EB`) can be
checked against the real code instead of against the reading.

    pip install unicorn
    LIBUBNT=/path/to/usr/lib/libubnt.so.1.0.0 python3 -c "from oracle import *; ..."

`Oracle().run({offset: (struct_fmt, value)})` returns `(v0, struct_bytes)`. For
`calc_sta_satisfaction` (U7LR 6.8.2) the result block is at struct+520: score, reason @+8,
anomalies @+16, 16 sub-scores @+24 (-1 = term skipped). Not emulated: the `libubnt_log` varargs
path (a run that logs raises `UcError`).
