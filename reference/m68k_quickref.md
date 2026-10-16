# MC68000 Quick Reference

## Registers

D0-D7 (data, 32-bit), A0-A6 (address, 32-bit), A7 = SP (USP in user mode,
SSP in supervisor mode), PC (24-bit address bus on the 68000), SR = system byte
(T, S, interrupt mask I2-I0) + CCR (X N Z V C).

## Addressing Modes (vasm Motorola syntax as emitted by dasm68k.py)

| Mode | Reg | Syntax | Extension words |
|------|-----|--------|-----------------|
| 000 | n | `Dn` | 0 |
| 001 | n | `An` | 0 (not for byte size) |
| 010 | n | `(An)` | 0 |
| 011 | n | `(An)+` | 0 |
| 100 | n | `-(An)` | 0 |
| 101 | n | `d16(An)` e.g. `$1C00(A1)` | 1 |
| 110 | n | `d8(An,Xn.W/L)` | 1 (brief format; scale must be 1 on the 68000) |
| 111 | 000 | `($1234).W` (sign-extended: `($FFFF8000).W`) | 1 |
| 111 | 001 | `($00400000).L` | 2 |
| 111 | 010 | `label(PC)` | 1 |
| 111 | 011 | `label(PC,Xn.W/L)` | 1 |
| 111 | 100 | `#imm` | 1 (byte/word) or 2 (long) |

Categories: **data** = all but An; **memory** = all but Dn/An; **control** =
(An), d16(An), d8(An,Xn), abs, PC-relative; **alterable** = no PC-relative,
no immediate.

## Opcode Map (top 4 bits)

| Bits 15-12 | Group |
|-----------|-------|
| 0000 | bit ops (BTST/BCHG/BCLR/BSET), MOVEP, immediate ops (ORI ANDI SUBI ADDI EORI CMPI) |
| 0001 / 0011 / 0010 | MOVE.B / MOVE.W / MOVE.L (MOVEA when destination is An) |
| 0100 | misc: LEA, PEA, CLR, NEG, NEGX, NOT, TST, TAS, EXT, SWAP, MOVEM, JMP, JSR, LINK, UNLK, TRAP, RTS, RTE, RTR, NOP, STOP, RESET, CHK, MOVE to/from SR/CCR/USP, NBCD, ILLEGAL ($4AFC) |
| 0101 | ADDQ, SUBQ, Scc, DBcc |
| 0110 | BRA, BSR, Bcc (8-bit displacement, or 0 = 16-bit word follows) |
| 0111 | MOVEQ |
| 1000 | OR, DIVU, DIVS, SBCD |
| 1001 | SUB, SUBA, SUBX |
| 1010 | **line A: unimplemented, raises vector $28. Macintosh traps.** |
| 1011 | CMP, CMPA, CMPM, EOR |
| 1100 | AND, MULU, MULS, ABCD, EXG |
| 1101 | ADD, ADDA, ADDX |
| 1110 | shifts and rotates (ASx LSx ROXx ROx), register or memory (word, by 1) |
| 1111 | line F: unimplemented, raises vector $2C |

## Condition Codes

| cc | Meaning | Test | cc | Meaning | Test |
|----|---------|------|----|---------|------|
| T | true | 1 | F | false | 0 |
| HI | higher (unsigned) | !C & !Z | LS | lower or same | C \| Z |
| CC (HS) | carry clear | !C | CS (LO) | carry set | C |
| NE | not equal | !Z | EQ | equal | Z |
| VC | overflow clear | !V | VS | overflow set | V |
| PL | plus | !N | MI | minus | N |
| GE | greater or equal | N = V | LT | less than | N != V |
| GT | greater than | !Z & N = V | LE | less or equal | Z \| N != V |

`DBcc Dn,label`: if cc is false, decrement Dn.W and branch unless it became -1,
so `DBF D0,loop` runs the loop D0+1 times.

## Exception Vectors

| Vector | Address | Use |
|--------|---------|-----|
| 0 | $000 | reset: initial SSP |
| 1 | $004 | reset: initial PC |
| 2 | $008 | bus error |
| 3 | $00C | address error (word/long access at an odd address) |
| 4 | $010 | illegal instruction |
| 5 | $014 | divide by zero |
| 6 | $018 | CHK |
| 7 | $01C | TRAPV |
| 8 | $020 | privilege violation |
| 9 | $024 | trace |
| 10 | $028 | line 1010 (A-traps) |
| 11 | $02C | line 1111 |
| 24 | $060 | spurious interrupt |
| 25-31 | $064-$07C | level 1-7 autovectors |
| 32-47 | $080-$0BC | TRAP #0-#15 |
| 64-255 | $100-$3FF | user (vectored) interrupts: the Mac uses this area for system globals instead |

Group 1/2 exception frame (TRAP, line A, interrupts): SR (word) then PC (long)
pushed on the supervisor stack; RTE pops them. Bus/address error frames add
access address, instruction register and a status word (7 words total).

## Idioms

| Code | Meaning |
|------|---------|
| `MOVEM.L D3-D7/A2-A4,-(SP)` ... `MOVEM.L (SP)+,D3-D7/A2-A4` | save / restore callee-saved registers |
| `LINK A6,#-n` ... `UNLK A6` | stack frame with n bytes of locals |
| `MOVEA.L (SP)+,A0` / `ADDQ.L #n,SP` / `JMP (A0)` | Pascal return: callee pops n bytes of parameters |
| `ADD.W D0,D0` / `MOVE.W tbl(PC,D0.W),D0` / `JMP tbl(PC,D0.W)` | jump table of word offsets from `tbl` |
| `JMP tbl(PC,D0.W)` into `BRA.W` x n | jump table of branches |
| `MOVE.W #$2700,SR` | supervisor mode, all interrupts masked |
| `ORI.W #$0700,SR` / `MOVE.W (SP)+,SR` | mask interrupts / restore previous level |
| `MOVEQ #n,D0` + `DBF D0,loop` | counted loop (n+1 iterations) |
| `LEA handler(PC),A0` / `MOVE.L A0,($64).W` | install an exception / interrupt handler |
| `$Axxx` word | Macintosh trap (see mac_traps.md) |
