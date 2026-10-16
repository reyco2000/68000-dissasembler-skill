; Atari ST GEMDOS executable fixture (original code).
; Build: vasmm68k_mot -Ftos -nosym -no-opt -m68000 -o hello.prg hello_st.s
; Exercises relocations in code and data, BSS references, TOS calls,
; a Supexec callback, a VBL install, hardware / system variables,
; a PC-relative jump table and Line-A.

        MC68000
        TEXT
start:  MOVEA.L 4(SP),A5                ; basepage
        PEA     hello(PC)
        MOVE.W  #$09,-(SP)              ; Cconws
        TRAP    #1
        ADDQ.L  #6,SP
        PEA     super_init(PC)
        MOVE.W  #38,-(SP)               ; Supexec
        TRAP    #14
        ADDQ.L  #6,SP
        MOVE.L  #counter,D0             ; relocated immediate into BSS
        MOVEA.L D0,A0
        CLR.L   (A0)
        LEA     (table).L,A1            ; relocated absolute into DATA
        MOVEQ   #2,D1
        BSR.S   dispatch
        DC.W    $A000                   ; Line-A init
        MOVE.W  #7,-(SP)                ; Crawcin
        TRAP    #1
        ADDQ.L  #2,SP
        CLR.W   -(SP)                   ; Pterm0
        TRAP    #1
        DC.B    'never reached',0
        EVEN
dispatch:
        ADD.W   D1,D1
        MOVE.W  jt(PC,D1.W),D1
        JMP     jt(PC,D1.W)
jt:     DC.W    case0-jt,case1-jt,case2-jt
case0:  RTS
case1:  MOVEQ   #1,D0
        RTS
case2:  MOVEA.L ptrs+4,A0               ; relocated absolute into DATA
        JSR     (A0)
        RTS
super_init:
        MOVE.W  #$0777,($FFFF8240).W    ; palette 0 = white
        MOVE.L  ($000004BA).W,D0        ; _hz_200
        MOVE.L  #vbl,($00000070).W      ; install VBL handler (relocated immediate)
        MOVE.B  #$0F,($FFFF8800).W      ; YM register 15
        RTS
vbl:    ADDQ.L  #1,counter
        RTE
helper: LINK    A6,#-4
        MOVE.L  8(A6),D0
        UNLK    A6
        RTS

        DATA
hello:  DC.B    'Hello from the ST',13,10,0
        EVEN
table:  DC.W    1,2,3,4
ptrs:   DC.L    case0,helper,counter,hello
        DC.L    $00010000               ; not relocated: stays a number

        BSS
counter: DS.L   1
buffer: DS.B    256
bufend:
