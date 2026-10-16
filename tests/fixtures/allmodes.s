; Every MC68000 instruction form and addressing mode, for decoder tests.
; Build: vasmm68k_mot -Fbin -no-opt -m68000 -o allmodes.bin allmodes.s
; The disassembly of allmodes.bin must contain no DC.W in the code and
; must reassemble to identical bytes.

        MC68000
        ORG     $10000
Start:
; ---- data movement, all source modes ----
        MOVE.L  D1,D2
        MOVEA.L A3,A4
        MOVE.W  (A0),D0
        MOVE.W  (A1)+,D0
        MOVE.W  -(A2),D0
        MOVE.W  $10(A3),D0
        MOVE.W  -$10(A3),D0
        MOVE.B  $7F(A4,D5.W),D0
        MOVE.B  -$80(A4,A5.L),D0
        MOVE.L  ($1234).W,D0
        MOVE.L  ($FFFF8000).W,D0
        MOVE.L  ($00123456).L,D0
        MOVE.W  Start(PC),D0
        MOVE.W  Start(PC,D1.W),D0
        MOVE.W  Start(PC,A1.L),D0
        MOVE.B  #$12,D0
        MOVE.W  #$1234,D0
        MOVE.L  #$12345678,D0
; ---- all destination modes ----
        MOVE.L  D0,(A0)
        MOVE.L  D0,(A0)+
        MOVE.L  D0,-(A0)
        MOVE.L  D0,$100(A0)
        MOVE.L  D0,$1(A0,D0.W)
        MOVE.L  D0,($0100).W
        MOVE.L  D0,($00FF0000).L
        MOVE.W  #$0001,$10(A0)
        MOVEA.W D0,A0
        MOVEA.W #$8000,A1
        MOVEQ   #$7F,D7
        MOVEQ   #-$80,D7
        MOVEP.W $10(A0),D0
        MOVEP.L -$10(A0),D1
        MOVEP.W D2,$20(A1)
        MOVEP.L D3,$30(A1)
        MOVEM.L D0-D7/A0-A6,-(SP)
        MOVEM.L (SP)+,D0-D7/A0-A6
        MOVEM.W D0/D2/A3,(A0)
        MOVEM.W $10(A0),D1/A1
        MOVEM.L Start(PC),D0-D1
        MOVEM.L D3,($1000).W
        LEA     $10(A0),A1
        LEA     Start(PC),A2
        LEA     ($00400000).L,A3
        PEA     (A0)
        PEA     Start(PC)
        EXG     D0,D1
        EXG     A0,A1
        EXG     D2,A3
        SWAP    D4
        LINK    A6,#-$20
        UNLK    A6
        MOVE.W  SR,D0
        MOVE.W  SR,(A0)
        MOVE.W  D0,CCR
        MOVE.W  #$001F,CCR
        MOVE.W  D0,SR
        MOVE.W  #$2700,SR
        MOVE.L  A0,USP
        MOVE.L  USP,A1
; ---- arithmetic ----
        ADD.B   D0,D1
        ADD.W   (A0),D1
        ADD.L   #$10000,D1
        ADD.W   D1,(A0)
        ADD.L   D1,$10(A0)
        ADDA.W  D0,A0
        ADDA.L  #$12345678,A0
        ADDI.B  #$01,D0
        ADDI.W  #$1234,(A0)
        ADDI.L  #$12345678,($1234).W
        ADDQ.B  #1,D0
        ADDQ.W  #8,A0
        ADDQ.L  #4,(A0)+
        ADDX.B  D0,D1
        ADDX.L  -(A0),-(A1)
        SUB.B   D0,D1
        SUB.W   D1,(A0)
        SUBA.L  A1,A0
        SUBI.W  #$0010,D0
        SUBQ.L  #1,D0
        SUBX.W  -(A2),-(A3)
        NEG.B   D0
        NEG.W   (A0)
        NEGX.L  D0
        CLR.B   D0
        CLR.W   (A0)+
        CLR.L   -(A0)
        EXT.W   D0
        EXT.L   D1
        MULU.W  D0,D1
        MULU.W  #$10,D1
        MULS.W  (A0),D2
        DIVU.W  D0,D1
        DIVS.W  #$0003,D2
        ABCD    D0,D1
        ABCD    -(A0),-(A1)
        SBCD    D2,D3
        SBCD    -(A2),-(A3)
        NBCD    D0
        NBCD    (A0)
; ---- compare / test ----
        CMP.B   D0,D1
        CMP.W   (A0),D1
        CMP.L   #$00000000,D0
        CMPA.W  D0,A0
        CMPA.L  (A0),A1
        CMPI.B  #$7F,D0
        CMPI.W  #$1234,(A0)
        CMPI.L  #$12345678,($1234).W
        CMPM.B  (A0)+,(A1)+
        CMPM.L  (A2)+,(A3)+
        TST.B   D0
        TST.W   (A0)
        TST.L   ($0100).W
        TAS     D0
        TAS     (A0)
        CHK.W   D0,D1
        CHK.W   #$0010,D1
; ---- logic ----
        AND.B   D0,D1
        AND.W   #$00FF,D1
        AND.L   D1,(A0)
        ANDI.B  #$0F,D0
        ANDI.W  #$F0F0,(A0)
        ANDI.B  #$1F,CCR
        ANDI.W  #$F8FF,SR
        OR.B    D0,D1
        OR.W    D1,(A0)
        ORI.L   #$80000000,D0
        ORI.B   #$01,CCR
        ORI.W   #$0700,SR
        EOR.B   D0,D1
        EOR.L   D1,(A0)
        EORI.W  #$FFFF,D0
        EORI.B  #$04,CCR
        EORI.W  #$2000,SR
        NOT.B   D0
        NOT.L   (A0)
; ---- shifts / rotates ----
        ASL.B   #1,D0
        ASL.W   #8,D0
        ASL.L   D1,D0
        ASR.W   #3,D0
        LSL.L   #2,D0
        LSR.B   D2,D3
        ROL.W   #1,D0
        ROR.L   #8,D0
        ROXL.B  #4,D0
        ROXR.W  D1,D0
        ASL.W   (A0)
        ASR.W   $10(A0)
        LSL.W   (A0)+
        LSR.W   -(A0)
        ROL.W   ($1000).W
        ROR.W   ($00012345).L
        ROXL.W  (A1)
        ROXR.W  (A2)
; ---- bit operations ----
        BTST    D0,D1
        BTST    D0,(A0)
        BTST    D0,Start(PC)
        BTST    D0,#$55
        BTST    #31,D0
        BTST    #7,(A0)
        BTST    #0,Start(PC)
        BCHG    D1,D2
        BCHG    #3,(A0)
        BCLR    D1,(A0)+
        BCLR    #15,D0
        BSET    D1,-(A0)
        BSET    #2,$10(A0)
; ---- conditions ----
        ST      D0
        SF      (A0)
        SHI     D1
        SLS     D1
        SCC     D1
        SCS     D1
        SNE     D1
        SEQ     D1
        SVC     D1
        SVS     D1
        SPL     D1
        SMI     D1
        SGE     D1
        SLT     D1
        SGT     D1
        SLE     $10(A0)
Loop:   DBF     D0,Loop
        DBT     D0,Loop
        DBNE    D1,Loop
        DBEQ    D1,Loop
        BHI.S   Loop
        BLS.S   Loop
        BCC.S   Loop
        BCS.S   Loop
        BNE.W   Loop
        BEQ.W   Loop
        BVC.W   Loop
        BVS.W   Loop
        BPL.S   Fwd
        BMI.S   Fwd
        BGE.S   Fwd
        BLT.S   Fwd
        BGT.W   Fwd
        BLE.W   Fwd
        BSR.S   Fwd
        BSR.W   Fwd
        JSR     Fwd(PC)
        JSR     (A0)
        JSR     $10(A0)
        JSR     ($00010000).L
        NOP
        TRAP    #0
        TRAP    #15
        TRAPV
        RESET
        STOP    #$2700
; ---- Macintosh A-line traps ----
        DC.W    $A9F0           ; _LoadSeg
        DC.W    $A11E           ; _NewPtr
        DC.W    $A402           ; _Read ,ASYNC
        DC.W    $A86E           ; _InitGraf
        BRA.W   Fwd
Fwd:    RTS
        RTE
        RTR
        JMP     (A0)
        ILLEGAL
