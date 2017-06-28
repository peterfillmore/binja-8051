from __future__ import absolute_import
from binaryninja import *
from binaryninja.enums import * 
import struct
import os
import ctypes
from binaryninja.enums import Endianness

EM_8051 = 165

#addressing modes
IMMEDIATE_MODE = 0  #Immediate Addressing    MOV A,#20h
REGISTER_MODE = 1 #Register Addressing MOV A, R0 
DIRECT_MODE = 2 #Direct Addressing   MOV A,30h 
REG_INDIRECT_MODE = 3   #Indirect Addressing MOV A,@R0
INDEXED_MODE = 4   #External Direct MOVX A,@DPTR
CODE_MODE = 5       #Code Indirect   MOVC A,@A+DPTR
BIT_ADDRESS_MODE = 6 #SETB bit_addr
BIT_INDEXED_MODE = 7 #jnb ACC.0, code_addr
FLAG_MODE = 8 #MOV bit addr,C  
IMMEDIATE_OFFSET_MODE = 9 #CJNE A,#data,reladdr
DIRECT_OFFSET_MODE = 10 #CJNE A,imm_data,reladdr

TextToken = InstructionTextTokenType.TextToken
PossibleAddressToken = InstructionTextTokenType.PossibleAddressToken
RegisterToken = InstructionTextTokenType.RegisterToken
OperandSeparatorToken = InstructionTextTokenType.OperandSeparatorToken
IntegerToken = InstructionTextTokenType.IntegerToken 
DataSymbolToken = InstructionTextTokenType.DataSymbolToken 

LLFC_E = enums.LowLevelILFlagCondition.LLFC_E 
LLFC_NE = enums.LowLevelILFlagCondition.LLFC_NE
LLFC_ULT = enums.LowLevelILFlagCondition.LLFC_ULT
LLFC_UGE = enums.LowLevelILFlagCondition.LLFC_UGE
LLFC_UGT = enums.LowLevelILFlagCondition.LLFC_UGT
LLFC_O = enums.LowLevelILFlagCondition.LLFC_O
 
reglookup = {
        0x00 : 'R0', 
        0x01 : 'R1', 
        0x02 : 'R2', 
        0x03 : 'R3', 
        0x04 : 'R4', 
        0x05 : 'R5', 
        0x06 : 'R6', 
        0x07 : 'R7', 
        0x08 : 'R0', 
        0x09 : 'R1', 
        0x0a : 'R2', 
        0x0b : 'R3', 
        0x0c : 'R4', 
        0x0d : 'R5', 
        0x0e : 'R6', 
        0x0f : 'R7', 
        0x10 : 'R0', 
        0x11 : 'R1', 
        0x12 : 'R2', 
        0x13 : 'R3', 
        0x14 : 'R4', 
        0x15 : 'R5', 
        0x16 : 'R6', 
        0x17 : 'R7', 
        0x18 : 'R0', 
        0x19 : 'R1', 
        0x1a : 'R2', 
        0x1b : 'R3', 
        0x1c : 'R4', 
        0x1d : 'R5', 
        0x1e : 'R6', 
        0x1f : 'R7', 
        0x81 : 'SP',
        0x82 : 'DPL',
        0x83 : 'DPH',
        0xd0 : 'PSW',
        0xe0 : 'A',
        0xf0 : 'B'
}


def convertBitField(field):
    bitaddress = ((0x20 * 8) + field) // 8
    bitval = field % 8
    return 'RAM{:02X}.{:d}'.format(bitaddress, bitval)

OperandTokenGen = [
    lambda reg, value, addr : [ #IMMEDIATE
        InstructionTextToken(TextToken,'#'),
        InstructionTextToken(DataSymbolToken, hex(reg), reg)
        #InstructionTextToken(PossibleAddressToken, hex(reg), reg)
        #InstructionTextToken(InstructionTextTokenType.TextToken,'h') 
    ],
    lambda reg, value, addr: [ #REGISTER
        InstructionTextToken(RegisterToken,reg)
    ],
    lambda reg, value, addr: [ #DIRECT
        InstructionTextToken(PossibleAddressToken, '0x{:02X}'.format(reg), reg)
    ],
    lambda reg, value, addr: [ #INDIRECT
        InstructionTextToken(TextToken,'@'),
        InstructionTextToken(RegisterToken, reg)
    ],
    lambda reg, value, addr: [ #INDEXED 
        InstructionTextToken(TextToken,'@'),
        InstructionTextToken(RegisterToken, reg)
    ],
    lambda reg, value, addr: [ #code mode 
        InstructionTextToken(TextToken, '@'),
        InstructionTextToken(RegisterToken, reg),
        #InstructionTextToken(OperandSeperatorToken, '+'),
        InstructionTextToken(TextToken, '+'),
        InstructionTextToken(RegisterToken, value)
    ],
    lambda reg, value, addr: [ #bit address mode 
        #InstructionTextToken(PossibleAddressToken, convertBitField(reg), reg) 
        InstructionTextToken(TextToken, convertBitField(reg), reg) 
    ],
    lambda reg, value, addr: [ #jnb ACC.0, code_addr
        InstructionTextToken(RegisterToken, reglookup[reg]),
        InstructionTextToken(TextToken,'.'),
        InstructionTextToken(TextToken, '{}'.format(1 >> value))
    ],
    lambda reg, value, addr: [ # FLAG_MODE "C"
        #InstructionTextToken(TextToken,'C'),
        InstructionTextToken(RegisterToken,'C'),
    ],
    lambda reg, value, addr: [ #IMMEDIATE_OFFSET_MODE = 9 CJNE A,#data,reladdr
        InstructionTextToken(TextToken, '#'), 
        InstructionTextToken(IntegerToken,hex(reg), reg),
        #InstructionTextToken(PossibleAddressToken,hex(reg), reg),
        InstructionTextToken(TextToken, ','),
        InstructionTextToken(PossibleAddressToken,hex(value), value)
    ],
    lambda reg, value, addr: [ #DIRECT_OFFSET_MODE = 9 CJNE A,#data,reladdr
        InstructionTextToken(PossibleAddressToken, hex(reg), reg),
        InstructionTextToken(TextToken, ','),
        InstructionTextToken(PossibleAddressToken, hex(value), value)
    ]
]
Registers = [
    'SP',       #stack pointer 0x81 
    'DPTR',       #data pointer  0x82-83
    'PWS',      #Program Status Word
    'A',        #accumulator A 0xE0
    'B',        #B register 0xF0
    'R0',       #Reg Bank 0,1,2,3
    'R1',
    'R2',
    'R3',
    'R4',
    'R5',
    'R6',
    'R7'
]

SourceOperandsIL = [
    #IMMEDIATE MODE, MOV A, #20h 
    lambda il, width, reg, value: il.const(width, reg),

    #REGISTER MODE MOV A,R0
    lambda il, width, reg, value: il.reg(width,reg),
    
    #DIRECT MODE,  MOV A, 30h
    lambda il, width, reg, value: il.load(width, il.const(width, reg)),

    #INDIRECT MODE MOV A, @R0
    lambda il, width, reg, value: il.load(width, il.reg(width, reg)),

    #external mode  MOVX A, @DPTR
    lambda il, width, reg, value: il.load(width, il.reg(2, 'DPTR')),

    #code indirect MOVC A,@A+DPTR
    lambda il, width, reg, value: il.load(width, il.add(width, il.reg(width, reg), il.reg(2, 'DPTR'))),
   
    #bit address mode
    lambda il, width, reg, value: il.load(width, il.const(width, value)),

    #jnb ACC.0, code_addr
    lambda il, width, reg, value: il.unimplemented(),

    #Flag Mode
    lambda il, width, reg, value: il.flag('C'),
   
    #IMMEDIATE_OFFSET_MODE = 9 CJNE A,#data,reladdr 
    lambda il, width, reg, value: il.const(width,reg), 
    
    #DIRECT_OFFSET_MODE = 9 CJNE A,#data,reladdr 
    lambda il, width, reg, value: il.load(width, il.const(width,reg)) 
]

#IMMEDIATE_MODE = 0  #Immediate Addressing    MOV A,#20h
#REGISTER_MODE = 1 #Register Addressing MOV A, R0 
#DIRECT_MODE = 2 #Direct Addressing   MOV A,30h 
#REG_INDIRECT_MODE = 3   #Indirect Addressing MOV A,@R0
#INDEXED_MODE = 4   #External Direct MOVX A,@DPTR
#CODE_MODE = 5       #Code Indirect   MOVC A,@A+DPTR

DestOperandsIL = [
   #immediate mode MOV #data, A 
    lambda il, width, reg, value, src: il.unimplemented(),
    
    #Register Mode MOV R0, A 
    lambda il, width, reg ,value, src: il.set_reg(width, reg, src),  

    #DIRECT_MODE = 2 #Direct Addressing   MOV A,30h 
    lambda il, width, reg, value, src: il.store(width, il.const(width,reg), src),
    
    #REG_INDIRECT_MODE = 3   #Indirect Addressing MOV @R0, A
    lambda il, width, reg, value, src: il.store(width, il.reg(width, reg), src), 

    #INDEXED_MODE = 4   #External Direct MOVX A,@DPTR
    lambda il, width, reg, value, src: il.store(width, il.reg(2, 'DPTR'), src), 
    
    #CODE_MODE = 5       #Code Indirect   MOVC A,@A+DPTR
    lambda il, width, reg, value, src: il.unimplemented(),

    #bit set mode
    lambda il, width, reg, value, src: il.store(width, il.const(1,value), src), 

    #jnb ACC.0, code_addr
    lambda il, width, reg, value: il.unimplemented(),
   
    #flag mode 
    lambda il, width, reg, value, src: il.flag_bit(width, il.flag('C'), reg),
    
    #IMMEDIATE_OFFSET_MODE = 9 CJNE A,#data,reladdr 
    lambda il, width, reg, value, src: il.unimplemented(),
    lambda il, width, reg, value, src: il.unimplemented(),

    #log_warn('il={}, width={}, reg={}, value={}, src={}'.format(il, width, reg, value,src))
]


def jump(il, dest):
    label = None
    #log_debug("JUMP = il={}, il.dest={} il.dest.value={} il.op={} il.address={} il.dir={}".format(il, il[dest], il[dest].value, il[dest].operation, hex(il[dest].address), dir(il[dest])))
    if il[dest].operation == LowLevelILOperation.LLIL_CONST:
        label = il.get_label_for_address(
            Architecture['i8051'],
            il[dest].address
        )
    if label is None:
        return il.jump(dest)
    else:
        return il.goto(label)

def jnb(il, jump_const, jump_dest, address_to_check, bit_to_check):
    #il.add_label_for_address(
    #    Architecture['i8051'],
    #    jump_const 
    #)
    t = None 
    #if il[jump_const].operation == LowLevelILOperation.LLIL_CONST:
    #    t = il.get_label_for_address(
    #        Architecture['i8051'],
    #        il[jump_const].value 
    #    )
    if t is None:
        t = LowLevelILLabel()
        indirect = True
    else:
        indirect = False
    
    il.add_label_for_address(
        Architecture['i8051'],  
        il.current_address+3 
    )
    f = il.get_label_for_address(
        Architecture['i8051'],  
        il.current_address+3 
    ) 

    #log_warn('current_addr={} dest={} t={} f={}'.format(hex(il.current_address+3),hex(jump_dest),hex(address_to_check),t,f))
    il.append(il.if_expr(
       il.and_expr(1,
           il.load(2, il.const(2,address_to_check)),
           il.const(1, bit_to_check)),
       t,
       f)
    )
    if indirect:
        il.mark_label(t)
        il.append(il.jump(jump_const))
    il.mark_label(f)
    return None

def djnz_branch(il, src_op, dst_op, src, dst, jump_address, jump_length):
    #log_debug("djnz branch  il={}, src_op={}, dst_op={}, src={}, dst={}, jump_address={}, jump_length={}".format(il, src_op, dst_op, src, dst, jump_address, jump_length))
    if dst_op == REGISTER_MODE:
        il.append(
            il.store(1, 
                il.reg(1, dst), 
                il.sub(1, 
                    il.reg(1, dst), 
                    il.const(1, 1))
                )
            )
        cond = il.compare_not_equal(1, 
            il.reg(1, dst), 
            il.const(1,0)) 
    elif dst_op == DIRECT_MODE:
        il.append(
            il.store(1, 
                il.const(1, dst), 
                il.sub(1, 
                    il.load(1, il.const(1, dst)), 
                    il.const(1, 1))
                )
            )
        cond = il.compare_not_equal(1, 
            il.load(1, il.const(1, dst)), 
            il.const(1,0))
    t = il.get_label_for_address(
        Architecture['i8051'],
        jump_address 
    )
    if t is None:
        t = LowLevelILLabel()
        indirect = True
    else:
        indirect = False
  
    f_label_found = True
    f = il.get_label_for_address(
        Architecture['i8051'],
        il.current_address + jump_length 
    ) 
    if f is None:
        f = LowLevelILLabel()
        f_label_found = False
    
    il.append(il.if_expr(
       cond,
       t,
       f)
    )
    if indirect:
        # If the destination is not in the current function,
        # then a jump, rather than a goto, needs to be added to
        # the IL.
        il.mark_label(t)
        il.append(il.jump(il.const(2,jump_address)))
    if not f_label_found:
        il.mark_label(f)

def cond_branch(il, cond, dest, length):
    #log_debug("COND BRANCH = il={}, il.dest={} il.op={}".format(il, il[dest], il[dest].operation))
    t = il.get_label_for_address(
        Architecture['i8051'],
        il[dest].address 
    )
    if t is None:
        t = LowLevelILLabel()
        indirect = True
    else:
        indirect = False
  
    f_label_found = True
    f = il.get_label_for_address(
        Architecture['i8051'],
        il.current_address + length 
    ) 
    if f is None:
        f = LowLevelILLabel()
        f_label_found = False
    
    il.append(il.if_expr(
       cond,
       t,
       f)
    )
    if indirect:
        # If the destination is not in the current function,
        # then a jump, rather than a goto, needs to be added to
        # the IL.
        il.mark_label(t)
        il.append(il.jump(dest))
    if not f_label_found:
        il.mark_label(f)

InstructionIL = {
    'SETB': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: [
        (DestOperandsIL[DIRECT_MODE] (
            il, width, src_value, None,
            il.or_expr(
                width, 
                SourceOperandsIL[DIRECT_MODE](
                    il, width, src_value, None 
                ),
                SourceOperandsIL[IMMEDIATE_MODE](
                    il, width, dst_value, None 
                )
            )
        )) if dst_op != FLAG_MODE
        else (
            None
        )
        ],
    #'SETB C': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: il.flag_bit(1, 'C', 1), 
    'MOV': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: [
        ( 
            DestOperandsIL[dst_op] (
                il, width, dst, dst_value,
                SourceOperandsIL[src_op](
                    il, width, src, src_value)
        ) if dst_op != FLAG_MODE
        else None
        ) 
        ],
    'MOVX': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: 
    [
        DestOperandsIL[dst_op] (
            il, width, dst, dst_value,
            SourceOperandsIL[src_op](
                il, width, src, src_value)
        ),
        (
            None
        )
    ], 
    'MOVC': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: 
    [
        DestOperandsIL[dst_op] (
            il, width, dst, dst_value,
            SourceOperandsIL[src_op](
                il, width, src, src_value)
        ),
        (
            None
        )
    ],
    'NOP': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: il.nop(),
    'RET': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: il.ret(il.pop(2)),
    'RETI': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: il.ret(il.pop(2)),
    'LJMP': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: il.jump(il.const(2,dst)), 
            #jump(il, il.const(2, dst)),
    'SJMP': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: jump(il, il.const(width, dst)),
    'JMP': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: 
        jump(il, 
                il.add(width, 
                    il.reg(1, 'A'), 
                    il.reg(2,'DPTR')
                )
            ),
    'PUSH': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: il.push(width, il.load(width, il.const(1, dst))),
#il.push(width, SourceOperandsIL[dst_op](il, width, dst, dst_value)),
    'POP': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: DestOperandsIL[dst_op](
            il, width, dst, dst_value, il.pop(width)
            ),
    'ANL': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: DestOperandsIL[dst_op] (
            il, width, dst, dst_value,
            il.and_expr(width,
                SourceOperandsIL[dst_op] (
                    il, width, dst, dst_value),
                SourceOperandsIL[src_op] (
                    il, width, src, src_value)
        )
    ),
    'INC': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: DestOperandsIL[dst_op] (
            il, width, dst, dst_value,
            il.add(width, 
                SourceOperandsIL[dst_op](il, width, dst, dst_value), 
                il.const(1,1)
                )
            ),
    'DEC': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: DestOperandsIL[dst_op] (
            il, width, dst, dst_value,
            il.sub(width, 
                SourceOperandsIL[dst_op](il, width, dst, dst_value), 
                il.const(1,1)
                )
            ),
    'LCALL': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: il.call(il.const(2, dst)),
    'ACALL': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: il.call(il.const(2, dst)),
    'CLR': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: clear_bits(il, src_op, dst_op, src, dst, width, src_value, dst_value),
    #'CLR': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: il.unimplemented(), 
    #'CLR C': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: il.unimplemented(), 
    #'CLR C': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: il.set_flag('C', il.const(0,0)), 
    'ADD': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: DestOperandsIL[dst_op](il, width, dst, dst_value, 
            il.add(width, SourceOperandsIL[src_op](il, width, src, src_value), SourceOperandsIL[dst_op](il, width, dst, dst_value),
            flags='cacov')
        ),
    'ADDC': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: il.unimplemented(), #TODO fix me
        #DestOperandsIL[dst_op](il, width, dst, dst_value, 
        #    il.add_carry(width, SourceOperandsIL[src_op](il, width, src, src_value), SourceOperandsIL[dst_op](il, width, dst, dst_value),
        #    flags='cacov')
        #), 
    'XRL': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: DestOperandsIL[dst_op](il, width, dst, dst_value, 
            il.xor_expr(width, SourceOperandsIL[src_op](il, width, src, src_value), SourceOperandsIL[dst_op](il, width, dst, dst_value)
            )
        ),
    'SUBB': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: il.unimplemented(), #TODO fixme
        #DestOperandsIL[dst_op](il, width, dst, dst_value, 
        #    il.sub_borrow(width, SourceOperandsIL[src_op](il, width, src, src_value), SourceOperandsIL[dst_op](il, width, dst, dst_value),
        #    flags='cacov')
        #),
    'CPL': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: DestOperandsIL[dst_op](
            il, width, dst, dst_value, 
            il.xor_expr(width, 
                SourceOperandsIL[dst_op](il, width, dst, dst_value), 
                il.const(1, dst_value) 
                )
            ),
    'CPL C': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: il.set_flag('C', il.xor_expr(0, il.flag('C'), il.const(0,1))),
    'ORL': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: DestOperandsIL[dst_op](il, width, dst, dst_value,
            il.or_expr(width,
                SourceOperandsIL[dst_op](il,width,dst,dst_value),
                SourceOperandsIL[src_op](il,width,src,src_value)
                )
            ),
    'XCH': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: [
        il.push(width, SourceOperandsIL[src_op](il, width, src, src_value)),
        DestOperandsIL[src_op](il, width, src, src_value, 
            SourceOperandsIL[dst_op](il,width,dst,dst_value)),
        DestOperandsIL[dst_op](il, width, dst, dst_value,
            il.pop(width))
        ],
    'SWAP': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: il.rotate_right(width, il.reg(width, 'A'), il.const(width, 4)),
    'RR': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: il.rotate_right(width, il.reg(width, 'A'), il.const(width, 1),flags='onlyC'),
    'RRC': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: il.unimplemented(), #TODO Fixme
        #il.rotate_right_carry(width, il.reg(width, 'A'), il.const(width, 1),flags='onlyC'),
    'RL': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: il.rotate_left(width, il.reg(width, 'A'), il.const(width, 1), flags='onlyC'),
    'RLC': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: il.unimplemented(), #TODO fixme
        #il.rotate_left_carry(width, il.reg(width, 'A'), il.const(width, 1), flags='onlyC'),
    'MUL AB': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: [
            il.push(2, il.mult(2, il.reg(1,'A'), il.reg(1,'B'))),
            il.set_reg(1, 'A', 
               il.pop(1) 
            ),
            il.set_reg(1, 'B',
                il.pop(1)
            )
            ],
    'DIV AB': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: il.unimplemented(), #TODO: work out a sequence of IL that does this instruction
    'AJMP': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: jump(il, SourceOperandsIL[dst_op](il, width, dst, dst_value)),
    'JZ': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: cond_branch(il, il.compare_equal(1, il.reg(1,'A'), il.const(1,0)), il.const(2,dst), width),  
#il.jump(il.if_expr(
#        il.compare_equal(1, 
#            il.reg(1,'A'), 
#            il.const(1,0)),
#        il.get_label_for_address(Architecture['i8051'], dst),
#        il.get_label_for_address(Architecture['i8051'], il.current_address+2)
#        )
#        ),
    'JNZ': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: cond_branch(il, 
            il.compare_not_equal(1, 
                il.reg(1, 'A'), 
                il.const(1,0)), 
            il.const(2, dst), 
            width),
#il.jump(il.if_expr(
#        il.compare_not_equal(1, 
#            il.reg(1,'A'), 
#            il.const(1,0)),
#        il.get_label_for_address(Architecture['i8051'], dst),
#        il.get_label_for_address(Architecture['i8051'], il.current_address+2)
#        )
#        ),
    'DJNZ': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: 
            djnz_branch(il, src_op, dst_op, src, dst, src_value, dst_value),     
        #[
            #dst_value = length to jump 
            #decrement the destination
            #DestOperandsIL[dst_op](il, width, dst, dst_value,
            #    il.sub(width, SourceOperandsIL[dst_op](il, width, dst, dst_value), il.const(width, 1))),
            #(
            #    cond_branch(il, 
            #    il.compare_not_equal(1, 
            #        SourceOperandsIL[dst_op](il, width, dst, dst_value), 
            #        il.const(1,0)), 
            #    il.const(2, src), 
            #    width
            #    )
            #) if True else None
            #],
    'JC': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: cond_branch(
            il, 
            il.compare_equal(0, il.flag('C'), il.const(0, 1)), 
            il.const(2,dst), 
            2),
    'JNC': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: cond_branch(
            il, 
            il.compare_not_equal(0, il.flag('C'), il.const(0, 1)), 
            il.const(2,dst), 
            2),
    'CJNE': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: cond_branch(il, il.compare_not_equal(width,                
        SourceOperandsIL[src_op](il,width,src,src_value), 
        SourceOperandsIL[dst_op](il, width, dst, dst_value)),
                il.const(2, src_value), 3),
#il.jump(il.if_expr(
#            il.compare_not_equal(width,
#                SourceOperandsIL[src_op](il,width,src,src_value),
#                SourceOperandsIL[dst_op](il,width,dst,dst_value)
#            ),
#            il.get_label_for_address(Architecture['i8051'], dst),
#            il.get_label_for_address(Architecture['i8051'], il.current_address+3)
#            )
#        ),
    'JB': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: 
        cond_branch(il, 
                il.compare_equal(1, 
                        il.and_expr(1, 
                            il.load(1, il.const(2,src_value)), 
                            il.const(1, dst_value)),
                    il.const(1, dst_value)),
                il.const(2, src),
                3
        ),
        #        il.jump(il.if_expr(
#                il.and_expr(width, 
#                    il.load(width, 
#                        il.const(width, dst)), #address to check
#                    il.const(width, dst_value)   #bit to check
#                    ),
#            il.get_label_for_address(Architecture['i8051'], dst),
#            il.get_label_for_address(Architecture['i8051'], il.current_address+3)
#            )
#        ),
    'JBC': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: cond_branch(il,
            il.and_expr(width, SourceOperandsIL[dst_op](il, width, dst, dst_value), il.not_expr(width,il.const(width, dst_value))),
            il.const(2,src),
            3),
#        il.jump(il.if_expr(
#                il.and_expr(width, 
#                    il.load(width,dst), 
#                    il.const(width, dst_value), #address to check
#                    il.const(width, dst_val)   #bit to check
#                    ),
#            il.get_label_for_address(Architecture['i8051'], dst),
#            il.get_label_for_address(Architecture['i8051'], il.current_address+3)
#            )
#        ),
    'JNB': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: 
        cond_branch(il, 
                il.compare_not_equal(1, 
                        il.and_expr(1, 
                            il.load(1, il.const(2,src_value)),  #bit address
                            il.const(1, dst_value)), 
                    il.const(1, dst_value)), #bit to check
                il.const(2, src), #jump address
                3
        ),
        #il.jump(il.if_expr(
        #        il.and_expr(width, 
        #            il.load(width, 
        #                il.const(width, dst)), #address to check
        #            il.const(width, dst_val)   #bit to check
        #            ),
        #    il.get_label_for_address(Architecture['i8051'], il.current_address+2),
        #    ),
        #    il.get_label_for_address(Architecture['i8051'], dst)
        #),
    'DA': lambda il, src_op, dst_op, src, dst, width, src_value, dst_value: il.unimplemented(), #TODO 
 
}

def clear_bits(il, src_op, dst_op, src, dst, width, src_value, dst_value):
    #log_debug("Clear Bits =  il={}, src_op={}, dst_op={}, src={}, dst={}, width={}, src_value={}, dst_value={}".format(il, src_op, dst_op, src, dst, width, src_value, dst_value))
    if dst_op == BIT_INDEXED_MODE:
        il.append(
            il.store(1, 
                src_value, #address to clear
                il.const(1,src_value),
                il.and_expr(
                    il.load(1, 
                        il.const(1,src_value)), 
                    il.const(1, il.not_expr(1,dst_value))
                )
            )
        )
    elif dst_op == REGISTER_MODE: 
        il.append(
            il.set_reg(1, dst,il.const(1,0))
        )
    if dst_op == FLAG_MODE:
        il.append( 
            il.set_flag('C', il.const(0, 0)),
        )

class i8051(Architecture):
    name = 'i8051'
    address_size = 2
    default_int_size = 1
    max_instr_length = 3 
   
    SFR = {
            0xe0 : 'A',
            0xf0 : 'B',
            0xd0 : 'PSW',
            0x81 : 'SP',
            0x82 : 'DPL',
            0x83 : 'DPH'
    }

    regs = {
        'A': RegisterInfo(  'A', 1),
        'B': RegisterInfo(  'B', 1),
        'DPTR': RegisterInfo( 'DPTR', 2),
        'PSW': RegisterInfo('PSW', 1),
        'R0': RegisterInfo( 'R0', 1),
        'R1': RegisterInfo( 'R1', 1),
        'R2': RegisterInfo( 'R2', 1),
        'R3': RegisterInfo( 'R3', 1),
        'R4': RegisterInfo( 'R4', 1),
        'R5': RegisterInfo( 'R5', 1),
        'R6': RegisterInfo( 'R6', 1),
        'R7': RegisterInfo( 'R7', 1),
        'SP': RegisterInfo( 'SP', 2)
    }
    stack_pointer = 'SP'
     
    flags = ['P', 'UD', 'OV', 'RS0', 'RS1', 'F0', 'AC', 'C']
    
    flag_write_types = ['*', 'cacov', 'onlyC', 'cov', 'onlyP', 'onlyUD', 'onlyOV', 'onlyRS0', 'onlyRS1', 'onlyF0', 'onlyAC']

    flags_written_by_flag_write_type = {
        '*' : ['P', 'UD', 'OV', 'RS0', 'RS1', 'F0', 'AC', 'C'],
        'cacov' : ['C', 'AC', 'OV'],
        'onlyC' : ['C'],
        'cov' : ['C','OV'],
        'onlyP' : ['P'],
        'onlyUD' : ['UD'],
        'onlyOV' : ['OV'],
        'onlyRS0' : ['RS0'],
        'onlyRS1' : ['RS1'],
        'onlyF0' : ['F0'],
        'onlyAC' : ['AC']
    }
    flag_roles = {
        'P': FlagRole.EvenParityFlagRole,
        #'P': FlagRole.SpecialFlagRole,
        'UD': FlagRole.SpecialFlagRole,
        'OV': FlagRole.OverflowFlagRole,
        'RS0': FlagRole.SpecialFlagRole,
        'RS1': FlagRole.SpecialFlagRole,
        'F0': FlagRole.SpecialFlagRole,
        'AC': FlagRole.CarryFlagRole,
        'C': FlagRole.CarryFlagRole
    }
    flags_required_for_flag_condition = {
           #LLFC_E : ['Z'], #Equal
           #LLFC_NE : ['Z'], #Not Equal
    ##     LLFC_SLT : ['N'], #Signed Less Than
           LLFC_ULT : ['C'], #Unsigned Less Than
    ##     LLFC_SLE : ['N'], #Signed Less Then or Equal to
    ##     LLFC_ULE : [''], #Unsigned Less Than or Equal to
    ##     LLFC_SGE : ['N'], #Signed Greather Than
           LLFC_UGE : ['C'], #Unsigned Greater Than
    ##     LLFC_SGT : ['N'], #Signed Greater Than
           LLFC_UGT : ['C'], #Unsigned Greater Than
    ##     LLFC_NEG : ['N'], #Negative
    ##     LLFC_POS : ['N'], #Positive
           LLFC_O : ['OV'], #Overflow
    ##     LowLevelILFlagCondition.LLFC_NO : ['OV'] #No Overflow
    }
    def decode_instruction(self, data, addr):
        error_value = (None, None, None, None, None, None, None, None, None)
        #if len(data) < 2:
        #    return error_value
        instruction = struct.unpack('<B', data[0])[0]
        #print("Current Instruction is " + str(hex(instruction))) 
        if instruction == 0x00:
            return 'NOP', None, None, None, None, None, 1, None, None 
        elif instruction == 0x01:
            (high_address,low_address) = struct.unpack('>BB', data[0:2])
            direct_addr = ((high_address & 0xe0 >> 5) << 8) | low_address 
            return_addr = ((addr + 2) & 0xF800) + direct_addr
            return 'AJMP', 1, None, DIRECT_MODE, None, return_addr, 2, None, None 
        elif instruction == 0x02:
            address = struct.unpack('>H', data[1:3])[0]
            return 'LJMP', 2, None, DIRECT_MODE, None, address, 3, None, None 
        elif instruction == 0x03: 
            return 'RR', 1, None, None, None, None, 1, None, None 
        elif instruction == 0x04: 
            return 'INC', 1, None, REGISTER_MODE, None, 'A', 1, None, None
        elif instruction == 0x05: 
            inc_addr = struct.unpack('>B', data[1])[0] 
            return 'INC', 1, None, DIRECT_MODE, None, inc_addr, 2, None, None
        elif instruction == 0x06: 
            return 'INC', 1, None, REG_INDIRECT_MODE, None, 'R0', 1, None, None
        elif instruction == 0x07: 
            return 'INC', 1, None, REG_INDIRECT_MODE, None, 'R1', 1, None, None
        elif instruction == 0x08: 
            return 'INC', 1, None, REGISTER_MODE, None, 'R0', 1, None, None
        elif instruction == 0x09: 
            return 'INC', 1, None, REGISTER_MODE, None, 'R1', 1, None, None
        elif instruction == 0x0a: 
            return 'INC', 1, None, REGISTER_MODE, None, 'R2', 1, None, None
        elif instruction == 0x0b: 
            return 'INC', 1, None, REGISTER_MODE, None, 'R3', 1, None, None
        elif instruction == 0x0c: 
            return 'INC', 1, None, REGISTER_MODE, None, 'R4', 1, None, None
        elif instruction == 0x0d: 
            return 'INC', 1, None, REGISTER_MODE, None, 'R5', 1, None, None
        elif instruction == 0x0e: 
            return 'INC', 1, None, REGISTER_MODE, None, 'R6', 1, None, None
        elif instruction == 0x0f: 
            return 'INC', 1, None, REGISTER_MODE, None, 'R7', 1, None, None
        elif instruction == 0x10: 
            (bit_addr, offset) = struct.unpack('>BB',data[1:3])    
            #convert the operand to address + bit 
            bitaddress = ((0x20 * 8) + bit_addr) // 8
            bitval = bit_addr % 8
            signed_number = ctypes.c_byte(offset).value
            jump_address = addr + 3 + signed_number 
            return 'JBC', 1, DIRECT_MODE, BIT_ADDRESS_MODE, jump_address, bit_addr, 3, bitaddress, bitval 
        elif instruction == 0x11: 
            (high_address,low_address) = struct.unpack('>BB', data[0:2])
            direct_addr = ((high_address & 0xe0 >> 5) << 8) | low_address 
            return_addr = ((addr + 2) & 0xF800) + direct_addr 
            return 'ACALL', 1, None, DIRECT_MODE, None, return_addr, 2, None, None  
        elif instruction == 0x12: 
            code_addr = struct.unpack('>H', data[1:3])[0] 
            return 'LCALL', 1, None, DIRECT_MODE, None, code_addr, 3, None, None 
        elif instruction == 0x13: 
            return 'RRC', 0, None, REGISTER_MODE, None, 'A', 1, None, None 
        elif instruction == 0x14: 
            return 'DEC', 1, None, REGISTER_MODE, None, 'A', 1, None, None
        elif instruction == 0x15: 
            iram_addr = struct.unpack('>B',data[1])[0]
            return 'DEC', 2, None, DIRECT_MODE, None, iram_addr, 2, None, None 
        elif instruction == 0x16: 
            return 'DEC', 1, None, REG_INDIRECT_MODE, None, 'R0', 1, None, None 
        elif instruction == 0x17: 
            return 'DEC', 1, None, REG_INDIRECT_MODE, None, 'R1', 1, None, None 
        elif instruction == 0x18: 
            return 'DEC', 1, None, REGISTER_MODE, None, 'R0', 1, None, None 
        elif instruction == 0x19: 
            return 'DEC', 1, None, REGISTER_MODE, None, 'R1', 1, None, None 
        elif instruction == 0x1a: 
            return 'DEC', 1, None, REGISTER_MODE, None, 'R2', 1, None, None 
        elif instruction == 0x1b: 
            return 'DEC', 1, None, REGISTER_MODE, None, 'R3', 1, None, None 
        elif instruction == 0x1c: 
            return 'DEC', 1, None, REGISTER_MODE, None, 'R4', 1, None, None 
        elif instruction == 0x1d: 
            return 'DEC', 1, None, REGISTER_MODE, None, 'R5', 1, None, None 
        elif instruction == 0x1e: 
            return 'DEC', 1, None, REGISTER_MODE, None, 'R6', 1, None, None 
        elif instruction == 0x1e: 
            return 'DEC', 1, None, REGISTER_MODE, None, 'R7', 1, None, None 
        elif instruction == 0x20: 
            (bit_addr, offset) = struct.unpack('>BB',data[1:3])    
            #translated_bit_address = ((0x20 * 8) + bit_addr) // 8
            translated_bit_address = bit_addr - (bit_addr % 8) 
            bitval = bit_addr % 8
            signed_number = ctypes.c_byte(offset).value
            bit_to_check = 1 << bitval 
            jump_address = addr + 3 + signed_number 
            #return 'JB',  1, DIRECT_MODE, BIT_ADDRESS_MODE, jump_address, bit_addr, 3, translated_bit_address, bit_to_check 
            return 'JB',  1, DIRECT_MODE, BIT_ADDRESS_MODE, jump_address, bit_addr, 3, translated_bit_address, bit_to_check 
        elif instruction == 0x21:
            (high_address,low_address) = struct.unpack('>BB', data[0:2])
            direct_addr = ((high_address & 0xe0 >> 5) << 8) | low_address 
            return_addr = ((addr + 2) & 0xF800) + direct_addr
            return 'AJMP', 1, None, DIRECT_MODE, None, return_addr, 2, None, None 
        elif instruction == 0x22: 
            return 'RET', 1, None, None, None, None, 1, None, None 
        elif instruction == 0x23: 
            return 'RL', 1, None, REGISTER_MODE, None, 'A', 1, None, None 
        elif instruction == 0x24:  #ADD A,#data
            src = struct.unpack('<B', data[1])[0] 
            dst = Registers[3] #A
            src_operand_type = IMMEDIATE_MODE
            dst_operand_type = REGISTER_MODE
            return 'ADD',   1, IMMEDIATE_MODE, REGISTER_MODE, src, dst, 2, None, None
        elif instruction == 0x25: #ADD A,iram addr   
            src = struct.unpack('<B', data[1])[0] 
            #dst = Registers[3] #A
            return 'ADD',   1, DIRECT_MODE, REGISTER_MODE, src, 'A', 2, None, None
        elif instruction == 0x26: #ADD A,@R0    
            return 'ADD',   1, REG_INDIRECT_MODE, REGISTER_MODE, 'R0', 'A', 1, None, None 
        elif instruction == 0x27: #ADD A,@R1    
            return 'ADD',   1, REG_INDIRECT_MODE, REGISTER_MODE, 'R1', 'A', 1, None, None 
        elif instruction == 0x28: #ADD A,R0 
            return 'ADD',   1, REGISTER_MODE, REGISTER_MODE, 'R0', 'A', 1, None, None 
        elif instruction == 0x29: 
            return 'ADD',   1, REGISTER_MODE, REGISTER_MODE, 'R1', 'A', 1, None, None 
        elif instruction == 0x2a: 
            return 'ADD',   1, REGISTER_MODE, REGISTER_MODE, 'R2', 'A', 1, None, None 
        elif instruction == 0x2b: 
            return 'ADD',   1, REGISTER_MODE, REGISTER_MODE, 'R3', 'A', 1, None, None 
        elif instruction == 0x2c: 
            return 'ADD',   1, REGISTER_MODE, REGISTER_MODE, 'R4', 'A', 1, None, None 
        elif instruction == 0x2d: 
            return 'ADD',   1, REGISTER_MODE, REGISTER_MODE, 'R5', 'A', 1, None, None 
        elif instruction == 0x2e: 
            return 'ADD',   1, REGISTER_MODE, REGISTER_MODE, 'R6', 'A', 1, None, None 
        elif instruction == 0x2f: 
            return 'ADD',   1, REGISTER_MODE, REGISTER_MODE, 'R7', 'A', 1, None, None 
        elif instruction == 0x30: 
            (bit_addr, offset) = struct.unpack('>BB',data[1:3])    
            #translated_bit_address = ((0x20 * 8) + bit_addr) // 8
            translated_bit_address = bit_addr - (bit_addr % 8) 
            bit_to_check = 1 << (bit_addr % 8)
            signed_number = ctypes.c_byte(offset).value
            jump_address = addr + 3 + signed_number 
            return 'JNB',  1, DIRECT_MODE, BIT_ADDRESS_MODE, jump_address, bit_addr, 3, translated_bit_address, bit_to_check 
        elif instruction == 0x31: 
            (high_address,low_address) = struct.unpack('>BB', data[0:2])
            direct_addr = ((high_address & 0xe0 >> 5) << 8) | low_address 
            return_addr = ((addr + 2) & 0xF800) + direct_addr 
            return 'ACALL', 1, None, DIRECT_MODE, None, return_addr, 2, None, None  
        elif instruction == 0x32: 
            return 'RETI', 1, None, None, None, None, 1, None, None 
        elif instruction == 0x33: 
            return 'RLC',  1, None, None, None, None, 1, None, None 
        elif instruction == 0x34: 
            src = struct.unpack('<B', data[1])[0] 
            dst = Registers[3] #A
            src_operand_type = IMMEDIATE_MODE
            dst_operand_type = REGISTER_MODE
            return 'ADDC',   1, IMMEDIATE_MODE, REGISTER_MODE, src, dst, 2, None, None
        elif instruction == 0x35: 
            src = struct.unpack('<B', data[1])[0] 
            dst = Registers[3] #A
            src_operand_type = IMMEDIATE_MODE
            dst_operand_type = REGISTER_MODE
            return 'ADDC',   1, IMMEDIATE_MODE, REGISTER_MODE, src, dst, 2, None, None
        elif instruction == 0x36: 
            return 'ADDC',   1, REG_INDIRECT_MODE, REGISTER_MODE, 'R0', 'A', 1, None, None 
        elif instruction == 0x37: 
            return 'ADDC',   1, REG_INDIRECT_MODE, REGISTER_MODE, 'R1', 'A', 1, None, None 
        elif instruction == 0x38: 
            return 'ADDC',   1, REGISTER_MODE, REGISTER_MODE, 'R0', 'A', 1, None, None 
        elif instruction == 0x39: 
            return 'ADDC',   1, REGISTER_MODE, REGISTER_MODE, 'R1', 'A', 1, None, None 
        elif instruction == 0x3a: 
            return 'ADDC',   1, REGISTER_MODE, REGISTER_MODE, 'R2', 'A', 1, None, None 
        elif instruction == 0x3b: 
            return 'ADDC',   1, REGISTER_MODE, REGISTER_MODE, 'R3', 'A', 1, None, None 
        elif instruction == 0x3c: 
            return 'ADDC',   1, REGISTER_MODE, REGISTER_MODE, 'R4', 'A', 1, None, None 
        elif instruction == 0x3d: 
            return 'ADDC',   1, REGISTER_MODE, REGISTER_MODE, 'R5', 'A', 1, None, None 
        elif instruction == 0x3e: 
            return 'ADDC',   1, REGISTER_MODE, REGISTER_MODE, 'R6', 'A', 1, None, None 
        elif instruction == 0x3f: 
            return 'ADDC',   1, REGISTER_MODE, REGISTER_MODE, 'R7', 'A', 1, None, None 
        elif instruction == 0x40: 
            rel_addr = struct.unpack('>B', data[1])[0]
            signed_number = ctypes.c_byte(rel_addr).value
            jump_address = addr + 2 + signed_number 
            return 'JC', 1, None, DIRECT_MODE, None, jump_address, 2, None, None 
        elif instruction == 0x41: 
            (high_address,low_address) = struct.unpack('>BB', data[0:2])
            direct_addr = ((high_address & 0xe0 >> 5) << 8) | low_address 
            return_addr = ((addr + 2) & 0xF800) + direct_addr
            return 'AJMP', 1, None, DIRECT_MODE, None, return_addr, 2, None, None 
        elif instruction == 0x42: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'ORL', 1, DIRECT_MODE, REGISTER_MODE, iram_addr, 'A', 2, None, None 
        elif instruction == 0x43: 
            (iram_addr, imm_data) = struct.unpack('>BB', data[1:3]) 
            return 'ORL', 1, IMMEDIATE_MODE, DIRECT_MODE, imm_data, iram_addr, 3, None, None 
        elif instruction == 0x44: 
            imm_data = struct.unpack('>B', data[1])[0] 
            return 'ORL',   1, IMMEDIATE_MODE,REGISTER_MODE, imm_data, 'A', 2, None, None
        elif instruction == 0x45: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'ORL',   1, DIRECT_MODE, REGISTER_MODE, iram_addr, 'A', 2, None, None 
        elif instruction == 0x46: 
            return 'ORL',   1, REG_INDIRECT_MODE, REGISTER_MODE, 'R0', 'A', 1, None, None 
        elif instruction == 0x47: 
            return 'ORL',   1, REG_INDIRECT_MODE, REGISTER_MODE, 'R1', 'A', 1, None, None 
        elif instruction == 0x48: 
            return 'ORL',   1, REGISTER_MODE, REGISTER_MODE, 'R0', 'A', 1, None, None 
        elif instruction == 0x49: 
            return 'ORL',   1, REGISTER_MODE, REGISTER_MODE, 'R1', 'A', 1, None, None 
        elif instruction == 0x4a: 
            return 'ORL',   1, REGISTER_MODE, REGISTER_MODE, 'R2', 'A', 1, None, None 
        elif instruction == 0x4b: 
            return 'ORL',   1, REGISTER_MODE, REGISTER_MODE, 'R3', 'A', 1, None, None 
        elif instruction == 0x4c: 
            return 'ORL',   1, REGISTER_MODE, REGISTER_MODE, 'R4', 'A', 1, None, None 
        elif instruction == 0x4d: 
            return 'ORL',   1, REGISTER_MODE, REGISTER_MODE, 'R5', 'A', 1, None, None 
        elif instruction == 0x4e: 
            return 'ORL',   1, REGISTER_MODE, REGISTER_MODE, 'R6', 'A', 1, None, None 
        elif instruction == 0x4f: 
            return 'ORL',   1, REGISTER_MODE, REGISTER_MODE, 'R7', 'A', 1, None, None 
        elif instruction == 0x50: 
            rel_addr = struct.unpack('>B', data[1])[0] 
            signed_number = ctypes.c_byte(rel_addr).value
            jump_address = addr + 2 + signed_number 
            return 'JNC',   1, None, DIRECT_MODE, None, jump_address, 2, None, None 
        elif instruction == 0x51: 
            (high_address,low_address) = struct.unpack('>BB', data[0:2])
            direct_addr = ((high_address & 0xe0 >> 5) << 8) | low_address 
            return_addr = ((addr + 2) & 0xF800) + direct_addr 
            return 'ACALL', 1, None, DIRECT_MODE, None, return_addr, 2, None, None
        elif instruction == 0x52: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'ANL',  1, REGISTER_MODE, DIRECT_MODE, 'A', iram_addr, 2, None, None 
        elif instruction == 0x53:
            (iram_addr, imm_data) = struct.unpack('>BB', data[1:3])
            return 'ANL',  2, IMMEDIATE_MODE, DIRECT_MODE, imm_data, iram_addr, 3, None, None 
        elif instruction == 0x54: 
            imm_data = struct.unpack('>B', data[1])[0] 
            return 'ANL',   1, IMMEDIATE_MODE, REGISTER_MODE, imm_data, 'A', 2, None, None
        elif instruction == 0x55: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'ANL',   1, DIRECT_MODE, REGISTER_MODE, iram_addr, 'A', 2, None, None 
        elif instruction == 0x56: 
            return 'ANL',   1, REG_INDIRECT_MODE, REGISTER_MODE, 'R0', 'A', 1, None, None 
        elif instruction == 0x57: 
            return 'ANL',   1, REG_INDIRECT_MODE, REGISTER_MODE, 'R1', 'A', 1, None, None 
        elif instruction == 0x58: 
            return 'ANL',   1, REGISTER_MODE, REGISTER_MODE, 'R0', 'A', 1, None, None 
        elif instruction == 0x59: 
            return 'ANL',   1, REGISTER_MODE, REGISTER_MODE, 'R1', 'A', 1, None, None 
        elif instruction == 0x5a: 
            return 'ANL',   1, REGISTER_MODE, REGISTER_MODE, 'R2', 'A', 1, None, None 
        elif instruction == 0x5b: 
            return 'ANL',   1, REGISTER_MODE, REGISTER_MODE, 'R3', 'A', 1, None, None 
        elif instruction == 0x5c: 
            return 'ANL',   1, REGISTER_MODE, REGISTER_MODE, 'R4', 'A', 1, None, None 
        elif instruction == 0x5d: 
            return 'ANL',   1, REGISTER_MODE, REGISTER_MODE, 'R5', 'A', 1, None, None 
        elif instruction == 0x5e: 
            return 'ANL',   1, REGISTER_MODE, REGISTER_MODE, 'R6', 'A', 1, None, None 
        elif instruction == 0x5f: 
            return 'ANL',   1, REGISTER_MODE, REGISTER_MODE, 'R7', 'A', 1, None, None 
        elif instruction == 0x60: 
            offset = struct.unpack('>B', data[1])[0]; 
            signed_number = ctypes.c_byte(offset).value
            jump_address = addr + 2 + signed_number
            return 'JZ',   1, None, DIRECT_MODE, None, jump_address, 2, None, None 
        elif instruction == 0x61: 
            (high_address,low_address) = struct.unpack('>BB', data[0:2])
            direct_addr = ((high_address & 0xe0 >> 5) << 8) | low_address 
            return_addr = ((addr + 2) & 0xF800) + direct_addr 
            return 'ACALL', 1, None, DIRECT_MODE, None, return_addr, 2, None, None
        elif instruction == 0x62: 
            iram_addr = struct.unpack('>B', data[1])[0]
            return 'XRL', 1, REGISTER_MODE, DIRECT_MODE, 'A', iram_addr, 2, None, None 
        elif instruction == 0x63: 
            (iram_addr, imm_data) = struct.unpack('>BB', data[1:3]) 
            return 'XRL', 2, IMMEDIATE_MODE, DIRECT_MODE, imm_data, iram_addr, 3, None, None 
        elif instruction == 0x64: 
            imm_data = struct.unpack('>B', data[1])[0] 
            return 'XRL',   1, IMMEDIATE_MODE, REGISTER_MODE, imm_data, 'A', 2, None, None
        elif instruction == 0x65: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'XRL',   1, DIRECT_MODE, REGISTER_MODE, iram_addr, 'A', 2, None, None 
        elif instruction == 0x66: 
            return 'XRL',   1, REG_INDIRECT_MODE, REGISTER_MODE, 'R0', 'A', 1, None, None 
        elif instruction == 0x67: 
            return 'XRL',   1, REG_INDIRECT_MODE, REGISTER_MODE, 'R1', 'A', 1, None, None 
        elif instruction == 0x68: 
            return 'XRL',   1, REGISTER_MODE, REGISTER_MODE, 'R0', 'A', 1, None, None 
        elif instruction == 0x69: 
            return 'XRL',   1, REGISTER_MODE, REGISTER_MODE, 'R1', 'A', 1, None, None 
        elif instruction == 0x6a: 
            return 'XRL',   1, REGISTER_MODE, REGISTER_MODE, 'R2', 'A', 1, None, None 
        elif instruction == 0x6b: 
            return 'XRL',   1, REGISTER_MODE, REGISTER_MODE, 'R3', 'A', 1, None, None 
        elif instruction == 0x6c: 
            return 'XRL',   1, REGISTER_MODE, REGISTER_MODE, 'R4', 'A', 1, None, None 
        elif instruction == 0x6d: 
            return 'XRL',   1, REGISTER_MODE, REGISTER_MODE, 'R5', 'A', 1, None, None 
        elif instruction == 0x6e: 
            return 'XRL',   1, REGISTER_MODE, REGISTER_MODE, 'R6', 'A', 1, None, None 
        elif instruction == 0x6f: 
            return 'XRL',   1, REGISTER_MODE, REGISTER_MODE, 'R7', 'A', 1, None, None 
        elif instruction == 0x70: 
            rel_addr = struct.unpack('>B', data[1])[0] 
            signed_number = ctypes.c_byte(rel_addr).value 
            jump_address = addr + 2 + signed_number
            return 'JNZ',   1, None, DIRECT_MODE, None, rel_addr, 2, None, None 
        elif instruction == 0x71: 
            (high_address,low_address) = struct.unpack('>BB', data[0:2])
            direct_addr = ((high_address & 0xe0 >> 5) << 8) | low_address 
            return_addr = ((addr + 2) & 0xF800) + direct_addr 
            return 'ACALL', 1, None, DIRECT_MODE, None, return_addr, 2, None, None
        elif instruction == 0x72: 
            bit_addr = struct.unpack('>B', data[1])[0] 
            return 'ORL', 1, DIRECT_MODE, None, bit_addr, None, 2, None, None 
        elif instruction == 0x73: #special case of jump. need to il it
            return 'JMP', 1, None, CODE_MODE, None, 'A', 1, None, 'DPTR' 
        elif instruction == 0x74: 
            imm_data = struct.unpack('>B', data[1])[0] 
            return 'MOV',   1, IMMEDIATE_MODE, REGISTER_MODE, imm_data, 'A', 2, None, None
        elif instruction == 0x75: 
            (iram_addr, imm_data) = struct.unpack('>BB', data[1:3]) 
            return 'MOV',   1, IMMEDIATE_MODE, DIRECT_MODE, imm_data, iram_addr, 3, None, None 
        elif instruction == 0x76: 
            imm_data = struct.unpack('>B', data[1])[0] 
            return 'MOV',   1, IMMEDIATE_MODE, REG_INDIRECT_MODE, imm_data, 'R0', 2, None, None
        elif instruction == 0x77: 
            imm_data = struct.unpack('>B', data[1])[0] 
            return 'MOV',   1, IMMEDIATE_MODE, REG_INDIRECT_MODE, imm_data, 'R1', 2, None, None
        elif instruction == 0x78: 
            imm_data = struct.unpack('>B', data[1])[0] 
            return 'MOV',   1, IMMEDIATE_MODE, REGISTER_MODE, imm_data, 'R0', 2, None, None
        elif instruction == 0x79: 
            imm_data = struct.unpack('>B', data[1])[0] 
            return 'MOV',   1, IMMEDIATE_MODE, REGISTER_MODE, imm_data, 'R1', 2, None, None
        elif instruction == 0x7a: 
            imm_data = struct.unpack('>B', data[1])[0] 
            return 'MOV',   1, IMMEDIATE_MODE, REGISTER_MODE, imm_data, 'R2', 2, None, None
        elif instruction == 0x7b: 
            imm_data = struct.unpack('>B', data[1])[0] 
            return 'MOV',   1, IMMEDIATE_MODE, REGISTER_MODE, imm_data, 'R3', 2, None, None
        elif instruction == 0x7c: 
            imm_data = struct.unpack('>B', data[1])[0] 
            return 'MOV',   1, IMMEDIATE_MODE, REGISTER_MODE, imm_data, 'R4', 2, None, None
        elif instruction == 0x7d: 
            imm_data = struct.unpack('>B', data[1])[0] 
            return 'MOV',   1, IMMEDIATE_MODE, REGISTER_MODE, imm_data, 'R5', 2, None, None
        elif instruction == 0x7e: 
            imm_data = struct.unpack('>B', data[1])[0] 
            return 'MOV',   1, IMMEDIATE_MODE, REGISTER_MODE, imm_data, 'R6', 2, None, None
        elif instruction == 0x7f: 
            imm_data = struct.unpack('>B', data[1])[0] 
            return 'MOV',   1, IMMEDIATE_MODE, REGISTER_MODE, imm_data, 'R7', 2, None, None
        elif instruction == 0x80: 
            offset = struct.unpack('>B',data[1])[0]
            signed_number = ctypes.c_byte(offset).value 
            jump_address = addr + 2 + signed_number 
            return 'SJMP',  2, None, DIRECT_MODE, None, jump_address, 2, None, None 
        elif instruction == 0x81: 
            (high_address,low_address) = struct.unpack('>BB', data[0:2])
            direct_addr = ((high_address & 0xe0 >> 5) << 8) | low_address 
            return_addr = ((addr + 2) & 0xF800) + direct_addr
            return 'AJMP', 1, None, DIRECT_MODE, None, return_addr, 2, None, None 
        elif instruction == 0x82: 
            
            bit_addr = struct.unpack('>B', data[1])[0] 
            #return 'ANL', 1, DIRECT_MODE, None, bit_addr, None, None, 2, None, None 
            return None, 1, None, None, None, None, 2, None, None 
        elif instruction == 0x83: 
            return 'MOVC', 0, CODE_MODE, REGISTER_MODE, 'A', 'A', 1, 'PC', None 
        elif instruction == 0x84: 
            return 'DIV AB',  0, REGISTER_MODE, REGISTER_MODE, 'B', 'A', 1, None, None
        elif instruction == 0x85: 
            (iram_addr_to, iram_addr_from) = struct.unpack('>BB',data[1:3]) 
            return 'MOV',  1, DIRECT_MODE, DIRECT_MODE, iram_addr_from, iram_addr_to, 3, None,None 
        elif instruction == 0x86: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'MOV', 1, REGISTER_MODE, DIRECT_MODE, 'R0', iram_addr, 2, None, None 
        elif instruction == 0x87: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'MOV', 1, REGISTER_MODE, DIRECT_MODE, 'R1', iram_addr, 2, None, None 
        elif instruction == 0x88: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'MOV', 1, REGISTER_MODE, DIRECT_MODE, 'R0', iram_addr, 2, None, None 
        elif instruction == 0x89: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'MOV', 1, REGISTER_MODE, DIRECT_MODE, 'R1', iram_addr, 2, None, None 
        elif instruction == 0x8a: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'MOV', 1, REGISTER_MODE, DIRECT_MODE, 'R2', iram_addr, 2, None, None 
        elif instruction == 0x8b: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'MOV', 1, REGISTER_MODE, DIRECT_MODE, 'R3', iram_addr, 2, None, None 
        elif instruction == 0x8c: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'MOV', 1, REGISTER_MODE, DIRECT_MODE, 'R4', iram_addr, 2, None, None 
        elif instruction == 0x8d: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'MOV', 1, REGISTER_MODE, DIRECT_MODE, 'R5', iram_addr, 2, None, None 
        elif instruction == 0x8e: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'MOV', 1, REGISTER_MODE, DIRECT_MODE, 'R6', iram_addr, 2, None, None 
        elif instruction == 0x8f: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'MOV', 1, REGISTER_MODE, DIRECT_MODE, 'R7', iram_addr, 2, None, None 
        elif instruction == 0x90: 
            data16 = struct.unpack('>H',data[1:3])[0] 
            return 'MOV',   2, IMMEDIATE_MODE, REGISTER_MODE, data16, 'DPTR', 3, None, None 
        elif instruction == 0x91: 
            (high_address,low_address) = struct.unpack('>BB', data[0:2])
            direct_addr = ((high_address & 0xe0 >> 5) << 8) | low_address 
            return_addr = ((addr + 2) & 0xF800) + direct_addr 
            return 'ACALL', 1, None, DIRECT_MODE, None, return_addr, 2, None, None
        elif instruction == 0x92: 
            address_int = struct.unpack('>B', data[1])[0] 
            bit_to_set = 1 << (address_int % 8)
            bit_address = address_int - (address_int % 8)
            return 'MOV', 1, FLAG_MODE, DIRECT_MODE, 'C', bit_address, 2, bit_to_set, bit_to_set 
        elif instruction == 0x93: 
            return 'MOVC',   1, CODE_MODE, REGISTER_MODE, 'A', 'A', 1, 'DPTR', None 
        elif instruction == 0x94: 
            imm_data = struct.unpack('>B', data[1])[0] 
            return 'SUBB',   1, IMMEDIATE_MODE, REGISTER_MODE, imm_data, 'A', 2, None, None
        elif instruction == 0x95: 
            imm_data = struct.unpack('>B', data[1])[0] 
            return 'SUBB',   1, DIRECT_MODE, REGISTER_MODE, imm_data, 'A', 2, None, None
        elif instruction == 0x96: 
            return 'SUBB',   1, REG_INDIRECT_MODE, REGISTER_MODE, 'R0', 'A', 1, None, None
        elif instruction == 0x97: 
            return 'SUBB',   1, REG_INDIRECT_MODE, REGISTER_MODE, 'R1', 'A', 1, None, None
        elif instruction == 0x98: 
            return 'SUBB',   1, REGISTER_MODE, REGISTER_MODE, 'R0', 'A', 1, None, None
        elif instruction == 0x99: 
            return 'SUBB',   1, REGISTER_MODE, REGISTER_MODE, 'R1', 'A', 1, None, None
        elif instruction == 0x9a: 
            return 'SUBB',   1, REGISTER_MODE, REGISTER_MODE, 'R2', 'A', 1, None, None
        elif instruction == 0x9b: 
            return 'SUBB',   1, REGISTER_MODE, REGISTER_MODE, 'R3', 'A', 1, None, None
        elif instruction == 0x9c: 
            return 'SUBB',   1, REGISTER_MODE, REGISTER_MODE, 'R4', 'A', 1, None, None
        elif instruction == 0x9d: 
            return 'SUBB',   1, REGISTER_MODE, REGISTER_MODE, 'R5', 'A', 1, None, None
        elif instruction == 0x9e: 
            return 'SUBB',   1, REGISTER_MODE, REGISTER_MODE, 'R6', 'A', 1, None, None
        elif instruction == 0x9f: 
            return 'SUBB',   1, REGISTER_MODE, REGISTER_MODE, 'R7', 'A', 1, None, None
        elif instruction == 0xa0: 
            return 'ORL',    1, None, None, None, None, 2, None, None 
        elif instruction == 0xa1: 
            (high_address,low_address) = struct.unpack('>BB', data[0:2])
            direct_addr = ((high_address & 0xe0 >> 5) << 8) | low_address 
            return_addr = ((addr + 2) & 0xF800) + direct_addr
            return 'AJMP', 1, None, DIRECT_MODE, None, return_addr, 2, None, None 
        elif instruction == 0xa2: 
            address_int = struct.unpack('>B', data[1])[0] 
            bit_to_set = 1 << (address_int % 8)
            bit_addr = address_int - (address_int % 8) 
            return 'MOV', 1, DIRECT_MODE, FLAG_MODE, bit_addr, 'C', 2, bit_to_set, bit_to_set 
        elif instruction == 0xa3: 
            return 'INC', 2, None, REGISTER_MODE, None, 'DPTR', 1, None, None
        elif instruction == 0xa4: 
            return 'MUL AB', 1,  REGISTER_MODE, REGISTER_MODE, 'B', 'A', 1, 'A', 'B' 
        elif instruction == 0xa5: 
            return '???',   None, None, None, None, None, 1, None, None 
        elif instruction == 0xa6: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'MOV',   1, DIRECT_MODE, REG_INDIRECT_MODE, iram_addr, 'R0', 2, None, None 
        elif instruction == 0xa7: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'MOV',   1, DIRECT_MODE, REG_INDIRECT_MODE, iram_addr, 'R1', 2, None, None 
        elif instruction == 0xa8: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'MOV',   1, DIRECT_MODE, REGISTER_MODE, iram_addr, 'R0', 2, None, None 
        elif instruction == 0xa9: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'MOV',   1, DIRECT_MODE, REGISTER_MODE, iram_addr, 'R1', 2, None, None 
        elif instruction == 0xaa: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'MOV',   1, DIRECT_MODE, REGISTER_MODE, iram_addr, 'R2', 2, None, None 
        elif instruction == 0xab: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'MOV',   1, DIRECT_MODE, REGISTER_MODE, iram_addr, 'R3', 2, None, None 
        elif instruction == 0xac: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'MOV',   1, DIRECT_MODE, REGISTER_MODE, iram_addr, 'R4', 2, None, None 
        elif instruction == 0xad: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'MOV',   1, DIRECT_MODE, REGISTER_MODE, iram_addr, 'R5', 2, None, None 
        elif instruction == 0xae: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'MOV',   1, DIRECT_MODE, REGISTER_MODE, iram_addr, 'R6', 2, None, None 
        elif instruction == 0xaf: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'MOV',   1, DIRECT_MODE, REGISTER_MODE, iram_addr, 'R7', 2, None, None 
        elif instruction == 0xb0: 
            bit_addr = struct.unpack('>B', data[1])[0] 
            #return 'ANL',   1, DIRECT_MODE, None, bit_addr, None, 2, None, None 
            return None,   1, None, None, None, None, 2, None, None 
        elif instruction == 0xb1: 
            (high_address,low_address) = struct.unpack('>BB', data[0:2])
            direct_addr = ((high_address & 0xe0 >> 5) << 8) | low_address 
            return_addr = ((addr + 2) & 0xF800) + direct_addr 
            return 'ACALL', 1, None, DIRECT_MODE, None, return_addr, 2, None, None
        elif instruction == 0xb2: 
            bit_addr = struct.unpack('>B', data[1])[0] 
            address_to_flip = bit_addr - (bit_addr%8)
            bit_to_flip = 1 << (bit_addr % 8)
            return 'CPL', 1, None, BIT_ADDRESS_MODE, None, address_to_flip, 2, None, bit_to_flip 
        elif instruction == 0xb3: 
            return 'CPL C',   1, None, None, None, None, 1, None, None 
        elif instruction == 0xb4: 
            (imm_data, rel_addr) = struct.unpack('>BB', data[1:3]) 
            signed_number = ctypes.c_byte(rel_addr).value 
            jump_address = addr + 3 + signed_number
            return 'CJNE',   1, IMMEDIATE_OFFSET_MODE, REGISTER_MODE, imm_data, 'A', 3, jump_address, None
        elif instruction == 0xb5: 
            (imm_data, rel_addr) = struct.unpack('>BB', data[1:3]) 
            signed_number = ctypes.c_byte(rel_addr).value 
            jump_address = addr + 3 + signed_number
            return 'CJNE',   1, DIRECT_OFFSET_MODE, REGISTER_MODE, imm_data, 'A', 3, jump_address, None        
        elif instruction == 0xb6: 
            (imm_data, rel_addr) = struct.unpack('>BB', data[1:3]) 
            signed_number = ctypes.c_byte(rel_addr).value 
            jump_address = addr + 3 + signed_number
            return 'CJNE',   1, IMMEDIATE_OFFSET_MODE, REG_INDIRECT_MODE, imm_data, 'R0', 3, jump_address, None
        elif instruction == 0xb7: 
            (imm_data, rel_addr) = struct.unpack('>BB', data[1:3]) 
            signed_number = ctypes.c_byte(rel_addr).value 
            jump_address = addr + 3 + signed_number
            return 'CJNE',   1, IMMEDIATE_OFFSET_MODE, REG_INDIRECT_MODE, imm_data, 'R1', 3, jump_address, None
        elif instruction == 0xb8: 
            (imm_data, rel_addr) = struct.unpack('>BB', data[1:3])
            signed_number = ctypes.c_byte(rel_addr).value 
            jump_address = addr + 3 + signed_number
            return 'CJNE',   1, IMMEDIATE_OFFSET_MODE, REGISTER_MODE, imm_data, 'R0', 3, jump_address, None
        elif instruction == 0xb9: 
            (imm_data, rel_addr) = struct.unpack('>BB', data[1:3])
            signed_number = ctypes.c_byte(rel_addr).value 
            jump_address = addr + 3 + signed_number
            return 'CJNE',   1, IMMEDIATE_OFFSET_MODE, REGISTER_MODE, imm_data, 'R1', 3, jump_address, None
        elif instruction == 0xba: 
            (imm_data, rel_addr) = struct.unpack('>BB', data[1:3])
            signed_number = ctypes.c_byte(rel_addr).value 
            jump_address = addr + 3 + signed_number
            return 'CJNE',   1, IMMEDIATE_OFFSET_MODE, REGISTER_MODE, imm_data, 'R2', 3, jump_address, None
        elif instruction == 0xbb: 
            (imm_data, rel_addr) = struct.unpack('>BB', data[1:3])
            signed_number = ctypes.c_byte(rel_addr).value 
            jump_address = addr + 3 + signed_number
            return 'CJNE',   1, IMMEDIATE_OFFSET_MODE, REGISTER_MODE, imm_data, 'R3', 3, jump_address, None
        elif instruction == 0xbc: 
            (imm_data, rel_addr) = struct.unpack('>BB', data[1:3])
            signed_number = ctypes.c_byte(rel_addr).value 
            jump_address = addr + 3 + signed_number
            return 'CJNE',   1, IMMEDIATE_OFFSET_MODE, REGISTER_MODE, imm_data, 'R4', 3, jump_address, None
        elif instruction == 0xbd: 
            (imm_data, rel_addr) = struct.unpack('>BB', data[1:3])
            signed_number = ctypes.c_byte(rel_addr).value 
            jump_address = addr + 3 + signed_number
            return 'CJNE',   1, IMMEDIATE_OFFSET_MODE, REGISTER_MODE, imm_data, 'R5', 3, jump_address, None
        elif instruction == 0xbe: 
            (imm_data, rel_addr) = struct.unpack('>BB', data[1:3]) 
            signed_number = ctypes.c_byte(rel_addr).value 
            jump_address = addr + 3 + signed_number
            return 'CJNE',   1, IMMEDIATE_OFFSET_MODE, REGISTER_MODE, imm_data, 'R6', 3, jump_address, None
        elif instruction == 0xbf: 
            (imm_data, rel_addr) = struct.unpack('>BB', data[1:3]) 
            signed_number = ctypes.c_byte(rel_addr).value 
            jump_address = addr + 3 + signed_number
            return 'CJNE',   1, IMMEDIATE_OFFSET_MODE, REGISTER_MODE, imm_data, 'R7', 3, jump_address, None
        elif instruction == 0xc0: 
            direct_addr = struct.unpack('>B', data[1])[0] 
            return 'PUSH', 1,  None, DIRECT_MODE, None, direct_addr, 2, None, None 
        elif instruction == 0xc1: 
            (high_address,low_address) = struct.unpack('>BB', data[0:2])
            direct_addr = ((high_address & 0xe0 >> 5) << 8) | low_address 
            return_addr = ((addr + 2) & 0xF800) + direct_addr
            return 'AJMP', 1, None, DIRECT_MODE, None, return_addr, 2, None, None 
        elif instruction == 0xc2: 
            bit_addr = struct.unpack('>B', data[1])[0] 
            address_to_check = ((0x20 * 8) + bit_addr) // 8
            bitval = 1 << bit_addr % 8
            #bit_to_clear = (~(1 << (bit_addr % 8)) & 0xff) 
            return 'CLR', 1, None, BIT_ADDRESS_MODE, None, bit_addr, 2, address_to_check, bitval 
        elif instruction == 0xc3: 
            return 'CLR', 1,  None, FLAG_MODE, None, 'C', 1, 0, None 
        elif instruction == 0xc4: 
            return 'SWAP', 0,  None, REGISTER_MODE, None, 'A', 1, None, None
        elif instruction == 0xc5: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'XCH',   1, DIRECT_MODE, REGISTER_MODE, iram_addr, 'A', 2, None, None 
        elif instruction == 0xc6: 
            return 'XCH',   1, REG_INDIRECT_MODE, REGISTER_MODE, 'R0', 'A', 1, None, None 
        elif instruction == 0xc7: 
            return 'XCH',   1, REG_INDIRECT_MODE, REGISTER_MODE, 'R1', 'A', 1, None, None 
        elif instruction == 0xc8: 
            return 'XCH',   1, REGISTER_MODE, REGISTER_MODE, 'R0', 'A', 1, None, None 
        elif instruction == 0xc9: 
            return 'XCH',   1, REGISTER_MODE, REGISTER_MODE, 'R1', 'A', 1, None, None 
        elif instruction == 0xca: 
            return 'XCH',   1, REGISTER_MODE, REGISTER_MODE, 'R2', 'A', 1, None, None 
        elif instruction == 0xcb: 
            return 'XCH',   1, REGISTER_MODE, REGISTER_MODE, 'R3', 'A', 1, None, None 
        elif instruction == 0xcc: 
            return 'XCH',   1, REGISTER_MODE, REGISTER_MODE, 'R4', 'A', 1, None, None 
        elif instruction == 0xcd: 
            return 'XCH',   1, REGISTER_MODE, REGISTER_MODE, 'R5', 'A', 1, None, None 
        elif instruction == 0xce: 
            return 'XCH',   1, REGISTER_MODE, REGISTER_MODE, 'R6', 'A', 1, None, None 
        elif instruction == 0xcf: 
            return 'XCH',   1, REGISTER_MODE, REGISTER_MODE, 'R7', 'A', 1, None, None 
        elif instruction == 0xd0: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'POP',   1, None, DIRECT_MODE, None, iram_addr, 2, None, None 
        elif instruction == 0xd1: 
            (high_address,low_address) = struct.unpack('>BB', data[0:2])
            direct_addr = ((high_address & 0xe0 >> 5) << 8) | low_address 
            return_addr = ((addr + 2) & 0xF800) + direct_addr 
            return 'ACALL', 1, None, DIRECT_MODE, None, return_addr, 2, None, None
        elif instruction == 0xd2: 
            address_int = struct.unpack('<B', data[1])[0]
            address_to_write = ((0x20 * 8) + address_int) // 8
            #address_to_write = address_int - (address_int % 8) 
            bit_to_set = 1 << (address_int % 8)
            return 'SETB', 1, None, BIT_ADDRESS_MODE, None, address_int, 2, address_to_write, bit_to_set 
        elif instruction == 0xd3: 
            return 'SETB', 1, None, FLAG_MODE, None, 'C', 1, None, None 
        elif instruction == 0xd4: 
            return 'DA',   1, None, REGISTER_MODE, None, 'A', 1, None, None
        elif instruction == 0xd5: 
            (iram_addr, rel_addr) = struct.unpack('>BB', data[1:3]) 
            signed_number = ctypes.c_byte(rel_addr).value
            jump_address = addr + 3 + signed_number
            jump_length = 3 #instruction length
            return 'DJNZ',   1, DIRECT_MODE, DIRECT_MODE, rel_addr, iram_addr, 3, jump_address, jump_length 
        elif instruction == 0xd6: 
            return 'XCHD',   1, REG_INDIRECT_MODE, REGISTER_MODE, 'R0', 'A', 1, None, None 
        elif instruction == 0xd7: 
            return 'XCHD',   1, REG_INDIRECT_MODE, REGISTER_MODE, 'R1', 'A', 1, None, None 
        elif instruction == 0xd8: 
            rel_addr = struct.unpack('>B', data[1])[0] 
            signed_number = ctypes.c_byte(rel_addr).value
            jump_address = addr + 2 + signed_number
            jump_length = 2 #instruction length
            return 'DJNZ',   1, DIRECT_MODE, REGISTER_MODE, jump_address, 'R0', 2, jump_address, jump_length  
        elif instruction == 0xd9: 
            rel_addr = struct.unpack('>B', data[1])[0] 
            signed_number = ctypes.c_byte(rel_addr).value
            jump_address = addr + 2 + signed_number
            jump_length = 2 
            return 'DJNZ',   1, DIRECT_MODE, REGISTER_MODE, jump_address, 'R1', 2, jump_address, jump_length  
        elif instruction == 0xda: 
            rel_addr = struct.unpack('>B', data[1])[0] 
            signed_number = ctypes.c_byte(rel_addr).value
            jump_address = addr + 2 + signed_number
            jump_length = 2 
            return 'DJNZ',   1, DIRECT_MODE, REGISTER_MODE, jump_address, 'R2', 2, jump_address, jump_length  
        elif instruction == 0xdb: 
            rel_addr = struct.unpack('>B', data[1])[0] 
            signed_number = ctypes.c_byte(rel_addr).value
            jump_address = addr + 2 + signed_number
            jump_length = 2 
            return 'DJNZ',   1, DIRECT_MODE, REGISTER_MODE, jump_address, 'R3', 2, jump_address, jump_length  
        elif instruction == 0xdc: 
            rel_addr = struct.unpack('>B', data[1])[0] 
            signed_number = ctypes.c_byte(rel_addr).value
            jump_address = addr + 2 + signed_number
            jump_length = 2 
            return 'DJNZ',   1, DIRECT_MODE, REGISTER_MODE, jump_address, 'R4', 2, jump_address, jump_length  
        elif instruction == 0xdd: 
            rel_addr = struct.unpack('>B', data[1])[0] 
            signed_number = ctypes.c_byte(rel_addr).value
            jump_address = addr + 2 + signed_number
            jump_length = 2 
            return 'DJNZ',   1, DIRECT_MODE, REGISTER_MODE, jump_address, 'R5', 2, jump_address, jump_length  
        elif instruction == 0xde: 
            rel_addr = struct.unpack('>B', data[1])[0] 
            signed_number = ctypes.c_byte(rel_addr).value
            jump_address = addr + 2 + signed_number
            jump_length = 2 
            return 'DJNZ',   1, DIRECT_MODE, REGISTER_MODE, jump_address, 'R6', 2, jump_address, jump_length  
        elif instruction == 0xdf: 
            rel_addr = struct.unpack('>B', data[1])[0] 
            signed_number = ctypes.c_byte(rel_addr).value
            jump_address = addr + 2 + signed_number
            jump_length = 2 
            return 'DJNZ',   1, DIRECT_MODE, REGISTER_MODE, jump_address, 'R7', 2, jump_address, jump_length  
        elif instruction == 0xe0: #MOVX A,@DPTR
            return 'MOVX',   2, INDEXED_MODE, REGISTER_MODE, 'DPTR', 'A', 1, None, None 
        elif instruction == 0xe1: 
            (high_address,low_address) = struct.unpack('>BB', data[0:2])
            direct_addr = ((high_address & 0xe0 >> 5) << 8) | low_address 
            return_addr = ((addr + 2) & 0xF800) + direct_addr
            return 'AJMP', 1, None, DIRECT_MODE, None, return_addr, 2, None, None 
        elif instruction == 0xe2: 
            return 'MOVX', 1, REG_INDIRECT_MODE, REGISTER_MODE, 'R0', 'A', 1, None, None 
        elif instruction == 0xe3: 
            return 'MOVX', 1, REG_INDIRECT_MODE, REGISTER_MODE, 'R1', 'A', 1, None, None 
        elif instruction == 0xe4: 
            return 'CLR',   1, None, REGISTER_MODE, None, 'A', 1, None, None
        elif instruction == 0xe5: 
            iram_addr = struct.unpack('>B', data[1])[0] 
            return 'MOV',   1, DIRECT_MODE, REGISTER_MODE, iram_addr, 'A', 2, None, None 
        elif instruction == 0xe6: 
            return 'MOV',   1, REG_INDIRECT_MODE, REGISTER_MODE, 'R0', 'A', 1, None, None 
        elif instruction == 0xe7: 
            return 'MOV',   1, REG_INDIRECT_MODE, REGISTER_MODE, 'R1', 'A', 1, None, None 
        elif instruction == 0xe8: 
            return 'MOV',   1, REGISTER_MODE, REGISTER_MODE, 'R0', 'A', 1, None, None 
        elif instruction == 0xe9: 
            return 'MOV',   1, REGISTER_MODE, REGISTER_MODE, 'R1', 'A', 1, None, None 
        elif instruction == 0xea: 
            return 'MOV',   1, REGISTER_MODE, REGISTER_MODE, 'R2', 'A', 1, None, None 
        elif instruction == 0xeb: 
            return 'MOV',   1, REGISTER_MODE, REGISTER_MODE, 'R3', 'A', 1, None, None 
        elif instruction == 0xec: 
            return 'MOV',   1, REGISTER_MODE, REGISTER_MODE, 'R4', 'A', 1, None, None 
        elif instruction == 0xed: 
            return 'MOV',   1, REGISTER_MODE, REGISTER_MODE, 'R5', 'A', 1, None, None 
        elif instruction == 0xee: 
            return 'MOV',   1, REGISTER_MODE, REGISTER_MODE, 'R6', 'A', 1, None, None 
        elif instruction == 0xef: 
            return 'MOV',   1, REGISTER_MODE, REGISTER_MODE, 'R7', 'A', 1, None, None 
        elif instruction == 0xf0: #MOVX @DPTR,A 
            return 'MOVX',  2, REGISTER_MODE, INDEXED_MODE, 'A', 'DPTR', 1, None, None 
        elif instruction == 0xf1: 
            (high_address,low_address) = struct.unpack('>BB', data[0:2])
            direct_addr = ((high_address & 0xe0 >> 5) << 8) | low_address 
            return_addr = ((addr + 2) & 0xF800) + direct_addr 
            return 'ACALL', 1, None, DIRECT_MODE, None, return_addr, 2, None, None
        elif instruction == 0xf2: 
            return 'MOVX',  1, REGISTER_MODE, REG_INDIRECT_MODE, 'A', 'R0', 1, None, None 
        elif instruction == 0xf3: 
            return 'MOVX',  1, REGISTER_MODE, REG_INDIRECT_MODE, 'A', 'R1', 1, None, None 
        elif instruction == 0xf4: 
            return 'CPL',   1, None, REGISTER_MODE, None, 'A', 1, None, 0xff 
        elif instruction == 0xf5: 
            iram_addr = struct.unpack('>B',data[1])[0]
            return 'MOV',   1, REGISTER_MODE, DIRECT_MODE, 'A', iram_addr, 2, None, None 
        elif instruction == 0xf6: 
            return 'MOV',   1, REGISTER_MODE, REG_INDIRECT_MODE, 'A', 'R0', 1, None, None 
        elif instruction == 0xf7: 
            return 'MOV',   1, REGISTER_MODE, REG_INDIRECT_MODE, 'A', 'R1', 1, None, None 
        elif instruction == 0xf8: 
            return 'MOV',   1, REGISTER_MODE, REGISTER_MODE, 'A', 'R0', 1, None, None  
        elif instruction == 0xf9: 
            return 'MOV',   1, REGISTER_MODE, REGISTER_MODE, 'A', 'R1', 1, None, None  
        elif instruction == 0xfa: 
            return 'MOV',   1, REGISTER_MODE, REGISTER_MODE, 'A', 'R2', 1, None, None  
        elif instruction == 0xfb: 
            return 'MOV',   1, REGISTER_MODE, REGISTER_MODE, 'A', 'R3', 1, None, None  
        elif instruction == 0xfc: 
            return 'MOV',   1, REGISTER_MODE, REGISTER_MODE, 'A', 'R4', 1, None, None  
        elif instruction == 0xfd: 
            return 'MOV',   1, REGISTER_MODE, REGISTER_MODE, 'A', 'R5', 1, None, None  
        elif instruction == 0xfe: 
            return 'MOV',   1, REGISTER_MODE, REGISTER_MODE, 'A', 'R6', 1, None, None  
        elif instruction == 0xff: 
            return 'MOV',   1, REGISTER_MODE, REGISTER_MODE, 'A', 'R7', 1, None, None  
    
    def perform_get_instruction_text(self, data, addr):
        (instr, width, src_operand, dst_operand, src, dst, length, src_value, dst_value) = self.decode_instruction(data, addr)
        if instr is None:
            return None

        tokens = []

        instruction_text = instr
        tokens = [
            InstructionTextToken(InstructionTextTokenType.TextToken, '{:7s}'.format(instruction_text))
        ]
        if dst_operand != None:
            tokens += OperandTokenGen[dst_operand](dst, dst_value, addr)
        if dst_operand != None and src_operand != None:
            tokens += [InstructionTextToken(TextToken, ',')]
        if src_operand != None:
            tokens += OperandTokenGen[src_operand](src, src_value, addr)

        return tokens, length
    
    def perform_get_instruction_info(self, data, addr):
        instr, width, src_op, dst_op, src, dst, length, src_value, dst_value = self.decode_instruction(data,addr)
        #log_warn('decoded func={}'.format(hex(addr)))
        if instr is None:
            return None
        result = InstructionInfo()
        result.length = length
        if instr in ['RET','RETI']:
            result.add_branch(BranchType.FunctionReturn)
        elif instr in ['ACALL','LCALL']:
            result.add_branch(BranchType.CallDestination, dst)
        elif instr in ['JMP']: #JMP @A+DPTR
            result.add_branch(BranchType.UnresolvedBranch)
        elif instr in ['AJMP', 'SJMP', 'LJMP']:
            result.add_branch(BranchType.UnconditionalBranch, dst)
        elif instr in ['JZ','JNC', 'JC']:
            #log_info("instr={}".format(instr)) 
            result.add_branch(BranchType.TrueBranch, dst)
            result.add_branch(BranchType.FalseBranch, addr+2)
        elif instr in ['DJNZ'] and length == 2:
            #log_info("instr={}".format(instr)) 
            result.add_branch(BranchType.TrueBranch, src)
            result.add_branch(BranchType.FalseBranch, addr+2)
        elif instr in ['JB','JNB']:
            result.add_branch(BranchType.TrueBranch, src)
            result.add_branch(BranchType.FalseBranch, addr+3)
        elif instr in ['DJNZ','CJNE','JBC'] and length == 3:
            #log_info("instr={}".format(instr)) 
            result.add_branch(BranchType.TrueBranch, src_value)
            result.add_branch(BranchType.FalseBranch, addr+3)
        return result
    
    def perform_get_instruction_low_level_il(self, data, addr, il):
        (instr, width, src_operand, dst_operand, src, dst, length, src_value, dst_value) = self.decode_instruction(data, addr)
        #log_warn('instr={}, src_op={}, dst_op={}, src={}, dst={}, width={}, src_value={}, dst_value={}'.format(instr, src_operand, dst_operand, src, dst, width, src_value, dst_value))
        if instr is None:
            return None
        if InstructionIL.get(instr) is None:
            log_error('[0x{:2x}]: {} not implemented'.format(addr,instr))
            il.append(il.unimplemented())
        else:
            il_instr = InstructionIL[instr](
                il, src_operand, dst_operand, src, dst, width, src_value, dst_value)
            if isinstance(il_instr, list):
                for i in [i for i in il_instr if i is not None]:
                    #log_debug("instr={} LLIL={}".format(instr, i.index)) 
                    il.append(i)
            elif il_instr is not None:
                il.append(il_instr)
        return length
    #def __init__(self, *args, **kwargs):
    #    super (Spu, self).__init__*args, **kwargs)
    #    self.init_addresses()

    #def init_addresses(self, addr, il):
    #    il.add_label_for_address(
    #def init_instructions(self):
    #    class idef(object):
    #        def __init__(self,name):
    #            self.name = name
    #        def decode(self, opcode, addr):
    #            raise NotImplementedError
    #        def get_text(self, opcode, addr):
    #            raise NotImplementedError

#class DefaultCallingConvention(CallingConvention):
#    name = 'default'
#    int_arg_regs = ['R7', 'R5', 'R3']

#class SDCC
i8051.register()
arch = Architecture['i8051']
#BinaryViewType[''].register_arch(EM_8051, Endianness.LittleEndian, arch)

#def do_nothing(bv,function):
#	show_message_box("Do Nothing", "Congratulations! You have successfully done nothing.\n\n" +
#					 "Pat yourself on the back.", OKButtonSet, ErrorIcon)
#
#PluginCommand.register_for_address("Useless Plugin", "Basically does nothing", do_nothing)
