#cython: language_level=3
#distutils: language=c++

from dotnetutils import net_exceptions

cdef class OpCode:
    """ Represents a .NET IL opcode.
    
    Notes:
        name (str): the name of the opcode
        operand_count (int): how many operands the opcode has
        two_byte_opcode (bint): does the opcode require two bytes to be represented.
        has_arg_list (bint): Does the opcode have a list as an argument?
        is_branch (bint): does the opcode branch
        has_token_argument (bint): is the argument a metadata token?
        nstack (int): The number of items added or popped from the stack by the opcode.
        astack (int): The number of items added to the stack by the opcode.
        pstack (int): The number of items popped from the stack by the opcode.
    """
    def __init__(self, str name, int operand_count=0, bint is_two_byte_opcode=False, bint has_arg_list=False, bint is_branch=False,
                 bint has_token_argument=False, int nstack=0, int astack=0, int pstack=0):
        self.name = name
        self.operand_count = operand_count
        self.two_byte_opcode = is_two_byte_opcode
        self.has_arg_list = has_arg_list
        self.is_branch = is_branch
        self.has_token_argument = has_token_argument
        self.nstack = nstack
        self.astack = astack
        self.pstack = pstack

    cpdef int get_astack(self):
        """ Obtains the number of items appended to the stack by the opcode.
            same rules as get_nstack()

        Returns:
            int: The number of items appended to the stack.
        """
        return self.astack

    cpdef int get_pstack(self):
        """ Obtains the number of items popped from the stack by the opcode.
            same rules as get_nstack()

        Returns:
            int: The number of items popped from the stack.
        """
        return self.pstack

    cpdef int get_nstack(self):
        """ Obtains the number of items added or removed from the stack by the opcode.
            Not accurate for call, castclass, callvirt and newobj
        
        Returns:
            int: the number of items added or removed from the stack by the opcode.
        """
        return self.nstack

    cpdef int get_operand_count(self):
        return self.operand_count

    cpdef str get_name(self):
        return self.name

    cpdef bint is_branch_opcode(self):
        return self.is_branch

    cpdef bint is_token_argument_opcode(self):
        return self.has_token_argument

    cpdef bint has_arg_list_opcode(self):
        return self.has_arg_list

    cpdef bint is_two_byte_opcode(self):
        return self.two_byte_opcode

    cdef void set_opcode(self, int opcode_):
        """ Internal method for setting up the opcode value.
        """
        self.opcode = opcode_

    cpdef Opcodes obtain_opcode(self):
        """Returns the byte value of an opcode
        """
        return <Opcodes> self.opcode
    
    cpdef bint opcode_argument_signed(self):
        cdef list unsigned_args
        unsigned_args = [
            Opcodes.Ldarg,
            Opcodes.Ldarg_S,
            Opcodes.Ldarga,
            Opcodes.Ldarga_S,
            Opcodes.Ldloc,
            Opcodes.Ldloc_S,
            Opcodes.Ldloca,
            Opcodes.Ldloca_S,
            Opcodes.Starg,
            Opcodes.Starg_S,
            Opcodes.Stloc,
            Opcodes.Stloc_S
        ]
        return Opcodes(self.obtain_opcode()) not in unsigned_args

cdef NET_OPCODE_DB = {
    0x0: OpCode(name='nop'),
    0x1: OpCode(name='break'),
    0x2: OpCode(name='ldarg.0', nstack=1, astack=1),
    0x3: OpCode(name='ldarg.1', nstack=1, astack=1),
    0x4: OpCode(name='ldarg.2', nstack=1, astack=1),
    0x5: OpCode(name='ldarg.3', nstack=1, astack=1),
    0x6: OpCode(name='ldloc.0', nstack=1, astack=1),
    0x7: OpCode(name='ldloc.1', nstack=1, astack=1),
    0x8: OpCode(name='ldloc.2', nstack=1, astack=1),
    0x9: OpCode(name='ldloc.3', nstack=1, astack=1),
    0xA: OpCode(name="stloc.0", operand_count=0, nstack=-1, pstack=1),
    0xB: OpCode(name="stloc.1", operand_count=0, nstack=-1, pstack=1),
    0xC: OpCode(name="stloc.2", operand_count=0, nstack=-1, pstack=1),
    0xD: OpCode(name="stloc.3", operand_count=0, nstack=-1, pstack=1),
    0xE: OpCode(name="ldarg.s", operand_count=1, nstack=1, astack=1),
    0xF: OpCode(name="ldarga.s", operand_count=1, nstack=1, astack=1),
    0x10: OpCode(name="starg.s", operand_count=1, nstack=-1, pstack=1),
    0x11: OpCode(name="ldloc.s", operand_count=1, nstack=1, astack=1),
    0x12: OpCode(name="ldloca.s", operand_count=1, nstack=1, astack=1),
    0x13: OpCode(name="stloc.s", operand_count=1, nstack=-1, pstack=1),
    0x14: OpCode(name="ldnull", operand_count=0, nstack=1, astack=1),
    0x15: OpCode(name="ldc.i4.m1", operand_count=0, nstack=1, astack=1),
    0x16: OpCode(name="ldc.i4.0", operand_count=0, nstack=1, astack=1),
    0x17: OpCode(name="ldc.i4.1", operand_count=0, nstack=1, astack=1),
    0x18: OpCode(name="ldc.i4.2", operand_count=0, nstack=1, astack=1),
    0x19: OpCode(name="ldc.i4.3", operand_count=0, nstack=1, astack=1),
    0x1A: OpCode(name="ldc.i4.4", operand_count=0, nstack=1, astack=1),
    0x1B: OpCode(name="ldc.i4.5", operand_count=0, nstack=1, astack=1),
    0x1C: OpCode(name="ldc.i4.6", operand_count=0, nstack=1, astack=1),
    0x1D: OpCode(name="ldc.i4.7", operand_count=0, nstack=1, astack=1),
    0x1E: OpCode(name="ldc.i4.8", operand_count=0, nstack=1, astack=1),
    0x1F: OpCode(name="ldc.i4.s", operand_count=1, nstack=1, astack=1),
    0x20: OpCode(name="ldc.i4", operand_count=4, nstack=1, astack=1),
    0x21: OpCode(name="ldc.i8", operand_count=8, nstack=1, astack=1),
    0x22: OpCode(name="ldc.r4", operand_count=4, nstack=1, astack=1),
    0x23: OpCode(name="ldc.r8", operand_count=8, nstack=1, astack=1),
    0x25: OpCode(name="dup", operand_count=0, nstack=1, astack=2, pstack=1),
    0x26: OpCode(name="pop", operand_count=0, nstack=-1, pstack=1),
    0x27: OpCode(name="jmp", operand_count=4, has_token_argument=True),
    0x28: OpCode(name="call", operand_count=4, has_token_argument=True),
    0x29: OpCode(name="calli", operand_count=4),
    0x2A: OpCode(name="ret", operand_count=0),
    0x2B: OpCode(name="br.s", operand_count=1, is_branch=True),
    0x2C: OpCode(name="brfalse.s", operand_count=1, is_branch=True, nstack=-1, pstack=1),
    0x2D: OpCode(name="brtrue.s", operand_count=1, is_branch=True, nstack=-1, pstack=1),
    0x2E: OpCode(name="beq.s", operand_count=1, is_branch=True, nstack=-2, pstack=2),
    0x2F: OpCode(name="bge.s", operand_count=1, is_branch=True, nstack=-2, pstack=2),
    0x30: OpCode(name="bgt.s", operand_count=1, is_branch=True, nstack=-2, pstack=2),
    0x31: OpCode(name="ble.s", operand_count=1, is_branch=True, nstack=-2, pstack=2),
    0x32: OpCode(name="blt.s", operand_count=1, is_branch=True, nstack=-2, pstack=2),
    0x33: OpCode(name="bne.un.s", operand_count=1, is_branch=True, nstack=-2, pstack=2),
    0x34: OpCode(name="bge.un.s", operand_count=1, is_branch=True, nstack=-2, pstack=2),
    0x35: OpCode(name="bgt.un.s", operand_count=1, is_branch=True, nstack=-2, pstack=2),
    0x36: OpCode(name="ble.un.s", operand_count=1, is_branch=True, nstack=-2, pstack=2),
    0x37: OpCode(name="blt.un.s", operand_count=1, is_branch=True, nstack=-2),
    0x38: OpCode(name="br", operand_count=4, is_branch=True),
    0x39: OpCode(name="brfalse", operand_count=4, is_branch=True, nstack=-1, pstack=1),
    0x3A: OpCode(name="brtrue", operand_count=4, is_branch=True, nstack=-1, pstack=1),
    0x3B: OpCode(name="beq", operand_count=4, is_branch=True, nstack=-2, pstack=2),
    0x3C: OpCode(name="bge", operand_count=4, is_branch=True, nstack=-2, pstack=2),
    0x3D: OpCode(name="bgt", operand_count=4, is_branch=True, nstack=-2, pstack=2),
    0x3E: OpCode(name="ble", operand_count=4, is_branch=True, nstack=-2, pstack=2),
    0x3F: OpCode(name="blt", operand_count=4, is_branch=True, nstack=-2, pstack=2),
    0x40: OpCode(name="bne.un", operand_count=4, is_branch=True, nstack=-2, pstack=2),
    0x41: OpCode(name="bge.un", operand_count=4, is_branch=True, nstack=-2, pstack=2),
    0x42: OpCode(name="bgt.un", operand_count=4, is_branch=True, nstack=-2, pstack=2),
    0x43: OpCode(name="ble.un", operand_count=4, is_branch=True, nstack=-2, pstack=2),
    0x44: OpCode(name="blt.un", operand_count=4, is_branch=True, nstack=-2, pstack=2),
    0x45: OpCode(name="switch", operand_count=4, has_arg_list=True, nstack=-1, pstack=1),
    0x46: OpCode(name="ldind.i1", operand_count=0, astack=1, pstack=1),
    0x47: OpCode(name="ldind.u1", operand_count=0, astack=1, pstack=1),
    0x48: OpCode(name="ldind.i2", operand_count=0, astack=1, pstack=1),
    0x49: OpCode(name="ldind.u2", operand_count=0, astack=1, pstack=1),
    0x4A: OpCode(name="ldind.i4", operand_count=0, astack=1, pstack=1),
    0x4B: OpCode(name="ldind.u4", operand_count=0, astack=1, pstack=1),
    0x4C: OpCode(name="ldind.i8", operand_count=0, astack=1, pstack=1),
    0x4D: OpCode(name="ldind.i", operand_count=0, astack=1, pstack=1),
    0x4E: OpCode(name="ldind.r4", operand_count=0, astack=1, pstack=1),
    0x4F: OpCode(name="ldind.r8", operand_count=0, astack=1, pstack=1),
    0x50: OpCode(name="ldind.ref", operand_count=0, astack=1, pstack=1),
    0x51: OpCode(name="stind.ref", operand_count=0, nstack=-2, pstack=2),
    0x52: OpCode(name="stind.i1", operand_count=0, nstack=-2, pstack=2),
    0x53: OpCode(name="stind.i2", operand_count=0, nstack=-2, pstack=2),
    0x54: OpCode(name="stind.i4", operand_count=0, nstack=-2, pstack=2),
    0x55: OpCode(name="stind.i8", operand_count=0, nstack=-2, pstack=2),
    0x56: OpCode(name="stind.r4", operand_count=0, nstack=-2, pstack=2),
    0x57: OpCode(name="stind.r8", operand_count=0, nstack=-2, pstack=2),
    0x58: OpCode(name="add", operand_count=0, nstack=-1, astack=1, pstack=2),
    0x59: OpCode(name="sub", operand_count=0, nstack=-1, astack=1, pstack=2),
    0x5A: OpCode(name="mul", operand_count=0, nstack=-1, astack=1, pstack=2),
    0x5B: OpCode(name="div", operand_count=0, nstack=-1, astack=1, pstack=2),
    0x5C: OpCode(name="div.un", operand_count=0, nstack=-1, astack=1, pstack=2),
    0x5D: OpCode(name="rem", operand_count=0, nstack=-1, astack=1, pstack=2),
    0x5E: OpCode(name="rem.un", operand_count=0, nstack=-1, astack=1, pstack=2),
    0x5F: OpCode(name="and", operand_count=0, nstack=-1, astack=1, pstack=2),
    0x60: OpCode(name="or", operand_count=0, nstack=-1, astack=1, pstack=2),
    0x61: OpCode(name="xor", operand_count=0, nstack=-1, astack=1, pstack=2),
    0x62: OpCode(name="shl", operand_count=0, nstack=-1, astack=1, pstack=2),
    0x63: OpCode(name="shr", operand_count=0, nstack=-1, astack=1, pstack=2),
    0x64: OpCode(name="shr.un", operand_count=0, nstack=-1, astack=1, pstack=2),
    0x65: OpCode(name="neg", operand_count=0, pstack=1, astack=1),
    0x66: OpCode(name="not", operand_count=0, astack=1, pstack=1),
    0x67: OpCode(name="conv.i1", operand_count=0, astack=1, pstack=1),
    0x68: OpCode(name="conv.i2", operand_count=0, astack=1, pstack=1),
    0x69: OpCode(name="conv.i4", operand_count=0, astack=1, pstack=1),
    0x6A: OpCode(name="conv.i8", operand_count=0, astack=1, pstack=1),
    0x6B: OpCode(name="conv.r4", operand_count=0, astack=1, pstack=1),
    0x6C: OpCode(name="conv.r8", operand_count=0, astack=1, pstack=1),
    0x6D: OpCode(name="conv.u4", operand_count=0, astack=1, pstack=1),
    0x6E: OpCode(name="conv.u8", operand_count=0, astack=1, pstack=1),
    0x6F: OpCode(name="callvirt", operand_count=4, has_token_argument=True),
    0x70: OpCode(name="cpobj", operand_count=4, has_token_argument=True, nstack=-2, pstack=2),
    0x71: OpCode(name="ldobj", operand_count=4, has_token_argument=True, astack=1, pstack=1),
    0x72: OpCode(name="ldstr", operand_count=4, has_token_argument=True, nstack=1, astack=1),
    0x73: OpCode(name="newobj", operand_count=4, has_token_argument=True),
    0x74: OpCode(name="castclass", operand_count=4, has_token_argument=True, astack=1, pstack=1),
    0x75: OpCode(name="isinst", operand_count=4, has_token_argument=True, astack=1, pstack=1),
    0x76: OpCode(name="conv.r.un", operand_count=0, astack=1, pstack=1),
    0x79: OpCode(name="unbox", operand_count=4, has_token_argument=True, astack=1, pstack=1),
    0x7A: OpCode(name="throw", operand_count=0, nstack=-1, pstack=1),
    0x7B: OpCode(name="ldfld", operand_count=4, has_token_argument=True, astack=1, pstack=1),
    0x7C: OpCode(name="ldflda", operand_count=4, has_token_argument=True, astack=1, pstack=1),
    0x7D: OpCode(name="stfld", operand_count=4, has_token_argument=True, nstack=-2, pstack=2),
    0x7E: OpCode(name="ldsfld", operand_count=4, has_token_argument=True, nstack=1, astack=1),
    0x7F: OpCode(name="ldsflda", operand_count=4, has_token_argument=True, nstack=1, astack=1),
    0x80: OpCode(name="stsfld", operand_count=4, has_token_argument=True, nstack=-1, pstack=1),
    0x81: OpCode(name="stobj", operand_count=4, has_token_argument=True, nstack=-2, pstack=2),
    0x82: OpCode(name="conv.ovf.i1.un", operand_count=0, astack=1, pstack=1),
    0x83: OpCode(name="conv.ovf.i2.un", operand_count=0, astack=1, pstack=1),
    0x84: OpCode(name="conv.ovf.i4.un", operand_count=0, astack=1, pstack=1),
    0x85: OpCode(name="conv.ovf.i8.un", operand_count=0, astack=1, pstack=1),
    0x86: OpCode(name="conv.ovf.u1.un", operand_count=0, astack=1, pstack=1),
    0x87: OpCode(name="conv.ovf.u2.un", operand_count=0, astack=1, pstack=1),
    0x88: OpCode(name="conv.ovf.u4.un", operand_count=0, astack=1, pstack=1),
    0x89: OpCode(name="conv.ovf.u8.un", operand_count=0, astack=1, pstack=1),
    0x8A: OpCode(name="conv.ovf.i.un", operand_count=0, astack=1, pstack=1),
    0x8B: OpCode(name="conv.ovf.u.un", operand_count=0, astack=1, pstack=1),
    0x8C: OpCode(name="box", operand_count=4, has_token_argument=True, astack=1, pstack=1),
    0x8D: OpCode(name="newarr", operand_count=4, has_token_argument=True, astack=1, pstack=1),
    0x8E: OpCode(name="ldlen", operand_count=0, nstack=1, astack=1),
    0x8F: OpCode(name="ldelema", operand_count=4, has_token_argument=True, nstack=-1),
    0x90: OpCode(name="ldelem.i1", operand_count=0, nstack=-1, astack=1, pstack=2),
    0x91: OpCode(name="ldelem.u1", operand_count=0, nstack=-1, astack=1, pstack=2),
    0x92: OpCode(name="ldelem.i2", operand_count=0, nstack=-1, astack=1, pstack=2),
    0x93: OpCode(name="ldelem.u2", operand_count=0, nstack=-1, astack=1, pstack=2),
    0x94: OpCode(name="ldelem.i4", operand_count=0, nstack=-1, astack=1, pstack=2),
    0x95: OpCode(name="ldelem.u4", operand_count=0, nstack=-1, astack=1, pstack=2),
    0x96: OpCode(name="ldelem.i8", operand_count=0, nstack=-1, astack=1, pstack=2),
    0x97: OpCode(name="ldelem.i", operand_count=0, nstack=-1, astack=1, pstack=2),
    0x98: OpCode(name="ldelem.r4", operand_count=0, nstack=-1, astack=1, pstack=2),
    0x99: OpCode(name="ldelem.r8", operand_count=0, nstack=-1, astack=1, pstack=2),
    0x9A: OpCode(name="ldelem.ref", operand_count=0, nstack=-1, astack=1, pstack=2),
    0x9B: OpCode(name="stelem.i", operand_count=0, nstack=-3, pstack=3),
    0x9C: OpCode(name="stelem.i1", operand_count=0, nstack=-3, pstack=3),
    0x9D: OpCode(name="stelem.i2", operand_count=0, nstack=-3, pstack=3),
    0x9E: OpCode(name="stelem.i4", operand_count=0, nstack=-3, pstack=3),
    0x9F: OpCode(name="stelem.i8", operand_count=0, nstack=-3, pstack=3),
    0xA0: OpCode(name="stelem.r4", operand_count=0, nstack=-3, pstack=3),
    0xA1: OpCode(name="stelem.r8", operand_count=0, nstack=-3, pstack=3),
    0xA2: OpCode(name="stelem.ref", operand_count=0, nstack=-3, pstack=3),
    0xA3: OpCode(name="ldelem", operand_count=4, has_token_argument=True, nstack=-1, astack=1, pstack=2),
    0xA4: OpCode(name="stelem", operand_count=4, has_token_argument=True, nstack=-3, pstack=3),
    0xA5: OpCode(name="unbox.any", operand_count=4, has_token_argument=True, astack=1, pstack=1),
    0xB3: OpCode(name="conv.ovf.i1", operand_count=0, astack=1, pstack=1),
    0xB4: OpCode(name="conv.ovf.u1", operand_count=0, astack=1, pstack=1),
    0xB5: OpCode(name="conv.ovf.i2", operand_count=0, astack=1, pstack=1),
    0xB6: OpCode(name="conv.ovf.u2", operand_count=0, astack=1, pstack=1),
    0xB7: OpCode(name="conv.ovf.i4", operand_count=0, astack=1, pstack=1),
    0xB8: OpCode(name="conv.ovf.u4", operand_count=0, astack=1, pstack=1),
    0xB9: OpCode(name="conv.ovf.i8", operand_count=0, astack=1, pstack=1),
    0xBA: OpCode(name="conv.ovf.u8", operand_count=0, astack=1, pstack=1),
    0xC2: OpCode(name="refanyval", operand_count=4, has_token_argument=True, astack=1, pstack=1),
    0xC3: OpCode(name="ckfinite", operand_count=0, astack=1, pstack=1),
    0xC6: OpCode(name="mkrefany", operand_count=4, has_token_argument=True, astack=1, pstack=1),
    0xD0: OpCode(name="ldtoken", operand_count=4, has_token_argument=True, nstack=1, astack=1),
    0xD1: OpCode(name="conv.u2", operand_count=0, astack=1, pstack=1),
    0xD2: OpCode(name="conv.u1", operand_count=0, astack=1, pstack=1),
    0xD3: OpCode(name="conv.i", operand_count=0, astack=1, pstack=1),
    0xD4: OpCode(name="conv.ovf.i", operand_count=0, astack=1, pstack=1),
    0xD5: OpCode(name="conv.ovf.u", operand_count=0, astack=1, pstack=1),
    0xD6: OpCode(name="add.ovf", operand_count=0, nstack=-1, astack=1, pstack=2),
    0xD7: OpCode(name="add.ovf.un", operand_count=0, nstack=-1, astack=1, pstack=2),
    0xD8: OpCode(name="mul.ovf", operand_count=0, nstack=-1, astack=1, pstack=2),
    0xD9: OpCode(name="mul.ovf.un", operand_count=0, nstack=-1, astack=1, pstack=2),
    0xDA: OpCode(name="sub.ovf", operand_count=0, nstack=-1, astack=1, pstack=2),
    0xDB: OpCode(name="sub.ovf.un", operand_count=0, nstack=-1, astack=1, pstack=2),
    0xDC: OpCode(name="endfinally", operand_count=0),
    0xDD: OpCode(name="leave", operand_count=4, is_branch=True),
    0xDE: OpCode(name="leave.s", operand_count=1, is_branch=True),
    0xDF: OpCode(name="stind.i", operand_count=0, nstack=-2, pstack=2),
    0xE0: OpCode(name="conv.u", operand_count=0, astack=1, pstack=2),
    0xFE00: OpCode(name="arglist", operand_count=0, is_two_byte_opcode=True),
    0xFE01: OpCode(name="ceq", operand_count=0, is_two_byte_opcode=True, nstack=-1, astack=1, pstack=2),
    0xFE02: OpCode(name="cgt", operand_count=0, is_two_byte_opcode=True, nstack=-1, astack=1, pstack=2),
    0xFE03: OpCode(name="cgt.un", operand_count=0, is_two_byte_opcode=True, nstack=-1, astack=1, pstack=2),
    0xFE04: OpCode(name="clt", operand_count=0, is_two_byte_opcode=True, nstack=-1, astack=1, pstack=2),
    0xFE05: OpCode(name="clt.un", operand_count=0, is_two_byte_opcode=True, nstack=-1, astack=1, pstack=2),
    0xFE16: OpCode(name="constrained.", operand_count=4, has_token_argument=True, is_two_byte_opcode=True),
    0xFE17: OpCode(name="cpblk", operand_count=0, is_two_byte_opcode=True, nstack=-3, pstack=3),
    0xFE11: OpCode(name="endfilter", operand_count=0, is_two_byte_opcode=True),
    0xFE18: OpCode(name="initblk", operand_count=0, is_two_byte_opcode=True, nstack=-3, pstack=3),
    0xFE15: OpCode(name="initobj", operand_count=4, has_token_argument=True, is_two_byte_opcode=True, nstack=-1, pstack=1),
    0xFE09: OpCode(name="ldarg", operand_count=2, is_two_byte_opcode=True, nstack=1, astack=1),
    0xFE0A: OpCode(name="ldarga", operand_count=2, is_two_byte_opcode=True, nstack=1, astack=1),
    0xFE06: OpCode(name="ldftn", operand_count=4, has_token_argument=True, is_two_byte_opcode=True, nstack=1, astack=1),
    0xFE0C: OpCode(name="ldloc", operand_count=2, is_two_byte_opcode=True, nstack=1, astack=1),
    0xFE0D: OpCode(name="ldloca", operand_count=2, is_two_byte_opcode=True, nstack=1, astack=1),
    0xFE07: OpCode(name="ldvirtftn", operand_count=4, has_token_argument=True, is_two_byte_opcode=True, nstack=1, astack=1),
    0xFE0F: OpCode(name="localloc", operand_count=0, is_two_byte_opcode=True, astack=1, pstack=1),
    0xFE19: OpCode(name="no.", operand_count=1, is_two_byte_opcode=True),
    0xFE1E: OpCode(name="readonly.", operand_count=0, is_two_byte_opcode=True),
    0xFE1D: OpCode(name="Refanytype", operand_count=0, is_two_byte_opcode=True, astack=1, pstack=1),
    0xFE1A: OpCode(name="rethrow", operand_count=0, is_two_byte_opcode=True),
    0xFE1C: OpCode(name="sizeof", operand_count=4, has_token_argument=True, is_two_byte_opcode=True, nstack=1, astack=11),
    0xFE0B: OpCode(name="starg", operand_count=2, is_two_byte_opcode=True, nstack=-1, pstack=1),
    0xFE0E: OpCode(name="stloc", operand_count=2, is_two_byte_opcode=True, nstack=-1, pstack=1),
    0xFE14: OpCode(name="tail.", operand_count=0, is_two_byte_opcode=True),
    0xFE12: OpCode(name="unaligned.", operand_count=1, is_two_byte_opcode=True),
    0xFE13: OpCode(name="volatile.", operand_count=0, is_two_byte_opcode=True)
}
#initialize the opcodes
cdef int op_num
cdef OpCode op_val
for op_num, op_val in NET_OPCODE_DB.items():
    op_val.set_opcode(op_num)