#cython: language_level=3
#distutils: language=c++

import io
from dotnetutils import net_exceptions
from dotnetutils cimport net_row_objects, dotnetpefile, net_opcodes, net_tokens, net_structs, net_utils, net_table_objects
from cpython.ref cimport PyObject, Py_INCREF

from cython.operator cimport dereference
from libcpp.utility cimport pair


cpdef get_total_method_size(data):
    """
    Parse the .NET method header
    :param data: The data of the method
    :return: total size of the method (header + code)
    """
    cdef net_structs.DotNetDataReader reader
    cdef int start
    cdef int val
    cdef unsigned long header_size
    cdef unsigned long code_size
    cdef int flags
    cdef unsigned long extra_sect_offset
    cdef unsigned long amt_to_add
    cdef net_structs.CorILMethod sect_flags
    cdef int data_size

    reader = net_structs.DotNetDataReader(data)
    start = reader.read_byte()
    val = start & 7
    header_size = 0
    code_size = 0
    if val == 2 or val == 6:
        header_size = 1
        code_size = (start >> 2)
    else:
        flags = ((reader.read_byte() << 8) | start) & 0xFFFF
        header_size = (flags >> 12)
        reader.read_uint16() # skip max stack
        code_size = reader.read_uint32()
        header_size *= 4
        if flags & net_structs.CorILMethod.MoreSects:
            extra_sect_offset = header_size + code_size
            #align to next 4 byte boundry - TODO: Will method offset always be aligned to 4?
            if extra_sect_offset % 4 != 0:
                amt_to_add = 4 - (extra_sect_offset % 4)
                extra_sect_offset += amt_to_add
            while True:
                reader.seek(extra_sect_offset, io.SEEK_SET)
                sect_flags = <net_structs.CorILMethod>reader.read_byte()
                extra_sect_offset += 1
                
                 #Make sure we're parsing exception information here, otherwise we need to support different things.
                if sect_flags & net_structs.CorILMethod.Sect_EHTable == 0:
                    raise net_exceptions.InvalidHeaderException
                
                if sect_flags & net_structs.CorILMethod.Sect_FatFormat == 0: #This takes care of tiny headers
                    data_size = reader.read_byte()
                    extra_sect_offset += 1
                    extra_sect_offset += 2 # Reserved padding, always zero.
                    extra_sect_offset += (data_size - 4) # that takes care of this data section.
                else: # fat headers
                    data_size = int.from_bytes(reader.read(3), 'little')
                    extra_sect_offset += 3
                    extra_sect_offset += (data_size - 4)
                
                if sect_flags & net_structs.CorILMethod.Sect_MoreSects == 0:
                    break
            return extra_sect_offset

    return header_size + code_size


cdef class Instruction:

    def __init__(self, net_opcodes.OpCode opcode_one, MethodDisassembler disasm_obj, unsigned int offset=0, unsigned int instr_index=<unsigned int>-1):
        """
        Represents a full instruction, including the arguments.
        :param opcode_one: The first opcode in the instruction
        :param opcode_two: The second opcode in the instruction
        :param offset: The 0 index offset of the instruction in the method.
        """
        self.opcode_one = opcode_one
        self.instr_size = -1
        self.arguments = b''
        self.offset = offset
        self.__saved_argument = None
        self.__disasm_obj = disasm_obj
        self.instr_index = instr_index

    cpdef int get_instr_size(self):
        """
        Obtain the size in bytes of a instruction (same as len())
        """
        if self.instr_size == -1:
            raise Exception('instruction size not initialized')
        return self.instr_size

    cpdef unsigned int get_instr_index(self):
        """
        Obtain the index of an instruction within a method body.
        """
        return self.instr_index

    cpdef unsigned int get_instr_offset(self):
        """
        Obtain the byte offset from the start of the method's code of an instruction.
        """
        return self.offset

    cdef void add_argument(self, int argument):
        """
        Add an argument to an instruction
        :param argument: The byte argument to add
        :return: None
        """
        self.arguments += bytes([argument])
        self.__saved_argument = None #Reset saved argument for this.

    cdef void __set_arguments(self, bytes arguments):
        self.arguments = arguments

    cpdef str get_name(self):
        """
        Get the name of an instruction's opcode.
        :return: the name representing the instruction.
        """
        return self.opcode_one.get_name()

    cpdef bint is_twobyte_opcode(self):
        """
        Returns True if the opcode is represented by two bytes instead of one.
        """
        return self.opcode_one.is_two_byte_opcode()

    cpdef net_opcodes.Opcodes get_opcode(self):
        """
        Obtains the OpCode representing the instruction.
        """
        return self.opcode_one.obtain_opcode()

    cpdef object get_argument(self):
        """
        Obtain a DotNetUtils representation of an instruction's argument.
        """
        cdef bytes instr_args
        cdef str name
        cdef list args
        cdef unsigned long token
        cdef list offsets_list
        cdef int current
        try:
            if self.__saved_argument is None:
                instr_args = self.get_arguments()
                if len(instr_args) == 0:
                    name = self.get_name()
                    if '.' in name:
                        args = name.split('.')
                        if args[-1].isdigit():
                            self.__saved_argument = int(args[-1])
                            return self.__saved_argument
                        elif args[-1] == 'm1':
                            self.__saved_argument = -1
                            return self.__saved_argument

                    self.__saved_argument = None
                    return self.__saved_argument
                elif self.get_opcode() != net_opcodes.Opcodes.Switch:
                    if self.has_token_argument():
                        token = int.from_bytes(instr_args, 'little', signed=False)
                        self.__saved_argument = self.__disasm_obj.get_dotnetpe().get_token_value(token)
                        return self.__saved_argument
                    else:
                        if self.is_argument_signed():
                            self.__saved_argument = int.from_bytes(instr_args, 'little', signed=True)
                            return self.__saved_argument
                        else:
                            self.__saved_argument = int.from_bytes(instr_args, 'little', signed=False)
                            return self.__saved_argument
                else:
                    # from start of code
                    offsets_list = list()
                    current = 4
                    while current < len(instr_args):
                        offsets_list.append(
                            self.get_instr_offset() + len(self) + int.from_bytes(instr_args[current:current + 4], 'little',
                                                                    signed=True))
                        current += 4
                    self.__saved_argument = offsets_list
                    return self.__saved_argument

            return self.__saved_argument
        except Exception as e:
            raise e

    cpdef bytes get_arguments(self):
        """
        Obtain the array of raw bytes that represents an instruction's arguments.
        """
        return self.arguments

    cdef void setup_instr_size(self, int instr_size):
        """
        Internal method for setting an instructions size.
        Likely to be removed.
        :param instr_size: The size of an instruction
        :return:
        """
        self.instr_size = instr_size

    def __str__(self):
        """
        :return: A string representing the instruction
        """
        result = self.get_name()
        for argument in self.get_arguments():
            result += ' '
            result += hex(argument)
        return result

    def __len__(self):
        """
        :return: The full length of the instruction
        """
        cdef int args_len
        if self.instr_size != -1:
            return self.instr_size
        args_len = 0
        if self.get_opcode() == net_opcodes.Opcodes.Switch:
            args_len += (int.from_bytes(self.get_arguments(), 'little', signed=False) * 4)
        if self.is_two_byte_opcode():
            return 2 + args_len + self.opcode_one.get_operand_count()
        return 1 + args_len + self.opcode_one.get_operand_count()

    cpdef bytes get_bytes(self):
        """
        :return: The bytes representing the instruction.
        """
        cdef bytes result
        result = None
        if self.opcode_one.is_two_byte_opcode():
            result = int.to_bytes(self.opcode_one.obtain_opcode(), 2, 'big')
        else:
            result = bytes([self.opcode_one.obtain_opcode()])
        result += bytes(self.get_arguments())
        return result
    
    cpdef bytes to_bytes(self): # For compatibility reasons.
        return self.get_bytes()

    cpdef bint has_token_argument(self):
        """
        Does the instruction have a token as an argument?
        :return: True if the instruction has a token as an argument, false otherwise.
        """
        return self.opcode_one.is_token_argument_opcode()

    cpdef bint is_branch(self):
        """
        Does the instruction represent a branch?
        """
        if self.get_opcode() == net_opcodes.Opcodes.Switch:
            return True
        return self.opcode_one.is_branch_opcode()

    cpdef bint is_argument_signed(self):
        """
        Returns true if the operand for the instruction is expected to be signed.
        """
        if self.has_token_argument():
            return True

        return self.opcode_one.opcode_argument_signed()

    cpdef bint is_absolute_jmp(self):
        """
        Does the instruction represent an absolute jump (br or br.s)
        """
        return self.get_name() == 'br' or self.get_name() == 'br.s'


cdef class MethodDisassembler:

    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, object method, bytes force_data=None):
        """
        Represents a method
        :param streams: The .NET streams object corresponding to the binary
        :param data: The data from the start of the method to the end of the binary
        """
        self.dotnetpe = dotnetpe
        self.method_obj = method
        if not force_data:
            self.__reader: net_structs.DotNetDataReader = net_structs.DotNetDataReader(self.method_obj.get_method_data())
            self.disassemble_loop()
        else:
            self.__reader: net_structs.DotNetDataReader = net_structs.DotNetDataReader(force_data)
            self.disassemble_loop()

    cpdef object get_method(self):
        """
        Obtain the method object being disassembled.
        """
        return self.method_obj

    cpdef dotnetpefile.DotNetPeFile get_dotnetpe(self):
        """
        Obtain the Assembly's DotNetPeFile object.
        """
        return self.dotnetpe

    cpdef list get_list_of_instrs(self):
        """
        Obtains a list of instructions.  The instructions will be in order of instruction index.
        """
        cdef list result = list()
        cdef unsigned int i = 0
        for i in range(self.instrs.size()):
            result.append(<Instruction>self.instrs.at(i))
        return result

    cpdef tuple get_arg_token_properties(self, Instruction instr):
        """
        Obtains a instruction argument token's rid and table name.
        """
        cdef bytes instr_args
        cdef int token
        instr_args = instr.get_arguments()
        if len(instr_args) != 0:
            if instr.get_opcode() != net_opcodes.Opcodes.Switch:
                token = int.from_bytes(instr_args, 'little')
                if instr.has_token_argument():
                    try:
                        return net_tokens.get_Signature().decode_token(token)
                    except net_exceptions.InvalidTokenException:
                        pass
        return None, None

    cpdef int get_header_size(self):
        """
        Obtain the size of the beginning header in the method.
        """
        return self.header_size

    cpdef int get_code_size(self):
        """
        Obtain the size of the code in bytes for a method.
        """
        return self.code_size

    cdef void parse_header(self):
        """
        Parse the .NET method header
        :param data: The data of the method
        :return: None
        """
        cdef int start
        cdef int val
        cdef net_table_objects.TableObject signature_table
        cdef net_row_objects.RowObject signature_entry
        cdef bytes blob_value
        cdef net_utils.SignatureReader sig_reader
        cdef net_utils.LocalSig local_sig
        cdef int extra_sect_offset
        cdef int amt_to_add
        cdef int sect_flags
        cdef int data_size
        cdef int num_clauses
        start = self.__reader.read_byte()
        val = start & 7
        import binascii
        if val == 2 or val == 6:
            self.flags = 0
            self.header_size = 1
            self.code_size = (start >> 2)
            self.max_stack = 8
            self.local_var_sig_tok = 0
            self.local_types = list()
            self.exception_blocks = list() #Small headers cant have exceptions.
        else:
            self.flags = ((self.__reader.read_byte() << 8) | start)
            self.header_size = (self.flags >> 12)
            self.max_stack = self.__reader.read_uint16()
            self.code_size = self.__reader.read_uint32()
            self.local_var_sig_tok = self.__reader.read_uint32()
            if self.header_size < 3:
                self.flags &= 0xFFF7
            self.header_size *= 4
            if self.local_var_sig_tok > 0:
                signature_table = self.dotnetpe.get_metadata_table('StandAloneSig')
                if self.local_var_sig_tok & 0x11000000:
                    try:
                        self.local_var_sig_tok = net_tokens.get_Signature().decode_token(self.local_var_sig_tok)[1]
                    except net_exceptions.InvalidTokenException:
                        self.local_var_sig_tok = 0
                if self.local_var_sig_tok != 0:
                    signature_entry = signature_table.get(self.local_var_sig_tok)
                    if signature_entry:
                        blob_value = signature_entry.get_column('Signature').get_value()
                        if blob_value[0] != net_structs.CorCallingConvention.LocalSig:
                            raise net_exceptions.InvalidHeaderException
                        sig_reader = net_utils.SignatureReader(self.dotnetpe, blob_value)
                        local_sig = sig_reader.read_signature()
                        self.local_types = local_sig.get_local_vars()
                    else:
                        self.local_types = list()
                else:
                    self.local_types = list()
            else:
                self.local_types = list()

            self.exception_blocks = list()

            #parse exception data
            if self.flags & net_structs.CorILMethod.MoreSects:
                extra_sect_offset = self.header_size + self.code_size
                #align to next 4 byte boundry - TODO: Will method offset always be aligned to 4?
                if extra_sect_offset % 4 != 0:
                    amt_to_add = 4 - (extra_sect_offset % 4)
                    extra_sect_offset += amt_to_add
                while True:
                    self.__reader.seek(extra_sect_offset, io.SEEK_SET)
                    sect_flags = self.__reader.read_byte()
                    extra_sect_offset += 1
                    
                    #Make sure we're parsing exception information here, otherwise we need to support different things.
                    if sect_flags & net_structs.CorILMethod.Sect_EHTable == 0:
                        raise net_exceptions.InvalidHeaderException
                    
                    if sect_flags & net_structs.CorILMethod.Sect_FatFormat == 0: #This takes care of tiny headers
                        data_size = self.__reader.read_byte()
                        extra_sect_offset += 1
                        extra_sect_offset += 2 # Reserved padding, always zero.
                        self.__reader.seek(extra_sect_offset, io.SEEK_SET)
                        num_clauses = (data_size - 4) // 12
                        for _ in range(num_clauses):
                            clause_flags = self.__reader.read_uint16()
                            extra_sect_offset += 2
                            try_offset = self.__reader.read_uint16()
                            extra_sect_offset += 2
                            try_length = self.__reader.read_byte()
                            extra_sect_offset += 1
                            handler_offset = self.__reader.read_uint16()
                            extra_sect_offset += 2
                            handler_length = self.__reader.read_byte()
                            extra_sect_offset += 1
                            class_token = self.__reader.read_uint32()
                            extra_sect_offset += 4
                            self.exception_blocks.append((clause_flags, try_offset, try_length, handler_offset, handler_length, class_token))
                    else: # fat headers
                        data_size = int.from_bytes(self.__reader.read(3), 'little')
                        extra_sect_offset += 3
                        num_clauses = (data_size - 4) // 24
                        self.__reader.seek(extra_sect_offset, io.SEEK_SET)
                        for _ in range(num_clauses):
                            clause_flags = self.__reader.read_uint32()
                            extra_sect_offset += 4
                            try_offset = self.__reader.read_uint32()
                            extra_sect_offset += 4
                            try_length = self.__reader.read_uint32()
                            extra_sect_offset += 4
                            handler_offset = self.__reader.read_uint32()
                            extra_sect_offset += 4
                            handler_length = self.__reader.read_uint32()
                            extra_sect_offset += 4
                            class_token = self.__reader.read_uint32()
                            extra_sect_offset += 4
                            self.exception_blocks.append((clause_flags, try_offset, try_length, handler_offset, handler_length, class_token))
                    
                    if sect_flags & net_structs.CorILMethod.Sect_MoreSects == 0:
                        break

    cdef void disassemble_loop(self):
        """
        Disassemble the instructions in the method
        :param data: the method's data
        :return: A list of instructions, otherwise InvalidAssemblyException
        """
        cdef int index = 0
        cdef int instr_index = 0
        cdef int orig_index
        cdef int opcode_one
        cdef net_opcodes.OpCode usable_opcode
        cdef int opcode_two
        cdef int full_opcode
        cdef Instruction instr
        cdef bytes instr_args
        cdef int amt_of_extra
        cdef int x
        index = 0
        instr_index = 0
        try:
            self.parse_header()
            if self.header_size == 0 or self.code_size == 0:
                raise net_exceptions.InvalidHeaderException(self.method_obj.get_token())

            self.__reader.seek(self.header_size, io.SEEK_SET)
            while index < self.code_size:
                orig_index = index
                opcode_one = self.__reader.read_byte()
                index += 1
                usable_opcode = None
                if opcode_one not in net_opcodes.NET_OPCODE_DB.keys():
                    opcode_two = self.__reader.read_byte()
                    full_opcode = int.from_bytes(bytes([opcode_one, opcode_two]), 'big')
                    if full_opcode not in net_opcodes.NET_OPCODE_DB.keys():
                        raise net_exceptions.InvalidAssemblyException()
                    else:
                        usable_opcode = net_opcodes.NET_OPCODE_DB[full_opcode]
                        index += 1
                else:
                    usable_opcode = net_opcodes.NET_OPCODE_DB[opcode_one]

                if usable_opcode is None:
                    raise net_exceptions.OpcodeLookupException

                if usable_opcode.get_operand_count() == 0:
                    instr = Instruction(usable_opcode, self, offset=orig_index, instr_index=instr_index)
                else:
                    instr = Instruction(usable_opcode, self, offset=orig_index, instr_index=instr_index)
                    for x in range(index, index + usable_opcode.get_operand_count()):
                        instr.add_argument(self.__reader.read_single_byte())
                        index += 1
                    # handle switch statements

                    if instr.get_opcode() == net_opcodes.Opcodes.Switch:
                        instr_args = instr.get_arguments()
                        amt_of_extra = int.from_bytes(bytes(instr_args), 'little', signed=False) * 4
                        for x in range(index, index + amt_of_extra):
                            instr.add_argument(self.__reader.read_single_byte())
                            index += 1


                instr.setup_instr_size(index - orig_index)
                Py_INCREF(instr)
                self.offsets[orig_index] = instr_index
                self.instrs.push_back(<PyObject*>instr)
                instr_index += 1
        except Exception as e:
            raise e
            #raise net_exceptions.InvalidAssemblyException()

    def __iter__(self):
        return iter(self.get_list_of_instrs())

    def __len__(self):
        return self.instrs.size()

    def __getitem__(self, Py_ssize_t item):
        """
        Obtain an instruction in the method by its INDEX.
        """
        cdef Instruction result = <Instruction>self.instrs.at(item)
        return result

    cpdef Instruction get_instr_at_offset(self, int offset):
        """
        Obtain an instruction in the method by its offset within the method's code.
        """
        cdef pair[int, int] res = dereference(self.offsets.find(offset))
        cdef Instruction result = <Instruction>self.instrs.at(res.second)
        return <Instruction>result

    cpdef int get_instr_offset(self, int instr_index):
        """
        Obtain the offset of instruction at index instr_index.
        """
        cdef Instruction instr = <Instruction>self.instrs.at(instr_index)
        return instr.get_instr_offset()

    cpdef unsigned int get_instr_index_by_offset(self, unsigned int instr_offset):
        """
        Obtain the index of the instruction at offset instr_offset.
        """
        cdef pair[int, int] res = dereference(self.offsets.find(instr_offset))
        return res.second

    cpdef Instruction get_instr_at_index(self, int index):
        """
        Obtains an Instruction at a specified index.
        """
        cdef Instruction result = <Instruction>self.instrs.at(index)
        return result
