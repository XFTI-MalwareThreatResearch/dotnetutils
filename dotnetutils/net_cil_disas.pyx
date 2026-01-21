#cython: language_level=3
#distutils: language=c++

import io
from dotnetutils import net_exceptions
from dotnetutils cimport net_row_objects, dotnetpefile, net_opcodes, net_tokens, net_structs, net_sigs, net_table_objects
from cpython.ref cimport PyObject, Py_INCREF, Py_XDECREF
from libc.stdint cimport uint16_t, uint32_t, int64_t
from libc.string cimport memcpy
from cpython.bytes cimport PyBytes_FromStringAndSize, PyBytes_AS_STRING

from cython.operator cimport dereference
from libcpp.utility cimport pair


cpdef unsigned long get_total_method_size(bytes data):
    """ Calculates the total size, including headers of a .NET managed method.

    Args:
        data (bytes): The method's data.  The data may strech beyond the length of the method itself.

    Returns:
        unsigned long: The calculated size of the method, including headers.
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
    val = start & 3
    header_size = 0
    code_size = 0
    if val == 2:
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
    """ Represents a .NET CIL instruction.

    Notes:
        opcode_one (net_opcodes.OpCode): the instruction's first OpCode.
        instr_size (int): The calculated size in bytes of the instruction.
        arguments (bytes): A byte representation of the instruction's arguments.
        offset (unsigned int): The code offset of the instruction.
        __saved_argument (object): A saved representation of the Instruction's argument.
        __disasm_obj (net_cil_disas.MethodDisassembler): A reference to the MethodDisassembler that produced the instruction.
        instr_index (unsigned int): The instruction index within the code of the instruction.

    Returns:
        list[net_row_objects.TypeDef]: A list containing all TypeDef objects that match name.
    """

    def __init__(self, net_opcodes.OpCode opcode_one, MethodDisassembler disasm_obj, unsigned int offset, unsigned int instr_index):
        """ Create a new Instruction object.

        Args:
            opcode_one (net_opcodes.OpCode): the instruction's first OpCode.
            disasm_obj (net_cil_disas.MethodDisassembler): The disassembler object that produced the instruction.
            offset (unsigned int): The code offset of the instruction.
            instr_index (unsigned int): The instruction index within the code of the instruction.

        Returns:
            net_cil_disas.Instruction: An Instruction object.
        """
        self.opcode_one = opcode_one
        self.instr_size = -1
        self.arguments = b''
        self.offset = offset
        self.__saved_argument = None
        self.__disasm_obj = disasm_obj
        self.instr_index = instr_index

    cpdef Instruction duplicate(self):
        cdef Instruction new_instr = Instruction(self.opcode_one, self.__disasm_obj, self.offset, self.instr_index)
        new_instr.arguments = self.arguments
        new_instr.instr_size = self.instr_size
        return new_instr

    cpdef int get_nstack(self):
        """ Returns the number of stack items that the instruction will add or remove to the stack.

        Returns:
            int: the number of items added or removed from the stack by the instruction.
        """

        cdef int result = 0
        cdef net_row_objects.MethodDefOrRef mref = None
        cdef net_opcodes.Opcodes opcode = self.get_opcode()
        if opcode == net_opcodes.Opcodes.Call or opcode == net_opcodes.Opcodes.Callvirt:
            mref = self.get_argument()
            result = <int>len(mref.get_param_types())
            result *= -1
            if mref.method_has_this():
                result -= 1

            if mref.has_return_value():
                result += 1
        elif opcode == net_opcodes.Opcodes.Ret:
            mref = self.__disasm_obj.get_method()
            if mref.has_return_value():
                result = -1
        elif opcode == net_opcodes.Opcodes.Newobj:
            mref = self.get_argument()
            result = <int>len(mref.get_param_types())
            result *= -1
            result += 1
        else:
            result = self.opcode_one.get_nstack()
        return result

    cpdef int get_astack(self):
        """ Returns the number of stack items that the instruction will add to the stack.

        Returns:
            int: the number of items added to the stack by the instruction.
        """

        cdef int result = 0
        cdef net_row_objects.MethodDefOrRef mref = None
        cdef net_opcodes.Opcodes opcode = self.get_opcode()
        if opcode == net_opcodes.Opcodes.Call or opcode == net_opcodes.Opcodes.Callvirt:
            mref = self.get_argument()
            if mref.has_return_value():
                result += 1
        elif opcode == net_opcodes.Opcodes.Newobj:
            result += 1
        else:
            result = self.opcode_one.get_astack()
        return result

    cpdef int get_pstack(self):
        """ Returns the number of stack items that the instruction will pop from the stack.

        Returns:
            int: the number of items popped from the stack by the instruction.
        """

        cdef int result = 0
        cdef net_row_objects.MethodDefOrRef mref = None
        cdef net_opcodes.Opcodes opcode = self.get_opcode()
        if opcode == net_opcodes.Opcodes.Call or opcode == net_opcodes.Opcodes.Callvirt:
            mref = self.get_argument()
            result = <int>len(mref.get_param_types())
            if mref.method_has_this():
                result += 1

        elif opcode == net_opcodes.Opcodes.Ret:
            mref = self.__disasm_obj.get_method()
            if mref.has_return_value():
                result = 1
        elif opcode == net_opcodes.Opcodes.Newobj:
            mref = self.get_argument()
            result = <int>len(mref.get_param_types())
        else:
            result = self.opcode_one.get_pstack()
        return result

    cpdef int get_instr_size(self):
        """ Obtain the size of the instruction.

        Returns:
            int: The size in bytes of the instruction.

        Raises:
            net_exceptions.InvalidArgumentsException: If instruction size has not been initialized.  An internal error indicating an issue with DotNetUtils.
        """
        if self.instr_size == -1:
            raise net_exceptions.InvalidArgumentsException()
        return self.instr_size

    cpdef void setup_instr_offset(self, unsigned int instr_offset, unsigned int instr_index):
        """
        Internal method, may be removed later.
        Used to change the instruction's offset and index (mostly used in the disassembler, and control flow deob.)
        """
        self.offset = instr_offset
        self.instr_index = instr_index

    cpdef unsigned int get_instr_index(self):
        """ Obtains the index of an instruction.

        Returns:
            unsigned int: The index of the instruction.
        """
        return self.instr_index

    cpdef unsigned int get_instr_offset(self):
        """ Obtains the code offset of an instruction.

        Returns:
            unsigned int: The code offset of the instruction.
        """
        return self.offset

    cdef void add_argument(self, int argument):
        """ Adds an argument to the instruction.  Mostly for internal use.

        Args:
            argument (int): The byte representation of the instruction argument to add.
        """
        self.arguments += bytes([argument])
        self.__saved_argument = None #Reset saved argument for this.

    cdef void _set_arguments(self, bytes arguments):
        """ Internal method for setting the Instruction's argument data.

        Args:
            arguments (bytes): The bytes representation of the instruction's arguments
        """
        self.arguments = arguments

    cpdef void setup_arguments_from_int32(self, int arguments):
        """ Internal method for setting arguments from an integer value.

        Args:
            arguments (int): the argument to set.
        """
        self.__saved_argument = None
        self.arguments = int.to_bytes(arguments, 4, 'little', signed=True)

    cpdef void setup_arguments_from_int8(self, char arguments):
        """ Internal method for setting arguments from an int8 value.

        Args:
            arguments (char): the argument to set.
        """
        self.__saved_argument = None
        self.arguments = int.to_bytes(arguments, 1, 'little', signed=True)
    
    cpdef void setup_arguments_from_argslist(self, list arguments):
        """ Internal method for setting arguments from an argument list value.
            Used for switch instrs.
        Args:
            arguments (list): the argument to set.
        """
        cdef unsigned int l = <unsigned int>len(arguments)
        cdef bytearray result = bytearray(int.to_bytes(l, 4, 'little', signed=False))
        cdef unsigned int x = 0
        for x in range(l):
            result.extend(int.to_bytes(arguments[x], 4, 'little', signed=True))
        self.__saved_argument = None
        self.arguments = bytes(result)

    cpdef void setup_arguments_from_int64(self, int64_t arguments):
        """ Internal method for setting arguments from an argument int64_t value.
            Used for switch instrs.
        Args:
            arguments (int64_t): the argument to set.
        """
        self.__saved_argument = None
        self.arguments = int.to_bytes(arguments, 8, 'little', signed=True)

    cpdef void setup_arguments_from_float(self, float arguments):
        """ Internal method for setting arguments from an argument float value.
            Used for switch instrs.
        Args:
            arguments (float): the argument to set.
        """
        cdef bytes b = PyBytes_FromStringAndSize(NULL, 4)
        memcpy(PyBytes_AS_STRING(b), &arguments, 4)
        self.__saved_argument = None
        self.arguments = b

    cpdef void setup_arguments_from_double(self, double arguments):
        """ Internal method for setting arguments from an argument double value.
            Used for switch instrs.
        Args:
            arguments (double): the argument to set.
        """
        cdef bytes b = PyBytes_FromStringAndSize(NULL, 8)
        memcpy(PyBytes_AS_STRING(b), &arguments, 8)
        self.__saved_argument = None
        self.arguments = b

    cpdef str get_name(self):
        """ Obtains the name of an instruction's OpCode.

        Returns:
            str: The name of an instruction (e.x ldstr)
        """
        return self.opcode_one.get_name()

    cpdef bint is_twobyte_opcode(self):
        """ informs the caller whether the instruction uses two bytes for an opcode. 

        Returns:
            bool: True if the instruction uses two bytes for an opcode, False otherwise.
        """
        return self.opcode_one.is_two_byte_opcode()

    cpdef net_opcodes.Opcodes get_opcode(self):
        """ Obtains the Opcodes enum representing the opcode for the instruction.

        Returns:
            net_opcodes.Opcodes: The opcode for the instruction.
        """
        return self.opcode_one.obtain_opcode()

    cpdef object get_argument(self):
        """ Obtains a python object representing the instruction's argument
        For instructions which have a token argument, the return value will be a python representation of the token.
        For example, ldtoken instructions will return a net_row_object.RowObject.
        ldstr will return bytes.
        switch will return a list of offsets for each branch, relative to the start of the method.
        Most other instructions will return an integer value, or None if the instruction does not have an argument.

        Returns:
            object: The instruction's argument.
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
        """ Obtains the bytes representation of the Instruction's arguments.

        Returns:
            bytes: A byte representation of the instruction's arguments.
        """
        return self.arguments

    cpdef void setup_instr_size(self, int instr_size):
        """ Internal method for setting up an instruction's size.  Must be called before len() and Instruction.get_instr_size().

        Args:
            instr_size (int): The calculated size of the instruction.
        """
        self.instr_size = instr_size

    def __str__(self):
        cdef str result = ''
        cdef int arg = 0
        if self.get_opcode() == net_opcodes.Opcodes.Switch:
            result = 'Offset={}, Name={}, Argument=['.format(hex(self.get_instr_offset()), self.get_name())
            for arg in self.get_argument():
                result += hex(arg) + ', '
            result = result.rstrip(', ')
            result += ']'
            return result
        elif self.is_branch() or self.is_absolute_jmp():
            return 'Offset={}, Name={}, Argument={}'.format(hex(self.get_instr_offset()), self.get_name(), hex(self.get_argument() + len(self) + self.get_instr_offset()))
        else:
            return 'Offset={}, Name={}, Argument={}'.format(hex(self.get_instr_offset()), self.get_name(), str(self.get_argument()))

    def __repr__(self):
        return self.__str__()

    def __len__(self):
        """ Obtains the length in bytes of the instruction

        Returns:
            Py_ssize_t: The length in bytes of the instruction.
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
        """ Obtains the a byte representation of the instruction.

        Returns:
            bytes: A byte representation of the instruction
        """
        cdef bytes result
        result = None
        if self.opcode_one.is_two_byte_opcode():
            result = int.to_bytes(self.opcode_one.obtain_opcode(), 2, 'big')
        else:
            result = bytes([self.opcode_one.obtain_opcode()])
        result += bytes(self.get_arguments())
        return result
    
    cpdef bytes to_bytes(self):
        """ Obtains the a byte representation of the instruction.

        Returns:
            bytes: A byte representation of the instruction
        """
        return self.get_bytes()

    cpdef bint has_token_argument(self):
        """ Does the instruction have an argument which represents a token?

        Returns:
            bool: True if the instruction's argument represents a metadata token, False otherwise.
        """
        return self.opcode_one.is_token_argument_opcode()

    cpdef bint is_branch(self):
        """ Is the instruction a branch instruction (e.x switch, br.s, brfalse)

        Returns:
            bool: True if the instruction branches, False otherwise.
        """
        if self.get_opcode() == net_opcodes.Opcodes.Switch:
            return True
        return self.opcode_one.is_branch_opcode()

    cpdef bint is_argument_signed(self):
        """ Does the instruction have a signed integer for an argument?

        Returns:
            bool: True if the instruction contains a signed integer in the arguments, false otherwise.
        """
        if self.has_token_argument():
            return True

        return self.opcode_one.opcode_argument_signed()

    cpdef bint is_absolute_jmp(self):
        """ Determines if the instruction causes an absolute jump.
            Generally only br, br.s, leave and leave.s causes this, since no matter what happens they jump.

        Returns:
            bool: True if the instruction causes an absolute jump False otherwise (absolute jumps)
        """
        cdef net_opcodes.Opcodes opcode = self.get_opcode()
        return opcode == net_opcodes.Opcodes.Br or opcode == net_opcodes.Opcodes.Br_S or opcode == net_opcodes.Opcodes.Leave or opcode == net_opcodes.Opcodes.Leave_S

    cpdef int get_instr_handler(self):
        """ Obtain the index of a exception handler containing the instruction.
            Will obtain the first index - an instruction can be within multiple handlers.

        Returns:
            int: an index corresponding to a member of get_exception_blocks(), or -1 for not found.
        """
        cdef int x = 0
        cdef list exc = None
        cdef int try_offset = 0
        cdef int try_length = 0
        for exc in self.__disasm_obj.exception_blocks:
            try_offset = exc[1]
            try_length = exc[2]

            if try_offset <= <int>self.get_instr_offset() < (try_offset + try_length):
                return x
            try_offset = exc[3]
            try_length = exc[4]
            if try_offset <= <int>self.get_instr_offset() < (try_offset + try_length):
                return x
            x += 1
        return -1

    cpdef bint is_in_try(self):
        """ Checks whether the instruction exists within a try clause.

        Returns:
            bint: True if the instruction is within a try, False otherwise.
        """
        cdef int handler = self.get_instr_handler()
        cdef list exc = None
        if handler == -1:
            return False
        exc = self.__disasm_obj.exception_blocks[handler]
        if exc[1] <= <int>self.get_instr_offset() < (exc[1] + exc[2]):
            return True
        return False

    cpdef bint is_in_catch(self):
        """ Checks whether the instruction exists within a catch clause.

        Returns:
            bint: True if the instruction is within a catch, False otherwise.
        """
        cdef int handler = self.get_instr_handler()
        cdef list exc = None
        if handler == -1:
            return False
        exc = self.__disasm_obj.exception_blocks[handler]
        if exc[3] <= <int>self.get_instr_offset() < (exc[3] + exc[4]):
            return True
        return False

cdef class MethodDisassembler:
    """ Represents a disassembler for a specific method.
    
    Notes:
        dotnetpe (dotnetpefile.DotNetPeFile): The DotNetPeFile that produced the disassembler.
        method_obj (net_row_objects.MethodDef): The method object that is being disassembled.  Right now its a MethodDef, leaving the door open to changes for emulation of dynamic methods.
        max_stack (int): The method's maximum stack size.
        __reader (net_structs.DotNetDataReader): a data reader object for the method.
        flags (int): The method header's flags value.
        header_size (int): The size of the method's header.
        code_size (int): The size of the code in the method.
        local_var_sig_tok (int): The token which represents the LocalSig for the method.
        exception_blocks: (list[uint16_t, uint16_t, uint16_t, uint16_t, uint16_t, int]): A list of tuples representing exception blocks for the method, containing the following values: (clause_flags, try_offset, try_length, handler_offset, handler_length, class_token)
    """
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, object method, bytes force_data=None, list force_local_types=None):
        """ Constructor for MethodDisassembler - creates a new object.
        
        Args:
            dotnetpe (dotnetpefile.DotNetPeFile): the DotNetPeFile that created the disassembler.
            method (object): An object representing the method to disassemble.  Currently only can be MethodDef, but leaving the door open to others.
            force_data (bytes): To force the disassembler to disassemble specific bytes instead of reading it from the method object.

        Returns:
            MethodDisassembler: A new disassembler for the specified method.

        Raises:
            net_exceptions.InvalidAssemblyException: Whenever there is an issue that prevents disassembly of the method.
        """
        self.dotnetpe = dotnetpe
        self.method_obj = method
        self.max_stack = 0
        self.local_types = None
        self.local_var_sig_tok = 0
        self.flags = 0
        self.header_size = 0
        self.code_size = 0
        if force_data is None:
            self.__reader: net_structs.DotNetDataReader = net_structs.DotNetDataReader(self.method_obj.get_method_data())
            self.disassemble_loop()
        else:
            self.__reader: net_structs.DotNetDataReader = net_structs.DotNetDataReader(force_data)
            self.disassemble_loop()

        if force_local_types is not None:
            self.local_types = force_local_types
    
    cpdef Instruction emit_instruction(self, net_opcodes.Opcodes op):
        """ Emits an instruction without any arguments or offsets setup.
            In order to be usable, setup_instr_size(), setup_instr_offset() and setup_arguments_from_*() must be called on the instruction.

            This will eventually be favored over patching using patch_instruction()

        Returns:
            Instruction: The newly created instruction.
        """
        cdef net_opcodes.OpCode opcode  = net_opcodes.NET_OPCODE_DB[op]
        return Instruction(opcode, self, 0, 0) #No offset or index for now, set that up later.

    def __dealloc__(self):
        self.clear()

    cpdef list get_exception_blocks(self):
        """ Obtains the exception blocks parsed from the method.
            Each exception block is represented as a tuple with the following elements
            exc[0] (int): The flags for the clause
            exc[1] (int): the IL offset for the try block
            exc[2] (int): The code size for the try block
            exc[3] (int): The IL offset for the handler block
            exc[4] (int): The code size for the handler block
            exc[5] (int): The class token for the exception block.

        Returns:
            list[tuple[int, int, int, int, int, int]]: A list of tuples, containing the above described values.
        """
        return self.exception_blocks

    cpdef int get_max_stack_size(self):
        """ Obtain the maximum stack size for the method.

        Returns:
            int: The maximum stack size for the method.
        """
        return self.max_stack

    cpdef net_row_objects.MethodDefOrRef get_method(self):
        """ Obtain the method object being disassembled.

        Returns:
            net_row_objects.MethodDefOrRef: The method object being disassembled.
        """
        return self.method_obj

    cpdef dotnetpefile.DotNetPeFile get_dotnetpe(self):
        """ Obtain the DotNetPeFile that created the disassembler.

        Returns:
            dotnetpefile.DotNetPeFile: The PE file which created the disassembler.
        """
        return self.dotnetpe

    cpdef list get_list_of_instrs(self):
        """ Obtain a python list of net_cil_disas.Instruction objects.

        Returns:
            list[net_cil_disas.Instruction]: A python list of instruction objects that were disassembled.
        """
        cdef list result = list()
        cdef unsigned int i = 0
        for i in range(<unsigned int>self.instrs.size()):
            result.append(<Instruction>self.instrs.at(i))
        return result

    cpdef tuple get_arg_token_properties(self, Instruction instr):
        """ Obtain the table and rid for a instruction's argument.
        Mostly for internal use, possibly going to be removed eventually.

        Returns:
            tuple[str, int]: The table and index of a instruction's token argument.  None if invalid.
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
        """ Obtain the size of the method's header.

        Returns:
            int: The size of the method's header.
        """
        return self.header_size

    cpdef int get_code_size(self):
        """ Obtain the size of the method's code.

        Returns:
            int: The size of the method's code.
        """
        return self.code_size

    cpdef list get_local_types(self):
        """ Obtain a list of the local types in the method.

        Returns:
            list[net_sigs.TypeSig]: A list of local type signatures for the method.
        """
        if self.local_var_sig_tok == 0:
            if self.local_types is None:
                self.local_types = list()
        if self.local_types is None:
            if self.local_var_sig_tok > 0:
                if self.local_var_sig_tok != 0:
                    signature_entry = self.dotnetpe.get_token_value(self.local_var_sig_tok)
                    if signature_entry is not None and signature_entry.get_table_name() == 'StandAloneSig':
                        blob_value = signature_entry.get_column('Signature').get_value()
                        if blob_value is None or blob_value[0] != net_structs.CorCallingConvention.LocalSig:
                            self.local_types = list()
                        else:
                            sig_reader = net_sigs.SignatureReader(self.dotnetpe, blob_value)
                            local_sig = sig_reader.read_signature()
                            self.local_types = local_sig.get_local_vars()
                    else:
                        #the local var sig token is invalid.
                        self.local_types = list()
            if self.local_types is None:
                self.local_types = list()
        return self.local_types

    cpdef int get_flags(self):
        """ Obtain the flags associated with the method.

        Returns:
            int: the flags for the method.
        """
        return self.flags

    cpdef int get_local_var_sig_token(self):
        """ Obtain the integer local variable signature token associated with the method.

        Returns:
            int: the token value for the local var signature token.
        """
        return self.local_var_sig_tok

    cdef void clear(self):
        cdef Instruction instr = None
        cdef size_t x = 0
        for x in range(self.instrs.size()):
            instr = <Instruction>self.instrs[x]
            Py_XDECREF(<PyObject*>instr)
        self.instrs.clear()
        self.offsets.clear()

    cdef void parse_header(self):
        """ Internal method to parse the method's header.
        """
        cdef int start
        cdef int val
        cdef net_row_objects.RowObject signature_entry
        cdef bytes blob_value
        cdef net_sigs.SignatureReader sig_reader
        cdef net_sigs.LocalSig local_sig
        cdef int extra_sect_offset
        cdef int amt_to_add
        cdef int sect_flags
        cdef int data_size
        cdef int num_clauses
        cdef uint16_t clause_flags
        cdef uint16_t try_offset
        cdef uint16_t handler_offset
        cdef uint32_t class_token
        cdef int handler_length
        cdef int try_length
        start = self.__reader.read_byte()
        val = start & 0x3
        if val == 2:
            self.flags = 0
            self.header_size = 1
            self.code_size = (start >> 2)
            self.max_stack = 8
            self.local_var_sig_tok = 0
            self.local_types = list()
            self.exception_blocks = list() #Small headers cant have exceptions.
        elif val == 3:
            self.flags = ((self.__reader.read_byte() << 8) | start)
            self.header_size = (self.flags >> 12)
            self.flags = self.flags & 0x0FFF
            self.max_stack = self.__reader.read_uint16()
            self.code_size = self.__reader.read_uint32()
            self.local_var_sig_tok = self.__reader.read_uint32()
            self.header_size *= 4
            if self.header_size != 12:
                raise net_exceptions.InvalidArgumentsException()

            self.exception_blocks = list()

            #parse exception data
            if self.flags & net_structs.CorILMethod.MoreSects:
                extra_sect_offset = self.header_size + self.code_size
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
        else:
            raise net_exceptions.InvalidArgumentsException()

    cdef void disassemble_loop(self):
        """ Internal method to parse the method's code.
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
                    instr = Instruction(usable_opcode, self, orig_index, instr_index)
                else:
                    instr = Instruction(usable_opcode, self, orig_index, instr_index)
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
            raise net_exceptions.InvalidAssemblyException()

    def __iter__(self):
        return iter(self.get_list_of_instrs())

    def __len__(self):
        return self.instrs.size()

    def __getitem__(self, Py_ssize_t item):
        """ Obtain an instruction by INDEX

        Args:
            item (Py_ssize_t): The index to obtain the instruction for.

        Returns:
            net_cil_disas.Instruction: The instruction corresponding to the provided index.
        
        Raises:
            IndexError: If there is no instruction at item
        """
        if item < 0 or item >= len(self):
            raise IndexError
        cdef Instruction result = <Instruction>self.instrs.at(item)
        return result

    cpdef Instruction get_instr_at_offset(self, int offset):
        """ Obtain an Instruction at offset.

        Args:
            offset (int): The instruction offset to obtain

        Returns:
            net_cil_disas.Instruction: The obtained instruction, None if it doesnt exist.
        """
        cdef unordered_map[int, int].iterator it = self.offsets.find(offset)
        cdef pair[int, int] res
        cdef Instruction result = None
        if it == self.offsets.end():
            return None
        res = dereference(it)
        if res.second >= len(self):
            return None
        result = <Instruction>self.instrs.at(res.second)
        return result

    cpdef int get_instr_offset(self, int instr_index):
        """ Obtain an Instruction's offset at instr_index.

        Args:
            instr_index (int): The instruction index to obtain the offset for.

        Returns:
            int: The obtained instruction's offset, -1 if it doesnt exist.
        """
        if instr_index < 0 or instr_index >= len(self):
            return -1
        cdef Instruction instr = <Instruction>self.instrs.at(instr_index)
        return instr.get_instr_offset()

    cpdef int get_instr_index_by_offset(self, unsigned int instr_offset):
        """ Obtain an Instruction's index at instr_offset.

        Args:
            instr_index (int): The instruction offset to obtain the index for.

        Returns:
            int: The obtained instruction's index, -1 if it doesnt exist.
        """
        cdef unordered_map[int, int].iterator it = self.offsets.find(instr_offset)
        cdef pair[int, int] res
        if it == self.offsets.end():
            return -1
        res = dereference(it)
        return res.second

    cpdef Instruction get_instr_at_index(self, int index):
        """ Obtain an Instruction at index.

        Args:
            index (int): The instruction index to obtain

        Returns:
            net_cil_disas.Instruction: The obtained instruction, None if it doesnt exist.
        """
        if index < 0 or index >= len(self):
            return None
        cdef Instruction result = <Instruction>self.instrs.at(index)
        return result