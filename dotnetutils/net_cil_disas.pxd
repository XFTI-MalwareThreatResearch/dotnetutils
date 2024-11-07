#cython: language_level=3
from dotnetutils cimport dotnetpefile
from dotnetutils cimport net_row_objects
from dotnetutils cimport net_structs
from dotnetutils cimport net_opcodes

cdef class Instruction:

    cdef net_opcodes.OpCode opcode_one
    cdef list arguments
    cdef int instr_size
    cdef int offset
    cdef object __saved_argument
    cdef MethodDisassembler __disasm_obj
    cdef int instr_index

    cpdef int get_instr_size(self)

    cpdef int get_instr_index(self)

    cpdef int get_instr_offset(self)

    cdef void add_argument(self, int argument)

    cpdef str get_name(self)

    cpdef bint is_twobyte_opcode(self)

    cpdef net_opcodes.Opcodes get_opcode(self)

    cpdef object get_argument(self)

    cpdef bytes get_arguments(self)

    cdef void setup_instr_size(self, int instr_size)

    cpdef bytes get_bytes(self)
    
    cpdef bytes to_bytes(self)

    cpdef bint has_token_argument(self)

    cpdef bint is_branch(self)

    cpdef bint is_argument_signed(self)

    cpdef bint is_absolute_jmp(self)


cdef class MethodDisassembler:
    cdef dotnetpefile.DotNetPeFile dotnetpe
    cdef net_row_objects.MethodDef method_obj
    cdef int header_size
    cdef int code_size
    cdef int max_stack
    cdef int local_var_sig_tok
    cdef list local_types
    cdef list exception_blocks
    cdef int flags
    cdef dict instrs
    cdef net_structs.DotNetDataReader __reader

    cpdef object get_method(self)

    cpdef dotnetpefile.DotNetPeFile get_dotnetpe(self)

    cpdef list get_list_of_instrs(self)

    cpdef tuple get_arg_token_properties(self, Instruction instr)

    cpdef int get_header_size(self)

    cpdef int get_code_size(self)

    cdef void parse_header(self)

    cdef dict disassemble_loop(self)

    cpdef Instruction get_instr_at_offset(self, int offset)

    cpdef int get_instr_offset(self, int instr_index)

    cpdef int get_instr_index_by_offset(self, int instr_offset)


cpdef get_total_method_size(data)