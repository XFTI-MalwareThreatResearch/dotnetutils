#cython: language_level=3
#distutils: language=c++

from dotnetutils cimport dotnetpefile
from dotnetutils cimport net_row_objects
from dotnetutils cimport net_structs
from dotnetutils cimport net_opcodes
from cpython.ref cimport PyObject
from cython.operator cimport dereference
from libcpp.vector cimport vector
from libc.stdint cimport int64_t
from libcpp.unordered_map cimport unordered_map

cdef class Instruction:
    cdef net_opcodes.OpCode opcode_one
    cdef bytes arguments
    cdef int instr_size
    cdef unsigned int offset
    cdef object __saved_argument
    cdef MethodDisassembler __disasm_obj
    cdef unsigned int instr_index

    cpdef int get_nstack(self)

    cpdef int get_astack(self)

    cpdef int get_pstack(self)

    cpdef int get_instr_size(self)

    cpdef unsigned int get_instr_index(self)

    cpdef unsigned int get_instr_offset(self)

    cdef void add_argument(self, int argument)
    
    cdef void _set_arguments(self, bytes arguments)

    cpdef void setup_arguments_from_int32(self, int arguments)

    cpdef void setup_arguments_from_int8(self, char arguments)

    cpdef void setup_arguments_from_int64(self, int64_t arguments)

    cpdef void setup_arguments_from_float(self, float arguments)

    cpdef void setup_arguments_from_double(self, double arguments)

    cpdef void setup_arguments_from_argslist(self, list arguments)

    cpdef str get_name(self)

    cpdef bint is_twobyte_opcode(self)

    cpdef net_opcodes.Opcodes get_opcode(self)

    cpdef object get_argument(self)

    cpdef bytes get_arguments(self)

    cpdef void setup_instr_size(self, int instr_size)

    cpdef void setup_instr_offset(self, unsigned int instr_offset, unsigned int instr_index)

    cpdef bytes get_bytes(self)
    
    cpdef bytes to_bytes(self)

    cpdef bint has_token_argument(self)

    cpdef bint is_branch(self)

    cpdef bint is_argument_signed(self)

    cpdef bint is_absolute_jmp(self)

    cpdef bint is_in_catch(self)

    cpdef bint is_in_try(self)

    cpdef int get_instr_handler(self)

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
    cdef vector[PyObject*] instrs
    cdef unordered_map[int, int] offsets
    cdef net_structs.DotNetDataReader __reader

    cpdef Instruction emit_instruction(self, net_opcodes.Opcodes op)

    cpdef void add_instruction_at_index(self, int index, Instruction instr, int handler=*, bint is_try=*, bint is_catch=*)

    cdef void __update_offsets(self, int offset, int index, int difference, int except_handler, bint is_try, bint is_catch)

    cpdef void remove_instruction_at_index(self, int index)

    cpdef int get_max_stack_size(self)

    cpdef net_row_objects.MethodDefOrRef get_method(self)

    cpdef dotnetpefile.DotNetPeFile get_dotnetpe(self)

    cpdef list get_list_of_instrs(self)

    cpdef tuple get_arg_token_properties(self, Instruction instr)

    cpdef int get_header_size(self)

    cpdef int get_flags(self)

    cpdef int get_local_var_sig_token(self)

    cpdef int get_code_size(self)

    cpdef list get_local_types(self)

    cdef void parse_header(self)

    cdef void disassemble_loop(self)

    cpdef Instruction get_instr_at_offset(self, int offset)

    cpdef Instruction get_instr_at_index(self, int index)

    cpdef int get_instr_offset(self, int instr_index)

    cpdef int get_instr_index_by_offset(self, unsigned int instr_offset)

    cpdef bytes recompile_method(self)

    cdef void clear(self)

    cpdef list get_exception_blocks(self)


cpdef unsigned long get_total_method_size(bytes data)