#cython: language_level=3
#distutils: language=c++

from dotnetutils cimport net_row_objects, net_cil_disas, net_sigs, net_emu_types, dotnetpefile
from libcpp.unordered_map cimport unordered_map
from libcpp.vector cimport vector
from cpython.object cimport PyObject
from libc.stdint cimport uint64_t, uint16_t, int64_t, int32_t, uint32_t
from dotnetutils.net_structs cimport CorElementType

ctypedef StackCell (*emu_func_type)(net_emu_types.DotNetObject, StackCell * params, int nparams)
ctypedef net_emu_types.DotNetObject (*newobj_func_type)(DotNetEmulator)
ctypedef StackCell (*static_func_type)(EmulatorAppDomain, StackCell * params, int nparams)
ctypedef bint (*emu_instr_handler_type)(DotNetEmulator)

cdef bint do_call(DotNetEmulator emu, bint is_virt, bint is_newobj, net_row_objects.MethodDef force_method_obj, net_row_objects.TypeDefOrRef force_extern_type, StackCell * force_method_args, int nforce_method_args, net_row_objects.MethodDefOrRef initial_method_obj)

cdef void __init_handlers()

cdef struct ByRefItem:
    int kind
    int idx
    PyObject * owner

cdef union StackCellItem:
    int32_t i4
    uint32_t u4
    int64_t i8
    uint64_t u8
    double r8
    bint b
    PyObject * ref
    ByRefItem byref

cdef struct StackCell:
    CorElementType tag
    int rid
    StackCellItem item
    PyObject * emulator_obj
    void * extra_data

cdef class StackCellWrapper:
    cdef uint64_t u8_holder
    cdef PyObject * ref_holder
    cdef CorElementType cor_type
    cdef int kind_holder
    cdef PyObject * owner_holder
    cdef int idx_holder
    cdef int rid_holder
    cdef void * extra_data_holder
    
    cdef StackCell get_wrapped(self)

cdef class CctorRegistry:
    cdef list __executed_cctors

    cpdef bint can_execute(self, net_row_objects.MethodDef method_obj)

cdef class EmulatorAppDomain:
    cdef list __assemblyresolve_handlers
    cdef list __resourceresolve_handlers
    cdef list __loaded_assemblies
    cdef net_emu_types.DotNetAssembly original_assembly
    cdef DotNetEmulator __emu_obj
    cdef int __current_thread_num
    cdef DotNetEmulator __current_emulator
    cdef dotnetpefile.DotNetPeFile __starter_dpe
    cdef dotnetpefile.DotNetPeFile __calling_dotnetpe
    cdef dotnetpefile.DotNetPeFile __executing_dotnetpe
    cdef unordered_map[int, static_func_type] __static_functions
    cdef unordered_map[int, newobj_func_type] __newobj_ctors
    cdef unordered_map[int, int] __static_field_mappings
    cdef vector[StackCell] __static_fields

    cdef static_func_type get_static_func(self, int token)

    cdef newobj_func_type get_ctor_func(self, int token)

    cdef bint has_ctor_func(self, int token)

    cdef bint has_static_func(self, int token)

    cdef StackCell get_static_field_idx(self, int index)

    cdef void __reserve_static_fields(self)

    cdef void register_static_functions(self)

    cpdef int get_thread_id(self)

    cpdef DotNetEmulator get_emulator_obj(self)

    cpdef void add_resource_handler(self, net_row_objects.MethodDefOrRef obj)

    cpdef void add_assembly_handler(self, net_row_objects.MethodDefOrRef obj)

    cpdef list get_loaded_assemblies(self)

    cpdef net_emu_types.DotNetAssembly load_assembly_from_bytes(self, bytes data)

    cpdef net_emu_types.DotNetAssembly load_dotnetpe_as_assembly(self, dotnetpefile.DotNetPeFile dpe)

    cpdef net_emu_types.DotNetAssembly get_assembly_by_name(self, net_emu_types.DotNetString name) except *

    cpdef bytes get_resource_by_name(self, net_emu_types.DotNetString name, net_emu_types.DotNetAssembly assembly) except *

    cpdef DotNetEmulator get_current_emulator(self)

    cpdef dotnetpefile.DotNetPeFile get_calling_dotnetpe(self)
    
    cpdef dotnetpefile.DotNetPeFile get_executing_dotnetpe(self)

    cpdef void set_current_emulator(self, DotNetEmulator)
    
    cpdef void set_calling_dotnetpe(self, dotnetpefile.DotNetPeFile)

    cpdef void set_executing_dotnetpe(self, dotnetpefile.DotNetPeFile)

    cpdef EmulatorAppDomain get_current_appdomain(self)

    cdef void set_static_field(self, int idno, StackCell cell)
    
    cdef StackCell get_static_field(self, int idno)

    cdef StackCell get_static_field_idx(self, int index)

    cdef void clear_static_fields(self)

    cdef int get_amt_static_fields(self)

cdef class DotNetStack:
    cdef DotNetEmulator __emulator
    cdef vector[StackCell] __internal_stack
    cdef int __max_stack_size

    cdef void append(self, StackCell obj)

    cdef StackCell pop(self)

    cdef StackCell peek(self)

    cpdef void clear(self)

    cdef StackCell get(self, int index)

    cpdef net_emu_types.DotNetObject pop_obj(self)


cdef class DotNetEmulator:
    """
    This class is capable of emulating most .NET CIL instructions.
    """

    cdef net_row_objects.MethodDefOrRef method_obj
    cdef net_cil_disas.MethodDisassembler disasm_obj
    cdef StackCell * __method_params
    cdef int __nparams
    cdef public int end_offset
    cdef public DotNetStack stack
    cdef vector[StackCell] localvars
    cdef vector[PyObject*] local_var_sigs
    cdef public int end_method_rid
    cdef CctorRegistry executed_cctors
    cdef public unsigned int current_eip
    cdef public unsigned int current_offset
    cdef uint64_t __last_instr_start
    cdef uint64_t __last_instr_end
    cdef uint64_t start_time
    cdef uint64_t timeout_ns
    cdef DotNetEmulator caller
    cdef public int end_eip
    cdef bint should_break
    cdef bint print_debug
    cdef bint print_hex
    cdef bint print_debug_children
    cdef bint ignore_security_exceptions
    cdef bint dont_execute_cctor
    cdef bint break_on_unsupported
    cdef bint already_init
    cdef bint spawned
    cdef bint __skip_next_instruction
    cdef public list print_debug_instrs
    cdef list print_debug_offsets
    cdef public dict print_debug_rids
    cdef public list ignore_instrs
    cdef list print_debug_methods
    cdef EmulatorAppDomain app_domain
    cdef int print_debug_level
    cdef net_emu_types.DotNetThread running_thread
    cdef bint __is_64bit
    cdef net_cil_disas.Instruction instr

    cdef StackCell cast_cell(self, StackCell cell, net_sigs.TypeSig sig)

    cpdef void setup_method_params(self, list method_params)

    cdef int get_num_params(self)

    cpdef net_row_objects.MethodDefOrRef get_method_obj(self)

    cpdef DotNetEmulator get_caller(self)

    cdef StackCell convert_unsigned(self, StackCell cell)

    cdef StackCell get_method_param(self, int idx)

    cdef void _add_param(self, int idx, StackCell cell)

    cdef void _allocate_params(self, int nparams)

    cdef StackCellWrapper wrap_cell(self, StackCell cell)

    cdef StackCell duplicate_cell(self, StackCell cell)

    cdef StackCell duplicate_cell_object(self, StackCell cell)

    cpdef DotNetStack get_stack(self)

    cdef void set_ref(self, StackCell ref, StackCell value)

    cdef bint cell_is_false(self, StackCell cell)

    cdef bint cell_is_gt(self, StackCell one, StackCell two)

    cdef bint cell_is_lt(self, StackCell one, StackCell two)

    cdef bint cell_is_ge(self, StackCell one, StackCell two)

    cdef bint cell_is_le(self, StackCell one, StackCell two)

    cdef StackCell cell_and(self, StackCell one, StackCell two)

    cdef StackCell cell_or(self, StackCell one, StackCell two)

    cdef StackCell cell_xor(self, StackCell one, StackCell two)

    cdef StackCell cell_sub(self, StackCell one, StackCell two)

    cdef StackCell cell_neg(self, StackCell one)

    cdef StackCell cell_add(self, StackCell one, StackCell two)

    cdef StackCell cell_shl(self, StackCell one, StackCell two)

    cdef StackCell cell_shr(self, StackCell one, StackCell two)

    cdef StackCell cell_divide(self, StackCell one, StackCell two)

    cdef StackCell cell_rem(self, StackCell one, StackCell two)

    cdef StackCell cell_multiply(self, StackCell one, StackCell two)

    cdef StackCell cell_not(self, StackCell cell)

    cdef void deref_cell(self, StackCell cell)

    cdef StackCell get_ref(self, StackCell ref)

    cdef void set_param(self, int idx, StackCell value)

    cdef void ref_cell(self, StackCell cell)
    
    cdef bint cell_is_true(self, StackCell cell)

    cdef bint cell_is_null(self, StackCell one)

    cdef bint cell_is_equal(self, StackCell one, StackCell two)

    cdef bint cell_is_not_equal(self, StackCell one, StackCell two)

    cdef void dealloc_cell(self, StackCell cell)

    cdef size_t hash_cell(self, StackCell cell)

    cdef bytes cell_to_bytes(self, StackCell cell)

    cdef str cell_to_str(self, StackCell cell)

    cdef StackCell pack_blanktag(self)

    cdef StackCell pack_i4(self, int i)

    cdef StackCell pack_i(self, int64_t i)

    cdef StackCell pack_u(self, uint64_t i)

    cdef StackCell pack_i1(self, char i)

    cdef StackCell pack_u1(self, unsigned char i)

    cdef StackCell pack_i2(self, short i)

    cdef StackCell pack_u2(self, unsigned short i)

    cdef StackCell pack_char(self, unsigned short i)

    cdef StackCell pack_bool(self, bint i)
    
    cdef StackCell pack_u4(self, unsigned int i)

    cdef StackCell pack_i8(self, int64_t i)
    
    cdef StackCell pack_u8(self, uint64_t i)

    cdef StackCell pack_r4(self, float i)
    
    cdef StackCell pack_r8(self, double i)

    cdef StackCell pack_object(self, net_emu_types.DotNetObject obj)

    cdef StackCell pack_string(self, net_emu_types.DotNetString obj)

    cdef StackCell pack_ref(self, int kind, int idx, object owner)

    cdef StackCell pack_null(self)

    cdef StackCell box_value(self, StackCell cell, net_sigs.TypeSig type_sig)

    cdef StackCell unbox_value(self, StackCell cell)

    cdef bint is_64bit(self)

    cpdef net_emu_types.DotNetThread get_current_thread(self)

    cpdef void set_running_thread(self, net_emu_types.DotNetThread thread_obj)

    cpdef EmulatorAppDomain get_appdomain(self)

    cdef void initialize_locals(self)

    cdef StackCell get_local(self, int idx)

    cdef void set_local(self, int idx, StackCell obj)

    cdef void print_string(self, str string, int print_debug_level)

    cpdef void print_current_state(self)

    cpdef CctorRegistry get_executed_cctors(self)

    cpdef DotNetEmulator spawn_new_emulator(self, net_row_objects.MethodDef method_obj, int start_offset=*, int end_offset=*, DotNetEmulator caller=*, int end_method_rid=*, int end_eip=*)

    cdef StackCell _get_default_value(self, net_sigs.TypeSig type_sig)

    cdef void print_instr(self, net_cil_disas.Instruction instr)

    cpdef void run_function(self) except *

    cdef void cleanup(self)