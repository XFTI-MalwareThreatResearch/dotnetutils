#cython: language_level=3
from dotnetutils cimport net_row_objects, net_cil_disas, net_utils, net_emu_types, dotnetpefile

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
    cdef dotnetpefile.DotNetPeFile __calling_dotnetpe
    cdef dotnetpefile.DotNetPeFile __executing_dotnetpe

    cpdef int get_thread_id(self)

    cpdef DotNetEmulator get_emulator_obj(self)

    cpdef void add_resource_handler(self, net_row_objects.MethodDefOrRef obj)

    cpdef void add_assembly_handler(self, net_row_objects.MethodDefOrRef obj)

    cpdef list get_loaded_assemblies(self)

    cpdef net_emu_types.DotNetAssembly load_assembly_from_bytes(self, bytes data)

    cpdef net_emu_types.DotNetAssembly load_dotnetpe_as_assembly(self, dotnetpefile.DotNetPeFile dpe)

    cpdef net_emu_types.DotNetAssembly get_assembly_by_name(self, net_emu_types.DotNetString name)

    cpdef bytes get_resource_by_name(self, net_emu_types.DotNetString name)

    cpdef DotNetEmulator get_current_emulator(self)

    cpdef dotnetpefile.DotNetPeFile get_calling_dotnetpe(self)
    
    cpdef dotnetpefile.DotNetPeFile get_executing_dotnetpe(self)

    cpdef void set_current_emulator(self, DotNetEmulator)
    
    cpdef void set_calling_dotnetpe(self, dotnetpefile.DotNetPeFile)

    cpdef void set_executing_dotnetpe(self, dotnetpefile.DotNetPeFile)

    cpdef EmulatorAppDomain get_current_appdomain(self)

cdef class DotNetStack:
    cdef DotNetEmulator __emulator
    cdef list __internal_stack
    cdef int __max_stack_size

    cdef void append(self, object obj)

    cpdef object pop(self)

    cpdef void clear(self)


cdef class DotNetEmulator:
    """
    This class is capable of emulating most .NET CIL instructions.
    """

    cdef net_row_objects.MethodDef method_obj
    cdef net_cil_disas.MethodDisassembler disasm_obj
    cdef public list method_params
    cdef public int end_offset
    cdef public dict static_fields
    cdef public DotNetStack stack
    cdef dict localvars
    cdef public int end_method_rid
    cdef CctorRegistry executed_cctors
    cdef public int current_eip
    cdef public Py_ssize_t current_offset
    cdef unsigned long long __last_instr_start
    cdef unsigned long long __last_instr_end
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

    cpdef net_emu_types.DotNetThread get_current_thread(self)

    cpdef void set_running_thread(self, net_emu_types.DotNetThread thread_obj)

    cpdef EmulatorAppDomain get_appdomain(self)

    cdef void initialize_locals(self)

    cdef void print_string(self, str string, int print_debug_level)

    cpdef void print_current_state(self)

    cpdef object get_static_field(self, int idno)

    cpdef CctorRegistry get_executed_cctors(self)

    cpdef void set_static_field(self, int idno, object val)

    cpdef DotNetEmulator spawn_new_emulator(self, net_row_objects.MethodDef method_obj, list method_params=*, int start_offset=*, int end_offset=*, DotNetEmulator caller=*, int end_method_rid=*, int end_eip=*)

    cdef object __get_default_value(self, net_utils.TypeSig type_sig)

    cdef bint handle_general_jump(self, net_cil_disas.Instruction instr, Py_ssize_t force_offset) except *

    cdef bint handle_brfalse_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_brtrue_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_call_instruction(self, net_cil_disas.Instruction instr, bint is_virt, bint is_newobj, net_row_objects.MethodDef force_method_obj,
                                str force_extern_type_name) except *

    cdef bint handle_callvirt_instruction(self, net_cil_disas.Instruction instr, bint force_virtcall=*, net_row_objects.TypeDefOrRef force_virt_type=*) except *

    cdef bint handle_ceq_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_cgt_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_cgt_un_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_clt_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_clt_un_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_add_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_and_instruction(self, net_cil_disas.Instruction instr) except *
    
    cdef bint handle_conv_i_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_conv_r_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_conv_u_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_ldarg_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_ldelem_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_ldc_i4_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_ldc_i8_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_ldc_r4_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_ldc_r8_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_ldloc_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_beq_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_bge_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_bge_un_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_bgt_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_bgt_un_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_div_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_dup_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_ldsfld_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_ldstr_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_ldtoken_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_mul_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_neg_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_newarr_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_ble_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_ble_un_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_blt_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_blt_un_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_bne_un_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_ldfld_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_or_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_not_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_ret_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_shl_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_shr_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_shr_un_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_stfld_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_stind_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_stloc_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_stsfld_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_sub_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_switch_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_xor_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_stelem_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_rem_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_rem_un_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_ldind_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_ldelema_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_box_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_castclass_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_conv_r_un_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_initobj_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_isinst_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_ldflda_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_ldlen_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_ldloca_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_ldsflda_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_ldobj_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_leave_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_starg_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_stobj_instruction(self, net_cil_disas.Instruction instr) except *

    cdef bint handle_unbox_any_instruction(self, net_cil_disas.Instruction instr) except *

    cpdef void run_function(self) except *