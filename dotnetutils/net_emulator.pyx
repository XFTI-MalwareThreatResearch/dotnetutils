#cython: language_level=3
#distutils: language=c++

import threading
from dotnetutils import net_exceptions
from libc.stdint cimport int64_t, uint64_t
from libc.string cimport strlen, strcmp, memset, memcpy
from libc.stdlib cimport free, malloc
from dotnetutils cimport net_sigs, net_tokens, net_utils, net_opcodes, net_cil_disas, net_structs, net_row_objects, net_emu_types, net_table_objects, dotnetpefile
from dotnetutils.net_structs cimport CorElementType
from dotnetutils.net_opcodes cimport Opcodes
from cpython.ref cimport Py_INCREF, Py_XDECREF
from libcpp.utility cimport pair
from cpython.exc cimport PyErr_CheckSignals
from dotnetutils.net_emu_structs cimport StackCell, SlimStackCell, SlimObject

include "net_emu_types.pxi"

"""
Used for polling the performance counter with minimal overhead
This is done a lot with print debugs so it can save a ton of time.
"""
cdef extern from * nogil:
    """
    #include <stdint.h>

    #if defined(_WIN32)
      #include <windows.h>
      static inline uint64_t _perf_counter_ns(void) {
          static LARGE_INTEGER freq = {0};
          LARGE_INTEGER t;
          if (freq.QuadPart == 0) { QueryPerformanceFrequency(&freq); }
          QueryPerformanceCounter(&t);
          return (uint64_t)((t.QuadPart * 1000000000ULL) / (uint64_t)freq.QuadPart);
      }

    #elif defined(__APPLE__) && defined(__MACH__)
      #include <mach/mach_time.h>
      static inline uint64_t _perf_counter_ns(void) {
          static mach_timebase_info_data_t tb = {0, 0};
          if (tb.denom == 0) mach_timebase_info(&tb);
          uint64_t t = mach_absolute_time();
          return (t * (uint64_t)tb.numer) / (uint64_t)tb.denom;  // nanoseconds
      }

    #else
      #include <time.h>
      static inline uint64_t _perf_counter_ns(void) {
          struct timespec ts;
        #ifdef CLOCK_MONOTONIC_RAW
          const clockid_t clk = CLOCK_MONOTONIC_RAW;
        #else
          const clockid_t clk = CLOCK_MONOTONIC;
        #endif
          clock_gettime(clk, &ts);
          return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
      }
    #endif
    """
    uint64_t _perf_counter_ns()

cdef emu_instr_handler_type emu_func_handlers[0x10000] #an array of functions used to execute each .NET instruction.

cdef bint __is_handlers_initialized = False #Boolean value to determine if handlers are initialized.  They only need to be initialized once.

cdef void __init_handlers():
    """ Initializes all emulator instruction handlers.  This method should only be called once.
    """
    memset(emu_func_handlers, 0x0, sizeof(emu_func_handlers))

    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Invalid] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Nop] = handle_nop_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Break] = handle_break_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldarg_0] = handle_ldarg_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldarg_1] = handle_ldarg_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldarg_2] = handle_ldarg_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldarg_3] = handle_ldarg_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldloc_0] = handle_ldloc_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldloc_1] = handle_ldloc_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldloc_2] = handle_ldloc_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldloc_3] = handle_ldloc_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldloc_S] = handle_ldloc_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stloc_0] = handle_stloc_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stloc_1] = handle_stloc_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stloc_2] = handle_stloc_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stloc_3] = handle_stloc_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldarg_S] = handle_ldarg_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldarga_S] = handle_ldarga_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stloc_S] = handle_stloc_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stloc] = handle_stloc_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldnull] = handle_ldnull_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldc_I4_M1] = handle_ldc_i4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldc_I4_0] = handle_ldc_i4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldc_I4_1] = handle_ldc_i4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldc_I4_2] = handle_ldc_i4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldc_I4_3] = handle_ldc_i4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldc_I4_4] = handle_ldc_i4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldc_I4_5] = handle_ldc_i4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldc_I4_6] = handle_ldc_i4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldc_I4_7] = handle_ldc_i4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldc_I4_8] = handle_ldc_i4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldc_I4_S] = handle_ldc_i4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Call] = handle_call_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldc_I4] = handle_ldc_i4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldc_I8] = handle_ldc_i8_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldc_R4] = handle_ldc_r4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldc_R8] = handle_ldc_r8_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Dup] = handle_dup_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Pop] = handle_pop_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Jmp] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Calli] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ret] = handle_ret_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Br_S] = handle_br_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Brfalse_S] = handle_brfalse_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Brtrue_S] = handle_brtrue_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Beq_S] = handle_beq_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Bge_S] = handle_bge_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Bgt_S] = handle_bgt_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ble_S] = handle_ble_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Blt_S] = handle_blt_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Bne_Un_S] = handle_bne_un_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Bge_Un_S] = handle_bge_un_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Bgt_Un_S] = handle_bgt_un_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ble_Un_S] = handle_ble_un_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Blt_Un_S] = handle_blt_un_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Br] = handle_br_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Brfalse] = handle_brfalse_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Brtrue] = handle_brtrue_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Beq] = handle_beq_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Bge] = handle_bge_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Bgt] = handle_bgt_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ble] = handle_ble_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Blt] = handle_blt_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Bne_Un] = handle_bne_un_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Bge_Un] = handle_bge_un_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Bgt_Un] = handle_bgt_un_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ble_Un] = handle_ble_un_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Blt_Un] = handle_blt_un_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Switch] = handle_switch_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldind_I1] = handle_ldind_i1_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldind_U1] = handle_ldind_u1_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldind_I2] = handle_ldind_i2_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldind_U2] = handle_ldind_u2_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldind_I4] = handle_ldind_i4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldind_U4] = handle_ldind_u4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldind_I8] = handle_ldind_i8_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldind_I] = handle_ldind_i_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldind_R4] = handle_ldind_r4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldind_R8] = handle_ldind_r8_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldind_Ref] = handle_ldind_ref_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stind_Ref] = handle_stind_ref_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stind_I1] = handle_stind_i1_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stind_I2] = handle_stind_i2_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stind_I4] = handle_stind_i4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stind_I8] = handle_stind_i8_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stind_R4] = handle_stind_r4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stind_R8] = handle_stind_r8_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Add] = handle_add_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Sub] = handle_sub_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Mul] = handle_mul_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Div] = handle_div_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Div_Un] = handle_div_un_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Rem] = handle_rem_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Rem_Un] = handle_rem_un_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.And] = handle_and_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Or] = handle_or_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Xor] = handle_xor_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Shl] = handle_shl_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Shr] = handle_shr_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Shr_Un] = handle_shr_un_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Neg] = handle_neg_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Not] = handle_not_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_I1] = handle_conv_i1_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_I2] = handle_conv_i2_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_I4] = handle_conv_i4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_I8] = handle_conv_i8_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_R4] = handle_conv_r4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_R8] = handle_conv_r8_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_U4] = handle_conv_u4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_U8] = handle_conv_u8_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Callvirt] = handle_callvirt_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Cpobj] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldobj] = handle_ldobj_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldstr] = handle_ldstr_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Newobj] = handle_newobj_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Castclass] = handle_castclass_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Isinst] = handle_isinst_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_R_Un] = handle_conv_r_un_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Unbox] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Throw] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldfld] = handle_ldfld_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldflda] = handle_ldflda_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stsfld] = handle_stsfld_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stobj] = handle_stobj_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_Ovf_I1_Un] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_Ovf_I2_Un] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_Ovf_I4_Un] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_Ovf_I8_Un] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_Ovf_U1_Un] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_Ovf_U2_Un] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_Ovf_U4_Un] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_Ovf_U8_Un] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_Ovf_I_Un] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_Ovf_U_Un] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Box] = handle_box_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Newarr] = handle_newarr_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldlen] = handle_ldlen_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldelema] = handle_ldelema_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldelem_I1] = handle_ldelem_i1_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldelem_U1] = handle_ldelem_u1_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldelem_I2] = handle_ldelem_i2_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldelem_U2] = handle_ldelem_u2_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldelem_I4] = handle_ldelem_i4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldelem_U4] = handle_ldelem_u4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldelem_I8] = handle_ldelem_i8_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldelem_Ref] = handle_ldelem_ref_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stelem_I] = handle_stelem_i_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stelem_I1] = handle_stelem_i1_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stelem_I2] = handle_stelem_i2_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stelem_I4] = handle_stelem_i4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stelem_I8] = handle_stelem_i8_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stelem_R4] = handle_stelem_r4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stelem_R8] = handle_stelem_r8_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stelem_Ref] = handle_stelem_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldelem] = handle_ldelem_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stelem] = handle_stelem_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Unbox_Any] = handle_unbox_any_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_Ovf_I1] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_Ovf_U1] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_Ovf_I2] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_Ovf_U2] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_Ovf_I4] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_Ovf_U4] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_Ovf_I8] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_Ovf_U8] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Refanyval] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ckfinite] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Mkrefany] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldtoken] = handle_ldtoken_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_U2] = handle_conv_u2_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_U1] = handle_conv_u1_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_I] = handle_conv_i_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_Ovf_I] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_Ovf_U] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Add_Ovf] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Add_Ovf_Un] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Mul_Ovf] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Mul_Ovf_Un] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Sub_Ovf] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Sub_Ovf_Un] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Endfinally] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Leave] = handle_leave_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Leave_S] = handle_leave_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stind_I] = handle_stind_i_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Conv_U] = handle_conv_u_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Prefix7] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Prefix6] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Prefix5] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Prefix4] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Prefix3] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Prefix2] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Prefix1] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.PrefixRef] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Arglist] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ceq] = handle_ceq_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Cgt] = handle_cgt_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Cgt_Un] = handle_cgt_un_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Clt] = handle_clt_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Clt_Un] = handle_clt_un_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldftn] = handle_ldftn_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldvirtftn] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldarg] = handle_ldarg_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldarga] = handle_ldarga_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Starg] = handle_starg_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Starg_S] = handle_starg_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldloc] = handle_ldloc_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Localloc] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Endfilter] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Unaligned] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Volatile] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Tail] = handle_nop_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Initobj] = handle_initobj_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Constrained] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Cpblk] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Initblk] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Rethrow] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Sizeof] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Refanytype] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Readonly] = handle_unsupported_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldsflda] = handle_ldsflda_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldloca] = handle_ldloca_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldloca_S] = handle_ldloca_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Stfld] = handle_stfld_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldsfld] = handle_ldsfld_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldelem_R4] = handle_ldelem_r4_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldelem_R8] = handle_ldelem_r8_instruction
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldelem_I] = handle_ldelem_i_instruction
    __is_handlers_initialized = True

"""
These functions are for the most part instruction handlers
These handlers are meant to emulate specific instructions.
Instruction handlers return False if the emulator should move to the next instruction
True is returned if the instruction is a jump and has already jumped to the next instruction.
"""

cdef bint handle_general_jump(DotNetEmulator emu): 
    """ Performs a jump.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef int instr_offset  = <int>emu.instr.get_argument()
    cdef unsigned int expected_offset = emu.current_offset + emu.instr.get_instr_size() + instr_offset
    emu.current_offset = expected_offset
    emu.current_eip = emu.disasm_obj.get_instr_index_by_offset(expected_offset)
    return True

cdef bint handle_stind_i_instruction(DotNetEmulator emu):
    """ Performs stind.i instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell num = emu.stack.pop()
    cdef StackCell addr = emu.stack.pop()
    cdef StackCell casted
    if not net_utils.is_cortype_number(<CorElementType>num.tag) or addr.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.InvalidArgumentsException()
    casted = emu.cast_cell(num, net_sigs.get_CorSig_IntPtr())
    emu.set_ref(addr, casted)
    emu.dealloc_cell(num)
    emu.dealloc_cell(addr)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_stind_i1_instruction(DotNetEmulator emu):
    """ Performs stind.i1 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell num = emu.stack.pop()
    cdef StackCell addr = emu.stack.pop()
    cdef StackCell casted
    if not net_utils.is_cortype_number(<CorElementType>num.tag) or addr.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.InvalidArgumentsException()
    casted = emu.cast_cell(num, net_sigs.get_CorSig_SByte())
    emu.set_ref(addr, casted)
    emu.dealloc_cell(num)
    emu.dealloc_cell(addr)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_stind_i2_instruction(DotNetEmulator emu):
    """ Performs stind.i2 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell num = emu.stack.pop()
    cdef StackCell addr = emu.stack.pop()
    cdef StackCell casted
    if not net_utils.is_cortype_number(<CorElementType>num.tag) or addr.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.InvalidArgumentsException()
    casted = emu.cast_cell(num, net_sigs.get_CorSig_Int16())
    emu.set_ref(addr, casted)
    emu.dealloc_cell(num)
    emu.dealloc_cell(addr)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_stind_i4_instruction(DotNetEmulator emu):
    """ Performs stind.i4 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell num = emu.stack.pop()
    cdef StackCell addr = emu.stack.pop()
    cdef StackCell casted
    if not net_utils.is_cortype_number(<CorElementType>num.tag) or addr.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.InvalidArgumentsException()
    casted = emu.cast_cell(num, net_sigs.get_CorSig_Int32())
    emu.set_ref(addr, casted)
    emu.dealloc_cell(num)
    emu.dealloc_cell(addr)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_stind_i8_instruction(DotNetEmulator emu):
    """ Performs stind.i8 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell num = emu.stack.pop()
    cdef StackCell addr = emu.stack.pop()
    cdef StackCell casted
    if not net_utils.is_cortype_number(<CorElementType>num.tag) or addr.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.InvalidArgumentsException()
    casted = emu.cast_cell(num, net_sigs.get_CorSig_Int64())
    emu.set_ref(addr, casted)
    emu.dealloc_cell(num)
    emu.dealloc_cell(addr)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_stind_r4_instruction(DotNetEmulator emu):
    """ Performs stind.r4 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell num = emu.stack.pop()
    cdef StackCell addr = emu.stack.pop()
    cdef StackCell casted
    if not net_utils.is_cortype_number(<CorElementType>num.tag) or addr.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.InvalidArgumentsException()
    casted = emu.cast_cell(num, net_sigs.get_CorSig_Single())
    emu.set_ref(addr, casted)
    emu.dealloc_cell(num)
    emu.dealloc_cell(addr)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_stind_r8_instruction(DotNetEmulator emu):
    """ Performs stind.r8 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell num = emu.stack.pop()
    cdef StackCell addr = emu.stack.pop()
    cdef StackCell casted
    if not net_utils.is_cortype_number(<CorElementType>num.tag) or addr.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.InvalidArgumentsException()
    casted = emu.cast_cell(num, net_sigs.get_CorSig_Double())
    emu.set_ref(addr, casted)
    emu.dealloc_cell(num)
    emu.dealloc_cell(addr)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_stind_ref_instruction(DotNetEmulator emu):
    """ Performs stind.ref instruction.

        Instruction is currently not supported and should not be used.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    raise net_exceptions.FeatureNotImplementedException()

cdef bint handle_ldind_i_instruction(DotNetEmulator emu):
    """ Performs ldind.i instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell addr_obj = emu.stack.pop()
    cdef StackCell ref_obj
    cdef StackCell casted
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    ref_obj = emu.get_ref(addr_obj)
    if not net_utils.is_cortype_number(<CorElementType>ref_obj.tag):
        raise net_exceptions.InvalidArgumentsException()
    casted = emu.cast_cell(ref_obj, net_sigs.get_CorSig_IntPtr())
    emu.stack.append(casted)
    emu.dealloc_cell(ref_obj)
    emu.dealloc_cell(addr_obj)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_ldind_i1_instruction(DotNetEmulator emu):
    cdef StackCell addr_obj = emu.stack.pop()
    cdef StackCell ref_obj
    cdef StackCell casted
    """ Performs ldind.i1 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    ref_obj = emu.get_ref(addr_obj)
    if not net_utils.is_cortype_number(<CorElementType>ref_obj.tag):
        raise net_exceptions.InvalidArgumentsException()
    casted = emu.cast_cell(ref_obj, net_sigs.get_CorSig_SByte())
    emu.stack.append(casted)
    emu.dealloc_cell(ref_obj)
    emu.dealloc_cell(addr_obj)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_ldind_i2_instruction(DotNetEmulator emu):
    """ Performs ldind.i2 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell addr_obj = emu.stack.pop()
    cdef StackCell ref_obj
    cdef StackCell casted
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    ref_obj = emu.get_ref(addr_obj)
    if not net_utils.is_cortype_number(<CorElementType>ref_obj.tag):
        raise net_exceptions.InvalidArgumentsException()
    casted = emu.cast_cell(ref_obj, net_sigs.get_CorSig_Int16())
    emu.stack.append(casted)
    emu.dealloc_cell(ref_obj)
    emu.dealloc_cell(addr_obj)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_ldind_i4_instruction(DotNetEmulator emu):
    """ Performs ldind.i4 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell addr_obj = emu.stack.pop()
    cdef StackCell ref_obj
    cdef StackCell casted
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    ref_obj = emu.get_ref(addr_obj)
    if not net_utils.is_cortype_number(<CorElementType>ref_obj.tag):
        raise net_exceptions.InvalidArgumentsException()
    casted = emu.cast_cell(ref_obj, net_sigs.get_CorSig_Int32())
    emu.stack.append(casted)
    emu.dealloc_cell(ref_obj)
    emu.dealloc_cell(addr_obj)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_ldind_i8_instruction(DotNetEmulator emu):
    """ Performs ldind.i8 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell addr_obj = emu.stack.pop()
    cdef StackCell ref_obj
    cdef StackCell casted
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    ref_obj = emu.get_ref(addr_obj)
    if not net_utils.is_cortype_number(<CorElementType>ref_obj.tag):
        raise net_exceptions.InvalidArgumentsException()
    casted = emu.cast_cell(ref_obj, net_sigs.get_CorSig_Int64())
    emu.stack.append(casted)
    emu.dealloc_cell(ref_obj)
    emu.dealloc_cell(addr_obj)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_ldind_r4_instruction(DotNetEmulator emu):
    """ Performs ldind.r4 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell addr_obj = emu.stack.pop()
    cdef StackCell ref_obj
    cdef StackCell casted
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    ref_obj = emu.get_ref(addr_obj)
    if not net_utils.is_cortype_number(<CorElementType>ref_obj.tag):
        raise net_exceptions.InvalidArgumentsException()
    casted = emu.cast_cell(ref_obj, net_sigs.get_CorSig_Single())
    emu.stack.append(casted)
    emu.dealloc_cell(ref_obj)
    emu.dealloc_cell(addr_obj)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_ldind_r8_instruction(DotNetEmulator emu):
    """ Performs ldind.r8 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell addr_obj = emu.stack.pop()
    cdef StackCell ref_obj
    cdef StackCell casted
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    ref_obj = emu.get_ref(addr_obj)
    if not net_utils.is_cortype_number(<CorElementType>ref_obj.tag):
        raise net_exceptions.InvalidArgumentsException()
    casted = emu.cast_cell(ref_obj, net_sigs.get_CorSig_Double())
    emu.stack.append(casted)
    emu.dealloc_cell(ref_obj)
    emu.dealloc_cell(addr_obj)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_ldind_ref_instruction(DotNetEmulator emu):
    """ Performs ldind.ref instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell addr_obj = emu.stack.pop()
    cdef StackCell ref_obj
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    ref_obj = emu.get_ref(addr_obj)
    if ref_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.InvalidArgumentsException()
    emu.stack.append(ref_obj)
    emu.dealloc_cell(ref_obj)
    emu.dealloc_cell(addr_obj)
    return False

cdef bint handle_ldind_u1_instruction(DotNetEmulator emu):
    """ Performs ldind.u1 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell addr_obj = emu.stack.pop()
    cdef StackCell ref_obj
    cdef StackCell casted
    cdef StackCell result
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    ref_obj = emu.get_ref(addr_obj)
    if not net_utils.is_cortype_number(<CorElementType>ref_obj.tag):
        raise net_exceptions.InvalidArgumentsException()
    casted = emu.cast_cell(ref_obj, net_sigs.get_CorSig_Byte())
    result = emu.cast_cell(casted, net_sigs.get_CorSig_Int32())
    emu.stack.append(result)
    emu.dealloc_cell(ref_obj)
    emu.dealloc_cell(addr_obj)
    emu.dealloc_cell(casted)
    emu.dealloc_cell(result)
    return False

cdef bint handle_ldind_u2_instruction(DotNetEmulator emu):
    """ Performs ldind.u2 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell addr_obj = emu.stack.pop()
    cdef StackCell ref_obj
    cdef StackCell casted
    cdef StackCell result
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    ref_obj = emu.get_ref(addr_obj)
    if not net_utils.is_cortype_number(<CorElementType>ref_obj.tag):
        raise net_exceptions.InvalidArgumentsException()
    casted = emu.cast_cell(ref_obj, net_sigs.get_CorSig_UInt16())
    result = emu.cast_cell(casted, net_sigs.get_CorSig_Int32())
    emu.stack.append(result)
    emu.dealloc_cell(ref_obj)
    emu.dealloc_cell(addr_obj)
    emu.dealloc_cell(casted)
    emu.dealloc_cell(result)
    return False

cdef bint handle_ldind_u4_instruction(DotNetEmulator emu):
    """ Performs ldind.u4 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell addr_obj = emu.stack.pop()
    cdef StackCell ref_obj
    cdef StackCell casted
    cdef StackCell result
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    ref_obj = emu.get_ref(addr_obj)
    if not net_utils.is_cortype_number(<CorElementType>ref_obj.tag):
        raise net_exceptions.InvalidArgumentsException()
    casted = emu.cast_cell(ref_obj, net_sigs.get_CorSig_UInt32())
    result = emu.cast_cell(casted, net_sigs.get_CorSig_Int32())
    emu.stack.append(result)
    emu.dealloc_cell(ref_obj)
    emu.dealloc_cell(addr_obj)
    emu.dealloc_cell(casted)
    emu.dealloc_cell(result)
    return False

cdef bint handle_br_instruction(DotNetEmulator emu): 
    """ Performs br instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    return handle_general_jump(emu)

cdef bint handle_brfalse_instruction(DotNetEmulator emu): 
    """ Performs brfalse instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value1 = emu.stack.pop()
    #if its not null then its an object
    if emu.cell_is_false(value1):
        emu.dealloc_cell(value1)
        return handle_general_jump(emu)
    emu.dealloc_cell(value1)
    return False

cdef bint handle_brtrue_instruction(DotNetEmulator emu): 
    """ Performs brtrue instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value1 = emu.stack.pop()
    if emu.cell_is_true(value1):
        emu.dealloc_cell(value1)
        return handle_general_jump(emu)
    emu.dealloc_cell(value1)
    return False

cdef bint do_call(DotNetEmulator emu, bint is_virt, bint is_newobj, net_row_objects.MethodDefOrRef force_method_obj, net_row_objects.TypeDefOrRef force_extern_type, StackCell * force_method_args, int nforce_method_args, net_row_objects.MethodDefOrRef initial_method_obj) except *: 
    """ Handles a lot of the legwork for call instructions.  Creates new emulator objects, calls imported methods etc.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.
        is_virt (bint): Is the call a callvirt instruction.
        is_newobj (bint): Is the call a newobj instruction
        force_method_obj (net_row_objects.MethodDef): Force the execution of this method.  Can be None.  Usually used by do_virtcall()
        force_extern_type (net_roW_Objects.TypeDefOrRef): Force the type to use for virtual lookups.  Can be None.  Usually used by do_virtcall()
        force_method_args (net_emu_structs.StackCell *): Used to force specific arguments instead of pulling them from the stack.  Used by Invoke() method calls.
        nforce_method_args (int): Used to force specific method args.  Used by Invoke() method calls.
        initial_method_obj (net_row_objects.MethodDefOrRef): The initial method object used in the call instruction.  Important for when MethodSpec is used.


    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.EmulatorExecutionException: When theres an error executing the instruction, such as not enough memory etc.
        net_exceptions.InvalidArgumentsException: When force_method_args is used improperly.
    """
    cdef net_row_objects.MethodDefOrRef method_obj
    cdef net_row_objects.TypeDefOrRef parent_type
    cdef net_row_objects.MethodDef cctor_method
    cdef DotNetEmulator new_emu
    cdef int amt_params
    cdef net_emu_types.DotNetObject dot_obj = None
    cdef str type_full_name
    cdef bytes method_name
    cdef str method_full_name
    cdef type emulated_type
    cdef bint push_obj_reference
    cdef net_row_objects.ColumnValue params_obj
    cdef net_emu_types.DotNetObject ret_val
    cdef emu_func_type emu_func = NULL
    cdef static_func_type static_emu_func = NULL
    cdef newobj_func_type newobj_func = NULL
    cdef net_emu_types.DotNetObject obj_ref = None
    cdef StackCell obj_ref_initial
    cdef net_row_objects.TypeSpec tspec = None
    cdef int x = 0
    cdef int params_start = 0
    cdef int params_end = 1
    cdef int amt_args = 0
    cdef StackCell cell
    cdef StackCell * method_args = NULL
    cdef StackCell boxed_this
    cdef StackCell ret_cell
    cdef StackCell casted_cell
    cdef net_sigs.MethodSig method_signature = initial_method_obj.get_method_signature()
    memset(&obj_ref_initial, 0, sizeof(StackCell))
    if force_method_obj is not None:
        method_obj = force_method_obj
    else:
        method_obj = <net_row_objects.MethodDefOrRef>emu.instr.get_argument()
        if method_obj.get_table_name() == 'MethodDef' and not method_obj.has_body() and force_extern_type is None:
            if method_obj.get_parent_type():
                parent_type = <net_row_objects.TypeDefOrRef>method_obj.get_parent_type().get_superclass()
                if parent_type:
                    return do_call(emu, is_virt, is_newobj, force_method_obj, parent_type, NULL, 0, initial_method_obj)

    if method_obj.get_table_name() == 'MethodDef' and not force_extern_type:
        method_name = method_obj.get_name()
        amt_args = <int>len(method_obj.get_param_types())
        if not isinstance(initial_method_obj, net_row_objects.MethodSpec):
            new_emu = emu.spawn_new_emulator(method_obj, caller=emu)
        else:
            new_emu = emu.spawn_new_emulator(method_obj, caller=emu, spec_obj=initial_method_obj)
        if method_obj.method_has_this():
            new_emu._allocate_params(amt_args + 1)
        else:
            new_emu._allocate_params(amt_args)

        if force_method_args == NULL:
            if len(emu.stack) < amt_args:
                raise net_exceptions.EmulatorExecutionException(emu, 'There are not enough items on the stack to execute the instruction')
            if method_obj.method_has_this() or is_newobj:
                params_start = 1
                params_end = 0
            for x in range(amt_args - params_end, params_start - 1, -1): #len(method_obj.get_param_types()) seems to be inaccurate sometimes.
                cell = emu.stack.pop()
                new_emu._add_param(x, cell)
                emu.dealloc_cell(cell)
            if (method_obj.method_has_this() and not is_newobj):
                if len(emu.stack) < 1:
                    raise net_exceptions.EmulatorExecutionException(emu, 'There are not enough items on the stack to execute the instruction')
                cell = emu.stack.pop()
                new_emu._add_param(0, cell)
                emu.dealloc_cell(cell)
        else:
            for x in range(nforce_method_args):
                cell = force_method_args[x]
                new_emu._add_param(x, cell)
        if is_newobj:
            if isinstance(initial_method_obj.get_parent_type(), net_row_objects.TypeSpec):
                cell = emu.pack_slimobject(initial_method_obj.get_parent_type().get_type())
            else:
                cell = emu.pack_slimobject(initial_method_obj.get_parent_type())
            new_emu._add_param(0, cell)
            emu.dealloc_cell(cell)
        new_emu.run_function()
        # the handler for ret instruction handles cleaning up the stack after this.
    elif method_obj.get_table_name() == 'MemberRef' or force_extern_type:
        if force_extern_type is None and isinstance(method_obj.get_parent_type(), net_row_objects.TypeSpec): #generics etc.
            if isinstance(method_obj.get_parent_type().get_type(), net_row_objects.TypeDef): #TODO: Look over this logic in terms of DotNetDelegate.Invoke() calls.
                return do_virtcall(emu, force_virtcall=True, force_virt_type=method_obj.get_parent_type().get_type())
        method_name = method_obj.get_name()
        amt_args = <int>len(method_obj.get_param_types())
        push_obj_reference = False
        if not is_newobj and method_obj.method_has_this():
            push_obj_reference = True
        if force_method_args == NULL:
            if amt_args != 0:
                method_args = <StackCell*>malloc(sizeof(StackCell) * (amt_args))
                if method_args == NULL:
                    raise net_exceptions.EmulatorExecutionException(emu, 'error allocating memory for args')
                memset(method_args, 0, amt_args * sizeof(StackCell))
            if len(emu.stack) < amt_args:
                raise net_exceptions.EmulatorExecutionException(emu, 'There are not enough items on the stack to execute the instruction')
            for x in range(amt_args - 1, -1, -1):
                cell = emu.stack.pop()
                casted_cell = emu.cast_cell(cell, method_signature.get_parameters()[x])
                method_args[x] = casted_cell
                emu.dealloc_cell(cell)
        else:
            method_args = force_method_args
        if not is_newobj and push_obj_reference and force_method_args == NULL:
            if len(emu.stack) < 1:
                raise net_exceptions.EmulatorExecutionException(emu, 'There are not enough items on the stack to execute the instruction')
            cell = emu.stack.pop()
            if cell.tag == CorElementType.ELEMENT_TYPE_BYREF:
                obj_ref_initial = cell
                cell = emu.get_ref(cell)
                emu.dealloc_cell(obj_ref_initial)
            if emu.cell_is_null(cell):
                raise net_exceptions.InvalidArgumentsException()
            boxed_this = emu.box_value(cell, None) #TODO: should there be a sig here
            emu.dealloc_cell(cell)
            if emu.cell_is_null(boxed_this):
                raise net_exceptions.EmulatorExecutionException(emu, 'obj_ref is NULL when trying to do a instance call')
            obj_ref = <net_emu_types.DotNetObject>boxed_this.item.ref
        elif force_method_args != NULL and not is_newobj and push_obj_reference:
            cell = method_args[0]
            if cell.tag == CorElementType.ELEMENT_TYPE_BYREF:
                obj_ref_initial = cell
                cell = emu.get_ref(cell)
            if emu.cell_is_null(cell):
                raise net_exceptions.InvalidArgumentsException()
            boxed_this = emu.box_value(cell, None)
            if obj_ref_initial.tag == CorElementType.ELEMENT_TYPE_BYREF:
                emu.dealloc_cell(cell)
            
            if emu.cell_is_null(boxed_this):
                raise net_exceptions.EmulatorExecutionException(emu, 'obj_ref is NULL when trying to do a instance call')
            obj_ref = <net_emu_types.DotNetObject>boxed_this.item.ref
            if amt_args == 0:
                method_args = NULL
            else:
                method_args = &method_args[1] #Make sure this isnt included
        emu_method = None
        if method_obj.is_static_method():
            if not emu.get_appdomain().has_static_func(method_obj.get_token()):
                raise net_exceptions.EmulatorExecutionException(emu, 'unknown static function called {} {}'.format(hex(method_obj.get_token()), method_obj.get_full_name()))
            static_emu_func = emu.get_appdomain().get_static_func(method_obj.get_token())
            dot_obj = None
        elif method_name == b'.ctor': #newobj instructions only.
            if force_extern_type is None:
                parent_type = method_obj.get_parent_type()
            else:
                parent_type = force_extern_type
            if parent_type is not None and isinstance(parent_type, net_row_objects.TypeSpec):
                tspec = parent_type
                parent_type = tspec.get_type()
            if is_newobj and parent_type is not None and emu.get_appdomain().has_ctor_func(parent_type.get_token()):
                newobj_func = emu.get_appdomain().get_ctor_func(parent_type.get_token())
                dot_obj = newobj_func(emu)
                dot_obj.initialize_type(parent_type)
            elif parent_type is not None and not is_newobj:
                #for calls with ctors, do nothing.  Allocation already happened and for our purposes thats when the Ctor is called.
                if force_method_args == NULL:
                    for x in range(amt_args):
                        emu.dealloc_cell(method_args[x])
                if obj_ref is not None:
                    emu.dealloc_cell(boxed_this)
                return False
            else:
                ret_call = emu.pack_null()
                if not emu.strict_typing:
                    print('Warning: Unable to handle token: unknown ctor {} {} {} {}'.format(method_obj.get_full_name(), hex(method_obj.get_token()), hex(parent_type.get_token()), parent_type.get_full_name()))
                else:
                    raise net_exceptions.EmulatorExecutionException(emu, 'Unable to handle token: unknown ctor {} {} {} {}'.format(method_obj.get_full_name(), hex(method_obj.get_token()), hex(parent_type.get_token()), parent_type.get_full_name()))
            if newobj_func != NULL and not dot_obj.has_function(method_name):
                raise net_exceptions.EmulatorExecutionException(emu, 'type is missing .ctor')
            if newobj_func != NULL:
                emu_func = dot_obj.get_function(method_name)
                ret_cell = emu_func(dot_obj, method_args, amt_args) #ctors should always return self.
            if is_newobj:
                #A ctor cant return None
                cell = emu.unbox_value(ret_cell)
                emu.dealloc_cell(ret_cell)
                emu.stack.append(cell)
                emu.dealloc_cell(cell)
            if force_method_args == NULL: #these args are cleaned up by a later call.
                for x in range(amt_args):
                    emu.dealloc_cell(method_args[x])
            if obj_ref is not None:
                emu.dealloc_cell(boxed_this)
            return False 
        else:
            #static methods are handled so this should only be thiscall methods.
            if obj_ref is not None:
                if obj_ref.has_function(method_name):
                    emu_func = obj_ref.get_function(method_name)
                else:
                    raise net_exceptions.EmulatorMethodNotFoundException('{}:{}'.format(str(obj_ref), method_name))
            else:
                raise net_exceptions.EmulatorMethodNotFoundException(
                    method_name)
        if emu_func == NULL and static_emu_func == NULL:
            raise net_exceptions.EmulatorExecutionException(emu, 'emu_func == NULL')
        if static_emu_func != NULL:
            ret_cell = static_emu_func(emu.get_appdomain(), method_args, amt_args)
        else:
            ret_cell = emu_func(obj_ref, method_args, amt_args)
        if method_obj.has_return_value():
            cell = emu.unbox_value(ret_cell)
            emu.dealloc_cell(ret_cell)
            emu.stack.append(cell)
            emu.dealloc_cell(cell)
        for x in range(amt_args):
            emu.dealloc_cell(method_args[x])
        if obj_ref is not None:
            emu.dealloc_cell(boxed_this)
    elif method_obj.get_table_name() == 'MethodSpec':
        return do_call(emu, is_virt, is_newobj, method_obj.get_column('Method').get_value(), None, NULL, 0, method_obj)
    else:
        raise net_exceptions.EmulatorMethodNotFoundException(
            str(method_obj))
    return False

cdef bint handle_call_instruction(DotNetEmulator emu): 
    """ Performs call instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    return do_call(emu, False, False, None, None, NULL, 0, emu.instr.get_argument())

cdef bint do_virtcall(DotNetEmulator emu, bint force_virtcall=False, net_row_objects.TypeDefOrRef force_virt_type=None) except *: 
    """ Does the legwork for callvirt instructions.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.
        force_virtcall (bint): Used to force virtual lookup.  Sometimes do_virtcall() is called by do_call() so sometimes this is True.
        force_virt_type (net_row_objects.TypeDefOrRef): Used to force the Type to do the virtual lookup on.  Useful for TypeSpecs etc.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.EmulatorExecutionException: When theres an error executing the instruction.
    """
    cdef net_row_objects.MethodDefOrRef method_obj = emu.instr.get_argument()
    cdef net_row_objects.TypeDefOrRef parent_type
    cdef int amt_args
    cdef net_emu_types.DotNetObject obj_ref
    cdef StackCell obj_ref_cell
    cdef StackCell obj_ref_boxed
    cdef net_row_objects.TypeDefOrRef obj_type
    cdef net_row_objects.MethodDefOrRef actual_method_obj
    cdef net_sigs.MethodSig initial_method_sig
    cdef net_table_objects.MethodImplTable method_impl_table
    cdef net_row_objects.MethodDef def_method
    cdef net_row_objects.MethodDefOrRef curr_method_obj
    cdef int x = 0
    cdef net_sigs.GenericInstMethodSig genmethodsig = None
    cdef net_sigs.GenericInstSig gentypesig = None
    if not force_virtcall:
        if isinstance(method_obj, net_row_objects.MemberRef) and isinstance(method_obj.get_parent_type(),
                                                                            net_row_objects.TypeRef):
            return do_call(emu, True, False, None, None, NULL, 0, method_obj)
        
        if isinstance(method_obj, net_row_objects.MemberRef) and isinstance(method_obj.get_parent_type(), net_row_objects.TypeSpec):
            parent_type = method_obj.get_parent_type()
            if isinstance(parent_type.get_type(), net_row_objects.TypeRef):
                return do_call(emu, True, False, None, parent_type.get_type(), NULL, 0, method_obj)

        if isinstance(method_obj, net_row_objects.MethodDef) and method_obj.has_body():
            return do_call(emu, True, False, None, None, NULL, 0, method_obj)
    if force_virt_type is None:
        amt_args = method_obj.get_amt_params() 
        if method_obj.method_has_this():
            obj_ref_cell = emu.stack.get(<int>len(emu.stack) - amt_args - 1)
        else:
            obj_ref_cell = emu.stack.get(<int>len(emu.stack) - amt_args)
        obj_ref_boxed = emu.box_value(obj_ref_cell, None)
        if not obj_ref_boxed.is_slim_object:
            if obj_ref_boxed.item.ref == NULL:
                raise net_exceptions.EmulatorExecutionException(emu, 'Attempted to do virtcall on null ref')
            obj_ref = <net_emu_types.DotNetObject>obj_ref_boxed.item.ref
            obj_type = obj_ref.get_type_obj()
        else:
            obj_type = emu.get_method_obj().get_dotnetpe().get_token_value(obj_ref_boxed.item.slim_object.type_token)

        emu.dealloc_cell(obj_ref_cell)
        emu.dealloc_cell(obj_ref_boxed)
    else:
        obj_type = force_virt_type
    if not obj_type:
        raise net_exceptions.EmulatorTypeNotFoundException(
            'UNKNOWN PARENT TYPE')
    if isinstance(method_obj, net_row_objects.MethodSpec):
        genmethodsig = method_obj.get_sig_obj()

    if isinstance(method_obj.get_parent_type(), net_row_objects.TypeSpec):
        gentypesig = method_obj.get_parent_type().get_sig_obj()
    
    actual_method_obj = None
    initial_method_sig = method_obj.get_method_signature()
    method_impl_table = method_obj.get_dotnetpe().get_metadata_table('MethodImpl')
    while obj_type and not actual_method_obj:
        if isinstance(obj_type, net_row_objects.TypeDef):
            if method_impl_table is not None:
                #first check the methodimpl table.
                def_method = method_impl_table.get_method_definition(method_obj, obj_type)
                if def_method != None:
                    actual_method_obj = def_method
                    break

            #now check every method based on whether or not its hidebyname or hidebyname + sig
            for curr_method_obj in obj_type.get_methods():
                if method_obj.is_hidebysig():
                    if curr_method_obj.get_name() == method_obj.get_name():
                        if net_sigs.method_sig_compare(curr_method_obj.get_method_signature(), method_obj.get_method_signature(), genmethodsig, gentypesig):
                            if curr_method_obj.has_body():
                                actual_method_obj = curr_method_obj
                                break
                else:
                    if curr_method_obj.get_name() == method_obj.get_name():
                        if curr_method_obj.has_body():
                            actual_method_obj = curr_method_obj
                            break
        else:
            for curr_method_obj in obj_type.get_methods():
                if method_obj.is_hidebysig():
                    if curr_method_obj.get_name() == method_obj.get_name():
                        if net_sigs.method_sig_compare(curr_method_obj.get_method_signature(), method_obj.get_method_signature(), genmethodsig, gentypesig):
                            if curr_method_obj.has_body() or curr_method_obj.get_table_name() == 'MemberRef':
                                actual_method_obj = curr_method_obj
                                break
                else:
                    if curr_method_obj.get_name() == method_obj.get_name():
                        if curr_method_obj.has_body() or curr_method_obj.get_table_name() == 'MemberRef':
                            actual_method_obj = curr_method_obj
                            break
            if not actual_method_obj:
                #Last resort, try treating it as a call with a forced type.  If this doesnt work, it should error.
                return do_call(emu, True, emu.instr.get_opcode() == net_opcodes.Opcodes.Newobj, None, obj_type, NULL, 0, method_obj)
            
        if isinstance(obj_type, net_row_objects.TypeDef):
            obj_type = obj_type.get_superclass()
        else:
            break

    if not actual_method_obj:
        raise net_exceptions.EmulatorMethodNotFoundException(
            str(method_obj.get_full_name()))
    return do_call(emu, True, emu.instr.get_opcode() == net_opcodes.Opcodes.Newobj, actual_method_obj, None, NULL, 0, method_obj)

cdef bint handle_callvirt_instruction(DotNetEmulator emu): 
    """ Performs callvirt instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    return do_virtcall(emu, False, None)

cdef bint handle_ceq_instruction(DotNetEmulator emu): 
    """ Performs ceq instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell result
    if emu.cell_is_equal(value1, value2):
        result = emu.pack_i4(1)
    else:
        result = emu.pack_i4(0)
    emu.stack.append(result)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(value2)
    emu.dealloc_cell(result)
    return False

cdef bint handle_cgt_instruction(DotNetEmulator emu): 
    """ Performs cgt instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell val2 = emu.convert_signed(value2)
    cdef StackCell val1 = emu.convert_signed(value1)
    cdef StackCell result
    if emu.cell_is_gt(val1, val2):
        result = emu.pack_i4(1)
    else:
        result = emu.pack_i4(0)
    emu.stack.append(result)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(value2)
    emu.dealloc_cell(val1)
    emu.dealloc_cell(val2)
    emu.dealloc_cell(result)
    return False 

cdef bint handle_cgt_un_instruction(DotNetEmulator emu):
    """ Performs cgt.un instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell val2 = emu.stack.pop()
    cdef StackCell val1 = emu.stack.pop()
    cdef StackCell value2 = emu.convert_unsigned(val2)
    cdef StackCell value1 = emu.convert_unsigned(val1)
    cdef StackCell result

    if emu.cell_is_gt(value1, value2):
        result = emu.pack_i4(1)
    else:
        result = emu.pack_i4(0)
    emu.stack.append(result)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(value2)
    emu.dealloc_cell(result)
    emu.dealloc_cell(val2)
    emu.dealloc_cell(val1)
    return False 

cdef bint handle_clt_instruction(DotNetEmulator emu): 
    """ Performs clt instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell val2 = emu.convert_signed(value2)
    cdef StackCell val1 = emu.convert_signed(value1)
    cdef StackCell result

    if emu.cell_is_lt(val1, val2):
        result = emu.pack_i4(1)
    else:
        result = emu.pack_i4(0)
    emu.stack.append(result)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(value2)
    emu.dealloc_cell(result)
    emu.dealloc_cell(val1)
    emu.dealloc_cell(val2)
    return False

cdef bint handle_clt_un_instruction(DotNetEmulator emu):
    """ Performs clt.un instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell val2 = emu.stack.pop()
    cdef StackCell val1 = emu.stack.pop()
    cdef StackCell value2 = emu.convert_unsigned(val2)
    cdef StackCell value1 = emu.convert_unsigned(val1)
    cdef StackCell result

    if emu.cell_is_lt(value1, value2):
        result = emu.pack_i4(1)
    else:
        result = emu.pack_i4(0)
    emu.stack.append(result)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(value2)
    emu.dealloc_cell(result)
    emu.dealloc_cell(val2)
    emu.dealloc_cell(val1)
    return False 

cdef bint handle_add_instruction(DotNetEmulator emu):
    """ Performs add instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell result = emu.cell_add(value1, value2)
    emu.stack.append(result)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(value2)
    emu.dealloc_cell(result)
    return False

cdef bint handle_and_instruction(DotNetEmulator emu):
    """ Performs and instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell result = emu.cell_and(value1, value2)
    emu.stack.append(result)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(value2)
    emu.dealloc_cell(result)
    return False

cdef bint handle_conv_i_instruction(DotNetEmulator emu):
    """ Performs conv.i instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: When theres an invalid item popped off the stack for this instruction.
    
    """
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell casted
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    casted = emu.cast_cell(value1, net_sigs.get_CorSig_IntPtr())
    emu.stack.append(casted)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_conv_i1_instruction(DotNetEmulator emu):
    """ Performs conv.i1 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.

    Raises:
        net_exceptions.OperationNotSupportedException: When theres an invalid item popped off the stack for this instruction.

    """
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell casted
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    casted = emu.cast_cell(value1, net_sigs.get_CorSig_SByte())
    emu.stack.append(casted)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_conv_i2_instruction(DotNetEmulator emu):
    """ Performs conv.i2 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: When theres an invalid item popped off the stack for this instruction.
    
    """
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell casted
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    casted = emu.cast_cell(value1, net_sigs.get_CorSig_Int16())
    emu.stack.append(casted)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_conv_i4_instruction(DotNetEmulator emu):
    """ Performs conv.i4 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: When theres an invalid item popped off the stack for this instruction.
    
    """
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell casted
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    casted = emu.cast_cell(value1, net_sigs.get_CorSig_Int32())
    emu.stack.append(casted)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_conv_i8_instruction(DotNetEmulator emu):
    """ Performs conv.i8 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: When theres an invalid item popped off the stack for this instruction.
    
    """
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell casted
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    casted = emu.cast_cell(value1, net_sigs.get_CorSig_Int64())
    emu.stack.append(casted)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_conv_r4_instruction(DotNetEmulator emu):
    """ Performs conv.r4 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: When theres an invalid item popped off the stack for this instruction.
    
    """
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell casted
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    casted = emu.cast_cell(value1, net_sigs.get_CorSig_Single())
    emu.stack.append(casted)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_conv_r8_instruction(DotNetEmulator emu):
    """ Performs conv.r8 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: When theres an invalid item popped off the stack for this instruction.
    
    """
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell casted
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    casted = emu.cast_cell(value1, net_sigs.get_CorSig_Double())
    emu.stack.append(casted)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_conv_r_un_instruction(DotNetEmulator emu):
    """ Performs conv.r.un instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: When theres an invalid item popped off the stack for this instruction.
    
    """
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell unsigned = emu.convert_unsigned(value1)
    cdef StackCell casted
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    casted = emu.cast_cell(unsigned, net_sigs.get_CorSig_Double())
    emu.stack.append(casted)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(casted)
    emu.dealloc_cell(unsigned)
    return False

cdef bint handle_conv_u_instruction(DotNetEmulator emu):
    """ Performs conv.u instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: When theres an invalid item popped off the stack for this instruction.
    
    """
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell casted
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    casted = emu.cast_cell(value1, net_sigs.get_CorSig_UIntPtr())
    emu.stack.append(casted)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_conv_u1_instruction(DotNetEmulator emu):
    """ Performs conv.u1 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: When theres an invalid item popped off the stack for this instruction.
    
    """
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell casted
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    casted = emu.cast_cell(value1, net_sigs.get_CorSig_Byte())
    emu.stack.append(casted)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_conv_u2_instruction(DotNetEmulator emu):
    """ Performs conv.u2 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: When theres an invalid item popped off the stack for this instruction.
    
    """
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell casted
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    casted = emu.cast_cell(value1, net_sigs.get_CorSig_UInt16())
    emu.stack.append(casted)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_conv_u4_instruction(DotNetEmulator emu):
    """ Performs conv.u4 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: When theres an invalid item popped off the stack for this instruction.
    
    """
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell casted
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    casted = emu.cast_cell(value1, net_sigs.get_CorSig_UInt32())
    emu.stack.append(casted)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_conv_u8_instruction(DotNetEmulator emu):
    """ Performs conv.u8 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: When theres an invalid item popped off the stack for this instruction.
    
    """
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell casted
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    casted = emu.cast_cell(value1, net_sigs.get_CorSig_UInt64())
    emu.stack.append(casted)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_ldarg_instruction(DotNetEmulator emu):
    """ Performs ldarg instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.EmulatorExecutionException: The instruction argument is larger than the amount of parameters in the emulator.
    
    """
    cdef int number = emu.instr.get_argument()
    cdef StackCell cell
    if number >= emu.get_num_params():
        raise net_exceptions.EmulatorExecutionException(emu, 'Attempted to ldarg a parameter that isnt in the emulator')
    cell = emu.get_method_param(number)
    emu.stack.append(cell)
    emu.dealloc_cell(cell)
    return False

cdef bint handle_ldarga_instruction(DotNetEmulator emu):
    """ Performs ldarga instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.EmulatorExecutionException: The instruction argument is larger than the amount of parameters in the emulator.
    
    """
    cdef int number = emu.instr.get_argument()
    cdef StackCell result
    if number >= emu.get_num_params():
        raise net_exceptions.EmulatorExecutionException(emu, 'Attempted to ldarga a parameter that isnt in the emulator')
    result = emu.pack_ref(5, number, <void*><PyObject*>emu)
    emu.stack.append(result)
    emu.dealloc_cell(result)
    return False

cdef bint handle_ldelem_instruction(DotNetEmulator emu):
    """ Performs ldelem instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: An invalid instruction operand was popped off the stack.
    
    """
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef StackCell casted = emu.cast_cell(index, net_sigs.get_CorSig_Int64())
    cdef int64_t index_val = casted.item.i8
    cdef net_emu_types.DotNetArray array_obj = None
    cdef StackCell result
    emu.dealloc_cell(casted)
    if not net_utils.is_cortype_number(<CorElementType>index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotNetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetObject>result_obj
    result = array_obj._get_item(index_val)
    if result.tag == CorElementType.ELEMENT_TYPE_END:
        raise net_exceptions.EmulatorExecutionException(emu, 'Error ldelem element')
    if result.tag == CorElementType.ELEMENT_TYPE_OBJECT or result.tag == CorElementType.ELEMENT_TYPE_STRING:
        if result.item.ref != NULL:
            result_obj = <net_emu_types.DotNetObject>result.item.ref
            result_obj.initialize_type(emu.instr.get_argument())
    emu.stack.append(result)
    emu.dealloc_cell(index)
    emu.dealloc_cell(arr)
    emu.dealloc_cell(result)
    return False

cdef bint handle_ldelem_i_instruction(DotNetEmulator emu):
    """ Performs ldelem.i instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: An invalid instruction operand was popped off the stack.
    
    """
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef StackCell casted = emu.cast_cell(index, net_sigs.get_CorSig_Int64())
    cdef int64_t index_val = casted.item.i8
    cdef net_emu_types.DotNetArray array_obj = None
    cdef StackCell result
    emu.dealloc_cell(casted)
    if not net_utils.is_cortype_number(<CorElementType>index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotNetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetObject>result_obj
    result = array_obj._get_item(index_val)
    if result.tag == CorElementType.ELEMENT_TYPE_END:
        raise net_exceptions.EmulatorExecutionException(emu, 'Error ldelem element')
    if not net_utils.is_cortype_number(<CorElementType>result.tag):
        raise net_exceptions.OperationNotSupportedException()
    casted = emu.cast_cell(result, net_sigs.get_CorSig_IntPtr())
    emu.stack.append(casted)
    emu.dealloc_cell(index)
    emu.dealloc_cell(arr)
    emu.dealloc_cell(result)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_ldelem_i1_instruction(DotNetEmulator emu):
    """ Performs ldelem.i1 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: An invalid instruction operand was popped off the stack.
    
    """
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef StackCell casted = emu.cast_cell(index, net_sigs.get_CorSig_Int64())
    cdef int64_t index_val = casted.item.i8
    cdef net_emu_types.DotNetArray array_obj = None
    cdef StackCell result
    emu.dealloc_cell(casted)
    if not net_utils.is_cortype_number(<CorElementType>index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotNetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetObject>result_obj
    result = array_obj._get_item(index_val)
    if result.tag == CorElementType.ELEMENT_TYPE_END:
        raise net_exceptions.EmulatorExecutionException(emu, 'Error ldelem element')
    if not net_utils.is_cortype_number(<CorElementType>result.tag):
        raise net_exceptions.OperationNotSupportedException()
    casted = emu.cast_cell(result, net_sigs.get_CorSig_SByte())
    emu.stack.append(casted)
    emu.dealloc_cell(index)
    emu.dealloc_cell(arr)
    emu.dealloc_cell(result)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_ldelem_u1_instruction(DotNetEmulator emu):
    """ Performs ldelem.u1 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: An invalid instruction operand was popped off the stack.
    
    """
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef StackCell casted = emu.cast_cell(index, net_sigs.get_CorSig_Int64())
    cdef int64_t index_val = casted.item.i8
    cdef net_emu_types.DotNetArray array_obj = None
    cdef StackCell result
    emu.dealloc_cell(casted)
    if not net_utils.is_cortype_number(<CorElementType>index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotNetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetObject>result_obj
    result = array_obj._get_item(index_val)
    if result.tag == CorElementType.ELEMENT_TYPE_END:
        raise net_exceptions.EmulatorExecutionException(emu, 'Error ldelem element')
    if not net_utils.is_cortype_number(<CorElementType>result.tag):
        raise net_exceptions.OperationNotSupportedException()
    casted = emu.cast_cell(result, net_sigs.get_CorSig_Byte())
    emu.dealloc_cell(result)
    result = emu.cast_cell(casted, net_sigs.get_CorSig_Int32())
    emu.stack.append(result)
    emu.dealloc_cell(index)
    emu.dealloc_cell(arr)
    emu.dealloc_cell(result)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_ldelem_i2_instruction(DotNetEmulator emu):
    """ Performs ldelem.i2 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: An invalid instruction operand was popped off the stack.
    
    """
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef StackCell casted = emu.cast_cell(index, net_sigs.get_CorSig_Int64())
    cdef int64_t index_val = casted.item.i8
    cdef net_emu_types.DotNetArray array_obj = None
    cdef StackCell result
    emu.dealloc_cell(casted)
    if not net_utils.is_cortype_number(<CorElementType>index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotNetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetObject>result_obj
    result = array_obj._get_item(index_val)
    if result.tag == CorElementType.ELEMENT_TYPE_END:
        raise net_exceptions.EmulatorExecutionException(emu, 'Error ldelem element')
    if not net_utils.is_cortype_number(<CorElementType>result.tag):
        raise net_exceptions.OperationNotSupportedException()
    casted = emu.cast_cell(result, net_sigs.get_CorSig_Int16())
    emu.stack.append(casted)
    emu.dealloc_cell(index)
    emu.dealloc_cell(arr)
    emu.dealloc_cell(result)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_ldelem_u2_instruction(DotNetEmulator emu):
    """ Performs ldelem.u2 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: An invalid instruction operand was popped off the stack.
    
    """
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef StackCell casted = emu.cast_cell(index, net_sigs.get_CorSig_Int64())
    cdef int64_t index_val = casted.item.i8
    cdef net_emu_types.DotNetArray array_obj = None
    cdef StackCell result
    emu.dealloc_cell(casted)
    if not net_utils.is_cortype_number(<CorElementType>index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotNetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetObject>result_obj
    result = array_obj._get_item(index_val)
    if result.tag == CorElementType.ELEMENT_TYPE_END:
        raise net_exceptions.EmulatorExecutionException(emu, 'Error ldelem element')
    if not net_utils.is_cortype_number(<CorElementType>result.tag):
        raise net_exceptions.OperationNotSupportedException()
    casted = emu.cast_cell(result, net_sigs.get_CorSig_UInt16())
    emu.dealloc_cell(result)
    result = emu.cast_cell(casted, net_sigs.get_CorSig_Int32())
    emu.stack.append(result)
    emu.dealloc_cell(index)
    emu.dealloc_cell(arr)
    emu.dealloc_cell(result)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_ldelem_i4_instruction(DotNetEmulator emu):
    """ Performs ldelem.i4 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: An invalid instruction operand was popped off the stack.
    
    """
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef StackCell casted = emu.cast_cell(index, net_sigs.get_CorSig_Int64())
    cdef int64_t index_val = casted.item.i8
    cdef net_emu_types.DotNetArray array_obj = None
    cdef StackCell result
    emu.dealloc_cell(casted)
    if not net_utils.is_cortype_number(<CorElementType>index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotNetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetObject>result_obj
    result = array_obj._get_item(index_val)
    if result.tag == CorElementType.ELEMENT_TYPE_END:
        raise net_exceptions.EmulatorExecutionException(emu, 'Error ldelem element')
    if not net_utils.is_cortype_number(<CorElementType>result.tag):
        raise net_exceptions.OperationNotSupportedException()
    casted = emu.cast_cell(result, net_sigs.get_CorSig_Int32())
    emu.stack.append(casted)
    emu.dealloc_cell(index)
    emu.dealloc_cell(arr)
    emu.dealloc_cell(result)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_ldelem_u4_instruction(DotNetEmulator emu):
    """ Performs ldelem.u4 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: An invalid instruction operand was popped off the stack.
    
    """
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef StackCell casted = emu.cast_cell(index, net_sigs.get_CorSig_Int64())
    cdef int64_t index_val = casted.item.i8
    cdef net_emu_types.DotNetArray array_obj = None
    cdef StackCell result
    emu.dealloc_cell(casted)
    if not net_utils.is_cortype_number(<CorElementType>index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotNetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetObject>result_obj
    result = array_obj._get_item(index_val)
    if result.tag == CorElementType.ELEMENT_TYPE_END:
        raise net_exceptions.EmulatorExecutionException(emu, 'Error ldelem element')
    if not net_utils.is_cortype_number(<CorElementType>result.tag):
        raise net_exceptions.OperationNotSupportedException()
    casted = emu.cast_cell(result, net_sigs.get_CorSig_UInt32())
    emu.dealloc_cell(result)
    result = emu.cast_cell(casted, net_sigs.get_CorSig_Int32())
    emu.stack.append(result)
    emu.dealloc_cell(index)
    emu.dealloc_cell(arr)
    emu.dealloc_cell(result)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_ldelem_ref_instruction(DotNetEmulator emu):
    """ Performs ldelem.ref instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: An invalid instruction operand was popped off the stack.
    
    """
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef StackCell casted = emu.cast_cell(index, net_sigs.get_CorSig_Int64())
    cdef int64_t index_val = casted.item.i8
    cdef net_emu_types.DotNetArray array_obj = None
    cdef StackCell cell
    emu.dealloc_cell(casted)
    if not net_utils.is_cortype_number(<CorElementType>index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotNetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetObject>result_obj
    cell = emu.pack_ref(3, index_val, <void*><PyObject*>array_obj)
    emu.stack.append(cell)
    emu.dealloc_cell(index)
    emu.dealloc_cell(arr)
    emu.dealloc_cell(cell)
    return False

cdef bint handle_ldelem_i8_instruction(DotNetEmulator emu):
    """ Performs ldelem.i8 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: An invalid instruction operand was popped off the stack.
    
    """
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef StackCell casted = emu.cast_cell(index, net_sigs.get_CorSig_Int64())
    cdef int64_t index_val = casted.item.i8
    cdef net_emu_types.DotNetArray array_obj = None
    cdef StackCell result
    emu.dealloc_cell(casted)
    if not net_utils.is_cortype_number(<CorElementType>index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotNetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetObject>result_obj
    result = array_obj._get_item(index_val)
    if result.tag == CorElementType.ELEMENT_TYPE_END:
        raise net_exceptions.EmulatorExecutionException(emu, 'Error ldelem element')
    if not net_utils.is_cortype_number(<CorElementType>result.tag):
        raise net_exceptions.OperationNotSupportedException()
    casted = emu.cast_cell(result, net_sigs.get_CorSig_Int64())
    emu.stack.append(casted)
    emu.dealloc_cell(index)
    emu.dealloc_cell(arr)
    emu.dealloc_cell(result)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_ldelem_r4_instruction(DotNetEmulator emu):
    """ Performs ldelem.r4 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: An invalid instruction operand was popped off the stack.
    
    """
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef StackCell casted = emu.cast_cell(index, net_sigs.get_CorSig_Int64())
    cdef int64_t index_val = casted.item.i8
    cdef net_emu_types.DotNetArray array_obj = None
    cdef StackCell result
    emu.dealloc_cell(casted)
    if not net_utils.is_cortype_number(<CorElementType>index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotNetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetObject>result_obj
    result = array_obj._get_item(index_val)
    if result.tag == CorElementType.ELEMENT_TYPE_END:
        raise net_exceptions.EmulatorExecutionException(emu, 'Error ldelem element')
    if not net_utils.is_cortype_number(<CorElementType>result.tag):
        raise net_exceptions.OperationNotSupportedException()
    casted = emu.cast_cell(result, net_sigs.get_CorSig_Single())
    emu.stack.append(casted)
    emu.dealloc_cell(index)
    emu.dealloc_cell(arr)
    emu.dealloc_cell(result)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_ldelem_r8_instruction(DotNetEmulator emu):
    """ Performs ldelem.r8 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: An invalid instruction operand was popped off the stack.
    
    """
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef StackCell casted = emu.cast_cell(index, net_sigs.get_CorSig_Int64())
    cdef int64_t index_val = casted.item.i8
    cdef net_emu_types.DotNetArray array_obj = None
    cdef StackCell result
    emu.dealloc_cell(casted)
    if not net_utils.is_cortype_number(<CorElementType>index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotNetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetObject>result_obj
    result = array_obj._get_item(index_val)
    if result.tag == CorElementType.ELEMENT_TYPE_END:
        raise net_exceptions.EmulatorExecutionException(emu, 'Error ldelem element')
    if not net_utils.is_cortype_number(<CorElementType>result.tag):
        raise net_exceptions.OperationNotSupportedException()
    casted = emu.cast_cell(result, net_sigs.get_CorSig_Double())
    emu.stack.append(casted)
    emu.dealloc_cell(index)
    emu.dealloc_cell(arr)
    emu.dealloc_cell(result)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_ldc_i4_instruction(DotNetEmulator emu):
    """ Performs ldc.i4 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    """
    cdef StackCell cell = emu.pack_i4(emu.instr.get_argument())
    emu.stack.append(cell)
    emu.dealloc_cell(cell)
    return False

cdef bint handle_ldc_i8_instruction(DotNetEmulator emu):
    """ Performs ldc.i8 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    """
    cdef StackCell cell = emu.pack_i8(emu.instr.get_argument())
    emu.stack.append(cell)
    emu.dealloc_cell(cell)
    return False

cdef bint handle_ldc_r4_instruction(DotNetEmulator emu):
    """ Performs ldc.r4 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell cell = emu.pack_r4(emu.instr.get_argument())
    emu.stack.append(cell)
    emu.dealloc_cell(cell)
    return False

cdef bint handle_ldc_r8_instruction(DotNetEmulator emu):
    """ Performs ldc.r8 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell cell = emu.pack_r8(emu.instr.get_argument())
    emu.stack.append(cell)
    emu.dealloc_cell(cell)
    return False

cdef bint handle_ldloc_instruction(DotNetEmulator emu):
    """ Performs ldloc instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef int index = emu.instr.get_argument()
    cdef StackCell local_obj = emu.get_local(index)
    emu.stack.append(local_obj)
    emu.dealloc_cell(local_obj)
    return False

cdef bint handle_beq_instruction(DotNetEmulator emu):
    """ Performs beq instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    if emu.cell_is_equal(value1, value2):
        emu.dealloc_cell(value2)
        emu.dealloc_cell(value1)
        return handle_general_jump(emu)
    emu.dealloc_cell(value2)
    emu.dealloc_cell(value1)
    return False

cdef bint handle_bge_instruction(DotNetEmulator emu):
    """ Performs bge instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell val2 = emu.convert_signed(value2)
    cdef StackCell val1 = emu.convert_signed(value1)
    if emu.cell_is_ge(val1, val2):
        emu.dealloc_cell(value2)
        emu.dealloc_cell(value1)
        emu.dealloc_cell(val1)
        emu.dealloc_cell(val2)
        return handle_general_jump(emu)
    emu.dealloc_cell(value2)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(val1)
    emu.dealloc_cell(val2)
    return False

cdef bint handle_bge_un_instruction(DotNetEmulator emu):
    """ Performs bge.un instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell val2 = emu.stack.pop()
    cdef StackCell val1 = emu.stack.pop()
    cdef StackCell value2 = emu.convert_unsigned(val2)
    cdef StackCell value1 = emu.convert_unsigned(val1)
    if emu.cell_is_ge(value1, value2):
        emu.dealloc_cell(value2)
        emu.dealloc_cell(value1)
        return handle_general_jump(emu)
    emu.dealloc_cell(value2)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(val2)
    emu.dealloc_cell(val1)
    return False

cdef bint handle_bgt_instruction(DotNetEmulator emu):
    """ Performs bgt instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell val2 = emu.convert_signed(value2)
    cdef StackCell val1 = emu.convert_signed(value1)
    if emu.cell_is_gt(val1, val2):
        emu.dealloc_cell(value2)
        emu.dealloc_cell(value1)
        emu.dealloc_cell(val2)
        emu.dealloc_cell(val1)
        return handle_general_jump(emu)
    emu.dealloc_cell(value2)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(val2)
    emu.dealloc_cell(val1)
    return False

cdef bint handle_bgt_un_instruction(DotNetEmulator emu):
    """ Performs bgt.un instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    handle_cgt_un_instruction(emu)
    return handle_brtrue_instruction(emu)

cdef bint handle_div_instruction(DotNetEmulator emu):
    """ Performs div instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell result = emu.cell_divide(value1, value2)
    emu.stack.append(result)
    emu.dealloc_cell(value2)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(result)
    return False

cdef bint handle_div_un_instruction(DotNetEmulator emu):
    """ Performs div.un instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell val2 = emu.convert_unsigned(value2)
    cdef StackCell val1 = emu.convert_unsigned(value1)
    cdef StackCell result = emu.cell_divide(val1, val2)
    emu.stack.append(result)
    emu.dealloc_cell(value2)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(val1)
    emu.dealloc_cell(val2)
    emu.dealloc_cell(result)
    return False

cdef bint handle_dup_instruction(DotNetEmulator emu):
    """ Performs dup instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell dup_obj = emu.duplicate_cell(value1)
    emu.stack.append(value1)
    emu.stack.append(dup_obj)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(dup_obj)
    return False

cdef bint handle_ldsfld_instruction(DotNetEmulator emu):
    """ Performs ldsfld instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.ObjectTypeException: Attempted to call ldsfld on a non static field.
        net_exceptions.EmulatorExecutionException: General error executing the instruction, likely wrong item popped off stack.
        net_exceptions.OperationNotSupportedException: Could not get the static variable, likely internal error.
    """
    cdef net_row_objects.RowObject field_obj = emu.instr.get_argument()
    cdef net_row_objects.TypeDefOrRef parent_type = field_obj.get_parent_type()
    cdef net_row_objects.MethodDef cctor_method
    cdef list args
    cdef str field_name
    cdef str type_name
    cdef type type_obj
    cdef net_sigs.FieldSig sig
    cdef net_row_objects.Field field
    cdef StackCell current_obj
    # check if the cctor has been executed.
    if isinstance(parent_type, net_row_objects.TypeSpec):
        parent_type = parent_type.get_type()
    cctor_method = parent_type.get_static_constructor()
    if cctor_method:
        if emu.executed_cctors.can_execute(cctor_method) and not emu.dont_execute_cctor:
            new_emu = emu.spawn_new_emulator(cctor_method, caller=emu)
            new_emu._allocate_params(0)
            new_emu.run_function()
    if isinstance(field_obj, net_row_objects.MemberRef):
        current_obj = do_virt_field_lookup(emu, emu.pack_blanktag())
        if current_obj.tag == CorElementType.ELEMENT_TYPE_END:
            raise net_exceptions.EmulatorExecutionException(emu, 'Error with ldsfld virt lookup')
        emu.stack.append(current_obj)
    else:
        if not field_obj.is_static():
            raise net_exceptions.ObjectTypeException
        current_obj = emu.get_appdomain().get_static_field(field_obj.get_rid())
        if current_obj.tag == CorElementType.ELEMENT_TYPE_END:
            raise net_exceptions.OperationNotSupportedException()
        emu.stack.append(current_obj)
    emu.dealloc_cell(current_obj)
    return False

cdef bint handle_ldstr_instruction(DotNetEmulator emu):
    """ Performs ldstr instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef net_emu_types.DotNetString string_obj = net_emu_types.DotNetString(emu, emu.instr.get_argument(), 'utf-16le')
    cdef StackCell cell = emu.pack_string(string_obj)
    emu.stack.append(cell)
    emu.dealloc_cell(cell)
    return False

cdef bint handle_ldtoken_instruction(DotNetEmulator emu):
    """ Performs ldtoken instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.EmulatorExecutionException: The token type is not currently supported by the instruction.
    """
    cdef net_row_objects.RowObject internal_item = emu.instr.get_argument()
    cdef str table_name = internal_item.get_table_name()
    cdef StackCell cell
    if table_name == 'MethodDef' or  table_name == 'MethodRef':
        cell = emu.pack_object(net_emu_types.DotNetRuntimeMethodHandle(emu, internal_item))
    elif  table_name == 'Field':
        cell = emu.pack_object(net_emu_types.DotNetRuntimeFieldHandle(emu, internal_item))
    elif table_name == 'TypeDef' or table_name == 'TypeRef' or table_name == 'TypeSpec':
        cell = emu.pack_object(net_emu_types.DotNetRuntimeTypeHandle(emu, internal_item))
    else:
        raise net_exceptions.EmulatorExecutionException(emu, 'invalid table {}'.format(table_name)) #Invalid table
    emu.stack.append(cell)
    emu.dealloc_cell(cell)
    return False

cdef net_row_objects.MethodDef resolve_ref(net_row_objects.MemberRef ref_obj):
    """ Helper for ldftn instruction, Needs to be reworked a bit.  Supposed to resolve memberref methods to their proper methoddefs.
        With the new signature changes, going to need to better account for generics.

    Args:
        ref_obj (net_row_objects.MemberRef): The memberref object to resolve.

    Returns:
        net_row_objects.MethodDef: The resolved methoddef or None if not found.
    """
    cdef net_sigs.MethodSig ref_sig = ref_obj.get_method_signature()
    cdef net_row_objects.TypeDefOrRef parent_type = ref_obj.get_parent_type().get_type()
    cdef net_row_objects.MethodDef mdef = None
    if not isinstance(parent_type, net_row_objects.TypeDef):
        return None
    for mdef in parent_type.get_methods():
        if mdef.get_name() == ref_obj.get_name():
            if mdef.get_method_signature() == ref_sig:
                return mdef
    return None

cdef bint handle_ldftn_instruction(DotNetEmulator emu):
    """ Performs ldftn instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.EmulatorExecutionException: Couldnt find method object if the argument is MemberRef (needs to be fixed.) or invalid token table.
    
    """
    cdef net_row_objects.RowObject internal_item = emu.instr.get_argument()
    cdef str table_name = internal_item.get_table_name()
    cdef StackCell cell
    if table_name == 'MethodDef' or  table_name == 'MethodRef':
        cell = emu.pack_object(net_emu_types.DotNetRuntimeMethodHandle(emu, internal_item))
    elif table_name == 'MemberRef':
        internal_item = resolve_ref(internal_item)
        if internal_item is None:
            raise net_exceptions.EmulatorExecutionException(emu, 'Could not find method obj for ldftn')
        cell = emu.pack_object(net_emu_types.DotNetRuntimeMethodHandle(emu, internal_item))
    else:
        raise net_exceptions.EmulatorExecutionException(emu, 'invalid table {}'.format(table_name)) #Invalid table
    emu.stack.append(cell)
    emu.dealloc_cell(cell)
    return False

cdef bint handle_mul_instruction(DotNetEmulator emu):
    """ Performs mul instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell result = emu.cell_multiply(value1, value2)
    emu.stack.append(result)
    emu.dealloc_cell(value2)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(result)
    return False

cdef bint handle_neg_instruction(DotNetEmulator emu):
    """ Performs neg instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell result = emu.cell_neg(value1)
    emu.stack.append(result)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(result)
    return False

cdef bint handle_newarr_instruction(DotNetEmulator emu):
    """ Performs newarr instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef net_row_objects.TypeDefOrRef type_obj = emu.instr.get_argument()
    cdef StackCell amt_of_elem = emu.stack.pop()
    cdef int64_t elem_val = amt_of_elem.item.i8
    cdef net_emu_types.DotNetArray value1 = net_emu_types.DotNetArray(emu, elem_val, type_obj)
    cdef StackCell result = emu.pack_object(value1)
    emu.stack.append(result)
    emu.dealloc_cell(amt_of_elem)
    emu.dealloc_cell(result)
    return False

cdef bint handle_ble_instruction(DotNetEmulator emu):
    """ Performs ble instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell val2 = emu.convert_signed(value2)
    cdef StackCell val1 = emu.convert_signed(value1)
    if emu.cell_is_le(val1, val2):
        emu.dealloc_cell(value1)
        emu.dealloc_cell(value2)
        emu.dealloc_cell(val1)
        emu.dealloc_cell(val2)
        return handle_general_jump(emu)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(value2)
    emu.dealloc_cell(val1)
    emu.dealloc_cell(val2)
    return False

cdef bint handle_ble_un_instruction(DotNetEmulator emu):
    """ Performs ble.un instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell val2 = emu.stack.pop()
    cdef StackCell val1 = emu.stack.pop()
    cdef StackCell value2 = emu.convert_unsigned(val2)
    cdef StackCell value1 = emu.convert_unsigned(val1)
    if emu.cell_is_le(value1, value2):
        emu.dealloc_cell(value1)
        emu.dealloc_cell(value2)
        return handle_general_jump(emu)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(value2)
    emu.dealloc_cell(val2)
    emu.dealloc_cell(val1)
    return False

cdef bint handle_blt_instruction(DotNetEmulator emu):
    """ Performs blt instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell val2 = emu.convert_signed(value2)
    cdef StackCell val1 = emu.convert_signed(value1)
    if emu.cell_is_lt(val1, val2):
        emu.dealloc_cell(value1)
        emu.dealloc_cell(value2)
        emu.dealloc_cell(val1)
        emu.dealloc_cell(val2)
        return handle_general_jump(emu)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(value2)
    emu.dealloc_cell(val1)
    emu.dealloc_cell(val2)
    return False

cdef bint handle_blt_un_instruction(DotNetEmulator emu):
    """ Performs blt.un instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    handle_clt_un_instruction(emu)
    return handle_brtrue_instruction(emu)

cdef bint handle_bne_un_instruction(DotNetEmulator emu):
    """ Performs bne.un instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell val1 = emu.convert_unsigned(value1)
    cdef StackCell val2 = emu.convert_unsigned(value2)
    cdef StackCell result
    if emu.cell_is_equal(val1, val2):
        result = emu.pack_i4(1)
    else:
        result = emu.pack_i4(0)
    emu.stack.append(result)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(value2)
    emu.dealloc_cell(result)
    emu.dealloc_cell(val1)
    emu.dealloc_cell(val2)
    return handle_brfalse_instruction(emu)

cdef bint handle_ldfld_instruction(DotNetEmulator emu):
    """ Performs ldfld instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.

    Raises:
        net_exceptions.OperationNotSupportedException: An invalid item was popped off the stack (not an object)
        net_exceptions.InvalidArgumentsException: The item popped off the stack wasnt a slim object.  Non slim objects with fields have been replaced and will be removed.
    """
    cdef net_row_objects.Field field_obj = emu.instr.get_argument()
    cdef StackCell orig_cell = emu.stack.pop()
    cdef StackCell obj_ref = emu.get_ref(orig_cell)
    cdef net_emu_types.DotNetObject dot_obj = None
    cdef StackCell cell
    if obj_ref.tag != CorElementType.ELEMENT_TYPE_OBJECT:
        raise net_exceptions.OperationNotSupportedException()
    if obj_ref.is_slim_object:
        cell = emu.get_slimobj_field(obj_ref, field_obj.get_rid())
    else:
        raise net_exceptions.InvalidArgumentsException()
    emu.stack.append(cell)
    emu.dealloc_cell(cell)
    emu.dealloc_cell(orig_cell)
    emu.dealloc_cell(obj_ref)
    return False

cdef bint handle_or_instruction(DotNetEmulator emu):
    """ Performs or instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell result = emu.cell_or(value1, value2)
    emu.stack.append(result)
    emu.dealloc_cell(value2)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(result)
    return False

cdef bint handle_not_instruction(DotNetEmulator emu):
    """ Performs not instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell result = emu.cell_not(value1)
    emu.stack.append(result)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(result)
    return False

cdef bint handle_ret_instruction(DotNetEmulator emu):
    """ Performs ret instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value1
    memset(&value1, 0x0, sizeof(value1))
    if emu.method_obj.has_return_value():
        if emu.caller:
            value1 = emu.stack.pop()
            emu.caller.stack.append(value1)
    else:
        if emu.method_obj.get_name() == b'.ctor':
            if emu.caller:
                value1 = emu.get_method_param(0)
                emu.caller.stack.append(value1)
    if value1.tag != CorElementType.ELEMENT_TYPE_END:
        emu.dealloc_cell(value1)
    return False

cdef bint handle_shl_instruction(DotNetEmulator emu):
    """ Performs shl instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell bits = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell result = emu.cell_shl(value1, bits)
    emu.stack.append(result)
    emu.dealloc_cell(bits)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(result)
    return False

cdef bint handle_shr_instruction(DotNetEmulator emu):
    """ Performs shr instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell bits = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell result = emu.cell_shr(value1, bits)
    emu.stack.append(result)
    emu.dealloc_cell(bits)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(result)
    return False

cdef bint handle_shr_un_instruction(DotNetEmulator emu):
    """ Performs shr.un instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell bits1 = emu.stack.pop()
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.convert_unsigned(value2)
    cdef StackCell result = emu.cell_shr(value1, bits1)
    emu.stack.append(result)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(result)
    emu.dealloc_cell(bits1)
    emu.dealloc_cell(value2)
    return False

cdef bint handle_stfld_instruction(DotNetEmulator emu):
    """ Performs stfld instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.

    Raises:
        net_exceptions.OperationNotSupportedException: Popped an invalid item off the stack (not an object)
        net_exceptions.InvalidArgumentsException: Popped an invalid item off the stack (not a slim object, non slim fields have been removed.)
    """
    cdef net_row_objects.Field field_obj = emu.instr.get_argument()
    cdef net_sigs.TypeSig local_type_sig
    cdef net_structs.CorElementType e_type
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell orig_cell = emu.stack.pop()
    cdef StackCell obj_ref = emu.get_ref(orig_cell)
    cdef net_emu_types.DotNetObject dot_obj = None
    cdef StackCell deref_cell
    if obj_ref.tag != CorElementType.ELEMENT_TYPE_OBJECT or field_obj.is_static():
        raise net_exceptions.OperationNotSupportedException()
    local_type_sig = field_obj.get_field_signature().get_type_sig()
    if obj_ref.is_slim_object:
        emu.set_slimobj_field(obj_ref, field_obj.get_rid(), value1)
    else:
        raise net_exceptions.InvalidArgumentsException()
    emu.dealloc_cell(orig_cell)
    emu.dealloc_cell(obj_ref)
    emu.dealloc_cell(value1)
    return False

cdef bint handle_stloc_instruction(DotNetEmulator emu):
    """ Performs stloc instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef int number = emu.instr.get_argument()
    cdef StackCell value1 = emu.stack.pop()
    emu.set_local(number, value1)
    emu.dealloc_cell(value1)
    return False

cdef StackCell do_virt_field_lookup(DotNetEmulator emu, StackCell set_val):
    """ Supposed to perform a virtual field lookup for when the field is being referenced by a MemberRef, but needs to be reworked a bit
        to account for new changes.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the operation on.
        set_val (net_emu_structs.StackCell): The value to set if its a stsfld instr.

    Returns:
        net_emu_structs.StackCell: The target stackcell value if its a ldsfld instr.

    Raises:
        net_exceptions.EmulatorExecutionException: general error.
        net_exceptions.FeatureNotImplementedException: Need to rework this function a bit.
    """
    cdef net_row_objects.MemberRef ref_obj = emu.instr.get_argument()
    cdef static_func_type static_func = NULL
    cdef StackCell current_obj
    cdef net_row_objects.TypeDefOrRef parent_type = None
    cdef net_row_objects.Field field_obj = None
    cdef net_row_objects.Field field_obj2 = None
    cdef net_sigs.TypeSig sig_obj = None
    cdef net_row_objects.ColumnValue col_val = None
    cdef DotNetEmulator new_emu = None
    cdef net_row_objects.MethodDef cctor_method = None
    cdef net_sigs.FieldSig field_sig = None
    cdef bint fsig_equal = False
    cdef net_row_objects.TypeSpec tspec = None
    cdef bint was_set = False
    if emu.get_appdomain().has_static_func(ref_obj.get_token()):
        if set_val.tag != CorElementType.ELEMENT_TYPE_END:
            raise net_exceptions.EmulatorExecutionException(emu, 'Erorr invalid state')
        static_func = emu.get_appdomain().get_static_func(ref_obj.get_token())
        if static_func == NULL:
            raise net_exceptions.EmulatorExecutionException(emu, 'Error NULL ptr for static field ref')
    
        current_obj = static_func(emu.get_appdomain(), NULL, 0)
        return current_obj
    else:
        #Okay so heres our generic inst sig

        parent_type = ref_obj.get_parent_type()
        if not isinstance(parent_type, net_row_objects.TypeSpec):
            raise net_exceptions.EmulatorExecutionException(emu, 'Attempted to do a virt field lookup when the parent isnt a typespec.')
        if parent_type is None:
            return emu.pack_blanktag()
        tspec = <net_row_objects.TypeSpec>parent_type
        col_val = tspec.get_type().get_column('FieldList')
        if col_val is None:
            return emu.pack_blanktag()
        was_set = False
        for field_obj in col_val.get_formatted_value():
            if ref_obj.get_name().startswith(field_obj.get_column('Name').get_value_as_bytes()):
                field_sig = field_obj.get_field_signature()
                if emu.spec_obj is None:
                    fsig_equal = net_sigs.field_sig_compare(field_sig, ref_obj.get_method_signature(), None, tspec.get_sig_obj())
                else:
                    fsig_equal = net_sigs.field_sig_compare(field_sig, ref_obj.get_method_signature(), emu.spec_obj.get_sig_obj(), tspec.get_sig_obj())
                if fsig_equal:
                    cctor_method = tspec.get_type().get_static_constructor()
                    if cctor_method:
                        if emu.executed_cctors.can_execute(cctor_method) and not emu.dont_execute_cctor:
                            new_emu = emu.spawn_new_emulator(cctor_method, caller=emu)
                            new_emu.setup_method_params([])
                            new_emu.run_function()
                    if set_val.tag == CorElementType.ELEMENT_TYPE_END:
                        current_obj = emu.get_appdomain().get_static_field(field_obj.get_rid())
                        return current_obj
                    else:
                        emu.get_appdomain().set_static_field(field_obj.get_rid(), set_val)
                        was_set = True
                        break
    if not was_set:
        raise net_exceptions.EmulatorExecutionException(emu, 'Attempted to get or set a virtual field but nothing was actually done.')
    return emu.pack_blanktag()

cdef bint handle_stsfld_instruction(DotNetEmulator emu):
    """ Performs stslfd instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef net_row_objects.RowObject field_obj = emu.instr.get_argument()
    cdef StackCell value1 = emu.stack.pop()
    if isinstance(field_obj, net_row_objects.MemberRef):
        do_virt_field_lookup(emu, value1)
    else:
        emu.get_appdomain().set_static_field(field_obj.get_rid(), value1)
    emu.dealloc_cell(value1)
    return False

cdef bint handle_sub_instruction(DotNetEmulator emu):
    """ Performs sub instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell result = emu.cell_sub(value1, value2)
    emu.stack.append(result)
    emu.dealloc_cell(value2)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(result)
    return False

cdef bint handle_switch_instruction(DotNetEmulator emu):
    """ Performs switch instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef list targets = emu.instr.get_argument()
    cdef StackCell value1 = emu.stack.pop()
    if 0 <= value1.item.i4 < len(targets):
        emu.current_offset = targets[value1.item.i4]
        emu.current_eip = emu.disasm_obj.get_instr_index_by_offset(emu.current_offset)
        emu.dealloc_cell(value1)
        return True
    else:
        #fallthrough case.  No exception here.
        emu.dealloc_cell(value1)
        return False

cdef bint handle_xor_instruction(DotNetEmulator emu):
    """ Performs xor instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell result = emu.cell_xor(value1, value2)
    emu.stack.append(result)
    emu.dealloc_cell(result)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(value2)
    return False

cdef bint handle_stelem_instruction(DotNetEmulator emu):
    """ Performs stelem instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.

    Raises:
        net_exceptions.OperationNotSupportedException: Popped an invalid item (not an object or not an array) off the stack.
    """
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef StackCell casted = emu.cast_cell(index, net_sigs.get_CorSig_Int64())
    cdef int64_t index_val = casted.item.i8
    cdef net_emu_types.DotNetArray array_obj = None
    emu.dealloc_cell(casted)
    if not net_utils.is_cortype_number(<CorElementType>index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT:
        raise net_exceptions.OperationNotSupportedException()
    if not isinstance(<net_emu_types.DotNetObject>arr.item.ref, net_emu_types.DotNetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetArray>arr.item.ref
    array_obj._set_item(index_val, value1)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(index)
    emu.dealloc_cell(arr)
    return False

cdef bint handle_stelem_i_instruction(DotNetEmulator emu):
    """ Performs stelem.i instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.

    Raises:
        net_exceptions.OperationNotSupportedException: Popped an invalid item (not an object or not an array) off the stack.
    """
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef StackCell casted = emu.cast_cell(index, net_sigs.get_CorSig_Int64())
    cdef int64_t index_val = casted.item.i8
    cdef net_emu_types.DotNetArray array_obj = None
    emu.dealloc_cell(casted)
    if not net_utils.is_cortype_number(<CorElementType>index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT:
        raise net_exceptions.OperationNotSupportedException()
    if not isinstance(<net_emu_types.DotNetObject>arr.item.ref, net_emu_types.DotNetArray) or not net_utils.is_cortype_number(<CorElementType>value1.tag):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetArray>arr.item.ref
    casted = emu.cast_cell(value1, net_sigs.get_CorSig_IntPtr())
    array_obj._set_item(index_val, casted)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(index)
    emu.dealloc_cell(arr)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_stelem_i1_instruction(DotNetEmulator emu):
    """ Performs stelem.i1 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.

    Raises:
        net_exceptions.OperationNotSupportedException: Popped an invalid item (not an object or not an array) off the stack.
    """
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef StackCell casted = emu.cast_cell(index, net_sigs.get_CorSig_Int64())
    cdef int64_t index_val = casted.item.i8
    cdef net_emu_types.DotNetArray array_obj = None
    emu.dealloc_cell(casted)
    if not net_utils.is_cortype_number(<CorElementType>index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT:
        raise net_exceptions.OperationNotSupportedException()
    if not isinstance(<net_emu_types.DotNetObject>arr.item.ref, net_emu_types.DotNetArray) or not net_utils.is_cortype_number(<CorElementType>value1.tag):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetArray>arr.item.ref
    casted = emu.cast_cell(value1, net_sigs.get_CorSig_SByte())
    array_obj._set_item(index_val, casted)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(index)
    emu.dealloc_cell(arr)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_stelem_i2_instruction(DotNetEmulator emu):
    """ Performs stelem.i2 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.

    Raises:
        net_exceptions.OperationNotSupportedException: Popped an invalid item (not an object or not an array) off the stack.
    """
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef StackCell casted = emu.cast_cell(index, net_sigs.get_CorSig_Int64())
    cdef int64_t index_val = casted.item.i8
    cdef net_emu_types.DotNetArray array_obj = None
    emu.dealloc_cell(casted)
    if not net_utils.is_cortype_number(<CorElementType>index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT:
        raise net_exceptions.OperationNotSupportedException()
    if not isinstance(<net_emu_types.DotNetObject>arr.item.ref, net_emu_types.DotNetArray) or not net_utils.is_cortype_number(<CorElementType>value1.tag):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetArray>arr.item.ref
    casted = emu.cast_cell(value1, net_sigs.get_CorSig_Int16())
    array_obj._set_item(index_val, casted)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(index)
    emu.dealloc_cell(arr)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_stelem_i4_instruction(DotNetEmulator emu):
    """ Performs stelem.i4 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.

    Raises:
        net_exceptions.OperationNotSupportedException: Popped an invalid item (not an object or not an array) off the stack.
    """
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef StackCell casted = emu.cast_cell(index, net_sigs.get_CorSig_Int64())
    cdef int64_t index_val = casted.item.i8
    cdef net_emu_types.DotNetArray array_obj = None
    emu.dealloc_cell(casted)
    if not net_utils.is_cortype_number(<CorElementType>index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT:
        raise net_exceptions.OperationNotSupportedException()
    if not isinstance(<net_emu_types.DotNetObject>arr.item.ref, net_emu_types.DotNetArray) or not net_utils.is_cortype_number(<CorElementType>value1.tag):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetArray>arr.item.ref
    casted = emu.cast_cell(value1, net_sigs.get_CorSig_Int32())
    array_obj._set_item(index_val, casted)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(index)
    emu.dealloc_cell(arr)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_stelem_i8_instruction(DotNetEmulator emu):
    """ Performs stelem.i8 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.

    Raises:
        net_exceptions.OperationNotSupportedException: Popped an invalid item (not an object or not an array) off the stack.
    """
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef StackCell casted = emu.cast_cell(index, net_sigs.get_CorSig_Int64())
    cdef int64_t index_val = casted.item.i8
    cdef net_emu_types.DotNetArray array_obj = None
    emu.dealloc_cell(casted)
    if not net_utils.is_cortype_number(<CorElementType>index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT:
        raise net_exceptions.OperationNotSupportedException()
    if not isinstance(<net_emu_types.DotNetObject>arr.item.ref, net_emu_types.DotNetArray) or not net_utils.is_cortype_number(<CorElementType>value1.tag):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetArray>arr.item.ref
    casted = emu.cast_cell(value1, net_sigs.get_CorSig_Int64())
    array_obj._set_item(index_val, casted)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(index)
    emu.dealloc_cell(arr)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_stelem_r4_instruction(DotNetEmulator emu):
    """ Performs stelem.r4 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.

    Raises:
        net_exceptions.OperationNotSupportedException: Popped an invalid item (not an object or not an array) off the stack.
    """
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef StackCell casted = emu.cast_cell(index, net_sigs.get_CorSig_Int64())
    cdef int64_t index_val = casted.item.i8
    cdef net_emu_types.DotNetArray array_obj = None
    emu.dealloc_cell(casted)
    if not net_utils.is_cortype_number(<CorElementType>index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT:
        raise net_exceptions.OperationNotSupportedException()
    if not isinstance(<net_emu_types.DotNetObject>arr.item.ref, net_emu_types.DotNetArray) or not net_utils.is_cortype_number(<CorElementType>value1.tag):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetArray>arr.item.ref
    casted = emu.cast_cell(value1, net_sigs.get_CorSig_Single())
    array_obj._set_item(index_val, casted)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(index)
    emu.dealloc_cell(arr)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_stelem_r8_instruction(DotNetEmulator emu):
    """ Performs stelem.r8 instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.

    Raises:
        net_exceptions.OperationNotSupportedException: Popped an invalid item (not an object or not an array) off the stack.
    """
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef StackCell casted = emu.cast_cell(index, net_sigs.get_CorSig_Int64())
    cdef int64_t index_val = casted.item.i8
    cdef net_emu_types.DotNetArray array_obj = None
    emu.dealloc_cell(casted)
    if not net_utils.is_cortype_number(<CorElementType>index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT:
        raise net_exceptions.OperationNotSupportedException()
    if not isinstance(<net_emu_types.DotNetObject>arr.item.ref, net_emu_types.DotNetArray) or not net_utils.is_cortype_number(<CorElementType>value1.tag):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetArray>arr.item.ref
    casted = emu.cast_cell(value1, net_sigs.get_CorSig_Double())
    array_obj._set_item(index_val, casted)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(index)
    emu.dealloc_cell(arr)
    emu.dealloc_cell(casted)
    return False

cdef bint handle_rem_instruction(DotNetEmulator emu):
    """ Performs rem instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell result = emu.cell_rem(value1, value2)
    emu.stack.append(result)
    emu.dealloc_cell(result)
    emu.dealloc_cell(value2)
    emu.dealloc_cell(value1)
    return False

cdef bint handle_rem_un_instruction(DotNetEmulator emu):
    """ Performs rem.un instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell val2 = emu.convert_unsigned(value2)
    cdef StackCell val1 = emu.convert_unsigned(value1)
    cdef StackCell result = emu.cell_rem(val1, val2)
    emu.stack.append(result)
    emu.dealloc_cell(value2)
    emu.dealloc_cell(value1)
    emu.dealloc_cell(val2)
    emu.dealloc_cell(val1)
    emu.dealloc_cell(result)
    return False

cdef bint handle_ldelema_instruction(DotNetEmulator emu):
    """ Performs ldelema instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: an invalid itme was popped off the stack (not a object or array)
    """
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef uint64_t idx = index.item.u8
    cdef net_emu_types.DotNetArray array_obj = None
    cdef StackCell result
    if not net_utils.is_cortype_number(<CorElementType>index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT:
        raise net_exceptions.OperationNotSupportedException()
    if arr.is_slim_object or arr.item.ref == NULL or not isinstance(<net_emu_types.DotNetObject>arr.item.ref, net_emu_types.DotNetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetArray>arr.item.ref
    result = emu.pack_ref(3, idx, <void*><PyObject*>array_obj)
    emu.stack.append(result)
    emu.dealloc_cell(result)
    emu.dealloc_cell(arr)
    emu.dealloc_cell(index)
    return False

cdef bint handle_box_instruction(DotNetEmulator emu):
    """ Performs box instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef net_row_objects.TypeDefOrRef arg_obj = emu.instr.get_argument()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell result = emu.box_value(value1, None) #TODO: should this be None?
    emu.stack.append(result)
    emu.dealloc_cell(result)
    emu.dealloc_cell(value1)
    return False

cdef bint handle_castclass_instruction(DotNetEmulator emu):
    """ Performs castclass instruction.

        In the contexts that ive seen it used so far I dont see the need to do anything, but that may change.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    return False

cdef bint handle_initobj_instruction(DotNetEmulator emu):
    """ Performs initobj instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef net_row_objects.TypeDefOrRef type_obj = emu.instr.get_argument()
    cdef StackCell orig_cell = emu.stack.pop()
    cdef StackCell obj_ref = emu.get_ref(orig_cell)
    cdef StackCell result
    cdef net_emu_types.DotNetObject dot_obj = None
    if orig_cell.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.InvalidArgumentsException()
    if obj_ref.tag != CorElementType.ELEMENT_TYPE_OBJECT and obj_ref.tag != CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.ObjectTypeException
    if not obj_ref.is_slim_object:
        dot_obj = <net_emu_types.DotNetObject>obj_ref.item.ref
        dot_obj.initialize_type(type_obj)
    emu.set_ref(orig_cell, obj_ref)
    emu.dealloc_cell(orig_cell)
    emu.dealloc_cell(obj_ref)
    return False

cdef bint handle_isinst_instruction(DotNetEmulator emu):
    """ Performs isinst instruction.
        This function is currently not supported.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef net_row_objects.TypeDefOrRef arg = emu.instr.get_argument()
    cdef StackCell cell = emu.stack.pop()
    cdef net_emu_types.DotNetObject dnobj = None
    cdef StackCell result
    if cell.is_slim_object or (cell.tag != CorElementType.ELEMENT_TYPE_OBJECT and cell.tag != CorElementType.ELEMENT_TYPE_STRING) or cell.item.ref == NULL:
        raise net_exceptions.FeatureNotImplementedException()
    
    dnobj = <net_emu_types.DotNetObject>cell.item.ref
    if dnobj.isinst(arg):
        emu.stack.append(cell)
    else:
        result = emu.pack_null()
        emu.stack.append(result)
        emu.dealloc_cell(result)
    emu.dealloc_cell(cell)
    return False
    
cdef bint handle_ldflda_instruction(DotNetEmulator emu):
    """ Performs ldflda instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: Invalid item popped off the stack.
    """
    cdef net_row_objects.Field field_obj = emu.instr.get_argument()
    cdef StackCell obj_ref = emu.stack.pop()
    cdef StackCell result
    cdef SlimObject* obj = NULL
    if obj_ref.tag != CorElementType.ELEMENT_TYPE_OBJECT or field_obj.is_static() or not obj_ref.is_slim_object:
        raise net_exceptions.OperationNotSupportedException()
    obj = <SlimObject*>obj_ref.item.slim_object
    result = emu.pack_ref(4, field_obj.get_rid(), <void*>obj)
    emu.stack.append(result)
    emu.dealloc_cell(result)
    emu.dealloc_cell(obj_ref)
    return False

cdef bint handle_ldlen_instruction(DotNetEmulator emu):
    """ Performs ldlen instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: invalid item popped off the stack.
    """
    cdef StackCell value_obj = emu.stack.pop()
    cdef StackCell result
    cdef net_emu_types.DotNetObject obj = None
    if value_obj.tag != CorElementType.ELEMENT_TYPE_OBJECT or value_obj.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    obj = <net_emu_types.DotNetObject> value_obj.item.ref
    result = emu.pack_u8(len(obj))
    emu.stack.append(result)
    emu.dealloc_cell(result)
    emu.dealloc_cell(value_obj)
    return False

cdef bint handle_ldloca_instruction(DotNetEmulator emu):
    """ Performs ldloca instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef int index = emu.instr.get_argument()
    cdef StackCell result = emu.pack_ref(1, index, <void*><PyObject*>emu)
    emu.stack.append(result)
    emu.dealloc_cell(result)
    return False

cdef bint handle_ldsflda_instruction(DotNetEmulator emu):
    """ Performs ldsflda instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.FeatureNotImplementedException: Currently ldsflda on MemberRefs needs to be implemented.  Currently unsupported.
    """
    cdef net_row_objects.RowObject arg_obj = emu.instr.get_argument()
    cdef net_row_objects.Field field_obj = <net_row_objects.Field>arg_obj
    cdef StackCell cell
    if isinstance(arg_obj, net_row_objects.MemberRef):
        raise net_exceptions.FeatureNotImplementedException()
    else:
        cell = emu.pack_ref(2, field_obj.get_rid(), <void*><PyObject*>emu)
        emu.stack.append(cell)
        emu.dealloc_cell(cell)
    return False

cdef bint handle_ldobj_instruction(DotNetEmulator emu):
    """ Performs ldobj instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: Item popped off the stack was not a ELEMENT_TYPE_BYREF
    """
    cdef StackCell addr_obj = emu.stack.pop()
    cdef StackCell result
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    result = emu.get_ref(addr_obj)
    emu.stack.append(result)
    emu.dealloc_cell(result)
    emu.dealloc_cell(addr_obj)
    return False 

cdef bint handle_leave_instruction(DotNetEmulator emu):
    """ Performs leave instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    emu.stack.clear()
    return handle_general_jump(emu)

cdef bint handle_starg_instruction(DotNetEmulator emu):
    """ Performs starg instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef int number = emu.instr.get_argument()
    cdef StackCell value1 = emu.stack.pop()
    emu._add_param(number, value1)
    emu.dealloc_cell(value1)
    return False

cdef bint handle_stobj_instruction(DotNetEmulator emu):
    """ Performs stobj instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    
    Raises:
        net_exceptions.OperationNotSupportedException: Item popped off the stack was not a ELEMENT_TYPE_BYREF
    """
    cdef StackCell value_obj = emu.stack.pop()
    cdef StackCell addr_obj = emu.stack.pop()
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    emu.set_ref(addr_obj, value_obj)
    emu.dealloc_cell(value_obj)
    emu.dealloc_cell(addr_obj)
    return False

cdef bint handle_unbox_any_instruction(DotNetEmulator emu):
    """ Performs unbox.any instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell boxed_obj = emu.stack.pop()
    cdef StackCell unboxed_obj = emu.unbox_value(boxed_obj)
    emu.stack.append(unboxed_obj)
    emu.dealloc_cell(boxed_obj)
    emu.dealloc_cell(unboxed_obj)
    return False

cdef bint handle_pop_instruction(DotNetEmulator emu):
    """ Performs pop instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell cell = emu.stack.pop()
    emu.dealloc_cell(cell)
    return False

cdef bint handle_break_instruction(DotNetEmulator emu):
    """ Performs break instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    emu.should_break = True
    return False

cdef bint handle_unsupported_instruction(DotNetEmulator emu):
    """ A general handler for instructions that are not currently supported.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    raise net_exceptions.InstructionNotSupportedException(emu.instr.get_name())

cdef bint handle_nop_instruction(DotNetEmulator emu):
    """ Performs nop instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    return False

cdef bint handle_ldnull_instruction(DotNetEmulator emu):
    """ Performs ldnull instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    cdef StackCell null = emu.pack_null()
    emu.stack.append(null)
    emu.dealloc_cell(null)
    return False

cdef bint handle_newobj_instruction(DotNetEmulator emu):
    """ Performs newobj instruction.

    Args:
        emu (net_emulator.DotNetEmulator): The emulator object to perform the instruction on.

    Returns:
        bool: True if the emulator should increment EIP and move to the next instruction, False if we have already done that within the handler.
    """
    return do_call(emu, False, True, None, None, NULL, 0, emu.instr.get_argument())

"""
A lot of the stuff below is for internal use mainly.
"""

cdef class CctorRegistry:
    """ Used to keep track of the .cctor methods that have already been executed.
        This class will be removed eventually as its sort of pointless and unneeded.

    Notes:
        __executed_cctors (list[int]): A list of static constructor rids that have been executed.
    """
    def __init__(self):
        self.__executed_cctors = list()

    cpdef bint can_execute(self, net_row_objects.MethodDef method_obj):
        """ Will be removed eventually.  Returns True if a cctor should be executed.

        Args:
            method_obj (net_row_objects.MethodDef): the method to execute.
        Returns:
            bool: True if the cctor hasnt been executed, False otherwise.
        """
        if method_obj.get_rid() not in self.__executed_cctors:
            self.__executed_cctors.append(method_obj.get_rid())
            return True
        return False

cdef class EmulatorAppDomain:
    """
    Represents the AppDomain of an emulator.  Contains static variables, resolve handlers, loaded assemblies, globals and other important info.
    
    Notes:
        __assemblyresolve_handlers (list[net_row_objects.MethodDefOrRef]): The AssemblyResolve handlers.
        __resourceresolve_handlers (list[net_row_objects.MethodDefOrRef]): The ResourceResolve handlers.
        __loaded_assemblies (list[dotnetpefile.DotNetPeFile]): A list of currently loaded assemblies.
        __current_thread_num (int): Not really used for anything yet but may eventually be used for System.Threading.Thread.get_ManagedThreadId.
        __emu_obj (net_emulator.DotNetEmulator): the initial emulator object.
        __starter_dpe (dotnetpefile.DotNetPeFile): the initial dotnetpefile object.
        __calling_dotnetpe (dotnetpefile.DotNetPeFile): result of System.Reflection.Assembly.GetCallingAssembly()
        __executing_dotnetpe (dotnetpefile.DotNetPeFile): result of System.Reflection.Assembly.GetExecutingAssembly()
        __current_emulator (net_emulator.DotNetEmulator): The currently executing emulator.
        __field_index_registrations (dict[int, dict[int, int]]): Contains a types to dict[field rids -> field counter] mapping.  Used to save memory when allocating spaces for fields by allocating as arrays.
        __field_counter_registrations (dict[int, dict[int, int]]): Contains a types to dict[field counter -> field rids] mapping.  Same as above.
    """
    def __init__(self, dotnetpefile.DotNetPeFile dpe, DotNetEmulator emu_obj):
        self.__assemblyresolve_handlers = list()
        self.__resourceresolve_handlers = list()
        self.__loaded_assemblies = list()
        self.__current_thread_num = 1
        self.__emu_obj = emu_obj
        self.__starter_dpe = dpe
        self.__calling_dotnetpe = None
        self.__executing_dotnetpe = None
        self.__current_emulator = None
        self.__field_index_registrations = dict()
        self.__field_counter_registrations = dict()
        self.__user_instr_handlers = dict()

    cpdef void register_instr_handler(self, Opcodes opcode, object instrFn, object param):
        """ Register an instr handler.  Instruction handlers are functions that follow this signature: def func(emulator: DotNetEmulator, param: object) -> bool.
            Instruction handlers return True if the emulator should execute the instruction normally and False otherwise.
        Args:
            opcode (net_opcodes.Opcodes): the opcode to call the instruction handler on.  It is called on every instruction of this type executed within a emulator context.
            instrFn (object): The handler.  It must follow the function signature above.
            param (object): A optional parameter that will be passed to every handler called for this opcode.  Can be None.
        """
        self.__user_instr_handlers[opcode] = (instrFn, param)

    cdef tuple get_instr_handler(self, Opcodes opcode):
        """ Used by the emulator to obtain instr handlers.
        """
        if opcode not in self.__user_instr_handlers:
            return None
        return self.__user_instr_handlers[opcode]

    cdef void _initialize(self):
        """ Initialize the AppDomain.  Must be called once only.
        """
        self.load_dotnetpe_as_assembly(self.__starter_dpe)
        self.register_static_functions()
        self.__reserve_static_fields()
        self.__create_field_mappings()

    cdef void __create_field_mappings(self):
        """ Create mappings that map types to field rids to counters and vice versa.
        This is used so that we can malloc() an array of StackCells when storing TypeDef fields.  Saves a ton of space versus unordered_maps.
        """
        cdef net_table_objects.TableObject tdeftable = self.__emu_obj.get_method_obj().get_dotnetpe().get_metadata_table('TypeDef')
        cdef net_row_objects.TypeDef tdef = None
        cdef net_row_objects.TypeDefOrRef ptr = None
        cdef Py_ssize_t x = 0
        cdef list fields_list = None
        cdef int counter = 0
        cdef net_row_objects.Field field
        if tdeftable is None:
            return

        for x in range(1, len(tdeftable) + 1):
            tdef = tdeftable.get(<int>x)
            ptr = tdef
            counter = 0
            if tdef.get_token() not in self.__field_index_registrations:
                self.__field_index_registrations[tdef.get_token()] = dict()
            if tdef.get_token() not in self.__field_counter_registrations:
                self.__field_counter_registrations[tdef.get_token()] = dict()
            while ptr is not None:
                if isinstance(ptr, net_row_objects.TypeRef):
                    break
                if isinstance(ptr, net_row_objects.TypeSpec):
                    ptr = (<net_row_objects.TypeSpec>ptr).get_type()
                    continue
                if isinstance(ptr, net_row_objects.TypeDef):
                    fields_list = ptr.get_column('FieldList').get_formatted_value()
                    if fields_list is not None:
                        for field in fields_list:
                            if field.is_static():
                                continue
                            self.__field_index_registrations[tdef.get_token()][field.get_rid()] = counter
                            self.__field_counter_registrations[tdef.get_token()][counter] = field.get_rid()
                            counter += 1
                    ptr = ptr.get_superclass()

    cdef int get_field_rid(self, int field_index, int type_token):
        """ Get the RID of a field by index and type token.

        Args:
            field_index (int): The field's index in the array of fields for the type.
            type_token (int): the type token for the fields parent type.
        
        Returns:
            int: The corresponding field's RID or an Exception.

        Raises:
            net_exceptions.InvalidArgumentsException: If type_token is 0
            net_exceptions.EmulatorExecutionException: The type token isnt in the registrations, internal error?
        """
        if type_token == 0:
            raise net_exceptions.InvalidArgumentsException()
        cdef dict mapping = None
        cdef int result = 0
        if type_token not in self.__field_counter_registrations:
            raise net_exceptions.EmulatorExecutionException(self.get_emulator_obj(), 'Type token not in reg {}'.format(hex(type_token)))
        mapping = self.__field_counter_registrations[type_token]
        result = mapping[field_index]
        return result

    cdef int get_field_index(self, int field_rid, int type_token):
        """ Get the index of a field by RID and type token.

        Args:
            field_rid (int): The field's RID in the array of fields for the type.
            type_token (int): the type token for the fields parent type.
        
        Returns:
            int: The corresponding field's index or an Exception.

        Raises:
            net_exceptions.InvalidArgumentsException: If type_token is 0
            net_exceptions.EmulatorExecutionException: The type token isnt in the registrations, internal error?
        """
        if type_token == 0:
            raise net_exceptions.InvalidArgumentsException()
        cdef dict mapping = self.__field_index_registrations[type_token]
        cdef int result = mapping[field_rid]
        return result

    cdef int get_amt_static_fields(self):
        """ Obtain the amount of static fields present in the app domain.

        Returns:
            int: the amount of static fields present.
        """
        return <int>self.__static_fields.size()

    cdef StackCell get_static_field_idx(self, int index):
        """ Obtain the value for a static field by index.
            Only used for printing, unsafe for general use.
        
        Returns:
            net_emu_structs.StackCell: The stackcell corresponding to the field index.
        """
        return self.__static_fields[index]

    def __dealloc__(self):
        self.clear_static_fields()

    cdef void clear_static_fields(self):
        """ Clear and deallocate all static fields.
        """
        cdef size_t x = 0
        cdef StackCell cell
        for x in range(self.__static_fields.size()):
            cell = self.__static_fields[x]
            self.get_emulator_obj().deref_cell(cell)
            self.get_emulator_obj().dealloc_cell(cell)
        self.__static_fields.clear()

    cdef void __reserve_static_fields(self):
        """ Pre reserve as many static fields as we can with their default arguments.
            We cant pre reserve generics because we dont know what those will be.
        """
        cdef int amt_fields = 0
        cdef int x = 0
        cdef size_t y = 0
        cdef Py_ssize_t z = 0
        cdef net_row_objects.Field field_obj = None
        cdef StackCell cell
        cdef net_sigs.FieldSig fsig = None
        cdef net_table_objects.TableObject field_table = self.get_emulator_obj().get_method_obj().get_dotnetpe().get_metadata_table('Field')
        if field_table is None:
            return
        for z in range(1, len(field_table) + 1):
            field_obj = field_table.get(<int>z)
            if field_obj.is_static():
                self.__static_field_mappings[field_obj.get_rid()] = x
                fsig = field_obj.get_field_signature()
                if isinstance(fsig.get_type_sig(), net_sigs.GenericInstSig) or isinstance(fsig.get_type_sig(), net_sigs.GenericVar):
                    cell = self.get_emulator_obj().pack_blanktag()
                    cell.rid = field_obj.get_rid()
                    self.get_emulator_obj().ref_cell(cell)
                    self.__static_fields.push_back(cell)
                else:
                    cell = self.get_emulator_obj()._get_default_value(fsig.get_type_sig(), field_obj.get_parent_type())
                    cell.rid = field_obj.get_rid()
                    self.__emu_obj.ref_cell(cell)
                    self.__static_fields.push_back(cell)
                x += 1
                amt_fields += 1

    cdef void set_static_field(self, int idno, StackCell cell):
        """ Set a static field's value, for internal use.
            Places a duplicate cell in the field.  because of that, cell must be freed by the caller using DotNetEmulator.dealloc_cell()
        
        Args:
            idno (int): The RID of the static field.
            cell (StackCell): The value to set the static field to

        Raises:
            net_exceptions.InvalidArgumentsException: There was an issue obtaining the index for the static field.  Internal error.
        """
        cdef int actual_index = self.__static_field_mappings[idno]
        cdef StackCell old_value = self.__static_fields[actual_index]
        cdef net_row_objects.Field field = self.get_emulator_obj().get_method_obj().get_dotnetpe().get_metadata_table('Field').get(idno)
        cdef net_sigs.TypeSig sig_obj = field.get_field_signature().get_type_sig()
        cdef StackCell duped = self.get_emulator_obj().cast_cell(cell, sig_obj)
        if actual_index >= <int>self.__static_fields.size():
            raise net_exceptions.InvalidArgumentsException()
        self.get_emulator_obj().deref_cell(old_value)
        self.get_emulator_obj().dealloc_cell(old_value)
        self.get_emulator_obj().ref_cell(cell)
        duped.rid = idno
        self.__static_fields[actual_index] = duped

    cdef StackCell get_static_field(self, int idno):
        """ get a static field's value, for internal use.
            NOTE: because this returns a duplicate, it needs to be freed separately using DotNetEmulator.dealloc_cell()
        
        Args:
            idno (int): The RID of the static field.

        Returns:
            net_emu_structs.StackCell: A duplicate of the stackcell in the static field.

        Raises:
            net_exceptions.InvalidArgumentsException: There was an issue obtaining the index for the static field.  Internal error.
            net_exceptions.EmulatorExecutionException: Pulled an uninitialized field.
        """
        cdef int actual_index = self.__static_field_mappings[idno]
        cdef net_row_objects.Field fobj = None
        cdef net_sigs.FieldSig fsig = None
        cdef StackCell new_cell
        if actual_index >= <int>self.__static_fields.size():
            raise net_exceptions.InvalidArgumentsException()
        if self.__static_fields[actual_index].tag == CorElementType.ELEMENT_TYPE_END:
            fobj = self.get_emulator_obj().get_method_obj().get_dotnetpe().get_metadata_table('Field').get(idno)
            fsig = fobj.get_field_signature()
            new_cell = self.get_emulator_obj()._get_default_value(fsig.get_type_sig(), None)
            self.get_emulator_obj().ref_cell(new_cell)
            self.__static_fields[actual_index] = new_cell
        return self.get_emulator_obj().duplicate_cell(self.__static_fields[actual_index])

    cdef static_func_type get_static_func(self, int token):
        """ Obtains the pointer to an emulated MemberRef (static functions only).

        Args:
            token (int): The MethodDef / MemberRef token to obtain

        Returns:
            static_func_type: the pointer to the emulated function.
        """
        return self.__static_functions[token]

    cdef newobj_func_type get_ctor_func(self, int token):
        """ Obtains the pointer to a function which simply creates an emulated type.

        Args:
            token (int): The MethodDef / MemberRef token to obtain

        Returns:
            newobj_func_type: the pointer to the emulated function.
        """
        return self.__newobj_ctors[token]

    cdef bint has_ctor_func(self, int token):
        """ Informs the user whether a ctor function is registered.
            ctor functions are registered by their method token to save time.

        Args:
            token (int): The MethodDef / MemberRef token to obtain

        Returns:
            bint: True if the ctor function exists in the registry, false otherwise
        """
        return self.__newobj_ctors.count(token) > 0

    cdef bint has_static_func(self, int token):
        """ Informs the user whether a static function is registered.
            static functions are registered by their method token to save time.

        Args:
            token (int): The MethodDef / MemberRef token to obtain

        Returns:
            bint: True if the static function exists in the registry, false otherwise
        """
        return self.__static_functions.count(token) > 0

    cdef void register_static_functions(self):
        """ This function is responsible for registering static functions and ctor functions by token.
            Allows the lookup for these functions to be sped up a bit.
        """
        #register static methods first.
        #speed doesnt really matter here since itll only be called once.
        cdef net_emu_types.NewobjFuncMapping newobj_mapping
        cdef net_emu_types.EmuFuncMapping func_mapping
        cdef list methods
        cdef net_row_objects.TypeRef ref_obj
        cdef net_row_objects.MemberRef mref_obj
        cdef int x
        cdef bytes mapping_name
        cdef bytes full_name
        cdef bytes test_name
        for x in range(AMT_OF_TYPES):
            newobj_mapping = net_emu_types.NET_EMULATE_TYPE_REGISTRATIONS[x]
            mapping_name = newobj_mapping.name[:strlen(newobj_mapping.name)]
            for ref_obj in self.__starter_dpe.get_metadata_table('TypeRef'):
                #handle generics here
                full_name = ref_obj.get_full_name()
                if full_name is not None:
                    if full_name == mapping_name:
                        self.__newobj_ctors[ref_obj.get_token()] = newobj_mapping.func_ptr
                    elif full_name.startswith(mapping_name):
                        test_name = full_name.lstrip(mapping_name)
                        if test_name.startswith(b'`'):
                            self.__newobj_ctors[ref_obj.get_token()] = newobj_mapping.func_ptr
        
        for x in range(AMT_OF_STATIC_FUNCTIONS):
            func_mapping = net_emu_types.NET_EMULATE_STATIC_FUNC_REGISTRATIONS[x]
            mapping_name = func_mapping.name[:strlen(func_mapping.name)]
            methods = self.__starter_dpe.get_methods_by_full_name(mapping_name) #given the current way this method works it should do well for fields as well.
            for mref_obj in methods:
                self.__static_functions[mref_obj.get_token()] = func_mapping.func_ptr

    cpdef dotnetpefile.DotNetPeFile get_calling_dotnetpe(self):
        """ Obtains the current calling dotnetpe, used for Assembly.GetCallingAssembly()

        Returns:
            dotnetpefile.DotNetPeFile: The current calling DotNetPeFile.
        """
        return self.__calling_dotnetpe

    cpdef dotnetpefile.DotNetPeFile get_executing_dotnetpe(self):
        """ Obtains the current executing dotnetpe, used for Assembly.GetExecutingAssembly()

        Returns:
            dotnetpefile.DotNetPeFile: The current executing DotNetPeFile.
        """
        return self.__executing_dotnetpe

    cpdef DotNetEmulator get_current_emulator(self):
        """ Obtains the currently executing emulator object

        Returns:
            net_emulator.DotNetEmulator: The currently executing emulator.
        """
        return self.__current_emulator

    cpdef void set_current_emulator(self, DotNetEmulator emulator):
        """ Helper function used to set the current emulator internally
        """
        self.__current_emulator = emulator

    cpdef void set_calling_dotnetpe(self, dotnetpefile.DotNetPeFile dpe):
        """ Helper function used to set the current calling dotnetpe internally
        """
        self.__calling_dotnetpe = dpe

    cpdef void set_executing_dotnetpe(self, dotnetpefile.DotNetPeFile dpe):
        """ Helper function used to set the current executing emulator internally
        """
        self.__executing_dotnetpe = dpe

    cpdef int get_thread_id(self):
        """ Something that may be used later for System.Threading.Thread.get_ManagedThreadId.
            Currently unused, intended to get a spare thread id number.
        
        Returns:
            int: Thread id number to use.
        """
        cdef int curr
        curr = self.__current_thread_num
        self.__current_thread_num += 1
        return curr

    cpdef DotNetEmulator get_emulator_obj(self):
        """ Obtain the initial emulator object associated with an app domain.  This is not the currently executing emulator.

        Returns:
            net_emulator.DotNetEmulator: The initially executed emulator object.
        """
        return self.__emu_obj

    cpdef void add_resource_handler(self, net_row_objects.MethodDefOrRef obj):
        """ Helper function used to add resource handlers on add_ResourceResolve calls.
        """
        self.__resourceresolve_handlers.append(obj)

    cpdef void add_assembly_handler(self, net_row_objects.MethodDefOrRef obj):
        """ Helper function used to add assembly handlers on add_AssemblyResolve calls.
        """
        self.__assemblyresolve_handlers.append(obj)

    cpdef list get_loaded_assemblies(self):
        """ Obtain a list of loaded assemblies.

        Returns:
            list[dotnetpefile.DotNetPeFile]: List of loaded assemblies.
        """
        return self.__loaded_assemblies

    cpdef net_emu_types.DotNetAssembly load_assembly_from_bytes(self, bytes data):
        """ Used to sort of emulate Assembly.Load().  Adds an assembly into the AppDomain.

        Args:
            data (bytes): Bytes of the assembly to load.

        Returns:
            net_emu_types.DotNetAssembly: A dotnetassembly object representing the newly loaded assembly.
        """
        return self.load_dotnetpe_as_assembly(dotnetpefile.DotNetPeFile(pe_data=data))

    cpdef net_emu_types.DotNetAssembly load_dotnetpe_as_assembly(self, dotnetpefile.DotNetPeFile dpe):
        """ Helper function used to load assemblies into the AppDomain.

        Args:
            dpe (dotnetpefile.DotNetPeFile): A DotNetPeFile object representing the assembly.
        
        Returns:
            net_emu_types.DotNetAssembly: The new assembly that was loaded.
        """
        cdef net_row_objects.RowObject asm_obj = dpe.get_metadata_table('Assembly').get(1)
        cdef net_emu_types.DotNetAssembly result = net_emu_types.DotNetAssembly(self.get_emulator_obj(), asm_obj)
        if len(self.__loaded_assemblies) == 0:
            self.original_assembly = result
        self.__loaded_assemblies.append(result)
        return result

    cpdef net_emu_types.DotNetAssembly get_assembly_by_name(self, net_emu_types.DotNetString name) except *:
        """ This function is used to handle lookups that account for potential AssemblyResolve handlers.

        Params:
            name (net_emu_types.DotNetString): the name of the assembly to look up, in DotNetString form.

        Returns:
            net_emu_types.DotNetAssembly: The resolved assembly, or None if not found.
        """
        cdef net_emu_types.DotNetAssembly asm_obj
        cdef net_emu_types.DotNetAssemblyName asm_name_obj
        cdef net_emu_types.DotNetString asm_name_str
        cdef net_row_objects.MethodDefOrRef mrefdef_obj
        cdef net_row_objects.MethodDef mdef_obj
        cdef net_emu_types.DotNetResolveEventArgs arg_two
        cdef DotNetEmulator emu_obj
        cdef StackCell result_obj
        cdef StackCell name_cell = self.get_emulator_obj().pack_string(name)
        cdef StackCell cell
        cdef net_emu_types.DotNetAssembly result
        #first check the resolve methods, see if we get anything from there.
        for mrefdef_obj in self.__assemblyresolve_handlers:
            if isinstance(mrefdef_obj, net_row_objects.MethodDef):
                mdef_obj = <net_row_objects.MethodDef> mrefdef_obj
                arg_two = net_emu_types.DotNetResolveEventArgs(self.get_emulator_obj())
                arg_two.ctor(&name_cell, 1)
                emu_obj = self.get_emulator_obj().spawn_new_emulator(mdef_obj, caller=self)
                emu_obj._allocate_params(2)
                cell = self.__emu_obj.pack_null()
                emu_obj._add_param(0, cell)
                self.__emu_obj.dealloc_cell(cell)
                cell = self.__emu_obj.pack_object(arg_two)
                emu_obj._add_param(1, cell)
                self.__emu_obj.dealloc_cell(cell)
                emu_obj.run_function()
                result_obj = emu_obj.stack.pop()
                if not self.get_emulator_obj().cell_is_null(result_obj) and isinstance(<net_emu_types.DotNetObject>result_obj.item.ref, net_emu_types.DotNetAssembly):
                    self.get_emulator_obj().dealloc_cell(name_cell)
                    result = <net_emu_types.DotNetAssembly>result_obj.item.ref
                    self.__emu_obj.dealloc_cell(result_obj)
                    return result
                self.__emu_obj.dealloc_cell(result_obj)
        self.get_emulator_obj().dealloc_cell(name_cell)
        
        for asm_obj in self.__loaded_assemblies:
            name_cell = asm_obj.GetName(NULL, 0)
            asm_name_obj = <net_emu_types.DotNetAssemblyName>name_cell.item.ref
            self.get_emulator_obj().dealloc_cell(name_cell)
            name_cell = asm_name_obj.get_Name(NULL, 0)
            asm_name_str = <net_emu_types.DotNetString>name_cell.item.ref
            self.__emu_obj.dealloc_cell(name_cell)
            if asm_name_str == name:
                return asm_obj
        return None

    cpdef bytes get_resource_by_name(self, net_emu_types.DotNetString name, net_emu_types.DotNetAssembly assembly) except *:
        """ This function is used to handle lookups that account for potential ResourceResolve handlers.

        Params:
            name (net_emu_types.DotNetString): the name of the resource to look up, in DotNetString form.

        Returns:
            bytes: The data of the resolved resource in bytes, or None if not found.
        """
        
        cdef net_emu_types.DotNetAssembly asm_obj
        cdef net_emu_types.DotNetAssemblyName asm_name_obj
        cdef net_emu_types.DotNetString asm_name_str
        cdef net_row_objects.MethodDefOrRef mrefdef_obj
        cdef net_row_objects.MethodDef mdef_obj
        cdef net_emu_types.DotNetResolveEventArgs arg_two
        cdef DotNetEmulator emu_obj
        cdef StackCell name_cell = self.get_emulator_obj().pack_string(name)
        cdef StackCell result_obj
        cdef StackCell cell
        cdef net_emu_types.DotNetObject result = None
        cdef bytes rsrc_name = name.get_str_data_as_bytes().decode(name.get_str_encoding()).encode('utf-8')
        cdef bytes result_b = assembly.get_module().get_dotnetpe().get_resource_by_name(rsrc_name)
        if result_b is not None:
            return result_b
        #first check the resolve methods, see if we get anything from there.
        for mrefdef_obj in self.__resourceresolve_handlers: #TODO: Exceptions wont properly show in this, need to fix.
            if isinstance(mrefdef_obj, net_row_objects.MethodDef):
                mdef_obj = <net_row_objects.MethodDef> mrefdef_obj
                arg_two = net_emu_types.DotNetResolveEventArgs(self.get_emulator_obj())
                arg_two.ctor(&name_cell, 1)
                emu_obj = self.get_emulator_obj().spawn_new_emulator(mdef_obj, caller=self)
                emu_obj._allocate_params(2)
                cell = self.__emu_obj.pack_null()
                emu_obj._add_param(0, cell)
                self.__emu_obj.dealloc_cell(cell)
                cell = self.__emu_obj.pack_object(arg_two)
                emu_obj._add_param(1, cell)
                self.__emu_obj.dealloc_cell(cell)
                emu_obj.run_function()
                result_obj = emu_obj.get_stack().pop()
                if not self.get_emulator_obj().cell_is_null(result_obj) and isinstance(<net_emu_types.DotNetObject>result_obj.item.ref, net_emu_types.DotNetAssembly):
                    result = <net_emu_types.DotNetAssembly>result_obj.item.ref
                    self.__emu_obj.dealloc_cell(result_obj)
                    self.__emu_obj.dealloc_cell(name_cell)
                    return result.get_module().get_dotnetpe().get_resource_by_name(rsrc_name)
                self.__emu_obj.dealloc_cell(result_obj)
        self.__emu_obj.dealloc_cell(name_cell)
        return None

cdef class DotNetStack:

    """ This class is used as a representation of the method's stack.  Some detail on how this works:
        The stack can only contain StackCell objects.  They must be duplicated upon append().  This means that after any append() call,
        the caller must call DotNetEmulator.dealloc_cell().  The stack will also hold a reference on StackCells within, being dereferenced on pop().
    
    Notes:
        __emulator (net_emulator.DotNetEmulator): The emulator object which created the stack.
        __max_stack_size (int): the maximum stack size from the methods header.
        __internal_stack (vector[net_emu_structs.StackCell]): the internal vector for the stack.
    """

    def __init__(self, DotNetEmulator emulator, int max_stack_size):
        """ Creates a new DotNetStack.  Requires the curent executing emulator and the maximum stack size from the methods header.
            Stack memory is reserved on initialization and cannot be changed.
        """
        self.__emulator = emulator
        self.__max_stack_size = max_stack_size
        self.__internal_stack.reserve(max_stack_size)

    cdef void append(self, StackCell cell):
        """ Appends an item to the stack.  Per CIL rules, integers are extended to 32 bits.
            A duplicated cell is appended onto the stack, so it must be freed by the caller.
        """
        if cell.tag == CorElementType.ELEMENT_TYPE_END:
            raise net_exceptions.InvalidArgumentsException()
        cdef StackCell duped_cell
        #Extend out smaller types
        if cell.tag == CorElementType.ELEMENT_TYPE_I1 or cell.tag == CorElementType.ELEMENT_TYPE_I2:
            duped_cell = self.__emulator.cast_cell(cell, net_sigs.get_CorSig_Int32())
        elif cell.tag == CorElementType.ELEMENT_TYPE_U1 or cell.tag == CorElementType.ELEMENT_TYPE_U2 or cell.tag == CorElementType.ELEMENT_TYPE_CHAR:
            duped_cell = self.__emulator.cast_cell(cell, net_sigs.get_CorSig_UInt32())
        elif cell.tag == CorElementType.ELEMENT_TYPE_BOOLEAN:
            duped_cell = self.__emulator.cast_cell(cell, net_sigs.get_CorSig_Int32())
        else:
            duped_cell = self.__emulator.duplicate_cell(cell)
        self.__emulator.ref_cell(duped_cell)
        self.__internal_stack.push_back(duped_cell)

    cpdef void append_obj(self, net_emu_types.DotNetObject obj):
        """ A function for users to append items onto emulator stacks.
        
        Args:
            obj (net_emu_types.DotNetObject): the object to append to the stack.  Values are automatically unboxed, 
                so a DotNetInt32() will be translated to a raw StackCell representation for example.
        """
        cdef StackCell boxed
        cdef StackCell unboxed

        if obj is not None:
            if isinstance(obj, net_emu_types.DotNetString):
                boxed = self.__emulator.pack_string(obj)
            else:
                boxed = self.__emulator.pack_object(obj)
            unboxed = self.__emulator.unbox_value(boxed)
        else:
            boxed = self.__emulator.pack_null()
            unboxed = self.__emulator.duplicate_cell(boxed)
        self.append(unboxed)
        self.__emulator.dealloc_cell(unboxed)
        self.__emulator.dealloc_cell(boxed)

    cdef StackCell pop(self):
        """ Pops an item off the stack and dereferences it.  All items returned from this function must be dealloced.

        Raises:
            net_exceptions.EmulatorExecutionException: If the stack is empty.
        """
        if self.__internal_stack.empty():
            raise net_exceptions.EmulatorExecutionException(self.__emulator, 'Attempted to pop an item off the stack when its empty')
        cdef StackCell obj = self.__internal_stack.back()
        self.__internal_stack.pop_back()
        self.__emulator.deref_cell(obj)
        return obj

    cpdef net_emu_types.DotNetObject pop_obj(self):
        """ Pops an item off the stack and boxes it.  Inteded for users to obtain values off the stack.
            For instance a StackCell of ELEMENT_TYPE_I4 will be translated to DotNetInt32() objects.

        Returns:
            net_emu_types.DotNetObject: A boxed representation of the top item on the stack.
        Raises:
            net_exceptions.EmulatorExecutionException: If the stack is empty.
        """
        if self.__internal_stack.empty():
            raise net_exceptions.EmulatorExecutionException(self.__emulator, 'Attempted to pop an item off the stack when its empty')
        cdef StackCell obj = self.__internal_stack.back()
        cdef StackCell boxed_obj = self.__emulator.box_value(obj, None)
        cdef net_emu_types.DotNetObject return_value = None
        self.__internal_stack.pop_back()
        self.__emulator.deref_cell(obj)
        self.__emulator.dealloc_cell(obj)
        if boxed_obj.item.ref != NULL:
            return_value = <net_emu_types.DotNetObject>boxed_obj.item.ref
        self.__emulator.dealloc_cell(boxed_obj)
        return return_value

    cpdef net_emu_types.DotNetObject peek_obj(self):
        """ boxes the first value on the stack and returns it.  Inteded for users to obtain values off the stack.
            For instance a StackCell of ELEMENT_TYPE_I4 will be translated to DotNetInt32() objects.

        Returns:
            net_emu_types.DotNetObject: A boxed representation of the top item on the stack.
        Raises:
            net_exceptions.EmulatorExecutionException: If the stack is empty.
        """
        if self.__internal_stack.empty():
            raise net_exceptions.EmulatorExecutionException(self.__emulator, 'Attempted to pop an item off the stack when its empty')
        cdef StackCell obj = self.__internal_stack.back()
        cdef StackCell boxed_obj = self.__emulator.box_value(obj, None)
        cdef net_emu_types.DotNetObject return_value = None
        self.__emulator.deref_cell(obj)
        self.__emulator.dealloc_cell(obj)
        if boxed_obj.item.ref != NULL:
            return_value = <net_emu_types.DotNetObject>boxed_obj.item.ref
        self.__emulator.dealloc_cell(boxed_obj)
        return return_value

    cpdef void remove_obj(self):
        """ Pops an item off the stack without returning it.
        """
        cdef StackCell obj = self.__internal_stack.back()
        self.__internal_stack.pop_back()
        self.__emulator.deref_cell(obj)
        self.__emulator.dealloc_cell(obj)

    cdef StackCell peek(self):
        """ Obtains an item off the stack without popping it off.
        """
        cdef StackCell obj = self.__internal_stack.back()
        return obj

    cpdef void clear(self):
        """ Deallocate any memory associated with the stack.
        """
        cdef size_t i = 0
        cdef StackCell cell
        for i in range(self.__internal_stack.size()):
            cell = self.__internal_stack[i]
            self.__emulator.deref_cell(cell)
            self.__emulator.dealloc_cell(cell)
        self.__internal_stack.clear()

    cdef StackCell get(self, int index):
        """ Obtain an item off the stack by index.
        """
        if <size_t>index >= self.__internal_stack.size():
            raise net_exceptions.InvalidArgumentsException()
        cdef StackCell old = self.__internal_stack[index]
        cdef StackCell duped = self.__emulator.duplicate_cell(self.__internal_stack[index])
        return duped

    def __len__(self) -> int:
        return self.__internal_stack.size()

    def __dealloc__(self):
        self.clear()

cdef class StackCellWrapper:
    """ This class is used when there absolutely must be a full python object to store a StackCell.
        The only case where this is required currently is DotNetDictionary.
    """
    def __cinit__(self, DotNetEmulator emu_obj, CorElementType cor_type, uint64_t u8, uint64_t ref, int kind, int idx, uint64_t owner, int rid, uint64_t extra_data, bint is_slim_object):
        self.__emu_obj = emu_obj
        self.cor_type = cor_type
        self.u8_holder = u8
        self.ref_holder = <PyObject*><void*>ref
        self.kind_holder = kind
        self.owner_holder = <void*>owner
        self.idx_holder = idx
        self.extra_data_holder = <void*>extra_data
        self.rid_holder = rid
        self.is_slim_object_holder = is_slim_object

    def __str__(self):
        return self.__emu_obj.cell_to_str(self.get_wrapped())

    def __repr__(self):
        return str(self)

    def __hash__(self):
        cdef DotNetEmulator emu_obj = self.__emu_obj
        return emu_obj.hash_cell(self.get_wrapped())

    def __eq__(self, other):
        cdef StackCellWrapper wrapper = None
        cdef DotNetEmulator emu_obj = self.__emu_obj
        if not isinstance(other, StackCellWrapper):
            return False
        wrapper = <StackCellWrapper>other
        return emu_obj.cell_is_equal(self.get_wrapped(), wrapper.get_wrapped())
    
    cdef StackCell get_wrapped(self):
        cdef StackCell cell
        cell.tag = self.cor_type
        cell.rid = self.rid_holder
        cell.item.u8 = self.u8_holder
        cell.item.ref = self.ref_holder
        cell.item.byref.kind = self.kind_holder
        cell.item.byref.owner = self.owner_holder
        cell.item.byref.idx = self.idx_holder
        cell.extra_data = self.extra_data_holder
        cell.emulator_obj = <PyObject*>self.__emu_obj
        cell.is_slim_object = self.is_slim_object_holder
        return cell

cdef class DotNetEmulator:

    """ Reprsents a .NET emulator object for a specific method.

    Notes:
        method_obj (net_row_objects.MethodDefOrRef): The currently executing method.
        spec_obj (net_row_objects.MethodSpec): The methods generic specification if it exists.
        disasm_obj (net_cil_disas.MethodDisassembler): A method disassembly object for the specified method.
        __method_params (net_emu_structs.StackCell *): An array representing the methods parameters.
        __nparams (int): The number of method parameters.
        end_offset (int): The code offset to stop execution on.
        stack (net_emulator.DotNetStack): the stack frame for the call.
        localvars (vector[net_emu_structs.StackCell]): a vector containing all the locals for the method.
        local_var_sigs (vector[PyObject*/net_sigs.TypeSig]): A vector containing the signatures for various local vars.
        end_method_rid (int): The method rid which to handle end_offset for.
        executed_cctors (net_emulator.CctorRegistry): An object handling which cctor methods have been executed.
        curent_eip (unsigned int): the current eip counter.
        current_offset (unsigned int): The current method code offset.
        __last_instr_end (uint64_t): Used to hold a timestamp for the last instruction execution, if enabled.
        __last_instr_start (uint64_t): Used to hold a timestamp for the start of instruction execution, if enabled.
        start_time (uint64_t): used to hold a counter for timeouts.
        timeout_ns (uint64_t): The amount of nanoseconds until the emulator should time out.
        caller (net_emulator.DotNetEmulator): The emulator object that spawned this emulator, if exists.
        end_eip (int): the eip value which to end execution (currently unused)
        strict_typing (bool): Current default behavior is to replace ctors to unknown TypeRefs with null.  If this is True, it will error instead.
        should_break (bool): Used to inform the emulator about break instrs.
        print_debug (bool): Should debug printing be enabled for this emulator.
        print_hex (bool): Unused and likely to be removed.
        print_debug_children (bool): Should children emulator objects also enable print debugging.
        ignore_security_exceptions (bool): Not really used at this point.
        dont_execute_cctor (bool): dont execute any cctor methods.
        break_on_unsupported (bool): break on unsupported instructions instead of error.
        already_init (bool): Has the emulator been initialized.
        spawned (bool): Was the emulator spawned by a parent.
        __skip_next_instruction (bool): Unused right now.
        print_debug_instrs (list[str]): A list of instruction names to enable print debugging for.  May not be enabled currently.
        print_debug_offsets (list[int]): A list of offsets to enable print debugging for.  May not be enabled currently.
        print_debug_rids (dict): Currently unused, may be removed
        ignore_instrs (list[str]): Currently unused, may be removed.
        print_debug_methods (list[int]): A list of rids to enable print debugging for.
        app_domain (net_emulator.EmulatorAppDomain): the app domain for the execution.
        print_debug_level (int): Currently unused.
        running_thread (net_emu_types.DotNetThread): Currently unused.
        __is_64bit (bint): is the emulator executing as 64 bit.
        instr (net_cil_disas.Instruction): The currently executing instruction.
        is_destroyed (bint): has the emulator already been deallocated?
    """

    def __init__(self, net_row_objects.MethodDefOrRef method_obj, int end_method_rid=-1, int end_offset=-1, DotNetEmulator caller=None, bint break_on_unsupported=False, bint ignore_security_exceptions=False, bint dont_execute_cctor=False, force_memory=None, int start_offset=0, list print_debug_instrs=[], list print_debug_rids=[], should_print_callback=None, should_print_callback_param=None, list ignore_instrs=list(), app_domain=None, int timeout_seconds=-1, net_row_objects.MethodSpec spec_obj=None, bint strict_typing=False, bint init_open_generics_as_object=False):
        """ Constructor for Emulator objects.

        Params:
            method_obj (net_row_objects.MethodDefOrRef): The method to emulate.
            end_method_rid (int): the RID of the method to end execution on, -1 for None.
            end_offset (int): The code offset to end execution associated with end_method_rid.
            caller (net_emulator.DotNetEmulator): For the most part this param is handled internally but used to inform DotNetEmulator of its parent.
            break_on_unsupported (bool): Break on unsupported instructions instead of erroring.
            ignore_security_exceptions (bool): Not really used, may be removed.
            dont_execute_cctor (bool): If True, all cctor methods will be ignored.
            force_memory (object): unused and may be removed.
            start_offset (int): the start offset to begin execution at.
            print_debug_instrs (list[str]): A list of instruction names to print debug.
            print_debug_rids (list[int]): A list of method RIDs to print debug.
            should_print_callback (object): Likely to be removed.  Unused.
            should_print_callback_param (object): Likely to be removed, unused.
            ignore_instrs (list[str]): currently unused, may be removed.
            app_domain (net_emulator.EmulatorAppDomain): Handled internally usually, used to set the app domain.
            timeout_seconds (int): the timeout in seconds.  Once the timeout is hit, net_emulator.EmulatorTimeoutException is thrown.  -1 for no timeout.
            spec_obj (net_row_objects.MethodSpec): the methodSpec object, if it exists. Not really used, may be removed.
            strict_typing (bool): Currently default is to use NULL on ctors for TypeRefs that we cant handle.  If true, it will throw an exception instead.
            init_open_generics_as_object (bool): Initializes all open generics as a NULL object.  Used for emulations where you dont expect to actually use the generics.

        Raises:
            net_exceptions.InvalidArgumentsException: The method object is invalid.
            net_exceptions.DisassemblyFailedException: could not disassemble the method.
        
        """
        if method_obj is None:
            raise net_exceptions.InvalidArgumentsException()
        self.spec_obj = None
        self.is_destroyed = False
        self.__init_open_generics_as_object = init_open_generics_as_object
        if isinstance(method_obj, net_row_objects.MethodSpec):
            self.spec_obj = method_obj
            method_obj = (<net_row_objects.MethodSpec>method_obj).get_method()

        if isinstance(method_obj, net_row_objects.MemberRef):
            raise net_exceptions.InvalidArgumentsException()
        self.method_obj = method_obj
        if not self.method_obj.has_body():
            raise net_exceptions.InvalidArgumentsException()
        self.strict_typing = strict_typing
        self.disasm_obj = self.method_obj.disassemble_method()
        if self.disasm_obj is None:
            raise net_exceptions.EmulatorExecutionException(self, 'Could not get disasm object for method {}'.format(hex(self.method_obj.get_token())))
        self.end_offset = end_offset
        self.stack = DotNetStack(self, self.disasm_obj.max_stack)
        self.end_method_rid = end_method_rid
        if self.spec_obj is None and spec_obj is not None:
            self.spec_obj = spec_obj
        self.executed_cctors = CctorRegistry()
        if start_offset > -1:
            self.current_eip = self.disasm_obj.get_instr_index_by_offset(start_offset)
        else:
            self.current_eip = 0
        self.current_offset = start_offset
        self.__last_instr_start = 0
        self.__last_instr_end = 0
        self.caller = caller
        self.end_eip = -1
        self.should_break = False
        self.print_debug = False
        self.print_hex = False
        self.print_debug_children = False
        self.break_on_unsupported = break_on_unsupported
        self.ignore_security_exceptions = ignore_security_exceptions
        self.dont_execute_cctor = dont_execute_cctor
        self.spawned = False
        self.print_debug_offsets = list()
        self.print_debug_methods = list()
        #self.__pre_exec_callback = None
        #self.__post_exec_callback = None
        self.__skip_next_instruction = False
        #self.__callback_param = None
        self.print_debug_instrs = print_debug_instrs
        self.instr = None
        self.ignore_instrs = ignore_instrs
        self.__is_64bit = self.method_obj.get_dotnetpe().get_processor_bits() == 64
        if app_domain is None:
            self.app_domain = EmulatorAppDomain(self.method_obj.get_dotnetpe(), self)
            self.app_domain._initialize()
        else:
            self.app_domain = app_domain

        self.print_debug_level = 0
        self.already_init = self.app_domain.get_calling_dotnetpe() is not None

        if not self.already_init:
            self.app_domain.set_calling_dotnetpe(self.method_obj.get_dotnetpe())

        if not self.disasm_obj:
            raise net_exceptions.DisassemblyFailedException
        
        if not __is_handlers_initialized:
            __init_handlers()
        if timeout_seconds > 0:
            self.timeout_ns = <uint64_t>(timeout_seconds * 1000000000ULL)
        else:
            self.timeout_ns = 0
        self.start_time = 0
        self.initialize_locals() #So that locals can be set before everything is set up.

    cpdef net_cil_disas.Instruction get_instr(self):
        return self.instr

    cdef StackCell convert_unsigned(self, StackCell cell):
        """ For numbers, this will convert a StackCell to its unsigned counterpart and return a duplicate.
            If the number is unsigned, it just returns a duplicate.  If its not a number, it returns a duplicate.
        
        Args:
            cell (net_emu_structs.StackCell): The stackcell to convert.

        Returns:
            net_emu_structs.StackCell: The unsigned or dupicate stackcell.

        Raises:
            net_exceptions.InvalidArgumentsException: We currently dont support that type for conversion.
        """
        cdef StackCell new_cell = self.duplicate_cell(cell)
        if self.cell_is_null(new_cell):
            return new_cell
        if not net_utils.is_cortype_number(<CorElementType>cell.tag):
            return new_cell
        if net_utils.is_cortype_unsigned(<CorElementType>cell.tag):
            return new_cell
        else:
            if cell.tag == CorElementType.ELEMENT_TYPE_I:
                new_cell.tag = CorElementType.ELEMENT_TYPE_U
            elif cell.tag == CorElementType.ELEMENT_TYPE_I1:
                new_cell.tag = CorElementType.ELEMENT_TYPE_U1
            elif cell.tag == CorElementType.ELEMENT_TYPE_I2:
                new_cell.tag = CorElementType.ELEMENT_TYPE_U2
            elif cell.tag == CorElementType.ELEMENT_TYPE_I4:
                new_cell.tag = CorElementType.ELEMENT_TYPE_U4
            elif cell.tag == CorElementType.ELEMENT_TYPE_I8:
                new_cell.tag = CorElementType.ELEMENT_TYPE_U8
            else:
                raise net_exceptions.InvalidArgumentsException()
        return new_cell

    cdef StackCell convert_signed(self, StackCell cell):
        """ For numbers, this will convert a StackCell to its signed counterpart and return a duplicate.
            If the number is signed, it just returns a duplicate.  If its not a number, it returns a duplicate.
        
        Args:
            cell (net_emu_structs.StackCell): The stackcell to convert.

        Returns:
            net_emu_structs.StackCell: The signed or dupicate stackcell.

        Raises:
            net_exceptions.InvalidArgumentsException: We currently dont support that type for conversion.
        """
        cdef StackCell new_cell = self.duplicate_cell(cell)
        if not net_utils.is_cortype_number(<CorElementType>cell.tag):
            raise net_exceptions.InvalidArgumentsException()
        if net_utils.is_cortype_signed(<CorElementType>cell.tag):
            return new_cell
        else:
            if cell.tag == CorElementType.ELEMENT_TYPE_U:
                new_cell.tag = CorElementType.ELEMENT_TYPE_I
            elif cell.tag == CorElementType.ELEMENT_TYPE_U1:
                new_cell.tag = CorElementType.ELEMENT_TYPE_I1
            elif cell.tag == CorElementType.ELEMENT_TYPE_U2 or cell.tag == CorElementType.ELEMENT_TYPE_CHAR:
                new_cell.tag = CorElementType.ELEMENT_TYPE_I2
            elif cell.tag == CorElementType.ELEMENT_TYPE_U4:
                new_cell.tag = CorElementType.ELEMENT_TYPE_I4
            elif cell.tag == CorElementType.ELEMENT_TYPE_U8:
                new_cell.tag = CorElementType.ELEMENT_TYPE_I8
            else:
                raise net_exceptions.InvalidArgumentsException()
        return new_cell
                
    cdef StackCell duplicate_cell(self, StackCell cell):
        """ Shallow copies a stackcell.  A duplicated stack cell must be freed using net_emulator.DotNetEmulator.dealloc_cell().
        
        Args:
            cell (net_emu_structs.StackCell): The stackcell to duplicate.

        Returns:
            net_emu_structs.StackCell: The shallow duplicated cell.

        Raises:
            net_exceptions.EmulatorExecutionException: Internal error with the cell.
        """
        cdef StackCell new_cell
        cdef int x = 0
        cdef SlimObject * slim = NULL
        memcpy(&new_cell, &cell, sizeof(new_cell))
        if cell.tag == CorElementType.ELEMENT_TYPE_END:
            return self.pack_blanktag()
        if new_cell.emulator_obj != NULL:
            Py_INCREF(<DotNetEmulator>new_cell.emulator_obj)
        else:
            raise net_exceptions.EmulatorExecutionException(self, 'cell of type {} doesnt have emu obj'.format(net_utils.get_cor_type_name(<CorElementType>cell.tag)))
        if new_cell.tag == CorElementType.ELEMENT_TYPE_BYREF:
            if new_cell.item.byref.kind != 4:
                Py_INCREF(<object>new_cell.item.byref.owner)
            else:
                slim = <SlimObject*>new_cell.item.byref.owner
                slim.refs += 1
        elif new_cell.tag == CorElementType.ELEMENT_TYPE_OBJECT or new_cell.tag == CorElementType.ELEMENT_TYPE_STRING:
            if new_cell.is_slim_object:
                new_cell.item.slim_object.refs += 1
            else:
                if new_cell.item.ref != NULL:
                    Py_INCREF(<net_emu_types.DotNetObject>new_cell.item.ref)
        return new_cell

    cdef StackCell duplicate_cell_object(self, StackCell cell):
        """ Deep copies a stackcell.  A duplicated stack cell must be freed using net_emulator.DotNetEmulator.dealloc_cell().
            This method isnt really used.
        Args:
            cell (net_emu_structs.StackCell): The stackcell to duplicate.

        Returns:
            net_emu_structs.StackCell: The deep duplicated cell.

        Raises:
            net_exceptions.EmulatorExecutionException: Internal error with the cell.
        """
        cdef StackCell duped_cell
        cdef net_emu_types.DotNetObject dup_object = None
        cdef int x = 0
        memset(&duped_cell, 0, sizeof(duped_cell))
        if cell.tag == CorElementType.ELEMENT_TYPE_STRING or cell.tag == CorElementType.ELEMENT_TYPE_OBJECT:
            if cell.is_slim_object:
                duped_cell.is_slim_object = True
                duped_cell.tag = CorElementType.ELEMENT_TYPE_OBJECT
                duped_cell.item.slim_object = <SlimObject*>malloc(sizeof(SlimObject))
                duped_cell.rid = cell.rid
                if duped_cell.item.slim_object == NULL:
                    raise net_exceptions.EmulatorExecutionException(self, 'memory error')
                memset(duped_cell.item.slim_object, 0, sizeof(SlimObject))
                duped_cell.item.slim_object.refs = 1
                duped_cell.item.slim_object.num_fields = cell.item.slim_object.num_fields
                duped_cell.item.slim_object.type_token = cell.item.slim_object.type_token
                if cell.item.slim_object.num_fields > 0:
                    duped_cell.item.slim_object.fields = <StackCell*>malloc(sizeof(StackCell) * cell.item.slim_object.num_fields)
                    if duped_cell.item.slim_object.fields == NULL:
                        raise net_exceptions.EmulatorExecutionException(self, 'memory error')
                    memset(duped_cell.item.slim_object.fields, 0, sizeof(StackCell) * cell.item.slim_object.num_fields)
                    for x in range(duped_cell.item.slim_object.num_fields):
                        duped_cell.item.slim_object.fields[x] = self.duplicate_cell_object(cell.item.slim_object.fields[x])
                        self.ref_cell(duped_cell.item.slim_object.fields[x])
            if cell.item.ref == NULL:
                return self.pack_null()
            dup_obj = <net_emu_types.DotNetObject>cell.item.ref
            dup_obj = dup_obj.duplicate()
            if not isinstance(dup_obj, net_emu_types.DotNetString):
                duped_cell = self.pack_object(dup_obj)
            else:
                duped_cell = self.pack_string(dup_obj)
        else:
            duped_cell = self.duplicate_cell(cell)
        return duped_cell

    cdef bint cell_is_not_equal(self, StackCell one, StackCell two):
        """ Used to compare two cells for non equality.

        Args:
            one (net_emu_structs.StackCell): The first argument to compare.
            two (net_emu_structs.StackCell): The second argument to compare.

        Returns:
            bool: True if not equal, False otherwise.
        """
        return not self.cell_is_equal(one, two)

    cdef StackCell cell_and(self, StackCell one, StackCell two):
        """ Performs an and operation on two numeric cells.
        
        Args:
            one (net_emu_structs.StackCell): The first argument for the operation.
            two (net_emu_structs.StackCell): the second argument for the opeartion.

        Returns:
            net_emu_structs.StackCell: A duplicated result.  The result must be freed.

        Raises:
            net_exceptions.InvalidArgumentsException: The operation currently cant handle the provided types.
        """
        cdef CorElementType tag1 = <CorElementType>one.tag
        cdef CorElementType tag2 = <CorElementType>two.tag
        cdef StackCell result = self.duplicate_cell(one)
        if tag1 == CorElementType.ELEMENT_TYPE_I4 or tag1 == CorElementType.ELEMENT_TYPE_U4:
            if tag2 == CorElementType.ELEMENT_TYPE_U4 or tag2 == CorElementType.ELEMENT_TYPE_I4:
                result.item.i4 &= two.item.i4
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_I or tag2 == CorElementType.ELEMENT_TYPE_U:
                if self.__is_64bit:
                    result.item.i4 &= two.item.i8
                else:
                    result.item.i4 &= two.item.i4
                return result
        elif tag1 == CorElementType.ELEMENT_TYPE_I8 or tag1 == CorElementType.ELEMENT_TYPE_U8:
            if tag2 == CorElementType.ELEMENT_TYPE_U8 or tag2 == CorElementType.ELEMENT_TYPE_I8:
                result.item.i8 &= two.item.i8
                return result
        elif tag1 == CorElementType.ELEMENT_TYPE_I or tag1 == CorElementType.ELEMENT_TYPE_U:
            if tag2 == CorElementType.ELEMENT_TYPE_I or tag2 == CorElementType.ELEMENT_TYPE_U:
                if self.__is_64bit:
                    result.item.i8 &= two.item.i8
                else:
                    result.item.i4 &= two.item.i4
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_I4 or tag2 == CorElementType.ELEMENT_TYPE_U4:
                if self.__is_64bit:
                    result.item.i8 &= two.item.i4
                else:
                    result.item.i4 &= two.item.i4
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_I8 or tag2 == CorElementType.ELEMENT_TYPE_U8:
                if self.__is_64bit:
                    result.item.i8 &= two.item.i8
                    return result
        raise net_exceptions.InvalidArgumentsException()

    cdef StackCell cell_add(self, StackCell one, StackCell two):
        """ Performs an add operation on two numeric cells.
        
        Args:
            one (net_emu_structs.StackCell): The first argument for the operation.
            two (net_emu_structs.StackCell): the second argument for the opeartion.

        Returns:
            net_emu_structs.StackCell: A duplicated result.  The result must be freed.

        Raises:
            net_exceptions.InvalidArgumentsException: The operation currently cant handle the provided types.
        """
        cdef CorElementType tag1 = <CorElementType>one.tag
        cdef CorElementType tag2 = <CorElementType>two.tag
        cdef StackCell result = self.duplicate_cell(one)
        if tag1 == CorElementType.ELEMENT_TYPE_I4 or tag1 == CorElementType.ELEMENT_TYPE_U4:
            if tag2 == CorElementType.ELEMENT_TYPE_I4 or tag2 == CorElementType.ELEMENT_TYPE_U4:
                result.item.i4 += two.item.i4
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_I or tag2 == CorElementType.ELEMENT_TYPE_U:
                result.tag = tag2
                if self.__is_64bit:
                    result.item.i8 += two.item.i8
                else:
                    result.item.i4 += two.item.i4
                return result
        elif tag1 == CorElementType.ELEMENT_TYPE_I8 or tag1 == CorElementType.ELEMENT_TYPE_U8:
            if tag2 == CorElementType.ELEMENT_TYPE_I8 or tag2 == CorElementType.ELEMENT_TYPE_U8:
                result.item.i8 += two.item.i8
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_I or tag2 == CorElementType.ELEMENT_TYPE_U:
                result.tag = CorElementType.ELEMENT_TYPE_U
                if self.__is_64bit:
                    result.item.i8 += two.item.i8
                else:
                    result.item.i4 += two.item.i4
                return result
        elif tag1 == CorElementType.ELEMENT_TYPE_I or tag1 == CorElementType.ELEMENT_TYPE_U:
            if tag2 == CorElementType.ELEMENT_TYPE_U or tag2 == CorElementType.ELEMENT_TYPE_I:
                if self.__is_64bit:
                    result.item.i8 += two.item.i8
                else:
                    result.item.i4 += two.item.i4
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_I4 or tag2 == CorElementType.ELEMENT_TYPE_U4:
                if self.__is_64bit:
                    result.item.i8 += two.item.i4
                else:
                    result.item.i4 += two.item.i4
                return result
        elif tag1 == CorElementType.ELEMENT_TYPE_R4 or tag2 == CorElementType.ELEMENT_TYPE_R8:
            if tag1 == tag2:
                result.item.r8 += two.item.r8
                return result
        raise net_exceptions.InvalidArgumentsException()

    cdef StackCell cell_divide(self, StackCell one, StackCell two):
        """ Performs an divide operation on two numeric cells.
        
        Args:
            one (net_emu_structs.StackCell): The first argument for the operation.
            two (net_emu_structs.StackCell): the second argument for the opeartion.

        Returns:
            net_emu_structs.StackCell: A duplicated result.  The result must be freed.

        Raises:
            net_exceptions.InvalidArgumentsException: The operation currently cant handle the provided types.
        """
        cdef CorElementType tag1 = <CorElementType>one.tag
        cdef CorElementType tag2 = <CorElementType>two.tag
        cdef StackCell result = self.duplicate_cell(one)
        if tag1 == CorElementType.ELEMENT_TYPE_I4:
            if tag2 == tag1:
                result.item.i4 /= two.item.i4
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_I:
                result.tag = CorElementType.ELEMENT_TYPE_I
                if self.__is_64bit:
                    result.item.i8 /= two.item.i8
                else:
                    result.item.i4 /= two.item.i4
                return result
        elif tag1 == CorElementType.ELEMENT_TYPE_U4:
            if tag2 == tag1:
                result.item.u4 /= two.item.u4
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_U:
                result.tag = CorElementType.ELEMENT_TYPE_U
                if self.__is_64bit:
                    result.item.u8 /= two.item.u8
                else:
                    result.item.u4 /= two.item.u4
                return result
        elif tag1 == CorElementType.ELEMENT_TYPE_I8:
            if tag2 == tag1:
                result.item.i8 /= two.item.i8
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_I:
                result.tag = CorElementType.ELEMENT_TYPE_I
                if self.__is_64bit:
                    result.item.i8 /= two.item.i8
                else:
                    result.item.i4 /= two.item.i4
                return result
        elif tag1 == CorElementType.ELEMENT_TYPE_U8:
            if tag2 == tag1:
                result.item.u8 /= two.item.u8
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_U:
                result.tag = CorElementType.ELEMENT_TYPE_U
                if self.__is_64bit:
                    result.item.u8 /= two.item.u8
                else:
                    result.item.u4 /= two.item.u4
                return result
        elif tag1 == CorElementType.ELEMENT_TYPE_I:
            if tag2 == tag1:
                if self.__is_64bit:
                    result.item.i8 /= two.item.i8
                else:
                    result.item.i4 /= two.item.i4
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_I4:
                if self.__is_64bit:
                    result.item.i8 /= two.item.i4
                else:
                    result.item.i4 /= two.item.i4
                return result
        elif tag1 == CorElementType.ELEMENT_TYPE_U:
            if tag2 == tag1:
                if self.__is_64bit:
                    result.item.u8 /= two.item.u8
                else:
                    result.item.u4 /= two.item.u4
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_U4:
                if self.__is_64bit:
                    result.item.u8 /= two.item.u4
                else:
                    result.item.u4 /= two.item.u4
                return result
        elif tag1 == CorElementType.ELEMENT_TYPE_R4 or tag2 == CorElementType.ELEMENT_TYPE_R8:
            if tag1 == tag2:
                result.item.r8 /= two.item.r8
                return result
        raise net_exceptions.InvalidArgumentsException()
    
    cdef StackCell cell_sub(self, StackCell one, StackCell two):
        """ Performs an subtract operation on two numeric cells.
        
        Args:
            one (net_emu_structs.StackCell): The first argument for the operation.
            two (net_emu_structs.StackCell): the second argument for the opeartion.

        Returns:
            net_emu_structs.StackCell: A duplicated result.  The result must be freed.

        Raises:
            net_exceptions.InvalidArgumentsException: The operation currently cant handle the provided types.
        """
        cdef CorElementType tag1 = <CorElementType>one.tag
        cdef CorElementType tag2 = <CorElementType>two.tag
        cdef StackCell result = self.duplicate_cell(one)
        #first check unsigned
        if tag1 == CorElementType.ELEMENT_TYPE_U or tag2 == CorElementType.ELEMENT_TYPE_U:
            if self.__is_64bit:
                result.item.u8 -= two.item.u8
            else:
                result.item.u4 -= two.item.u4
            result.tag = CorElementType.ELEMENT_TYPE_U
            return result
        elif tag1 == CorElementType.ELEMENT_TYPE_U4 or tag2 == CorElementType.ELEMENT_TYPE_U4:
            result.tag = CorElementType.ELEMENT_TYPE_U4
            result.item.u4 -= two.item.u4
            return result
        elif tag1 == CorElementType.ELEMENT_TYPE_U8 or tag2 == CorElementType.ELEMENT_TYPE_U8:
            result.tag = CorElementType.ELEMENT_TYPE_U8
            result.item.u8 -= two.item.u8
            return result
        elif tag1 == CorElementType.ELEMENT_TYPE_I4:
            if tag2 == tag1:
                result.item.i4 -= two.item.i4
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_I:
                result.tag = CorElementType.ELEMENT_TYPE_I
                if self.__is_64bit:
                    result.item.i8 -= two.item.i8
                else:
                    result.item.i4 -= two.item.i4
                return result
        elif tag1 == CorElementType.ELEMENT_TYPE_I8:
            if tag2 == tag1:
                result.item.i8 -= two.item.i8
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_I:
                result.tag = CorElementType.ELEMENT_TYPE_I
                if self.__is_64bit:
                    result.item.i8 -= two.item.i8
                else:
                    result.item.i4 -= two.item.i4
                return result
        elif tag1 == CorElementType.ELEMENT_TYPE_I:
            if tag2 == tag1:
                if self.__is_64bit:
                    result.item.i8 -= two.item.i8
                else:
                    result.item.i4 -= two.item.i4
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_I4:
                if self.__is_64bit:
                    result.item.i8 -= two.item.i4
                else:
                    result.item.i4 -= two.item.i4
                return result
        elif tag1 == CorElementType.ELEMENT_TYPE_R4 or tag2 == CorElementType.ELEMENT_TYPE_R8:
            if tag1 == tag2:
                result.item.r8 -= two.item.r8
                return result
        raise net_exceptions.InvalidArgumentsException()

    cdef StackCell cell_shl(self, StackCell one, StackCell two):
        """ Performs an shl operation on two numeric cells.
        
        Args:
            one (net_emu_structs.StackCell): The first argument for the operation.
            two (net_emu_structs.StackCell): the second argument for the opeartion.

        Returns:
            net_emu_structs.StackCell: A duplicated result.  The result must be freed.

        Raises:
            net_exceptions.InvalidArgumentsException: The operation currently cant handle the provided types.
        """
        cdef CorElementType tag1 = <CorElementType>one.tag
        cdef CorElementType tag2 = <CorElementType>two.tag
        cdef StackCell result = self.duplicate_cell(one)
        if tag1 == CorElementType.ELEMENT_TYPE_I4 or tag1 == CorElementType.ELEMENT_TYPE_U4:
            if tag2 == CorElementType.ELEMENT_TYPE_U4 or tag2 == CorElementType.ELEMENT_TYPE_I4:
                result.item.i4 <<= (two.item.u4 & 31)
                return result
        elif tag1 == CorElementType.ELEMENT_TYPE_I8 or tag1 == CorElementType.ELEMENT_TYPE_U8:
            if tag2 == CorElementType.ELEMENT_TYPE_U8 or tag2 == CorElementType.ELEMENT_TYPE_I8:
                result.item.i8 <<= (two.item.u8 & 63)
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_U4 or tag2 == CorElementType.ELEMENT_TYPE_I4:
                result.item.i8 <<= (two.item.u4 & 31)
                return result
        elif tag1 == CorElementType.ELEMENT_TYPE_I or tag1 == CorElementType.ELEMENT_TYPE_U:
            if tag2 == CorElementType.ELEMENT_TYPE_I or tag2 == CorElementType.ELEMENT_TYPE_U:
                if self.__is_64bit:
                    result.item.i8 <<= (two.item.u8 & 63)
                else:
                    result.item.i4 <<= (two.item.u4 & 31)
                return result
        raise net_exceptions.InvalidArgumentsException()

    cdef StackCell cell_shr(self, StackCell one, StackCell two):
        """ Performs an shr operation on two numeric cells.
        
        Args:
            one (net_emu_structs.StackCell): The first argument for the operation.
            two (net_emu_structs.StackCell): the second argument for the opeartion.

        Returns:
            net_emu_structs.StackCell: A duplicated result.  The result must be freed.

        Raises:
            net_exceptions.InvalidArgumentsException: The operation currently cant handle the provided types.
        """
        cdef CorElementType tag1 = <CorElementType>one.tag
        cdef CorElementType tag2 = <CorElementType>two.tag
        cdef StackCell result = self.duplicate_cell(one)
        if tag1 == CorElementType.ELEMENT_TYPE_I4 or tag1 == CorElementType.ELEMENT_TYPE_U4:
            if tag2 == CorElementType.ELEMENT_TYPE_I4:
                if tag1 == CorElementType.ELEMENT_TYPE_I4:
                    result.item.i4 >>= (two.item.u4 & 31)
                    return result
                else:
                    result.item.u4 >>= (two.item.u4 & 31)
                    return result
        elif tag1 == CorElementType.ELEMENT_TYPE_I8 or tag1 == CorElementType.ELEMENT_TYPE_U8:
            if tag2 == CorElementType.ELEMENT_TYPE_I8:
                if tag1 == CorElementType.ELEMENT_TYPE_I8:
                    result.item.i8 >>= (two.item.u8 & 63)
                    return result
                else:
                    result.item.u8 >>= (two.item.u8 & 63)
                    return result
            elif tag2 == CorElementType.ELEMENT_TYPE_I4:
                if tag1 == CorElementType.ELEMENT_TYPE_I8:
                    result.item.i8 >>= (two.item.u4 & 31)
                else:
                    result.item.u8 >>= (two.item.u4 & 31)
                return result
        elif tag1 == CorElementType.ELEMENT_TYPE_I or tag1 == CorElementType.ELEMENT_TYPE_U:
            if tag2 == CorElementType.ELEMENT_TYPE_I:
                if tag1 == CorElementType.ELEMENT_TYPE_I:
                    if self.__is_64bit:
                        result.item.i8 >>= (two.item.u8 & 63)
                    else:
                        result.item.i4 >>= (two.item.u4 & 31)
                    return result
                else:
                    if self.__is_64bit:
                        result.item.u8 >>= (two.item.u8 & 63)
                    else:
                        result.item.u4 >>= (two.item.u4 & 31)
                    return result

        raise net_exceptions.InvalidArgumentsException()

    cdef StackCell cell_or(self, StackCell one, StackCell two):
        """ Performs an or operation on two numeric cells.
        
        Args:
            one (net_emu_structs.StackCell): The first argument for the operation.
            two (net_emu_structs.StackCell): the second argument for the opeartion.

        Returns:
            net_emu_structs.StackCell: A duplicated result.  The result must be freed.

        Raises:
            net_exceptions.InvalidArgumentsException: The operation currently cant handle the provided types.
        """
        cdef CorElementType tag1 = <CorElementType>one.tag
        cdef CorElementType tag2 = <CorElementType>two.tag
        cdef StackCell result = self.duplicate_cell(one)
        if tag1 == CorElementType.ELEMENT_TYPE_I4 or tag1 == CorElementType.ELEMENT_TYPE_U4:
            if tag2 == CorElementType.ELEMENT_TYPE_I4 or tag2 == CorElementType.ELEMENT_TYPE_U4:
                result.item.i4 |= two.item.i4
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_I or tag2 == CorElementType.ELEMENT_TYPE_U:
                if self.__is_64bit:
                    result.item.i4 |= two.item.i4
                else:
                    result.item.i4 |= two.item.i4
                return result
        elif tag1 == CorElementType.ELEMENT_TYPE_I8 or tag1 == CorElementType.ELEMENT_TYPE_U8:
            if tag2 == CorElementType.ELEMENT_TYPE_U8 or tag2 == CorElementType.ELEMENT_TYPE_I8:
                result.item.i8 |= two.item.i8
                return result
        elif tag1 == CorElementType.ELEMENT_TYPE_I or tag1 == CorElementType.ELEMENT_TYPE_U:
            if tag2 == CorElementType.ELEMENT_TYPE_I or tag2 == CorElementType.ELEMENT_TYPE_U:
                if self.__is_64bit:
                    result.item.i8 |= two.item.i8
                else:
                    result.item.i4 |= two.item.i4
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_I4 or tag2 == CorElementType.ELEMENT_TYPE_U4:
                if self.__is_64bit:
                    result.item.i8 |= <int64_t>two.item.i4
                else:
                    result.item.i4 |= two.item.i4
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_I8 or tag2 == CorElementType.ELEMENT_TYPE_U8:
                if self.__is_64bit:
                    result.item.i8 |= two.item.i8
                    return result
        raise net_exceptions.InvalidArgumentsException()

    cdef StackCell cell_xor(self, StackCell one, StackCell two):
        """ Performs an xor operation on two numeric cells.
        
        Args:
            one (net_emu_structs.StackCell): The first argument for the operation.
            two (net_emu_structs.StackCell): the second argument for the opeartion.

        Returns:
            net_emu_structs.StackCell: A duplicated result.  The result must be freed.

        Raises:
            net_exceptions.InvalidArgumentsException: The operation currently cant handle the provided types.
        """
        cdef CorElementType tag1 = <CorElementType>one.tag
        cdef CorElementType tag2 = <CorElementType>two.tag
        cdef StackCell result = self.duplicate_cell(one)
        if tag1 == CorElementType.ELEMENT_TYPE_I4 or tag1 == CorElementType.ELEMENT_TYPE_U4:
            if tag2 == CorElementType.ELEMENT_TYPE_U4 or tag2 == CorElementType.ELEMENT_TYPE_I4:
                result.item.i4 ^= two.item.i4
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_I or tag2 == CorElementType.ELEMENT_TYPE_U:
                if self.__is_64bit:
                    result.item.i4 ^= two.item.i4 
                else:
                    result.item.i4 ^= two.item.i4
                return result
        elif tag1 == CorElementType.ELEMENT_TYPE_I8 or tag1 == CorElementType.ELEMENT_TYPE_U8:
            if tag2 == CorElementType.ELEMENT_TYPE_U8 or tag2 == CorElementType.ELEMENT_TYPE_I8:
                result.item.i8 ^= two.item.i8
                return result
        elif tag1 == CorElementType.ELEMENT_TYPE_I or tag1 == CorElementType.ELEMENT_TYPE_U:
            if tag2 == CorElementType.ELEMENT_TYPE_U or tag2 == CorElementType.ELEMENT_TYPE_I:
                if self.__is_64bit:
                    result.item.i8 ^= two.item.i8
                else:
                    result.item.i4 ^= two.item.i4
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_I4 or tag2 == CorElementType.ELEMENT_TYPE_U4:
                if self.__is_64bit:
                    result.item.i8 ^= two.item.i4
                else:
                    result.item.i4 ^= two.item.i4
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_I8 or tag2 == CorElementType.ELEMENT_TYPE_U8:
                if self.__is_64bit:
                    result.item.i8 ^= two.item.i8
                    return result
        raise net_exceptions.InvalidArgumentsException()

    cdef StackCell cell_neg(self, StackCell one):
        """ Performs an neg operation on a numeric cells.
        
        Args:
            one (net_emu_structs.StackCell): The first argument for the operation.

        Returns:
            net_emu_structs.StackCell: A duplicated result.  The result must be freed.

        Raises:
            net_exceptions.InvalidArgumentsException: The operation currently cant handle the provided types.
        """
        cdef CorElementType tag1 = <CorElementType>one.tag
        cdef StackCell result = self.duplicate_cell(one)
        if tag1 == CorElementType.ELEMENT_TYPE_I4:
            result.item.i4 = -1 * result.item.i4
            return result
        elif tag1 == CorElementType.ELEMENT_TYPE_I8:
            result.item.i8 = -1 * result.item.i8
            return result
        elif tag1 == CorElementType.ELEMENT_TYPE_I:
            if self.__is_64bit:
                result.item.i8 = -1 * result.item.i8
            else:
                result.item.i4 = -1 * result.item.i4
            return result
        elif tag1 == CorElementType.ELEMENT_TYPE_R4:
            result.item.r8 = -1 * <float>result.item.r8
            return result
        elif tag1 == CorElementType.ELEMENT_TYPE_R8:
            result.item.r8 = -1 * result.item.r8
            return result

        raise net_exceptions.InvalidArgumentsException()
            

    cdef StackCell cell_multiply(self, StackCell one, StackCell two):
        """ Performs an multiply operation on two numeric cells.
        
        Args:
            one (net_emu_structs.StackCell): The first argument for the operation.
            two (net_emu_structs.StackCell): the second argument for the opeartion.

        Returns:
            net_emu_structs.StackCell: A duplicated result.  The result must be freed.

        Raises:
            net_exceptions.InvalidArgumentsException: The operation currently cant handle the provided types.
        """
        cdef CorElementType tag1 = <CorElementType>one.tag
        cdef CorElementType tag2 = <CorElementType>two.tag
        cdef StackCell result = self.duplicate_cell(one)
        if tag1 == CorElementType.ELEMENT_TYPE_I4 or tag1 == CorElementType.ELEMENT_TYPE_U4:
            if tag2 == CorElementType.ELEMENT_TYPE_U4 or tag2 == CorElementType.ELEMENT_TYPE_I4:
                result.item.i4 *= two.item.i4
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_I or tag2 == CorElementType.ELEMENT_TYPE_U:
                result.tag = tag2
                if self.__is_64bit:
                    result.item.i8 *= two.item.i8
                else:
                    result.item.i4 *= two.item.i4
                return result
        elif tag1 == CorElementType.ELEMENT_TYPE_I8 or tag1 == CorElementType.ELEMENT_TYPE_U8:
            if tag2 == CorElementType.ELEMENT_TYPE_U8 or tag2 == CorElementType.ELEMENT_TYPE_I8:
                result.item.i8 *= two.item.i8
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_I or tag2 == CorElementType.ELEMENT_TYPE_U:
                result.tag = tag2
                if self.__is_64bit:
                    result.item.i8 *= two.item.i8
                else:
                    result.item.i4 *= two.item.i4
                return result
        elif tag1 == CorElementType.ELEMENT_TYPE_I or tag1 == CorElementType.ELEMENT_TYPE_U:
            if tag2 == CorElementType.ELEMENT_TYPE_U or tag2 == CorElementType.ELEMENT_TYPE_I:
                if self.__is_64bit:
                    result.item.i8 *= two.item.i8
                else:
                    result.item.i4 *= two.item.i4
                return result
            elif tag2 == CorElementType.ELEMENT_TYPE_I4 or tag2 == CorElementType.ELEMENT_TYPE_U4:
                if self.__is_64bit:
                    result.item.i8 *= two.item.i4
                else:
                    result.item.i4 *= two.item.i4
                return result
        elif tag1 == CorElementType.ELEMENT_TYPE_R4 or tag1 == CorElementType.ELEMENT_TYPE_R8:
            if tag1 == tag2:
                result.item.r8 *= two.item.r8
                return result
        raise net_exceptions.InvalidArgumentsException()

    cdef StackCell cell_rem(self, StackCell one, StackCell two):
        """ Performs an rem operation on two numeric cells.
        
        Args:
            one (net_emu_structs.StackCell): The first argument for the operation.
            two (net_emu_structs.StackCell): the second argument for the opeartion.

        Returns:
            net_emu_structs.StackCell: A duplicated result.  The result must be freed.

        Raises:
            net_exceptions.InvalidArgumentsException: The operation currently cant handle the provided types.
        """
        if one.tag == CorElementType.ELEMENT_TYPE_I4 and two.tag == one.tag:
            return self.pack_i4(net_emu_types.rem_i4(one.item.i4, two.item.i4))
        elif one.tag == CorElementType.ELEMENT_TYPE_I8 and one.tag == two.tag:
            return self.pack_i8(net_emu_types.rem_i8(one.item.i8, two.item.i8))
        elif one.tag == CorElementType.ELEMENT_TYPE_U4 and one.tag == two.tag:
            return self.pack_u4(net_emu_types.rem_u4(one.item.u4, two.item.u4))
        elif one.tag == CorElementType.ELEMENT_TYPE_U8 and one.tag == two.tag:
            return self.pack_u8(net_emu_types.rem_u8(one.item.u8, two.item.u8))
        raise net_exceptions.InvalidArgumentsException()

    cdef bint cell_is_lt(self, StackCell one, StackCell two):
        """ Used to compare two cells for less than.

        Args:
            one (net_emu_structs.StackCell): The first argument to compare.
            two (net_emu_structs.StackCell): The second argument to compare.

        Returns:
            bool: True if one is less than two, False otherwise.

        Raises:
            net_exceptions.FeatureNotImplementedException: Attempted to compare objects. Not implemented currently.
            net_exceptions.InvalidArgumentsException: The arguments provided are not currently supported.
        """
        cdef StackCell ref_one
        cdef StackCell ref_two
        cdef bint result = False

        if one.tag != two.tag:
            raise net_exceptions.InvalidArgumentsException()
        if one.tag == CorElementType.ELEMENT_TYPE_STRING or one.tag == CorElementType.ELEMENT_TYPE_OBJECT or \
            two.tag == CorElementType.ELEMENT_TYPE_OBJECT or two.tag == CorElementType.ELEMENT_TYPE_STRING:
            raise net_exceptions.FeatureNotImplementedException

        elif one.tag == CorElementType.ELEMENT_TYPE_BYREF or two.tag == CorElementType.ELEMENT_TYPE_BYREF:
            if one.tag == CorElementType.ELEMENT_TYPE_BYREF:
                ref_one = self.get_ref(one)
            else:
                ref_one = self.duplicate_cell(one)
            
            if two.tag == CorElementType.ELEMENT_TYPE_BYREF:
                ref_two = self.get_ref(two)
            else:
                ref_two = self.duplicate_cell(two)
            result = self.cell_is_lt(ref_one, ref_two)
            self.dealloc_cell(ref_one)
            self.dealloc_cell(ref_two)
            return result
        elif one.tag == CorElementType.ELEMENT_TYPE_BOOLEAN:
            if two.tag != CorElementType.ELEMENT_TYPE_BOOLEAN:
                raise net_exceptions.InvalidArgumentsException()
            return not one.item.b and two.item.b
        elif one.tag == CorElementType.ELEMENT_TYPE_I4:
            return one.item.i4 < two.item.i4
        elif one.tag == CorElementType.ELEMENT_TYPE_U4:
            return one.item.u4 < two.item.u4
        elif one.tag == CorElementType.ELEMENT_TYPE_I8:
            return one.item.i8 < two.item.i8
        elif one.tag == CorElementType.ELEMENT_TYPE_U8:
            return one.item.u8 < two.item.u8
        elif one.tag == CorElementType.ELEMENT_TYPE_I:
            if self.__is_64bit:
                return one.item.i8 < two.item.i8
            else:
                return one.item.i4 < two.item.i4
        elif one.tag == CorElementType.ELEMENT_TYPE_R4:
            if two.tag != CorElementType.ELEMENT_TYPE_R4:
                raise net_exceptions.InvalidArgumentsException()
            return <float>one.item.r8 < <float>two.item.r8
        elif one.tag == CorElementType.ELEMENT_TYPE_R8:
            if two.tag != CorElementType.ELEMENT_TYPE_R8:
                raise net_exceptions.InvalidArgumentsException()
            return one.item.r8 < two.item.r8
        else:
            raise net_exceptions.InvalidArgumentsException()

    cdef bint cell_is_le(self, StackCell one, StackCell two):
        """ Used to compare two cells for less than or equal to.

        Args:
            one (net_emu_structs.StackCell): The first argument to compare.
            two (net_emu_structs.StackCell): The second argument to compare.

        Returns:
            bool: True if one is less than or equal to two, False otherwise.

        Raises:
            net_exceptions.FeatureNotImplementedException: Attempted to compare objects. Not implemented currently.
            net_exceptions.InvalidArgumentsException: The arguments provided are not currently supported.
        """
        cdef StackCell ref_one
        cdef StackCell ref_two
        cdef bint result = False

        if one.tag != two.tag:
            raise net_exceptions.InvalidArgumentsException()
        if one.tag == CorElementType.ELEMENT_TYPE_STRING or one.tag == CorElementType.ELEMENT_TYPE_OBJECT or \
            two.tag == CorElementType.ELEMENT_TYPE_OBJECT or two.tag == CorElementType.ELEMENT_TYPE_STRING:
            raise net_exceptions.FeatureNotImplementedException

        elif one.tag == CorElementType.ELEMENT_TYPE_BYREF or two.tag == CorElementType.ELEMENT_TYPE_BYREF:
            if one.tag == CorElementType.ELEMENT_TYPE_BYREF:
                ref_one = self.get_ref(one)
            else:
                ref_one = self.duplicate_cell(one)
            
            if two.tag == CorElementType.ELEMENT_TYPE_BYREF:
                ref_two = self.get_ref(two)
            else:
                ref_two = self.duplicate_cell(two)
            result = self.cell_is_le(ref_one, ref_two)
            self.dealloc_cell(ref_one)
            self.dealloc_cell(ref_two)
            return result
        elif one.tag == CorElementType.ELEMENT_TYPE_BOOLEAN:
            if two.tag != CorElementType.ELEMENT_TYPE_BOOLEAN:
                raise net_exceptions.InvalidArgumentsException()
            return (not one.item.b and two.item.b) or (one.item.b == two.item.b)
        elif one.tag == CorElementType.ELEMENT_TYPE_I4:
            return one.item.i4 <= two.item.i4
        elif one.tag == CorElementType.ELEMENT_TYPE_U4:
            return one.item.u4 <= two.item.u4
        elif one.tag == CorElementType.ELEMENT_TYPE_I8:
            return one.item.i8 <= two.item.i8
        elif one.tag == CorElementType.ELEMENT_TYPE_U8:
            return one.item.u8 <= two.item.u8
        elif one.tag == CorElementType.ELEMENT_TYPE_I:
            if self.__is_64bit:
                return one.item.i8 <= two.item.i8
            else:
                return one.item.i4 <= two.item.i4
        elif one.tag == CorElementType.ELEMENT_TYPE_R4:
            if two.tag != CorElementType.ELEMENT_TYPE_R4:
                raise net_exceptions.InvalidArgumentsException()
            return <float>one.item.r8 <= <float>two.item.r8
        elif one.tag == CorElementType.ELEMENT_TYPE_R8:
            if two.tag != CorElementType.ELEMENT_TYPE_R8:
                raise net_exceptions.InvalidArgumentsException()
            return one.item.r8 <= two.item.r8
        else:
            raise net_exceptions.InvalidArgumentsException()

    cdef bint cell_is_ge(self, StackCell one, StackCell two):
        """ Used to compare two cells for greater than or equal to.

        Args:
            one (net_emu_structs.StackCell): The first argument to compare.
            two (net_emu_structs.StackCell): The second argument to compare.

        Returns:
            bool: True if one is greater than or equal to two, False otherwise.

        Raises:
            net_exceptions.FeatureNotImplementedException: Attempted to compare objects. Not implemented currently.
            net_exceptions.InvalidArgumentsException: The arguments provided are not currently supported.
        """
        cdef StackCell ref_one
        cdef StackCell ref_two
        cdef bint result = False

        if one.tag != two.tag:
            raise net_exceptions.InvalidArgumentsException()
        if one.tag == CorElementType.ELEMENT_TYPE_STRING or one.tag == CorElementType.ELEMENT_TYPE_OBJECT or \
            two.tag == CorElementType.ELEMENT_TYPE_OBJECT or two.tag == CorElementType.ELEMENT_TYPE_STRING:
            raise net_exceptions.FeatureNotImplementedException

        elif one.tag == CorElementType.ELEMENT_TYPE_BYREF or two.tag == CorElementType.ELEMENT_TYPE_BYREF:
            if one.tag == CorElementType.ELEMENT_TYPE_BYREF:
                ref_one = self.get_ref(one)
            else:
                ref_one = self.duplicate_cell(one)
            
            if two.tag == CorElementType.ELEMENT_TYPE_BYREF:
                ref_two = self.get_ref(two)
            else:
                ref_two = self.duplicate_cell(two)
            result = self.cell_is_ge(ref_one, ref_two)
            self.dealloc_cell(ref_one)
            self.dealloc_cell(ref_two)
            return result
        elif one.tag == CorElementType.ELEMENT_TYPE_BOOLEAN:
            if two.tag != CorElementType.ELEMENT_TYPE_BOOLEAN:
                raise net_exceptions.InvalidArgumentsException()
            return (one.item.b and not two.item.b) or (one.item.b == two.item.b)
        elif one.tag == CorElementType.ELEMENT_TYPE_I4:
            return one.item.i4 >= two.item.i4
        elif one.tag == CorElementType.ELEMENT_TYPE_U4:
            return one.item.u4 >= two.item.u4
        elif one.tag == CorElementType.ELEMENT_TYPE_I8:
            return one.item.i8 >= two.item.i8
        elif one.tag == CorElementType.ELEMENT_TYPE_U8:
            return one.item.u8 >= two.item.u8
        elif one.tag == CorElementType.ELEMENT_TYPE_I:
            if self.__is_64bit:
                return one.item.i8 >= two.item.i8
            else:
                return one.item.i4 >= two.item.i4
        elif one.tag == CorElementType.ELEMENT_TYPE_R4:
            if two.tag != CorElementType.ELEMENT_TYPE_R4:
                raise net_exceptions.InvalidArgumentsException()
            return <float>one.item.r8 >= <float>two.item.r8
        elif one.tag == CorElementType.ELEMENT_TYPE_R8:
            if two.tag != CorElementType.ELEMENT_TYPE_R8:
                raise net_exceptions.InvalidArgumentsException()
            return one.item.r8 >= two.item.r8
        else:
            raise net_exceptions.InvalidArgumentsException()

    cdef bint cell_is_gt(self, StackCell one, StackCell two):
        """ Used to compare two cells for greater than.

        Args:
            one (net_emu_structs.StackCell): The first argument to compare.
            two (net_emu_structs.StackCell): The second argument to compare.

        Returns:
            bool: True if one is greater than two, False otherwise.

        Raises:
            net_exceptions.FeatureNotImplementedException: Attempted to compare objects. Not implemented currently.
            net_exceptions.InvalidArgumentsException: The arguments provided are not currently supported.
        """
        cdef StackCell ref_one
        cdef StackCell ref_two
        cdef bint result = False

        if one.tag != two.tag:
            if one.tag != CorElementType.ELEMENT_TYPE_OBJECT and one.tag != CorElementType.ELEMENT_TYPE_STRING:
                raise net_exceptions.InvalidArgumentsException()
            if two.tag != CorElementType.ELEMENT_TYPE_OBJECT and two.tag != CorElementType.ELEMENT_TYPE_STRING:
                raise net_exceptions.InvalidArgumentsException()
        if one.tag == CorElementType.ELEMENT_TYPE_STRING or one.tag == CorElementType.ELEMENT_TYPE_OBJECT or \
            two.tag == CorElementType.ELEMENT_TYPE_OBJECT or two.tag == CorElementType.ELEMENT_TYPE_STRING:
            if self.cell_is_null(one):
                return False

            if self.cell_is_null(two):
                return True
            raise net_exceptions.FeatureNotImplementedException

        elif one.tag == CorElementType.ELEMENT_TYPE_BYREF or two.tag == CorElementType.ELEMENT_TYPE_BYREF:
            if one.tag == CorElementType.ELEMENT_TYPE_BYREF:
                ref_one = self.get_ref(one)
            else:
                ref_one = self.duplicate_cell(one)
            
            if two.tag == CorElementType.ELEMENT_TYPE_BYREF:
                ref_two = self.get_ref(two)
            else:
                ref_two = self.duplicate_cell(two)
            result = self.cell_is_gt(ref_one, ref_two)
            self.dealloc_cell(ref_one)
            self.dealloc_cell(ref_two)
            return result
        elif one.tag == CorElementType.ELEMENT_TYPE_BOOLEAN:
            if two.tag != CorElementType.ELEMENT_TYPE_BOOLEAN:
                raise net_exceptions.InvalidArgumentsException()
            return one.item.b and not two.item.b
        elif one.tag == CorElementType.ELEMENT_TYPE_I4:
            return one.item.i4 > two.item.i4
        elif one.tag == CorElementType.ELEMENT_TYPE_U4:
            return one.item.u4 > two.item.u4
        elif one.tag == CorElementType.ELEMENT_TYPE_I8:
            return one.item.i8 > two.item.i8
        elif one.tag == CorElementType.ELEMENT_TYPE_U8:
            return one.item.u8 > two.item.u8
        elif one.tag == CorElementType.ELEMENT_TYPE_I:
            if self.__is_64bit:
                return one.item.i8 > two.item.i8
            else:
                return one.item.i4 > two.item.i4
        elif one.tag == CorElementType.ELEMENT_TYPE_R4:
            if two.tag != CorElementType.ELEMENT_TYPE_R4:
                raise net_exceptions.InvalidArgumentsException()
            return <float>one.item.r8 > <float>two.item.r8
        elif one.tag == CorElementType.ELEMENT_TYPE_R8:
            if two.tag != CorElementType.ELEMENT_TYPE_R8:
                raise net_exceptions.InvalidArgumentsException()
            return one.item.r8 > two.item.r8
        else:
            raise net_exceptions.InvalidArgumentsException()

    cdef StackCellWrapper wrap_cell(self, StackCell cell):
        """ Used internally to wrap a StackCell into a StackCellWrapper.
            A StackCellWrapper contains all of the originals references so it must be dereferenced and dealloced
            once it is converted back to a stackcell.
        """
        return StackCellWrapper(self, cell.tag, cell.item.u8, <uint64_t>cell.item.ref, cell.item.byref.kind, cell.item.byref.idx, <uint64_t>cell.item.byref.owner, cell.rid, <uint64_t>cell.extra_data, cell.is_slim_object)

    cpdef void setup_method_params(self, list method_params):
        """ Used by users to set up method params.
            Takes a list of dotnetobjects, unboxes them, and adds them as method parameters.

        Args:
            method_params (list[net_emu_types.DotNetObject]): A list of parameters to setup.
        """
        cdef net_emu_types.DotNetObject param_val = None
        cdef int x = 0
        cdef StackCell unboxed
        cdef StackCell obj
        cdef net_sigs.MethodSig method_sig = self.method_obj.get_method_signature()
        self._allocate_params(<int>len(method_params))
        for param_val in method_params:
            if isinstance(param_val, net_emu_types.DotNetString):
                obj = self.pack_string(param_val)
            else:
                obj = self.pack_object(param_val)
            unboxed = self.unbox_value(obj)
            self._add_param(x, unboxed)
            self.dealloc_cell(obj)
            self.dealloc_cell(unboxed)
            x += 1

    cdef void _allocate_params(self, int nparams):
        """ Allocates parameter space for the emulator.

        Args:
            nparams (int): Number of params to allocate for.

        Raises:
            net_exceptions.OperationNotSupportedException: internal error.
        """
        if self.__method_params != NULL:
            raise net_exceptions.OperationNotSupportedException()
        self.__nparams = nparams
        if nparams == 0:
            return
        self.__method_params = <StackCell*>malloc(sizeof(StackCell) * nparams)
        memset(self.__method_params, 0, sizeof(StackCell) * nparams)

    cdef StackCell cast_cell(self, StackCell cell, net_sigs.TypeSig sig):
        """ Casts a cell from one TypeSig to another.
            Returns a duplicated cell in all cases that must be freed.
            In some cases this will do nothing and simply return a duplicated cell (objects)

        Args:
            cell (net_emu_structs.StackCell): The cell to cast.
            sig (net_sigs.TypeSig): The signature of the resulting type.

        Returns:
            net_emu_structs.StackCell: A duplicated cell casted to sig.

        Raises:
            net_exceptions.InvalidArgumentsException: The arguments provided are not supported by this method.
        """
        cdef CorElementType etype = CorElementType.ELEMENT_TYPE_END
        cdef StackCell result
        if isinstance(sig, net_sigs.CorLibTypeSig):
            etype = sig.get_element_type()
            result = self.duplicate_cell(cell)
            if net_utils.is_cortype_number(etype):
                result.tag = etype
                result.item.i8 = 0
                if etype == CorElementType.ELEMENT_TYPE_I1:
                    if cell.tag == CorElementType.ELEMENT_TYPE_I1:
                        result.item.i1 = cell.item.i1
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I2:
                        result.item.i1 = <char>cell.item.i2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I4:
                        result.item.i1 = <char>cell.item.i4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I8:
                        result.item.i1 = <char>cell.item.i8
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I:
                        if self.__is_64bit:
                            result.item.i1 = <char>cell.item.i8
                        else:
                            result.item.i1 = <char>cell.item.i4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U1:
                        result.item.i1 = <char>cell.item.u1
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U2:
                        result.item.i1 = <char>cell.item.u2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U4:
                        result.item.i1 = <char>cell.item.u4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U8:
                        result.item.i1 = <char>cell.item.u8
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U:
                        if self.__is_64bit:
                            result.item.i1 = <char>cell.item.u8
                        else:
                            result.item.i1 = <char>cell.item.u4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_CHAR:
                        result.item.i1 = <char>cell.item.u2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_R4:
                        result.item.i1 = <char>cell.item.r4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_R8:
                        result.item.i1 = <char>cell.item.r8
                    else:
                        raise net_exceptions.InvalidArgumentsException()
                    
                elif etype == CorElementType.ELEMENT_TYPE_I2:
                    if cell.tag == CorElementType.ELEMENT_TYPE_I1:
                        result.item.i2 = <short>cell.item.i1
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I2:
                        result.item.i2 = <short>cell.item.i2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I4:
                        result.item.i2 = <short>cell.item.i4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I8:
                        result.item.i2 = <short>cell.item.i8
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I:
                        if self.__is_64bit:
                            result.item.i2 = <short>cell.item.i8
                        else:
                            result.item.i2 = <short>cell.item.i4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U1:
                        result.item.i2 = <short>cell.item.u1
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U2:
                        result.item.i2 = <short>cell.item.u2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U4:
                        result.item.i2 = <short>cell.item.u4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U8:
                        result.item.i2 = <short>cell.item.u8
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U:
                        if self.__is_64bit:
                            result.item.i2 = <short>cell.item.u8
                        else:
                            result.item.i2 = <short>cell.item.u4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_CHAR:
                        result.item.i2 = <short>cell.item.u2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_R4:
                        result.item.i2 = <short>cell.item.r4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_R8:
                        result.item.i2 = <short>cell.item.r8
                    else:
                        raise net_exceptions.InvalidArgumentsException()
                elif etype == CorElementType.ELEMENT_TYPE_I4:
                    if cell.tag == CorElementType.ELEMENT_TYPE_I1:
                        result.item.i4 = <int>cell.item.i1
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I2:
                        result.item.i4 = <int>cell.item.i2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I4:
                        result.item.i4 = <int>cell.item.i4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I8:
                        result.item.i4 = <int>cell.item.i8
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I:
                        if self.__is_64bit:
                            result.item.i4 = <int>cell.item.i8
                        else:
                            result.item.i4 = <int>cell.item.i4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U1:
                        result.item.i4 = <int>cell.item.u1
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U2:
                        result.item.i4 = <int>cell.item.u2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U4:
                        result.item.i4 = <int>cell.item.u4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U8:
                        result.item.i4 = <int>cell.item.u8
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U:
                        if self.__is_64bit:
                            result.item.i4 = <int>cell.item.u8
                        else:
                            result.item.i4 = <int>cell.item.u4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_CHAR:
                        result.item.i4 = <int>cell.item.u2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_R4:
                        result.item.i4 = <int>cell.item.r4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_R8:
                        result.item.i4 = <int>cell.item.r8
                    elif cell.tag == CorElementType.ELEMENT_TYPE_BOOLEAN:
                        if cell.item.b:
                            result.item.i4 = 1
                        else:
                            result.item.i4 = 0
                    else:
                        raise net_exceptions.InvalidArgumentsException()
                elif etype == CorElementType.ELEMENT_TYPE_U1:
                    if cell.tag == CorElementType.ELEMENT_TYPE_I1:
                        result.item.u1 = <unsigned char>cell.item.i1
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I2:
                        result.item.u1 = <unsigned char>cell.item.i2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I4:
                        result.item.u1 = <unsigned char>cell.item.i4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I8:
                        result.item.u1 = <unsigned char>cell.item.i8
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I:
                        if self.__is_64bit:
                            result.item.u1 = <unsigned char>cell.item.i8
                        else:
                            result.item.u1 = <unsigned char>cell.item.i4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U1:
                        result.item.u1 = <unsigned char>cell.item.u1
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U2:
                        result.item.u1 = <unsigned char>cell.item.u2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U4:
                        result.item.u1 = <unsigned char>cell.item.u4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U8:
                        result.item.u1 = <unsigned char>cell.item.u8
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U:
                        if self.__is_64bit:
                            result.item.u1 = <unsigned char>cell.item.u8
                        else:
                            result.item.u1 = <unsigned char>cell.item.u4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_CHAR:
                        result.item.u1 = <unsigned char>cell.item.u2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_R4:
                        result.item.u1 = <unsigned char>cell.item.r4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_R8:
                        result.item.u1 = <unsigned char>cell.item.r8
                    else:
                        raise net_exceptions.InvalidArgumentsException()
                elif etype == CorElementType.ELEMENT_TYPE_U2:
                    if cell.tag == CorElementType.ELEMENT_TYPE_I1:
                        result.item.u2 = <unsigned short>cell.item.i1
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I2:
                        result.item.u2 = <unsigned short>cell.item.i2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I4:
                        result.item.u2 = <unsigned short>cell.item.i4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I8:
                        result.item.u2 = <unsigned short>cell.item.i8
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I:
                        if self.__is_64bit:
                            result.item.u2 = <unsigned short>cell.item.i8
                        else:
                            result.item.u2 = <unsigned short>cell.item.i4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U1:
                        result.item.u2 = <unsigned short>cell.item.u1
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U2:
                        result.item.u2 = <unsigned short>cell.item.u2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U4:
                        result.item.u2 = <unsigned short>cell.item.u4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U8:
                        result.item.u2 = <unsigned short>cell.item.u8
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U:
                        if self.__is_64bit:
                            result.item.u2 = <unsigned short>cell.item.u8
                        else:
                            result.item.u2 = <unsigned short>cell.item.u4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_CHAR:
                        result.item.u2 = <unsigned short>cell.item.u2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_R4:
                        result.item.u2 = <unsigned short>cell.item.r4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_R8:
                        result.item.u2 = <unsigned short>cell.item.r8
                    else:
                        raise net_exceptions.InvalidArgumentsException()
                elif etype == CorElementType.ELEMENT_TYPE_U4:
                    if cell.tag == CorElementType.ELEMENT_TYPE_I1:
                        result.item.u4 = <unsigned int>cell.item.i1
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I2:
                        result.item.u4 = <unsigned int>cell.item.i2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I4:
                        result.item.u4 = <unsigned int>cell.item.i4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I8:
                        result.item.u4 = <unsigned int>cell.item.i8
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I:
                        if self.__is_64bit:
                            result.item.u4 = <unsigned int>cell.item.i8
                        else:
                            result.item.u4 = <unsigned int>cell.item.i4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U1:
                        result.item.u4 = <unsigned int>cell.item.u1
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U2:
                        result.item.u4 = <unsigned int>cell.item.u2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U4:
                        result.item.u4 = <unsigned int>cell.item.u4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U8:
                        result.item.u4 = <unsigned int>cell.item.u8
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U:
                        if self.__is_64bit:
                            result.item.u4 = <unsigned int>cell.item.u8
                        else:
                            result.item.u4 = <unsigned int>cell.item.u4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_CHAR:
                        result.item.u4 = <unsigned int>cell.item.u2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_R4:
                        result.item.u4 = <unsigned int>cell.item.r4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_R8:
                        result.item.u4 = <unsigned int>cell.item.r8
                    else:
                        raise net_exceptions.InvalidArgumentsException()
                elif etype == CorElementType.ELEMENT_TYPE_CHAR:
                    if cell.tag == CorElementType.ELEMENT_TYPE_I1:
                        result.item.u2 = <unsigned short>cell.item.i1
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I2:
                        result.item.u2 = <unsigned short>cell.item.i2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I4:
                        result.item.u2 = <unsigned short>cell.item.i4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I8:
                        result.item.u2 = <unsigned short>cell.item.i8
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I:
                        if self.__is_64bit:
                            result.item.u2 = <unsigned short>cell.item.i8
                        else:
                            result.item.u2 = <unsigned short>cell.item.i4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U1:
                        result.item.u2 = <unsigned short>cell.item.u1
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U2:
                        result.item.u2 = <unsigned short>cell.item.u2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U4:
                        result.item.u2 = <unsigned short>cell.item.u4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U8:
                        result.item.u2 = <unsigned short>cell.item.u8
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U:
                        if self.__is_64bit:
                            result.item.u2 = <unsigned short>cell.item.u8
                        else:
                            result.item.u2 = <unsigned short>cell.item.u4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_CHAR:
                        result.item.u2 = <unsigned short>cell.item.u2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_R4:
                        result.item.u2 = <unsigned short>cell.item.r4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_R8:
                        result.item.u2 = <unsigned short>cell.item.r8
                    else:
                        raise net_exceptions.InvalidArgumentsException()
                elif etype == CorElementType.ELEMENT_TYPE_R4:
                    if cell.tag == CorElementType.ELEMENT_TYPE_I1:
                        result.item.r4 = <float>cell.item.i1
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I2:
                        result.item.r4 = <float>cell.item.i2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I4:
                        result.item.r4 = <float>cell.item.i4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I8:
                        result.item.r4 = <float>cell.item.i8
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I:
                        if self.__is_64bit:
                            result.item.r4 = <float>cell.item.i8
                        else:
                            result.item.r4 = <float>cell.item.i4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U1:
                        result.item.r4 = <float>cell.item.u1
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U2:
                        result.item.r4 = <float>cell.item.u2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U4:
                        result.item.r4 = <float>cell.item.u4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U8:
                        result.item.r4 = <float>cell.item.u8
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U:
                        if self.__is_64bit:
                            result.item.r4 = <float>cell.item.u8
                        else:
                            result.item.r4 = <float>cell.item.u4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_CHAR:
                        result.item.r4 = <float>cell.item.u2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_R4:
                        result.item.r4 = <float>cell.item.r4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_R8:
                        result.item.r4 = <float>cell.item.r8
                    else:
                        raise net_exceptions.InvalidArgumentsException()
                elif etype == CorElementType.ELEMENT_TYPE_R8:
                    if cell.tag == CorElementType.ELEMENT_TYPE_I1:
                        result.item.r8 = <double>cell.item.i1
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I2:
                        result.item.r8 = <double>cell.item.i2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I4:
                        result.item.r8 = <double>cell.item.i4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I8:
                        result.item.r8 = <double>cell.item.i8
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I:
                        if self.__is_64bit:
                            result.item.r8 = <double>cell.item.i8
                        else:
                            result.item.r8 = <double>cell.item.i4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U1:
                        result.item.r8 = <double>cell.item.u1
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U2:
                        result.item.r8 = <double>cell.item.u2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U4:
                        result.item.r8 = <double>cell.item.u4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U8:
                        result.item.r8 = <double>cell.item.u8
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U:
                        if self.__is_64bit:
                            result.item.r8 = <double>cell.item.u8
                        else:
                            result.item.r8 = <double>cell.item.u4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_CHAR:
                        result.item.r8 = <double>cell.item.u2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_R4:
                        result.item.r8 = <double>cell.item.r4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_R8:
                        result.item.r8 = <double>cell.item.r8
                    else:
                        raise net_exceptions.InvalidArgumentsException()
                elif etype == CorElementType.ELEMENT_TYPE_I:
                    if not self.__is_64bit:
                        if cell.tag == CorElementType.ELEMENT_TYPE_I1:
                            result.item.i4 = <int>cell.item.i1
                        elif cell.tag == CorElementType.ELEMENT_TYPE_I2:
                            result.item.i4 = <int>cell.item.i2
                        elif cell.tag == CorElementType.ELEMENT_TYPE_I4:
                            result.item.i4 = <int>cell.item.i4
                        elif cell.tag == CorElementType.ELEMENT_TYPE_I8:
                            result.item.i4 = <int>cell.item.i8
                        elif cell.tag == CorElementType.ELEMENT_TYPE_I:
                            if self.__is_64bit:
                                result.item.i4 = <int>cell.item.i8
                            else:
                                result.item.i4 = <int>cell.item.i4
                        elif cell.tag == CorElementType.ELEMENT_TYPE_U1:
                            result.item.i4 = <int>cell.item.u1
                        elif cell.tag == CorElementType.ELEMENT_TYPE_U2:
                            result.item.i4 = <int>cell.item.u2
                        elif cell.tag == CorElementType.ELEMENT_TYPE_U4:
                            result.item.i4 = <int>cell.item.u4
                        elif cell.tag == CorElementType.ELEMENT_TYPE_U8:
                            result.item.i4 = <int>cell.item.u8
                        elif cell.tag == CorElementType.ELEMENT_TYPE_U:
                            if self.__is_64bit:
                                result.item.i4 = <int>cell.item.u8
                            else:
                                result.item.i4 = <int>cell.item.u4
                        elif cell.tag == CorElementType.ELEMENT_TYPE_CHAR:
                            result.item.i4 = <int>cell.item.u2
                        elif cell.tag == CorElementType.ELEMENT_TYPE_R4:
                            result.item.i4 = <int>cell.item.r4
                        elif cell.tag == CorElementType.ELEMENT_TYPE_R8:
                            result.item.i4 = <int>cell.item.r8
                        elif cell.tag == CorElementType.ELEMENT_TYPE_OBJECT:
                            if not cell.is_slim_object:
                                if cell.item.ref != NULL:
                                    #We need to account for potential ldftn objects in this for now at least.
                                    if isinstance(<net_emu_types.DotNetObject>cell.item.ref, net_emu_types.DotNetRuntimeMethodHandle):
                                        result.item.ref = cell.item.ref
                                        result.tag = CorElementType.ELEMENT_TYPE_OBJECT
                                        return result
                            raise net_exceptions.InvalidArgumentsException()
                        else:
                            raise net_exceptions.InvalidArgumentsException()
                    else:
                        if cell.tag == CorElementType.ELEMENT_TYPE_I1:
                            result.item.i8 = <int64_t>cell.item.i1
                        elif cell.tag == CorElementType.ELEMENT_TYPE_I2:
                            result.item.i8 = <int64_t>cell.item.i2
                        elif cell.tag == CorElementType.ELEMENT_TYPE_I4:
                            result.item.i8 = <int64_t>cell.item.i4
                        elif cell.tag == CorElementType.ELEMENT_TYPE_I8:
                            result.item.i8 = <int64_t>cell.item.i8
                        elif cell.tag == CorElementType.ELEMENT_TYPE_I:
                            if self.__is_64bit:
                                result.item.i8 = <int64_t>cell.item.i8
                            else:
                                result.item.i8 = <int64_t>cell.item.i4
                        elif cell.tag == CorElementType.ELEMENT_TYPE_U1:
                            result.item.i8 = <int64_t>cell.item.u1
                        elif cell.tag == CorElementType.ELEMENT_TYPE_U2:
                            result.item.i8 = <int64_t>cell.item.u2
                        elif cell.tag == CorElementType.ELEMENT_TYPE_U4:
                            result.item.i8 = <int64_t>cell.item.u4
                        elif cell.tag == CorElementType.ELEMENT_TYPE_U8:
                            result.item.i8 = <int64_t>cell.item.u8
                        elif cell.tag == CorElementType.ELEMENT_TYPE_U:
                            if self.__is_64bit:
                                result.item.i8 = <int64_t>cell.item.u8
                            else:
                                result.item.i8 = <int64_t>cell.item.u4
                        elif cell.tag == CorElementType.ELEMENT_TYPE_CHAR:
                            result.item.i8 = <int64_t>cell.item.u2
                        elif cell.tag == CorElementType.ELEMENT_TYPE_R4:
                            result.item.i8 = <int64_t>cell.item.r4
                        elif cell.tag == CorElementType.ELEMENT_TYPE_R8:
                            result.item.i8 = <int64_t>cell.item.r8
                        elif cell.tag == CorElementType.ELEMENT_TYPE_OBJECT:
                            if not cell.is_slim_object:
                                if cell.item.ref != NULL:
                                    #We need to account for potential ldftn objects in this for now at least.
                                    if isinstance(<net_emu_types.DotNetObject>cell.item.ref, net_emu_types.DotNetRuntimeMethodHandle):
                                        result.item.ref = cell.item.ref
                                        result.tag = CorElementType.ELEMENT_TYPE_OBJECT
                                        return result
                            raise net_exceptions.InvalidArgumentsException()
                        else:
                            raise net_exceptions.InvalidArgumentsException()
                elif etype == CorElementType.ELEMENT_TYPE_U:
                    if not self.__is_64bit:
                        if cell.tag == CorElementType.ELEMENT_TYPE_I1:
                            result.item.u4 = <unsigned int>cell.item.i1
                        elif cell.tag == CorElementType.ELEMENT_TYPE_I2:
                            result.item.u4 = <unsigned int>cell.item.i2
                        elif cell.tag == CorElementType.ELEMENT_TYPE_I4:
                            result.item.u4 = <unsigned int>cell.item.i4
                        elif cell.tag == CorElementType.ELEMENT_TYPE_I8:
                            result.item.u4 = <unsigned int>cell.item.i8
                        elif cell.tag == CorElementType.ELEMENT_TYPE_I:
                            if self.__is_64bit:
                                result.item.u4 = <unsigned int>cell.item.i8
                            else:
                                result.item.u4 = <unsigned int>cell.item.i4
                        elif cell.tag == CorElementType.ELEMENT_TYPE_U1:
                            result.item.u4 = <unsigned int>cell.item.u1
                        elif cell.tag == CorElementType.ELEMENT_TYPE_U2:
                            result.item.u4 = <unsigned int>cell.item.u2
                        elif cell.tag == CorElementType.ELEMENT_TYPE_U4:
                            result.item.u4 = <unsigned int>cell.item.u4
                        elif cell.tag == CorElementType.ELEMENT_TYPE_U8:
                            result.item.u4 = <unsigned int>cell.item.u8
                        elif cell.tag == CorElementType.ELEMENT_TYPE_U:
                            if self.__is_64bit:
                                result.item.u4 = <unsigned int>cell.item.u8
                            else:
                                result.item.u4 = <unsigned int>cell.item.u4
                        elif cell.tag == CorElementType.ELEMENT_TYPE_CHAR:
                            result.item.u4 = <unsigned int>cell.item.u2
                        elif cell.tag == CorElementType.ELEMENT_TYPE_R4:
                            result.item.u4 = <unsigned int>cell.item.r4
                        elif cell.tag == CorElementType.ELEMENT_TYPE_R8:
                            result.item.u4 = <unsigned int>cell.item.r8
                        else:
                            raise net_exceptions.InvalidArgumentsException()
                    else:
                        if cell.tag == CorElementType.ELEMENT_TYPE_I1:
                            result.item.u8 = <uint64_t>cell.item.i1
                        elif cell.tag == CorElementType.ELEMENT_TYPE_I2:
                            result.item.u8 = <uint64_t>cell.item.i2
                        elif cell.tag == CorElementType.ELEMENT_TYPE_I4:
                            result.item.u8 = <uint64_t>cell.item.i4
                        elif cell.tag == CorElementType.ELEMENT_TYPE_I8:
                            result.item.u8 = <uint64_t>cell.item.i8
                        elif cell.tag == CorElementType.ELEMENT_TYPE_I:
                            if self.__is_64bit:
                                result.item.u8 = <uint64_t>cell.item.i8
                            else:
                                result.item.u8 = <uint64_t>cell.item.i4
                        elif cell.tag == CorElementType.ELEMENT_TYPE_U1:
                            result.item.u8 = <uint64_t>cell.item.u1
                        elif cell.tag == CorElementType.ELEMENT_TYPE_U2:
                            result.item.u8 = <uint64_t>cell.item.u2
                        elif cell.tag == CorElementType.ELEMENT_TYPE_U4:
                            result.item.u8 = <uint64_t>cell.item.u4
                        elif cell.tag == CorElementType.ELEMENT_TYPE_U8:
                            result.item.u8 = <uint64_t>cell.item.u8
                        elif cell.tag == CorElementType.ELEMENT_TYPE_U:
                            if self.__is_64bit:
                                result.item.u8 = <uint64_t>cell.item.u8
                            else:
                                result.item.u8 = <uint64_t>cell.item.u4
                        elif cell.tag == CorElementType.ELEMENT_TYPE_CHAR:
                            result.item.u8 = <uint64_t>cell.item.u2
                        elif cell.tag == CorElementType.ELEMENT_TYPE_R4:
                            result.item.u8 = <uint64_t>cell.item.r4
                        elif cell.tag == CorElementType.ELEMENT_TYPE_R8:
                            result.item.u8 = <uint64_t>cell.item.r8
                        else:
                            raise net_exceptions.InvalidArgumentsException()
                elif etype == CorElementType.ELEMENT_TYPE_U8:
                    if cell.tag == CorElementType.ELEMENT_TYPE_I1:
                        result.item.u8 = <uint64_t>cell.item.i1
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I2:
                        result.item.u8 = <uint64_t>cell.item.i2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I4:
                        result.item.u8 = <uint64_t>cell.item.i4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I8:
                        result.item.u8 = <uint64_t>cell.item.i8
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I:
                        if self.__is_64bit:
                            result.item.u8 = <uint64_t>cell.item.i8
                        else:
                            result.item.u8 = <uint64_t>cell.item.i4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U1:
                        result.item.u8 = <uint64_t>cell.item.u1
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U2:
                        result.item.u8 = <uint64_t>cell.item.u2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U4:
                        result.item.u8 = <uint64_t>cell.item.u4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U8:
                        result.item.u8 = <uint64_t>cell.item.u8
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U:
                        if self.__is_64bit:
                            result.item.u8 = <uint64_t>cell.item.u8
                        else:
                            result.item.u8 = <uint64_t>cell.item.u4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_CHAR:
                        result.item.u8 = <uint64_t>cell.item.u2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_R4:
                        result.item.u8 = <uint64_t>cell.item.r4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_R8:
                        result.item.u8 = <uint64_t>cell.item.r8
                    else:
                        raise net_exceptions.InvalidArgumentsException()
                elif etype == CorElementType.ELEMENT_TYPE_I8:
                    if cell.tag == CorElementType.ELEMENT_TYPE_I1:
                        result.item.i8 = <int64_t>cell.item.i1
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I2:
                        result.item.i8 = <int64_t>cell.item.i2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I4:
                        result.item.i8 = <int64_t>cell.item.i4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I8:
                        result.item.i8 = <int64_t>cell.item.i8
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I:
                        if self.__is_64bit:
                            result.item.i8 = <int64_t>cell.item.i8
                        else:
                            result.item.i8 = <int64_t>cell.item.i4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U1:
                        result.item.i8 = <int64_t>cell.item.u1
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U2:
                        result.item.i8 = <int64_t>cell.item.u2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U4:
                        result.item.i8 = <int64_t>cell.item.u4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U8:
                        result.item.i8 = <int64_t>cell.item.u8
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U:
                        if self.__is_64bit:
                            result.item.i8 = <int64_t>cell.item.u8
                        else:
                            result.item.i8 = <int64_t>cell.item.u4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_CHAR:
                        result.item.i8 = <int64_t>cell.item.u2
                    elif cell.tag == CorElementType.ELEMENT_TYPE_R4:
                        result.item.i8 = <int64_t>cell.item.r4
                    elif cell.tag == CorElementType.ELEMENT_TYPE_R8:
                        result.item.i8 = <int64_t>cell.item.r8
                    else:
                        raise net_exceptions.InvalidArgumentsException()
                elif etype == CorElementType.ELEMENT_TYPE_BOOLEAN:
                    if cell.tag == CorElementType.ELEMENT_TYPE_R4:
                        result.item.b = cell.item.r4 != 0
                    elif cell.tag == CorElementType.ELEMENT_TYPE_R8:
                        result.item.b = cell.item.r8 != 0
                    elif cell.tag == CorElementType.ELEMENT_TYPE_BOOLEAN:
                        result.item.b = cell.item.b
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I or cell.tag == CorElementType.ELEMENT_TYPE_U:
                        if self.__is_64bit:
                            result.item.b = cell.item.u8 != 0
                        else:
                            result.item.b = cell.item.u4 != 0
                        
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I1 or cell.tag == CorElementType.ELEMENT_TYPE_U1:
                        result.item.b = cell.item.u1 != 0
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I2 or cell.tag == CorElementType.ELEMENT_TYPE_I2 or cell.tag == CorElementType.ELEMENT_TYPE_CHAR:
                        result.item.b = cell.item.u2 != 0
                    elif cell.tag == CorElementType.ELEMENT_TYPE_I4 or cell.tag == CorElementType.ELEMENT_TYPE_U4:
                        result.item.b = cell.item.u4 != 0
                    elif cell.tag == CorElementType.ELEMENT_TYPE_U8 or cell.tag == CorElementType.ELEMENT_TYPE_I8:
                        result.item.b = cell.item.u8 != 0
                    else:
                        raise net_exceptions.InvalidArgumentsException()
                else:
                    raise net_exceptions.InvalidArgumentsException()
                return result
            elif etype == CorElementType.ELEMENT_TYPE_STRING:
                return result
            elif etype == CorElementType.ELEMENT_TYPE_OBJECT:
                return result
            else:
                raise net_exceptions.InvalidArgumentsException()
            return result
        else:
            return self.duplicate_cell(cell)

    cdef void _add_param(self, int idx, StackCell cell):
        """ Internal method to handle parameter setup and casting.

        Args:
            idx (int): index of parameter to set.
            cell (net_emu_structs.StackCell): The parameter value.

        Raises:
            net_exceptions.InvalidArgumentsException: either index or cell is invalid.
        """
        if idx >= self.__nparams:
            raise net_exceptions.InvalidArgumentsException()
        if cell.tag == CorElementType.ELEMENT_TYPE_END:
            raise net_exceptions.InvalidArgumentsException()
        cdef StackCell old = self.__method_params[idx]
        cdef net_sigs.MethodSig msig_obj = self.method_obj.get_method_signature()
        cdef StackCell casted_val
        if self.method_obj.method_has_this() and idx != 0:
            casted_val = self.cast_cell(cell, msig_obj.get_parameters()[idx - 1])
        else:
            if self.method_obj.method_has_this():
                casted_val = self.duplicate_cell(cell)
            else:
                casted_val = self.cast_cell(cell, msig_obj.get_parameters()[idx])
        self.ref_cell(casted_val)
        self.deref_cell(old)
        self.dealloc_cell(old)
        self.__method_params[idx] = casted_val

    cdef StackCell get_method_param(self, int idx):
        """ Internal method that returns a duplicated copy of the method parameter idx.
        """
        return self.duplicate_cell(self.__method_params[idx])

    cdef int get_num_params(self):
        """ Obtain the number of allocated parameters.
        """
        return self.__nparams

    cdef StackCell cell_not(self, StackCell cell):
        """ Perform a not operation on a cell.

            The last line here may need to be reworked as in general it is expected that extra space in item is 0.

        Args:
            cell (net_emu_structs.StackCell): the cell to perform the operation on.

        Returns:
            net_emu_structs.StackCell: The result of the operation.

        Raises:
            net_exceptions.InvalidArgumentsException: Argument is not a number.
        """
        if not net_utils.is_cortype_number(<CorElementType>cell.tag):
            raise net_exceptions.InvalidArgumentsException()
        cdef StackCell result = self.duplicate_cell(cell)
        if result.tag == CorElementType.ELEMENT_TYPE_BOOLEAN:
            result.item.b = not result.item.b
            return result
        result.item.u8 = ~result.item.u8
        return result

    cdef bint cell_is_false(self, StackCell cell):
        """ Determines if a cells truth value is False.

        Args:
            cell (net_emu_structs.StackCell): The cell to determine truth value for.

        Returns:
            bool: True if the cell is False, False if the cell is True.
        """
        cdef net_emu_types.DotNetObject obj = None
        cdef StackCell ref
        cdef bint result = False
        if cell.tag == CorElementType.ELEMENT_TYPE_BYREF:
            ref = self.get_ref(cell)
            result = self.cell_is_false(ref)
            self.dealloc_cell(ref)
            return result
        if cell.tag == CorElementType.ELEMENT_TYPE_STRING or cell.tag == CorElementType.ELEMENT_TYPE_OBJECT:
            if cell.is_slim_object:
                return False #Slim objects are never NULL
            if cell.item.ref == NULL:
                return True
            obj = <net_emu_types.DotNetObject>cell.item.ref
            return obj.is_false()
        return cell.item.u8 == 0

    cdef void deref_cell(self, StackCell cell):
        """ Handles the dereferencing of cells.  Cells should be derferenced whenever they are taken out of a structure like the stack, list etc.

        Args:
            cell (net_emu_structs.StackCell): the cell to dereference.
        
        Raises:
            net_exceptions.InvalidArgumentsException: internal error.
        """
        if cell.tag != CorElementType.ELEMENT_TYPE_OBJECT and cell.tag != CorElementType.ELEMENT_TYPE_STRING:
            return
        if cell.is_slim_object:
            if cell.item.slim_object == NULL or cell.item.slim_object.refs == 0:
                raise net_exceptions.InvalidArgumentsException()
            cell.item.slim_object.refs -= 1
            return
        Py_XDECREF(cell.item.ref)

    cdef StackCell get_ref(self, StackCell cell):
        """ Returns a duplicated copy of a cell if it is not ELEMENT_TYPE_BYREF, otherwise it returns a duplicated copy of the cell being referenced.

        Args:
            cell (net_emu_structs.StackCell): the cell to obtain the reference for.

        Returns:
            net_emu_structs.StackCell: The cell being referenced or duplicated cell.
        
        Raises:
            net_exceptions.OperationNotSupportedException: internal error.
        """
        if cell.tag != CorElementType.ELEMENT_TYPE_BYREF:
            return self.duplicate_cell(cell)
        cdef DotNetEmulator owner_emu = None
        cdef net_emu_types.DotNetObject owner_obj = None
        cdef SlimObject * slim = NULL
        cdef StackCell cell1
        if cell.item.byref.kind == 1: #local variable
            owner_emu = <DotNetEmulator>cell.item.byref.owner
            return owner_emu.get_local(<int>cell.item.byref.idx)
        elif cell.item.byref.kind == 2: #Static variable
            owner_emu = <DotNetEmulator>cell.item.byref.owner
            return owner_emu.get_appdomain().get_static_field(<int>cell.item.byref.idx)
        elif cell.item.byref.kind == 3: #array object
            owner_obj = <net_emu_types.DotNetObject>cell.item.byref.owner
            return (<net_emu_types.DotNetArray>owner_obj)._get_item(cell.item.byref.idx)
        elif cell.item.byref.kind == 4: #field
            slim = <SlimObject*>cell.item.byref.owner
            memset(&cell1, 0x0, sizeof(cell))
            cell1.tag = CorElementType.ELEMENT_TYPE_OBJECT
            cell1.is_slim_object = True
            cell1.item.slim_object = slim
            return self.get_slimobj_field(cell1, <int>cell.item.byref.idx)
        elif cell.item.byref.kind == 5: #argument
            owner_emu = <DotNetEmulator>cell.item.byref.owner
            return self.duplicate_cell(owner_emu.__method_params[cell.item.byref.idx])
        raise net_exceptions.OperationNotSupportedException()

    cdef void set_ref(self, StackCell ref, StackCell value):
        """ Sets the object referenced by an ELEMENT_TYPE_BYREF to a specified value.
        
        Args:
            ref (net_emu_structs.StackCell): the ELEMENT_TYPE_BYREF to set.
            value (net_emu_structs.StackCell): the value to set ref to.

        Raises:
            net_exceptions.OperationNotSupportedException: ref is not a BYREF or internal error.
        """
        if ref.tag != CorElementType.ELEMENT_TYPE_BYREF:
            raise net_exceptions.OperationNotSupportedException()
        cdef DotNetEmulator owner_emu = None
        cdef SlimObject * owner_slim = NULL
        cdef net_emu_types.DotNetObject owner_obj = None
        cdef StackCell cell
        if ref.item.byref.kind == 1: #local variable
            owner_emu = <DotNetEmulator>ref.item.byref.owner
            owner_emu.set_local(<int>ref.item.byref.idx, value)
        elif ref.item.byref.kind == 2: #Static variable
            owner_emu = <DotNetEmulator>ref.item.byref.owner
            owner_emu.get_appdomain().set_static_field(<int>ref.item.byref.idx, value)
        elif ref.item.byref.kind == 3: #array object
            owner_obj = <net_emu_types.DotNetObject>ref.item.byref.owner
            (<net_emu_types.DotNetArray>owner_obj)._set_item(ref.item.byref.idx, value)
        elif ref.item.byref.kind == 4: #field
            if ref.is_slim_object:
                raise net_exceptions.FeatureNotImplementedException() #TODO implement slim objects for references.
            else:
                memset(&cell, 0x0, sizeof(cell))
                cell.tag = CorElementType.ELEMENT_TYPE_OBJECT
                cell.item.ref = NULL
                cell.is_slim_object = True
                owner_slim = <SlimObject*>ref.item.byref.owner
                cell.item.slim_object = owner_slim
                self.set_slimobj_field(cell, <int>ref.item.byref.idx, value)
        elif ref.item.byref.kind == 5: #argument
            owner_emu = <DotNetEmulator>ref.item.byref.owner
            owner_emu._add_param(<int>ref.item.byref.idx, value)
        else:
            raise net_exceptions.OperationNotSupportedException()
    
    cdef bint cell_is_true(self, StackCell cell):
        """ Determines if a cells truth value is True.

        Args:
            cell (net_emu_structs.StackCell): The cell to determine truth value for.

        Returns:
            bool: True if the cell is True, False if the cell is False.
        """
        cdef net_emu_types.DotNetObject obj = None
        cdef bint result = False
        cdef StackCell ref
        cdef StackCell casted
        if cell.tag == CorElementType.ELEMENT_TYPE_BYREF:
            ref = self.get_ref(cell)
            result = self.cell_is_true(ref)
            self.dealloc_cell(ref)
            return result
        if cell.tag == CorElementType.ELEMENT_TYPE_STRING or cell.tag == CorElementType.ELEMENT_TYPE_OBJECT:
            if cell.is_slim_object:
                return True #Slim objects are never NULL
            if cell.item.ref == NULL:
                return False
            obj = <net_emu_types.DotNetObject>cell.item.ref
            return obj.is_true()
        casted = self.cast_cell(cell, net_sigs.get_CorSig_Boolean())
        result = casted.item.b
        self.dealloc_cell(casted)
        return result

    cdef bint cell_is_null(self, StackCell one):
        """ Determines if a cell represents NULL.

        Args:
            cell (net_emu_structs.StackCell): The cell to determine NULL value for.

        Returns:
            bool: True if the cell is NULL, False if the cell not NULL.
        """
        return (one.tag == CorElementType.ELEMENT_TYPE_OBJECT or one.tag == CorElementType.ELEMENT_TYPE_STRING ) and not one.is_slim_object and one.item.ref == NULL

    cdef bint cell_is_equal(self, StackCell one, StackCell two):
        """ Determines if two cells are equal to eachother.

        Args:
            one (net_emu_structs.StackCell): the first cell to compare
            two (net_emu_structs.StackCell): the second cell to compare

        Returns:
            bool: True if they are equal, False otherwise.

        Raises:
            net_exceptions.InvalidArgumentsException: The two argument types are not supported currently.
        """
        cdef StackCell uone = one
        cdef StackCell utwo = two
        cdef CorElementType type_one = <CorElementType>uone.tag
        cdef CorElementType type_two = <CorElementType>utwo.tag
        cdef net_emu_types.DotNetObject obj1 = None
        cdef net_emu_types.DotNetObject obj2 = None
        cdef StackCell temp1
        cdef StackCell temp2
        cdef bint result = False
        if type_one == CorElementType.ELEMENT_TYPE_BYREF or type_two == CorElementType.ELEMENT_TYPE_BYREF:
            #be careful about byrefs for now
            if type_one != type_two:
                raise net_exceptions.InvalidArgumentsException()
            temp1 = self.get_ref(uone)
            temp2 = self.get_ref(utwo)
            result = self.cell_is_equal(temp1, temp2)
            self.dealloc_cell(temp1)
            self.dealloc_cell(temp2)
            return result
        elif self.cell_is_null(uone) or self.cell_is_null(utwo):
            if uone.tag != utwo.tag:
                raise net_exceptions.OperationNotSupportedException()
            return uone.item.ref == utwo.item.ref 
        elif type_one == CorElementType.ELEMENT_TYPE_STRING or type_two == CorElementType.ELEMENT_TYPE_STRING:
            if type_one != type_two:
                return False
            obj1 = <net_emu_types.DotNetObject> uone.item.ref
            obj2 = <net_emu_types.DotNetObject> utwo.item.ref
            return obj1 == obj2
        elif type_one == CorElementType.ELEMENT_TYPE_OBJECT or type_two == CorElementType.ELEMENT_TYPE_OBJECT:
            if uone.is_slim_object or utwo.is_slim_object:
                raise net_exceptions.FeatureNotImplementedException()
            if type_one != type_two:
                return False
            if self.cell_is_null(uone) or self.cell_is_null(utwo):
                return uone.item.ref == utwo.item.ref
            obj1 = <net_emu_types.DotNetObject> uone.item.ref
            obj2 = <net_emu_types.DotNetObject> utwo.item.ref
            return obj1 == obj2
        if not net_utils.is_cortype_number(type_one) or not net_utils.is_cortype_number(type_two):
            raise net_exceptions.OperationNotSupportedException()
        if type_one == CorElementType.ELEMENT_TYPE_I:
            if self.__is_64bit:
                return uone.item.i8 == utwo.item.i8
            return uone.item.i4 == utwo.item.i4
        elif type_one == CorElementType.ELEMENT_TYPE_I4:
            return uone.item.i4 == utwo.item.i4
        elif type_one == CorElementType.ELEMENT_TYPE_I8:
            return uone.item.i8 == utwo.item.i8
        elif type_one == CorElementType.ELEMENT_TYPE_U:
            if self.__is_64bit:
                return uone.item.u8 == utwo.item.u8
            return uone.item.u4 == utwo.item.u4
        elif type_one == CorElementType.ELEMENT_TYPE_U4:
            return uone.item.u4 == utwo.item.u4
        elif type_one == CorElementType.ELEMENT_TYPE_U8:
            return uone.item.u8 == utwo.item.u8
        elif type_one == CorElementType.ELEMENT_TYPE_R4:
            return <float>uone.item.r8 == <float>utwo.item.r8
        elif type_one == CorElementType.ELEMENT_TYPE_R8:
            return uone.item.r8 == utwo.item.r8
        else:
            raise net_exceptions.FeatureNotImplementedException()

    cdef void dealloc_cell(self, StackCell cell):
        """  Deallocates an allocated stackcell

        Args:
            cell (net_emu_structs.StackCell): The cell to deallocated

        Raises:
            net_exceptions.InvalidArgumentsException: internal error
        """
        cdef int x
        cdef SlimObject * slim = NULL
        if cell.tag == CorElementType.ELEMENT_TYPE_END:
            return
        Py_XDECREF(cell.emulator_obj)
        cell.emulator_obj = NULL
        if cell.tag == CorElementType.ELEMENT_TYPE_OBJECT or cell.tag == CorElementType.ELEMENT_TYPE_STRING:
            if cell.is_slim_object:
                if cell.item.slim_object == NULL:
                    raise net_exceptions.InvalidArgumentsException()
                cell.item.slim_object.refs -= 1
                if cell.item.slim_object.refs == 0:
                    for x in range(cell.item.slim_object.num_fields):
                        self.deref_cell(cell.item.slim_object.fields[x])
                        self.dealloc_cell(cell.item.slim_object.fields[x])
                    free(cell.item.slim_object.fields)
                    cell.item.slim_object.fields = NULL
                    cell.item.slim_object.num_fields = 0
                    free(cell.item.slim_object)
                    cell.item.slim_object = NULL
                return
            Py_XDECREF(cell.item.ref)
            cell.item.ref = NULL
        elif cell.tag == CorElementType.ELEMENT_TYPE_BYREF:
            if cell.item.byref.kind == 4:
                slim = <SlimObject*>cell.item.byref.owner
                slim.refs -= 1
            else:
                Py_XDECREF(<PyObject*>cell.item.byref.owner)
            cell.item.byref.owner = NULL
        #Ints and such dont need to have anything done

    cdef size_t hash_cell(self, StackCell cell):
        """ Hashes a stackcell.  Currently not used really but may be eventually.

        Args:
            cell (net_emu_structs.StackCell): the cell to hash

        Returns:
            size_t: the hash value for the cell.

        Raises:
            net_exceptions.InvalidArgumentsException: internal error.
            net_exceptions.FeatureNotImplementedException: attempted to hash a slim object.
        """
        if cell.tag == CorElementType.ELEMENT_TYPE_END:
            raise net_exceptions.InvalidArgumentsException()
        cdef StackCell deref = self.get_ref(cell) #TODO: make deref return a copy
        cdef net_emu_types.DotNetObject dobj = None
        if deref.tag == CorElementType.ELEMENT_TYPE_OBJECT or deref.tag == CorElementType.ELEMENT_TYPE_STRING:
            if deref.is_slim_object:
                raise net_exceptions.FeatureNotImplementedException()
            if deref.item.ref == NULL:
                self.dealloc_cell(deref)
                return 0
            dobj = <net_emu_types.DotNetObject>deref.item.ref
            self.dealloc_cell(deref)
            return <size_t>hash(dobj)
        else:
            self.dealloc_cell(deref)
            return <size_t>deref.item.i8

    cdef SlimStackCell slim_cell(self, StackCell cell):
        """ Convert a StackCell to a SlimStackCell representing the same value.

        Args:
            cell (net_emu_structs.StackCell): the stackcell to convert.

        Returns:
            net_emu_structs.SlimStackCell: The converted cell.
        """
        cdef SlimStackCell result
        memset(&result, 0x0, sizeof(result))
        Py_XDECREF(cell.emulator_obj)
        cell.emulator_obj = NULL
        result.tag = <char>cell.tag
        result.is_slim_object = cell.is_slim_object
        result.item = cell.item
        return result

    cdef StackCell unslim_cell(self, DotNetEmulator emu_obj, SlimStackCell cell):
        """ Convert a SlimStackCell to a StackCell representing the same value.

        Args:
            emu_obj (net_emulator.DotNetEmulator): the emulator object that created the cell.
            cell (net_emu_structs.StackCell): the stackcell to convert.

        Returns:
            net_emu_structs.StackCell: The converted cell.
        """
        cdef StackCell result
        memset(&result, 0x0, sizeof(result))
        result.emulator_obj = <PyObject*>emu_obj
        Py_INCREF(emu_obj)
        result.tag = cell.tag
        result.is_slim_object = cell.is_slim_object
        result.item = cell.item
        return result

    cdef bytes cell_to_bytes(self, StackCell cell):
        """ Converts a stackcell to bytes representation if possible.

        Args:
            cell (net_emu_structs.StackCell): The cell to convert.

        Returns:
            bytes: A bytes representation of the cell.

        Raises:
            net_exceptions.InvalidArgumentsException: internal error.
            net_exceptions.FeatureNotImplementedException: attempted to convert a slim object, not implemented yet.
            net_exceptions.OperationNotSupportedException: couldnt convert, not supported.
        """
        if cell.tag == CorElementType.ELEMENT_TYPE_END:
            raise net_exceptions.InvalidArgumentsException()
        cdef int int_size = 0
        cdef net_emu_types.DotNetObject dobj = None
        cdef StackCell deref = self.get_ref(cell)
        cdef char * ptr = NULL
        if deref.tag == CorElementType.ELEMENT_TYPE_STRING or deref.tag == CorElementType.ELEMENT_TYPE_OBJECT:
            if deref.is_slim_object:
                raise net_exceptions.FeatureNotImplementedException()
            if deref.item.ref == NULL:
                self.dealloc_cell(deref)
                return bytes()
            dobj = <net_emu_types.DotNetObject>deref.item.ref
            self.dealloc_cell(deref)
            return dobj.as_bytes()
        else:
            if not net_utils.is_cortype_number(<CorElementType>deref.tag):
                raise net_exceptions.InvalidArgumentsException()
            ptr = <char*>&deref.item.i8
            self.dealloc_cell(deref)
            if deref.tag == CorElementType.ELEMENT_TYPE_I or deref.tag == CorElementType.ELEMENT_TYPE_U:
                if self.__is_64bit:
                    return ptr[:8]
                return ptr[:4]
            elif deref.tag == CorElementType.ELEMENT_TYPE_R4 or deref.tag == CorElementType.ELEMENT_TYPE_I4 or deref.tag == CorElementType.ELEMENT_TYPE_U4:
                return ptr[:4]
            elif deref.tag == CorElementType.ELEMENT_TYPE_R8 or deref.tag == CorElementType.ELEMENT_TYPE_I8 or deref.tag == CorElementType.ELEMENT_TYPE_U8:
                return ptr[:8]
            elif deref.tag == CorElementType.ELEMENT_TYPE_I1 or deref.tag == CorElementType.ELEMENT_TYPE_U1:
                return ptr[:1]
            elif deref.tag == CorElementType.ELEMENT_TYPE_I2 or deref.tag == CorElementType.ELEMENT_TYPE_U2 or deref.tag == CorElementType.ELEMENT_TYPE_CHAR:
                return ptr[:2]
            elif deref.tag == CorElementType.ELEMENT_TYPE_BOOLEAN:
                if deref.item.b:
                    return b'\x01'
                return b'\x00'
        raise net_exceptions.OperationNotSupportedException()

    cdef void ref_cell(self, StackCell cell):
        """ Adds a reference to a stackcell.  StackCellls should be referenced when being added to the stack, params, arrays etc.

        Args:
            cell (net_emu_structs.StackCell): the cell to reference.
        """
        if cell.tag != CorElementType.ELEMENT_TYPE_OBJECT and cell.tag != CorElementType.ELEMENT_TYPE_STRING:
            return
        if cell.is_slim_object:
            cell.item.slim_object.refs += 1
            return
        if cell.item.ref == NULL:
            return
        cdef net_emu_types.DotNetObject obj = <net_emu_types.DotNetObject>cell.item.ref
        Py_INCREF(obj)

    cdef StackCell pack_blanktag(self):
        """ Creates an invalid cell that simply holds nothing.

        Returns:
            net_emu_structs.StackCell: An invalid, blank stackcell.
        """
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        return cell

    cdef int _get_num_fields(self, net_row_objects.TypeDefOrRef ref):
        """ Determine how many fields need to be allocated for a specific type.
        """
        cdef net_row_objects.TypeDefOrRef ptr = ref
        cdef int result = 0
        cdef list fields = None
        cdef int x = 0
        cdef net_row_objects.Field fobj = None
        while ptr is not None:
            if isinstance(ptr, net_row_objects.TypeRef):
                return result

            if isinstance(ptr, net_row_objects.TypeSpec):
                ptr = (<net_row_objects.TypeSpec>ptr).get_type()
                continue
            
            if isinstance(ptr, net_row_objects.TypeDef):
                fields = ptr.get_column('FieldList').get_formatted_value()
                for x in range(<int>len(fields)):
                    fobj = fields[x]
                    if not fobj.is_static():
                        result += 1      
                        
                ptr = ptr.get_superclass()
        return result

    cdef StackCell pack_slimobject(self, net_row_objects.TypeDef ref):
        """ Creates a stackcell that is used to represent a TypeDef.

        Args:
            ref (net_row_objects.TypeDef): the typedef that the slim object is created for.

        Returns:
            net_emu_structs.StackCell: A initialized StackCell ready to be used as a TypeDef object.

        Raises:
            net_exceptions.InvalidArgumentsException: ref is None.
            net_exceptions.EmulatorExecutionException: internal error.
        """
        if ref is None:
            raise net_exceptions.InvalidArgumentsException()
        cdef StackCell cell
        cdef int flags = 0
        memset(&cell, 0, sizeof(cell))
        cell.emulator_obj = <PyObject*>self
        Py_INCREF(self)
        cell.tag = CorElementType.ELEMENT_TYPE_OBJECT
        cell.is_slim_object = True
        cell.item.slim_object = <SlimObject*>malloc(sizeof(SlimObject))
        if cell.item.slim_object == NULL:
            raise net_exceptions.EmulatorExecutionException(self, 'memory error')
        memset(cell.item.slim_object, 0, sizeof(SlimObject))
        cell.item.slim_object.num_fields = self._get_num_fields(ref)
        cell.item.slim_object.refs = 1
        if cell.item.slim_object.num_fields > 0:
            cell.item.slim_object.fields = <StackCell *>malloc(sizeof(StackCell) * cell.item.slim_object.num_fields)
            if cell.item.slim_object.fields == NULL:
                raise net_exceptions.EmulatorExecutionException(self, 'memory error')
            memset(cell.item.slim_object.fields, 0, sizeof(StackCell) * cell.item.slim_object.num_fields)
        cell.item.slim_object.type_token = ref.get_token()
        return cell

    cdef StackCell pack_i4(self, int i):
        """ Creates a cell that holds an I4.

        Args:
            i (int): the number to hold in the cell.

        Returns:
            net_emu_structs.StackCell: A cell holding an I4.
        """
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.emulator_obj = <PyObject*>self
        Py_INCREF(self)
        cell.tag = CorElementType.ELEMENT_TYPE_I4
        cell.item.i4 = i
        return cell

    cdef StackCell pack_i(self, int64_t i):
        """ Creates a cell that holds an IntPtr.

        Args:
            i (int64_t): the number to hold in the cell.

        Returns:
            net_emu_structs.StackCell: A cell holding an IntPtr.
        """
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.emulator_obj = <PyObject*>self
        Py_INCREF(self)
        cell.tag = CorElementType.ELEMENT_TYPE_I
        cell.item.i8 = i
        return cell

    cdef StackCell pack_u(self, uint64_t i):
        """ Creates a cell that holds a UintPtr.

        Args:
            i (uint64_t): the number to hold in the cell.

        Returns:
            net_emu_structs.StackCell: A cell holding a UintPtr.
        """
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.emulator_obj = <PyObject*>self
        Py_INCREF(self)
        cell.tag = CorElementType.ELEMENT_TYPE_U
        cell.item.u8 = i
        return cell

    cdef StackCell pack_i1(self, char i):
        """ Creates a cell that holds a I1.

        Args:
            i (char): the number to hold in the cell.

        Returns:
            net_emu_structs.StackCell: A cell holding a I1.
        """
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.emulator_obj = <PyObject*>self
        Py_INCREF(self)
        cell.tag = CorElementType.ELEMENT_TYPE_I1
        cell.item.i1 = i
        return cell

    cdef StackCell pack_u1(self, unsigned char i):
        """ Creates a cell that holds a U1.

        Args:
            i (unsigned char): the number to hold in the cell.

        Returns:
            net_emu_structs.StackCell: A cell holding a U1.
        """
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.emulator_obj = <PyObject*>self
        Py_INCREF(self)
        cell.tag = CorElementType.ELEMENT_TYPE_U1
        cell.item.u1 = i
        return cell

    cdef StackCell pack_i2(self, short i):
        """ Creates a cell that holds a I2.

        Args:
            i (short): the number to hold in the cell.

        Returns:
            net_emu_structs.StackCell: A cell holding a I2.
        """
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.emulator_obj = <PyObject*>self
        Py_INCREF(self)
        cell.tag = CorElementType.ELEMENT_TYPE_I
        cell.item.i2 = i
        return cell

    cdef StackCell pack_u2(self, unsigned short i):
        """ Creates a cell that holds a U2.

        Args:
            i (unsigned short): the number to hold in the cell.

        Returns:
            net_emu_structs.StackCell: A cell holding a U2.
        """
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.emulator_obj = <PyObject*>self
        Py_INCREF(self)
        cell.tag = CorElementType.ELEMENT_TYPE_U2
        cell.item.u2 = i
        return cell

    cdef StackCell pack_char(self, unsigned short i):
        """ Creates a cell that holds a CHAR.

        Args:
            i (unsigned short): the number to hold in the cell.

        Returns:
            net_emu_structs.StackCell: A cell holding a CHAR.
        """
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.emulator_obj = <PyObject*>self
        Py_INCREF(self)
        cell.tag = CorElementType.ELEMENT_TYPE_CHAR
        cell.item.u2 = i
        return cell

    cdef StackCell pack_bool(self, bint i):
        """ Creates a cell that holds a bool.

        Args:
            i (bint): the number to hold in the cell.

        Returns:
            net_emu_structs.StackCell: A cell holding a bool.
        """
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.emulator_obj = <PyObject*>self
        Py_INCREF(self)
        cell.tag = CorElementType.ELEMENT_TYPE_BOOLEAN
        cell.item.b = i
        return cell
    
    cdef StackCell pack_u4(self, unsigned int i):
        """ Creates a cell that holds a U4.

        Args:
            i (char): the number to hold in the cell.

        Returns:
            net_emu_structs.StackCell: A cell holding a U4.
        """
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.emulator_obj = <PyObject*>self
        Py_INCREF(self)
        cell.tag = CorElementType.ELEMENT_TYPE_U4
        cell.item.u4 = i
        return cell

    cdef StackCell pack_i8(self, int64_t i):
        """ Creates a cell that holds a I8.

        Args:
            i (char): the number to hold in the cell.

        Returns:
            net_emu_structs.StackCell: A cell holding a I8.
        """
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.emulator_obj = <PyObject*>self
        Py_INCREF(self)
        cell.tag = CorElementType.ELEMENT_TYPE_I8
        cell.item.i8 = i
        return cell
    
    cdef StackCell pack_u8(self, uint64_t i):
        """ Creates a cell that holds a U8.

        Args:
            i (char): the number to hold in the cell.

        Returns:
            net_emu_structs.StackCell: A cell holding a U8.
        """
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.emulator_obj = <PyObject*>self
        Py_INCREF(self)
        cell.tag = CorElementType.ELEMENT_TYPE_U8
        cell.item.u8 = i
        return cell

    cdef StackCell pack_r4(self, float i):
        """ Creates a cell that holds a R4.

        Args:
            i (char): the number to hold in the cell.

        Returns:
            net_emu_structs.StackCell: A cell holding a R4.
        """
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.emulator_obj = <PyObject*>self
        Py_INCREF(self)
        cell.tag = CorElementType.ELEMENT_TYPE_R4
        cell.item.r4 = i
        return cell
    
    cdef StackCell pack_r8(self, double i):
        """ Creates a cell that holds a R8.

        Args:
            i (char): the number to hold in the cell.

        Returns:
            net_emu_structs.StackCell: A cell holding a R8.
        """
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.emulator_obj = <PyObject*>self
        Py_INCREF(self)
        cell.tag = CorElementType.ELEMENT_TYPE_R8
        cell.item.r8 = i
        return cell

    cdef StackCell pack_object(self, net_emu_types.DotNetObject obj):
        """ Creates a cell that holds a memberref or boxed object.

        Args:
            obj (net_emu_types.DotNetObject): the object to hold in the cell.

        Returns:
            net_emu_structs.StackCell: A cell holding a object.

        Raises:
            net_exceptions.OperationNotSupportedException: attempted to put a string in a object cell.
        """
        cdef StackCell cell
        if isinstance(obj, net_emu_types.DotNetString):
            raise net_exceptions.OperationNotSupportedException() # use pack_string()
        memset(&cell, 0, sizeof(cell))
        cell.tag = CorElementType.ELEMENT_TYPE_OBJECT
        cell.emulator_obj = <PyObject*>self
        Py_INCREF(self)
        Py_INCREF(obj)
        cell.item.ref = <PyObject*>obj
        return cell

    cdef StackCell pack_string(self, net_emu_types.DotNetString obj):
        """ Creates a cell that holds a string value

        Args:
            obj (net_emu_types.DotNetString): the string to hold in the cell.

        Returns:
            net_emu_structs.StackCell: A cell holding a string.
        """
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.tag = CorElementType.ELEMENT_TYPE_STRING
        cell.emulator_obj = <PyObject*>self
        Py_INCREF(self)
        Py_INCREF(obj)
        cell.item.ref = <PyObject*>obj
        return cell

    cdef StackCell pack_ref(self, int kind, int64_t idx, void * owner):
        """ Creates a cell that holds a ELEMENT_TYPE_BYREF.

            See net_emu_structs.ByRefItem for details.

        Args:
            kind (int): the type of reference.
            idx (int64_t): The index for the reference.
            owner (void*): the owner of the reference.

        Returns:
            net_emu_structs.StackCell: A stackcell holding the reference.
        """
        cdef StackCell cell
        cdef SlimObject * slim = NULL
        memset(&cell, 0, sizeof(cell))
        cell.tag = CorElementType.ELEMENT_TYPE_BYREF
        cell.item.byref.kind = kind
        cell.item.byref.idx = idx
        cell.emulator_obj = <PyObject*>self
        Py_INCREF(self)
        if (kind == 4 and owner != NULL) or (owner != NULL and (<object>owner) is not None):
            cell.item.byref.owner = owner
            if kind == 4:
                slim = <SlimObject*>owner
                slim.refs += 1
            else:
                Py_INCREF(<object>owner)
        else:
            cell.item.byref.owner = NULL
        return cell

    cdef StackCell pack_null(self):
        """ Creates a cell that holds a NULL object.

        Returns:
            net_emu_structs.StackCell: A cell holding a NULL object.
        """
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.emulator_obj = <PyObject*>self
        Py_INCREF(self)
        cell.tag = CorElementType.ELEMENT_TYPE_OBJECT
        return cell

    cdef StackCell box_value(self, StackCell cell, net_sigs.TypeSig type_sig):
        """ Performs boxing on an cell.  Boxing does things like convet a Int32 stackcell to a DotNetInt32 object.
            Always returns a duplicated cell.

        Args:
            cell (net_emu_structs.StackCell): The stackcell to box
            type_sig (net_sigs.TypeSig): The TypeSig that the boxed value should be (can be None for default)

        Returns:
            net_emu_structs.StackCell: the boxed value, duplicated.

        Raises:
            net_exceptions.OperationNotSupportedException: the operation cant be done on the provided args.
            net_exceptions.FeatureNotImplementedException: Ability to box this item has not been implemented.
        """
        cdef net_emu_types.DotNetObject dobj = None
        cdef net_emu_types.DotNetNumber dnum = None
        cdef net_sigs.CorLibTypeSig cor_sig = None
        cdef CorElementType cor_type
        cdef net_sigs.TypeSig usable_sig = type_sig
        cdef net_emu_types.BoxedReference box_ref = None
        if cell.tag == CorElementType.ELEMENT_TYPE_OBJECT or cell.tag == CorElementType.ELEMENT_TYPE_STRING:
            return self.duplicate_cell(cell)
        if cell.tag == CorElementType.ELEMENT_TYPE_END:
            raise net_exceptions.OperationNotSupportedException()
            
        if cell.tag == CorElementType.ELEMENT_TYPE_BYREF:
            box_ref = net_emu_types.BoxedReference(self)
            box_ref.init_internal_cell(cell)
            return self.pack_object(box_ref)
            
        if cell.is_slim_object:
            raise net_exceptions.OperationNotSupportedException()

        if usable_sig is None:
            usable_sig = net_sigs.CorLibTypeSig(cell.tag, None, None)
        if isinstance(usable_sig, net_sigs.CorLibTypeSig):
            cor_sig = <net_sigs.CorLibTypeSig>usable_sig
            cor_type = cor_sig.get_element_type()
            if cor_type == CorElementType.ELEMENT_TYPE_STRING:
                return self.duplicate_cell(cell)
            elif cor_type == CorElementType.ELEMENT_TYPE_I:
                dnum = net_emu_types.DotNetIntPtr(self, None)
                if self.__is_64bit:
                    dnum.from_long(cell.item.i8)
                else:
                    dnum.from_int(cell.item.i4)
                return self.pack_object(dnum)
            elif cor_type == CorElementType.ELEMENT_TYPE_U:
                dnum = net_emu_types.DotNetUIntPtr(self, None)
                if self.__is_64bit:
                    dnum.from_ulong(cell.item.u8)
                else:
                    dnum.from_uint(cell.item.u4)
                return self.pack_object(dnum)
            elif cor_type == CorElementType.ELEMENT_TYPE_I1:
                dnum = net_emu_types.DotNetInt8(self, None)
                dnum.from_char(<char>cell.item.i4)
                return self.pack_object(dnum)
            elif cor_type == CorElementType.ELEMENT_TYPE_U1:
                dnum = net_emu_types.DotNetUInt8(self, None)
                dnum.from_uchar(<unsigned char>cell.item.u4)
                return self.pack_object(dnum)
            elif cor_type == CorElementType.ELEMENT_TYPE_I2:
                dnum = net_emu_types.DotNetInt16(self, None)
                dnum.from_short(<short>cell.item.i4)
                return self.pack_object(dnum)
            elif cor_type == CorElementType.ELEMENT_TYPE_U2:
                dnum = net_emu_types.DotNetUInt16(self, None)
                dnum.from_ushort(<unsigned short>cell.item.u4)
                return self.pack_object(dnum)
            elif cor_type == CorElementType.ELEMENT_TYPE_I4:
                dnum = net_emu_types.DotNetInt32(self, None)
                dnum.from_int(cell.item.i4)
                return self.pack_object(dnum)
            elif cor_type == CorElementType.ELEMENT_TYPE_U4:
                dnum = net_emu_types.DotNetUInt32(self, None)
                dnum.from_uint(cell.item.u4)
                return self.pack_object(dnum)
            elif cor_type == CorElementType.ELEMENT_TYPE_I8:
                dnum = net_emu_types.DotNetInt64(self, None)
                dnum.from_long(cell.item.i8)
                return self.pack_object(dnum)
            elif cor_type == CorElementType.ELEMENT_TYPE_U8:
                dnum = net_emu_types.DotNetUInt64(self, None)
                dnum.from_ulong(cell.item.u8)
                return self.pack_object(dnum)
            elif cor_type == CorElementType.ELEMENT_TYPE_R4:
                dnum = net_emu_types.DotNetSingle(self, None)
                dnum.from_float(<float>cell.item.r8)
                return self.pack_object(dnum)
            elif cor_type == CorElementType.ELEMENT_TYPE_R8:
                dnum = net_emu_types.DotNetDouble(self, None)
                dnum.from_double(cell.item.r8)
                return self.pack_object(dnum)
            elif cor_type == CorElementType.ELEMENT_TYPE_BOOLEAN:
                dnum = net_emu_types.DotNetBoolean(self, None)
                dnum.from_bool(cell.item.b)
                return self.pack_object(dnum)
            elif cor_type == CorElementType.ELEMENT_TYPE_CHAR:
                dnum = net_emu_types.DotNetChar(self, None)
                dnum.from_ushort(<unsigned short>cell.item.u4)
                return self.pack_object(dnum)
            else:
                raise net_exceptions.EmulatorExecutionException(self, 'Cor type not supported for boxing {}'.format(net_utils.get_cor_type_name(cor_type)))
        raise net_exceptions.FeatureNotImplementedException()

    cdef StackCell unbox_value(self, StackCell cell):
        """ Performs unboxing on an cell.  Unboxing does things like convet a DotNetInt32() stackcell to a ELEMENT_TYPE_I4 stackcell.
            Always returns a duplicated cell.

        Args:
            cell (net_emu_structs.StackCell): The stackcell to unbox

        Returns:
            net_emu_structs.StackCell: the unboxed value, duplicated.

        Raises:
            net_exceptions.OperationNotSupportedException: the operation cant be done on the provided args.
            net_exceptions.FeatureNotImplementedException: Ability to unbox this item has not been implemented.
        """
        cdef net_emu_types.DotNetObject dobj = None
        cdef net_emu_types.DotNetNumber nobj = None
        cdef CorElementType cor_type = CorElementType.ELEMENT_TYPE_END
        cdef StackCell ref_cell
        cdef StackCell result
        if cell.is_slim_object:
            return self.duplicate_cell(cell)
        
        if cell.tag == CorElementType.ELEMENT_TYPE_BYREF:
            ref_cell = self.get_ref(cell)
            result = self.unbox_value(ref_cell)
            self.dealloc_cell(ref_cell)
            return result
        
        if cell.tag != CorElementType.ELEMENT_TYPE_OBJECT:
            return self.duplicate_cell(cell)
        if cell.item.ref == NULL:
            return self.pack_null()
        dobj = <net_emu_types.DotNetObject> cell.item.ref
        if not dobj.is_number():
            return self.duplicate_cell(cell)
        nobj = <net_emu_types.DotNetNumber>dobj
        cor_type = nobj.get_num_type()
        if cor_type == CorElementType.ELEMENT_TYPE_I:
            if self.__is_64bit:
                return self.pack_i(nobj.as_long())
            else:
                return self.pack_i(<int64_t>nobj.as_int())
        elif cor_type == CorElementType.ELEMENT_TYPE_U:
            if self.__is_64bit:
                return self.pack_u(nobj.as_ulong())
            else:
                return self.pack_u(<uint64_t>nobj.as_uint())
        elif cor_type == CorElementType.ELEMENT_TYPE_I1:
            return self.pack_i1(nobj.as_char())
        elif cor_type == CorElementType.ELEMENT_TYPE_U1:
            return self.pack_u1(nobj.as_uchar())
        elif cor_type == CorElementType.ELEMENT_TYPE_BOOLEAN:
            return self.pack_bool(nobj.as_bool())
        elif cor_type == CorElementType.ELEMENT_TYPE_CHAR:
            return self.pack_char(nobj.as_ushort())
        elif cor_type == CorElementType.ELEMENT_TYPE_I2:
            return self.pack_i2(nobj.as_short())
        elif cor_type == CorElementType.ELEMENT_TYPE_U2:
            return self.pack_u2(nobj.as_ushort())
        elif cor_type == CorElementType.ELEMENT_TYPE_I4:
            return self.pack_i4(nobj.as_int())
        elif cor_type == CorElementType.ELEMENT_TYPE_U4:
            return self.pack_u4(nobj.as_uint())
        elif cor_type == CorElementType.ELEMENT_TYPE_I8:
            return self.pack_i8(nobj.as_long())
        elif cor_type == CorElementType.ELEMENT_TYPE_U8:
            return self.pack_u8(nobj.as_ulong())
        elif cor_type == CorElementType.ELEMENT_TYPE_R4:
            return self.pack_r4(nobj.as_float())
        elif cor_type == CorElementType.ELEMENT_TYPE_R8:
            return self.pack_r8(nobj.as_double())
        else:
            raise net_exceptions.OperationNotSupportedException()

    def __dealloc__(self):
        self.cleanup()

    cpdef bint is_64bit(self):
        """ Is the emulator running as 64 bit.
        """
        return self.__is_64bit

    def set_print_debugging(self, print_debug, print_debug_children, print_debug_instrs=list(), print_debug_offsets=list(), print_debug_methods=list(), print_debug_level=1):
        """ Used to set up print debugging on the user side.  Print debugging prints a ton of information about the state of the emulator before and after each execution.
            It prints a ton of output, and drastically adds to the emulator runtime.

        Args:
            print_debug (bool): Should print debugging be enabled.
            print_debug_children (bool): should print debugging children emulators (call instrs e.x) be enabled.
            print_debug_instrs (list[str]): a list of instr names to print debug.
            print_debug_offsets (list[int]): a list of offsets to print debug.
            print_debug_methods (list[int]): a list of method rids to print debug.
            print_debug_level (int): Not currently used may be removed.
        """
        
        self.print_debug = print_debug
        self.print_debug_children = print_debug_children
        self.print_debug_instrs = print_debug_instrs
        self.print_debug_offsets = print_debug_offsets
        self.print_debug_methods = print_debug_methods
        self.print_debug_level = print_debug_level

    cpdef DotNetStack get_stack(self):
        """ Obtain the DotNetStack object associated with this emulator.
        Stacks are per method.  For the most part, DotNetStack operates similar to a python list().

        Returns:
            net_emulator.DotNetStack: the emulators stack.
        """
        return self.stack

    cpdef net_row_objects.MethodDefOrRef get_method_obj(self):
        """ Obtain the method object this emulator is executing.

        Returns:
            net_row_objects.MethodDefOrRef: the method object being emulated.
        """
        return self.method_obj

    cpdef DotNetEmulator get_caller(self):
        """ Obtain the calling emulator if it exists.

        Returns:
            net_emulator.DotNetEmulator: the parent emulator object if exists.
        """
        return self.caller

    cpdef EmulatorAppDomain get_appdomain(self):
        """ Obtain the current appdomain

        Returns:
            net_emulator.EmulatorAppDomain: the current appdomain.
        """
        return self.app_domain

    cpdef CctorRegistry get_executed_cctors(self):
        """ Get the CctorRegistry associated with this execution.

            May be removed once CctorRegistry is removed.

        Returns:
            net_exceptions.CctorRegistry: the cctor registry associated with the execution.
        """
        return self.executed_cctors

    cpdef void set_static_field_obj(self, int idno, net_emu_types.DotNetObject obj):
        """ For users to set the values of static fields before emulator execution.  Similar to setup_method_params(), it unboxes any value then sets it.

        Args:
            idno (int): the rid of the static field to set.
            obj (net_emu_types.DotNetObject): The object to set the value to.
        """
        cdef StackCell cell
        cdef StackCell unboxed
        if isinstance(obj, net_emu_types.DotNetString):
            cell = self.pack_string(obj)
        else:
            cell = self.pack_object(obj)
        unboxed = self.unbox_value(cell)
        self.get_appdomain().set_static_field(idno, unboxed)
        self.dealloc_cell(cell)
        self.dealloc_cell(unboxed)

    cpdef net_emu_types.DotNetObject get_static_field_obj(self, int idno):
        """ For users to get the values of static fields.
            This method will return boxed values only.

        Args:
            idno (int): the rid of the static field to get.
        Returns:
            net_emu_types.DotNetObject: The DotNetObject held by the field.
        """

        cdef StackCell cell = self.get_appdomain().get_static_field(idno)
        cdef StackCell boxed = self.box_value(cell, None)
        cdef net_emu_types.DotNetObject obj = None
        if cell.tag == CorElementType.ELEMENT_TYPE_END:
            self.dealloc_cell(boxed)
            self.dealloc_cell(cell)
            return None

        if boxed.is_slim_object:
            self.dealloc_cell(cell)
            self.dealloc_cell(boxed)
            return None #Not supported really.
        if boxed.item.ref != NULL:
            obj = <net_emu_types.DotNetObject>boxed.item.ref
        self.dealloc_cell(cell)
        self.dealloc_cell(boxed)
        return obj

    cdef StackCell _get_default_value(self, net_sigs.TypeSig type_sig, net_row_objects.TypeDefOrRef tref):
        """ Obtains the default value for a specific type sig and typedef/ref combo.
            Attempts to handle generics and such.

        Returns:
            net_emu_structs.StackCell: A newly allocated stackcell with the default value for the type.
        Raises:
            net_exceptions.EmulatorExecutionException: internal error.
            net_exceptions.InvalidArgumentsException: internal error.
        """
        cdef net_structs.CorElementType element_type
        cdef StackCell result
        cdef net_emu_types.DotNetString string = None
        cdef net_emu_types.DotNetObject new_obj = None
        cdef net_row_objects.TypeDefOrRef origclass = None
        cdef net_row_objects.TypeDefOrRef superclass = None
        cdef int number = 0
        cdef Py_ssize_t x = 0
        cdef net_sigs.GenericInstMethodSig msig = None
        cdef net_row_objects.RowObject param_obj = None
        cdef net_sigs.GenericInstSig tsig = None
        cdef net_sigs.TypeSig rsig = None
        memset(&result, 0, sizeof(result))
        if isinstance(type_sig, net_sigs.CorLibTypeSig):
            element_type = type_sig.get_element_type()
            if element_type == CorElementType.ELEMENT_TYPE_OBJECT:
                result = self.pack_null()
            elif element_type == CorElementType.ELEMENT_TYPE_STRING:
                result = net_emu_types.DotNetString.Empty(self.get_appdomain(), NULL, 0)
            else:
                if not (CorElementType.ELEMENT_TYPE_BOOLEAN <= element_type <= CorElementType.ELEMENT_TYPE_R8) and element_type != CorElementType.ELEMENT_TYPE_I and element_type != CorElementType.ELEMENT_TYPE_U:
                    raise net_exceptions.EmulatorExecutionException(self, 'Weird CorLibTypeSig type')
                #Should be mostly limited to numbers here.  We dont need to do anything except set tag.
                result.tag = element_type
                result.emulator_obj = <PyObject*>self
                Py_INCREF(self)
            return result
        elif isinstance(type_sig, net_sigs.PinnedSig):
            return self._get_default_value(type_sig.get_next(), tref)
        elif isinstance(type_sig, net_sigs.PtrSig): #For the most part the emulator does not support PtrSigs.  This is just so
            #That we can patch out the offending methods without it crashing on initialization.
            return self.pack_u(0)
        elif isinstance(type_sig, net_sigs.ValueTypeSig):
            # handle System.Enums as a different case
            origclass = type_sig.get_type()
            superclass = origclass
            if origclass.is_enum():
                result = self.pack_i4(0)
                return result
            else:
                if isinstance(origclass, net_row_objects.TypeRef):
                    return self.pack_null()
                return self.pack_slimobject(origclass)
        elif isinstance(type_sig, net_sigs.SZArraySig):
            #arrays are treated as objects currently so we can just set this to null I think.
            return self.pack_null()
        elif isinstance(type_sig, net_sigs.ArraySig):
            return self.pack_null() #For multi dimensional arrays I think easiest way to support is just an array of arrays.
        elif isinstance(type_sig, net_sigs.ClassSig):
            return self.pack_null()
        elif isinstance(type_sig, net_sigs.CModReqdSig):
            return self._get_default_value((<net_sigs.CModReqdSig>type_sig).get_next(), tref)
        elif isinstance(type_sig, net_sigs.GenericInstSig):
            return self._get_default_value((<net_sigs.GenericInstSig>type_sig).get_generic_type(), tref)
        elif isinstance(type_sig, net_sigs.GenericMVar):
            number = (<net_sigs.GenericMVar>type_sig).get_number()
            if self.spec_obj is None:
                if self.__init_open_generics_as_object:
                    return self.pack_null()
                raise net_exceptions.OperationNotSupportedException()
            msig = <net_sigs.GenericInstMethodSig>self.spec_obj.get_sig_obj()
            rsig = msig.get_generic_args()[number]
            if rsig == type_sig:
                raise net_exceptions.EmulatorExecutionException(self, 'preventing a GenericMVar infinite loop')
            if isinstance(rsig, net_sigs.GenericMVar):
                if self.__init_open_generics_as_object:
                    return self.pack_null()
            return self._get_default_value(rsig, tref)
        elif isinstance(type_sig, net_sigs.GenericVar):
            number = (<net_sigs.GenericVar>type_sig).get_number()
            if not isinstance(tref, net_row_objects.TypeSpec):
                if self.__init_open_generics_as_object:
                    return self.pack_null()
                raise net_exceptions.InvalidArgumentsException()
            if not isinstance((<net_row_objects.TypeSpec>tref).get_sig_obj(), net_sigs.GenericInstSig):
                raise net_exceptions.InvalidArgumentsException()
            tsig = <net_sigs.GenericInstSig>(<net_row_objects.TypeSpec>tref).get_sig_obj()
            rsig = tsig.get_generic_args()[number]
            if rsig == type_sig:
                raise net_exceptions.EmulatorExecutionException(self, 'preventing a GenericVar infinite loop')
            if isinstance(rsig, net_sigs.GenericVar):
                if self.__init_open_generics_as_object:
                    return self.pack_null()
            return self._get_default_value(rsig, tref)
        else:
            raise net_exceptions.EmulatorExecutionException(self, 'weird sig {}'.format(type(type_sig)))
        return self.pack_null()

    def skip_next_instruction(self):
        """ Instructs the emulator to skip the next instruction.
        """
        self.__skip_next_instruction = True

    def stop_emulator(self):
        """ Instructs the emulator to stop.  May be removed soon since its kinda useless to some degree.
        """
        self.should_break = True

    cdef void print_string(self, str string, int print_debug_level):
        """ Prints a string if print debugging is enabled.
        """
        if self.print_debug:
            print(string)

    cpdef net_emu_types.DotNetThread get_current_thread(self):
        """ Obtains the current executing thread.
        """
        return self.running_thread

    cpdef void set_running_thread(self, net_emu_types.DotNetThread thread_obj):
        """ Sets the currently executing thread.
        """
        self.running_thread = thread_obj

    cpdef DotNetEmulator spawn_new_emulator(self, net_row_objects.MethodDefOrRef method_obj, int start_offset=0, int end_offset=-1, DotNetEmulator caller=None,
                           int end_method_rid=-1, int end_eip=-1, net_row_objects.MethodSpec spec_obj=None, int timeout_seconds=-1, bint strict_typing=False, bint dont_execute_first_cctor=False):
        """ Use this method to create a new emulator off an existing one.
            For instance, if you are trying to deobfuscate strings, the usual way to do it would be to emulate some cctor method
            and then use spawn_new_emulator() to create emulator objects each time the string decryption method is emulated.
            Also used by call instructions and such for the same purpose.

        Args:
            method_obj (net_row_objects.MethodDefOrRef): the method object to emulate.
            start_offset (int): the start offset to start emulation at.
            end_offset (int): The offset to end emulation at.  -1 for None.
            caller (net_emulator.DotNetEmulator): The parent emulator.  Sometimes this isnt needed so its a param, but usually its handled internally.
            end_method_rid (int): the RID of the method to use end_offset for, -1 for current.
            end_eip (int): The EIP to end execution on, -1 for None.
            spec_obj (net_row_objects.MethodSpec): If the method has a methodspec, provide it here.
            timeout_seconds (int): The timeout in seconds -1 for infinite.
            strict_typing (bool): see net_emulator.DotNetEmulator docs.
            dont_execute_first_cctor (bool): Block execution of only the first cctor (the one for the parent type of method_obj)
        
        Returns:
            net_emulator.DotNetEmulator: The newly allocated emulator object for the method.
        """
        cdef DotNetEmulator new_emu = DotNetEmulator(method_obj, start_offset=start_offset, end_offset=end_offset, caller=caller, app_domain=self.app_domain, spec_obj=spec_obj, strict_typing=strict_typing, init_open_generics_as_object=self.__init_open_generics_as_object)
        cdef net_row_objects.MethodDef cctor_method = None
        new_emu.executed_cctors = self.executed_cctors
        if end_method_rid == -1:
            new_emu.end_method_rid = self.end_method_rid
            if self.end_method_rid != -1:
                new_emu.end_offset = self.end_offset
        else:
            new_emu.end_method_rid = end_method_rid
        new_emu.end_eip = end_eip
        if timeout_seconds > 0:
            new_emu.start_time = _perf_counter_ns()
            new_emu.timeout_ns = <uint64_t>(timeout_seconds * 1000000000ULL)
        else:
            new_emu.timeout_ns = self.timeout_ns
            new_emu.start_time = self.start_time
        new_emu.print_debug_children = self.print_debug_children
        if self.print_debug_children:
            new_emu.print_debug = self.print_debug
        new_emu.ignore_security_exceptions = self.ignore_security_exceptions
        new_emu.break_on_unsupported = self.break_on_unsupported
        new_emu.spawned = True
        new_emu.dont_execute_cctor = self.dont_execute_cctor
        new_emu.print_debug_instrs = self.print_debug_instrs
        new_emu.print_debug_offsets = self.print_debug_offsets
        new_emu.print_debug_rids = self.print_debug_rids
        new_emu.ignore_instrs = self.ignore_instrs
        new_emu.print_debug_methods = self.print_debug_methods
        new_emu.print_debug_level = self.print_debug_level
        new_emu.running_thread = self.running_thread
        if dont_execute_first_cctor:
            if new_emu.method_obj.get_parent_type() is not None:
                cctor_method = new_emu.method_obj.get_parent_type().get_static_constructor()
                if cctor_method is not None:
                    new_emu.executed_cctors.can_execute(cctor_method)
        return new_emu

    cdef void set_slimobj_field(self, StackCell slim_obj, int idno, StackCell val):
        """ This is the new methods for handling object fields.  Slim Object representations are cheaper in memory than DotNetObject.

        Args:
            slim_obj (net_emu_structs.StackCell): the object to set the field for.
            idno (int): The rid of the field to set.
            val (net_emu_structs.StackCell): The value to set the field to.

        Raises:
            net_exceptions.InvalidArgumentsException: internal error, args are invalid.
        """
        if not slim_obj.is_slim_object:
            raise net_exceptions.InvalidArgumentsException()
        if slim_obj.item.slim_object == NULL or slim_obj.item.slim_object.fields == NULL or slim_obj.item.slim_object.num_fields <= self.get_appdomain().get_field_index(idno, slim_obj.item.slim_object.type_token):
            raise net_exceptions.InvalidArgumentsException()
        cdef int field_index = self.get_appdomain().get_field_index(idno, slim_obj.item.slim_object.type_token)
        cdef StackCell * fields = slim_obj.item.slim_object.fields
        cdef StackCell old = fields[field_index]
        cdef net_table_objects.TableObject field_table = self.get_method_obj().get_dotnetpe().get_metadata_table('Field')
        cdef net_row_objects.Field field = field_table.get(idno)
        cdef net_sigs.FieldSig fsig = field.get_field_signature()
        cdef StackCell new = self.cast_cell(val, fsig.get_type_sig())
        self.ref_cell(new)
        self.deref_cell(old)
        self.dealloc_cell(old)
        fields[field_index] = new

    cdef StackCell get_slimobj_field(self, StackCell slim_obj, int idno):
        """ This is the new methods for handling object fields.  Slim Object representations are cheaper in memory than DotNetObject.

        Args:
            slim_obj (net_emu_structs.StackCell): the object to get the field for.
            idno (int): The rid of the field to get.

        Returns:
            net_emu_structs.StackCell: a duplicated stackcell object pulled from the specified field.

        Raises:
            net_exceptions.InvalidArgumentsException: internal error, args are invalid.
            net_exceptions.OperationNotSupportedException: internal error, args are invalid.
        """
        if not slim_obj.is_slim_object:
            raise net_exceptions.InvalidArgumentsException()
        if slim_obj.item.slim_object == NULL or slim_obj.item.slim_object.fields == NULL or slim_obj.item.slim_object.num_fields <= self.get_appdomain().get_field_index(idno, slim_obj.item.slim_object.type_token):
            raise net_exceptions.InvalidArgumentsException()
        cdef int instr_index = self.get_appdomain().get_field_index(idno, slim_obj.item.slim_object.type_token)
        cdef StackCell * fields = slim_obj.item.slim_object.fields
        cdef StackCell cell = fields[instr_index]
        cdef net_table_objects.TableObject field_table = self.get_method_obj().get_dotnetpe().get_metadata_table('Field')
        cdef net_row_objects.Field field = field_table.get(idno)
        cdef net_sigs.FieldSig fsig = field.get_field_signature()
        if slim_obj.item.slim_object.fields == NULL:
            raise net_exceptions.OperationNotSupportedException()
        if cell.tag == CorElementType.ELEMENT_TYPE_END:
            cell = self._get_default_value(fsig.get_type_sig(), field.get_parent_type())
            if cell.tag == CorElementType.ELEMENT_TYPE_END:
                raise net_exceptions.OperationNotSupportedException()
            self.set_slimobj_field(slim_obj, idno, cell)
            self.dealloc_cell(cell)
        return self.duplicate_cell(fields[instr_index])

    cdef str slimobj_to_str(self, StackCell cell):
        """ Creates a string representation of a slim object for print debugging.

        Args:
            cell (net_emu_structs.StackCell): the cell to obtain string for.

        Returns:
            str: a string representation of the stackcell.

        Raises:
            net_exceptions.InvalidArgumentsException: internal error.
        """
        if not cell.is_slim_object:
            raise net_exceptions.InvalidArgumentsException()
        cdef str str_val
        cdef StackCell * fields = cell.item.slim_object.fields
        cdef int num_fields = cell.item.slim_object.num_fields
        if num_fields > 0:
            str_val = 'SlimDotNetObject,type_obj={}, fields='.format(hex(cell.item.slim_object.type_token))
            str_val += '{'
            for x in range(num_fields):
                rid = self.get_appdomain().get_field_rid(x, cell.item.slim_object.type_token)
                str_val += str(rid) + ': ' + self.cell_to_str(fields[x]) + ','
            str_val = str_val.rstrip(',') + '}'
            return str_val                
        return 'SlimDotNetObject,type_obj={}'.format(hex(cell.item.slim_object.type_token))

    cdef str cell_to_str(self, StackCell cell):
        """ Creates a string representation of a StackCell for print debugging.

        Args:
            cell (net_emu_structs.StackCell): the cell to obtain string for.

        Returns:
            str: a string representation of the stackcell.

        Raises:
            net_exceptions.InvalidArgumentsException: internal error.
        """
        cdef uint64_t * ptr = NULL
        cdef uint64_t ival = 0
        cdef str result = ''
        cdef StackCell obj
        cdef net_emu_types.DotNetObject dobj = None
        if cell.tag == CorElementType.ELEMENT_TYPE_BYREF:
            obj = self.get_ref(cell)
            result = self.cell_to_str(obj)
            self.dealloc_cell(obj)
            return 'Reference (kind: {}, idx: {}): '.format(cell.item.byref.kind, cell.item.byref.idx) + result
        elif cell.tag == CorElementType.ELEMENT_TYPE_OBJECT or cell.tag == CorElementType.ELEMENT_TYPE_STRING:
            if cell.is_slim_object:
                return self.slimobj_to_str(cell)
            if cell.item.ref == NULL:
                return 'null'
            dobj = <net_emu_types.DotNetObject>cell.item.ref
            return str(dobj)
        else:
            if cell.tag == CorElementType.ELEMENT_TYPE_END:
                return 'Blank Cell'
            ptr = <uint64_t*>&cell.item
            if net_utils.is_cortype_signed(<CorElementType>cell.tag):
                return hex(<int64_t>(<int64_t*>&cell.item)[0])
            ival = ptr[0]
            return hex(ival)

    cpdef void print_current_state(self):
        """ prints the current state of the emulator to stdout.  Used for print debugging.
        """
        cdef state_str = ''
        cdef StackCell value
        cdef unsigned int key = 0
        cdef int idno = 0
        cdef StackCell obj
        cdef Py_ssize_t x = 0
        cdef net_table_objects.TableObject field_table = self.get_method_obj().get_dotnetpe().get_metadata_table('Field')
        cdef net_sigs.FieldSig field_sig = None
        cdef list param_sigs = self.method_obj.get_method_signature().get_parameters()
        cdef int params_start = 0
        if self.is_destroyed:
            raise net_exceptions.OperationNotSupportedException()
        state_str += 'Emulator Method: {}:{} {}:{}\n'.format(self.method_obj.get_table_name(), self.method_obj.get_rid(), hex(self.method_obj.get_token()), self.method_obj.get_full_name())
        if self.method_obj.method_has_this() and self.get_num_params() >= 1:
            state_str += 'This Object: {}\n'.format(self.cell_to_str(self.__method_params[0]))
        state_str += 'Printing method arguments:\n'
        if self.method_obj.method_has_this():
            params_start = 1
        for x in range(params_start, self.get_num_params()):
            obj = self.__method_params[x]
            if self.method_obj.method_has_this():
                state_str += '{}: {} - {}\n'.format(x, self.cell_to_str(obj), str(param_sigs[x - 1]))
            else:
                state_str += '{}: {} - {}\n'.format(x, self.cell_to_str(obj), str(param_sigs[x]))
        """state_str += 'Printing static variables:\n'
        if field_table is not None:
            for idno in range(self.get_appdomain().get_amt_static_fields()):
                obj = self.get_appdomain().get_static_field_idx(idno)
                field_sig = (<net_row_objects.Field>field_table.get(obj.rid)).get_field_signature()
                state_str += '{}: {} - {}\n'.format(hex(obj.rid), self.cell_to_str(obj), str(field_sig.get_type_sig()))"""
        state_str += 'Printing local vars:\n'
        for key in range(self.localvars.size()):
            value = self.localvars[key]
            state_str += '{}: {} - {}\n'.format(hex(key), self.cell_to_str(value), str(<net_sigs.TypeSig>self.local_var_sigs[key]))
        state_str += 'Printing stack:\n'
        for x in range(len(self.stack)):
            value = self.stack.get(<int>x)
            state_str += '{} - {}\n'.format(self.cell_to_str(value), net_utils.get_cor_type_name(<CorElementType>value.tag).decode())
            self.dealloc_cell(value)
        state_str += 'Last Instruction Execution Time (perf_counter_ns): {}\n'.format(
            self.__last_instr_end - self.__last_instr_start)
        state_str += 'Current EIP: {} Current Offset: {}\n'.format(
            hex(self.current_eip), hex(self.current_offset))
        self.print_string(state_str, 1)

    cdef StackCell get_local(self, int idx):
        """ Obtains a duplicated local value for index idx.
        """
        if idx < 0 or <size_t>idx >= self.localvars.size():
            raise net_exceptions.InvalidArgumentsException()
        cdef StackCell return_value = self.duplicate_cell(self.localvars[idx])
        return return_value

    cpdef net_emu_types.DotNetObject get_local_obj(self, int idx):
        """ Obtains a DotNetObject representing the local at value idx.

        Returns:
            net_emu_types.DotNetObject: The object value corresponding to local idx.
        """

        cdef StackCell ret_val = self.get_local(idx)
        cdef StackCell boxed_cell
        cdef net_emu_types.DotNetObject result = None
        if ret_val.tag == CorElementType.ELEMENT_TYPE_END:
            raise net_exceptions.InvalidArgumentsException()
        boxed_cell = self.box_value(ret_val, None)
        if self.cell_is_null(boxed_cell):
            result = None
        else:
            result = <net_emu_types.DotNetObject>boxed_cell.item.ref
        self.dealloc_cell(boxed_cell)
        self.dealloc_cell(ret_val)
        return result

    cpdef void set_local_obj(self, int idx, net_emu_types.DotNetObject obj):
        """ Sets a local variable to a specified value.  Intended for user use.

        Args:
            idx (int): the local var number to set.
            obj (net_emu_types.DotNetObject): The object to set it to (None for NULL)
        """
        cdef StackCell cell
        cdef StackCell unboxed
        if obj is None:
            cell = self.pack_null()
            self.set_local(idx, cell)
            self.dealloc_cell(cell)
            return
        cell = self.pack_object(obj)
        unboxed = self.unbox_value(cell)
        self.set_local(idx, unboxed)
        self.dealloc_cell(unboxed)
        self.dealloc_cell(cell)

    cdef void set_local(self, int idx, StackCell obj):
        """ Sets a local value to obj at idx.
            obj must be deallocated by caller.
        """
        if idx < 0 or <size_t>idx >= self.localvars.size():
            raise net_exceptions.InvalidArgumentsException()
        cdef StackCell prev_val = self.get_local(idx)
        cdef StackCell dup_obj = self.cast_cell(obj, <net_sigs.TypeSig>self.local_var_sigs[idx])
        self.ref_cell(dup_obj)
        self.deref_cell(prev_val)
        self.dealloc_cell(prev_val)
        self.localvars[idx] = dup_obj

    cdef void print_instr(self, net_cil_disas.Instruction instr):
        """ Prints the current instruction the emulator is executing for print debugging.
        """          
        if isinstance(self.method_obj, net_emu_types.DynamicMethodObject):
            self.print_string('DynamicMethod: Offset={}, Instr={} {}'.format(hex(self.current_offset), instr.get_name(),
                                                                             instr.get_argument()), 1)
        else:
            self.print_string(
                'Emulator={}:{}:{}, Offset={}, Instr={} {}'.format(self.method_obj.get_table_name(), hex(self.method_obj.get_token()), self.method_obj.get_rid(),
                                                                hex(self.current_offset), instr.get_name(),
                                                                instr.get_argument()), 1)

    cdef void initialize_locals(self):
        """ Initializes locals to default values.
        """
        cdef net_sigs.TypeSig tsig
        cdef int index
        cdef StackCell ref
        for index in range(len(self.disasm_obj.local_types)):
            tsig = self.disasm_obj.local_types[index]
            try:
                ref = self._get_default_value(tsig, self.method_obj.get_parent_type())
            except Exception as e:
                raise net_exceptions.EmulatorExecutionException(self, 'Error initializing local {}.  Likely an unsupported signature {}: {}'.format(index, tsig, str(e)))
            Py_INCREF(tsig)
            self.ref_cell(ref)
            self.local_var_sigs.push_back(<PyObject*>tsig)
            self.localvars.push_back(ref)

    cpdef void run_function(self) except *:
        """ Emulates the method until instructed to end.
            Must be called by the user to begin execution.
        """
        cdef bint should_print = False
        cdef bint do_normal_offsets = False
        cdef bint debug_print = False
        cdef DotNetEmulator emu = None
        cdef emu_instr_handler_type emu_instr_handler = NULL
        cdef bint has_timeout = self.timeout_ns > 0
        cdef Py_ssize_t x = 0
        cdef StackCell cell
        cdef bint should_check_offset = False
        cdef unsigned int end_offset = 0
        cdef EmulatorAppDomain app_domain = self.get_appdomain()
        cdef bint should_do_normal_handler = False
        cdef tuple instr_handler = None
        if self.end_method_rid > 0:
            if isinstance(self.method_obj, net_row_objects.MethodDef) and self.method_obj.get_rid() == self.end_method_rid:
                should_check_offset = True
                end_offset = <unsigned int>self.end_offset
                self.end_method_rid = -1 #Clear end_method_rid to prevent issues with children emulators. #Make it zero not -1 to prevent 
        else:
            if self.end_offset > 0:
                end_offset = <unsigned int>self.end_offset
                should_check_offset = True
                self.end_offset = -1
        if self.caller is None and has_timeout:
            self.start_time = _perf_counter_ns()
        self.get_appdomain().set_current_emulator(self)
        self.get_appdomain().set_executing_dotnetpe(self.method_obj.get_dotnetpe())
        for x in range(self.get_num_params()):
            cell = self.__method_params[x]
            if cell.tag == CorElementType.ELEMENT_TYPE_END:
                raise net_exceptions.EmulatorExecutionException(self, 'Invalid param at position {}'.format(x))
            
        if isinstance(self.method_obj, net_row_objects.MethodDef) and not self.dont_execute_cctor:
            if not self.method_obj.is_static_constructor():
                if self.method_obj.get_parent_type():
                    cctor_method = self.method_obj.get_parent_type().get_static_constructor()
                    if cctor_method and cctor_method.is_static_constructor():
                        if self.executed_cctors.can_execute(cctor_method):
                            emu = self.spawn_new_emulator(cctor_method, caller=self)
                            emu._allocate_params(0) #Cctor methods dont have params
                            emu.run_function()
            else:
                self.executed_cctors.can_execute(self.method_obj)
        if isinstance(self.method_obj, net_row_objects.MethodDef):
            if self.method_obj.get_rid() in self.print_debug_methods:
                self.print_debug = True
        if self.caller is not None:
            if self.print_debug:
                self.print_current_state()
        while self.current_eip < len(self.disasm_obj):
            if PyErr_CheckSignals() == -1:
                raise net_exceptions.EmulatorExecutionException(self, 'PyErr_CheckSignals() returned -1')
            self.should_break = False
            self.instr = self.disasm_obj.get_instr_at_offset(self.current_offset)
            if self.instr == None:
                raise net_exceptions.InvalidArgumentsException()
            if self.instr.get_opcode() == net_opcodes.Opcodes.Invalid:
                raise net_exceptions.InstructionNotSupportedException(self.instr.get_name())
            if should_check_offset:
                if self.current_offset <= end_offset < (self.current_offset + self.instr.get_instr_size()):
                    raise net_exceptions.EmulatorEndExecutionException(self, self.method_obj.get_rid(), self.end_method_rid, end_offset, self.current_offset)

            if (self.print_debug and len(self.print_debug_instrs) == 0) or (self.print_debug and self.instr.get_name() in self.print_debug_instrs):
                self.print_instr(self.instr)

            try:
                if self.print_debug:
                    self.__last_instr_start = _perf_counter_ns()
                should_do_normal_handler = False
                instr_handler = app_domain.get_instr_handler(self.instr.get_opcode())
                if instr_handler is None:
                    should_do_normal_handler = True
                else:
                    should_do_normal_handler = instr_handler[0](self, instr_handler[1])
                    do_normal_offsets = True
                
                if should_do_normal_handler:
                    emu_instr_handler = emu_func_handlers[<uint16_t>self.instr.get_opcode()]
                    if emu_instr_handler == NULL:
                        raise net_exceptions.InstructionNotSupportedException(self.instr.get_name())
                    
                    do_normal_offsets = not emu_instr_handler(self)

                if do_normal_offsets:
                    self.current_eip += 1
                    self.current_offset += self.instr.get_instr_size()

                if self.print_debug or has_timeout:
                    self.__last_instr_end = _perf_counter_ns()

                if has_timeout:
                    if (self.__last_instr_end - self.start_time) > self.timeout_ns:
                        raise net_exceptions.EmulatorTimeoutException(self)
            except net_exceptions.InstructionNotSupportedException as e:
                if self.break_on_unsupported:
                    break
                else:
                    if not self.already_init:
                        self.get_appdomain().set_calling_dotnetpe(None)
                    if not self.print_debug:
                        self.print_debug = True
                    self.print_string('1: Error on method: {}:{} - Offset: {}'.format(self.method_obj,
                                                                                   hex(self.method_obj.get_token()),
                                                                                   hex(self.instr.get_instr_offset())), 1)
                    raise e

            except net_exceptions.EmulatorSecurityException as e:
                if self.ignore_security_exceptions:
                    self.current_eip += 1
                    self.current_offset += self.instr.get_instr_size()
                    self.print_string('Emulator: Ignoring Security Exception {}'.format(str(e)), 1)
                else:
                    if not self.print_debug:
                        self.print_debug = True
                    self.print_string('2: Error on method: {}:{} - Offset: {}'.format(self.method_obj,
                                                                                   hex(self.method_obj.get_token()),
                                                                                   hex(self.instr.get_instr_offset())), 1)
                    raise e
            except net_exceptions.TooManyMethodParameters as e:
                raise e
            except Exception as e:
                if not self.print_debug:
                    self.print_debug = True
                self.print_string('3: Error on method: {}:{} - Offset: {} {}'.format(self.method_obj,
                                                                               hex(self.method_obj.get_token()),
                                                                               hex(self.instr.get_instr_offset()), str(e)), 1)
                if not self.already_init:
                    self.get_appdomain().set_calling_dotnetpe(None)
                raise e
            if (self.print_debug and len(self.print_debug_instrs) == 0) or (self.print_debug and self.instr.get_name() in self.print_debug_instrs):
                self.print_current_state()

            if self.instr.get_opcode() == net_opcodes.Opcodes.Ret or self.should_break:
                break

        if not self.already_init:
            self.get_appdomain().set_calling_dotnetpe(None)
        if self.caller is not None: #sp that users can pop results off the stack if needed.
            self.stack.clear()
        self.cleanup()

    cdef void cleanup(self):
        """ Cleans up all allocated memory by the emulator.
        """
        cdef StackCell obj
        cdef unsigned int key = 0
        for key in range(self.localvars.size()):
            obj = self.localvars[key]
            self.deref_cell(obj) #Remove local var ref
            self.dealloc_cell(obj) #Remove cell ref
        for key in range(self.local_var_sigs.size()):
            Py_XDECREF(self.local_var_sigs[key])
        self.local_var_sigs.clear()
        self.localvars.clear()
        self.is_destroyed = True
        if self.__method_params != NULL:
            for key in range(<unsigned int>self.get_num_params()):
                self.deref_cell(self.__method_params[key])
                self.dealloc_cell(self.__method_params[key])
            free(self.__method_params)
            self.__method_params = NULL
