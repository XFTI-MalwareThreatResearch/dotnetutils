#cython: language_level=3
#distutils: language=c++

import threading
from dotnetutils import net_exceptions
from libc.stdint cimport int64_t, uint64_t
from libc.string cimport strlen, strcmp, memset
from dotnetutils cimport net_sigs, net_tokens, net_opcodes, net_cil_disas, net_structs, net_row_objects, net_emu_types, net_table_objects, dotnetpefile
from dotnetutils.net_structs cimport CorElementType
from cpython.ref cimport Py_INCREF, Py_XDECREF
from libcpp.utility cimport pair
from cpython.exc cimport PyErr_CheckSignals

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

tlock = threading.Lock()

cdef emu_instr_handler_type emu_func_handlers[0x10000]

cdef bint __is_handlers_initialized = False

cdef void __init_handlers():
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
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Div_Un] = handle_unsupported_instruction
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
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Ldelem_U8] = handle_ldelem_u8_instruction
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
    emu_func_handlers[<uint16_t>net_opcodes.Opcodes.Tail] = handle_unsupported_instruction
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

cdef int64_t handle_native_int(net_emu_types.DotNetNumber num):
    """
    Theres a series of issues where on 64 bit samples int32 will be pushed for various instructions instead of native int.
    Thats handled here. its allowed but not technically up to spec.
    """
    cdef net_emu_types.DotNetInt64 new_num = num.cast(net_structs.CorElementType.ELEMENT_TYPE_I8)
    return new_num.as_long()

"""
These functions are for the most part instruction handlers
These handlers are meant to emulate specific instructions.
Instruction handlers return False if the emulator should move to the next instruction
True is returned if the instruction is a jump and has already jumped to the next instruction.
"""

cdef bint handle_general_jump(DotNetEmulator emu): #Good
    cdef int instr_offset  = <int>emu.instr.get_argument()
    cdef unsigned int expected_offset = emu.current_offset + emu.instr.get_instr_size() + instr_offset
    emu.current_offset = expected_offset
    emu.current_eip = emu.disasm_obj.get_instr_index_by_offset(expected_offset)
    return True

cdef bint handle_stind_i_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber num_obj = emu.stack.pop()
    cdef net_emu_types.ArrayAddress addr_obj = emu.stack.pop()
    if not num_obj.is_number() or not isinstance(addr_obj, net_emu_types.ArrayAddress):
        raise net_exceptions.InvalidArgumentsException()
    addr_obj.set_obj_ref(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_I))
    return False

cdef bint handle_stind_i1_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber num_obj = emu.stack.pop()
    cdef net_emu_types.ArrayAddress addr_obj = emu.stack.pop()
    if not num_obj.is_number() or not isinstance(addr_obj, net_emu_types.ArrayAddress):
        raise net_exceptions.InvalidArgumentsException()
    addr_obj.set_obj_ref(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_I1))
    return False

cdef bint handle_stind_i2_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber num_obj = emu.stack.pop()
    cdef net_emu_types.ArrayAddress addr_obj = emu.stack.pop()
    if not num_obj.is_number() or not isinstance(addr_obj, net_emu_types.ArrayAddress):
        raise net_exceptions.InvalidArgumentsException()
    addr_obj.set_obj_ref(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_I2))
    return False

cdef bint handle_stind_i4_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber num_obj = emu.stack.pop()
    cdef net_emu_types.ArrayAddress addr_obj = emu.stack.pop()
    if not num_obj.is_number() or not isinstance(addr_obj, net_emu_types.ArrayAddress):
        raise net_exceptions.InvalidArgumentsException()
    addr_obj.set_obj_ref(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_I4))
    return False

cdef bint handle_stind_i8_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber num_obj = emu.stack.pop()
    cdef net_emu_types.ArrayAddress addr_obj = emu.stack.pop()
    if not num_obj.is_number() or not isinstance(addr_obj, net_emu_types.ArrayAddress):
        raise net_exceptions.InvalidArgumentsException()
    addr_obj.set_obj_ref(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_I8))
    return False

cdef bint handle_stind_r4_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber num_obj = emu.stack.pop()
    cdef net_emu_types.ArrayAddress addr_obj = emu.stack.pop()
    if not num_obj.is_number() or not isinstance(addr_obj, net_emu_types.ArrayAddress):
        raise net_exceptions.InvalidArgumentsException()
    addr_obj.set_obj_ref(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_R4))
    return False

cdef bint handle_stind_r8_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber num_obj = emu.stack.pop()
    cdef net_emu_types.ArrayAddress addr_obj = emu.stack.pop()
    if not num_obj.is_number() or not isinstance(addr_obj, net_emu_types.ArrayAddress):
        raise net_exceptions.InvalidArgumentsException()
    addr_obj.set_obj_ref(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_R8))
    return False

cdef bint handle_stind_ref_instruction(DotNetEmulator emu):
    cdef net_emu_types.ArrayAddress num_obj = emu.stack.pop()
    cdef net_emu_types.ArrayAddress addr_obj = emu.stack.pop()
    if not isinstance(num_obj, net_emu_types.ArrayAddress) or not isinstance(addr_obj, net_emu_types.ArrayAddress):
        raise net_exceptions.InvalidArgumentsException()
    addr_obj.set_obj_ref(num_obj)
    return False

cdef bint handle_ldind_i_instruction(DotNetEmulator emu):
    cdef StackCell addr_obj = emu.stack.pop()
    cdef StackCell ref_obj
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    if not net_utils.is_cortype_number(addr_obj.byref.tag):
        raise net_exceptions.InvalidArgumentsException()
    ref_obj = *addr_obj.item.byref
    ref_obj.tag = CorElementType.ELEMENT_TYPE_I
    emu.stack.append(ref_obj)
    return False

cdef bint handle_ldind_i1_instruction(DotNetEmulator emu):
    cdef StackCell addr_obj = emu.stack.pop()
    cdef StackCell ref_obj
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    if not net_utils.is_cortype_number(addr_obj.byref.tag):
        raise net_exceptions.InvalidArgumentsException()
    ref_obj = *addr_obj.item.byref
    ref_obj.tag = CorElementType.ELEMENT_TYPE_I4
    emu.stack.append(ref_obj)
    return False

cdef bint handle_ldind_i2_instruction(DotNetEmulator emu):
    cdef StackCell addr_obj = emu.stack.pop()
    cdef StackCell ref_obj
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    if not net_utils.is_cortype_number(addr_obj.byref.tag):
        raise net_exceptions.InvalidArgumentsException()
    ref_obj = *addr_obj.item.byref
    ref_obj.tag = CorElementType.ELEMENT_TYPE_I4
    emu.stack.append(ref_obj)
    return False

cdef bint handle_ldind_i4_instruction(DotNetEmulator emu):
    cdef StackCell addr_obj = emu.stack.pop()
    cdef StackCell ref_obj
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    if not net_utils.is_cortype_number(addr_obj.byref.tag):
        raise net_exceptions.InvalidArgumentsException()
    ref_obj = *addr_obj.item.byref
    ref_obj.tag = CorElementType.ELEMENT_TYPE_I4
    emu.stack.append(ref_obj)
    return False

cdef bint handle_ldind_i8_instruction(DotNetEmulator emu):
    cdef StackCell addr_obj = emu.stack.pop()
    cdef StackCell ref_obj
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    if not net_utils.is_cortype_number(addr_obj.byref.tag):
        raise net_exceptions.InvalidArgumentsException()
    ref_obj = *addr_obj.item.byref
    ref_obj.tag = CorElementType.ELEMENT_TYPE_I8
    emu.stack.append(ref_obj)
    return False

cdef bint handle_ldind_r4_instruction(DotNetEmulator emu):
    cdef StackCell addr_obj = emu.stack.pop()
    cdef StackCell ref_obj
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    if not net_utils.is_cortype_number(addr_obj.byref.tag):
        raise net_exceptions.InvalidArgumentsException()
    ref_obj = *addr_obj.item.byref
    ref_obj.tag = CorElementType.ELEMENT_TYPE_R4
    emu.stack.append(ref_obj)
    return False

cdef bint handle_ldind_r8_instruction(DotNetEmulator emu):
    cdef StackCell addr_obj = emu.stack.pop()
    cdef StackCell ref_obj
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    if not net_utils.is_cortype_number(addr_obj.byref.tag):
        raise net_exceptions.InvalidArgumentsException()
    ref_obj = *addr_obj.item.byref
    ref_obj.tag = CorElementType.ELEMENT_TYPE_R8
    emu.stack.append(ref_obj)
    return False

cdef bint handle_ldind_ref_instruction(DotNetEmulator emu):
    cdef StackCell addr_obj = emu.stack.pop()
    cdef StackCell ref_obj
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.InvalidArgumentsException()
    ref_obj = *addr_obj.item.byref
    if ref_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.InvalidArgumentsException()
    emu.stack.append(ref_obj)
    return False

cdef bint handle_ldind_u1_instruction(DotNetEmulator emu):
    cdef StackCell addr_obj = emu.stack.pop()
    cdef StackCell ref_obj
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    if not net_utils.is_cortype_number(addr_obj.byref.tag):
        raise net_exceptions.InvalidArgumentsException()
    ref_obj = *addr_obj.item.byref
    ref_obj.tag = CorElementType.ELEMENT_TYPE_U4
    emu.stack.append(ref_obj)
    return False

cdef bint handle_ldind_u2_instruction(DotNetEmulator emu):
    cdef StackCell addr_obj = emu.stack.pop()
    cdef StackCell ref_obj
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    if not net_utils.is_cortype_number(addr_obj.byref.tag):
        raise net_exceptions.InvalidArgumentsException()
    ref_obj = *addr_obj.item.byref
    ref_obj.tag = CorElementType.ELEMENT_TYPE_U4
    emu.stack.append(ref_obj)
    return False

cdef bint handle_ldind_u4_instruction(DotNetEmulator emu):
    cdef StackCell addr_obj = emu.stack.pop()
    cdef StackCell ref_obj
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    if not net_utils.is_cortype_number(addr_obj.byref.tag):
        raise net_exceptions.InvalidArgumentsException()
    ref_obj = *addr_obj.item.byref
    ref_obj.tag = CorElementType.ELEMENT_TYPE_U4
    emu.stack.append(ref_obj)
    return False

cdef bint handle_br_instruction(DotNetEmulator emu): #Good
    return handle_general_jump(emu)

cdef bint handle_brfalse_instruction(DotNetEmulator emu): #Good
    cdef StackCell value1 = emu.stack.pop()
    #if its not null then its an object
    if emu.cell_is_false(value1):
        return handle_general_jump(emu)
    return False

cdef bint handle_brtrue_instruction(DotNetEmulator emu): #Good
    cdef StackCell value1 = emu.stack.pop()
    if value1.cell_is_true(value1):
        return handle_general_jump(emu)
    return False

#TODO fix this one for new changes
cdef bint do_call(DotNetEmulator emu, bint is_virt, bint is_newobj, net_row_objects.MethodDef force_method_obj, net_row_objects.TypeDefOrRef force_extern_type, StackCell * force_method_args, int nforce_method_args): #Good
    cdef net_row_objects.MethodDefOrRef method_obj
    cdef net_row_objects.TypeDefOrRef parent_type
    cdef net_row_objects.MethodDef cctor_method
    cdef DotNetEmulator new_emu
    cdef int amt_params
    cdef net_emu_types.DotNetObject dot_obj
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
    cdef net_emu_types.ArrayAddress obj_ref_initial = None
    cdef net_row_objects.TypeSpec tspec = None
    cdef int x = 0
    cdef int params_start = 0
    cdef Py_ssize_t amt_args = 0
    cdef StackCell cell
    cdef StackCell * method_args = NULL
    
    if force_method_obj:
        method_obj = force_method_obj
    else:
        method_obj = <net_row_objects.MethodDefOrRef>emu.instr.get_argument()
        if method_obj.get_table_name() == 'MethodDef' and not method_obj.has_body() and force_extern_type is None:
            if method_obj.get_parent_type():
                parent_type = <net_row_objects.TypeDefOrRef>method_obj.get_parent_type().get_superclass()
                if parent_type:
                    return do_call(emu, is_virt, is_newobj, force_method_obj, parent_type, None)
    if method_obj.get_table_name() == 'MethodDef' and not force_extern_type:
        method_name = method_obj.get_column('Name').get_value_as_bytes()
        amt_params = <int>len(method_obj.get_param_types())
        new_emu = emu.spawn_new_emulator(method_obj, caller=emu)
        if method_obj.method_has_this():
            new_emu._allocate_params(amt_params + 1)
        else:
            new_emu._allocate_params(amt_params)

        if force_method_args == NULL:
            if len(emu.stack) < amt_params:
                raise net_exceptions.EmulatorExecutionException(emu, 'There are not enough items on the stack to execute the instruction')
            if method_obj.method_has_this() or is_newobj:
                params_start = 1
            for x in range(params_start + amt_args - 1, params_start - 1): #len(method_obj.get_param_types()) seems to be inaccurate sometimes.
                cell = emu.stack.pop()
                new_emu._add_param(cell, x)
            if method_obj.method_has_this() and method_name != b'.ctor':
                if len(emu.stack) < 1:
                    raise net_exceptions.EmulatorExecutionException(emu, 'There are not enough items on the stack to execute the instruction')
                cell = emu.stack.pop()
                new_emu._add_param(cell, 0)
        else:
            for x in range(nforce_method_args):
                cell = force_method_args[x]
                new_emu._add_param(cell, x)
        if is_newobj:
            dot_obj = net_emu_types.DotNetObject(emu)
            dot_obj.initialize_type(method_obj.get_parent_type())
            new_emu._add_param(emu.pack_object(dot_obj), 0)
        new_emu.run_function()
        # the handler for ret instruction handles cleaning up the stack after this.
    elif method_obj.get_table_name() == 'MemberRef' or force_extern_type:
        if force_method_args != NULL:
            raise net_exceptions.InvalidArgumentsException()
        if force_extern_type is None and isinstance(method_obj.get_parent_type(), net_row_objects.TypeSpec): #generics etc.
            if isinstance(method_obj.get_parent_type().get_type(), net_row_objects.TypeDef):
                return do_virtcall(emu, force_virtcall=True, force_virt_type=method_obj.get_parent_type().get_type())
        method_name = method_obj.get_column('Name').get_value_as_bytes()
        method_args = list()
        amt_args = <int>len(method_obj.get_param_types())

        push_obj_reference = False
        if not is_newobj and method_obj.method_has_this():
            push_obj_reference = True
        if amt_args != 0:
            method_args = malloc(sizeof(StackCell) * (amt_args))
            if method_args == NULL:
                raise net_exceptions.EmulatorExecutionException(emu, 'error allocating memory for args')
            memset(method_args, 0, amt_args * sizeof(StackCell))

        if len(emu.stack) < amt_args:
            raise net_exceptions.EmulatorExecutionException(emu, 'There are not enough items on the stack to execute the instruction')
        for x in range(amt_args - 1, -1):
            cell = emu.stack.pop()
            memcpy(&method_args[x], &cell, sizeof(cell))
            if cell.tag == CorElementType.ELEMENT_TYPE_OBJECT or cell.tag == CorElementType.ELEMENT_TYPE_STRING:
                if cell.item.ref != NULL:
                    Py_INCREF(cell.item.ref)
        if not is_newobj and push_obj_reference:
            if len(emu.stack) < 1:
                raise net_exceptions.EmulatorExecutionException(emu, 'There are not enough items on the stack to execute the instruction')
            cell = emu.stack.pop() #TODO: left off fixing here. 
            #TODO: for consistency allow boxed values for returns
            if isinstance(obj_ref, net_emu_types.ArrayAddress):
                obj_ref_initial = obj_ref
                obj_ref = obj_ref.get_obj_ref()
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
            elif parent_type is not None and not is_newobj:
                #for calls with ctors, do nothing.  Allocation already happened and for our purposes thats when the Ctor is called.
                return False
            else:
                raise net_exceptions.EmulatorExecutionException(emu, 'Unable to handle token: unknown ctor {} {} {} {}'.format(method_obj.get_full_name(), hex(method_obj.get_token()), hex(parent_type.get_token()), parent_type.get_full_name()))
            if not dot_obj.has_function(method_name):
                raise net_exceptions.EmulatorExecutionException(emu, 'type is missing .ctor')
            
            emu_func = dot_obj.get_function(method_name)
            ret_val = emu_func(dot_obj, method_args) #ctors should always return self.
            if is_newobj:
                if ret_val is not None:
                    ret_val.initialize_type(parent_type)
                emu.stack.append(ret_val)
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
            raise Exception('emu_func == NULL')
        if isinstance(obj_ref, net_emu_types.ArrayAddress):
            raise Exception()
        if static_emu_func != NULL:
            ret_val = static_emu_func(emu.get_appdomain(), method_args)
        else:
            ret_val = emu_func(obj_ref, method_args)
        if obj_ref_initial is not None and obj_ref is not None:
            obj_ref_initial.set_obj_ref(obj_ref)
        if method_obj.has_return_value():
            emu.stack.append(ret_val)
    elif method_obj.get_table_name() == 'MethodSpec':
        return do_call(emu, is_virt, is_newobj, method_obj.get_column('Method').get_value(), None, None)
    else:
        raise net_exceptions.EmulatorMethodNotFoundException(
            str(method_obj))
    return False

cdef bint handle_call_instruction(DotNetEmulator emu): #Good
    return do_call(emu, False, False, None, None, None)

#TODO fix this one for new changes
cdef bint do_virtcall(DotNetEmulator emu, bint force_virtcall=False, net_row_objects.TypeDefOrRef force_virt_type=None) except *: #Good
    cdef net_row_objects.MethodDefOrRef method_obj
    cdef net_row_objects.TypeDefOrRef parent_type
    cdef int amt_args
    cdef net_emu_types.DotNetObject obj_ref
    cdef net_row_objects.TypeDefOrRef obj_type
    cdef net_row_objects.MethodDefOrRef actual_method_obj
    cdef net_sigs.MethodSig initial_method_sig
    cdef net_table_objects.MethodImplTable method_impl_table
    cdef net_row_objects.MethodDef def_method
    cdef net_row_objects.MethodDefOrRef curr_method_obj
    cdef int x = 0
    method_obj = emu.instr.get_argument()
    if not force_virtcall:
        if isinstance(method_obj, net_row_objects.MemberRef) and isinstance(method_obj.get_parent_type(),
                                                                            net_row_objects.TypeRef):
            return do_call(emu, True, False, None, None, None)
        
        if isinstance(method_obj, net_row_objects.MemberRef) and isinstance(method_obj.get_parent_type(), net_row_objects.TypeSpec):
            parent_type = method_obj.get_parent_type()
            if isinstance(parent_type.get_type(), net_row_objects.TypeRef):
                return do_call(emu, True, False, None, parent_type.get_type(), None)

        if isinstance(method_obj, net_row_objects.MethodDef) and method_obj.has_body():
            return do_call(emu, True, False, None, None, None)
    if not force_virt_type:
        amt_args = method_obj.get_amt_params() 
        if method_obj.method_has_this():
            obj_ref = emu.stack[len(emu.stack) - amt_args - 1]
        else:
            obj_ref = emu.stack[len(emu.stack) - amt_args] #technically this shouldnt happen but ill leave it here for now TODO
        obj_type = obj_ref.get_type_obj()
    else:
        obj_type = force_virt_type
    if not obj_type:
        raise net_exceptions.EmulatorTypeNotFoundException(
            'UNKNOWN PARENT TYPE')
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
                    if curr_method_obj.get_column('Name').get_value_as_bytes() == method_obj.get_column('Name').get_value_as_bytes():
                        if curr_method_obj.get_method_signature() == method_obj.get_method_signature():
                            if curr_method_obj.has_body():
                                actual_method_obj = curr_method_obj
                                break
                else:
                    if curr_method_obj.get_column('Name').get_value_as_bytes() == method_obj.get_column('Name').get_value_as_bytes():
                        if curr_method_obj.has_body():
                            actual_method_obj = curr_method_obj
                            break
        else:
            for curr_method_obj in obj_type.get_methods():
                if method_obj.is_hidebysig():
                    if curr_method_obj.get_column('Name').get_value_as_bytes() == method_obj.get_column('Name').get_value_as_bytes():
                        if curr_method_obj.get_method_signature() == method_obj.get_method_signature():
                            if curr_method_obj.has_body() or curr_method_obj.get_table_name() == 'MemberRef':
                                actual_method_obj = curr_method_obj
                                break
                else:
                    if curr_method_obj.get_column('Name').get_value_as_bytes() == method_obj.get_column('Name').get_value_as_bytes():
                        if curr_method_obj.has_body() or curr_method_obj.get_table_name() == 'MemberRef':
                            actual_method_obj = curr_method_obj
                            break
            if not actual_method_obj:
                #Last resort, try treating it as a call with a forced type.  If this doesnt work, it should error.
                return do_call(emu, True, emu.instr.get_opcode() == net_opcodes.Opcodes.Newobj, None, obj_type, None)
            
        if isinstance(obj_type, net_row_objects.TypeDef):
            obj_type = obj_type.get_superclass()
        else:
            break

    if not actual_method_obj:
        raise net_exceptions.EmulatorMethodNotFoundException(
            str(method_obj.get_full_name()))
    return do_call(emu, True, emu.instr.get_opcode() == net_opcodes.Opcodes.Newobj, actual_method_obj, None, None)

cdef bint handle_callvirt_instruction(DotNetEmulator emu): #Good
    return do_virtcall(emu, False, None)

cdef bint handle_ceq_instruction(DotNetEmulator emu): #Good
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell result
    if emu.cell_is_equal(value1, value2):
        result = self.pack_i4(1)
    else:
        result = self.pack_i4(0)
    emu.stack.append(result)
    return False

cdef bint handle_cgt_instruction(DotNetEmulator emu): #Good
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell result
    if emu.cell_is_gt(value1, value2):
        result = emu.pack_i4(1)
    else:
        result = emu.pack_i4(0)
    emu.stack.append(result)
    return False 

cdef bint handle_cgt_un_instruction(DotNetEmulator emu): #Good
    cdef StackCell value2 = emu.convert_unsigned(emu.stack.pop())
    cdef StackCell value1 = emu.convert_unsigned(emu.stack.pop())
    cdef StackCell result

    if emu.cell_is_gt(value1, value2):
        result = emu.pack_i4(1)
    else:
        result = emu.pack_i4(0)
    emu.stack.append(result)
    return False 

cdef bint handle_clt_instruction(DotNetEmulator emu): #Good
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell result

    if emu.cell_is_lt(value1, value2):
        result = emu.pack_i4(1)
    else:
        result = emu.pack_i4(0)
    emu.stack.append(result)
    return False 

cdef bint handle_clt_un_instruction(DotNetEmulator emu): #Good
    cdef StackCell value2 = emu.convert_unsigned(emu.stack.pop())
    cdef StackCell value1 = emu.convert_unsigned(emu.stack.pop())
    cdef StackCell result

    if emu.cell_is_lt(value1, value2):
        result = emu.pack_i4(1)
    else:
        result = emu.pack_i4(0)
    emu.stack.append(result)
    return False 

cdef bint handle_add_instruction(DotNetEmulator emu): #Good
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell result = emu.add_cell(value1, value2)
    emu.stack.append(result)
    return False

cdef bint handle_and_instruction(DotNetEmulator emu): #Good
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell result = emu.and_cell(value1, value2)
    emu.stack.append(result)
    return False

cdef bint handle_conv_i_instruction(DotNetEmulator emu): #Good
    cdef StackCell value1 = emu.stack.pop()
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    value1.tag = CorElementType.ELEMENT_TYPE_I
    emu.stack.append(value1)
    return False

cdef bint handle_conv_i1_instruction(DotNetEmulator emu):
    cdef StackCell value1 = emu.stack.pop()
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    value1.tag = CorElementType.ELEMENT_TYPE_I4
    emu.stack.append(value1)
    return False

cdef bint handle_conv_i2_instruction(DotNetEmulator emu):
    cdef StackCell value1 = emu.stack.pop()
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    value1.tag = CorElementType.ELEMENT_TYPE_I4
    emu.stack.append(value1)
    return False

cdef bint handle_conv_i4_instruction(DotNetEmulator emu):
    cdef StackCell value1 = emu.stack.pop()
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    value1.tag = CorElementType.ELEMENT_TYPE_I4
    emu.stack.append(value1)
    return False

cdef bint handle_conv_i8_instruction(DotNetEmulator emu):
    cdef StackCell value1 = emu.stack.pop()
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    value1.tag = CorElementType.ELEMENT_TYPE_I8
    emu.stack.append(value1)
    return False

cdef bint handle_conv_r4_instruction(DotNetEmulator emu):
    cdef StackCell value1 = emu.stack.pop()
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    value1.tag = CorElementType.ELEMENT_TYPE_R4
    emu.stack.append(value1)
    return False

cdef bint handle_conv_r8_instruction(DotNetEmulator emu):
    cdef StackCell value1 = emu.stack.pop()
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    value1.tag = CorElementType.ELEMENT_TYPE_R8
    emu.stack.append(value1)
    return False

cdef bint handle_conv_r_un_instruction(DotNetEmulator emu):
    cdef StackCell value1 = emu.convert_unsigned(emu.stack.pop())
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    value1.tag = CorElementType.ELEMENT_TYPE_R8
    emu.stack.append(value1)
    return False

cdef bint handle_conv_u_instruction(DotNetEmulator emu):
    cdef StackCell value1 = emu.stack.pop()
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    value1.tag = CorElementType.ELEMENT_TYPE_U
    emu.stack.append(value1)
    return False

cdef bint handle_conv_u1_instruction(DotNetEmulator emu):
    cdef StackCell value1 = emu.stack.pop()
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    value1.tag = CorElementType.ELEMENT_TYPE_U4
    emu.stack.append(value1)
    return False

cdef bint handle_conv_u2_instruction(DotNetEmulator emu):
    cdef StackCell value1 = emu.stack.pop()
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    value1.tag = CorElementType.ELEMENT_TYPE_U4
    emu.stack.append(value1)
    return False

cdef bint handle_conv_u4_instruction(DotNetEmulator emu):
    cdef StackCell value1 = emu.stack.pop()
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    value1.tag = CorElementType.ELEMENT_TYPE_U4
    emu.stack.append(value1)
    return False

cdef bint handle_conv_u8_instruction(DotNetEmulator emu):
    cdef StackCell value1 = emu.stack.pop()
    if value1.tag == CorElementType.ELEMENT_TYPE_BYREF or value1.tag == CorElementType.ELEMENT_TYPE_OBJECT or value1.tag == CorElementType.ELEMENT_TYPE_STRING:
        raise net_exceptions.OperationNotSupportedException()
    value1.tag = CorElementType.ELEMENT_TYPE_U8
    emu.stack.append(value1)
    return False

cdef bint handle_ldarg_instruction(DotNetEmulator emu):
    cdef int number = emu.instr.get_argument()
    if number >= emu.get_num_params():
        raise net_exceptions.EmulatorExecutionException(emu, 'Attempted to ldarg a parameter that isnt in the emulator')
    emu.stack.append(emu.get_method_param(number))
    return False

cdef bint handle_ldarga_instruction(DotNetEmulator emu):
    cdef int number = emu.instr.get_argument()
    cdef StackCell result
    if number >= emu.get_num_params():
        raise net_exceptions.EmulatorExecutionException(emu, 'Attempted to ldarga a parameter that isnt in the emulator')
    result = emu.pack_ref(emu.get_method_param_ptr(number))
    return False


#TODO: need to see how I fix array before I fix ldelem

#FIXME: we may have some typing issues with DotNetNumber when compiled for non 64 bit of python.
cdef bint handle_ldelem_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef uint64_t index_val = index.item.u8
    cdef DotNetArray array_obj = None
    cdef StackCell result
    if not net_utils.is_cortype_number(index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotnetArray):
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
    return False

cdef bint handle_ldelem_i_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef uint64_t index_val = index.item.u8
    cdef DotNetArray array_obj = None
    cdef StackCell result
    if not net_utils.is_cortype_number(index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotnetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetObject>result_obj
    result = array_obj._get_item(index_val)
    if result.tag == CorElementType.ELEMENT_TYPE_END:
        raise net_exceptions.EmulatorExecutionException(emu, 'Error ldelem element')
    if not net_utils.is_cortype_number(result.tag):
        raise net_exceptions.OperationNotSupportedException()
    result.tag = CorElementType.ELEMENT_TYPE_I
    emu.stack.append(result)
    return False

cdef bint handle_ldelem_i1_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef uint64_t index_val = index.item.u8
    cdef DotNetArray array_obj = None
    cdef StackCell result
    if not net_utils.is_cortype_number(index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotnetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetObject>result_obj
    result = array_obj._get_item(index_val)
    if result.tag == CorElementType.ELEMENT_TYPE_END:
        raise net_exceptions.EmulatorExecutionException(emu, 'Error ldelem element')
    if not net_utils.is_cortype_number(result.tag):
        raise net_exceptions.OperationNotSupportedException()
    result.tag = CorElementType.ELEMENT_TYPE_I1
    emu.stack.append(result)
    return False

cdef bint handle_ldelem_u1_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef uint64_t index_val = index.item.u8
    cdef DotNetArray array_obj = None
    cdef StackCell result
    if not net_utils.is_cortype_number(index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotnetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetObject>result_obj
    result = array_obj._get_item(index_val)
    if result.tag == CorElementType.ELEMENT_TYPE_END:
        raise net_exceptions.EmulatorExecutionException(emu, 'Error ldelem element')
    if not net_utils.is_cortype_number(result.tag):
        raise net_exceptions.OperationNotSupportedException()
    result.tag = CorElementType.ELEMENT_TYPE_U1
    emu.stack.append(result)
    return False

cdef bint handle_ldelem_i2_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef uint64_t index_val = index.item.u8
    cdef DotNetArray array_obj = None
    cdef StackCell result
    if not net_utils.is_cortype_number(index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotnetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetObject>result_obj
    result = array_obj._get_item(index_val)
    if result.tag == CorElementType.ELEMENT_TYPE_END:
        raise net_exceptions.EmulatorExecutionException(emu, 'Error ldelem element')
    if not net_utils.is_cortype_number(result.tag):
        raise net_exceptions.OperationNotSupportedException()
    result.tag = CorElementType.ELEMENT_TYPE_I2
    emu.stack.append(result)
    return False

cdef bint handle_ldelem_u2_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef uint64_t index_val = index.item.u8
    cdef DotNetArray array_obj = None
    cdef StackCell result
    if not net_utils.is_cortype_number(index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotnetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetObject>result_obj
    result = array_obj._get_item(index_val)
    if result.tag == CorElementType.ELEMENT_TYPE_END:
        raise net_exceptions.EmulatorExecutionException(emu, 'Error ldelem element')
    if not net_utils.is_cortype_number(result.tag):
        raise net_exceptions.OperationNotSupportedException()
    result.tag = CorElementType.ELEMENT_TYPE_U2
    emu.stack.append(result)
    return False

cdef bint handle_ldelem_i4_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef uint64_t index_val = index.item.u8
    cdef DotNetArray array_obj = None
    cdef StackCell result
    if not net_utils.is_cortype_number(index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotnetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetObject>result_obj
    result = array_obj._get_item(index_val)
    if result.tag == CorElementType.ELEMENT_TYPE_END:
        raise net_exceptions.EmulatorExecutionException(emu, 'Error ldelem element')
    if not net_utils.is_cortype_number(result.tag):
        raise net_exceptions.OperationNotSupportedException()
    result.tag = CorElementType.ELEMENT_TYPE_I4
    emu.stack.append(result)
    return False

cdef bint handle_ldelem_u4_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef uint64_t index_val = index.item.u8
    cdef DotNetArray array_obj = None
    cdef StackCell result
    if not net_utils.is_cortype_number(index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotnetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetObject>result_obj
    result = array_obj._get_item(index_val)
    if result.tag == CorElementType.ELEMENT_TYPE_END:
        raise net_exceptions.EmulatorExecutionException(emu, 'Error ldelem element')
    if not net_utils.is_cortype_number(result.tag):
        raise net_exceptions.OperationNotSupportedException()
    result.tag = CorElementType.ELEMENT_TYPE_U4
    emu.stack.append(result)
    return False

cdef bint handle_ldelem_ref_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef uint64_t index_val = index.item.u8
    cdef DotNetArray array_obj = None
    cdef StackCell * result
    cdef StackCell cell
    if not net_utils.is_cortype_number(index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotnetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetObject>result_obj
    result = array_obj._get_item_ptr(index_val)
    if result == NULL:
        raise net_exceptions.EmulatorExecutionException(emu, 'Error ldelem element')
    cell = emu.pack_ref(result)
    emu.stack.append(cell)
    return False

cdef bint handle_ldelem_i8_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef uint64_t index_val = index.item.u8
    cdef DotNetArray array_obj = None
    cdef StackCell result
    if not net_utils.is_cortype_number(index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotnetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetObject>result_obj
    result = array_obj._get_item(index_val)
    if result.tag == CorElementType.ELEMENT_TYPE_END:
        raise net_exceptions.EmulatorExecutionException(emu, 'Error ldelem element'')
    if not net_utils.is_cortype_number(result.tag):
        raise net_exceptions.OperationNotSupportedException()
    result.tag = CorElementType.ELEMENT_TYPE_I8
    emu.stack.append(result)
    return False

cdef bint handle_ldelem_u8_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef uint64_t index_val = index.item.u8
    cdef DotNetArray array_obj = None
    cdef StackCell result
    if not net_utils.is_cortype_number(index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotnetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetObject>result_obj
    result = array_obj._get_item(index_val)
    if result.tag == CorElementType.ELEMENT_TYPE_END:
        raise net_exceptions.EmulatorExecutionException(emu, 'Error ldelem element'')
    if not net_utils.is_cortype_number(result.tag):
        raise net_exceptions.OperationNotSupportedException()
    result.tag = CorElementType.ELEMENT_TYPE_U8
    emu.stack.append(result)
    return False

cdef bint handle_ldelem_r4_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef uint64_t index_val = index.item.u8
    cdef DotNetArray array_obj = None
    cdef StackCell result
    if not net_utils.is_cortype_number(index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotnetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetObject>result_obj
    result = array_obj._get_item(index_val)
    if result.tag == CorElementType.ELEMENT_TYPE_END:
        raise net_exceptions.EmulatorExecutionException(emu, 'Error ldelem element'')
    if not net_utils.is_cortype_number(result.tag):
        raise net_exceptions.OperationNotSupportedException()
    result.tag = CorElementType.ELEMENT_TYPE_R4
    emu.stack.append(result)
    return False

cdef bint handle_ldelem_r8_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetObject result_obj = None
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef uint64_t index_val = index.item.u8
    cdef DotNetArray array_obj = None
    cdef StackCell result
    if not net_utils.is_cortype_number(index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT or arr.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    
    result_obj = <net_emu_types.DotNetObject> arr.item.ref
    if not isinstance(result_obj, net_emu_types.DotnetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetObject>result_obj
    result = array_obj._get_item(index_val)
    if result.tag == CorElementType.ELEMENT_TYPE_END:
        raise net_exceptions.EmulatorExecutionException(emu, 'Error ldelem element'')
    if not net_utils.is_cortype_number(result.tag):
        raise net_exceptions.OperationNotSupportedException()
    result.tag = CorElementType.ELEMENT_TYPE_R8
    emu.stack.append(result)
    return False

cdef bint handle_ldc_i4_instruction(DotNetEmulator emu):
    cdef StackCell cell = emu.pack_i4(emu.instr.get_argument())
    emu.stack.append(cell)
    return False

cdef bint handle_ldc_i8_instruction(DotNetEmulator emu):
    cdef StackCell cell = emu.pack_i8(emu.instr.get_argument())
    emu.stack.append(cell)
    return False

cdef bint handle_ldc_r4_instruction(DotNetEmulator emu):
    cdef StackCell cell = emu.pack_r4(emu.instr.get_argument())
    emu.stack.append(cell)
    return False

cdef bint handle_ldc_r8_instruction(DotNetEmulator emu):
    cdef StackCell cell = emu.pack_r8(emu.instr.get_argument())
    emu.stack.append(cell)
    return False

cdef bint handle_ldloc_instruction(DotNetEmulator emu):
    cdef int index = emu.instr.get_argument()
    cdef StackCell local_obj = emu.get_local(index)
    emu.stack.append(local_obj)
    return False

cdef bint handle_beq_instruction(DotNetEmulator emu):
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    if emu.cell_is_equal(value1, value2):
        return handle_general_jump(emu)
    return False

cdef bint handle_bge_instruction(DotNetEmulator emu):
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    if emu.cell_is_ge(value1, value2):
        return handle_general_jump(emu)
    return False

cdef bint handle_bge_un_instruction(DotNetEmulator emu):
    cdef StackCell value2 = emu.convert_unsigned(emu.stack.pop())
    cdef StackCell value1 = emu.convert_unsigned(emu.stack.pop())
    if emu.cell_is_ge(value1, value2):
        return handle_general_jump(emu)
    return False

cdef bint handle_bgt_instruction(DotNetEmulator emu):
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    if emu.cell_is_gt(value1, value2):
        return handle_general_jump(emu)
    return False

cdef bint handle_bgt_un_instruction(DotNetEmulator emu):
    handle_cgt_un_instruction(emu)
    return handle_brtrue_instruction(emu)

cdef bint handle_div_instruction(DotNetEmulator emu):
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    emu.stack.append(emu.divide_cell(value1, value2))
    return False

cdef bint handle_dup_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetObject value1 = emu.stack.pop()
    emu.stack.append(value1)
    emu.stack.append(emu.duplicate_cell(value1))
    return False

cdef net_emu_types.DotNetObject do_virt_field_lookup(DotNetEmulator emu, StackCell set_val):
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
    if emu.get_appdomain().has_static_func(ref_obj.get_token()):
        if set_val is not None:
            raise net_exceptions.EmulatorExecutionException(emu, 'Erorr invalid state')
        static_func = emu.get_appdomain().get_static_func(ref_obj.get_token())
        if static_func == NULL:
            raise net_exceptions.EmulatorExecutionException(emu, 'Error NULL ptr for static field ref')
    
        current_obj = static_func(emu.get_appdomain(), [])
    else:
        parent_type = ref_obj.get_parent_type().get_type()
        if parent_type is None:
            return None
        col_val = parent_type.get_column('FieldList')
        if col_val is None:
            return None
        for field_obj in col_val.get_formatted_value():
            if field_obj.get_column('Name').get_value_as_bytes() == ref_obj.get_column('Name').get_value_as_bytes():
                field_sig = field_obj.get_field_signature()
                if field_sig == ref_obj.get_method_signature():
                    cctor_method = parent_type.get_static_constructor()
                    if cctor_method:
                        if emu.executed_cctors.can_execute(cctor_method) and not emu.dont_execute_cctor:
                            new_emu = emu.spawn_new_emulator(cctor_method, caller=emu)
                            new_emu._allocate_params(0)
                            new_emu.run_function()
                    if set_val.tag == CorElementType.ELEMENT_TYPE_END:
                        current_obj = emu.get_appdomain().get_static_field(field_obj.get_rid())
                        return current_obj
                    else:
                        emu.get_appdomain().set_static_field(field_obj.get_rid(), set_val)
                        break
    return current_obj

cdef bint handle_ldsfld_instruction(DotNetEmulator emu):
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
        if current_obj.tag != CorElementType.ELEMENT_TYPE_END:
            raise net_exceptions.OperationNotSupportedException()
        emu.stack.append(current_obj)
    return False

cdef bint handle_ldstr_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetString string_obj = net_emu_types.DotNetString(emu, emu.instr.get_argument(), 'utf-16le')
    emu.stack.append(emu.pack_object(string_obj))
    return False

cdef bint handle_ldtoken_instruction(DotNetEmulator emu):
    cdef net_row_objects.RowObject internal_item = emu.instr.get_argument()
    cdef str table_name = internal_item.get_table_name()
    if table_name == 'MethodDef' or  table_name == 'MethodRef':
        emu.stack.append(emu.pack_object(net_emu_types.DotNetRuntimeMethodHandle(emu, internal_item)))
    elif  table_name == 'Field':
        emu.stack.append(emu.pack_object(net_emu_types.DotNetRuntimeFieldHandle(emu, internal_item)))
    elif table_name == 'TypeDef' or table_name == 'TypeRef' or table_name == 'TypeSpec':
        emu.stack.append(emu.pack_object(net_emu_types.DotNetRuntimeTypeHandle(emu, internal_item)))
    else:
        raise Exception('invalid table {}'.format(table_name)) #Invalid table
    return False

cdef net_row_objects.MethodDef resolve_ref(net_row_objects.MemberRef ref_obj):
    cdef net_sigs.MethodSig ref_sig = ref_obj.get_method_signature()
    cdef net_row_objects.TypeDefOrRef parent_type = ref_obj.get_parent_type().get_type()
    cdef net_row_objects.MethodDef mdef = None
    if not isinstance(parent_type, net_row_objects.TypeDef):
        return None
    for mdef in parent_type.get_methods():
        if mdef.get_column('Name').get_value_as_bytes() == ref_obj.get_column('Name').get_value_as_bytes():
            if mdef.get_method_signature() == ref_sig:
                return mdef
    return None

cdef bint handle_ldftn_instruction(DotNetEmulator emu):
    cdef net_row_objects.RowObject internal_item = emu.instr.get_argument()
    cdef str table_name = internal_item.get_table_name()
    if table_name == 'MethodDef' or  table_name == 'MethodRef':
        emu.stack.append(emu.pack_object(net_emu_types.DotNetRuntimeMethodHandle(emu, internal_item)))
    elif table_name == 'MemberRef':
        internal_item = resolve_ref(internal_item)
        if internal_item is None:
            raise net_exceptions.EmulatorExecutionException(emu, 'Could not find method obj for ldftn')
        emu.stack.append(emu.pack_object(net_emu_types.DotNetRuntimeMethodHandle(emu, internal_item)))
    else:
        raise Exception('invalid table {}'.format(table_name)) #Invalid table
    return False

cdef bint handle_mul_instruction(DotNetEmulator emu):
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    emu.stack.append(emu.cell_multiply(value1, value2))
    return False

cdef bint handle_neg_instruction(DotNetEmulator emu):
    cdef StackCell value1 = emu.stack.pop()
    emu.stack.append(emu.cell_neg(value1))
    return False

cdef bint handle_newarr_instruction(DotNetEmulator emu):
    cdef net_row_objects.TypeDefOrRef type_obj = emu.instr.get_argument()
    cdef StackCell amt_of_elem = emu.stack.pop()
    cdef int64_t elem_val = amt_of_elem.i8
    cdef net_emu_types.DotNetArray value1 = net_emu_types.DotNetArray(emu, elem_val, type_obj)
    emu.stack.append(emu.pack_object(value1))
    return False

cdef bint handle_ble_instruction(DotNetEmulator emu):
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    if emu.cell_is_le(value1, value2):
        return handle_general_jump(emu)
    return False

cdef bint handle_ble_un_instruction(DotNetEmulator emu):
    cdef StackCell value2 = emu.convert_unsigned(emu.stack.pop())
    cdef StackCell value1 = emu.convert_unsigned(emu.stack.pop())
    if emu.cell_is_le(value1, value2):
        return handle_general_jump(emu)
    return False

cdef bint handle_blt_instruction(DotNetEmulator emu):
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    if emu.cell_is_lt(value1, value2):
        return handle_general_jump(emu)
    return False

cdef bint handle_blt_un_instruction(DotNetEmulator emu):
    handle_clt_un_instruction(emu)
    return handle_brtrue_instruction(emu)

cdef bint handle_bne_un_instruction(DotNetEmulator emu):
    handle_ceq_instruction(emu)
    return handle_brfalse_instruction(emu)

cdef bint handle_ldfld_instruction(DotNetEmulator emu):
    cdef net_row_objects.Field field_obj
    cdef StackCell obj_ref = emu.deref_cell(emu.stack.pop())
    cdef net_emu_types.DotNetObject dot_obj = None
    if obj_ref.tag != CorElementType.ELEMENT_TYPE_OBJECT:
        raise net_exceptions.OperationNotSupportedException()
    dot_obj = <net_emu_types.DotNetObject>obj_ref.item.ref
    field_obj = emu.instr.get_argument()
    if field_obj.is_static():
        raise net_exceptions.OperationNotSupportedException()
    emu.stack.append(dot_obj.get_field(field_obj.get_rid()))
    return False

cdef bint handle_or_instruction(DotNetEmulator emu):
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    emu.stack.append(emu.cell_or(value1, value2))
    return False

cdef bint handle_not_instruction(DotNetEmulator emu):
    cdef StackCell value1 = emu.stack.pop()
    emu.stack.append(emu.cell_not(value1))
    return False

cdef bint handle_ret_instruction(DotNetEmulator emu):
    cdef StackCell value1
    if emu.method_obj.has_return_value():
        if emu.caller:
            value1 = emu.stack.pop()
            emu.caller.stack.append(value1)
    else:
        if emu.method_obj.get_column('Name').get_value_as_bytes() == b'.ctor':
            if emu.caller:
                emu.caller.stack.append(emu.get_method_param(0))
    return False

cdef bint handle_shl_instruction(DotNetEmulator emu):
    cdef StackCell bits = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    emu.stack.append(emu.cell_shl(value1, bits))
    return False

cdef bint handle_shr_instruction(DotNetEmulator emu):
    cdef StackCell bits = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    emu.stack.append(emu.cell_shr(value1, bits))
    return False

cdef bint handle_shr_un_instruction(DotNetEmulator emu):
    cdef StackCell bits = emu.convert_unsigned(emu.stack.pop())
    cdef StackCell value1 = emu.convert_unsigned(emu.stack.pop())
    cdef StackCell result = emu.cell_shr(value1, bits)
    emu.stack.append(result)
    return False

cdef bint handle_stfld_instruction(DotNetEmulator emu):
    cdef net_row_objects.Field field_obj = emu.instr.get_argument()
    cdef net_sigs.TypeSig local_type_sig
    cdef net_structs.CorElementType e_type
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell obj_ref = emu.deref_cell(emu.stack.pop())
    cdef net_emu_types.DotNetObject dot_obj = None
    cdef StackCell deref_cell
    if obj_ref.tag != CorElementType.ELEMENT_TYPE_OBJECT or field_obj.is_static():
        raise net_exceptions.OperationNotSupportedException()
    local_type_sig = field_obj.get_field_signature().get_type_sig()
    if obj_ref.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    dot_obj = <net_emu_types.DotNetObject>obj_ref.item.ref
    if isinstance(local_type_sig, net_sigs.CorLibTypeSig):
        e_type = local_type_sig.get_element_type()
        if net_utils.is_cortype_number(e_type):
            value1.tag = e_type
        dot_obj.set_field(field_obj.get_rid(), value1)
    else:
        deref_cell = emu.deref_cell(value1)
        if deref_cell.tag == CorElementType.ELEMENT_TYPE_OBJECT:
            value1.set_type_sig_obj(local_type_sig)
        dot_obj.set_field(field_obj.get_rid(), value1)
    return False

cdef bint handle_stloc_instruction(DotNetEmulator emu):
    cdef int number = emu.instr.get_argument()
    cdef StackCell value1 = emu.stack.pop()
    emu.set_local(number, value1)
    return False

cdef bint handle_stsfld_instruction(DotNetEmulator emu):
    cdef net_row_objects.RowObject field_obj = emu.instr.get_argument()
    cdef StackCell value1 = emu.stack.pop()
    if isinstance(field_obj, net_row_objects.MemberRef):
        do_virt_field_lookup(emu, value1)
    else:
        emu.get_appdomain().set_static_field(field_obj.get_rid(), value1)
    return False

cdef bint handle_sub_instruction(DotNetEmulator emu):
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    emu.stack.append(emu.cell_sub(value1, value2))
    return False

cdef bint handle_switch_instruction(DotNetEmulator emu):
    cdef list targets = emu.instr.get_argument()
    cdef StackCell value1 = emu.stack.pop()
    if value1.item.u4 < len(targets):
        emu.current_offset = targets[value1.item.u4]
        emu.current_eip = emu.disasm_obj.get_instr_index_by_offset(emu.current_offset)
        return True
    else:
        #fallthrough case.  No exception here.
        return False

cdef bint handle_xor_instruction(DotNetEmulator emu):
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    emu.stack.append(emu.cell_xor(value1, value2))
    return False

cdef bint handle_stelem_instruction(DotNetEmulator emu):
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef uint64_t index_val = index.item.u8
    cdef net_emu_types.DotNetArray array_obj = None
    if not net_utils.is_cortype_number(index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT:
        raise net_exceptions.OperationNotSupportedException()
    if not isinstance(<net_emu_types.DotNetObject>arr.item.ref, net_emu_types.DotNetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetArray>arr.item.ref
    array_obj._set_item(index_val, value1)
    return False

cdef bint handle_stelem_i_instruction(DotNetEmulator emu):
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef uint64_t index_val = index.item.u8
    cdef net_emu_types.DotNetArray array_obj = None
    if not net_utils.is_cortype_number(index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT:
        raise net_exceptions.OperationNotSupportedException()
    if not isinstance(<net_emu_types.DotNetObject>arr.item.ref, net_emu_types.DotNetArray) or not net_utils.is_cortype_number(value1.tag):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetArray>arr.item.ref
    value1.tag = CorElementType.ELEMENT_TYPE_I
    array_obj._set_item(index_val, value1)
    return False

cdef bint handle_stelem_i1_instruction(DotNetEmulator emu):
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef uint64_t index_val = index.item.u8
    cdef net_emu_types.DotNetArray array_obj = None
    if not net_utils.is_cortype_number(index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT:
        raise net_exceptions.OperationNotSupportedException()
    if not isinstance(<net_emu_types.DotNetObject>arr.item.ref, net_emu_types.DotNetArray) or not net_utils.is_cortype_number(value1.tag):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetArray>arr.item.ref
    value1.tag = CorElementType.ELEMENT_TYPE_I1
    array_obj._set_item(index_val, value1)
    return False

cdef bint handle_stelem_i2_instruction(DotNetEmulator emu):
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef uint64_t index_val = index.item.u8
    cdef net_emu_types.DotNetArray array_obj = None
    if not net_utils.is_cortype_number(index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT:
        raise net_exceptions.OperationNotSupportedException()
    if not isinstance(<net_emu_types.DotNetObject>arr.item.ref, net_emu_types.DotNetArray) or not net_utils.is_cortype_number(value1.tag):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetArray>arr.item.ref
    value1.tag = CorElementType.ELEMENT_TYPE_I2
    array_obj._set_item(index_val, value1)
    return False

cdef bint handle_stelem_i4_instruction(DotNetEmulator emu):
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef uint64_t index_val = index.item.u8
    cdef net_emu_types.DotNetArray array_obj = None
    if not net_utils.is_cortype_number(index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT:
        raise net_exceptions.OperationNotSupportedException()
    if not isinstance(<net_emu_types.DotNetObject>arr.item.ref, net_emu_types.DotNetArray) or not net_utils.is_cortype_number(value1.tag):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetArray>arr.item.ref
    value1.tag = CorElementType.ELEMENT_TYPE_I4
    array_obj._set_item(index_val, value1)
    return False

cdef bint handle_stelem_i8_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber index = emu.stack.pop()
    cdef net_emu_types.DotNetArray array_obj = emu.stack.pop()
    cdef int64_t index_val = handle_native_int(index)
    value1 = value1.cast(net_structs.CorElementType.ELEMENT_TYPE_I8)
    array_obj[index_val] = value1
    return False

cdef bint handle_stelem_r4_instruction(DotNetEmulator emu):
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef uint64_t index_val = index.item.u8
    cdef net_emu_types.DotNetArray array_obj = None
    if not net_utils.is_cortype_number(index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT:
        raise net_exceptions.OperationNotSupportedException()
    if not isinstance(<net_emu_types.DotNetObject>arr.item.ref, net_emu_types.DotNetArray) or not net_utils.is_cortype_number(value1.tag):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetArray>arr.item.ref
    value1.tag = CorElementType.ELEMENT_TYPE_I8
    array_obj._set_item(index_val, value1)
    return False

cdef bint handle_stelem_r8_instruction(DotNetEmulator emu):
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef uint64_t index_val = index.item.u8
    cdef net_emu_types.DotNetArray array_obj = None
    if not net_utils.is_cortype_number(index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT:
        raise net_exceptions.OperationNotSupportedException()
    if not isinstance(<net_emu_types.DotNetObject>arr.item.ref, net_emu_types.DotNetArray) or not net_utils.is_cortype_number(value1.tag):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetArray>arr.item.ref
    value1.tag = CorElementType.ELEMENT_TYPE_R8 
    array_obj._set_item(index_val, value1)
    return False

cdef bint handle_rem_instruction(DotNetEmulator emu):
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    emu.stack.append(emu.cell_rem(value1, value2))
    return False

cdef bint handle_rem_un_instruction(DotNetEmulator emu):
    cdef StackCell value2 = emu.stack.pop()
    cdef StackCell value1 = emu.stack.pop()
    cdef StackCell result = emu.cell_rem(emu.convert_unsigned(value1), emu.convert_unsigned(value2))
    emu.stack.append(result)
    return False

cdef bint handle_ldelema_instruction(DotNetEmulator emu):
    cdef StackCell index = emu.stack.pop()
    cdef StackCell arr = emu.stack.pop()
    cdef uint64_t idx = index.item.u8
    cdef net_emu_types.DotNetArray array_obj = None
    cdef StackCell * result = NULL
    if not net_utils.is_cortype_number(index.tag) or arr.tag != CorElementType.ELEMENT_TYPE_OBJECT:
        raise net_exceptions.OperationNotSupportedException()

    if arr.item.ref == NULL or not isinstance(<net_emu_types.DotNetObject>arr.item.ref, net_emu_types.DotNetArray):
        raise net_exceptions.OperationNotSupportedException()
    array_obj = <net_emu_types.DotNetArray>arr.item.ref
    result = array_obj._get_item_ptr(idx)
    if result == NULL:
        raise net_exceptions.EmulatorExecutionException(emu, 'invalid ldelema index')
    emu.stack.append(emu.pack_ref(result))
    return False

cdef bint handle_box_instruction(DotNetEmulator emu):
    """
    https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.net_opcodes.Opcodes.box?view=net-8.0
    Honestly im not entirely sure how this should be handled.
    I havent really figured out object references I guess, so for now just going to push the object itself.
    """
    cdef net_row_objects.TypeDefOrRef arg_obj = emu.instr.get_argument()
    cdef StackCell value1 = emu.stack.pop()
    emu.stack.append(emu.box_value(value1))
    return False

cdef bint handle_castclass_instruction(DotNetEmulator emu):
    """cdef net_row_objects.TypeDefOrRef class_type = emu.instr.get_argument()
    cdef net_emu_types.DotNetObject obj_ref = emu.stack.pop()

    obj_ref.initialize_type(class_type) #initialize_type() is handled for ArrayAddress. 
    emu.stack.append(obj_ref)
    return False"""
    raise net_exceptions.FeatureNotImplementedException()

cdef bint handle_initobj_instruction(DotNetEmulator emu):
    cdef net_row_objects.TypeDefOrRef type_obj = emu.instr.get_argument()
    cdef StackCell obj_ref = emu.deref_cell(emu.stack.pop())
    cdef net_emu_types.DotNetObject dot_obj = None
    if obj_ref.tag != CorElementType.ELEMENT_TYPE_OBJECT:
        raise net_exceptions.ObjectTypeException
    dot_obj = <net_emu_types.DotNetObject>obj_ref
    dot_obj.initialize_type(type_obj)
    return False

cdef bint handle_isinst_instruction(DotNetEmulator emu):
    """cdef net_emu_types.DotNetObject value1 = emu.stack.pop()
    cdef net_emu_types.DotNetObject result = None
    if value1.isinst(emu.instr.get_argument()):
        emu.stack.append(value1)
    else:
        result = net_emu_types.DotNetObject(emu)
        result.flag_null()
        emu.stack.append(result)
    return False"""
    raise net_exceptions.FeatureNotImplementedException()

cdef bint handle_ldflda_instruction(DotNetEmulator emu):
    cdef net_row_objects.Field field_obj = emu.instr.get_argument()
    cdef StackCell obj_ref = emu.stack.pop()
    cdef net_emu_types.DotNetObject obj = none
    cdef StackCell * ptr = NULL
    if obj_ref.tag != CorElementType.ELEMENT_TYPE_OBJECT or field_obj.is_static() or obj_ref.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    obj = <net_emu_types.DotNetObject>obj_ref.item.ref
    ptr = obj.get_field_ptr(field_obj.get_rid())
    emu.stack.append(emu.pack_ref(ptr))
    return False

cdef bint handle_ldlen_instruction(DotNetEmulator emu):
    cdef StackCell value_obj = emu.stack.pop()
    cdef net_emu_types.DotNetObject obj = None
    if value_obj.tag != CorElementType.ELEMENT_TYPE_OBJECT or value_obj.item.ref == NULL:
        raise net_exceptions.OperationNotSupportedException()
    obj = <net_emu_types.DotNetObject> value_obj.item.ref
    emu.stack.append(emu.pack_u8(len(obj)))
    return False

cdef bint handle_ldloca_instruction(DotNetEmulator emu):
    cdef int index = emu.instr.get_argument()
    emu.stack.append(emu.pack_ref(emu.get_local_ptr(index)))
    return False

cdef bint handle_ldsflda_instruction(DotNetEmulator emu):
    cdef net_row_objects.MemberRef mref_obj
    cdef net_row_objects.Field field_obj
    cdef net_row_objects.RowObject arg_obj
    cdef StackCell * current_obj = NULL
    cdef list args
    cdef str field_name
    cdef str type_name
    cdef type type_obj
    cdef StackCell cell
    arg_obj = emu.instr.get_argument()
    if isinstance(arg_obj, net_row_objects.MemberRef):
        raise net_exceptions.FeatureNotImplementedException()
    else:
        field_obj = <net_row_objects.Field>arg_obj
        current_obj = emu.get_static_field_ptr(field_obj.get_rid())
        cell = emu.pack_ref(current_obj)
        emu.stack.append(cell)
    return False

cdef bint handle_ldobj_instruction(DotNetEmulator emu):
    cdef StackCell addr_obj = emu.stack.pop()
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    emu.stack.append(*addr_obj.item.byref)
    return False 

cdef bint handle_leave_instruction(DotNetEmulator emu):
    emu.stack.clear()
    return handle_general_jump(emu)

cdef bint handle_starg_instruction(DotNetEmulator emu):
    cdef int number = emu.instr.get_argument()
    cdef StackCell value1 = emu.stack.pop()
    emu._add_param(value1, number)
    return False

cdef bint handle_stobj_instruction(DotNetEmulator emu):
    cdef StackCell value_obj = emu.stack.pop()
    cdef StackCell addr_obj = emu.stack.pop()
    if addr_obj.tag != CorElementType.ELEMENT_TYPE_BYREF:
        raise net_exceptions.OperationNotSupportedException()
    memcpy(addr_obj.byref, &value_obj, sizeof(StackCell)) #TODO: need to check over byref functionality for Py_INCREF and such.
    return False

cdef bint handle_unbox_any_instruction(DotNetEmulator emu):
    cdef StackCell boxed_obj = emu.stack.pop()
    emu.stack.append(emu.unbox_value(boxed_obj))
    return False

cdef bint handle_pop_instruction(DotNetEmulator emu):
    cdef StackCell cell = emu.stack.pop()
    emu.dealloc_cell(cell)
    return False

cdef bint handle_break_instruction(DotNetEmulator emu):
    emu.should_break = True
    return False

cdef bint handle_unsupported_instruction(DotNetEmulator emu):
    raise net_exceptions.InstructionNotSupportedException(emu.instr.get_name())

cdef bint handle_nop_instruction(DotNetEmulator emu):
    return False

cdef bint handle_ldnull_instruction(DotNetEmulator emu):
    emu.stack.append(emu.pack_null())
    return False

cdef bint handle_newobj_instruction(DotNetEmulator emu):
    return do_call(emu, False, True, None, None, None)

"""
A lot of the stuff below is for internal use mainly.
"""

def print_string_threadfn(string: str, fd):
    global tlock
    tlock.acquire()
    print(string)
    tlock.release()

cdef class CctorRegistry:
    def __init__(self):
        self.__executed_cctors = list()

    cpdef bint can_execute(self, net_row_objects.MethodDef method_obj):
        """
        Determine if a cctor was already executed and if not mark it as such.
        """
        if method_obj.get_rid() not in self.__executed_cctors:
            self.__executed_cctors.append(method_obj.get_rid())
            return True
        return False

cdef class EmulatorAppDomain:
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
        self.load_dotnetpe_as_assembly(dpe)
        self.register_static_functions()
        self.__reserve_static_fields()

    cdef int get_amt_static_fields(self):
        return <int>self.__static_fields.size()

    cdef StackCell get_static_field_idx(self, int index):
        return self.__static_fields[index]

    def __dealloc__(self):
        self.clear_static_fields()

    cdef void clear_static_fields(self):
        cdef size_t x = 0
        cdef StackCell cell
        for x in range(self.__static_fields.size()):
            cell = self.__static_fields[x]
            self.get_emulator_obj().dealloc_cell(cell)
        self.__static_fields.clear()

    cdef void __reserve_static_fields(self):
        cdef int amt_fields = 0
        cdef int x = 0
        cdef size_t y = 0
        cdef Py_ssize_t z = 0
        cdef net_row_objects.Field field_obj = None
        cdef StackCell cell
        cdef net_table_objects.TableObject field_table = self.get_emulator_obj().get_method_obj().get_dotnetpe().get_metadata_table('Field')
        for z in range(1, len(field_table) + 1):
            field_obj = field_table.get(z)
            if field_obj.is_static():
                self.__static_field_mappings[field_obj.get_rid()] = x
                cell = self.get_emulator_obj()._get_default_value(field_obj.get_field_signature().get_type_sig())
                self.__static_fields.push_back(cell)
                x += 1
                amt_fields += 1

    cdef void set_static_field(int idno, StackCell cell):
        cdef int actual_index = self.__static_field_mappings[idno]
        cdef StackCell * ptr = &self.__static_fields[actual_index]
        self.dealloc_cell(*ptr)
        memcpy(ptr, &cell, sizeof(cell))
        if cell.tag == CorElementType.ELEMENT_TYPE_OBJECT or cell.tag == CorElementType.ELEMENT_TYPE_STRING:
            if cell.item.ref != NULL:
                Py_INCREF(cell.item.ref)
        ptr.rid = idno

    cdef StackCell * get_static_field_ptr(int idno):
        cdef int actual_index = self.__static_field_mappings[idno]
        cdef StackCell * ptr = &self.__static_fields[actual_index]
        return ptr

    cdef StackCell get_static_field(int idno)
        cdef int actual_index = self.__static_field_mappings[idno]
        return self.__static_fields[actual_index]

    cdef static_func_type get_static_func(self, int token):
        return self.__static_functions[token]

    cdef newobj_func_type get_ctor_func(self, int token):
        return self.__newobj_ctors[token]

    cdef bint has_ctor_func(self, int token):
        return self.__newobj_ctors.count(token) > 0

    cdef bint has_static_func(self, int token):
        return self.__static_functions.count(token) > 0

    cdef void register_static_functions(self):
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
        for x in range(net_emu_types.AMT_OF_TYPES):
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
        
        for x in range(net_emu_types.AMT_OF_STATIC_FUNCTIONS):
            func_mapping = net_emu_types.NET_EMULATE_STATIC_FUNC_REGISTRATIONS[x]
            mapping_name = func_mapping.name[:strlen(func_mapping.name)]
            methods = self.__starter_dpe.get_methods_by_full_name(mapping_name)
            for mref_obj in methods:
                self.__static_functions[mref_obj.get_token()] = func_mapping.func_ptr
        #TODO: Handle the possibility that the static functions represent a field.

    cpdef dotnetpefile.DotNetPeFile get_calling_dotnetpe(self):
        return self.__calling_dotnetpe

    cpdef dotnetpefile.DotNetPeFile get_executing_dotnetpe(self):
        return self.__executing_dotnetpe

    cpdef DotNetEmulator get_current_emulator(self):
        return self.__current_emulator

    cpdef void set_current_emulator(self, DotNetEmulator emulator):
        self.__current_emulator = emulator

    cpdef void set_calling_dotnetpe(self, dotnetpefile.DotNetPeFile dpe):
        self.__calling_dotnetpe = dpe

    cpdef void set_executing_dotnetpe(self, dotnetpefile.DotNetPeFile dpe):
        self.__executing_dotnetpe = dpe

    cpdef EmulatorAppDomain get_current_appdomain(self):
        if self.get_current_emulator() is not None:
            return self.get_current_emulator().get_appdomain()
        return None

    cpdef int get_thread_id(self):
        cdef int curr
        curr = self.__current_thread_num
        self.__current_thread_num += 1
        return curr

    cpdef DotNetEmulator get_emulator_obj(self):
        return self.__emu_obj

    cpdef void add_resource_handler(self, net_row_objects.MethodDefOrRef obj):
        self.__resourceresolve_handlers.append(obj)

    cpdef void add_assembly_handler(self, net_row_objects.MethodDefOrRef obj):
        self.__assemblyresolve_handlers.append(obj)

    cpdef list get_loaded_assemblies(self):
        return self.__loaded_assemblies

    cpdef net_emu_types.DotNetAssembly load_assembly_from_bytes(self, bytes data):
        return self.load_dotnetpe_as_assembly(dotnetpefile.DotNetPeFile(pe_data=data))

    cpdef net_emu_types.DotNetAssembly load_dotnetpe_as_assembly(self, dotnetpefile.DotNetPeFile dpe):
        cdef net_row_objects.RowObject asm_obj = dpe.get_metadata_table('Assembly').get(1)
        cdef net_emu_types.DotNetAssembly result = net_emu_types.DotNetAssembly(self.get_emulator_obj(), asm_obj)
        if len(self.__loaded_assemblies) == 0:
            self.original_assembly = result
        self.__loaded_assemblies.append(result)
        return result

    cpdef net_emu_types.DotNetAssembly get_assembly_by_name(self, net_emu_types.DotNetString name) except *:
        cdef net_emu_types.DotNetAssembly asm_obj
        cdef net_emu_types.DotNetAssemblyName asm_name_obj
        cdef net_emu_types.DotNetString asm_name_str
        cdef net_row_objects.MethodDefOrRef mrefdef_obj
        cdef net_row_objects.MethodDef mdef_obj
        cdef net_emu_types.DotNetResolveEventArgs arg_two
        cdef DotNetEmulator emu_obj
        cdef net_emu_types.DotNetObject result_obj
        #first check the resolve methods, see if we get anything from there.
        for mrefdef_obj in self.__assemblyresolve_handlers:
            if isinstance(mrefdef_obj, net_row_objects.MethodDef):
                mdef_obj = <net_row_objects.MethodDef> mrefdef_obj
                arg_two = net_emu_types.DotNetResolveEventArgs(self.get_emulator_obj())
                arg_two.ctor([name])
                emu_obj = self.get_emulator_obj().spawn_new_emulator(mdef_obj, caller=self)
                emu_obj._allocate_params(2)
                emu_obj._add_param(self.get_emulator_obj().pack_null(), 0)
                emu_obj._add_param(self.pack_object(arg_two), 1)
                emu_obj.run_function()
                result_obj = emu_obj.get_stack().pop()
                if isinstance(result_obj, net_emu_types.DotNetAssembly):
                    return result_obj
        
        for asm_obj in self.__loaded_assemblies:
            asm_name_obj = asm_obj.GetName([])
            asm_name_str = asm_name_obj.get_Name([])
            if asm_name_str == name:
                return asm_obj
        return None

    cpdef bytes get_resource_by_name(self, net_emu_types.DotNetString name, net_emu_types.DotNetAssembly assembly) except *:
        cdef net_emu_types.DotNetAssembly asm_obj
        cdef net_emu_types.DotNetAssemblyName asm_name_obj
        cdef net_emu_types.DotNetString asm_name_str
        cdef net_row_objects.MethodDefOrRef mrefdef_obj
        cdef net_row_objects.MethodDef mdef_obj
        cdef net_emu_types.DotNetResolveEventArgs arg_two
        cdef DotNetEmulator emu_obj
        cdef net_emu_types.DotNetObject result_obj
        cdef bytes rsrc_name = name.get_str_data_as_bytes().decode(name.get_str_encoding()).encode('utf-8')
        cdef bytes result = assembly.get_module().get_dotnetpe().get_resource_by_name(rsrc_name)
        if result is not None:
            return result
        #first check the resolve methods, see if we get anything from there.
        for mrefdef_obj in self.__resourceresolve_handlers: #TODO: Exceptions wont properly show in this, need to fix.
            if isinstance(mrefdef_obj, net_row_objects.MethodDef):
                mdef_obj = <net_row_objects.MethodDef> mrefdef_obj
                arg_two = net_emu_types.DotNetResolveEventArgs(self.get_emulator_obj())
                arg_two.ctor([name])
                emu_obj = self.get_emulator_obj().spawn_new_emulator(mdef_obj, caller=self)
                emu_obj._allocate_params(2)
                emu_obj._add_param(self.pack_null(), 0)
                emu_obj._add_param(self.pack_object(arg_two), 1)
                emu_obj.run_function()
                result_obj = emu_obj.get_stack().pop()
                if isinstance(result_obj, net_emu_types.DotNetAssembly):
                    return (<net_emu_types.DotNetAssembly>result_obj).get_module().get_dotnetpe().get_resource_by_name(rsrc_name)
        return None

cdef class DotNetStack:

    def __init__(self, DotNetEmulator emulator, int max_stack_size):
        self.__emulator = emulator
        self.__max_stack_size = max_stack_size
        self.__internal_stack.reserve(max_stack_size)

    cdef void append(self, StackCell cell):
        cdef StackCell new_cell
        if <unsigned int>self.__internal_stack.size() == <unsigned int>self.__max_stack_size:
            raise net_exceptions.EmulatorExecutionException(self.__emulator, 'violated max_stack_size {} {}'.format(self.__max_stack_size, self.__internal_stack.size()))
        if cell.tag == CorElementType.ELEMENT_TYPE_OBJECT or cell.tag == CorElementType.ELEMENT_TYPE_BYREF or cell.tag == CorElementType.ELEMENT_TYPE_STRING:
            if cell.tag == CorElementType.ELEMENT_TYPE_OBJECT or cell.tag == CorElementType.ELEMENT_TYPE_STRING:
                if cell.item.ref != NULL:
                    Py_INCREF(cell.item.ref)
            self.__internal_stack.push_back(cell)
            return
        new_cell = cell
        if new_cell.tag == CorElementType.ELEMENT_TYPE_U2 or new_cell.tag == CorElementType.ELEMENT_TYPE_CHAR or new_cell.tag == CorElementType.ELEMENT_TYPE_U1:
            new_cell.tag = CorElementType.ELEMENT_TYPE_U4
        elif new_cell.tag == CorElementType.ELEMENT_TYPE_I2 or new_cell.tag == CorElementType.ELEMENT_TYPE_I1:
            new_cell.tag = CorElementType.ELEMENT_TYPE_I4
        self.__internal_stack.push_back(new_cell)

    cdef StackCell pop(self):
        cdef StackCell obj = self.__internal_stack.back()
        self.__internal_stack.pop_back()
        if obj.tag == CorElementType.ELEMENT_TYPE_OBJECT or obj.tag == CorElementType.ELEMENT_TYPE_STRING:
            Py_XDECREF(obj.item.ref) #TODO: Should we be decrefing here if we arent increfing for cell starts?  This may cause the underlying object to go stale.
        return obj

    cpdef StackCell peek(self):
        cdef StackCell obj = self.__internal_stack.back()
        return obj

    cpdef void clear(self):
        cdef size_t i = 0
        cdef StackCell cell
        for i in range(self.__internal_stack.size()):
            cell = self.__internal_stack[i]
            self.dealloc_cell(cell)
        self.__internal_stack.clear()

    def __len__(self) -> int:
        return self.__internal_stack.size()

    def __dealloc__(self):
        self.clear()

cdef class DotNetEmulator:
    """
    This class is capable of emulating most .NET CIL instructions.
    """

    def __init__(self, method_obj, end_method_rid=-1, end_offset=-1, caller=None,
                 break_on_unsupported=False, ignore_security_exceptions=False, dont_execute_cctor=False,
                 force_memory=None, start_offset=0, print_debug_instrs=[],
                 print_debug_rids={}, should_print_callback=None, should_print_callback_param=None, ignore_instrs=list(), app_domain=None, int timeout=-1):
        """
        Initializes a new DotNetEmulator
        :param method_obj: The MethodDef to emulate.
        :param method_params: A list of parameters to pass to the method.
        :param end_offset: Should the emulator end emulation at a specific offset?
        :param caller: Used internally by the call instruction.
        :param break_on_unsupported: 
        """

        if not (isinstance(method_obj, net_row_objects.MethodDef)):
            raise net_exceptions.ObjectTypeException
        
        self.static_fields = dict()
        self.method_obj = method_obj
        if not self.method_obj.has_body():
            print('method obj does not have body')
            raise net_exceptions.InvalidArgumentsException()
        self.disasm_obj = self.method_obj.disassemble_method()
        self.end_offset = end_offset
        self.stack = DotNetStack(self, self.disasm_obj.max_stack)
        self.end_method_rid = end_method_rid
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
        if timeout > 0:
            self.timeout_ns = <uint64_t>(timeout * 1000000000ULL)
        else:
            self.timeout_ns = 0
        self.start_time = 0

    cpdef void setup_method_params(self, list method_params):
        raise net_exceptions.FeatureNotImplementedException()

    cdef void _allocate_params(self, int nparams):
        if self.__method_params != NULL:
            raise net_exceptions.OperationNotSupportedException()
        self.__nparams = nparams
        if nparams == 0:
            return
        self.__method_params = malloc(sizeof(StackCell) * nparams)
        memset(self.__method_params, 0, sizeof(StackCell) * nparams)

    cdef void _add_param(self, StackCell cell, int idx):
        if idx >= self.__nparams:
            raise net_exceptions.OperationNotSupportedException()
        cdef StackCell old = self.__method_params[idx]
        self.dealloc_cell(old) #would do nothing if its ELEMENT_TYPE_END (0)
        memcpy(&self.__method_params, &cell, sizeof(cell))
        if cell.tag == CorElementType.ELEMENT_TYPE_OBJECT or cell.tag == CorElementType.ELEMENT_TYPE_OBJECT:
            if cell.item.ref != NULL:
                Py_INCREF(cell.item.ref)

    cdef StackCell * get_method_param_ptr(self, int idx):
        return &self.__method_params[idx]
    
    cdef StackCell get_method_param(self, int idx):
        return self.__method_params[idx]

    cdef int get_num_params(self):
        return self.__nparams

    cdef bint cell_is_false(self, StackCell cell):
        cdef net_emu_types.DotNetObject obj = None
        if cell.tag == CorElementType.ELEMENT_TYPE_BYREF:
            return self.cell_is_false(*cell.item.byref)
        if cell.tag == CorElementType.ELEMENT_TYPE_STRING or cell.tag == CorElementType.ELEMENT_TYPE_OBJECT:
            if cell.item.ref == NULL:
                return True
            obj = <net_emu_types.DotNetObject>cell.item.ref
            return obj.is_false()
        return cell.item.u8 == 0

    cdef StackCell deref_cell(self, StackCell cell):
        if cell.tag == CorElementType.ELEMENT_TYPE_BYREF:
            return self.deref_cell(*cell.item.byref)
        return cell
    
    cdef bint cell_is_true(self, StackCell cell):
        cdef net_emu_types.DotNetObject obj = None
        if cell.tag == CorElementType.ELEMENT_TYPE_BYREF:
            return self.cell_is_true(*cell.item.byref)
        if cell.tag == CorElementType.ELEMENT_TYPE_STRING or cell.tag == CorElementType.ELEMENT_TYPE_OBJECT:
            if cell.item.ref == NULL:
                return False
            obj = <net_emu_types.DotNetObject>cell.item.ref
            return obj.is_false()
        return cell.item.u8 != 0

    cdef bint cell_is_null(self, StackCell one):
        return one.tag == CorElementType.ELEMENT_TYPE_OBJECT and one.item.ref == NULL

    cdef bint cell_is_equal(self, StackCell one, StackCell two):
        cdef StackCell uone = self.deref_cell(one)
        cdef StackCell utwo = self.deref_cell(two)
        cdef CorElementType type_one = uone.tag
        cdef CorElementType type_two = utwo.tag
        cdef net_emu_types.DotNetObject obj1 = None
        cdef net_emu_types.DotNetObject obj2 = None
        if self.cell_is_null(uone) or self.cell_is_null(utwo):
            if uone.item.tag != utwo.item.tag:
                raise net_exceptions.OperationNotSupportedException()
            return uone.item.ref == utwo.item.ref 
        elif type_one == CorElementType.ELEMENT_TYPE_STRING or type_two == CorElementType.ELEMENT_TYPE_STRING:
            if type_one != type_two:
                return False
            obj1 = <net_emu_types.DotNetObject> uone.item.ref
            obj2 = <net_emu_types.DotNetObject> utwo.item.ref
            return obj1.equals(obj2)
        elif type_one == CorElementType.ELEMENT_TYPE_OBJECT or type_two == CorElementType.ELEMENT_TYPE_OBJECT:
            if type_one != type_two:
                return False
            if self.cell_is_null(uone) or self.cell_is_null(utwo):
                return uone.item.ref == utwo.item.ref
            obj1 = <net_emu_types.DotNetObject> uone.item.ref
            obj2 = <net_emu_types.DotNetObject> utwo.item.ref
            return obj1.equals(obj2)
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
        if cell.tag == CorElementType.ELEMENT_TYPE_OBJECT or cell.tag == CorElementType.ELEMENT_TYPE_STRING:
            Py_XDECREF(cell.ref)
            cell.ref = NULL
        #Ints and such dont need to have anything done

    cdef void pack_blanktag(self):
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        return cell

    cdef StackCell pack_i4(self, int i):
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.tag = CorElementType.ELEMENT_TYPE_I4
        cell.item.i4 = i
        return cell
    
    cdef StackCell pack_u4(self, unsigned int i):
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.tag = CorElementType.ELEMENT_TYPE_U4
        cell.item.u4 = i
        return cell

    cdef StackCell pack_i8(self, int64_t i):
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.tag = CorElementType.ELEMENT_TYPE_I8
        cell.item.i8 = i
        return cell
    
    cdef StackCell pack_u8(self, uint64_t i):
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.tag = CorElementType.ELEMENT_TYPE_U8
        cell.item.u8 = i
        return cell

    cdef StackCell pack_r4(self, float i):
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.tag = CorElementType.ELEMENT_TYPE_R4
        cell.item.r4 = i
        return cell
    
    cdef StackCell pack_r8(self, double i):
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.tag = CorElementType.ELEMENT_TYPE_R8
        cell.item.r8 = i
        return cell

    cdef StackCell pack_object(self, net_emu_types.DotNetObject obj):
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.tag = CorElementType.ELEMENT_TYPE_OBJECT
        cell.item.ref = <PyObject*>obj
        #Dont INCREF here otherwise we have to decref after every stack pop() twice TODO do we need to INCREF here

    cdef StackCell pack_ref(self, StackCell * ptr):
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.tag = CorElementType.ELEMENT_TYPE_BYREF
        cell.item.byref = ptr #TODO: need to make this more like the old model where it fetches the value every time.  Unordered_map ptrs arent reliable
        return cell

    cdef StackCell pack_null(self):
        cdef StackCell cell
        memset(&cell, 0, sizeof(cell))
        cell.tag = CorElementType.ELEMENT_TYPE_OBJECT
        return cell

    cdef StackCell box_value(self, StackCell cell, TypeSig type_sig):
        if cell.tag == CorElementType.ELEMENT_TYPE_OBJECT or ceil.tag == CorElementType.ELEMENT_TYPE_STRING:
            return cell
        if cell.tag == CorElementType.ELEMENT_TYPE_END or cell.tag == CorElementType.ELEMENT_TYPE_BYREF:
            raise net_exceptions.OperationNotSupportedException()
        cdef StackCell result
        cdef net_emu_types.DotNetObject dobj = None
        cdef net_sigs.CorLibTypeSig cor_sig = None
        cdef CorElementType cor_type
        if isinstance(type_sig, net_utils.CorLibTypeSig):
            cor_sig = <net_sigs.CorLibTypeSig>type_sig
            cor_type = cor_sig.get_element_type()
            if cor_type == CorElementType.ELEMENT_TYPE_I:
                dobj = net_emu_types.DotNetIntPtr(self, None)
                if self.__is_64bit:
                    dobj.from_long(cell.item.i8)
                else:
                    dobj.from_int(cell.item.i4)
                return self.pack_object(dobj)
            elif cor_type == CorElementType.ELEMENT_TYPE_U:
                dobj = net_emu_types.DotNetUIntPtr(self, None)
                if self.__is_64bit:
                    dobj.from_ulong(cell.item.u8)
                else:
                    dobj.from_uint(cell.item.u4)
                return self.pack_object(dobj)
            elif cor_type == CorElementType.ELEMENT_TYPE_I1:
                dobj = net_emu_types.DotNetInt8(self, None)
                dobj.from_char(<char>cell.item.i4)
                return dobj
            elif cor_type == CorElementType.ELEMENT_TYPE_U1:
                dobj = net_emu_types.DotNetUInt8(self, None)
                dobj.from_uchar(<unsigned char>cell.item.u4)
                return dobj
            elif cor_type == CorElementType.ELEMENT_TYPE_I2:
                dobj = net_emu_types.DotNetInt16(self, None)
                dobj.from_short(<short>cell.item.i4)
                return dobj
            elif cor_type == CorElementType.ELEMENT_TYPE_U2:
                dobj = net_emu_types.DotNetUInt16(self, None)
                dobj.from_ushort(<unsigned short>cell.item.u4)
                return dobj
            elif cor_type == CorElementType.ELEMENT_TYPE_I4:
                dobj = net_emu_types.DotNetInt32(self, None)
                dobj.from_int(cell.item.i4)
                return dobj
            elif cor_type == CorElementType.ELEMENT_TYPE_U4:
                dobj = net_emu_types.DotNetUInt32(self, None)
                dobj.from_uint(cell.item.u4)
                return dobj
            elif cor_type == CorElementType.ELEMENT_TYPE_I8:
                dobj = net_emu_types.DotNetInt64(self, None)
                dobj.from_long(cell.item.i8)
                return dobj
            elif cor_type == CorElementType.ELEMENT_TYPE_U8:
                dobj = net_emu_types.DotNetUInt64(self, None)
                dobj.from_ulong(cell.item.u8)
                return dobj
            elif cor_type == CorElementType.ELEMENT_TYPE_R4:
                dobj = net_emu_types.DotNetSingle(self, None)
                dobj.from_float(<float>cell.item.r8)
                return dobj
            elif cor_type == CorElementType.ELEMENT_TYPE_R8:
                dobj = net_emu_types.DotNetDouble(self, None)
                dobj.from_double(cell.item.r8)
                return dobj
            elif cor_type == CorElementType.ELEMENT_TYPE_BOOLEAN:
                dobj = net_emu_types.DotNetBoolean(self, None)
                dobj.from_bool(cell.item.b)
                return dobj
            elif cor_type == CorElementType.ELEMENT_TYPE_CHAR:
                dobj = net_emu_types.DotNetChar(self, None)
                dobj.from_ushort(<unsigned short>cell.item.u4)
                return dobj
            else:
                raise net_exceptions.FeatureNotImplementedException()
        raise net_exceptions.FeatureNotImplementedException()

    cdef StackCell unbox_value(self, StackCell cell):
        if cell.tag == CorElementType.ELEMENT_TYPE_BYREF:
            raise net_exceptions.OperationNotSupportedException()
        if cell.tag != CorElementType.ELEMENT_TYPE_OBJECT:
            return cell
        if cell.item.ref == NULL:
            return cell
        cdef net_emu_types.DotNetObject dobj = <net_emu_types.DotNetObject> cell.item.ref
        cdef net_emu_types.DotNetNumber nobj = None
        cdef CorElementType cor_type = CorElementType.ELEMENT_TYPE_END
        cdef StackCell result
        if not dobj.is_number():
            raise net_exceptions.OperationNotSupportedException()
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
        cdef net_emu_types.DotNetObject obj
        cdef unsigned int key = 0
        for key in range(self.localvars.size()):
            Py_XDECREF(self.localvars[key])
        self.localvars.clear()

    cdef bint is_64bit(self):
        return self.__is_64bit

    def set_print_debugging(self, print_debug, print_debug_children, print_debug_instrs=list(), print_debug_offsets=list(), print_debug_methods=list(), print_debug_level=1):
        self.print_debug = print_debug
        self.print_debug_children = print_debug_children
        self.print_debug_instrs = print_debug_instrs
        self.print_debug_offsets = print_debug_offsets
        self.print_debug_methods = print_debug_methods
        self.print_debug_level = print_debug_level

    cpdef DotNetStack get_stack(self):
        """
        Obtain the DotNetStack object associated with this emulator.
        Stacks are per method.  For the most part, DotNetStack operates similar to a python list().
        """
        return self.stack

    cpdef net_row_objects.MethodDefOrRef get_method_obj(self):
        """
        Obtain the method object this emulator is executing.
        """
        return self.method_obj

    cpdef DotNetEmulator get_caller(self):
        """
        Obtain the calling emulator if it exists.
        """
        return self.caller

    cpdef EmulatorAppDomain get_appdomain(self):
        return self.app_domain

    cpdef CctorRegistry get_executed_cctors(self):
        """
        Get the CctorRegistry associated with this execution.
        """
        return self.executed_cctors

    cdef StackCell _get_default_value(self, net_sigs.TypeSig type_sig):
        cdef net_structs.CorElementType element_type
        cdef StackCell result
        cdef net_emu_types.DotNetString string = None
        cdef net_emu_types.DotNetObject new_obj = None
        memset(&result, 0, sizeof(result))
        if isinstance(type_sig, net_sigs.CorLibTypeSig):
            element_type = type_sig.get_element_type()
            if element_type == CorElementType.ELEMENT_TYPE_OBJECT:
                result = self.pack_null()
            elif element_type == CorElementType.ELEMENT_TYPE_STRING
                string = net_emu_types.DotNetString.Empty(self.get_appdomain(), [])
                result = self.pack_object(string)
            else:
                if not (CorElementType.ELEMENT_TYPE_BOOLEAN <= elemnet_type <= CorElementType.ELEMENT_TYPE_R8) and element_type != CorElementType.ELEMENT_TYPE_I and element_type != CorElementType.ELEMENT_TYPE_U:
                    raise net_exceptions.EmulatorExecutionException(self, 'Weird CorLibTypeSig type')
                #Should be mostly limited to numbers here.  We dont need to do anything except set tag.
                result.tag = element_type
        elif isinstance(type_sig, net_sigs.ValueTypeSig):
            # handle System.Enums as a different case
            origclass = type_sig.get_type()
            superclass = origclass
            if superclass.get_full_name() == b'System.Enum':
                result = self.pack_i4(0)
            else:
                superclass = superclass.get_superclass()
                if superclass is not None: # if superclass is NULL, should DotNetNull or DotNetObject be returned?
                    if superclass.get_full_name() == b'System.Enum':
                        result = self.pack_i4(0)
                        return result
                #so for GCHandle even though its a valuetype it cant be instantiated. Only from GCHandle.Alloc().
                new_obj = net_emu_types.DotNetObject(self)
                new_obj.initialize_type(origclass)
                #we can just return a non null .NETObject here I think
                result = self.pack_object(new_obj)
                return result
        else:
            raise Exception('weird sig {}'.format(type(type_sig)))
        return self.pack_null()

    def skip_next_instruction(self):
        self.__skip_next_instruction = True

    def stop_emulator(self):
        self.should_break = True

    cdef void print_string(self, str string, int print_debug_level):
        #threading.Thread(target=print_string_threadfn, args=(string, self.dbg_output_fd)).start()
        if self.print_debug:
            if self.print_debug_level >= print_debug_level or True:
                print(string)

    cpdef net_emu_types.DotNetThread get_current_thread(self):
        return self.running_thread

    cpdef void set_running_thread(self, net_emu_types.DotNetThread thread_obj):
        self.running_thread = thread_obj

    cpdef DotNetEmulator spawn_new_emulator(self, net_row_objects.MethodDef method_obj, int start_offset=0, int end_offset=-1, DotNetEmulator caller=None,
                           int end_method_rid=-1, int end_eip=-1):
        cdef DotNetEmulator new_emu = DotNetEmulator(method_obj, start_offset=start_offset,
                                 end_offset=end_offset, caller=caller, app_domain=self.app_domain)
        """
        Use this method to create a new emulator off an existing one.
        For instance, if you are trying to deobfuscate strings, the usual way to do it would be to emulate some cctor method
        and then use spawn_new_emulator() to create emulator objects each time the string decryption method is emulated.
        """
        new_emu.executed_cctors = self.executed_cctors
        if end_method_rid == -1:
            new_emu.end_method_rid = self.end_method_rid
        else:
            new_emu.end_method_rid = end_method_rid
        new_emu.end_eip = end_eip
        new_emu.start_time = self.start_time
        new_emu.timeout_ns = self.timeout_ns
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
        return new_emu

    cdef str cell_to_str(self, StackCell cell):
        cdef uint64_t * ptr = NULL
        cdef uint64_t ival = 0
        if cell.tag == CorElementType.ELEMENT_TYPE_BYREF:
            return self.print_cell(*cell.byref)
        elif cell.tag == CorElementType.ELEMENT_TYPE_OBJECT or ceil.tag == CorElementType.ELEMENT_TYPE_STRING:
            if ceil.item.ref == NULL:
                return 'null'
            return str(<net_emu_types.DotNetObject>cell.ref)
        else:
            ptr = <uint64_t*>&cell.item
            ival = *ptr
            return hex(ival)

    cpdef void print_current_state(self):
        """
        prints the current state of the emulator.
        """
        cdef state_str = ''
        cdef StackCell value
        cdef unsigned int key = 0
        cdef int idno = 0
        cdef StackCell obj
        cdef net_table_objects.TableObject field_table = self.get_method_obj().get_dotnetpe().get_metadata_table('Field')
        state_str += 'Emulator Method: {}:{} {}\n'.format(self.method_obj.get_table_name(), self.method_obj.get_rid(), self.method_obj.get_token())
        if self.method_obj.method_has_this() and len(self.method_params) >= 1:
            state_str += 'This Object: {}\n'.format(self.cell_to_str(self.method_params[0]))
        state_str += 'Printing static variables:\n'
        if field_table is not None:
            for idno in range(self.get_appdomain().get_amt_static_fields()):
                obj = self.get_static_field_idx(idno)
                state_str += '{}: {} - {}\n'.format(hex(obj.rid), self.cell_to_str(obj), str((<net_row_objects.Field>field_table.get(obj.rid)).get_field_signature().get_type_sig()))
        state_str += 'Printing local vars:\n'
        for key in range(self.localvars.size()):
            value = self.localvars[key]
            state_str += '{}: {} - {}\n'.format(hex(key), self.cell_to_str(value), str(<net_sigs.TypeSig>self.local_var_sigs[key]))
        state_str += 'Printing stack:\n'
        for value in self.stack:
            state_str += '{} - {}\n'.format(self.cell_to_str(value), net_utils.get_cor_type_name(value.tag))
        state_str += 'Last Instruction Execution Time (perf_counter_ns): {}\n'.format(
            self.__last_instr_end - self.__last_instr_start)
        state_str += 'Current EIP: {} Current Offset: {}\n'.format(
            hex(self.current_eip), hex(self.current_offset))
        self.print_string(state_str, 1)

    cdef StackCell get_local(self, int idx):
        return self.localvars[idx]

    cdef StackCell * get_local_ptr(self, int idx):
        return &self.localvars[idx]

    cdef void set_local(self, int idx, StackCell obj):
        cdef StackCell prev_val = self.get_local(idx)
        self.dealloc_cell(prev_val)
        self.localvars[idx] = obj
        if obj.tag == CorElementType.ELEMENT_TYPE_OBJECT or obj.tag == CorElementType.ELEMENT_TYPE_STRING:
            if obj.item.ref != NULL:
                Py_INCREF(obj.item.ref)

    cdef void print_instr(self, net_cil_disas.Instruction instr):            
        if False: #isinstance(self.method_obj, net_emu_types.DotNetDynamicMethod):
            self.print_string('DynamicMethod: Offset={}, Instr={} {}'.format(hex(self.current_offset), instr.get_name(),
                                                                             instr.get_argument()), 1)
        else:
            self.print_string(
                'Emulator={}:{}, Offset={}, Instr={} {}'.format(self.method_obj.get_table_name(), self.method_obj.get_rid(),
                                                                hex(self.current_offset), instr.get_name(),
                                                                instr.get_argument()), 1)

    cdef void initialize_locals(self):
        cdef net_sigs.TypeSig tsig
        cdef int index
        cdef StackCell ref
        for index in range(len(self.disasm_obj.local_types)):
            tsig = self.disasm_obj.local_types[index]
            ref = self._get_default_value(tsig)
            Py_INCREF(tsig)
            self.local_var_sigs.push_back(tsig)
            self.localvars.push_back(ref)

    cpdef void run_function(self) except *:
        """
        Emulates the method until instructed to end.
        """
        cdef bint should_print = False
        cdef bint do_normal_offsets = False
        cdef bint debug_print = False
        cdef DotNetEmulator emu = None
        cdef emu_instr_handler_type emu_instr_handler = NULL
        cdef bint has_timeout = self.timeout_ns > 0
        if self.caller is None and has_timeout:
            self.start_time = _perf_counter_ns()
        self.get_appdomain().set_current_emulator(self)
        self.get_appdomain().set_executing_dotnetpe(self.method_obj.get_dotnetpe())
        self.initialize_locals()
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
            PyErr_CheckSignals()
            self.should_break = False
            self.instr = self.disasm_obj.get_instr_at_offset(self.current_offset)
            if self.instr == None:
                raise net_exceptions.InvalidArgumentsException()
            if self.instr.get_opcode() == net_opcodes.Opcodes.Invalid:
                raise net_exceptions.InstructionNotSupportedException(self.instr.get_name())
            if self.end_offset > 0:
                if self.end_method_rid < 0 or (isinstance(self.method_obj,
                                                          net_row_objects.MethodDef) and self.method_obj.get_rid() == self.end_method_rid):
                    if self.current_offset <= <unsigned int>self.end_offset < (self.current_offset + self.instr.get_instr_size()):
                        raise net_exceptions.EmulatorEndExecutionException(self)

            if (self.print_debug and len(self.print_debug_instrs) == 0) or (self.print_debug and self.instr.get_name() in self.print_debug_instrs):
                self.print_instr(self.instr)

            try:
                if self.print_debug:
                    self.__last_instr_start = _perf_counter_ns()

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
                        print('timing out')
                        raise net_exceptions.EmulatorTimeoutException(self)
            except net_exceptions.InstructionNotSupportedException as e:
                if self.break_on_unsupported:
                    break
                else:
                    if not self.already_init:
                        self.get_appdomain().set_calling_dotnetpe(None)
                    if not self.print_debug:
                        self.print_debug = True
                    self.print_string('Error on method: {}:{} - Offset: {}'.format(self.method_obj,
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
                    self.print_string('Error on method: {}:{} - Offset: {}'.format(self.method_obj,
                                                                                   hex(self.method_obj.get_token()),
                                                                                   hex(self.instr.get_instr_offset())), 1)
                    raise e
            except net_exceptions.TooManyMethodParameters as e:
                raise e
            except Exception as e:
                if not self.print_debug:
                    self.print_debug = True
                self.print_string('Error on method: {}:{} - Offset: {}'.format(self.method_obj,
                                                                               hex(self.method_obj.get_token()),
                                                                               hex(self.instr.get_instr_offset())), 1)
                if not self.already_init:
                    self.get_appdomain().set_calling_dotnetpe(None)
                raise e
            if (self.print_debug and len(self.print_debug_instrs) == 0) or (self.print_debug and self.instr.get_name() in self.print_debug_instrs):
                self.print_current_state()

            if self.instr.get_opcode() == net_opcodes.Opcodes.Ret or self.should_break:
                break

        if not self.already_init:
            self.get_appdomain().set_calling_dotnetpe(None)
        self.cleanup()

    cdef void cleanup(self):
        cdef StackCell obj
        cdef unsigned int key = 0
        for key in range(self.localvars.size()):
            obj = self.localvars[key]
            self.dealloc_cell(obj)
        for key in range(self.local_var_sigs.size()):
            Py_XDECREF(self.local_var_sigs[key])
        self.local_var_sigs.clear()
        self.localvars.clear()
        if self.__method_params != NULL:
            for key in range(<unsigned int>self.__nparams):
                obj = self.__method_params[key]
                self.dealloc_cell(obj)
            free(self.__method_params)
            self.__method_params = NULL