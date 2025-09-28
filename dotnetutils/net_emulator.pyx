#cython: language_level=3
#distutils: language=c++

import threading
from dotnetutils import net_exceptions
from libc.stdint cimport int64_t, uint64_t
from libc.string cimport strlen, strcmp, memset
from dotnetutils cimport net_utils, net_tokens, net_opcodes, net_cil_disas, net_structs, net_row_objects, net_emu_types, net_table_objects, dotnetpefile
from cpython.ref cimport Py_INCREF, Py_XDECREF
from libcpp.utility cimport pair

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
    cdef net_emu_types.ArrayAddress addr_obj = emu.stack.pop()
    cdef net_emu_types.DotNetNumber num_obj = addr_obj.get_obj_ref()
    if not num_obj.is_number():
        raise net_exceptions.InvalidArgumentsException()
    emu.stack.append(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_I))
    return False

cdef bint handle_ldind_i1_instruction(DotNetEmulator emu):
    cdef net_emu_types.ArrayAddress addr_obj = emu.stack.pop()
    cdef net_emu_types.DotNetNumber num_obj = addr_obj.get_obj_ref()
    if not num_obj.is_number():
        raise net_exceptions.InvalidArgumentsException()
    emu.stack.append(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_I1))
    return False

cdef bint handle_ldind_i2_instruction(DotNetEmulator emu):
    cdef net_emu_types.ArrayAddress addr_obj = emu.stack.pop()
    cdef net_emu_types.DotNetNumber num_obj = addr_obj.get_obj_ref()
    if not num_obj.is_number():
        raise net_exceptions.InvalidArgumentsException()
    emu.stack.append(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_I2))
    return False

cdef bint handle_ldind_i4_instruction(DotNetEmulator emu):
    cdef net_emu_types.ArrayAddress addr_obj = emu.stack.pop()
    cdef net_emu_types.DotNetNumber num_obj = addr_obj.get_obj_ref()
    if not num_obj.is_number():
        raise net_exceptions.InvalidArgumentsException()
    emu.stack.append(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_I4))
    return False

cdef bint handle_ldind_i8_instruction(DotNetEmulator emu):
    cdef net_emu_types.ArrayAddress addr_obj = emu.stack.pop()
    cdef net_emu_types.DotNetNumber num_obj = addr_obj.get_obj_ref()
    if not num_obj.is_number():
        raise net_exceptions.InvalidArgumentsException()
    emu.stack.append(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_I8))
    return False

cdef bint handle_ldind_r4_instruction(DotNetEmulator emu):
    cdef net_emu_types.ArrayAddress addr_obj = emu.stack.pop()
    cdef net_emu_types.DotNetNumber num_obj = addr_obj.get_obj_ref()
    if not num_obj.is_number():
        raise net_exceptions.InvalidArgumentsException()
    emu.stack.append(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_R4))
    return False

cdef bint handle_ldind_r8_instruction(DotNetEmulator emu):
    cdef net_emu_types.ArrayAddress addr_obj = emu.stack.pop()
    cdef net_emu_types.DotNetNumber num_obj = addr_obj.get_obj_ref()
    if not num_obj.is_number():
        raise net_exceptions.InvalidArgumentsException()
    emu.stack.append(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_R8))
    return False

cdef bint handle_ldind_ref_instruction(DotNetEmulator emu):
    cdef net_emu_types.ArrayAddress addr_obj = emu.stack.pop()
    cdef net_emu_types.DotNetObject num_obj = addr_obj.get_obj_ref()
    if not isinstance(num_obj, net_emu_types.ArrayAddress):
        raise net_exceptions.InvalidArgumentsException()
    emu.stack.append(num_obj)
    return False

cdef bint handle_ldind_u1_instruction(DotNetEmulator emu):
    cdef net_emu_types.ArrayAddress addr_obj = emu.stack.pop()
    cdef net_emu_types.DotNetNumber num_obj = addr_obj.get_obj_ref()
    if not num_obj.is_number():
        raise net_exceptions.InvalidArgumentsException()
    emu.stack.append(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_U1))
    return False

cdef bint handle_ldind_u2_instruction(DotNetEmulator emu):
    cdef net_emu_types.ArrayAddress addr_obj = emu.stack.pop()
    cdef net_emu_types.DotNetNumber num_obj = addr_obj.get_obj_ref()
    if not num_obj.is_number():
        raise net_exceptions.InvalidArgumentsException()
    emu.stack.append(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_U2))
    return False

cdef bint handle_ldind_u4_instruction(DotNetEmulator emu):
    cdef net_emu_types.ArrayAddress addr_obj = emu.stack.pop()
    cdef net_emu_types.DotNetNumber num_obj = addr_obj.get_obj_ref()
    if not num_obj.is_number():
        raise net_exceptions.InvalidArgumentsException()
    emu.stack.append(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_U4))
    return False

cdef bint handle_br_instruction(DotNetEmulator emu): #Good
    return handle_general_jump(emu)

cdef bint handle_brfalse_instruction(DotNetEmulator emu): #Good
    cdef net_emu_types.DotNetObject value1 = emu.stack.pop()
    #if its not null then its an object
    if value1.is_false():
        return handle_general_jump(emu)
    return False

cdef bint handle_brtrue_instruction(DotNetEmulator emu): #Good
    cdef net_emu_types.DotNetObject value1 = emu.stack.pop()
    if value1.is_true():
        return handle_general_jump(emu)
    return False

cdef bint do_call(DotNetEmulator emu, bint is_virt, bint is_newobj, net_row_objects.MethodDef force_method_obj, net_row_objects.TypeDefOrRef force_extern_type, list force_method_args): #Good
    cdef net_row_objects.MethodDefOrRef method_obj
    cdef net_row_objects.TypeDefOrRef parent_type
    cdef list method_args
    cdef net_row_objects.MethodDef cctor_method
    cdef DotNetEmulator new_emu
    cdef unsigned int amt_params
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
    cdef net_emu_types.DotNetObject obj_ref
    cdef net_emu_types.ArrayAddress obj_ref_initial
    cdef net_row_objects.TypeSpec tspec = None
    cdef unsigned int x = 0
    
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
        method_args = list()
        if method_obj.get_parent_type():
            cctor_method = method_obj.get_parent_type().get_static_constructor()
            #cctor method should always be MethodDef
            if cctor_method and emu.executed_cctors.can_execute(cctor_method):
                if not emu.dont_execute_cctor:
                    new_emu = emu.spawn_new_emulator(cctor_method, method_args, caller=emu)
                    new_emu.run_function()

        #crappy fix for the params issue - use whichever is bigger. #More investigation is definitely needed to fix this.
        #see  d18aa5d58656fffd7a2a0a3d7f6f4e011bf0f39b8f89701b0e5263951e1ce90c methods 1365 and 1404
        params_obj = method_obj.get_column('ParamList')
        amt_params = <unsigned int>len(method_obj.get_param_types())
        if force_method_args is None:
            for x in range(amt_params): #len(method_obj.get_param_types()) seems to be inaccurate sometimes.
                method_args.insert(0, emu.stack.pop())
            if method_obj.method_has_this() and method_obj.get_column('Name').get_value_as_bytes() != b'.ctor':
                method_args.insert(0, emu.stack.pop())
        else:
            method_args = force_method_args
        if is_newobj:
            dot_obj = net_emu_types.DotNetObject(emu)
            dot_obj.initialize_type(method_obj.get_parent_type())
            method_args.insert(0, dot_obj)
        new_emu = emu.spawn_new_emulator(method_obj, method_args, caller=emu)
        new_emu.run_function()
        # the handler for ret instruction handles cleaning up the stack after this.
    elif method_obj.get_table_name() == 'MemberRef' or force_extern_type:
        if force_method_args is not None:
            raise net_exceptions.InvalidArgumentsException()
        if force_extern_type is None and isinstance(method_obj.get_parent_type(), net_row_objects.TypeSpec): #generics etc.
            if isinstance(method_obj.get_parent_type().get_type(), net_row_objects.TypeDef):
                return do_virtcall(emu, force_virtcall=True, force_virt_type=method_obj.get_parent_type().get_type())
        method_name = method_obj.get_column('Name').get_value_as_bytes()
        method_args = list()
        amt_args = len(method_obj.get_param_types())
        push_obj_reference = False
        if method_obj.method_has_this():
            push_obj_reference = True
        for x in range(amt_args):
            method_args.insert(0, emu.stack.pop())
        emu_method = None
        obj_ref_initial = None
        obj_ref = None
        if method_obj.is_static_method():
            if not emu.get_appdomain().has_static_func(method_obj.get_token()):
                raise Exception('unknown static function called {} {}'.format(hex(method_obj.get_token()), method_obj.get_full_name()))
            static_emu_func = emu.get_appdomain().get_static_func(method_obj.get_token())
            dot_obj = None
        elif method_name == b'.ctor' and is_newobj: #newobj instructions only.
            if force_extern_type is None:
                parent_type = method_obj.get_parent_type()
            else:
                parent_type = force_extern_type
            if parent_type is not None and isinstance(parent_type, net_row_objects.TypeSpec):
                tspec = parent_type
                parent_type = tspec.get_type()
            if parent_type is not None and emu.get_appdomain().has_ctor_func(parent_type.get_token()):
                newobj_func = emu.get_appdomain().get_ctor_func(parent_type.get_token())
                dot_obj = newobj_func(emu)
            else:
                raise Exception('Unable to handle token: unknown ctor {} {} {} {}'.format(method_obj.get_full_name(), hex(method_obj.get_token()), hex(parent_type.get_token()), parent_type.get_full_name()))
            if not dot_obj.has_function(method_name):
                raise Exception('type is missing .ctor')
            
            emu_func = dot_obj.get_function(method_name)
            ret_val = emu_func(dot_obj, method_args) #ctors should always return self.
            if is_newobj:
                if ret_val is not None:
                    ret_val.initialize_type(parent_type)
                emu.stack.append(ret_val)
            return False 
        else:
            #static methods are handled so this should only be thiscall methods.
            if push_obj_reference:
                obj_ref = emu.stack.pop()
                if isinstance(obj_ref, net_emu_types.ArrayAddress):
                    obj_ref_initial = obj_ref
                    obj_ref = obj_ref.get_obj_ref()
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

cdef bint do_virtcall(DotNetEmulator emu, bint force_virtcall=False, net_row_objects.TypeDefOrRef force_virt_type=None) except *: #Good
    cdef net_row_objects.MethodDefOrRef method_obj
    cdef net_row_objects.TypeDefOrRef parent_type
    cdef int amt_args
    cdef net_emu_types.DotNetObject obj_ref
    cdef net_row_objects.TypeDefOrRef obj_type
    cdef net_row_objects.MethodDefOrRef actual_method_obj
    cdef net_utils.MethodSig initial_method_sig
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
    cdef net_emu_types.DotNetObject value2 = emu.stack.pop()
    cdef net_emu_types.DotNetObject value1 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber result = net_emu_types.DotNetInt32(emu, None)
    if value1 == value2:
        result.from_int(1)
    else:
        result.init_zero()
    emu.stack.append(result)
    return False

cdef bint handle_cgt_instruction(DotNetEmulator emu): #Good
    cdef net_emu_types.DotNetNumber value2 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    cdef net_emu_types.DotNetInt32 result = net_emu_types.DotNetInt32(emu, None)
    if value1.greaterthan(value2):
        result.from_int(1)
    else:
        result.init_zero()
    emu.stack.append(result)
    return False 

cdef bint handle_cgt_un_instruction(DotNetEmulator emu): #Good
    cdef net_emu_types.DotNetObject value2 = emu.stack.pop()
    cdef net_emu_types.DotNetObject value1 = emu.stack.pop()
    cdef net_emu_types.DotNetInt32 result = net_emu_types.DotNetInt32(emu, None)
    cdef net_emu_types.DotNetNumber num2 = None
    cdef net_emu_types.DotNetNumber num1 = None

    #handle the case where were checking for nulls here.
    if not value1.is_number() and not value2.is_number():
        if value2.is_null() and not value1.is_null():
            result.from_int(1)
        else:
            result.init_zero()
    else:
        num1 = <net_emu_types.DotNetNumber> value1
        num2 = <net_emu_types.DotNetNumber> value2
        if num1.convert_unsigned().greaterthan(num2.convert_unsigned()):
            result.from_int(1)
        else:
            result.init_zero()
    emu.stack.append(result)
    return False 

cdef bint handle_clt_instruction(DotNetEmulator emu): #Good
    cdef net_emu_types.DotNetNumber value2 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    cdef net_emu_types.DotNetInt32 result = net_emu_types.DotNetInt32(emu, None)
    if value1.lessthan(value2):
        result.from_int(1)
    else:
        result.init_zero()
    emu.stack.append(result)
    return False

cdef bint handle_clt_un_instruction(DotNetEmulator emu): #Good
    cdef net_emu_types.DotNetNumber value2 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    cdef net_emu_types.DotNetInt32 result = net_emu_types.DotNetInt32(emu, None)
    if value1.convert_unsigned().lessthan(value2.convert_unsigned()):
        result.from_int(1)
    else:
        result.init_zero()
    emu.stack.append(result)
    return False

cdef bint handle_add_instruction(DotNetEmulator emu): #Good
    cdef net_emu_types.DotNetNumber value2 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber result = value1.add(value2)
    emu.stack.append(result)
    return False

cdef bint handle_and_instruction(DotNetEmulator emu): #Good
    cdef net_emu_types.DotNetNumber value2 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber result = value1.andop(value2)
    emu.stack.append(result)
    return False

cdef bint handle_conv_i_instruction(DotNetEmulator emu): #Good
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    emu.stack.append(value1.cast(net_structs.CorElementType.ELEMENT_TYPE_I))
    return False

cdef bint handle_conv_i1_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop() #Good
    emu.stack.append(value1.cast(net_structs.CorElementType.ELEMENT_TYPE_I1))
    return False

cdef bint handle_conv_i2_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    emu.stack.append(value1.cast(net_structs.CorElementType.ELEMENT_TYPE_I2))
    return False

cdef bint handle_conv_i4_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    emu.stack.append(value1.cast(net_structs.CorElementType.ELEMENT_TYPE_I4))
    return False

cdef bint handle_conv_i8_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    emu.stack.append(value1.cast(net_structs.CorElementType.ELEMENT_TYPE_I8))
    return False

cdef bint handle_conv_r4_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    emu.stack.append(value1.cast(net_structs.CorElementType.ELEMENT_TYPE_R4))
    return False

cdef bint handle_conv_r8_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    emu.stack.append(value1.cast(net_structs.CorElementType.ELEMENT_TYPE_R8))
    return False

cdef bint handle_conv_r_un_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    emu.stack.append(value1.convert_unsigned().cast(net_structs.CorElementType.ELEMENT_TYPE_R8))
    return False

cdef bint handle_conv_u_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    emu.stack.append(value1.cast(net_structs.CorElementType.ELEMENT_TYPE_U))
    return False

cdef bint handle_conv_u1_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    emu.stack.append(value1.cast(net_structs.CorElementType.ELEMENT_TYPE_U1))
    return False

cdef bint handle_conv_u2_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    emu.stack.append(value1.cast(net_structs.CorElementType.ELEMENT_TYPE_U2))
    return False 

cdef bint handle_conv_u4_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    emu.stack.append(value1.cast(net_structs.CorElementType.ELEMENT_TYPE_U4))
    return False 

cdef bint handle_conv_u8_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    emu.stack.append(value1.cast(net_structs.CorElementType.ELEMENT_TYPE_U8))
    return False 

cdef bint handle_ldarg_instruction(DotNetEmulator emu):
    cdef int number = emu.instr.get_argument()
    cdef net_emu_types.DotNetObject obj = emu.method_params[number]
    obj = obj.dereference()
    emu.stack.append(obj)
    return False

cdef bint handle_ldarga_instruction(DotNetEmulator emu):
    cdef int number = emu.instr.get_argument()
    emu.stack.append(net_emu_types.ArrayAddress(emu, None, number, 4))
    return False

#FIXME: we may have some typing issues with DotNetNumber when compiled for non 64 bit of python.
cdef bint handle_ldelem_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetObject result_obj = None
    cdef net_emu_types.DotNetNumber index = emu.stack.pop()
    cdef net_emu_types.DotNetArray array_obj = emu.stack.pop()
    cdef net_emu_types.DotNetNumber num_obj = None
    cdef int64_t index_val = handle_native_int(index)
    result_obj = array_obj[index_val]
    result_obj.initialize_type(emu.instr.get_argument())
    emu.stack.append(result_obj)
    return False

cdef bint handle_ldelem_i_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetArray array_obj
    cdef net_emu_types.DotNetObject result_obj
    cdef net_emu_types.DotNetNumber index = emu.stack.pop()
    cdef net_emu_types.DotNetNumber num_obj = None
    cdef int64_t index_val = handle_native_int(index)
    array_obj = <net_emu_types.DotNetArray>emu.stack.pop()
    num_obj = array_obj[index_val]
    emu.stack.append(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_I))
    return False

cdef bint handle_ldelem_i1_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetArray array_obj
    cdef net_emu_types.DotNetObject result_obj
    cdef net_emu_types.DotNetNumber index = emu.stack.pop()
    cdef net_emu_types.DotNetNumber num_obj = None
    cdef int64_t index_val = handle_native_int(index)
    array_obj = <net_emu_types.DotNetArray>emu.stack.pop()
    num_obj = array_obj[index_val]
    emu.stack.append(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_I1).cast(net_structs.CorElementType.ELEMENT_TYPE_I4))
    return False

cdef bint handle_ldelem_u1_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetArray array_obj
    cdef net_emu_types.DotNetObject result_obj
    cdef net_emu_types.DotNetNumber index = emu.stack.pop()
    cdef net_emu_types.DotNetNumber num_obj = None
    cdef int64_t index_val = handle_native_int(index)
    array_obj = <net_emu_types.DotNetArray>emu.stack.pop()
    num_obj = array_obj[index_val]
    emu.stack.append(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_U1).cast(net_structs.CorElementType.ELEMENT_TYPE_I4))
    return False

cdef bint handle_ldelem_i2_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetArray array_obj
    cdef net_emu_types.DotNetObject result_obj
    cdef net_emu_types.DotNetNumber index = emu.stack.pop()
    cdef net_emu_types.DotNetNumber num_obj = None
    cdef int64_t index_val = handle_native_int(index)
    array_obj = <net_emu_types.DotNetArray>emu.stack.pop()
    num_obj = array_obj[index_val]
    emu.stack.append(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_I2).cast(net_structs.CorElementType.ELEMENT_TYPE_I4))
    return False

cdef bint handle_ldelem_u2_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetArray array_obj
    cdef net_emu_types.DotNetObject result_obj
    cdef net_emu_types.DotNetNumber index = emu.stack.pop()
    cdef net_emu_types.DotNetNumber num_obj = None
    cdef int64_t index_val = handle_native_int(index)
    array_obj = <net_emu_types.DotNetArray>emu.stack.pop()
    num_obj = array_obj[index_val]
    emu.stack.append(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_U2).cast(net_structs.CorElementType.ELEMENT_TYPE_I4))
    return False

cdef bint handle_ldelem_i4_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetArray array_obj
    cdef net_emu_types.DotNetObject result_obj
    cdef net_emu_types.DotNetNumber index = emu.stack.pop()
    cdef net_emu_types.DotNetNumber num_obj = None
    cdef int64_t index_val = handle_native_int(index)
    array_obj = <net_emu_types.DotNetArray>emu.stack.pop()
    num_obj = array_obj[index_val]
    emu.stack.append(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_I4))
    return False

cdef bint handle_ldelem_u4_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetArray array_obj
    cdef net_emu_types.DotNetObject result_obj
    cdef net_emu_types.DotNetNumber index = emu.stack.pop()
    cdef net_emu_types.DotNetNumber num_obj = None
    cdef int64_t index_val = handle_native_int(index)
    array_obj = <net_emu_types.DotNetArray>emu.stack.pop()
    num_obj = array_obj[index_val]
    emu.stack.append(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_U4))
    return False

cdef bint handle_ldelem_ref_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber index = emu.stack.pop()
    cdef net_emu_types.DotNetArray array_obj = <net_emu_types.DotNetArray>emu.stack.pop()
    cdef int64_t index_val = handle_native_int(index)
    emu.stack.append(net_emu_types.ArrayAddress(emu, array_obj, index_val, 0))
    return False

cdef bint handle_ldelem_i8_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetArray array_obj
    cdef net_emu_types.DotNetObject result_obj
    cdef net_emu_types.DotNetNumber index = emu.stack.pop()
    cdef net_emu_types.DotNetNumber num_obj = None
    cdef int64_t index_val = handle_native_int(index)
    array_obj = <net_emu_types.DotNetArray>emu.stack.pop()
    num_obj = array_obj[index_val]
    emu.stack.append(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_I8))
    return False

cdef bint handle_ldelem_u8_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetArray array_obj
    cdef net_emu_types.DotNetObject result_obj
    cdef net_emu_types.DotNetNumber index = emu.stack.pop()
    cdef net_emu_types.DotNetNumber num_obj = None
    cdef int64_t index_val = handle_native_int(index)
    array_obj = <net_emu_types.DotNetArray>emu.stack.pop()
    num_obj = array_obj[index_val]
    emu.stack.append(num_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_U8))
    return False

cdef bint handle_ldelem_r4_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetArray array_obj
    cdef net_emu_types.DotNetObject result_obj
    cdef net_emu_types.DotNetNumber index = emu.stack.pop()
    cdef net_emu_types.DotNetNumber num_obj = None
    cdef int64_t index_val = handle_native_int(index)
    array_obj = <net_emu_types.DotNetArray>emu.stack.pop()
    num_obj = array_obj[index_val]
    emu.stack.append(num_obj.duplicate())
    return False

cdef bint handle_ldelem_r8_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetArray array_obj
    cdef net_emu_types.DotNetObject result_obj
    cdef net_emu_types.DotNetNumber index = emu.stack.pop()
    cdef net_emu_types.DotNetNumber num_obj = None
    cdef int64_t index_val = handle_native_int(index)
    array_obj = <net_emu_types.DotNetArray>emu.stack.pop()
    num_obj = array_obj[index_val]
    emu.stack.append(num_obj.duplicate())
    return False

cdef bint handle_ldc_i4_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetInt32 num = net_emu_types.DotNetInt32(emu, None)
    num.from_int(emu.instr.get_argument())
    emu.stack.append(num)
    return False

cdef bint handle_ldc_i8_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetInt64 num = net_emu_types.DotNetInt64(emu, None)
    num.from_long(emu.instr.get_argument())
    emu.stack.append(num)
    return False

cdef bint handle_ldc_r4_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetSingle num = net_emu_types.DotNetSingle(emu, None)
    num.from_float(emu.instr.get_argument())
    emu.stack.append(num)
    return False

cdef bint handle_ldc_r8_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetDouble num = net_emu_types.DotNetDouble(emu, None)
    num.from_double(emu.instr.get_argument())
    emu.stack.append(num)
    return False

cdef bint handle_ldloc_instruction(DotNetEmulator emu):
    cdef int index = emu.instr.get_argument()
    cdef net_emu_types.DotNetObject local_obj = emu.get_local(index)
    cdef net_emu_types.DotNetNumber num = None
    cdef net_structs.CorElementType num_type = net_structs.CorElementType.ELEMENT_TYPE_VOID
    if local_obj.is_number():
        num = <net_emu_types.DotNetNumber>local_obj
        # extend uint8, uint16, int8, int16
        num_type = num.get_num_type()
        if num_type == net_structs.CorElementType.ELEMENT_TYPE_I1 or num_type == net_structs.CorElementType.ELEMENT_TYPE_I2 or \
            num_type == net_structs.CorElementType.ELEMENT_TYPE_U1 or num_type == net_structs.CorElementType.ELEMENT_TYPE_U2:
            local_obj = num.cast(net_structs.CorElementType.ELEMENT_TYPE_I4)
    emu.stack.append(local_obj)
    return False

cdef bint handle_beq_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetObject value2 = emu.stack.pop()
    cdef net_emu_types.DotNetObject value1 = emu.stack.pop()
    if value1 == value2:
        return handle_general_jump(emu)
    return False

cdef bint handle_bge_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetObject value2 = emu.stack.pop()
    cdef net_emu_types.DotNetObject value1 = emu.stack.pop()
    if value1 >= value2:
        return handle_general_jump(emu)
    return False

cdef bint handle_bge_un_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value2 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    if value1.convert_unsigned().greaterthanequals(value2.convert_unsigned()):
        return handle_general_jump(emu)
    return False

cdef bint handle_bgt_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetObject value2 = emu.stack.pop()
    cdef net_emu_types.DotNetObject value1 = emu.stack.pop()
    if value1 > value2:
        return handle_general_jump(emu)
    return False

cdef bint handle_bgt_un_instruction(DotNetEmulator emu):
    handle_cgt_un_instruction(emu)
    return handle_brtrue_instruction(emu)

cdef bint handle_div_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value2 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    emu.stack.append(value1.divide(value2))
    return False

cdef bint handle_dup_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetObject value1 = emu.stack.pop()
    emu.stack.append(value1)
    emu.stack.append(value1.duplicate())
    return False

cdef net_emu_types.DotNetObject do_virt_field_lookup(DotNetEmulator emu, net_emu_types.DotNetObject set_val):
    cdef net_row_objects.MemberRef ref_obj = emu.instr.get_argument()
    cdef static_func_type static_func = NULL
    cdef net_emu_types.DotNetObject current_obj = None
    cdef net_row_objects.TypeDefOrRef parent_type = None
    cdef net_row_objects.Field field_obj = None
    cdef net_row_objects.Field field_obj2 = None
    cdef net_utils.TypeSig sig_obj = None
    cdef net_row_objects.ColumnValue col_val = None
    cdef DotNetEmulator new_emu = None
    cdef net_row_objects.MethodDef cctor_method = None
    cdef net_utils.FieldSig field_sig = None
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
                            new_emu.run_function()
                    if set_val is None:
                        current_obj = emu.get_static_field(field_obj.get_rid())
                        if current_obj is None:
                            current_obj = emu._get_default_value(field_obj.get_field_signature().get_type_sig())
                            emu.set_static_field(field_obj.get_rid(), current_obj)
                            return current_obj
                        return current_obj
                    else:
                        emu.set_static_field(field_obj.get_rid(), set_val)
                        break
    return current_obj

cdef bint handle_ldsfld_instruction(DotNetEmulator emu):
    cdef net_row_objects.RowObject field_obj # can be either MemberRef or Field
    cdef net_row_objects.TypeDefOrRef parent_type
    cdef net_row_objects.MethodDef cctor_method
    cdef list args
    cdef str field_name
    cdef str type_name
    cdef type type_obj
    cdef net_utils.FieldSig sig
    cdef net_row_objects.Field field
    cdef net_emu_types.DotNetObject current_obj = None
    cdef net_emu_types.DotNetInt32 zero_num = net_emu_types.DotNetInt32(emu, None)
    zero_num.init_zero()
    field_obj = emu.instr.get_argument()
    # check if the cctor has been executed.
    parent_type = field_obj.get_parent_type()
    if isinstance(parent_type, net_row_objects.TypeSpec):
        parent_type = parent_type.get_type()
    cctor_method = parent_type.get_static_constructor()
    if cctor_method:
        if emu.executed_cctors.can_execute(cctor_method) and not emu.dont_execute_cctor:
            new_emu = emu.spawn_new_emulator(cctor_method, caller=emu)
            new_emu.run_function()
    if isinstance(field_obj, net_row_objects.MemberRef):
        current_obj = do_virt_field_lookup(emu, None)
        if current_obj is None:
            raise net_exceptions.EmulatorExecutionException(emu, 'Error with ldsfld virt lookup')
        emu.stack.append(current_obj)
    else:
        if not field_obj.is_static():
            raise net_exceptions.ObjectTypeException
        current_obj = emu.get_static_field(field_obj.get_rid())
        if current_obj is not None:
            emu.stack.append(current_obj)
        else:
            sig = field_obj.get_field_signature()
            if isinstance(sig, net_utils.FieldSig):
                current_obj = emu._get_default_value(sig.get_type_sig())
                emu.set_static_field(field_obj.get_rid(), current_obj)
                emu.stack.append(current_obj)
            else:
                current_obj = zero_num
                emu.set_static_field(field_obj.get_rid(), current_obj)
                emu.stack.append(current_obj)
    return False

cdef bint handle_ldstr_instruction(DotNetEmulator emu):
    emu.stack.append(net_emu_types.DotNetString(emu, emu.instr.get_argument(), 'utf-16le'))
    return False

cdef bint handle_ldtoken_instruction(DotNetEmulator emu):
    cdef net_row_objects.RowObject internal_item = emu.instr.get_argument()
    cdef str table_name = internal_item.get_table_name()
    if table_name == 'MethodDef' or  table_name == 'MethodRef':
        emu.stack.append(net_emu_types.DotNetRuntimeMethodHandle(emu, internal_item))
    elif  table_name == 'Field':
        emu.stack.append(net_emu_types.DotNetRuntimeFieldHandle(emu, internal_item))
    elif table_name == 'TypeDef' or table_name == 'TypeRef':
        emu.stack.append(net_emu_types.DotNetRuntimeTypeHandle(emu, internal_item))
    else:
        raise Exception('invalid table {}'.format(table_name)) #Invalid table
    return False

cdef net_row_objects.MethodDef resolve_ref(net_row_objects.MemberRef ref_obj):
    cdef net_utils.MethodSig ref_sig = ref_obj.get_method_signature()
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
        emu.stack.append(net_emu_types.DotNetRuntimeMethodHandle(emu, internal_item))
    elif table_name == 'MemberRef':
        internal_item = resolve_ref(internal_item)
        if internal_item is None:
            raise net_exceptions.EmulatorExecutionException(emu, 'Could not find method obj for ldftn')
        emu.stack.append(net_emu_types.DotNetRuntimeMethodHandle(emu, internal_item))
    else:
        raise Exception('invalid table {}'.format(table_name)) #Invalid table
    return False

cdef bint handle_mul_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value2 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    emu.stack.append(value1.multiply(value2))
    return False

cdef bint handle_neg_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    emu.stack.append(value1.neg())
    return False

cdef bint handle_newarr_instruction(DotNetEmulator emu):
    cdef net_row_objects.TypeDefOrRef type_obj = emu.instr.get_argument()
    cdef net_emu_types.DotNetNumber amt_of_elem = emu.stack.pop()
    cdef net_structs.CorElementType num_type = amt_of_elem.get_num_type()
    cdef int64_t elem_val = handle_native_int(amt_of_elem)
    cdef net_emu_types.DotNetArray value1 = net_emu_types.DotNetArray(emu, elem_val, type_obj)
    emu.stack.append(value1)
    return False

cdef bint handle_ble_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value2 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    if value1.lessthanequals(value2):
        return handle_general_jump(emu)
    return False

cdef bint handle_ble_un_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value2 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    if value1.convert_unsigned().lessthanequals(value2.convert_unsigned()):
        return handle_general_jump(emu)
    return False

cdef bint handle_blt_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value2 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    if value1.lessthan(value2):
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
    cdef net_emu_types.DotNetObject obj_ref = emu.stack.pop()
    obj_ref = obj_ref.dereference()
    field_obj = emu.instr.get_argument()
    if field_obj.is_static():
        raise net_exceptions.ObjectTypeException

    emu.stack.append(obj_ref.get_field(field_obj.get_rid()))
    return False

cdef bint handle_or_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value2 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    emu.stack.append(value1.orop(value2))
    return False

cdef bint handle_not_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    emu.stack.append(value1.notop())
    return False

cdef bint handle_ret_instruction(DotNetEmulator emu):
    if emu.method_obj.has_return_value():
        if emu.caller:
            value1 = emu.stack.pop()
            emu.caller.stack.append(value1)
    else:
        if emu.method_obj.get_column('Name').get_value_as_bytes() == b'.ctor':
            if emu.caller:
                emu.caller.stack.append(emu.method_params[0])
    return False

cdef bint handle_shl_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber bits = emu.stack.pop()
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    emu.stack.append(value1.shl(bits))
    return False

cdef bint handle_shr_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber bits = emu.stack.pop()
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    emu.stack.append(value1.shr(bits))
    return False

cdef bint handle_shr_un_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber bits = (<net_emu_types.DotNetNumber>emu.stack.pop()).convert_unsigned()
    cdef net_emu_types.DotNetNumber value1 = (<net_emu_types.DotNetNumber>emu.stack.pop()).convert_unsigned()
    cdef net_emu_types.DotNetNumber result = value1.shr(bits)
    emu.stack.append(result)
    return False

cdef bint handle_stfld_instruction(DotNetEmulator emu):
    cdef net_row_objects.Field field_obj
    cdef net_utils.TypeSig local_type_sig
    cdef net_structs.CorElementType e_type
    cdef net_emu_types.DotNetObject value1 = emu.stack.pop()
    cdef net_emu_types.DotNetObject obj_ref = emu.stack.pop()
    cdef net_emu_types.DotNetNumber num = None
    field_obj = emu.instr.get_argument()

    if not isinstance(
        obj_ref, net_emu_types.DotNetObject) or field_obj.is_static():
        raise net_exceptions.ObjectTypeException

    local_type_sig = field_obj.get_field_signature().get_type_sig()
    if isinstance(local_type_sig, net_utils.CorLibTypeSig):
        e_type = local_type_sig.get_element_type()
        if isinstance(value1, net_emu_types.DotNetNumber):
            num = <net_emu_types.DotNetNumber>value1
            obj_ref.set_field(field_obj.get_rid(), num.cast(e_type))
        else:
            obj_ref.set_field(field_obj.get_rid(), value1)
    else:
        if isinstance(value1, net_emu_types.DotNetObject):
            value1.set_type_sig_obj(local_type_sig)
        obj_ref.set_field(field_obj.get_rid(), value1)
    return False

cdef bint handle_stloc_instruction(DotNetEmulator emu):
    cdef int number
    cdef net_utils.TypeSig local_type_sig
    cdef net_structs.CorElementType e_type
    cdef net_emu_types.DotNetObject value1 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber num = None
    number = emu.instr.get_argument()
    local_type_sig = emu.disasm_obj.local_types[number]
    if isinstance(local_type_sig, net_utils.CorLibTypeSig):
        e_type = local_type_sig.get_element_type()
        if value1.is_number():
            num = <net_emu_types.DotNetNumber>value1
            value1 = num.cast(e_type)
        emu.set_local(number, value1)
    else:
        if isinstance(value1, net_emu_types.DotNetObject):
            value1.set_type_sig_obj(local_type_sig)
        emu.set_local(number, value1)
    return False

cdef bint handle_stsfld_instruction(DotNetEmulator emu):
    cdef net_row_objects.RowObject field_obj = emu.instr.get_argument()
    cdef net_emu_types.DotNetObject value1 = emu.stack.pop()
    if isinstance(field_obj, net_row_objects.MemberRef):
        do_virt_field_lookup(emu, value1)
    else:
        emu.set_static_field(field_obj.get_rid(), value1)
    return False

cdef bint handle_sub_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value2 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    emu.stack.append(value1.subtract(value2))
    return False

cdef bint handle_switch_instruction(DotNetEmulator emu):
    cdef list targets = emu.instr.get_argument()
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    value1 = value1.cast(net_structs.CorElementType.ELEMENT_TYPE_U4)
    if value1.as_uint() < len(targets):
        emu.current_offset = targets[value1.as_uint()]
        emu.current_eip = emu.disasm_obj.get_instr_index_by_offset(emu.current_offset)
        return True
    else:
        #fallthrough case.  No exception here.
        return False

cdef bint handle_xor_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value2 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    emu.stack.append(value1.xor(value2))
    return False

cdef bint handle_stelem_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetObject value1 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber index = emu.stack.pop()
    cdef net_emu_types.DotNetArray array_obj = emu.stack.pop()
    cdef int64_t index_val = handle_native_int(index)
    array_obj[index_val] = value1
    return False

cdef bint handle_stelem_i_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber index = emu.stack.pop()
    cdef net_emu_types.DotNetArray array_obj = emu.stack.pop()
    cdef int64_t index_val = handle_native_int(index)
    value1 = value1.cast(net_structs.CorElementType.ELEMENT_TYPE_I)
    array_obj[index_val] = value1
    return False

cdef bint handle_stelem_i1_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber index = emu.stack.pop()
    cdef net_emu_types.DotNetArray array_obj = emu.stack.pop()
    cdef int64_t index_val = handle_native_int(index)
    value1 = value1.cast(net_structs.CorElementType.ELEMENT_TYPE_I1)
    array_obj[index_val] = value1
    return False

cdef bint handle_stelem_i2_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber index = emu.stack.pop()
    cdef net_emu_types.DotNetArray array_obj = emu.stack.pop()
    cdef int64_t index_val = handle_native_int(index)
    value1 = value1.cast(net_structs.CorElementType.ELEMENT_TYPE_I2)
    array_obj[index_val] = value1
    return False

cdef bint handle_stelem_i4_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber index = emu.stack.pop()
    cdef net_emu_types.DotNetArray array_obj = emu.stack.pop()
    cdef int64_t index_val = handle_native_int(index)
    value1 = value1.cast(net_structs.CorElementType.ELEMENT_TYPE_I4)
    array_obj[index_val] = value1
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
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber index = emu.stack.pop()
    cdef net_emu_types.DotNetArray array_obj = emu.stack.pop()
    cdef int64_t index_val = handle_native_int(index)
    value1 = value1.cast(net_structs.CorElementType.ELEMENT_TYPE_R4)
    array_obj[index_val] = value1
    return False

cdef bint handle_stelem_r8_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber index = emu.stack.pop()
    cdef net_emu_types.DotNetArray array_obj = emu.stack.pop()
    cdef int64_t index_val = handle_native_int(index)
    value1 = value1.cast(net_structs.CorElementType.ELEMENT_TYPE_R8)
    array_obj[index_val] = value1
    return False

cdef bint handle_rem_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value2 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    emu.stack.append(value1.rem(value2))
    return False

cdef bint handle_rem_un_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber value2 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber value1 = emu.stack.pop()
    cdef net_emu_types.DotNetNumber result = value1.convert_unsigned().rem(value2.convert_unsigned())
    emu.stack.append(result)
    return False

cdef bint handle_ldelema_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetNumber index = emu.stack.pop()
    cdef net_emu_types.DotNetArray array_obj = emu.stack.pop()
    cdef net_emu_types.DotNetObject obj_ref = None
    cdef int idx = <int>handle_native_int(index) #TODO typing
    emu.stack.append(net_emu_types.ArrayAddress(emu, array_obj, idx, 0))
    return False

cdef bint handle_box_instruction(DotNetEmulator emu):
    """
    https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.net_opcodes.Opcodes.box?view=net-8.0
    Honestly im not entirely sure how this should be handled.
    I havent really figured out object references I guess, so for now just going to push the object itself.
    """
    cdef net_row_objects.TypeDefOrRef arg_obj = emu.instr.get_argument()
    cdef net_emu_types.DotNetObject value1 = emu.stack.pop()
    emu.stack.append(value1)
    return False

cdef bint handle_castclass_instruction(DotNetEmulator emu):
    cdef net_row_objects.TypeDefOrRef class_type
    cdef net_emu_types.DotNetObject obj_ref = emu.stack.pop()
    class_type = emu.instr.get_argument()
    obj_ref.initialize_type(class_type) #initialize_type() is handled for ArrayAddress. 
    emu.stack.append(obj_ref)
    return False

cdef bint handle_initobj_instruction(DotNetEmulator emu):
    cdef net_row_objects.TypeDefOrRef type_obj = emu.instr.get_argument()
    cdef net_emu_types.DotNetObject obj_ref = emu.stack.pop()
    if isinstance(obj_ref, net_emu_types.ArrayAddress):
        if obj_ref.get_obj_ref() is None:
            obj_ref.set_obj_ref(net_emu_types.DotNetObject(emu))
    if not isinstance(obj_ref, net_emu_types.DotNetObject):
        raise net_exceptions.ObjectTypeException
    obj_ref.initialize_type(type_obj)
    return False

cdef bint handle_isinst_instruction(DotNetEmulator emu):
    raise net_exceptions.InstructionNotSupportedException(emu.instr.get_name())
    return False

cdef bint handle_ldflda_instruction(DotNetEmulator emu):
    cdef net_row_objects.Field field_obj
    obj_ref = emu.stack.pop()
    field_obj = emu.instr.get_argument()
    if not isinstance(
        obj_ref, net_emu_types.DotNetObject) or field_obj.is_static():
        raise net_exceptions.ObjectTypeException
    emu.stack.append(net_emu_types.ArrayAddress(emu, obj_ref, field_obj.get_rid(), 1))
    return False

cdef bint handle_ldlen_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetObject value_obj = emu.stack.pop()
    cdef net_emu_types.DotNetUInt64 num = net_emu_types.DotNetUInt64(emu, None)
    num.from_ulong(len(value_obj))
    emu.stack.append(num)
    return False

cdef bint handle_ldloca_instruction(DotNetEmulator emu):
    cdef int index = emu.instr.get_argument()
    cdef net_emu_types.DotNetObject new_obj
    emu.stack.append(net_emu_types.ArrayAddress(emu, None, index, 2))
    return False

cdef bint handle_ldsflda_instruction(DotNetEmulator emu):
    cdef net_row_objects.MemberRef mref_obj
    cdef net_row_objects.Field field_obj
    cdef net_row_objects.RowObject arg_obj
    cdef net_emu_types.DotNetObject current_obj
    cdef list args
    cdef str field_name
    cdef str type_name
    cdef type type_obj
    arg_obj = emu.instr.get_argument()
    if isinstance(arg_obj, net_row_objects.MemberRef):
        raise Exception()
    else:
        field_obj = <net_row_objects.Field>arg_obj
        current_obj = emu.get_static_field(field_obj.get_rid())
        if current_obj is not None:
            emu.stack.append(net_emu_types.ArrayAddress(emu, None, field_obj.get_rid(), 3))
        else:
            current_obj = emu._get_default_value(field_obj.get_field_signature())
            emu.set_static_field(field_obj.get_rid(), current_obj)
            emu.stack.append(net_emu_types.ArrayAddress(emu, None, field_obj.get_rid(), 3))
    return False

cdef bint handle_ldobj_instruction(DotNetEmulator emu):
    cdef net_emu_types.ArrayAddress addr_obj = emu.stack.pop()
    cdef net_emu_types.DotNetObject obj = addr_obj.get_obj_ref()
    cdef net_row_objects.TypeDefOrRef tref = emu.instr.get_argument()
    cdef net_emu_types.DotNetNumber num = None
    if obj.is_number() and tref.get_full_name() == b'System.Byte':
        num = <net_emu_types.DotNetNumber> obj
        num = num.cast(net_structs.CorElementType.ELEMENT_TYPE_U1)
        emu.stack.append(num)
    else:
        emu.stack.append(obj) #TODO: maybe some type handling here
    return False 

cdef bint handle_leave_instruction(DotNetEmulator emu):
    emu.stack.clear()
    return handle_general_jump(emu)

cdef bint handle_starg_instruction(DotNetEmulator emu):
    cdef int number = emu.instr.get_argument()
    cdef net_emu_types.DotNetObject value1 = emu.stack.pop()
    emu.method_params[number] = value1
    return False

cdef bint handle_stobj_instruction(DotNetEmulator emu):
    cdef net_emu_types.ArrayAddress addr_obj
    value_obj = emu.stack.pop()
    addr_obj = emu.stack.pop()
    addr_obj.set_obj_ref(value_obj)
    return False

cdef bint handle_unbox_any_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetObject boxed_obj = emu.stack.pop()
    emu.stack.append(boxed_obj) # box doesnt do anything currently so neither should unbox.
    return False

cdef bint handle_pop_instruction(DotNetEmulator emu):
    emu.stack.pop()
    return False

cdef bint handle_break_instruction(DotNetEmulator emu):
    emu.should_break = True
    return False

cdef bint handle_unsupported_instruction(DotNetEmulator emu):
    raise net_exceptions.InstructionNotSupportedException(emu.instr.get_name())

cdef bint handle_nop_instruction(DotNetEmulator emu):
    return False

cdef bint handle_ldnull_instruction(DotNetEmulator emu):
    cdef net_emu_types.DotNetObject dno = net_emu_types.DotNetObject(emu)
    dno.flag_null()
    emu.stack.append(dno)
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
        cdef net_emu_types.DotNetObject arg_one
        cdef net_emu_types.DotNetResolveEventArgs arg_two
        cdef DotNetEmulator emu_obj
        cdef net_emu_types.DotNetObject result_obj
        #first check the resolve methods, see if we get anything from there.
        for mrefdef_obj in self.__assemblyresolve_handlers:
            if isinstance(mrefdef_obj, net_row_objects.MethodDef):
                mdef_obj = <net_row_objects.MethodDef> mrefdef_obj
                arg_one = net_emu_types.DotNetObject(self.get_emulator_obj()) #Not sure what arg_one actually is supposed to do but for now Null works.
                arg_one.flag_null()
                arg_two = net_emu_types.DotNetResolveEventArgs(self.get_emulator_obj())
                arg_two.ctor([name])
                emu_obj = self.get_emulator_obj().spawn_new_emulator(mdef_obj, method_params=[arg_one, arg_two])
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

    cpdef bytes get_resource_by_name(self, net_emu_types.DotNetString name) except *:
        cdef net_emu_types.DotNetAssembly asm_obj
        cdef net_emu_types.DotNetAssemblyName asm_name_obj
        cdef net_emu_types.DotNetString asm_name_str
        cdef net_row_objects.MethodDefOrRef mrefdef_obj
        cdef net_row_objects.MethodDef mdef_obj
        cdef net_emu_types.DotNetObject arg_one 
        cdef net_emu_types.DotNetResolveEventArgs arg_two
        cdef DotNetEmulator emu_obj
        cdef net_emu_types.DotNetObject result_obj
        cdef bytes rsrc_name = name.get_str_data_as_bytes().decode(name.get_str_encoding()).encode('utf-8')
        cdef bytes result = self.original_assembly.get_module().get_dotnetpe().get_resource_by_name(rsrc_name)
        if result is not None:
            return result
        #first check the resolve methods, see if we get anything from there.
        for mrefdef_obj in self.__resourceresolve_handlers: #TODO: Exceptions wont properly show in this, need to fix.
            if isinstance(mrefdef_obj, net_row_objects.MethodDef):
                mdef_obj = <net_row_objects.MethodDef> mrefdef_obj
                arg_one = net_emu_types.DotNetObject(self.get_emulator_obj()) #Not sure what arg_one actually is supposed to do but for now Null works.
                arg_one.flag_null()
                arg_two = net_emu_types.DotNetResolveEventArgs(self.get_emulator_obj())
                arg_two.ctor([name])
                emu_obj = self.get_emulator_obj().spawn_new_emulator(mdef_obj, method_params=[arg_one, arg_two])
                #emu_obj.set_print_debugging(True, True)
                emu_obj.run_function()
                raise Exception()
                result_obj = emu_obj.get_stack().pop()
                if isinstance(result_obj, net_emu_types.DotNetAssembly):
                    return (<net_emu_types.DotNetAssembly>result_obj).get_module().get_dotnetpe().get_resource_by_name(rsrc_name)
        return None

cdef class DotNetStack:

    def __init__(self, DotNetEmulator emulator, int max_stack_size):
        self.__emulator = emulator
        self.__max_stack_size = max_stack_size
        self.__internal_stack.reserve(max_stack_size)

    cdef void append(self, net_emu_types.DotNetObject obj):
        if <unsigned int>self.__internal_stack.size() == <unsigned int>self.__max_stack_size:
            raise Exception('violated max_stack_size')
        Py_INCREF(obj)
        self.__internal_stack.push_back(<PyObject*>obj)

    cpdef net_emu_types.DotNetObject pop(self):
        cdef PyObject * obj = self.__internal_stack.back()
        self.__internal_stack.pop_back()
        return <net_emu_types.DotNetObject>obj

    cpdef net_emu_types.DotNetObject peek(self):
        cdef PyObject * obj = self.__internal_stack.back()
        return <net_emu_types.DotNetObject>obj

    cpdef void clear(self):
        cdef size_t i = 0
        for i in range(self.__internal_stack.size()):
            Py_XDECREF(self.__internal_stack[i])
        self.__internal_stack.clear()

    def __getitem__(self, Py_ssize_t item):
        if item < 0 or item >= <long int>self.__internal_stack.size():
            raise IndexError('DotNetStack index out of range')
        return <net_emu_types.DotNetObject>self.__internal_stack[item]

    def __len__(self) -> int:
        return self.__internal_stack.size()

    def __dealloc__(self):
        self.clear()

cdef class DotNetEmulator:
    """
    This class is capable of emulating most .NET CIL instructions.
    """

    def __init__(self, method_obj, method_params=None, end_method_rid=-1, end_offset=-1, caller=None,
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
        
        if method_params is None:
            method_params = []
        self.static_fields = dict()
        self.method_obj = method_obj
        if not self.method_obj.has_body():
            print('method obj does not have body')
            raise net_exceptions.InvalidArgumentsException()
        self.disasm_obj = self.method_obj.disassemble_method()
        self.method_params = list(method_params)
        self.end_offset = end_offset
        self.stack = DotNetStack(self, self.disasm_obj.max_stack)
        self.end_method_rid = end_method_rid
        self.executed_cctors = CctorRegistry()
        if start_offset > -1:
            self.current_eip = self.disasm_obj.get_instr_index_by_offset(start_offset)
        self.current_eip = self.disasm_obj.get_instr_at_offset(start_offset).get_instr_index()
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

    def __dealloc__(self):
        cdef net_emu_types.DotNetObject obj
        cdef unsigned int key = 0
        for key in range(self.localvars.size()):
            Py_XDECREF(self.localvars[key])
        self.localvars.clear()
        if self.static_fields is not None:
            self.static_fields.clear()

    cdef bint is_64bit(self):
        return self.__is_64bit

    def set_print_debugging(self, print_debug, print_debug_children, print_debug_instrs=list(), print_debug_offsets=list(), print_debug_methods=list(), print_debug_level=1):
        self.print_debug = print_debug
        self.print_debug_children = print_debug_children
        self.print_debug_instrs = print_debug_instrs
        self.print_debug_offsets = print_debug_offsets
        self.print_debug_methods = print_debug_methods
        self.print_debug_level = print_debug_level

    def get_stack(self):
        """
        Obtain the DotNetStack object associated with this emulator.
        Stacks are per method.  For the most part, DotNetStack operates similar to a python list().
        """
        return self.stack

    def get_method_obj(self):
        """
        Obtain the method object this emulator is executing.
        """
        return self.method_obj

    def get_caller(self):
        """
        Obtain the calling emulator if it exists.
        """
        return self.caller

    cpdef EmulatorAppDomain get_appdomain(self):
        return self.app_domain

    cpdef net_emu_types.DotNetObject get_static_field(self, int idno):
        """
        Obtain a static field from the emulator by id number.
        """
        if idno not in self.static_fields:
            return None
        return <net_emu_types.DotNetObject>self.static_fields[idno]

    cpdef CctorRegistry get_executed_cctors(self):
        """
        Get the CctorRegistry associated with this execution.
        """
        return self.executed_cctors

    cpdef void set_static_field(self, int idno, net_emu_types.DotNetObject val):
        self.static_fields[idno] = val

    cdef net_emu_types.DotNetObject _get_default_value(self, net_utils.TypeSig type_sig):
        cdef net_structs.CorElementType element_type
        cdef net_row_objects.TypeDefOrRef superclass = None
        cdef net_row_objects.TypeDefOrRef origclass = None
        cdef net_emu_types.DotNetObject new_obj
        cdef net_emu_types.DotNetNumber num = None
        if isinstance(type_sig, net_utils.CorLibTypeSig):
            element_type = type_sig.get_element_type()
            if element_type == net_structs.CorElementType.ELEMENT_TYPE_I:
                num = net_emu_types.DotNetIntPtr(self, None)
            elif element_type == net_structs.CorElementType.ELEMENT_TYPE_I1:
                num = net_emu_types.DotNetInt8(self, None)
            elif element_type == net_structs.CorElementType.ELEMENT_TYPE_I2:
                num = net_emu_types.DotNetInt16(self, None)
            elif element_type == net_structs.CorElementType.ELEMENT_TYPE_I4:
                num = net_emu_types.DotNetInt32(self, None)
            elif element_type == net_structs.CorElementType.ELEMENT_TYPE_I8:
                num = net_emu_types.DotNetInt64(self, None)
            elif element_type == net_structs.CorElementType.ELEMENT_TYPE_U:
                num = net_emu_types.DotNetUIntPtr(self, None)
            elif element_type == net_structs.CorElementType.ELEMENT_TYPE_U1:
                num = net_emu_types.DotNetUInt8(self, None)
            elif element_type == net_structs.CorElementType.ELEMENT_TYPE_U2:
                num = net_emu_types.DotNetUInt16(self, None)
            elif element_type == net_structs.CorElementType.ELEMENT_TYPE_U4:
                num = net_emu_types.DotNetUInt32(self, None)
            elif element_type == net_structs.CorElementType.ELEMENT_TYPE_U8:
                num = net_emu_types.DotNetUInt64(self, None)
            if num != None:
                num.init_zero()
                return num
        elif isinstance(type_sig, net_utils.ValueTypeSig):
            # handle System.Enums as a different case
            origclass = type_sig.get_type()
            superclass = origclass
            if superclass.get_full_name() == b'System.Enum':
                num = net_emu_types.DotNetInt32(self, None)
                num.init_zero()
                return num
            else:
                superclass = superclass.get_superclass()
                if superclass != None: # if superclass is NULL, should DotNetNull or DotNetObject be returned?
                    if superclass.get_full_name() == b'System.Enum':
                        num = net_emu_types.DotNetInt32(self, None)
                        num.init_zero()
                        return num
                #so for GCHandle even though its a valuetype it cant be instantiated. Only from GCHandle.Alloc().
                new_obj = net_emu_types.DotNetObject(self)
                new_obj.initialize_type(origclass)
                #we can just return a non null .NETObject here I think
                return new_obj
        new_obj = net_emu_types.DotNetObject(self)
        new_obj.flag_null()
        return new_obj

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

    cpdef DotNetEmulator spawn_new_emulator(self, net_row_objects.MethodDef method_obj, list method_params=[], int start_offset=0, int end_offset=-1, DotNetEmulator caller=None,
                           int end_method_rid=0, int end_eip=-1):
        cdef DotNetEmulator new_emu = DotNetEmulator(method_obj, method_params=method_params, start_offset=start_offset,
                                 end_offset=end_offset, caller=caller, app_domain=self.app_domain)
        """
        Use this method to create a new emulator off an existing one.
        For instance, if you are trying to deobfuscate strings, the usual way to do it would be to emulate some cctor method
        and then use spawn_new_emulator() to create emulator objects each time the string decryption method is emulated.
        """
        new_emu.static_fields = self.static_fields            
        new_emu.executed_cctors = self.executed_cctors
        new_emu.end_method_rid = end_method_rid
        new_emu.end_eip = end_eip
        new_emu.start_time = self.start_time
        new_emu.timeout_ns = self.timeout_ns
        new_emu.print_debug_children = self.print_debug_children
        if self.print_debug_children:
            new_emu.print_debug = self.print_debug
        new_emu.ignore_security_exceptions = self.ignore_security_exceptions
        new_emu.break_on_unsupported = self.break_on_unsupported
        if self.end_offset > 0 and self.end_method_rid > 0:
            new_emu.end_offset = self.end_offset
            new_emu.end_method_rid = self.end_method_rid
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

    cpdef void print_current_state(self):
        """
        prints the current state of the emulator.
        """
        cdef state_str = ''
        cdef net_emu_types.DotNetObject value = None
        cdef unsigned int key = 0
        cdef int idno = 0
        cdef net_emu_types.DotNetObject obj = None
        if isinstance(self.method_obj, net_row_objects.MethodDef):
            state_str += 'Emulator Method: {}:{}\n'.format(self.method_obj.get_table_name(), self.method_obj.get_rid())
        else:
            state_str += 'Emulator Method: DynamicMethod\n'
        state_str += 'Method Params: {}\n'.format(self.method_params)
        if self.method_obj.method_has_this() and len(self.method_params) >= 1:
            state_str += 'This Object: {}\n'.format(str(self.method_params[0]))
        state_str += 'Printing static variables:\n'
        for idno, obj in self.static_fields.items():
            state_str += '{}: {} - {}\n'.format(hex(idno), str(obj), type(obj))
        state_str += 'Printing local vars:\n'
        for key in range(self.localvars.size()):
            value = <net_emu_types.DotNetObject>self.localvars[key]
            state_str += '{}: {} - {}\n'.format(hex(key), str(value), type(value))
        state_str += 'Printing stack:\n'
        for value in self.stack:
            state_str += '{} - {}\n'.format(str(value), type(value))

        state_str += 'Last Instruction Execution Time (perf_counter_ns): {}\n'.format(
            self.__last_instr_end - self.__last_instr_start)
        state_str += 'Current EIP: {} Current Offset: {}\n'.format(
            hex(self.current_eip), hex(self.current_offset))
        self.print_string(state_str, 1)

    cpdef net_emu_types.DotNetObject get_local(self, int idx):
        return <net_emu_types.DotNetObject>self.localvars[idx]

    cdef void set_local(self, int idx, net_emu_types.DotNetObject obj):
        Py_INCREF(obj)
        Py_XDECREF(self.localvars[idx])
        self.localvars[idx] = <PyObject*>obj

    def print_full_array(self, id_no, is_static):
        if is_static:
            array_obj = self.get_static_field(id_no)
        else:
            array_obj = self.get_local(id_no)

        if isinstance(array_obj.internal_array, bytearray) or isinstance(array_obj.internal_array, bytes):
            array_str = str(list(array_obj.internal_array))
        else:
            array_str = str(array_obj.internal_array)

        self.print_string(array_str, 1)

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
        cdef net_utils.TypeSig tsig
        cdef int index
        cdef net_emu_types.DotNetObject ref = None
        for index in range(len(self.disasm_obj.local_types)):
            tsig = self.disasm_obj.local_types[index]
            ref = self._get_default_value(tsig)
            Py_INCREF(ref)
            self.localvars.push_back(<PyObject*>ref)

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