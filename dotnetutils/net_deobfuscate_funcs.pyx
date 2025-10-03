#cython: language_level=3
#distutils: language=c++

import os

from dotnetutils cimport dotnetpefile, net_tokens, net_row_objects, net_emulator, net_cil_disas, net_processing
from dotnetutils cimport net_opcodes, net_table_objects, net_structs, net_emu_types, net_sigs
from dotnetutils import net_graphing, net_exceptions
from libc.stdio cimport snprintf
from libc.string cimport memcpy
from cpython.bytes cimport PyBytes_FromStringAndSize, PyBytes_AS_STRING, PyBytes_GET_SIZE, _PyBytes_Resize
from cpython.ref cimport PyObject

cdef bytes make_string(bytes prefix, unsigned int i):
    cdef Py_ssize_t plen = PyBytes_GET_SIZE(prefix)
    cdef char* pp = PyBytes_AS_STRING(prefix)

    cdef char tmp[11]  # Enough for 10 digits + null
    cdef int d = snprintf(tmp, sizeof(tmp), "%u", i)
    if d < 0 or d >= 11:
        raise net_exceptions.DotNetUtilsException()

    cdef bytes out = PyBytes_FromStringAndSize(NULL, plen + d)
    cdef char* dst = PyBytes_AS_STRING(out)
    memcpy(dst, pp, <size_t>plen)
    memcpy(dst + plen, tmp, <size_t>d)
    return out

"""
This file contains various functions for removing different types of obfuscation
Commonly seen in obfuscated .Net samples.
"""
cdef void remove_unk_obf_1_junk_loops(dotnetpefile.DotNetPeFile dotnet):
    """
    Intended to remove stuff like this:
        /* 0x0001B542 280900000A   */ IL_06BE: call      valuetype [mscorlib]System.DateTime [mscorlib]System.DateTime::get_Now()
        /* 0x0001B547 136F         */ IL_06C3: stloc.s   V_111
        /* 0x0001B549 126F         */ IL_06C5: ldloca.s  V_111
        /* 0x0001B54B 280A00000A   */ IL_06C7: call      instance int64 [mscorlib]System.DateTime::get_Ticks()
        /* 0x0001B550 20079997FF   */ IL_06CC: ldc.i4    -6842105
        /* 0x0001B555 6A           */ IL_06D1: conv.i8
        /* 0x0001B556 FE01         */ IL_06D2: ceq
        /* 0x0001B558 136E         */ IL_06D4: stloc.s   V_110
        /* 0x0001B55A 116E         */ IL_06D6: ldloc.s   V_110
        /* 0x0001B55C 3AECFCFFFF   */ IL_06D8: brtrue    IL_03C9

        while (DateTime.Now.Ticks == -6842105L)
        {
            Console.WriteLine(-5323106);
            Console.ReadLine();
            Environment.Exit(93952);
        }

        Another example:

        /* 0x000002D3 280900000A   */ IL_0053: call      valuetype [mscorlib]System.DateTime [mscorlib]System.DateTime::get_Now()
        /* 0x000002D8 0D           */ IL_0058: stloc.3
        /* 0x000002D9 1203         */ IL_0059: ldloca.s  V_3
        /* 0x000002DB 280A00000A   */ IL_005B: call      instance int64 [mscorlib]System.DateTime::get_Ticks()
        /* 0x000002E0 203A350300   */ IL_0060: ldc.i4    210234
        /* 0x000002E5 6A           */ IL_0065: conv.i8
        /* 0x000002E6 FE01         */ IL_0066: ceq
        /* 0x000002E8 16           */ IL_0068: ldc.i4.0
        /* 0x000002E9 FE01         */ IL_0069: ceq
        /* 0x000002EB 1304         */ IL_006B: stloc.s   V_4
        /* 0x000002ED 1104         */ IL_006D: ldloc.s   V_4
        /* 0x000002EF 2D1E         */ IL_006F: brtrue.s  IL_008F

        if (DateTime.Now.Ticks == 210234L)
        {
            Console.WriteLine(-6636328);
            Console.ReadLine();
            Environment.Exit(84135);
        }

        Makes sure conditionals like this dont fool decompilers by setting them to be clearly false or just nop em out.
    """

    cdef list datetime_methods
    cdef net_row_objects.MemberRef datetime_method
    cdef int method_rid
    cdef unsigned long xref_index
    cdef net_row_objects.MethodDef method_obj
    cdef net_cil_disas.MethodDisassembler disasm_obj
    cdef long instr_index
    cdef bint invert_ops
    cdef bint passed_checks
    cdef unsigned long start_offset
    cdef unsigned long end_offset
    cdef bytes nop_buf
    cdef int br_arg_length
    cdef int br_opcode

    # check for usages of DateTime.
    datetime_method_name = b'System.DateTime.get_Now'
    datetime_methods = dotnet.get_methods_by_full_name(datetime_method_name)

    if len(datetime_methods) != 1:
        raise net_exceptions.MethodLookupException(datetime_method_name)

    datetime_method = datetime_methods[0]
    for method_rid, xref_offset in datetime_method.get_xrefs():  # relying on instr_index gives some issues, maybe change this to an offset?
        method_obj = dotnet.get_method_by_rid(method_rid)
        disasm_obj = method_obj.disassemble_method()
        for instr_index in range(len(disasm_obj)):
            if disasm_obj[instr_index].get_name() == 'call' and disasm_obj[
                instr_index].get_argument().get_full_name() == datetime_method_name:
                if (instr_index + 9) < len(disasm_obj):
                    if disasm_obj[instr_index + 1].get_name().startswith('stloc'):
                        if disasm_obj[instr_index + 2].get_name().startswith('ldloc'):
                            if disasm_obj[instr_index + 3].get_name() == 'call' and disasm_obj[
                                instr_index + 3].get_argument().get_full_name() == b'System.DateTime.get_Ticks':
                                if disasm_obj[instr_index + 4].get_name() == 'ldc.i4':
                                    if disasm_obj[instr_index + 5].get_name() == 'conv.i8':
                                        if disasm_obj[instr_index + 6].get_name() == 'ceq':
                                            invert_ops = False
                                            passed_checks = False
                                            if disasm_obj[instr_index + 7].get_name() == 'ldc.i4.0':
                                                invert_ops = True
                                                if disasm_obj[instr_index + 8].get_name() == 'ceq':
                                                    if disasm_obj[instr_index + 9].get_name().startswith('stloc'):
                                                        if disasm_obj[instr_index + 10].get_name().startswith(
                                                                'ldloc'):
                                                            if disasm_obj[instr_index + 11].get_name().startswith(
                                                                    'brtrue'):
                                                                passed_checks = True
                                            else:
                                                if disasm_obj[instr_index + 7].get_name().startswith('stloc'):
                                                    if disasm_obj[instr_index + 8].get_name().startswith('ldloc'):
                                                        if disasm_obj[instr_index + 9].get_name().startswith(
                                                                'brtrue'):
                                                            passed_checks = True
                                            if passed_checks:
                                                if not invert_ops:
                                                    start_offset = disasm_obj[instr_index].get_instr_offset()
                                                    end_offset = disasm_obj[
                                                                        instr_index + 9].get_instr_offset() + len(
                                                        disasm_obj[instr_index + 9])
                                                    # ok so we can just nop this entre thing out.
                                                    nop_buf = b'\x00' * (end_offset - start_offset)
                                                    dotnet.patch_instruction(method_obj, nop_buf, start_offset,
                                                                                end_offset - start_offset)
                                                else:
                                                    start_offset = disasm_obj[instr_index].get_instr_offset()
                                                    end_offset = disasm_obj[
                                                        instr_index + 11].get_instr_offset()  # dont nop out the brtrue, replace it with a br / br.s

                                                    nop_buf = b'\x00' * (end_offset - start_offset)
                                                    br_arg_length = 1
                                                    br_opcode = 0x2b
                                                    if disasm_obj[instr_index + 11].get_name() == 'brtrue':
                                                        br_arg_length = 4
                                                        br_opcode = 0x38
                                                    # its always going to be true and jump so just replace it with br.s
                                                    dotnet.patch_instruction(method_obj, nop_buf, start_offset,
                                                                                end_offset - start_offset)
                                                    dotnet.patch_instruction(method_obj,
                                                                                bytes([br_opcode]) +
                                                                                int.to_bytes(
                                                                                    disasm_obj[
                                                                                        instr_index + 11].get_argument(),
                                                                                    br_arg_length, 'little',
                                                                                    signed=True),
                                                                                disasm_obj[
                                                                                    instr_index + 11].get_instr_offset(),
                                                                                    disasm_obj[instr_index + 11].get_instr_size())

cdef void remove_unk_obf_1_string_obfuscation(dotnetpefile.DotNetPeFile dotnet):
    cdef net_row_objects.MethodDef method_obj
    cdef net_row_objects.MethodDef target_cctor_method
    cdef dict delegate_mapping
    cdef net_cil_disas.Instruction instr
    cdef object arg_obj
    cdef net_row_objects.MethodDef arg_method_obj
    cdef net_sigs.MethodSig arg_sig
    cdef net_row_objects.MethodDefOrRef prev_method_obj
    cdef net_cil_disas.MethodDisassembler disasm_obj
    cdef long x
    cdef net_cil_disas.Instruction prev_instr
    cdef dict method_strings
    cdef net_emulator.DotNetEmulator emu_obj
    cdef net_emu_types.DotNetString result
    cdef dict string_mapping
    cdef unsigned long total_len
    cdef bytes resulting_string
    cdef unsigned long new_index
    cdef bytes ldstr_instr
    target_cctor_method = None
    delegate_mapping = dict()
    for method_obj in dotnet.get_metadata_table('MethodDef'):
        if method_obj.has_body() and method_obj.is_static_constructor():
            for instr in method_obj.disassemble_method():
                if instr.get_name() == 'ldftn':
                    arg_obj = instr.get_argument()
                    if isinstance(arg_obj, net_row_objects.MethodDef):
                        arg_method_obj = <net_row_objects.MethodDef>arg_method_obj
                        if arg_method_obj.is_static_method() and arg_method_obj.has_body():
                            arg_sig = arg_method_obj.get_method_signature()
                            if isinstance(arg_sig.get_return_type(), net_sigs.CorLibTypeSig):
                                if arg_sig.get_return_type().get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_STRING:
                                    if len(arg_sig.get_parameters()) == 0:
                                        target_cctor_method = method_obj
                                        break
        if target_cctor_method != None:
            break
    if target_cctor_method == None:
        print('Couldnt find target')
        return
    # now that we have our target cctor, we need to populate the delegate mapping.
    prev_method_obj = None
    disasm_obj = target_cctor_method.disassemble_method()
    for x in range(len(disasm_obj)):
        instr = disasm_obj[x]
        if instr.get_name() == 'ldftn':
            prev_method_obj = instr.get_argument()
        elif instr.get_name() == 'stsfld':
            prev_instr = disasm_obj[x - 1]
            if prev_instr.get_name() == 'newobj':
                delegate_mapping[instr.get_argument()] = prev_method_obj
            elif prev_instr.get_name() == 'ldsfld':
                delegate_mapping[instr.get_argument()] = delegate_mapping[prev_instr.get_argument()]

    # now emulate all the methods and get the string results.
    method_strings = dict()
    for method_obj in delegate_mapping.values():
        if method_obj in method_strings:
            continue
        emu_obj = net_emulator.DotNetEmulator(method_obj, dont_execute_cctor=True)
        emu_obj.run_function()
        result = emu_obj.get_stack().pop()
        method_strings[method_obj] = bytes(result.get_str_data_as_bytes().decode(result.get_str_encoding()).encode('utf-8'))

    string_mapping = dict()
    for method_obj in dotnet.get_metadata_table('MethodDef'):
        if method_obj.has_body() and method_obj not in delegate_mapping.values():
            disasm_obj = method_obj.disassemble_method()
            for x in range(len(disasm_obj)):
                instr = disasm_obj[x]
                if instr.get_name() == 'ldsfld' and instr.get_argument() in delegate_mapping.keys():
                    if disasm_obj[x + 1].get_name() == 'callvirt' and disasm_obj[x + 1].get_argument()[
                        'Name'].get_value() == b'Invoke':
                        total_len = instr.get_instr_size() + disasm_obj[x + 1].get_instr_size()
                        resulting_string = method_strings[delegate_mapping[instr.get_argument()]]
                        if resulting_string not in string_mapping:
                            new_index = dotnet.get_heap('#US').append_item(resulting_string)
                            string_mapping[resulting_string] = new_index
                        else:
                            new_index = string_mapping[resulting_string]
                        ldstr_instr = b'\x72' + int.to_bytes(new_index, 3, 'little', signed=False) + b'\x70'
                        ldstr_instr += (b'\x00' * (total_len - ldstr_instr.get_instr_size()))
                        dotnet.patch_instruction(method_obj, ldstr_instr, instr.get_instr_offset(), total_len)


cpdef bytes remove_unk_obf_1_obfuscation(bytes exe_data):
    """
    Temporary method to remove more obfuscation in a sample with hash e6579d0717d17f39f2024280100c9fffb8be1699ccf14d9c708150c0a54fcedb
    Once its determined if the sample is actually .NET Reactor or something else it should be moved to a parser.
    """
    cdef dotnetpefile.DotNetPeFile dotnet
    dotnet = dotnetpefile.try_get_dotnetpe(pe_data=exe_data)
    remove_unk_obf_1_junk_loops(dotnet)
    remove_unk_obf_1_string_obfuscation(dotnet)
    return dotnet.reconstruct_executable()


cpdef bytes remove_useless_bytearray_conditionals(bytes exe_data):
    """
    Something seen in possible DotNetReactor samples with hash e6579d0717d17f39f2024280100c9fffb8be1699ccf14d9c708150c0a54fcedb

    if(new byte[]{<random constant data>}.Equals(new byte[]{<more constant data, always nonequal to the first}))
    Removes this type of obfuscation.

    Example IL: 			
            /* 0x00001815 20FF000000   */ IL_0021: ldc.i4    255
			/* 0x0000181A 8D11000001   */ IL_0026: newarr    [mscorlib]System.Byte
			/* 0x0000181F 25           */ IL_002B: dup
			/* 0x00001820 D0C2030004   */ IL_002C: ldtoken   field valuetype Class16/Class18 Class16::field960
			/* 0x00001825 280E00000A   */ IL_0031: call      void [mscorlib]System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(class [mscorlib]System.Array, valuetype [mscorlib]System.RuntimeFieldHandle)
			/* 0x0000182A 20FF000000   */ IL_0036: ldc.i4    255
			/* 0x0000182F 8D11000001   */ IL_003B: newarr    [mscorlib]System.Byte
			/* 0x00001834 25           */ IL_0040: dup
			/* 0x00001835 D0C3030004   */ IL_0041: ldtoken   field valuetype Class16/Class18 Class16::field961
			/* 0x0000183A 280E00000A   */ IL_0046: call      void [mscorlib]System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(class [mscorlib]System.Array, valuetype [mscorlib]System.RuntimeFieldHandle)
			/* 0x0000183F 6F1600000A   */ IL_004B: callvirt  instance bool [mscorlib]System.Object::Equals(object)
			/* 0x00001844 0A           */ IL_0050: stloc.0
			/* 0x00001845 06           */ IL_0051: ldloc.0
			/* 0x00001846 2DAF         */ IL_0052: brtrue.s  IL_0003
    """
    cdef dotnetpefile.DotNetPeFile dotnet
    cdef list initialize_arrays
    cdef net_row_objects.MemberRef initialize_array
    cdef unsigned long method_rid
    cdef unsigned long instr_index
    cdef net_cil_disas.MethodDisassembler disasm_obj
    cdef long x
    cdef net_cil_disas.Instruction instr
    cdef bint no_ceq_instr
    cdef bint has_ldc_i4
    cdef net_cil_disas.Instruction ldtoken_first
    cdef net_cil_disas.Instruction ldtoken_second
    cdef bytes first_data
    cdef bytes second_data
    cdef unsigned long start_offset
    cdef unsigned long end_offset
    cdef bytes nop_buffer
    cdef int br_arg_length
    cdef int br_opcode
    dotnet = dotnetpefile.try_get_dotnetpe(pe_data=exe_data)
    if not dotnet:
        return None

    initialize_arrays = dotnet.get_methods_by_full_name(
        b'System.Runtime.CompilerServices.RuntimeHelpers.InitializeArray')
    if len(initialize_arrays) != 1:
        return None

    initialize_array = initialize_arrays[0]
    for method_rid, xref_offset in initialize_array.get_xrefs():
        method_obj = dotnet.get_method_by_rid(method_rid)
        disasm_obj = method_obj.disassemble_method()
        for x in range(len(disasm_obj)):
            instr = disasm_obj[x]
            if instr.get_name() == 'ldc.i4':
                if (x + 13) < len(disasm_obj):
                    if disasm_obj[x + 1].get_name() == 'newarr':
                        if disasm_obj[x + 2].get_name() == 'dup':
                            if disasm_obj[x + 3].get_name() == 'ldtoken':
                                if disasm_obj[x + 4].get_name() == 'call' and \
                                        disasm_obj[
                                            x + 4].get_argument().get_full_name() == b'System.Runtime.CompilerServices.RuntimeHelpers.InitializeArray':
                                    if disasm_obj[x + 5].get_name() == 'ldc.i4' and disasm_obj[
                                        x + 6].get_name() == 'newarr' and disasm_obj[x + 7].get_name() == 'dup':
                                        if disasm_obj[x + 8].get_name() == 'ldtoken':
                                            if disasm_obj[x + 9].get_name() == 'call' and \
                                                    disasm_obj[
                                                        x + 9].get_argument().get_full_name() == b'System.Runtime.CompilerServices.RuntimeHelpers.InitializeArray':
                                                if disasm_obj[x + 10].get_name() == 'callvirt' and disasm_obj[
                                                    x + 10].get_argument().get_full_name() == b'System.Object.Equals':
                                                    has_ldc_i4 = False
                                                    no_ceq_instr = False
                                                    if disasm_obj[x + 11].get_name().startswith('stloc') and disasm_obj[
                                                        x + 12].get_name().startswith('ldloc') and disasm_obj[
                                                        x + 13].get_name().startswith('brtrue'):
                                                        no_ceq_instr = True

                                                    if not no_ceq_instr and disasm_obj[x + 11].get_name() == 'ldc.i4.0':
                                                        has_ldc_i4 = True

                                                    if no_ceq_instr:
                                                        ldtoken_first = disasm_obj[x + 3]
                                                        ldtoken_second = disasm_obj[x + 8]
                                                        first_data = ldtoken_first.get_argument().get_data()
                                                        second_data = ldtoken_second.get_argument().get_data()
                                                        if first_data == second_data:
                                                            start_offset = disasm_obj[x].get_instr_offset()
                                                            end_offset = disasm_obj[x + 12].get_instr_offset() + disasm_obj[x + 12].get_instr_size()
                                                            nop_buffer = b'\x00' * (end_offset - start_offset)
                                                            br_arg_length = 1
                                                            br_opcode = 0x2b
                                                            if disasm_obj[x + 13].get_name() == 'brtrue':
                                                                br_arg_length = 4
                                                                br_opcode = 0x38
                                                            # its always going to be true and jump so just replace it with br.s
                                                            dotnet.patch_instruction(method_obj, nop_buffer,
                                                                                     start_offset, end_offset - start_offset)
                                                            dotnet.patch_instruction(method_obj,
                                                                                     bytes([br_opcode]) +
                                                                                     int.to_bytes(
                                                                                         disasm_obj[
                                                                                             x + 13].get_argument(),
                                                                                         br_arg_length, 'little',
                                                                                         signed=True),
                                                                                     disasm_obj[
                                                                                         x + 13].get_instr_offset(),
                                                                                     disasm_obj[x + 13].get_instr_size())
                                                        else:
                                                            # its never going to jump, just nop everything out.
                                                            start_offset = disasm_obj[x].get_instr_offset()
                                                            end_offset = disasm_obj[x + 13].get_instr_offset() + disasm_obj[x + 13].get_instr_size()
                                                            nop_buffer = b'\x00' * (end_offset - start_offset)
                                                            dotnet.patch_instruction(method_obj, nop_buffer,
                                                                                     start_offset, end_offset - start_offset)

                                                    elif has_ldc_i4 and disasm_obj[x + 12].get_name() == 'ceq' and (
                                                            x + 15) < len(disasm_obj):
                                                        if disasm_obj[x + 13].get_name().startswith('stloc'):
                                                            if disasm_obj[x + 14].get_name().startswith('ldloc'):
                                                                if disasm_obj[x + 15].get_name().startswith('brtrue'):
                                                                    ldtoken_first = disasm_obj[x + 3]
                                                                    ldtoken_second = disasm_obj[x + 8]
                                                                    first_data = ldtoken_first.get_argument().get_data()
                                                                    second_data = ldtoken_second.get_argument().get_data()
                                                                    if first_data != second_data:
                                                                        start_offset = disasm_obj[x].get_instr_offset()
                                                                        end_offset = disasm_obj[
                                                                                         x + 14].get_instr_offset() + disasm_obj[x + 14].get_instr_size()
                                                                        nop_buffer = b'\x00' * (
                                                                                    end_offset - start_offset)
                                                                        br_arg_length = 1
                                                                        br_opcode = 0x2b
                                                                        if disasm_obj[x + 15].get_name() == 'brtrue':
                                                                            br_arg_length = 4
                                                                            br_opcode = 0x38
                                                                        # its always going to be true and jump so just replace it with br.s
                                                                        dotnet.patch_instruction(method_obj, nop_buffer,
                                                                                                 start_offset,
                                                                                                 end_offset - start_offset)
                                                                        dotnet.patch_instruction(method_obj,
                                                                                                 bytes([br_opcode]) +
                                                                                                 int.to_bytes(
                                                                                                     disasm_obj[
                                                                                                         x + 15].get_argument(),
                                                                                                     br_arg_length,
                                                                                                     'little',
                                                                                                     signed=True),
                                                                                                 disasm_obj[
                                                                                                     x + 15].get_instr_offset(),
                                                                                                 disasm_obj[
                                                                                                         x + 15].get_instr_size())
                                                                    else:
                                                                        # its never going to jump, just nop everything out.
                                                                        start_offset = disasm_obj[x].get_instr_offset()
                                                                        end_offset = disasm_obj[
                                                                                         x + 15].get_instr_offset() + disasm_obj[x + 15].get_instr_size()
                                                                        nop_buffer = b'\x00' * (
                                                                                    end_offset - start_offset)
                                                                        dotnet.patch_instruction(method_obj, nop_buffer,
                                                                                                 start_offset,
                                                                                                 end_offset - start_offset)
                                                    elif not has_ldc_i4 and (x + 15) < len(disasm_obj):
                                                        if disasm_obj[x + 11].get_name().startswith('stloc'):
                                                            if disasm_obj[x + 12].get_name().startswith('ldloc'):
                                                                if disasm_obj[x + 13].get_name().startswith('brtrue'):
                                                                    ldtoken_first = disasm_obj[x + 3]
                                                                    ldtoken_second = disasm_obj[x + 8]
                                                                    first_data = ldtoken_first.get_argument().get_data()
                                                                    second_data = ldtoken_second.get_argument().get_data()
                                                                    if first_data == second_data:
                                                                        start_offset = disasm_obj[x].get_instr_offset()
                                                                        end_offset = disasm_obj[
                                                                                         x + 14].get_instr_offset() + len(
                                                                            disasm_obj[x + 14])
                                                                        nop_buffer = b'\x00' * (
                                                                                    end_offset - start_offset)
                                                                        br_arg_length = 1
                                                                        br_opcode = 0x2b
                                                                        if disasm_obj[x + 13].get_name() == 'brtrue':
                                                                            br_arg_length = 4
                                                                            br_opcode = 0x38
                                                                        # its always going to be true and jump so just replace it with br.s
                                                                        dotnet.patch_instruction(method_obj, nop_buffer,
                                                                                                 start_offset,
                                                                                                 end_offset - start_offset)
                                                                        dotnet.patch_instruction(method_obj,
                                                                                                 bytes([br_opcode]) +
                                                                                                 int.to_bytes(
                                                                                                     disasm_obj[
                                                                                                         x + 13].get_argument(),
                                                                                                     br_arg_length,
                                                                                                     'little',
                                                                                                     signed=True),
                                                                                                 disasm_obj[
                                                                                                     x + 13].get_instr_offset(),
                                                                                                 disasm_obj[
                                                                                                     x + 15].get_instr_size())
                                                                    else:
                                                                        # its never going to jump, just nop everything out.
                                                                        start_offset = disasm_obj[x].get_instr_offset()
                                                                        end_offset = disasm_obj[
                                                                                         x + 13].get_instr_offset() + disasm_obj[x + 13].get_instr_size()
                                                                        nop_buffer = b'\x00' * (
                                                                                    end_offset - start_offset)
                                                                        dotnet.patch_instruction(method_obj, nop_buffer,
                                                                                                 start_offset,
                                                                                                 end_offset - start_offset)

    return dotnet.reconstruct_executable()


cpdef bytes remove_useless_conditionals(bytes exe_data, list target_method_rids=[]):
    """
    Removes conditionals that will either always be true or always false
    currently handles the following cases:
    brtrue.s, brfalse.s, brtrue, brfalse: conditionals like if (6 != 0) then
    """
    cdef dotnetpefile.DotNetPeFile dotnet
    cdef net_row_objects.MethodDef method_obj
    cdef net_cil_disas.MethodDisassembler disas_obj
    cdef long x
    cdef long y
    cdef net_cil_disas.Instruction instr
    cdef net_cil_disas.Instruction prev_instr
    cdef long long number
    cdef unsigned long instr_offset
    cdef long long num_instrs
    cdef net_cil_disas.Instruction prev_instr2
    cdef net_table_objects.MethodDefTable methods
    cdef bint check_target_methods = len(target_method_rids) != 0

    dotnet = dotnetpefile.DotNetPeFile(pe_data=exe_data)
    methods = <net_table_objects.MethodDefTable>dotnet.get_metadata_table('MethodDef')
    for y in range(len(methods)):
        method_obj = <net_row_objects.MethodDef>methods.get(y + 1)
        if not method_obj.has_body() or (check_target_methods and method_obj.get_rid() not in target_method_rids):
            continue

        # make sure were creating a fresh copy every time.
        disas_obj = method_obj.disassemble_method()
        for x in range(len(disas_obj)):
            instr = disas_obj.get_instr_at_index(x)
            if x == 0:
                continue
            if instr.get_name() == 'brtrue.s':
                prev_instr = disas_obj.get_instr_at_index(x - 1)
                if prev_instr.get_name().startswith('ldc.i4.'):
                    number = prev_instr.get_argument()
                    if number != 0:
                        # its always going to make the jmp, just replace both instructions with a br.s
                        num_instrs = instr.get_argument()
                        instr_offset = prev_instr.get_instr_offset()
                        dotnet.patch_instruction(
                            method_obj, b'\x00' * prev_instr.get_instr_size(), instr_offset, prev_instr.get_instr_size())
                        dotnet.patch_instruction(method_obj,
                                                 b'\x2B' +
                                                 int.to_bytes(
                                                     num_instrs, 1, 'little', signed=True),
                                                 instr_offset + prev_instr.get_instr_size(), instr.get_instr_size())
                    else:
                        # if its never going to make the jump, just nop both out.
                        instr_offset = prev_instr.get_instr_offset()
                        dotnet.patch_instruction(
                            method_obj, b'\x00' * prev_instr.get_instr_size(), instr_offset, prev_instr.get_instr_size())
                        dotnet.patch_instruction(
                            method_obj, b'\x00' * instr.get_instr_size(), instr_offset + prev_instr.get_instr_size(), instr.get_instr_size())
                elif prev_instr.get_name() == 'ldnull':
                    # if its never going to make the jump, just nop both out.
                    instr_offset = prev_instr.get_instr_offset()
                    dotnet.patch_instruction(
                        method_obj, b'\x00' * prev_instr.get_instr_size(), instr_offset, prev_instr.get_instr_size())
                    dotnet.patch_instruction(
                        method_obj, b'\x00' * instr.get_instr_size(), instr_offset + prev_instr.get_instr_size(), instr.get_instr_size())
                elif prev_instr == 'dup' and x > 1:
                    prev_instr2 = disas_obj.get_instr_at_index(x - 2)
                    # run the check again on the instruction before that.
                    if prev_instr2.get_name().startswith('ldc.i4.'):
                        number = prev_instr2.get_argument()
                        if number != 0:
                            # its always going to make the jmp, just replace both instructions with a br.s
                            num_instrs = instr.get_argument()
                            instr_offset = prev_instr.get_instr_offset()
                            dotnet.patch_instruction(
                                method_obj, b'\x00' * prev_instr.get_instr_size(), instr_offset, prev_instr.get_instr_size())
                            dotnet.patch_instruction(method_obj,
                                                     b'\x2B' +
                                                     int.to_bytes(
                                                         num_instrs, 1, 'little', signed=True),
                                                     instr_offset + prev_instr.get_instr_size(), instr.get_instr_size())
                        else:
                            # if its never going to make the jump, just nop both out.
                            instr_offset = prev_instr.get_instr_offset()
                            dotnet.patch_instruction(
                                method_obj, b'\x00' * prev_instr.get_instr_size(), instr_offset, prev_instr.get_instr_size())
                            dotnet.patch_instruction(
                                method_obj, b'\x00' * instr.get_instr_size(), instr_offset + prev_instr.get_instr_size(), instr.get_instr_size())
                    elif prev_instr2.get_name() == 'ldnull':
                        # if its never going to make the jump, just nop both out.
                        instr_offset = prev_instr.get_instr_offset()
                        dotnet.patch_instruction(
                            method_obj, b'\x00' * prev_instr.get_instr_size(), instr_offset, prev_instr.get_instr_size())
                        dotnet.patch_instruction(
                            method_obj, b'\x00' * instr.get_instr_size(), instr_offset + prev_instr.get_instr_size(), instr.get_instr_size())

            elif instr.get_name() == 'brfalse.s':
                prev_instr = disas_obj.get_instr_at_index(x - 1)
                if prev_instr.get_name().startswith('ldc.i4.'):
                    number = prev_instr.get_argument()
                    if number == 0:
                        # its always going to make the jmp, just replace both instructions with a br.s
                        num_instrs = instr.get_argument()
                        instr_offset = prev_instr.get_instr_offset()
                        dotnet.patch_instruction(
                            method_obj, b'\x00' * prev_instr.get_instr_size(), instr_offset, prev_instr.get_instr_size())
                        dotnet.patch_instruction(method_obj,
                                                 b'\x2B' +
                                                 int.to_bytes(
                                                     num_instrs, 1, 'little', signed=True),
                                                 instr_offset + prev_instr.get_instr_size(), instr.get_instr_size())
                    else:
                        # if its never going to make the jump, just nop both out.
                        instr_offset = prev_instr.get_instr_offset()
                        dotnet.patch_instruction(
                            method_obj, b'\x00' * prev_instr.get_instr_size(), instr_offset, prev_instr.get_instr_size())
                        dotnet.patch_instruction(
                            method_obj, b'\x00' * instr.get_instr_size(), instr_offset + prev_instr.get_instr_size(), instr.get_instr_size())
                elif prev_instr.get_name() == 'ldnull':
                    # its always going to make the jmp, just replace both instructions with a br.s
                    num_instrs = instr.get_argument()
                    instr_offset = prev_instr.get_instr_offset()
                    dotnet.patch_instruction(
                        method_obj, b'\x00' * prev_instr.get_instr_size(), instr_offset, prev_instr.get_instr_size())
                    dotnet.patch_instruction(method_obj,
                                             b'\x2B' +
                                             int.to_bytes(
                                                 num_instrs, 1, 'little', signed=True),
                                             instr_offset + prev_instr.get_instr_size(), instr.get_instr_size())
                elif prev_instr.get_name() == 'dup' and x > 1:
                    prev_instr2 = disas_obj.get_instr_at_index(x - 2)
                    if prev_instr2.get_name().startswith('ldc.i4.'):
                        number = prev_instr2.get_argument()
                        if number == 0:
                            # its always going to make the jmp, just replace both instructions with a br.s
                            num_instrs = instr.get_argument()
                            instr_offset = prev_instr.get_instr_offset()
                            dotnet.patch_instruction(
                                method_obj, b'\x00' * prev_instr.get_instr_size(), instr_offset, prev_instr.get_instr_size())
                            dotnet.patch_instruction(method_obj,
                                                     b'\x2B' +
                                                     int.to_bytes(
                                                         num_instrs, 1, 'little', signed=True),
                                                     instr_offset + prev_instr.get_instr_size(), instr.get_instr_size())
                        else:
                            # if its never going to make the jump, just nop both out.
                            instr_offset = prev_instr.get_instr_offset()
                            dotnet.patch_instruction(
                                method_obj, b'\x00' * prev_instr.get_instr_size(), instr_offset, prev_instr.get_instr_size())
                            dotnet.patch_instruction(
                                method_obj, b'\x00' * instr.get_instr_size(), instr_offset + prev_instr.get_instr_size(), instr.get_instr_size())
                    elif prev_instr2.get_name() == 'ldnull':
                        # its always going to make the jmp, just replace both instructions with a br.s
                        num_instrs = instr.get_argument()
                        instr_offset = prev_instr.get_instr_offset()
                        dotnet.patch_instruction(
                            method_obj, b'\x00' * prev_instr.get_instr_size(), instr_offset, prev_instr.get_instr_size())
                        dotnet.patch_instruction(method_obj,
                                                 b'\x2B' +
                                                 int.to_bytes(
                                                     num_instrs, 1, 'little', signed=True),
                                                 instr_offset + prev_instr.get_instr_size(), instr.get_instr_size())
            elif instr.get_name() == 'brtrue':
                prev_instr = disas_obj.get_instr_at_index(x - 1)
                if prev_instr.get_name().startswith('ldc.i4.'):
                    number = prev_instr.get_argument()
                    if number != 0:
                        # its always going to make the jmp, just replace both instructions with a br.s
                        num_instrs = instr.get_argument()
                        instr_offset = prev_instr.get_instr_offset()

                        dotnet.patch_instruction(
                            method_obj, b'\x00' * prev_instr.get_instr_size(), instr_offset, prev_instr.get_instr_size())
                        dotnet.patch_instruction(method_obj,
                                                 b'\x38' +
                                                 int.to_bytes(
                                                     num_instrs, 4, 'little', signed=True),
                                                 instr_offset + prev_instr.get_instr_size(), instr.get_instr_size())
                    else:
                        instr_offset = prev_instr.get_instr_offset()

                        # if its never going to make the jump, just nop both out.
                        dotnet.patch_instruction(
                            method_obj, b'\x00' * prev_instr.get_instr_size(), instr_offset, prev_instr.get_instr_size())
                        dotnet.patch_instruction(
                            method_obj, b'\x00' * instr.get_instr_size(), instr_offset + prev_instr.get_instr_size(), instr.get_instr_size())
                elif prev_instr.get_name() == 'ldnull':
                    instr_offset = prev_instr.get_instr_offset()

                    # if its never going to make the jump, just nop both out.
                    dotnet.patch_instruction(
                        method_obj, b'\x00' * prev_instr.get_instr_size(), instr_offset, prev_instr.get_instr_size())
                    dotnet.patch_instruction(
                        method_obj, b'\x00' * instr.get_instr_size(), instr_offset + prev_instr.get_instr_size(), instr.get_instr_size())
                elif prev_instr.get_name() == 'dup' and x > 1:
                    prev_instr2 = disas_obj.get_instr_at_index(x - 2)
                    if prev_instr2.get_name().startswith('ldc.i4.'):
                        number = prev_instr2.get_argument()
                        if number != 0:
                            # its always going to make the jmp, just replace both instructions with a br.s
                            num_instrs = instr.get_argument()
                            instr_offset = prev_instr.get_instr_offset()

                            dotnet.patch_instruction(
                                method_obj, b'\x00' * prev_instr.get_instr_size(), instr_offset, prev_instr.get_instr_size())
                            dotnet.patch_instruction(method_obj,
                                                     b'\x38' +
                                                     int.to_bytes(
                                                         num_instrs, 4, 'little', signed=True),
                                                     instr_offset + prev_instr.get_instr_size(), instr.get_instr_size())
                        else:
                            instr_offset = prev_instr.get_instr_offset()

                            # if its never going to make the jump, just nop both out.
                            dotnet.patch_instruction(
                                method_obj, b'\x00' * prev_instr.get_instr_size(), instr_offset, prev_instr.get_instr_size())
                            dotnet.patch_instruction(
                                method_obj, b'\x00' * instr.get_instr_size(), instr_offset + prev_instr.get_instr_size(), instr.get_instr_size())
                    elif prev_instr2.get_name() == 'ldnull':
                        instr_offset = prev_instr.get_instr_offset()

                        # if its never going to make the jump, just nop both out.
                        dotnet.patch_instruction(
                            method_obj, b'\x00' * prev_instr.get_instr_size(), instr_offset, prev_instr.get_instr_size())
                        dotnet.patch_instruction(
                            method_obj, b'\x00' * instr.get_instr_size(), instr_offset + prev_instr.get_instr_size(), instr.get_instr_size())
            elif instr.get_name() == 'brfalse':
                prev_instr = disas_obj.get_instr_at_index(x - 1)
                if prev_instr.get_name().startswith('ldc.i4.'):
                    number = prev_instr.get_argument()
                    if number == 0:
                        # its always going to make the jmp, just replace both instructions with a br.s
                        num_instrs = instr.get_argument()
                        instr_offset = prev_instr.get_instr_offset()

                        dotnet.patch_instruction(
                            method_obj, b'\x00' * prev_instr.get_instr_size(), instr_offset, prev_instr.get_instr_size())
                        dotnet.patch_instruction(method_obj,
                                                 b'\x38' +
                                                 int.to_bytes(
                                                     num_instrs, 4, 'little', signed=True),
                                                 instr_offset + prev_instr.get_instr_size(), instr.get_instr_size())
                    else:
                        # if its never going to make the jump, just nop both out.
                        instr_offset = prev_instr.get_instr_offset()

                        dotnet.patch_instruction(
                            method_obj, b'\x00' * prev_instr.get_instr_size(), instr_offset, prev_instr.get_instr_size())
                        dotnet.patch_instruction(
                            method_obj, b'\x00' * instr.get_instr_size(), instr_offset + prev_instr.get_instr_size(), instr.get_instr_size())
                elif prev_instr.get_name() == 'ldnull':
                    # its always going to make the jmp, just replace both instructions with a br.s
                    num_instrs = instr.get_argument()
                    instr_offset = prev_instr.get_instr_offset()

                    dotnet.patch_instruction(
                        method_obj, b'\x00' * prev_instr.get_instr_size(), instr_offset, prev_instr.get_instr_size())
                    dotnet.patch_instruction(method_obj,
                                             b'\x38' +
                                             int.to_bytes(
                                                 num_instrs, 4, 'little', signed=True),
                                             instr_offset + prev_instr.get_instr_size(), instr.get_instr_size())
                elif prev_instr.get_name() == 'dup' and x > 1:
                    prev_instr2 = disas_obj.get_instr_at_index(x - 2)
                    if prev_instr2.get_name().startswith('ldc.i4.'):
                        number = prev_instr2.get_argument()
                        if number == 0:
                            # its always going to make the jmp, just replace both instructions with a br.s
                            num_instrs = instr.get_argument()
                            instr_offset = prev_instr.get_instr_offset()

                            dotnet.patch_instruction(
                                method_obj, b'\x00' * prev_instr.get_instr_size(), instr_offset, prev_instr.get_instr_size())
                            dotnet.patch_instruction(method_obj,
                                                     b'\x38' +
                                                     int.to_bytes(
                                                         num_instrs, 4, 'little', signed=True),
                                                     instr_offset + prev_instr.get_instr_size(), instr.get_instr_size())
                        else:
                            # if its never going to make the jump, just nop both out.
                            instr_offset = prev_instr.get_instr_offset()

                            dotnet.patch_instruction(
                                method_obj, b'\x00' * prev_instr.get_instr_size(), instr_offset, prev_instr.get_instr_size())
                            dotnet.patch_instruction(
                                method_obj, b'\x00' * instr.get_instr_size(), instr_offset + prev_instr.get_instr_size(), instr.get_instr_size())
                    elif prev_instr2.get_name() == 'ldnull':
                        # its always going to make the jmp, just replace both instructions with a br.s
                        num_instrs = instr.get_argument()
                        instr_offset = prev_instr.get_instr_offset()

                        dotnet.patch_instruction(
                            method_obj, b'\x00' * prev_instr.get_instr_size(), instr_offset, prev_instr.get_instr_size())
                        dotnet.patch_instruction(method_obj,
                                                 b'\x38' +
                                                 int.to_bytes(
                                                     num_instrs, 4, 'little', signed=True),
                                                 instr_offset + prev_instr.get_instr_size(), instr.get_instr_size())

    return dotnet.reconstruct_executable()

cdef bytes __is_useless_method(dotnetpefile.DotNetPeFile dpe, net_row_objects.MethodDef method_obj):
    """
    A useless method is defined as a method that for instance just pulls all arguments off the stack then does either newobj, callvirt or call then returns
    """
    cdef net_cil_disas.MethodDisassembler disasm_obj
    cdef list method_args_grabbed
    cdef list allowed_instrs
    cdef bytes potential_data
    cdef long x
    cdef net_cil_disas.Instruction instr
    cdef str instr_name
    cdef net_row_objects.MethodDefOrRef inner_method
    cdef net_sigs.MethodSig inner_method_sig
    cdef net_sigs.MethodSig outer_method_sig
    cdef list outer_method_params
    cdef list inner_method_params
    cdef bint bypass_rtype_check
    cdef net_sigs.TypeSig outer_return_sig
    cdef net_sigs.TypeSig inner_return_sig
    cdef net_row_objects.TypeDefOrRef expected_tdef
    cdef net_sigs.ClassSig outer_return_type
    cdef long y
    cdef net_sigs.TypeSig param1
    cdef net_sigs.TypeSig param2
    if method_obj.method_has_this():
        return bytes()  # skip thiscalls - CEX only uses static methods.
    disasm_obj = method_obj.disassemble_method()
    method_args_grabbed = []
    allowed_instrs = ['call', 'callvirt', 'newobj', 'ret', 'ldarg', 'ldarg.0', 'ldarg.1', 'ldarg.2', 'ldarg.3',
                        'ldarg.s', 'nop']
    potential_data = None
    for x in range(len(disasm_obj)):
        # first check if all the first few instructions are ldargs.
        instr = disasm_obj.get_instr_at_index(x)
        if instr.get_name() not in allowed_instrs:
            return bytes()

        if instr.get_name().startswith('ldarg'):
            method_args_grabbed.append(instr.get_argument())

        instr_name = instr.get_name()
        if (instr_name == 'callvirt' or instr_name == 'call' or instr_name == 'newobj') and (len(disasm_obj) > (x+1) and disasm_obj.get_instr_at_index(x+1).get_name() == 'ret'):
            if potential_data:
                return bytes()
            # ok so for this check, the first thing we are going to want to do is check if the methods have the same argument
            inner_method = instr.get_argument()
            # for simplicity sake skip any methodspecs
            if isinstance(inner_method, net_row_objects.MethodSpec):
                return bytes()
            inner_method_sig = inner_method.get_method_signature()
            outer_method_sig = method_obj.get_method_signature()
            outer_method_params = list(outer_method_sig.get_parameters())
            inner_method_params = list(inner_method_sig.get_parameters())

            if inner_method.method_has_this():
                if inner_method.get_column('Name').get_value() != b'.ctor':
                    inner_method_params.insert(0, outer_method_params[0])

            if len(inner_method_params) != len(outer_method_params):
                return bytes()

            # compare sigs
            bypass_rtype_check = False
            if isinstance(outer_method_sig.get_return_type(), net_sigs.SZArraySig) or isinstance(
                    inner_method_sig.get_return_type(), net_sigs.SZArraySig):
                inner_return_sig = inner_method_sig.get_return_type()
                outer_return_sig = outer_method_sig.get_return_type()
                if (isinstance(outer_return_sig,
                                net_sigs.ClassSig) and outer_return_sig.get_type().get_full_name() == b'System.Array') or \
                        (isinstance(inner_return_sig,
                                    net_sigs.ClassSig) and inner_return_sig.get_type().get_full_name() == b'System.Array'):
                    bypass_rtype_check = True
            if isinstance(outer_method_sig.get_return_type(), net_sigs.CorLibTypeSig) and outer_method_sig.get_return_type().get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_OBJECT:
                bypass_rtype_check = True #Objects can be anything.
            if isinstance(inner_method_sig.get_return_type(), net_sigs.CorLibTypeSig) and inner_method_sig.get_return_type().get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_OBJECT:
                bypass_rtype_check = True
            if not bypass_rtype_check and inner_method_sig.get_return_type() != outer_method_sig.get_return_type():
                # first do a check if its a ctor.  Ctors will say they return void in their sigs but really dont.
                if inner_method.get_column('Name').get_value() != b'.ctor':
                    return bytes()
                else:
                    expected_tdef = inner_method.get_parent_type()
                    if not isinstance(outer_method_sig.get_return_type(), net_sigs.ClassSig):
                        return bytes()
                    outer_return_type = outer_method_sig.get_return_type()
                    if outer_return_type.get_type() != expected_tdef:
                        return bytes()

            if len(inner_method_params) != len(outer_method_params):
                return bytes()

            for y in range(len(inner_method_params)):
                param1 = inner_method_params[y]
                param2 = outer_method_params[y]
                if param1 != param2:
                    # if we are matching a SZArraySig with System.Array classsig, return true for these purposes.
                    if isinstance(param1, net_sigs.SZArraySig) and isinstance(param2, net_sigs.ClassSig):
                        if param2.get_type().get_full_name() == b'System.Array':
                            continue

                    if isinstance(param1, net_sigs.ClassSig) and isinstance(param2, net_sigs.SZArraySig):
                        if param1.get_type().get_full_name() == b'System.Array':
                            continue

                    if isinstance(param2, net_sigs.CorLibTypeSig) and param2.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_OBJECT:
                        continue #Objects will match anything.

                    if isinstance(param1, net_sigs.CorLibTypeSig) and param1.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_OBJECT:
                        continue

                    return bytes()

            #At this point, we should check if the interior method is also a useless method.
            if isinstance(instr.get_argument(), net_row_objects.MethodDef):
                potential_data = __is_useless_method(dpe, instr.get_argument())
            if potential_data is None or len(potential_data) == 0:
                potential_data = instr.get_bytes()
            break
    if not potential_data:
        return bytes()
    return potential_data

cdef bint __is_modified_method(dotnetpefile.DotNetPeFile dpe, net_row_objects.MethodDef method_obj):
    """
    Used to skip methods that have the following signature: ldnull, ret, nop * x
    """
    cdef net_cil_disas.MethodDisassembler disasm_obj
    cdef net_cil_disas.Instruction instr_one
    cdef net_cil_disas.Instruction instr_two
    cdef net_cil_disas.Instruction instr_three
    disasm_obj = method_obj.disassemble_method()
    if len(disasm_obj) > 2:
        instr_one = disasm_obj[0]
        instr_two = disasm_obj[1]
        instr_three = disasm_obj[2]
        if instr_one.get_name() == 'ldnull':
            if instr_two.get_name() == 'ret':
                if instr_three.get_name() == 'nop':
                    return True
    return False

cdef int __is_junk_method(dotnetpefile.DotNetPeFile dpe, net_row_objects.MethodDef method_obj):
    """
    Junk methods are methods that simply check if a field is null that will always be null.
    Junk methods can also be returning a field that will always be null
    """
    cdef list allowed_instrs
    cdef net_cil_disas.MethodDisassembler disasm_obj
    cdef net_row_objects.RowObject field_id
    cdef bint has_compare
    cdef int method_rid
    cdef unsigned long instr_index
    cdef net_row_objects.MethodDef method_obj2
    cdef net_cil_disas.Instruction instr

    allowed_instrs = ['nop', 'ceq', 'ldnull', 'ldsfld', 'ret']
    # skip getters and setters
    if method_obj.get_column('Name').get_value_as_bytes().startswith(b'get_') or method_obj.get_column('Name').get_value_as_bytes().startswith(b'set_'):
        return 0

    disasm_obj = method_obj.disassemble_method()
    field_id = None
    has_compare = False
    for instr in disasm_obj:
        if instr.get_name() not in allowed_instrs:
            return 0

        if instr.get_name() == 'ldsfld':
            if field_id != None:
                return 0

            field_id = instr.get_argument()
        if instr.get_name() == 'ceq':
            has_compare = True

    if field_id != None:
        for method_rid, xref_offset in field_id.get_xrefs():
            method_obj2 = dpe.get_method_by_rid(method_rid)
            disasm_obj = method_obj2.disassemble_method()
            instr = <net_cil_disas.Instruction>disasm_obj.get_instr_at_offset(xref_offset)
            if instr.get_name() == 'stsfld':
                return 0

    # skip property methods that start with get and set
    if has_compare:
        return 1
    return 2

cpdef bytes remove_useless_functions(bytes data) except *:
    """
    Removes functions that simply call another function with the same arguments.
    TODO: This method needs a rewrite.  For example, on sample 0320 for cex parser, it takes around 5 minutes to decode strings
    A significant portion of the runtime appears to be this method.
    """
    cdef dict useless_methods
    cdef dotnetpefile.DotNetPeFile dotnet
    cdef net_row_objects.MethodDef method
    cdef bytes data2
    cdef int u_rid
    cdef net_row_objects.MethodDef u_method
    cdef int method_rid
    cdef unsigned long instr_index
    cdef net_row_objects.MethodDef method_obj
    cdef net_cil_disas.MethodDisassembler method_disasm
    cdef net_cil_disas.Instruction instr
    cdef net_row_objects.MethodDefOrRef instr_arg
    cdef net_row_objects.MemberRef memberref
    cdef net_row_objects.MethodDef method_impl
    cdef net_row_objects.MethodDefOrRef arg_obj
    cdef int junk_id
    cdef bytes patch
    cdef net_table_objects.MethodDefTable method_table
    cdef net_table_objects.MemberRefTable memberref_table
    cdef long x
    cdef long y
    cdef list useless_rids
    cdef list useless_xrefs
    cdef tuple xref_info

    import binascii
    
    useless_methods = dict()  # dictionary of useless method rids and the instructions to replace them with
    dotnet = dotnetpefile.DotNetPeFile(pe_data=data)
    method_table = <net_table_objects.MethodDefTable>dotnet.get_metadata_table('MethodDef')
    memberref_table = <net_table_objects.MemberRefTable>dotnet.get_metadata_table('MemberRef')
    for x in range(1, len(method_table) + 1):
        method = <net_row_objects.MethodDef>method_table.get(x)
        if method.has_body() and not method.is_static_constructor():
            if method.get_column('Name').get_value_as_bytes() != b'.cctor' and method.get_column('Name').get_value_as_bytes() != b'.ctor':
                if __is_modified_method(dotnet, method):
                    continue
                data2 = __is_useless_method(dotnet, method)
                if len(data2) != 0:
                    useless_methods[method.get_rid()] = data2
                    # for sanity sake set the raw value to 0.  TODO: fix this to remove the method from the binary entirely.
                    # method['RVA'].set_raw_value(0)
    useless_rids = list(useless_methods.keys())
    for x in range(len(useless_rids)):
        u_method = method_table.get(useless_rids[x])
        useless_xrefs = u_method.get_xrefs()
        for y in range(len(useless_xrefs)):
            xref_info = useless_xrefs[y]
            method_rid = xref_info[0]
            instr_offset = xref_info[1]
            method_obj = dotnet.get_method_by_rid(method_rid)
            method_disasm = method_obj.disassemble_method()
            instr = method_disasm.get_instr_at_offset(instr_offset)
            instr_arg = instr.get_argument()
            dotnet.patch_instruction(method_obj, useless_methods[instr_arg.get_rid()], instr.get_instr_offset(), instr.get_instr_size())

    # Check for useless memberref calls.

    for x in range(1, len(memberref_table) + 1):
        memberref = memberref_table.get(x)
        if memberref.is_method():
            method_impl = memberref.get_method_impl()
            if method_impl and method_impl.get_rid() in useless_methods.keys():
                for method_rid, instr_offset in memberref.get_xrefs():
                    method_obj = dotnet.get_method_by_rid(method_rid)
                    method_disasm = method_obj.disassemble_method()
                    instr = method_disasm.get_instr_at_offset(instr_offset)
                    dotnet.patch_instruction(method_obj, useless_methods[method_impl.get_rid()],
                                             instr.get_instr_offset(), instr.get_instr_size())

    # now search for junk methods
    for x in range(1, len(method_table) + 1):
        method = method_table.get(x)
        if method.has_body():
            disasm_obj = method.disassemble_method()
            for y in range(len(disasm_obj)):
                instr = disasm_obj.get_instr_at_index(y)
                if instr.get_name() == 'call' or instr.get_name() == 'callvirt':
                    arg_obj = instr.get_argument()
                    if isinstance(arg_obj, net_row_objects.MethodDef) and arg_obj.has_body():
                        if __is_modified_method(dotnet, arg_obj):
                            continue
                        junk_id = __is_junk_method(dotnet, arg_obj)
                        if junk_id != 0:
                            if junk_id == 1:
                                # replace with ldc.i4.1 instruction
                                patch = bytes(
                                    [net_opcodes.Opcodes.Ldc_I4_1])
                                patch = ((instr.get_instr_size() - len(patch))
                                         * b'\x00') + patch
                                dotnet.patch_instruction(
                                    method, patch, instr.get_instr_offset(), instr.get_instr_size())
                            elif junk_id == 2:
                                # replace with ldnull instruction.
                                patch = bytes(
                                    [net_opcodes.Opcodes.Ldnull])
                                patch = ((instr.get_instr_size() - len(patch))
                                         * b'\x00') + patch
                                dotnet.patch_instruction(
                                    method, patch, instr.get_instr_offset(), instr.get_instr_size())
    return dotnet.reconstruct_executable()

cdef bint has_prefix(bytes type_name):
    cdef list prefixes
    cdef bytes nums
    cdef bytes prefix
    cdef bytes check
    cdef int x
    cdef int y
    prefixes = [b'Class', b'NameSpace', b'field', b'param', b'Method', b'Property', b'VirtualMethod',
            b'mfield', b'gparam']
    nums = b'0123456789'
    if type_name.startswith(b'set_') or type_name.startswith(b'get_') or type_name.startswith(b'op_'):
        return True
    for x in range(len(prefixes)):
        prefix = prefixes[x]
        if type_name.startswith(prefix):
            check = type_name.replace(prefix, b'')
            for y in range(len(check)):
                item = check[y]
                if item not in nums:
                    return False
            return True

    return False

cdef void check_type(net_row_objects.MethodDefOrRef method_obj, net_row_objects.TypeDefOrRef type_obj, bytes parent_method_name, int new_method_name,
                                    net_sigs.MethodSig parent_method_signature, list checked_types, dict method_names):
    
    cdef net_row_objects.TypeDefOrRef superclass_type
    cdef bytes name
    cdef list types_to_check
    cdef net_row_objects.MethodDefOrRef method2
    cdef net_row_objects.TypeDefOrRef interface
    cdef net_row_objects.TypeDefOrRef int_obj
    cdef net_row_objects.ColumnValue col_val
    cdef net_row_objects.TypeDefOrRef tdefref
    cdef long x
    cdef long y
    cdef list methods
    cdef list interfaces
    cdef int new_index = new_method_name
    cdef net_processing.StringHeapObject string_heap = method_obj.get_dotnetpe().get_heap('#Strings')
    if type_obj == None:
        return
    if type_obj in checked_types:
        return
    checked_types.append(type_obj)
    superclass_type = type_obj.get_superclass()
    types_to_check = list()
    if superclass_type:
        types_to_check.append(superclass_type)

        methods = superclass_type.get_methods()

        for x in range(len(methods)):
            method2 = methods[x]
            if method2.get_column('Name').get_original_value() == parent_method_name:
                if parent_method_signature == method2.get_method_signature():
                    if isinstance(method2, net_row_objects.MemberRef) and isinstance(superclass_type, net_row_objects.TypeRef):
                        #for this situation, make the method name the name of the memberref.
                        new_index = method2.get_column('Name').get_raw_value()
                        break
                    col_val = method2.get_column('Name')
                    if col_val.get_raw_value() not in method_names:
                        name = col_val.get_original_value()
                    else:
                        name = method_names[col_val.get_raw_value()]
                    if not has_prefix(name):
                        col_val.set_raw_value(new_index)
                    else:
                        new_index = col_val.get_raw_value()
    interfaces = method_obj.get_parent_type().get_interfaces()
    for x in range(len(interfaces)):
        interface = interfaces[x]
        int_obj = interface
        if isinstance(interface, net_row_objects.TypeSpec):
            int_obj = interface.get_type()
        types_to_check.append(int_obj)
        methods = int_obj.get_methods()
        for y in range(len(methods)):
            method2 = methods[y]
            col_val = method2.get_column('Name')
            if col_val.get_raw_value() in method_names:
                name = method_names[col_val.get_raw_value()]
            else:
                name = col_val.get_original_value()
            if name == parent_method_name:
                if parent_method_signature == method2.get_method_signature():
                    if not has_prefix(name):
                        col_val.set_raw_value(new_index)
                    else:
                        new_index = col_val.get_raw_value()
        methods = int_obj.get_member_refs()
        for y in range(len(methods)):
            method2 = methods[y]
            col_val = method2.get_column('Name')

            if col_val.get_original_value() == parent_method_name:
                if parent_method_signature == method2.get_method_signature():
                    if col_val.get_raw_value() not in method_names:
                        name = col_val.get_original_value()
                    else:
                        name = method_names[col_val.get_raw_value()]
                    if not has_prefix(name):
                        col_val.set_raw_value(new_index)
                    else:
                        col_val.get_raw_value()
    method_obj.get_column('Name').set_raw_value(new_index)

    for x in range(len(types_to_check)):
        tdefref = types_to_check[x]
        check_type(
            method_obj, tdefref, parent_method_name, new_index, parent_method_signature, checked_types, method_names)

cpdef bytes cleanup_names(bytes data,
                  bint change_namespaces=True,
                  bint change_method_names=True,
                  bint change_param_names=True,
                  bint change_module_name=True,
                  bint change_type_names=True,
                  bint change_field_names=True,
                  bint change_property_names=True,
                  bint force_main_method=True,
                  bint change_import_names=True) except *:
    """
    Changes various names throughout the binary to more readable values
    Intended for instances when the names have been obfuscated.
    This function will recover what it can, but for the most part only imported functions can be changed to original names.
    Additionally this function now supports inheritence and can be used on more complex binaries.
    :param data: the original binary data
    All other parameters are to control what is changed.  By default everything is changed.
    :param change_namespaces: Should namespace names be changed?
    :param change_method_names: Should method names be changed?
    :param change_param_names: Should parameter names be changed?
    :param change_module_name: Should the module name be changed?
    :param change_type_names: Should type names be changed?
    :param change_field_names: Should field names be changed?
    :param change_property_names: Should property names be changed?
    :param force_main_method:  Should the entrypoint be forced to have a name of "Main"?
    """
    cdef dotnetpefile.DotNetPeFile dotnetpe = dotnetpefile.DotNetPeFile(pe_data=data)
    cdef unsigned int namespace_count
    cdef unsigned int class_count
    cdef list blacklisted_methods
    cdef list blacklisted_types
    cdef list blacklisted_method_rids
    cdef list blacklisted_field_rids
    cdef unsigned int module_count
    cdef net_row_objects.RowObject row_obj
    cdef net_row_objects.MethodDefOrRef method
    cdef net_table_objects.TableObject implmap_table
    cdef net_row_objects.RowObject item
    cdef str table_name
    cdef unsigned long table_rid
    cdef bytes name
    cdef long u_index
    cdef list typedefs
    cdef dict changed_namespaces
    cdef net_row_objects.TypeDef typedef
    cdef unsigned int field_count
    cdef unsigned int method_count
    cdef bytes old_value
    cdef bytes new_value
    cdef unsigned int param_count
    cdef net_row_objects.RowObject param
    cdef unsigned int gparam_count
    cdef unsigned int fcount
    cdef net_row_objects.Field fitem
    cdef net_row_objects.MemberRef memberref
    cdef unsigned int num_prop
    cdef net_table_objects.TableObject properties
    cdef net_row_objects.RowObject prop
    cdef net_row_objects.MethodDefOrRef getter_method
    cdef net_row_objects.MethodDefOrRef setter_method
    cdef list semantics
    cdef net_row_objects.MethodSemantic semantic
    cdef bytes setter_name
    cdef bytes getter_name
    cdef bytes property_name
    cdef str property_name_str
    cdef net_row_objects.MethodDef ep_method
    cdef bytes ep_name
    cdef unsigned long vmethod_id
    cdef net_row_objects.MethodImpl method_impl
    cdef net_table_objects.MethodImplTable method_impl_table
    cdef bytes new_name
    cdef net_row_objects.TypeDefOrRef interface
    cdef net_row_objects.TypeDefOrRef iface_obj
    cdef list checked_types
    cdef net_row_objects.TypeDefOrRef parent_type
    cdef long x
    cdef long y
    cdef long z
    cdef list methods_list
    cdef net_table_objects.TableObject param_table
    cdef net_table_objects.TableObject table_obj1
    cdef net_table_objects.TableObject table_obj2
    cdef net_table_objects.MethodSemanticsTable semantics_table
    cdef int new_offset = 0
    cdef net_processing.StringHeapObject string_heap = None
    cdef net_row_objects.ColumnValue col_val = None
    cdef net_row_objects.ColumnValue col_val2 = None
    cdef dict method_names = dict()
    if dotnetpe is None:
        raise net_exceptions.InvalidArgumentsException()
    string_heap = dotnetpe.get_heap('#Strings')
    namespace_count = 0
    class_count = 0
    # Add more common method names here that should not be manipulated.
    blacklisted_methods = [
        b'.cctor',
        b'Main',
        b'.ctor',
        b'Equals',
        b'Finalize',
        b'GetHashCode',
        b'GetType',
        b'MemberwiseClone',
        b'ReferenceEquals',
        b'ToString',
        b'Invoke',
        b'BeginInvoke',
        b'EndInvoke',
        b'Compare',
        b'GetEnumerator',
        b'TransformBlock',
        b'TransformFinalBlock',
        b'CreateEncryptor',
        b'CreateDecryptor',
        b'Flush',
        b'Dispose',
        b'ReleaseHandle',
        b'GenerateKey',
        b'GetBytes',
        b'Reset',
        b'Read',
        b'MoveNext',
        b'SetStateMachine'
    ]

    blacklisted_types = [
        b'<Module>',
        b'Program'
    ]

    blacklisted_method_rids = []
    blacklisted_field_rids = []

    # first change the module name
    if change_module_name:
        module_count = 0
        for row_obj in dotnetpe.get_metadata_table('Module'):
            name = make_string(b'Module', module_count)
            row_obj.get_column('Name').change_value(name)
            module_count += 1

    # specifically rename the entrypoint to main.
    # for now, assume COMIMAGE_FLAGS_NATIVE_ENTRYPOINT is not set.
    ep_method = dotnetpe.get_entry_point()
    if ep_method:
        ep_name = ep_method.get_column('Name').get_value_as_bytes()
        if ep_name != b'Main' and force_main_method:
            ep_method.get_column('Name').change_value(b'Main')

    # first deal with the implmap methods
    string_heap.begin_append_tx()
    if change_method_names or change_import_names:
        implmap_table = dotnetpe.get_metadata_table('ImplMap')
        if implmap_table is not None:
            for x in range(1, len(implmap_table) + 1):
                item = implmap_table.get(x)
                method = <net_row_objects.MethodDefOrRef>item.get_column('MemberForwarded').get_value_as_rowobject()
                col_val = item.get_column('ImportName')
                if col_val.get_raw_value() not in method_names:
                    name = item.get_column('ImportName').get_original_value()
                else:
                    name = method_names[col_val.get_raw_value()]
                # apply the new index
                table_name = method.get_table_name()
                table_rid = method.get_rid()
                new_index = string_heap.append_tx(name)
                method_names[new_index] = name
                if table_name == 'MethodDef':
                    method.get_column('Name').set_raw_value(new_index)
                    blacklisted_method_rids.append(
                        table_rid)  # we don't want to rename methods that obviously have the correct name.
                # other option is the field table - likely wont ever happen though.
                else:
                    method.get_column('Name').set_raw_value(new_index)
                    blacklisted_field_rids.append(table_rid)  # we don't want to rename methods that obviously have the correct name.
    string_heap.end_append_tx()
    # first fix types
    u_index = 0
    typedefs = list(dotnetpe.get_metadata_table('TypeDef'))
    changed_namespaces = dict()
    string_heap.begin_append_tx()
    while u_index < len(typedefs):
        typedef = typedefs[u_index]
        field_count = 0
        method_count = 0
        # check the namespace
        col_val = typedef.get_column('TypeNamespace')
        if col_val.get_raw_value() in method_names:
            name = method_names[col_val.get_raw_value()]
        else:
            name = col_val.get_original_value()
        if change_namespaces and col_val.get_raw_value() != 0 and not has_prefix(name):
            if name not in changed_namespaces:
                old_value = name
                new_value = make_string(b'NameSpace', namespace_count)
                new_index = string_heap.append_tx(new_value)
                method_names[new_index] = new_value
                col_val.set_raw_value(new_index)
                namespace_count += 1
                changed_namespaces[old_value] = new_index
            else:
                old_value = name
                new_index = changed_namespaces[old_value]
                col_val.set_raw_value(new_index)

        # check the type name
        col_val = typedef.get_column('TypeName')
        name = col_val.get_original_value()
        if change_type_names and not has_prefix(name) and name not in blacklisted_types:
            new_name = make_string(b'Class', class_count)
            new_index = string_heap.append_tx(new_name)
            method_names[new_index] = new_name
            col_val.set_raw_value(new_index)
            class_count += 1

        # check methods
        if change_method_names:
            methods_list = typedef.get_column('MethodList').get_formatted_value()
            for x in range(len(methods_list)):
                method = methods_list[x]
                # a lot of these conditions have to do with avoiding renaming methods that will cause errors if the code is exported.
                if method.get_rid() in blacklisted_method_rids:
                    continue

                if method.is_virtual():
                    continue

                if method.is_abstract():
                    continue
                col_val = method.get_column('Name')
                if col_val.get_raw_value() not in method_names:
                    name = col_val.get_original_value()
                else:
                    name = method_names[col_val.get_raw_value()]
                if not has_prefix(name) and name not in blacklisted_methods:
                    new_name = make_string(b'Method', method_count)
                    new_index = string_heap.append_tx(new_name)
                    method_names[new_index] = new_name
                    col_val.set_raw_value(new_index)
                    method_count += 1
        u_index += 1
    string_heap.end_append_tx()

    # next fix params
    u_index = 0
    param_count = 0
    if change_param_names: #TODO: takes too long
        if dotnetpe.has_metadata_table('Param'):
            string_heap.begin_append_tx()
            param_table = dotnetpe.get_metadata_table('Param')
            for x in range(1, len(param_table) + 1):
                param = param_table.get(x)
                col_val = param.get_column('Name')
                if col_val.get_raw_value() in method_names:
                    new_name = method_names[col_val.get_raw_value()]
                else:
                    new_name = col_val.get_original_value()
                if new_name is not None and has_prefix(new_name):
                    continue
                new_name = make_string(b'param', param_count)
                new_index = string_heap.append_tx(new_name)
                method_names[new_index] = new_name
                col_val.set_raw_value(new_index)
                param_count += 1
            string_heap.end_append_tx()

        if dotnetpe.has_metadata_table('GenericParam'):
            gparam_count = 0
            param_table = dotnetpe.get_metadata_table('GenericParam')
            string_heap.begin_append_tx()
            for x in range(1, len(param_table) + 1):
                param = param_table[x]
                new_name = make_string(b'gparam', gparam_count)
                new_index = string_heap.append_tx(new_name)
                method_names[new_index] = new_name
                param.get_column('Name').set_raw_value(new_index)
                gparam_count += 1
            string_heap.end_append_tx()

    if change_field_names and dotnetpe.has_metadata_table('Field'):
        # get anything in the fields table that hasnt been changed.
        fcount = 0
        table_obj1 = dotnetpe.get_metadata_table('Field')
        table_obj2 = dotnetpe.get_metadata_table('MemberRef')
        string_heap.begin_append_tx()
        for x in range(1, len(table_obj1) + 1):
            fitem = table_obj1.get(x)
            col_val = fitem.get_column('Name')
            if col_val.get_raw_value() not in method_names:
                name = col_val.get_original_value()
            else:
                name = method_names[col_val.get_raw_value()]
            if not has_prefix(name) and fitem.get_rid() not in blacklisted_field_rids:
                new_name = make_string(b'field', fcount)
                new_index = string_heap.append_tx(new_name)
                method_names[new_index] = new_name
                col_val.set_raw_value(new_index)
                fcount += 1
                if table_obj2 is not None:
                    for y in range(1, len(table_obj2) + 1):
                        memberref = table_obj2.get(y)
                        if memberref.is_field():
                            if memberref.get_method_signature() == fitem.get_field_signature() and memberref.get_column('Name').get_original_value() == fitem.get_column('Name').get_original_value():
                                col_val = memberref.get_column('Name')
                                col_val.set_raw_value(new_index)
                                break

        string_heap.end_append_tx()
    # property table
    num_prop = 0
    properties = dotnetpe.get_metadata_table('Property')
    if change_property_names and properties is not None:
        string_heap.begin_append_tx()
        if not dotnetpe.has_metadata_table('MethodSemantics'):
            for x in range(1, len(properties) + 1):
                prop = properties.get(x)
                col_val = prop.get_column('Name')
                if not has_prefix(col_val.get_original_value()):
                    new_name = make_string(b'Property', num_prop)
                    new_index = string_heap.append_tx(new_name)
                    method_names[new_index] = new_name
                    col_val.set_raw_value(new_index)
                    num_prop += 1
        else:
            semantics_table = dotnetpe.get_metadata_table('MethodSemantics')
            for x in range(1, len(properties) + 1):
                prop = properties.get(x)
                semantics = semantics_table.get_semantics_for_item(prop)
                getter_method = None
                setter_method = None
                if len(semantics) != 0:
                    for y in range(len(semantics)):
                        semantic = semantics[y]
                        if semantic.is_setter():
                            setter_method = semantic.get_method()
                        elif semantic.is_getter():
                            getter_method = semantic.get_method()

                        if getter_method != None and setter_method != None:
                            break
                else:
                    col_val = prop.get_column('Name')
                    setter_name = b'set_' + col_val.get_original_value()
                    getter_name = b'get_' + col_val.get_original_value()
                    table_obj2 = dotnetpe.get_metadata_table('MemberRef')
                    for y in range(1, len(table_obj2) + 1):
                        memberref = table_obj2.get(y)
                        col_val = memberref.get_column('Name')
                        if col_val.get_raw_value() in method_names:
                            name = method_names[col_val.get_raw_value()]
                        else:
                            name = col_val.get_original_value()
                        if name == setter_name:
                            setter_method = memberref
                        elif name == getter_name:
                            getter_method = memberref

                        if setter_method != None and getter_method != None:
                            break

                # check if method exists in memberref
                property_name = bytes()
                if setter_method:
                    # if the end of setter method matches name of property, set.
                    col_val = setter_method.get_column('Name')
                    if col_val.get_original_value().startswith(b'set_'):
                        # name is probably correct, use it.
                        property_name = col_val.get_original_value().replace(
                            b'set_', b'')
                        col_val = prop.get_column('Name')
                        if col_val.get_raw_value() in method_names:
                            name = method_names[col_val.get_raw_value()]
                        else:
                            name = col_val.get_original_value()
                        if name != property_name:
                            new_index = string_heap.append_tx(property_name)
                            method_names[new_index] = property_name
                            col_val.set_raw_value(new_index)

                if getter_method:
                    # if the end of setter method matches name of property, set.
                    col_val = getter_method.get_column('Name')
                    if col_val.get_original_value().startswith(b'get_'):
                        # name is probably correct, use it.
                        property_name = col_val.get_original_value().replace(
                            b'get_', b'')
                        col_val = prop.get_column('Name')
                        if col_val.get_raw_value() in method_names:
                            name = method_names[col_val.get_raw_value()]
                        else:
                            name = col_val.get_original_value()
                        if name != property_name:
                            new_index = string_heap.append_tx(property_name)
                            method_names[new_index] = property_name
                            col_val.set_raw_value(new_index)

                # if the method names arent correct, rename the property.
                if len(property_name) == 0: 
                    property_name = make_string(b'Property', num_prop)
                    num_prop += 1
                    new_index = string_heap.append_tx(property_name)
                    method_names[new_index] = property_name

                    if getter_method:
                        getter_method.get_column('Name').set_raw_value(new_index)

                    if setter_method:
                        setter_method.get_column('Name').set_raw_value(new_index)

                    prop.get_column('Name').set_raw_value(new_index)
        string_heap.end_append_tx()

    # first rename root methods
    table_obj1 = dotnetpe.get_metadata_table('MethodDef')

    if change_method_names:
        # go through all the memberrefs, find the root method.
        vmethod_id = 0
        method_impl_table = dotnetpe.get_metadata_table(
            'MethodImpl')
        if method_impl_table is not None:
            string_heap.begin_append_tx()
            for x in range(1, len(method_impl_table) + 1):
                method_impl = method_impl_table.get(x)
                col_val = method_impl.get_declaration().get_column('Name')
                if col_val.get_raw_value() in method_names:
                    name = method_names[col_val.get_raw_value()]
                else:
                    name = col_val.get_original_value()
                if name not in blacklisted_methods:
                    new_name = make_string(b'VirtualMethod', vmethod_id)
                    new_index = string_heap.append_tx(new_name)
                    method_names[new_index] = new_name
                    vmethod_id += 1
                else:
                    new_index = col_val.get_raw_value()
                method_impl.get_body().get_column('Name').set_raw_value(new_index)
                col_val.set_raw_value(new_index)
                interfaces = method_impl.get_class().get_interfaces()
                for y in range(len(interfaces)):
                    interface = interfaces[y]
                    iface_obj = interface
                    if isinstance(interface, net_row_objects.TypeSpec):
                        iface_obj = interface.get_type()
                    if isinstance(iface_obj, net_row_objects.TypeDef):
                        methods_list = iface_obj.get_methods()
                        for z in range(len(methods_list)):
                            method = methods_list[z]
                            # Try not to go around renaming methods that shouldnt be renamed.
                            if not method.is_virtual() or not method.is_abstract():
                                continue
                            # Let MethodImpl table take precedence.
                            if method_impl_table.is_method_in_table(method):
                                continue
                            # NOTE: somewhere here there should probably be a name check.  TODO.
                            col_val = method.get_column('Name')
                            if col_val.get_raw_value() not in method_names:
                                name = col_val.get_original_value()
                            else:
                                name = method_names[col_val.get_raw_value()]
                            if not has_prefix(name) and method.get_method_signature() == method_impl.get_declaration().get_method_signature():
                                method.get_column('Name').set_raw_value(new_index)
                                break
            string_heap.end_append_tx()
        # clean off the rest of the methods
        #first make sure all name columns are initialized
        string_heap.begin_append_tx()
        for x in range(1, len(table_obj1) + 1):
            method = table_obj1.get(x)
            col_val = method.get_column('Name')
            if col_val.get_raw_value() not in method_names:
                name = col_val.get_original_value()
            else:
                name = method_names[col_val.get_raw_value()]
            if method.has_body() and name not in blacklisted_methods:
                if (method.is_virtual() or method.is_abstract()):
                    if method.get_rid() not in blacklisted_method_rids:
                        if not has_prefix(name):
                            name = make_string(b'VirtualMethod', vmethod_id)
                            new_index = string_heap.append_tx(name)
                            method_names[new_index] = name
                            vmethod_id += 1
                        else:
                            new_index = method.get_column('Name').get_raw_value()
                        # check parent classes for same methods.
                        checked_types = list()
                        check_type(method, method.get_parent_type(), method.get_column('Name').get_original_value(), new_index, method.get_method_signature(), checked_types, method_names)
        string_heap.end_append_tx()
        string_heap.begin_append_tx() #Since we are potentially referencing the values we need to append the transaction data.
        table_obj2 = dotnetpe.get_metadata_table('MemberRef')
        for x in range(1, len(table_obj2) + 1):
            memberref = table_obj2.get(x)
            col_val = memberref.get_column('Name')
            if col_val.get_raw_value() not in method_names:
                name = col_val.get_original_value()
            else:
                name = method_names[col_val.get_raw_value()]
            if col_val.get_original_value() == name and isinstance(
                    memberref.get_parent_type(), net_row_objects.TypeSpec):
                parent_type = memberref.get_parent_type().get_type()
                if isinstance(parent_type, net_row_objects.TypeDef):
                    methods_list = parent_type.get_column('MethodList').get_formatted_value()
                    for y in range(len(methods_list)):
                        method = methods_list[y]
                        col_val2 = method.get_column('Name')
                        if col_val2.get_raw_value() not in method_names:
                            new_name = col_val2.get_original_value()
                        else:
                            new_name = method_names[col_val2.get_raw_value()]
                        if new_name == name and memberref.get_method_signature() == method.get_method_signature():
                            col_val.set_raw_value(col_val2.get_raw_value())
                            break
        string_heap.end_append_tx()
    return dotnetpe.reconstruct_executable()


def deobfuscate_method_control_flow(file_data: bytes):
    dpe = dotnetpefile.DotNetPeFile(pe_data=file_data)
    method: net_row_objects.MethodDef
    for method in dpe.get_metadata_table('MethodDef'):
        if method.has_body():
            disasm_obj = method.disassemble_method()
            if method.get_rid() != 55:
                continue
            print('Checking method with RID {} {} {}'.format(method.get_rid(), hex(method.get_token()), method.get_full_name()))
            try:
                fgraph = net_graphing.FunctionGraph(method, debug_print=True)
                for offset in fgraph.get_block_offsets():
                    print('Block at offset {}'.format(hex(offset)))
                """new_graph = fgraph.analyze()
                if new_graph:
                    mrec = net_graphing.GraphRecompiler(method, new_graph)
                    disasm_obj = method.disassemble_method()
                    original_size = disasm_obj.header_size + disasm_obj.code_size
                    new_method_bytes = mrec.recompile_graph()
                    if len(new_method_bytes) < original_size:
                        new_method_bytes += (b'\x00' * (original_size - len(new_method_bytes)))
                    method_offset = dpe.pe.get_offset_from_rva(method['RVA'].get_value())
                    dpe.exe_data = dpe.exe_data[:method_offset] + new_method_bytes + dpe.exe_data[method_offset + original_size:]"""
            except Exception as e:
                print('Error analyzing or recompiling function with RID {}: {}'.format(method.get_rid(), str(e)))
                raise e
    return dpe.reconstruct_executable()