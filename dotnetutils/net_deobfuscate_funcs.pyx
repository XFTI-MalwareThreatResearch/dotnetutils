#cython: language_level=3
#distutils: language=c++

import os

from dotnetutils cimport dotnetpefile, net_tokens, net_row_objects, net_emulator, net_cil_disas, net_processing
from dotnetutils cimport net_opcodes, net_table_objects, net_structs, net_emu_types, net_sigs
from dotnetutils import net_graphing, net_exceptions, net_graph_analyzer
from libc.stdio cimport snprintf
from libc.string cimport memcpy
from cpython.bytes cimport PyBytes_FromStringAndSize, PyBytes_AS_STRING, PyBytes_GET_SIZE, _PyBytes_Resize
from cpython.ref cimport PyObject

cdef bytes make_string(bytes prefix, unsigned int i):
    """ Quick method to create byte string with the following format: <prefix><i>

    Args:
        prefix (bytes): the byte prefix, in UTF-8 encoding.
        i <unsigned int>: The number to append onto the prefix as a byte string.
    
    Returns:
        bytes: a string, with the format b'<prefix><i>'

    Raises:
        net_exceptions.DotNetUtilsException: on internal error.
        
    """
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
    """Intended to remove stuff like this:
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

        Args:
            dotnet (dotnetpefile.DotNetPeFile): the DotNetPeFile to deobfuscate.
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
        if disasm_obj is None:
            continue
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
    """ Removes a special type of string obfuscation from a specific dotnet sample.

    Args:
        dotnet (dotnetpefile.DotNetPeFile): the DotNetPeFile to deobfuscate.
    """
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
            disasm_obj = method_obj.disassemble_method()
            if disasm_obj is None:
                continue
            for instr in disasm_obj:
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
    if disasm_obj is None:
        print('Error getting disasm obj: Method may be encrypted')
        return
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
        result = emu_obj.get_stack().pop_obj()
        method_strings[method_obj] = bytes(result.get_str_data_as_bytes().decode(result.get_str_encoding()).encode('utf-8'))

    string_mapping = dict()
    for method_obj in dotnet.get_metadata_table('MethodDef'):
        if method_obj.has_body() and method_obj not in delegate_mapping.values():
            disasm_obj = method_obj.disassemble_method()
            if disasm_obj is None:
                continue
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


cpdef void remove_unk_obf_1_obfuscation(dotnetpefile.DotNetPeFile dotnet):
    """Temporary method to remove more obfuscation in a sample with hash e6579d0717d17f39f2024280100c9fffb8be1699ccf14d9c708150c0a54fcedb
    Once its determined if the sample is actually .NET Reactor or something else it should be moved to a parser.

    Args:
        dotnet (dotnetpefile.DotNetPeFile): The dotnet file to deobfuscate.
    
    """
    remove_unk_obf_1_junk_loops(dotnet)
    remove_unk_obf_1_string_obfuscation(dotnet)

cpdef void remove_useless_bytearray_conditionals(dotnetpefile.DotNetPeFile dotnet):
    """
    Something seen in possible DotNetReactor samples with hash
    e6579d0717d17f39f2024280100c9fffb8be1699ccf14d9c708150c0a54fcedb

    This removes the following kind of obfuscation:
    if a method does:

    ::

        if (new byte[]{<random constant data>}.Equals(new byte[]{<more constant data, always nonequal to the first}))

    the conditional is always false; this function removes that pattern.

    Example IL::

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

    Args:
        dotnet (dotnetpefile.DotNetPeFile): the dotnet file to deobfuscate.
    """
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
    if not dotnet:
        return

    initialize_arrays = dotnet.get_methods_by_full_name(
        b'System.Runtime.CompilerServices.RuntimeHelpers.InitializeArray')
    if len(initialize_arrays) != 1:
        return

    initialize_array = initialize_arrays[0]
    for method_rid, xref_offset in initialize_array.get_xrefs():
        method_obj = dotnet.get_method_by_rid(method_rid)
        disasm_obj = method_obj.disassemble_method()
        if disasm_obj is None:
            continue
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

cpdef void remove_useless_conditionals(dotnetpefile.DotNetPeFile dotnet, list target_method_rids=[]):
    """Removes conditionals that will either always be true or always false
    currently handles the following cases:
    brtrue.s, brfalse.s, brtrue, brfalse: conditionals like if (6 != 0)
    
    Args:
        dotnet (dotnetpefile.DotNetPeFile): The dotnet exe to deobfuscate.
        target_method_rids (list[int]): The target rids to deobfuscate.  If empty, it will deobfuscate the whole executable.

    """
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

    methods = <net_table_objects.MethodDefTable>dotnet.get_metadata_table('MethodDef')
    for y in range(len(methods)):
        method_obj = <net_row_objects.MethodDef>methods.get(y + 1)
        if not method_obj.has_body() or (check_target_methods and method_obj.get_rid() not in target_method_rids):
            continue

        # make sure were creating a fresh copy every time.
        disas_obj = method_obj.disassemble_method()
        if disas_obj is None:
            continue
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

cdef bytes __is_useless_method(dotnetpefile.DotNetPeFile dpe, net_row_objects.MethodDef method_obj):
    """ A useless method is defined as a method that for instance just pulls all arguments off the stack then does either newobj, callvirt or call then returns
    
    Args:
        dpe (dotnetpefile.DotNetPeFile): The target DotNetPeFile
        method_obj (net_row_objects.Methoddef): The target method
    
    Returns:
        bytes: The bytes that should be patched in for all the method xrefs, bytes() if its not useless.
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
    if disasm_obj is None:
        return bytes()
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
                if len(outer_method_params) == 0:
                    return bytes()
                if inner_method.get_column('Name').get_value_as_bytes() != b'.ctor':
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
                if inner_method.get_column('Name').get_value_as_bytes() != b'.ctor':
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
    """ Used to skip methods that have the following signature: ldnull, ret, nop * x
        This is how i usually patch out old methods with DotNetUtils.
    
    Args:
        dpe (dotnetpefile.DotNetPeFile): the target DotNetPeFile
        method_obj (dotnetpefile.MethodDef): the target method

    Returns:
        bool: True if the method follows the scheme above or cant be parsed, False otherwise.
    """
    cdef net_cil_disas.MethodDisassembler disasm_obj
    cdef net_cil_disas.Instruction instr_one
    cdef net_cil_disas.Instruction instr_two
    cdef net_cil_disas.Instruction instr_three
    disasm_obj = method_obj.disassemble_method()
    if disasm_obj is None:
        return True #Skip invalid methods
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

    Args:
        dpe (dotnetpefile.DotNetPeFile): target DotNetPeFile
        method_obj (net_row_objects.MethodDef): target method

    Returns:
        int: 0 if the method shouldnt be touched, 1 if it should be replaced by an ldc.i4.1, 2 if it should be replaced by ldnull.
    """
    cdef list allowed_instrs
    cdef net_cil_disas.MethodDisassembler disasm_obj
    cdef net_row_objects.RowObject field_id
    cdef bint has_compare
    cdef int method_rid
    cdef unsigned long instr_index
    cdef net_row_objects.MethodDef method_obj2
    cdef net_cil_disas.Instruction instr
    cdef net_sigs.MethodSig msig = None
    cdef Py_ssize_t index = 0

    allowed_instrs = ['nop', 'ceq', 'ldnull', 'ldsfld', 'ret', 'ldc.i4.1']
    # skip getters and setters
    if method_obj.get_column('Name').get_value_as_bytes().startswith(b'get_') or method_obj.get_column('Name').get_value_as_bytes().startswith(b'set_'):
        return 0

    disasm_obj = method_obj.disassemble_method()
    if disasm_obj is None:
        return 0
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
            if disasm_obj is None:
                return 0
            instr = <net_cil_disas.Instruction>disasm_obj.get_instr_at_offset(xref_offset)
            if instr.get_name() == 'stsfld':
                return 0

    # skip property methods that start with get and set
    if has_compare:
        return 1
    msig = method_obj.get_method_signature()
    if len(msig.get_parameters()) == 0 and isinstance(msig.get_return_type(), net_sigs.CorLibTypeSig):
        if msig.get_return_type().get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_OBJECT:
            return 2
        elif msig.get_return_type().get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_BOOLEAN:
            index = len(disasm_obj) - 2
            if len(disasm_obj) > 1 and disasm_obj[index].get_name() == 'ldc.i4.1':
                return 1
    return 0

cpdef void remove_useless_functions(dotnetpefile.DotNetPeFile dotnet) except *:
    """ Removes functions that simply call another function with the same arguments.  Used heavily in confuserex.

    Args:
        dotnet (dotnetpefile.DotNetPeFile): The executable to deobfuscate.
    """
    cdef dict useless_methods
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
    useless_methods = dict()  # dictionary of useless method rids and the instructions to replace them with
    method_table = <net_table_objects.MethodDefTable>dotnet.get_metadata_table('MethodDef')
    if method_table is None:
        return
    memberref_table = <net_table_objects.MemberRefTable>dotnet.get_metadata_table('MemberRef')
    if memberref_table is None:
        return
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
            if method_disasm is None:
                continue
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
                    if method_disasm is None:
                        continue
                    instr = method_disasm.get_instr_at_offset(instr_offset)
                    dotnet.patch_instruction(method_obj, useless_methods[method_impl.get_rid()],
                                             instr.get_instr_offset(), instr.get_instr_size())

    # now search for junk methods
    for x in range(1, len(method_table) + 1):
        method = method_table.get(x)
        if method.has_body():
            disasm_obj = method.disassemble_method()
            if disasm_obj is None:
                continue
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

cdef bint has_prefix(bytes type_name):
    """ Does the provided name include a prefix that we set?

    Args:
        type_name (bytes): The name to check.

    Returns:
        bool: True if the name has a prefix, False otherwise.

    """
    cdef list prefixes
    cdef bytes nums
    cdef bytes prefix
    cdef bytes check
    cdef int x
    cdef int y
    prefixes = [b'Class', b'NameSpace', b'field', b'param', b'Method', b'Property', b'VirtualMethod',
            b'mfield', b'gparam', b'Event']
    nums = b'0123456789'
    if type_name.startswith(b'set_') or type_name.startswith(b'get_') or type_name.startswith(b'op_'):
        return True
    if type_name.startswith(b'raise_') or type_name.startswith(b'add_') or type_name.startswith(b'remove_'):
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

cdef bint is_in_chain(dict method_chains, net_row_objects.MethodDefOrRef mdef, net_row_objects.TypeDefOrRef base_type):
    """ Helper method for method inheritence.  Determines if a method is already in the chain dict.

    Args:
        method_chains (dict[net_row_objects.TypeDefOrRef, dict[net_row_objects.MethodDefOrRef, list[net_row_objects.MethodDefOrRef]]]): The current method_chains dict.
        mdef (net_row_objects.MethodDefOrRef): The method object to check.
        base_type (net_row_objects.TypeDefOrRef): the base type.

    Returns:
        bool: True if the method is within the chains dictionary already.  False otherwise.
    """
    if base_type not in method_chains:
        return False
    cdef dict chain = method_chains[base_type]
    cdef set item = None
    if mdef in chain.keys():
        return True
    for item in chain.values():
        if mdef in item:
            return True
    return False

cdef void find_method_chains(net_table_objects.MethodImplTable methodimpl, net_row_objects.TypeDefOrRef base_type, net_row_objects.TypeDefOrRef tdef, dict inst_sigs, dict override_chains, list sealed_slots):
    """ Fills method_chains with a chain representing the inheritence / hiding / overriding of each method.  Used to ensure certain methods match names.

    Args:
        methodimpl (net_row_objects.MethodImplTable): the MethodImpl table, if it exists.  Can be None.
        base_type: (net_row_objects.TypeDefOrRef): the base type to obtain inheritence for.
        tdef (net_row_objects.TypeDefOrRef): The TypeDef we are currently checking for method chains.
        inst_sigs (dict[net_row_objects.RowObject, Union[net_sigs.GenericInstSig, net_sigs.GenericINstMethodSig]]): a dictionary of all GenericInst sigs from MethodSpecs and TypeSpecs.
        override_chains (dict[net_row_objects.TypeDefOrRef, dict[net_row_objects.MethodDefOrRef, list[net_row_objects.MethodDefOrRef]]]): The output dictionary.
        sealed_slots (list[int]): Tokens of methods which can be considered sealed.
    """
    cdef net_row_objects.TypeDefOrRef ptr = tdef
    cdef net_row_objects.MethodDefOrRef mptr = None
    cdef net_row_objects.MethodDefOrRef mptr2 = None
    cdef bint result = False
    cdef bint found = False

    if base_type not in override_chains:
        override_chains[base_type] = dict()
    if isinstance(ptr, net_row_objects.TypeSpec):
        ptr = ptr.get_type()

    for ptr in tdef.get_interfaces():
        #Again interface methods are all going to be new.
        for mptr in ptr.get_methods():
            if methodimpl is not None:
                mptr2 = methodimpl.get_method_body(mptr)
                if mptr2 is not None:
                    if is_in_chain(override_chains, mptr2, base_type):
                        continue
                    if mptr not in override_chains[base_type]:
                        override_chains[base_type][mptr] = set()
                    override_chains[base_type][mptr].add(mptr2)
                    continue
            if mptr not in override_chains[base_type]:
                override_chains[base_type][mptr] = set()

        #Again interface methods are all going to be new.
        for mptr in ptr.get_member_refs():
            if not isinstance(mptr.get_method_signature(), net_sigs.MethodSig):
                continue
            if methodimpl is not None:
                mptr2 = methodimpl.get_method_body(mptr)
                if mptr2 is not None:
                    if is_in_chain(override_chains, mptr2, base_type):
                        continue
                    if mptr not in override_chains[base_type]:
                        override_chains[base_type][mptr] = set()
                    override_chains[base_type][mptr].add(mptr2)
                    continue
            if mptr not in override_chains[base_type]:
                override_chains[base_type][mptr] = set()

    #now for handling the actual methods and memberrefs
    for mptr in tdef.get_methods():
        found = False
        result = False
        if methodimpl is not None:
            mptr2 = methodimpl.get_method_body(mptr)
            if mptr2 is not None:
                if is_in_chain(override_chains, mptr2, base_type):
                    continue
                if mptr not in override_chains[base_type]:
                    override_chains[base_type][mptr] = set()
                override_chains[base_type][mptr].add(mptr2)
                continue
        if mptr.is_static_method():
            #static methods can only be hidden.
            for mptr2 in list(override_chains[base_type].keys()):
                if mptr2 in sealed_slots:
                    continue
                if mptr2.is_static_method(): #No chance of methodimpl here.
                    if mptr2.get_column('Name').get_value_as_bytes() == mptr.get_column('Name').get_value_as_bytes():
                        if mptr.is_hidebysig():
                            if mptr2 in inst_sigs:
                                if mptr2.get_parent_type() not in inst_sigs:
                                    result = net_sigs.method_sig_compare(mptr.get_method_signature(), mptr2.get_method_signature(), inst_sigs[mptr2], None)
                                else:
                                    result = net_sigs.method_sig_compare(mptr.get_method_signature(), mptr2.get_method_signature(), inst_sigs[mptr2], inst_sigs[mptr2.get_parent_type()])
                            else:
                                if mptr2.get_parent_type() not in inst_sigs:
                                    result = net_sigs.method_sig_compare(mptr.get_method_signature(), mptr2.get_method_signature(), None, None)
                                else:
                                    result = net_sigs.method_sig_compare(mptr.get_method_signature(), mptr2.get_method_signature(), None, inst_sigs[mptr2.get_parent_type()])
                            if result:
                                if is_in_chain(override_chains, mptr, base_type):
                                    continue
                                override_chains[base_type][mptr2].add(mptr)
                                if mptr.is_final():
                                    sealed_slots.append(mptr2)
                                found = True
                                break
                        else:
                            if is_in_chain(override_chains, mptr, base_type):
                                continue
                            if mptr.is_final():
                                sealed_slots.append(mptr2)
                            override_chains[base_type][mptr2].add(mptr)
                            found = True
                            break
            if not found:
                if mptr not in override_chains[base_type]:
                    if mptr.is_final():
                        sealed_slots.append(mptr)
                    override_chains[base_type][mptr] = set()
        else:
            #deal with virtualization.
            if mptr.is_abstract():
                #an abstract method is definitely the base.
                if mptr not in override_chains[base_type]:
                    override_chains[base_type][mptr] = set()
            else:
                if mptr.is_virtual() and not mptr.is_newslot():
                    for mptr2 in list(override_chains[base_type].keys()):
                        if mptr2 in sealed_slots:
                            continue
                        if mptr2.get_column('Name').get_value_as_bytes() == mptr.get_column('Name').get_value_as_bytes():
                            if mptr2 in inst_sigs:
                                if mptr2.get_parent_type() not in inst_sigs:
                                    result = net_sigs.method_sig_compare(mptr.get_method_signature(), mptr2.get_method_signature(), inst_sigs[mptr2], None)
                                else:
                                    result = net_sigs.method_sig_compare(mptr.get_method_signature(), mptr2.get_method_signature(), inst_sigs[mptr2], inst_sigs[mptr2.get_parent_type()])
                            else:
                                if mptr2.get_parent_type() not in inst_sigs:
                                    result = net_sigs.method_sig_compare(mptr.get_method_signature(), mptr2.get_method_signature(), None, None)
                                else:
                                    result = net_sigs.method_sig_compare(mptr.get_method_signature(), mptr2.get_method_signature(), None, inst_sigs[mptr2.get_parent_type()])
                            if result:
                                if is_in_chain(override_chains, mptr, base_type):
                                    continue
                                override_chains[base_type][mptr2].add(mptr)
                                if mptr.is_final():
                                    sealed_slots.append(mptr2)
                                found = True
                                break
                else:
                    #anything else participates in hiding.
                    for mptr2 in list(override_chains[base_type].keys()):
                        if mptr2 in sealed_slots:
                            continue
                        if mptr2.get_column('Name').get_value_as_bytes() == mptr.get_column('Name').get_value_as_bytes():
                            if mptr.is_hidebysig():
                                if mptr2 in inst_sigs:
                                    if mptr2.get_parent_type() not in inst_sigs:
                                        result = net_sigs.method_sig_compare(mptr.get_method_signature(), mptr2.get_method_signature(), inst_sigs[mptr2], None)
                                    else:
                                        result = net_sigs.method_sig_compare(mptr.get_method_signature(), mptr2.get_method_signature(), inst_sigs[mptr2], inst_sigs[mptr2.get_parent_type()])
                                else:
                                    if mptr2.get_parent_type() not in inst_sigs:
                                        result = net_sigs.method_sig_compare(mptr.get_method_signature(), mptr2.get_method_signature(), None, None)
                                    else:
                                        result = net_sigs.method_sig_compare(mptr.get_method_signature(), mptr2.get_method_signature(), None, inst_sigs[mptr2.get_parent_type()])
                                if result:
                                    if is_in_chain(override_chains, mptr, base_type):
                                        continue
                                    override_chains[base_type][mptr2].add(mptr)
                                    if mptr.is_final():
                                        sealed_slots.append(mptr2)
                                    found = True
                                    break
                            else:
                                if is_in_chain(override_chains, mptr, base_type):
                                    continue
                                if mptr.is_final():
                                    sealed_slots.append(mptr2)
                                override_chains[base_type][mptr2].add(mptr)
                                found = True
                                break
            if not found:
                if mptr not in override_chains[base_type]:
                    if mptr.is_final():
                        sealed_slots.append(mptr)
                    override_chains[base_type][mptr] = set()


    for mptr in tdef.get_member_refs():
        result = False
        found = False
        if not isinstance(mptr.get_method_signature(), net_sigs.MethodSig):
            continue #Ignore fields for now.  Handle field memberrefs later.
        #member refs should always implement a method
        if methodimpl is not None:
            mptr2 = methodimpl.get_method_body(mptr)
            if mptr2 is not None:
                if is_in_chain(override_chains, mptr2, base_type):
                    continue
                if mptr not in override_chains[base_type]:
                    override_chains[base_type][mptr] = set()
                override_chains[base_type][mptr].add(mptr2)
                continue
        for mptr2 in list(override_chains[base_type].keys()):
            if mptr2 in sealed_slots:
                continue
            if mptr2.get_column('Name').get_value_as_bytes() == mptr.get_column('Name').get_value_as_bytes():
                if mptr.get_parent_type() in inst_sigs:
                    if mptr in inst_sigs:
                        result = net_sigs.method_sig_compare(mptr.get_method_signature(), mptr2.get_method_signature(), inst_sigs[mptr], inst_sigs[mptr.get_parent_type()])
                    else:
                        result = net_sigs.method_sig_compare(mptr.get_method_signature(), mptr2.get_method_signature(), None, inst_sigs[mptr.get_parent_type()])
                else:
                    if mptr in inst_sigs:
                        result = net_sigs.method_sig_compare(mptr.get_method_signature(), mptr2.get_method_signature(), inst_sigs[mptr], None)
                    else:
                        result = net_sigs.method_sig_compare(mptr.get_method_signature(), mptr2.get_method_signature(), None, None)
                if result:
                    if is_in_chain(override_chains, mptr, base_type):
                        continue
                    override_chains[base_type][mptr2].add(mptr)
                    if mptr2.is_final():
                        sealed_slots.append(mptr2)
                    found = True
                    break
        if not found:
            if mptr not in override_chains[base_type]:
                if mptr.is_final():
                    sealed_slots.append(mptr)
                override_chains[base_type][mptr] = set()

    for ptr in tdef.get_child_classes():
        if isinstance(ptr, net_row_objects.TypeSpec):
            ptr = ptr.get_type()

        if isinstance(ptr, net_row_objects.TypeRef):
            continue
        find_method_chains(methodimpl, base_type, ptr, inst_sigs, override_chains, sealed_slots)


cpdef void cleanup_names(dotnetpefile.DotNetPeFile dotnet,
                  bint change_namespaces=True,
                  bint change_method_names=True,
                  bint change_param_names=True,
                  bint change_module_name=True,
                  bint change_type_names=True,
                  bint change_field_names=True,
                  bint change_property_names=True,
                  bint force_main_method=True,
                  bint change_import_names=True,
                  bint change_events=True) except *:
    """
    Changes various names throughout the binary to more readable values
    Intended for instances when the names have been obfuscated.
    This function will recover what it can, but for the most part only imported functions can be changed to original names.
    Additionally this function now supports inheritence and can be used on more complex binaries.
    Args:
        dotnet (dotnetpefile.DotNetPeFile): The dotnet executable to deobfuscate.
        change_namespaces (bool): Change namespace names, defaults to true.
        change_method_names (bool): Change method names, defaults to true.
        change_param_names (bool): Change GenericParam and Param names, defaults to true.
        change_module_names (bool): Change Module names, defaults to true.
        change_type_names (bool): Change TypeDef names, defaults to true.
        change_field_names (bool): Change FieldDef names, defaults to true.
        change_property_names (bool): Change PropertyDef names, defaults to true.
        force_main_method (bool): Force the name of the entrypoint to be Main, defaults to true.
        change_import_names (bool): Change names of imported methods from C dlls to proper names.  Defaults to true.
        change_events (bool): Change Event names, defaults to true.

    Raises:
        net_exceptions.InvalidArgumentsException: If the data is None or invalid, or doesnt have a #Strings heap.

    """
    cdef net_processing.StringHeapObject strings_heap = None
    cdef Py_ssize_t x = 0
    cdef net_row_objects.RowObject row_obj = None
    cdef net_row_objects.ColumnValue col_val = None
    cdef int count = 0
    cdef net_row_objects.MethodDef mdef_obj = None
    cdef net_row_objects.MethodDefOrRef mdefref_obj = None
    cdef net_row_objects.MethodDefOrRef mdefref2_obj = None
    cdef net_row_objects.MethodDefOrRef mdefref3_obj = None
    cdef net_row_objects.TypeDefOrRef tdefref = None
    cdef net_row_objects.TypeDefOrRef tdefref_ptr = None
    cdef net_table_objects.TableObject table_obj = None
    cdef dict inst_sigs = dict()
    cdef list blocklisted_methods = [
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
        b'SetStateMachine',
        b'Finalize'
    ]

    cdef list blocklisted_types = [
        b'<Module>',
        b'Program'
    ]

    cdef bytes name = None
    cdef int new_index = 0
    cdef net_row_objects.RowObject row_obj2 = None
    cdef int count2 = 0
    cdef dict changed_namespaces = dict()
    cdef net_table_objects.TableObject table_obj2 = None
    cdef net_row_objects.MethodSemantic msemantic = None
    cdef net_table_objects.MethodSemanticsTable msem_table = None
    cdef net_row_objects.TypeDefOrRef interface = None
    cdef list msemantics = None
    cdef bytes temp_name = None
    cdef bytes prop_name = None
    cdef dict method_chains = dict()
    cdef list sealed_methods = list()
    cdef dict type_method_chain = None
    cdef set chained_methods = None
    cdef list renamed_methods = list()
    cdef net_table_objects.MethodImplTable methodimpl = dotnet.get_metadata_table('MethodImpl')
    cdef net_sigs.CallingConventionSig csig = None
    cdef bint found = False
    cdef net_sigs.TypeSig tsig = None
    cdef list ran_inheritence = list()


    if dotnet is None:
        raise net_exceptions.InvalidArgumentsException()

    strings_heap = dotnet.get_heap('#Strings')

    if strings_heap is None:
        raise net_exceptions.InvalidArgumentsException()

    """
    Start off with the easy things to get that over with.
    """
    if change_module_name:
        for row_obj in dotnet.get_metadata_table('Module'):
            name = make_string(b'Module', count)
            row_obj.get_column('Name').change_value(name)
            count += 1
    count = 0
    mdef_obj = dotnet.get_entry_point()
    if mdef_obj is not None and force_main_method:
        ep_name = mdef_obj.get_column('Name').get_value_as_bytes()
        if ep_name != b'Main':
            mdef_obj.get_column('Name').change_value(b'Main')
            renamed_methods.append(mdef_obj.get_token())

    """
    This part is pretty consistent - sometimes .NET obfuscators will change the names of C imported functions, those we can recover with certainty.
    """
    strings_heap.begin_append_tx()
    if change_method_names or change_import_names:
        table_obj = dotnet.get_metadata_table('ImplMap')
        if table_obj is not None:
            for x in range(1, len(table_obj) + 1):
                row_obj = table_obj.get(<int>x)
                col_val = row_obj.get_column('ImportName')
                row_obj2 = row_obj.get_column('MemberForwarded').get_value_as_rowobject()
                name = row_obj.get_column('ImportName').get_original_value()
                # apply the new index
                if row_obj2.get_column('Name').get_value_as_bytes() != name:
                    new_index = strings_heap.append_tx(name)
                    row_obj2.get_column('Name').set_raw_value(new_index)
                renamed_methods.append(row_obj2.get_token())
    strings_heap.end_append_tx()

    """
    Now we can handle Type names since those should be pretty consistent.  Save methods for later.
    """

    count = 0
    table_obj = dotnet.get_metadata_table('TypeDef')
    if table_obj is not None and (change_type_names or change_namespaces):
        strings_heap.begin_append_tx()
        for x in range(1, len(table_obj) + 1):
            row_obj = table_obj.get(<int>x)
            name = row_obj.get_column('TypeName').get_value_as_bytes()
            if name not in blocklisted_types and not has_prefix(name) and change_type_names:
                name = make_string(b'Class', count)
                count += 1
                new_index = strings_heap.append_tx(name)
                row_obj.get_column('TypeName').set_raw_value(new_index)

            #now handle TypeNamespace
            name = row_obj.get_column('TypeNamespace').get_value_as_bytes()
            if name is not None and not has_prefix(name) and change_namespaces:
                if name not in changed_namespaces:
                    prop_name = name
                    name = make_string(b'NameSpace', count2)
                    count2 += 1
                    new_index = strings_heap.append_tx(name)
                    row_obj.get_column('TypeNamespace').set_raw_value(new_index)
                    changed_namespaces[prop_name] = new_index
                else:
                    row_obj.get_column('TypeNamespace').set_raw_value(changed_namespaces[name])
        strings_heap.end_append_tx()
    count = 0
    count2 = 0
    if change_param_names:
        table_obj = dotnet.get_metadata_table('Param')
        if table_obj is not None:
            strings_heap.begin_append_tx()
            for x in range(1, len(table_obj) + 1):
                row_obj = table_obj.get(<int>x)
                col_val = row_obj.get_column('Name')
                name = col_val.get_value_as_bytes()
                if name is None or not has_prefix(name):
                    name = make_string(b'param', count)
                    count += 1
                    new_index = strings_heap.append_tx(name)
                    col_val.set_raw_value(new_index)
            strings_heap.end_append_tx()
        count = 0

        table_obj = dotnet.get_metadata_table('GenericParam')
        if table_obj is not None:
            strings_heap.begin_append_tx()
            for x in range(1, len(table_obj) + 1):
                row_obj = table_obj.get(<int>x)
                col_val = row_obj.get_column('Name')
                name = col_val.get_value_as_bytes()
                if name is None or not has_prefix(name):
                    name = make_string(b'gparam', count)
                    count += 1
                    new_index = strings_heap.append_tx(name)
                    col_val.set_raw_value(new_index)
            strings_heap.end_append_tx()
            count = 0
    if change_field_names:
        table_obj = dotnet.get_metadata_table('Field')
        if table_obj is not None:
            strings_heap.begin_append_tx()
            for x in range(1, len(table_obj) + 1):
                row_obj = table_obj.get(<int>x)
                col_val = row_obj.get_column('Name')
                name = col_val.get_value_as_bytes()
                if name is None or not has_prefix(name):
                    name = make_string(b'field', count)
                    count += 1
                    new_index = strings_heap.append_tx(name)
                    col_val.set_raw_value(new_index)
            strings_heap.end_append_tx()
            count = 0
    #Ok so now comes the hard part: type inheritence chains.
    #For these, lets start at our base classes and walk down.
    count = 0
    if change_method_names:
        #Change method names by iterating the type inheritence chain.
        table_obj = dotnet.get_metadata_table('TypeSpec')
        #First get a listing of all instance sigs.
        if table_obj is not None:
            for x in range(1, len(table_obj) + 1):
                row_obj = table_obj.get(<int>x)
                inst_sigs[row_obj] = row_obj.get_sig_obj()
        table_obj = dotnet.get_metadata_table('MethodSpec')
        if table_obj is not None:
            for x in range(1, len(table_obj) + 1):
                row_obj = table_obj.get(<int>x)
                inst_sigs[row_obj] = row_obj.get_sig_obj()
        table_obj = dotnet.get_metadata_table('TypeDef')
        if table_obj is not None:
            for x in range(1, len(table_obj) + 1):
                tdefref = table_obj.get(<int>x)
                tdefref_ptr = tdefref.get_superclass()
                if isinstance(tdefref_ptr, net_row_objects.TypeSpec):
                    tdefref_ptr = tdefref_ptr.get_type()
                if tdefref_ptr is None or isinstance(tdefref_ptr, net_row_objects.TypeRef):
                    if tdefref_ptr is None:
                        if tdefref.get_token() not in ran_inheritence:
                            find_method_chains(methodimpl, tdefref, tdefref, inst_sigs, method_chains, sealed_methods)
                            ran_inheritence.append(tdefref.get_token())
                    else:
                        if tdefref_ptr.get_token() not in ran_inheritence:
                            find_method_chains(methodimpl, tdefref_ptr, tdefref_ptr, inst_sigs, method_chains, sealed_methods)
                            ran_inheritence.append(tdefref_ptr.get_token())
        count = 0
        strings_heap.begin_append_tx()
        for tdefref_ptr, type_method_chain in method_chains.items(): #TODO swap to list to allow for ordering
            for mdefref_obj, chained_methods in type_method_chain.items():
                tdefref = mdefref_obj.get_parent_type()
                name = None
                if isinstance(tdefref, net_row_objects.TypeSpec):
                    tdefref = tdefref.get_type()
                if isinstance(tdefref, net_row_objects.TypeRef):
                    name = mdefref_obj.get_column('Name').get_value_as_bytes()

                if mdefref_obj.get_column('Name').get_value_as_bytes() in blocklisted_methods:
                    name = mdefref_obj.get_column('Name').get_value_as_bytes()
                
                if name is None:
                    for mdefref2_obj in chained_methods:
                        tdefref = mdefref2_obj.get_parent_type()
                        if isinstance(tdefref, net_row_objects.TypeSpec):
                            tdefref = tdefref.get_type()
                        if isinstance(tdefref, net_row_objects.TypeRef):
                            name = mdefref2_obj.get_column('Name').get_value_as_bytes()
                            break
                if name is None:
                    name = make_string(b'Method', count)
                    count += 1
                new_index = strings_heap.append_tx(name)
                if mdefref_obj.get_token() not in renamed_methods:
                    mdefref_obj.get_column('Name').set_raw_value(new_index)
                    renamed_methods.append(mdefref_obj.get_token())
                for mdefref2_obj in chained_methods:
                    if mdefref2_obj.get_token() not in renamed_methods:
                        mdefref2_obj.get_column('Name').set_raw_value(new_index)
                        renamed_methods.append(mdefref2_obj.get_token())
        strings_heap.end_append_tx()
        table_obj = dotnet.get_metadata_table('MemberRef')
        if table_obj is not None:
            for x in range(1, len(table_obj) + 1):
                row_obj = table_obj.get(<int>x)
                tdefref = row_obj.get_parent_type()
                tdefref_ptr = None
                tsig = None
                found = False

                if isinstance(tdefref, net_row_objects.TypeSpec):
                    tdefref_ptr = tdefref
                    tdefref = tdefref.get_type()
                    tsig = tdefref_ptr.get_sig_obj()


                if isinstance(tdefref, net_row_objects.TypeRef):
                    continue
                csig = row_obj.get_method_signature()
                if csig is not None:
                    if isinstance(csig, net_sigs.MethodSig):
                        continue
                    if isinstance(csig, net_sigs.FieldSig):
                        for row_obj2 in tdefref.get_column('FieldList').get_formatted_value():
                            if row_obj2.get_column('Name').get_original_value() == row_obj.get_column('Name').get_original_value():
                                if net_sigs.field_sig_compare(row_obj2.get_field_signature(), csig, None, tsig):
                                    row_obj.get_column('Name').set_raw_value(row_obj2.get_column('Name').get_raw_value())
                                    found = True

                if not found:
                    print('Warning: memberref field not found.')
    count = 0
    if change_property_names:
        table_obj = dotnet.get_metadata_table('Property')
        msem_table = dotnet.get_metadata_table('MethodSemantics')
        if table_obj is not None:
            strings_heap.begin_append_tx()
            for x in range(1, len(table_obj) + 1):
                row_obj = table_obj.get(<int>x)
                col_val = row_obj.get_column('Name')
                name = col_val.get_value_as_bytes()
                mdefref_obj = None
                mdefref2_obj = None
                prop_name = None
                if name is None or not has_prefix(name):
                    if msem_table is None:
                        name = make_string(b'Property', count)
                        count += 1
                        new_index = strings_heap.append_tx(name)
                        col_val.set_raw_value(new_index)
                    else:
                        msemantics = msem_table.get_semantics_for_item(row_obj)
                        if len(msemantics) == 0:
                            name = make_string(b'Property', count)
                            count += 1
                            new_index = strings_heap.append_tx(name)
                            col_val.set_raw_value(new_index)
                        else:
                            for msemantic in msemantics:
                                if msemantic.is_getter():
                                    mdefref_obj = <net_row_objects.MethodDefOrRef>msemantic.get_method()
                                elif msemantic.is_setter():
                                    mdefref2_obj = <net_row_objects.MethodDefOrRef>msemantic.get_method()
                                if mdefref_obj and mdefref2_obj:
                                    break

                            if mdefref_obj is not None:
                                temp_name = mdefref_obj.get_column('Name').get_value_as_bytes()
                                if temp_name is not None and temp_name.startswith(b'get_'):
                                    prop_name = temp_name.lstrip(b'get_')

                            if mdefref2_obj is not None and prop_name is None:
                                temp_name = mdefref2_obj.get_column('Name').get_value_as_bytes()
                                if temp_name is not None and temp_name.startswith(b'set_'):
                                    prop_name = temp_name.lstrip(b'set_')
                            
                            if prop_name is None:
                                prop_name = make_string(b'Property', count)
                                count += 1
                            
                            if mdefref_obj is not None and mdefref_obj.get_column('Name').get_value_as_bytes() != (b'get_' + prop_name):
                                new_index = strings_heap.append_tx(b'get_' + prop_name)
                                mdefref_obj.get_column('Name').set_raw_value(new_index)

                            if mdefref2_obj is not None and mdefref2_obj.get_column('Name').get_value_as_bytes() != (b'set_' + prop_name):
                                new_index = strings_heap.append_tx(b'set_' + prop_name)
                                mdefref2_obj.get_column('Name').set_raw_value(new_index)
                            if col_val.get_value_as_bytes() != prop_name:
                                new_index = strings_heap.append_tx(prop_name)
                                col_val.set_raw_value(new_index)
            strings_heap.end_append_tx()
            count = 0
    if change_events:
        table_obj = dotnet.get_metadata_table('Event')
        msem_table = dotnet.get_metadata_table('MethodSemantics')
        if table_obj is not None:
            strings_heap.begin_append_tx()
            for x in range(1, len(table_obj) + 1):
                row_obj = table_obj.get(<int>x)
                col_val = row_obj.get_column('Name')
                name = col_val.get_value_as_bytes()
                mdefref_obj = None
                mdefref2_obj = None
                mdefref3_obj = None
                prop_name = None
                if name is None or not has_prefix(name):
                    if msem_table is None:
                        name = make_string(b'Event', count)
                        count += 1
                        new_index = strings_heap.append_tx(name)
                        col_val.set_raw_value(new_index)
                    else:
                        msemantics = msem_table.get_semantics_for_item(row_obj)
                        if len(msemantics) == 0:
                            name = make_string(b'Event', count)
                            count += 1
                            new_index = strings_heap.append_tx(name)
                            col_val.set_raw_value(new_index)
                        else:
                            for msemantic in msemantics:
                                if msemantic.is_add_on():
                                    mdefref_obj = <net_row_objects.MethodDefOrRef>msemantic.get_method()
                                elif msemantic.is_remove_on():
                                    mdefref2_obj = <net_row_objects.MethodDefOrRef>msemantic.get_method()
                                elif msemantic.is_fire():
                                    mdefref3_obj = <net_row_objects.MethodDefOrRef>msemantic.get_method()
                                if mdefref_obj and mdefref2_obj and mdefref3_obj:
                                    break

                            if mdefref_obj is not None:
                                temp_name = mdefref_obj.get_column('Name').get_value_as_bytes()
                                if temp_name is not None and temp_name.startswith(b'add_'):
                                    prop_name = temp_name.lstrip(b'add_')

                            if mdefref2_obj is not None and prop_name is None:
                                temp_name = mdefref2_obj.get_column('Name').get_value_as_bytes()
                                if temp_name is not None and temp_name.startswith(b'remove_'):
                                    prop_name = temp_name.lstrip(b'remove_')

                            if mdefref3_obj is not None and prop_name is None:
                                temp_name = mdefref3_obj.get_column('Name').get_value_as_bytes()
                                if temp_name is not None and temp_name.startswith(b'raise_'):
                                    prop_name = temp_name.lstrip(b'raise_')
                            
                            
                            if prop_name is None:
                                prop_name = make_string(b'Event', count)
                                count += 1
                            
                            if mdefref_obj is not None and mdefref_obj.get_column('Name').get_value_as_bytes() != (b'add_' + prop_name):
                                new_index = strings_heap.append_tx(b'add_' + prop_name)
                                mdefref_obj.get_column('Name').set_raw_value(new_index)

                            if mdefref2_obj is not None and mdefref2_obj.get_column('Name').get_value_as_bytes() != (b'remove_' + prop_name):
                                new_index = strings_heap.append_tx(b'remove_' + prop_name)
                                mdefref2_obj.get_column('Name').set_raw_value(new_index)
                            if mdefref3_obj is not None and mdefref3_obj.get_column('Name').get_value_as_bytes() != (b'raise_' + prop_name):
                                new_index = strings_heap.append_tx(b'remove_' + prop_name)
                                mdefref3_obj.get_column('Name').set_raw_value(new_index)
                            if col_val.get_value_as_bytes() != prop_name:
                                new_index = strings_heap.append_tx(prop_name)
                                col_val.set_raw_value(new_index)
            strings_heap.end_append_tx()
            count = 0


cpdef void deobfuscate_control_flow(dotnetpefile.DotNetPeFile dotnet, list target_rids=None):
    """ A control flow deobfuscator.  Deobfuscates control flow obfuscation that uses switch statements to produce constant outcomes.
        Currently in development.  There may be issues.  Currently doesnt support methods with try catch finally filter.
    
    Args:
        dotnet (dotnetpefile.DotNetPeFile): The dotnetpe to deobfuscate
        target_rids (list[int]): Rids of methods to target.  None for all.
        
    """
    cdef net_table_objects.TableObject mspec_table = dotnet.get_metadata_table('MethodSpec')
    cdef set mspec_methods = set()
    cdef net_row_objects.MethodSpec mspec = None
    cdef net_row_objects.MethodDef mobj = None
    cdef object fgraph = None
    cdef object fanalyzer = None
    cdef object new_graph = None
    cdef set mspecs_completed = set()
    for mspec in mspec_table:
        mspec_methods.add(mspec.get_method().get_rid())
    for mobj in dotnet.get_metadata_table('MethodDef'):
        if not mobj.has_body():
            continue
        if mobj.get_rid() in mspec_methods:
            continue
        if mobj.disassemble_method() is None:
            continue
        print('Deobfuscating control flow for method', hex(mobj.get_token()))
        fgraph = net_graphing.FunctionGraph(mobj)
        fgraph.validate_blocks()
        fanalyzer = net_graph_analyzer.GraphAnalyzer(mobj, fgraph)
        try:
            new_graph = fanalyzer.simplify_control_flow()
            if new_graph is None:
                print('function is not obfuscated.')
                continue
        except net_exceptions.EmulatorExecutionException as e:
            print('emulation failed due to error')
            continue
        except net_exceptions.ControlFlowDeobfuscationMisidentify as e:
            print('Possible control flow misidentification:', str(e))
            continue
        #new_graph.print_root()
        print('Done with control flow check')
    for mspec in mspec_table:
        method = mspec.get_method()
        if method.get_rid() in mspecs_completed:
            continue
        mspecs_completed.add(method.get_rid())
        if method.disassemble_method() is None:
            continue
        if not method.has_body():
            continue
        fgraph = net_graphing.FunctionGraph(mspec)
        fgraph.validate_blocks()
        fanalyzer = net_graph_analyzer.GraphAnalyzer(mspec, fgraph)
        try:
            new_graph = fanalyzer.simplify_control_flow()
            if new_graph is None:
                print('function is not obfuscated.')
                continue
        except net_exceptions.EmulatorExecutionException as e:
            print('emulation failed due to error', str(e))
            continue
        except net_exceptions.ControlFlowDeobfuscationMisidentify as e:
            print('Possible control flow misidentification:', str(e))
            continue