import lzma
import numpy
from dotnetutils import dotnetpefile
from dotnetutils import net_graphing
from dotnetutils import net_graph_analyzer
from dotnetutils import net_emu_types
from dotnetutils import net_exceptions
from dotnetutils import net_row_objects
from dotnetutils import net_sigs
from dotnetutils import net_structs
from dotnetutils import net_emulator
from dotnetutils import net_patch
from dotnetutils import net_deobfuscate_funcs
from dotnetutils.deobfuscators.deobfuscator import Deobfuscator
from dotnetutils.net_opcodes import Opcodes

def decompress_cex_blob(compressed_buffer, old_version):
    props = compressed_buffer[0:5]
    if not old_version:
        sz_unc = int.from_bytes(compressed_buffer[5:13], 'little')
        compressed_data = compressed_buffer[13:]
    else:
        sz_unc = int.from_bytes(compressed_buffer[5:9], 'little')
        compressed_data = compressed_buffer[9:]
    #parse the cex compressed data blob header.
    lc = props[0] % 9
    remainder = props[0] // 9
    lp = remainder % 5
    pb = remainder // 5
    dict_size = props[1] | (props[2] << 8) | (props[3] << 16) | (props[4] << 24)
    filters = [{
        "id": lzma.FILTER_LZMA1,
        "lc": lc,
        "lp": lp,
        "pb": pb,
        "dict_size": dict_size
    }]
    d = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
    decompressed_buffer = d.decompress(compressed_data, max_length=sz_unc)
    return decompressed_buffer

class ConfuserExDeobfuscator(Deobfuscator):

    NAME = 'confuserex'

    decrypt_method = None
    code_decrypt_method = None
    string_methods = list()

    identifiers = [b'ConfusedByAttribute\x00', b'Confused by ConfuserEx\x00']
    

    def identify_unpack(self, dotnet: dotnetpefile.DotNetPeFile):
        ep_method = dotnet.get_entry_point()
        if ep_method is None:
            return False
        
        #Check the entrypoint method for signs of this being a cex compressed executable.
        has_decrypt_call = False
        has_ldc_16 = False
        has_ldc_24 = False
        ep_disasm = ep_method.disassemble_method()
        if ep_disasm is None:
            return False
        has_unbox_any = False
        has_isinst = False
        for instr in ep_disasm:
            ins_op = instr.get_opcode()
            if ins_op in (Opcodes.Call, Opcodes.Callvirt):
                instr_arg = instr.get_argument()
                if isinstance(instr_arg, net_row_objects.MethodDef) and instr_arg.is_static_method():
                    msig = instr_arg.get_method_signature()
                    return_type = msig.get_return_type()
                    params = msig.get_parameters()
                    if len(params) == 2 and isinstance(return_type, net_sigs.ValueTypeSig):
                        if return_type.get_type().get_full_name() == b'System.Runtime.InteropServices.GCHandle':
                            if isinstance(params[0], net_sigs.SZArraySig):
                                if isinstance(params[0].get_next(), net_sigs.CorLibTypeSig) and params[0].get_next().get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_U4:
                                    if isinstance(params[1], net_sigs.CorLibTypeSig) and params[1].get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_U4:
                                        has_decrypt_call = True
                                        self.decrypt_method = instr_arg
            elif ins_op == Opcodes.Unbox_Any:
                if instr.get_argument().get_full_name() == b'System.Int32':
                    has_unbox_any = True
            elif ins_op == Opcodes.Isinst:
                if instr.get_argument().get_full_name() == b'System.Int32':
                    has_isinst = True
            elif instr.get_name().startswith('ldc.i4'):
                if instr.get_argument() == 16:
                    has_ldc_16 = True
                if instr.get_argument() == 24:
                    has_ldc_24 = True

            if has_decrypt_call and has_isinst and has_unbox_any and has_ldc_16 and has_ldc_24:
                return True
        return False
    
    def __identify_code_decryption_method(self, dotnet):
        for method in dotnet.get_metadata_table('MethodDef'):
            if not method.has_body() or not method.is_static_method():
                continue
            msig = method.get_method_signature()
            if not isinstance(msig.get_return_type(), net_sigs.CorLibTypeSig) or method.has_return_value():
                continue
            if len(msig.get_parameters()) != 0:
                continue
            if method.disassemble_method() is None:
                continue

            disasm = method.disassemble_method()
            local_types = disasm.get_local_types()
            has_uint32_ptrsig = False
            has_uint8_ptrsig = False
            if len(disasm) > 0:
                if disasm[0].get_opcode() != Opcodes.Ldtoken:
                    continue

            for local_type in local_types:
                if isinstance(local_type, net_sigs.PtrSig):
                    if isinstance(local_type.get_next(), net_sigs.CorLibTypeSig):
                        etype = local_type.get_next().get_element_type()
                        if etype == net_structs.CorElementType.ELEMENT_TYPE_U4:
                            has_uint32_ptrsig = True
                        elif etype == net_structs.CorElementType.ELEMENT_TYPE_U1:
                            has_uint8_ptrsig = True

                if has_uint8_ptrsig and has_uint32_ptrsig:
                    break

            if not has_uint32_ptrsig or not has_uint32_ptrsig:
                continue
            
            is_ctor_method = True
            for xref_rid, xref_offset in method.get_xrefs():
                xmethod = dotnet.get_method_by_rid(xref_rid)
                if not xmethod.is_static_constructor():
                    is_ctor_method = False
                    break

            if not is_ctor_method:
                continue

            self.code_decrypt_method = method
            break
        return self.code_decrypt_method

    def identify_deobfuscate(self, dotnet):
        #TODO: we dont want to only identify based on strings
        #A binary can be confuserex obfuscated and simply not have any strings.
        if dotnet.has_string(b'DNU_CEX_WATERMARK'):
            return False
        mspec_table = dotnet.get_metadata_table('MethodSpec')
        if mspec_table is None:
            return False
        self.__identify_string_methods(dotnet)
        self.__identify_code_decryption_method(dotnet)
        return len(self.string_methods) != 0 or self.code_decrypt_method is not None
    
    def __is_old_version(self, decompress_method):
        for instr in decompress_method.disassemble_method():
            if instr.get_opcode() in (Opcodes.Call, Opcodes.Callvirt):
                if instr.get_argument().get_full_name() == b'System.BitConverter.ToInt32':
                    return True
        return False
    
    def __identify_string_methods(self, dotnet):
        self.string_methods.clear()
        mspec_table = dotnet.get_metadata_table('MethodSpec')
        potential_string_methods = set()
        for mspec in mspec_table:
            sig_obj = mspec.get_sig_obj()
            gen_args = sig_obj.get_generic_args()
            if len(gen_args) == 1:
                if isinstance(gen_args[0], net_sigs.CorLibTypeSig) and gen_args[0].get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_STRING:
                    method_obj = mspec.get_method()
                    if not method_obj.is_static_method():
                        continue
                    msig = method_obj.get_method_signature()
                    if isinstance(msig.get_return_type(), net_sigs.GenericMVar):
                        params = msig.get_parameters()
                        if len(params) != 1:
                            continue
                        if not isinstance(params[0], net_sigs.CorLibTypeSig):
                            continue
                        if params[0].get_element_type() not in (net_structs.CorElementType.ELEMENT_TYPE_I4, net_structs.CorElementType.ELEMENT_TYPE_U4):
                            continue
                        potential_string_methods.add(mspec)
        for mspec in potential_string_methods:
            mobj = mspec.get_method()
            has_initobj = False
            has_newarr = False
            has_ldc_16 = False
            has_ldc_24 = False
            if mobj.disassemble_method() is None:
                continue
            for instr in mobj.disassemble_method():
                ins_op = instr.get_opcode()
                if ins_op == Opcodes.Initobj:
                    has_initobj = True
                if ins_op == Opcodes.Newarr:
                    has_newarr = True
                if instr.get_name().startswith('ldc.i4'):
                    if instr.get_argument() == 16:
                        has_ldc_16 = True
                    if instr.get_argument() == 24:
                        has_ldc_24 = True
                if has_ldc_16 and has_ldc_24 and has_newarr and has_initobj:
                    break
            if has_ldc_16 and has_ldc_24 and has_newarr and has_initobj:
                self.string_methods.append(mspec)

    def unpack(self, dotnet):
        #find the decompress method.
        if self.decrypt_method is None:
            raise net_exceptions.CantUnpackException('Cant unpack due to internal error.')
        
        decompress_method_offset = -1
        decompress_method = None
        for instr in self.decrypt_method.disassemble_method():
            if instr.get_opcode() == Opcodes.Call:
                if isinstance(instr.get_argument(), net_row_objects.MethodDef):
                    msig = instr.get_argument().get_method_signature()
                    if isinstance(msig.get_return_type(), net_sigs.SZArraySig) and isinstance(msig.get_return_type().get_next(), net_sigs.CorLibTypeSig):
                        if msig.get_return_type().get_next().get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_U1:
                            params = msig.get_parameters()
                            if len(params) == 1:
                                param = params[0]
                                if isinstance(param, net_sigs.SZArraySig) and isinstance(param.get_next(), net_sigs.CorLibTypeSig):
                                    if param.get_next().get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_U1:
                                        decompress_method_offset = instr.get_instr_offset()
                                        decompress_method = instr.get_argument()
                                        break

        if decompress_method_offset == -1 or decompress_method is None:
            raise net_exceptions.CantUnpackException('Cant unpack due to error finding decompress call.')
        
        emu = net_emulator.DotNetEmulator(dotnet.get_entry_point(), end_offset=decompress_method_offset, end_method_rid=self.decrypt_method.get_rid(), dont_execute_cctor=True)
        emu.setup_method_params([])
        old_emu = None
        worked = False
        try:
            emu.run_function()
        except net_exceptions.EmulatorEndExecutionException as e:
            old_emu = emu
            emu = e.get_emu_obj()
            worked = True
        
        if not worked:
            raise net_exceptions.CantUnpackException('Initial emulation failed.')
        
        compressed_buffer = emu.get_stack().pop_obj().as_bytes()

        decompressed_buffer = decompress_cex_blob(compressed_buffer, self.__is_old_version(decompress_method))
        #inject the decompressed buffer back into the mulator.
        buffer = net_emu_types.DotNetArray(emu, len(decompressed_buffer), dotnet.get_typeref_by_full_name(b'System.Byte'))
        buffer.from_python_obj(list(decompressed_buffer))
        emu.current_offset += 5
        emu.current_eip += 1
        emu.get_stack().append_obj(buffer)
        emu.run_function()
        gc_handler = old_emu.get_stack().pop_obj()
        dn_array = gc_handler.get_target()
        #now find the entry point
        #First find the call that looks like the ResolveSIgnature call.
        new_data = dn_array.as_bytes()
        new_dpe = dotnetpefile.try_get_dotnetpe(pe_data=new_data)
        if new_dpe is None:
            return [new_data]
        ep_disasm = dotnet.get_entry_point().disassemble_method()
        sig_obj = None
        for x in range(len(ep_disasm)):
            instr = ep_disasm[x]
            if instr.get_opcode() in (Opcodes.Call, Opcodes.Callvirt):
                instr_arg = instr.get_argument()
                if isinstance(instr_arg, net_row_objects.MemberRef):
                    if instr_arg.get_full_name() == b'System.Reflection.Module.ResolveSignature':
                        prev_instr = ep_disasm[x-1]
                        if not prev_instr.get_name().startswith('ldc.i4'):
                            raise net_exceptions.CantUnpackException('Cant find CEX compressed entrypoint')
                        sig_token = prev_instr.get_argument()
                        sig_obj = dotnet.get_token_value(sig_token)
                        break
                elif isinstance(instr_arg, net_row_objects.MethodDef):
                    #can be hidden behind method def.
                    msig = instr_arg.get_method_signature()
                    ret_type = msig.get_return_type()
                    if not isinstance(ret_type, net_sigs.SZArraySig):
                        continue
                    ret_next = ret_type.get_next()
                    if not isinstance(ret_next, net_sigs.CorLibTypeSig) or ret_next.get_element_type() != net_structs.CorElementType.ELEMENT_TYPE_U1:
                        continue
                    params = msig.get_parameters()
                    if len(params) != 2:
                        continue
                    if not isinstance(params[1], net_sigs.CorLibTypeSig):
                        continue
                    if params[1].get_element_type() != net_structs.CorElementType.ELEMENT_TYPE_I4:
                        continue
                    prev_instr = ep_disasm[x-1]
                    if not prev_instr.get_name().startswith('ldc.i4'):
                        raise net_exceptions.CantUnpackException('Cant find CEX compressed entrypoint')
                    sig_token = prev_instr.get_argument()
                    #entry point is hidden behind this StandAloneSig's blob data.
                    sig_obj = dotnet.get_token_value(sig_token)
                    break
        if sig_obj is None:
            raise net_exceptions.CantUnpackException("Cant find CEX compressed entrypoint.")
        
        ep_token = int.from_bytes(sig_obj.get_column('Signature').get_value()[:4], 'little')
        new_dpe.set_entry_point(ep_token)

        return [new_dpe.get_exe_data()]
    
    def __deobfuscate_strings(self, dotnet):
        self.__identify_string_methods(dotnet)
        if len(self.string_methods) == 0:
            print('Could not find string methods to deobfuscate strings.')
            return
        if not dotnet.has_heap('#US'):
            net_patch.insert_blank_userstrings(dotnet)
            self.__identify_string_methods(dotnet)
        us_heap = dotnet.get_heap('#US')
        string_defs = list()
        for mspec in self.string_methods:
            if mspec.get_method() not in string_defs:
                string_defs.append(mspec.get_method())

        #first identify which constructor methods need to be executed.

        string_data_field = None
        for instr in string_defs[0].disassemble_method():
            if instr.get_opcode() == Opcodes.Ldsfld:
                string_data_field = instr.get_argument()
                break

        if string_data_field is None:
            print('Could not find string data field.')
            return
        
        string_data_instr = None
        string_data_method = None
        string_compress_method = None
        for xref_rid, xref_offset in string_data_field.get_xrefs():
            xfm = dotnet.get_method_by_rid(xref_rid)
            if xfm in string_defs:
                continue
            dis = xfm.disassemble_method()
            instr = dis.get_instr_at_offset(xref_offset)
            if instr.get_opcode() == Opcodes.Stsfld:
                prev_instr = dis[instr.get_instr_index()-1]
                if prev_instr.get_opcode() == Opcodes.Call:
                    string_data_instr = prev_instr
                    string_data_method = xfm
                    string_compress_method = prev_instr.get_argument()
                    break

        if string_data_instr is None or string_data_method is None or string_compress_method is None:
            print('Could not find where data is set.')
            return
                
        #first deobfuscate the control flow of the string encryption method to make parsing easier.
        fgraph = net_graphing.FunctionGraph(string_data_method)
        fanalyzer = net_graph_analyzer.GraphAnalyzer(string_data_method, fgraph)
        fanalyzer.simplify_control_flow()
        #we need to rerun so that the end offset is updated for the new control flow.
        start_offset = -1
        #In some older versions of CEX, theres a call to a method that decrypts the resource assembly first, then the string decoding.
        string_disasm = string_data_method.disassemble_method()
        string_data_instr = None
        for x in range(len(string_disasm)):
            instr = string_disasm[x]
            if instr.get_opcode() == Opcodes.Call and instr.get_argument() == string_compress_method:
                string_data_instr = instr
                break
        if string_data_instr is None:
            print('Could not find end offset.')
            return
        array_size = -1
        for x in range(1, len(string_disasm) - 4):
            instr = string_disasm[x]
            if instr.get_opcode() == Opcodes.Newarr:
                instr2 = string_disasm[x+1]
                if instr2.get_opcode() == Opcodes.Dup:
                    instr3 = string_disasm[x+2]
                    if instr3.get_opcode() == Opcodes.Ldtoken:
                        instr4 = string_disasm[x+3]
                        if instr4.get_opcode() == Opcodes.Call:
                            prev_instr = string_disasm[x-1]
                            if not prev_instr.get_name().startswith('ldc.i4'):
                                print('error: Could not find array size.')
                                return
                            array_size = prev_instr.get_argument()
                            break
        if array_size == -1:
            print('Could not find array size.')
            return
        
        for x in range(len(string_disasm) - 1):
            instr = string_disasm[x]
            if instr.get_name().startswith('ldc.i4'):
                if instr.get_argument() == array_size:
                    next_instr = string_disasm[x+1]
                    if next_instr.get_name().startswith('stloc'):
                        start_offset = instr.get_instr_offset()
                        break

        if start_offset == -1:
            print('Could not find start offset.')
            return
        print('Emulating string constructor {} {} {}'.format(hex(string_data_method.get_token()), hex(start_offset), hex(string_data_instr.get_instr_offset())))

        emu = net_emulator.DotNetEmulator(string_data_method, start_offset=start_offset, end_offset=string_data_instr.get_instr_offset(), dont_execute_cctor=True)
        #TODO: there appears to be an error when decrypting the strings for e2fo.  encrypted data might be off.
        #Maybe its some sort of constant protection?  Look in dnspy.
        emu.setup_method_params([])
        worked = False
        try:
            emu.run_function()
        except net_exceptions.EmulatorEndExecutionException:
            worked = True

        if not worked:
            print('initial static constructor emulation failed.')
            return
        
        compressed_buffer = emu.get_stack().pop_obj()
        compressed_buffer = compressed_buffer.as_bytes()
        try:
            decomp_buffer = decompress_cex_blob(compressed_buffer, self.__is_old_version(string_compress_method))
        except Exception as e:
            print('error decompressing initial data.  Its possible the string blob is corrupted.')
            return
        new_arr = net_emu_types.DotNetArray(emu, len(decomp_buffer), dotnet.get_typeref_by_full_name(b'System.Byte'))
        new_arr.from_python_obj(list(decomp_buffer))
        emu.set_static_field_obj(string_data_field.get_rid(), new_arr)
        appended_strings = dict()
        us_heap.begin_append_tx()
        for mspec in self.string_methods:
            for xref_rid, xref_offset in mspec.get_xrefs():
                xfm = dotnet.get_method_by_rid(xref_rid)
                dis = xfm.disassemble_method()
                if dis is None:
                    print('error disassembling method {}'.format(hex(xfm.get_token())))
                    continue
                instr = dis.get_instr_at_offset(xref_offset)
                prev_instr = dis[instr.get_instr_index() - 1]
                if not prev_instr.get_name().startswith('ldc.i4'):
                    if prev_instr.get_opcode() in (Opcodes.Br, Opcodes.Br_S):
                        target = prev_instr.get_argument() + len(prev_instr) + prev_instr.get_instr_offset()
                        if target == xref_offset:
                            prev_instr = dis[prev_instr.get_instr_index() - 1]
                    if not prev_instr.get_name().startswith('ldc.i4'):
                        raise Exception()
                is_uint = False
                param_sig = mspec.get_method().get_param_types()[0]
                if param_sig == net_sigs.get_CorSig_UInt32():
                    is_uint = True
                elif param_sig != net_sigs.get_CorSig_Int32():
                    raise Exception()
                child_emu = emu.spawn_new_emulator(mspec)
                if is_uint:
                    arg = net_emu_types.DotNetUInt32(emu, None)
                    arg.from_uint(prev_instr.get_argument() & 0xFFFFFFFF)
                else:
                    arg = net_emu_types.DotNetInt32(emu, None)
                    arg.from_int(prev_instr.get_argument())
                child_emu.setup_method_params([arg])
                child_emu.run_function()
                result_string = child_emu.get_stack().pop_obj()
                result_data = result_string.get_str_data_as_str().encode('utf-16le')
                if result_data in appended_strings:
                    new_index = appended_strings[result_data]
                else:
                    new_index = us_heap.append_tx(result_data)
                    appended_strings[result_data] = new_index

                #nop out the ldc
                patch_buf = b'\x00' * len(prev_instr)
                dotnet.patch_instruction(xfm, patch_buf, prev_instr.get_instr_offset(), len(prev_instr))
                new_instr = b'\x72' + int.to_bytes(new_index, 3, 'little') + b'\x70'
                dotnet.patch_instruction(xfm, new_instr, instr.get_instr_offset(), len(new_instr))
                #For now just nop it + replace the call with ldstr.
        us_heap.end_append_tx()

    def __obtain_code_encrypt_key(self, dotnet):
        expected_value = None
        dis = self.code_decrypt_method.disassemble_method()
        for x in range(3, len(dis)):
            instr = dis[x]
            if instr.get_opcode() in (Opcodes.Bne_Un, Opcodes.Bne_Un_S):
                prev_instr = dis[x-1]
                if prev_instr.get_name().startswith('ldc.i4'):
                    prev_instr2 = dis[x-2]
                    if prev_instr2.get_name().startswith('ldloc'):
                        prev_instr3 = dis[x-3]
                        if prev_instr3.get_name().startswith('stloc'):
                            expected_value = numpy.int32(prev_instr.get_argument()).astype(numpy.uint32)
                            break
        if expected_value is None:
            print('expected value none')
            return False
                
        target_section = None
        #find seed values:
        numbers = list()
        past_ldc_24 = False
        for x in range(len(dis)):
            instr = dis[x]
            if instr.get_name().startswith('ldc.i4'):
                if instr.get_argument() == 24:
                    past_ldc_24 = True
            if past_ldc_24:
                if instr.get_name().startswith('stloc'):
                    prev_instr = dis[x-1]
                    if prev_instr.get_name().startswith('ldc.i4'):
                        numbers.append((numpy.int32(prev_instr.get_argument()).astype(numpy.uint32), instr.get_argument()))
                if instr.is_branch() or instr.is_absolute_jmp() or instr.get_opcode() in (Opcodes.Ret, Opcodes.Throw, Opcodes.Endfinally):
                    break
        if len(numbers) < 4:
            return False
        
        num4, num4_id = numbers[-4]
        num5, num5_id = numbers[-3]
        num6, num6_id = numbers[-2]
        num7, num7_id = numbers[-1]
        exe_data = dotnet.get_exe_data()
        for section in dotnet.get_pe().get_sections():
            name_data = section['Name']
            result_value = numpy.uint32(int.from_bytes(name_data[:4], 'little')) * numpy.uint32(int.from_bytes(name_data[4:], 'little'))
            if result_value == expected_value:
                target_section = section
            elif result_value != 0:
                section_size = section['SizeOfRawData'] >> 2
                section_data = exe_data[section['PointerToRawData']: section['PointerToRawData'] + section['SizeOfRawData']]
                sec_data_index = 0
                for x in range(0, section_size):
                    new_number = (num4 ^ numpy.uint32(int.from_bytes(section_data[sec_data_index:sec_data_index+4]))) + num5 + num6 * num7
                    num4 = num5
                    num5 = num7
                    num7 = new_number
                    sec_data_index += 4
        if target_section is None:
            print('target section is None')
            return False
        
        start_mixing_offset = None
        end_mixing_offset = None
        array_vars = list()
        prev_call = None
        for x in range(len(dis)):
            instr = dis[x]
            if instr.get_name() == 'newarr' and start_mixing_offset is None:
                if instr.get_argument().get_full_name() == b'System.UInt32':
                    start_mixing_offset = dis[x-1].get_instr_offset()
            if instr.get_name() == 'newarr':
                next_instr = dis[x+1]
                if next_instr.get_name().startswith('stloc'):
                    array_vars.append(next_instr.get_argument())
            
            if instr.get_name() in ('call', 'callvirt'):
                instr_arg = instr.get_argument()
                if not isinstance(instr_arg, net_row_objects.MethodDef):
                    prev_call = instr
                    continue
                msig = instr_arg.get_method_signature()
                if msig.get_return_type() == net_sigs.get_CorSig_Boolean():
                    end_mixing_offset = prev_call.get_instr_offset()
                prev_call = instr
            if end_mixing_offset is not None and start_mixing_offset is not None:
                break

        if end_mixing_offset is None or start_mixing_offset is None:
            return False
        
        emu = net_emulator.DotNetEmulator(self.code_decrypt_method, start_offset=start_mixing_offset, end_offset=end_mixing_offset, dont_execute_cctor=True)
        emu.setup_method_params([])
        num4_obj = net_emu_types.DotNetUInt32(emu, None)
        num4_obj.from_uint(num4)
        num5_obj = net_emu_types.DotNetUInt32(emu, None)
        num5_obj.from_uint(num5)
        num6_obj = net_emu_types.DotNetUInt32(emu, None)
        num6_obj.from_uint(num6)
        num7_obj = net_emu_types.DotNetUInt32(emu, None)
        num7_obj.from_uint(num7)
        emu.set_local_obj(num4_id, num4_obj)
        emu.set_local_obj(num5_id, num5_obj)
        emu.set_local_obj(num6_id, num6_obj)
        emu.set_local_obj(num7_id, num7_obj)
        worked = False
        print('running emulator from {} to {}'.format(hex(start_mixing_offset), hex(end_mixing_offset)))
        try:
            emu.run_function()
        except net_exceptions.EmulatorEndExecutionException:
            worked = True
        if not worked:
            return False
        array = emu.get_local_obj(array_vars[0]).as_python_obj()
        usable_array = list()
        for item in array:
            val = numpy.uint32(item.as_python_obj() & 0xFFFFFFFF)
            usable_array.append(val)

        add_val = None
        is_in_block = False
        for x in range(len(dis)):
            instr = dis[x]
            op = instr.get_opcode()
            if instr.get_name().startswith('ldloc') and instr.get_argument() == array_vars[0]:
                is_in_block = True

            if is_in_block:
                ops = (dis[x-1].get_opcode(), op, dis[x+1].get_opcode(), dis[x+2].get_opcode(), dis[x+3].get_opcode())
                if ops == (Opcodes.Ldind_U4, Opcodes.Xor, Opcodes.Ldc_I4, Opcodes.Add, Opcodes.Stelem_I4):
                    add_val = numpy.int32(dis[x+1].get_argument()).astype(numpy.uint32)
                    break
                
            
            if instr.is_branch() or instr.is_absolute_jmp() or op in (Opcodes.Throw, Opcodes.Ret, Opcodes.Endfinally):
                is_in_block = False

        if add_val is None:
            return False
        num_index = 0
        new_exe_data = bytearray(exe_data)
        for x in range(target_section['SizeOfRawData'] >> 2):
            index = target_section['PointerToRawData'] + num_index
            current_num = numpy.uint32(int.from_bytes(new_exe_data[index:index+4], 'little'))
            current_num ^= usable_array[x % 16]
            usable_array[x % 16] = (usable_array[x % 16] ^ current_num) + add_val
            new_exe_data = new_exe_data[:index] + current_num.tobytes() + new_exe_data[index + 4:]
            num_index += 4
        xrefs = self.code_decrypt_method.get_xrefs()
        dotnet.set_exe_data(bytes(new_exe_data))
        dotnet.reinit_dpe(False)
        #Lastly blank out the xrefs to prevent re code decryption.
        for xref_id, xref_offset in xrefs:
            m = dotnet.get_method_by_rid(xref_id)
            d = m.disassemble_method()
            if d is None:
                continue
            instr = d.get_instr_at_offset(xref_offset)
            dotnet.patch_instruction(m, b'\x00' * len(instr), xref_offset, len(instr))
        return True

    def __decrypt_method_code(self, dotnet):
        if self.code_decrypt_method is None:
            print('Did not find code decrypt method.  Code is likely not encrypted.')
            return
        if len(self.code_decrypt_method.get_xrefs()) == 0:
            print('Code decryption method found but not used.  Code is likely not encrypted.')
            return
        #first deobfuscate the control flow of the encryption method to make parsing easier.
        fgraph = net_graphing.FunctionGraph(self.code_decrypt_method)
        fanalyzer = net_graph_analyzer.GraphAnalyzer(self.code_decrypt_method, fgraph)
        fanalyzer.simplify_control_flow()

        worked = self.__obtain_code_encrypt_key(dotnet)
        if not worked:
            raise net_exceptions.CantDeobfuscateException('Code decryption failed.  Cannot continue with deobfuscator.')
        
    def __clean_names(self, dotnet):
        net_deobfuscate_funcs.cleanup_names(dotnet)

    def __clean_code(self, dotnet):
        net_deobfuscate_funcs.remove_useless_functions(dotnet)
        net_deobfuscate_funcs.deobfuscate_control_flow(dotnet)
    
    def deobfuscate(self, dotnet):
        self.__decrypt_method_code(dotnet)
        self.__deobfuscate_strings(dotnet)
        self.__clean_code(dotnet)
        self.__clean_names(dotnet)
        dotnet.add_string('DNU_CEX_WATERMARK')
        return True
    
    