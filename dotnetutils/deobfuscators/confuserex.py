import lzma
import pefile
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

"""
This section has some good examples on how to use emulator callbacks
The gist is:
- They are applied to the app domain so exist across all function calls made by an emulator.
- Return False if you dont want the emulator to process the instruction normally, True otherwise.
- You can modify the stack, locals and other emulator state related items.
- Utilize the pop_obj(), append_obj(), set_local_obj(), set_static_obj() etc.
"""

def cex_decrypt_ldind_u4_handler(emulator, argument):
    address_obj = emulator.get_stack().pop_obj()
    if not isinstance(address_obj, net_emu_types.DotNetIntPtr):
        raise Exception()
    address_val = address_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_U).as_python_obj()
    resulting_value = net_emu_types.DotNetInt32(emulator, None)
    resulting_value.from_int(argument.read_int32(address_val))
    emulator.get_stack().append_obj(resulting_value)
    return False

def cex_decrypt_stind_i4_handler(emulator, argument):
    value_obj = emulator.get_stack().pop_obj()
    address_obj = emulator.get_stack().pop_obj()
    if not isinstance(address_obj, net_emu_types.DotNetIntPtr) or not isinstance(value_obj, net_emu_types.DotNetInt32):
        raise Exception()
    address_val = address_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_U).as_python_obj()
    argument.write_int32(address_val, value_obj.as_python_obj())
    return False

def cex_decrypt_ldind_u2_handler(emulator, argument):
    address_obj = emulator.get_stack().pop_obj()
    if not isinstance(address_obj, net_emu_types.DotNetIntPtr):
        raise Exception()
    address_val = address_obj.cast(net_structs.CorElementType.ELEMENT_TYPE_U).as_python_obj()
    resulting_value = net_emu_types.DotNetUInt16(emulator, None)
    resulting_value.from_ushort(argument.read_uint16(address_val))
    emulator.get_stack().append_obj(resulting_value.cast(net_structs.CorElementType.ELEMENT_TYPE_I4))
    return False

def cex_decrypt_call_handler(emulator, argument):
    method_obj = emulator.get_instr().get_argument()
    if isinstance(method_obj, net_row_objects.MemberRef):
        full_name = method_obj.get_full_name()
        if full_name == b'System.Runtime.InteropServices.Marshal.GetHINSTANCE':
            module = emulator.get_stack().pop_obj()
            result = net_emu_types.DotNetIntPtr(emulator, None)
            if emulator.is_64bit():
                result.from_long(argument.get_imagebase())
            else:
                result.from_int(argument.get_imagebase())
            emulator.get_stack().append_obj(result)
            return False
    elif isinstance(method_obj, net_row_objects.MethodDef):
        implmap_table = emulator.get_method_obj().get_dotnetpe().get_metadata_table('ImplMap')
        is_virtprot = False
        if implmap_table is not None:
            for impl in implmap_table:
                if impl.get_column('MemberForwarded').get_value() == method_obj:
                    if impl.get_column('ImportName').get_value() == b'VirtualProtect':
                        is_virtprot = True
                        break
            if is_virtprot:
                oldprot_addr = emulator.get_stack().pop_obj()
                if not isinstance(oldprot_addr, net_emu_types.BoxedReference):
                    raise Exception()
                emulator.get_stack().remove_obj()
                emulator.get_stack().remove_obj()
                emulator.get_stack().remove_obj()
                #no op the VirtualProtect call.
                result = net_emu_types.DotNetBoolean(emulator, None)
                result.from_bool(True)
                emulator.get_stack().append_obj(result)
                #make sure the var isnt 64 to trick cex into decrypting.
                new_prot = net_emu_types.DotNetUInt32(emulator, None)
                new_prot.from_uint(0) #Can be anything that isnt 64, just to trick the check.
                oldprot_addr.set_val(new_prot)
                return False

    return True

class MemoryMappedExecutable:
    def __init__(self, dotnet):
        self.__buffer = None
        self.__imagebase = None
        self.__sizeofimage = None
        self.__last_rva_written = None
        self.__map_executable(dotnet)
        if self.__buffer is None or self.__imagebase is None or self.__sizeofimage is None:
            raise Exception()
        
    def get_last_rva_written(self):
        return self.__last_rva_written

    def __map_executable(self, dotnet):
        pe = pefile.PE(data=dotnet.get_exe_data())
        self.__buffer = bytearray(pe.get_memory_mapped_image())
        self.__imagebase = pe.OPTIONAL_HEADER.ImageBase
        self.__sizeofimage = pe.OPTIONAL_HEADER.SizeOfImage

    def get_imagebase(self):
        return self.__imagebase
    
    def get_buffer(self):
        return self.__buffer
    
    def read_uint32(self, address):
        rva = address - self.__imagebase
        return int.from_bytes(self.__buffer[rva:rva+4], 'little')
    
    def read_int32(self, address):
        rva = address - self.__imagebase
        return int.from_bytes(self.__buffer[rva:rva+4], 'little', signed=True)

    def read_uint16(self, address):
        rva = address - self.__imagebase
        return int.from_bytes(self.__buffer[rva:rva+2], 'little')
    
    def write_int32(self, address, value):
        rva = address - self.__imagebase
        self.__last_rva_written = rva
        val_b = int.to_bytes(value, 4, 'little', signed=True)
        self.__buffer = self.__buffer[:rva] + val_b + self.__buffer[rva + 4:]
        
class ConfuserExDeobfuscator(Deobfuscator):

    NAME = 'confuserex'

    decrypt_method = None
    code_decrypt_method = None
    string_methods = list()

    identifiers = [b'ConfusedByAttribute\x00', b'Confused by ConfuserEx\x00']
    

    def identify_unpack(self, dotnet: dotnetpefile.DotNetPeFile, ctx):
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

    def identify_deobfuscate(self, dotnet, ctx):
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
        potential_string_methods = list()
        for mspec in mspec_table:
            sig_obj = mspec.get_sig_obj()
            if not isinstance(sig_obj, net_sigs.GenericInstMethodSig):
                continue
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
                        if mspec in potential_string_methods:
                            continue
                        potential_string_methods.append(mspec)
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

    def unpack(self, dotnet, ctx):
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
        self.__identify_code_decryption_method(new_dpe)
        if self.code_decrypt_method is None or len(self.code_decrypt_method.get_xrefs()) == 0:
            new_dpe.set_entry_point(ep_token)
            self.code_decrypt_method = None
            return [new_dpe.get_exe_data()]
        ctx.set_item('Entry', ep_token)
        self.code_decrypt_method = None
        return [new_data]
    
    def __deobfuscate_strings(self, dotnet):
        self.__identify_string_methods(dotnet)
        if len(self.string_methods) == 0:
            print('Could not find string methods to deobfuscate strings.')
            return
        if not dotnet.has_heap('#US'):
            net_patch.insert_blank_userstrings(dotnet)
            self.__identify_string_methods(dotnet)
            if not dotnet.has_heap('#US'):
                raise Exception('Internal error adding #US stream')
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
        #instead of deobfuscating here, maybe just emulate with no op hooks for potential problematic instructions?  Also since we already identified the code decryption func earlier, we can proabably just reuse that for detection.
        fgraph = net_graphing.FunctionGraph(string_data_method)
        fanalyzer = net_graph_analyzer.GraphAnalyzer(string_data_method, fgraph)
        fanalyzer.simplify_control_flow()        
        dotnet.reinit_dpe(False)
        us_heap = dotnet.get_heap('#US')
        self.__identify_string_methods(dotnet)
        #we need to rerun so that the end offset is updated for the new control flow.
        string_data_method = dotnet.get_token_value(string_data_method.get_token())
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

    def __do_code_decrypt(self, dotnet):
        emulator = net_emulator.DotNetEmulator(self.code_decrypt_method, dont_execute_cctor=True)
        emulator.setup_method_params([])
        mapped = MemoryMappedExecutable(dotnet)
        app_domain = emulator.get_appdomain()
        app_domain.register_instr_handler(Opcodes.Ldind_U4, cex_decrypt_ldind_u4_handler, mapped)
        app_domain.register_instr_handler(Opcodes.Ldind_U2, cex_decrypt_ldind_u2_handler, mapped)
        app_domain.register_instr_handler(Opcodes.Stind_I4, cex_decrypt_stind_i4_handler, mapped)
        app_domain.register_instr_handler(Opcodes.Call, cex_decrypt_call_handler, mapped)
        orig_buffer = bytearray(mapped.get_buffer())
        emulator.run_function()
        new_buffer = mapped.get_buffer()
        exe_data = dotnet.get_exe_data()
        if orig_buffer != new_buffer and mapped.get_last_rva_written() is not None:
            #copy over just the encrypted section.
            encr_rva = mapped.get_last_rva_written()
            target_section = None
            pe = pefile.PE(data=exe_data)
            for section in pe.sections:
                if section.VirtualAddress <= encr_rva < (section.VirtualAddress + section.Misc_VirtualSize):
                    target_section = section
                    break
            if target_section is None:
                print('Could not find encrypted section.')
                return False
            
            amt_to_copy = min(target_section.SizeOfRawData, target_section.Misc_VirtualSize)
            exe_data = exe_data[:target_section.PointerToRawData] + new_buffer[target_section.VirtualAddress:target_section.VirtualAddress+amt_to_copy] + exe_data[target_section.PointerToRawData + amt_to_copy:]
            exe_data = bytes(exe_data)
            xrefs = self.code_decrypt_method.get_xrefs()
            dotnet.set_exe_data(bytes(exe_data))
            #Lastly blank out the xrefs to prevent re code decryption.
            for xref_id, xref_offset in xrefs:
                m = dotnet.get_method_by_rid(xref_id)
                d = m.disassemble_method()
                if d is None:
                    continue
                instr = d.get_instr_at_offset(xref_offset)
                dotnet.patch_instruction(m, b'\x00' * len(instr), xref_offset, len(instr))
            return True
        else:
            return False


    def __decrypt_method_code(self, dotnet):
        if self.code_decrypt_method is None:
            print('Did not find code decrypt method.  Code is likely not encrypted.')
            return
        if len(self.code_decrypt_method.get_xrefs()) == 0:
            print('Code decryption method found but not used.  Code is likely not encrypted.')
            return

        worked = self.__do_code_decrypt(dotnet)
        if not worked:
            raise net_exceptions.CantDeobfuscateException('Code decryption failed.  Cannot continue with deobfuscator.')
        
    def __clean_names(self, dotnet):
        net_deobfuscate_funcs.cleanup_names(dotnet)

    def __clean_code(self, dotnet):
        net_deobfuscate_funcs.remove_useless_functions(dotnet)
        net_deobfuscate_funcs.deobfuscate_control_flow(dotnet)
    
    def deobfuscate(self, dotnet, ctx):
        orig_ep = dotnet.get_pe().get_net_header()['EntryPoint']['EntryPointToken']
        print('Starting ConfuserEx deobfuscator')
        print('Attempting to deobfuscate encrypted code.')
        self.__decrypt_method_code(dotnet)
        print('Completed deobfuscate encrypted code.')
        print('Attempting to deobfuscate encrypted strings.')
        self.__deobfuscate_strings(dotnet)
        print('Deobfuscated encrypted strings.')
        print('Cleaning control flow obfuscation.')
        self.__clean_code(dotnet)
        print('Finished running code cleanups.')
        print('Cleaning up metadata names.')
        self.__clean_names(dotnet)
        print('Finished cleaning names, watermarking executable.')
        if ctx.has_item('Entry'):
            dotnet.set_entry_point(ctx.get_item('Entry'))
        dotnet.add_string('DNU_CEX_WATERMARK')
        print('Finished!')
        return True
    
    