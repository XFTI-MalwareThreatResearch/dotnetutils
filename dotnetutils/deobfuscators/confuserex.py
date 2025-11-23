import lzma
from dotnetutils import dotnetpefile
from dotnetutils import net_graphing
from dotnetutils import net_graph_analyzer
from dotnetutils import net_emu_types
from dotnetutils import net_exceptions
from dotnetutils import net_row_objects
from dotnetutils import net_sigs
from dotnetutils import net_structs
from dotnetutils import net_emulator
from dotnetutils.net_opcodes import Opcodes
from dotnetutils.deobfuscators.deobfuscator import Deobfuscator

class ConfuserExDeobfuscator:

    NAME = 'confuserex'

    decrypt_method = None
    string_method = None

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

    def identify_deobfuscate(self, dotnet):
        pass

    def unpack(self, dotnet):
        #find the decompress method.
        if self.decrypt_method is None:
            raise net_exceptions.CantUnpackException('Cant unpack due to internal error.')
        
        decompress_method_offset = -1
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
                                        break

        if decompress_method_offset == -1:
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

        props = compressed_buffer[:5]
        sz_unc = int.from_bytes(compressed_buffer[5:5+8], 'little')
        compressed_data = compressed_buffer[5 + 8:]

        lc = props[0] % 9
        remainder = props[0] // 9
        lp = remainder % 5
        pb = remainder // 5
        dict_size = 0
        for x in range(4):
            dict_size += ((props[1 + x] << x * 8))
        filters = [{
            "id": lzma.FILTER_LZMA1,
            "lc": lc,
            "lp": lp,
            "pb": pb,
            "dict_size": dict_size
        }]
        d = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
        decompressed_buffer = d.decompress(compressed_data, max_length=sz_unc)
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
        if sig_obj is None:
            raise net_exceptions.CantUnpackException("Cant find CEX compressed entrypoint.")
        
        ep_token = int.from_bytes(sig_obj.get_column('Signature').get_value(), 'little')
        new_dpe.set_entry_point(ep_token)

        return [new_dpe.get_exe_data()]
    
    def deobfuscate(self, dotnet):
        pass