import lzma
from dotnetutils import dotnetpefile
from dotnetutils import net_graphing
from dotnetutils import net_graph_analyzer
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
            print('ep none')
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
        worked = False
        try:
            emu.run_function()
        except net_exceptions.EmulatorEndExecutionException as e:
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
        return [decompressed_buffer]
    
    def deobfuscate(self, dotnet):
        pass