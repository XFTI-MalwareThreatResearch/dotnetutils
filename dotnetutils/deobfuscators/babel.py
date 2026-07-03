from dotnetutils.deobfuscators.deobfuscator import Deobfuscator
from dotnetutils import net_exceptions, net_sigs, net_emulator, net_emu_types
from dotnetutils.net_opcodes import Opcodes

class Babel(Deobfuscator):

    NAME = 'Babel'

    def __init__(self):
        pass

    def identify_unpack(self, dotnet, ctx):
        return False      

    def identify_babel_string_method(self, dotnet):
        methods = dotnet.get_methods_by_full_name(b'System.String.ToCharArray')
        if len(methods) == 0:
            return None
        method = methods[0]
        methods = dotnet.get_methods_by_full_name(b'System.String..ctor')
        rids = set()
        for m in methods:
            for xr, xo in m.get_xrefs():
                rids.add(xr)
        for xref_rid, xref_offset in method.get_xrefs():
            if xref_rid not in rids:
                continue
            xfm = dotnet.get_method_by_rid(xref_rid)
            if xfm.is_static_method():
                continue
            msig = xfm.get_method_signature()
            if len(msig.get_parameters()) != 2:
                continue
            param1 = msig.get_parameters()[0]
            param2 = msig.get_parameters()[1]
            if param1 != net_sigs.get_CorSig_String() or param2 != net_sigs.get_CorSig_Int32():
                continue
            if msig.get_return_type() != net_sigs.get_CorSig_String():
                continue

            return xfm
        return None

    def identify_deobfuscate(self, dotnet, ctx):
        return not dotnet.has_string(b'DNU_BABEL_DEOB') and self.identify_babel_string_method(dotnet) is not None

    def unpack(self, dotnet, ctx):
        return False

    def remove_delegates(self, dotnet):
        pass

    def remove_string_obfuscation(self, dotnet):
        string_method = self.identify_babel_string_method(dotnet)
        if string_method is None:
            return True
        actual_string_method = None
        for xref_rid, xref_offset in string_method.get_xrefs():
            actual_string_method = dotnet.get_method_by_rid(xref_rid)
            break
        if actual_string_method is None:
            print('Couldnt find actual string method')
            return True
        emu = net_emulator.DotNetEmulator(actual_string_method)
        us_heap = dotnet.get_heap('#US')
        us_heap.begin_append_tx()
        for xref_rid, xref_offset in actual_string_method.get_xrefs():
            xfm = dotnet.get_method_by_rid(xref_rid)
            dis = xfm.disassemble_method()
            instr = dis.get_instr_at_offset(xref_offset)
            instrs = list()
            for x in range(instr.get_instr_index() - 1, 0, -1):
                if dis[x].get_opcode() != Opcodes.Nop:
                    instrs.append(dis[x])
                    if len(instrs) == 2:
                        break
            if len(instrs) != 2 or instrs[1].get_opcode() != Opcodes.Ldstr:
                print('Detected potential obfuscation before babel obfuscation.')
                return False
            start_offset = instrs[1].get_instr_offset()
            end_offset = xref_offset + len(instr)
            print('decoding string in method {}'.format(xfm))
            new_emu = emu.spawn_new_emulator(xfm, start_offset=start_offset, end_offset=end_offset, dont_execute_first_cctor=True)
            worked = False
            try:
                new_emu.run_function()
            except net_exceptions.EmulatorEndExecutionException:
                worked = True

            if not worked:
                print('Emulator failure.')
                return True
            
            stack = new_emu.get_stack()
            string = stack.pop_obj()
            if not isinstance(string, net_emu_types.DotNetString):
                raise Exception('invalid return value')
            patch_size = end_offset - start_offset
            index = us_heap.append_tx(string.get_str_data_as_str().encode('utf-16le'))
            patch_buf = b'\x72' + int.to_bytes(index, 3, 'little') + b'\x70' + (b'\x00' * (patch_size - 5))
            dotnet.patch_instruction(xfm, patch_buf, start_offset, patch_size)
        us_heap.end_append_tx()
        return True
        
    def deobfuscate(self, dotnet, ctx):
        print('Removing Babel String obfuscation')
        if not self.remove_string_obfuscation(dotnet):
            return True
        dotnet.add_string('DNU_BABEL_DEOB')
        return True