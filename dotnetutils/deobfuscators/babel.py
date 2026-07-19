from dotnetutils.deobfuscators.deobfuscator import Deobfuscator
from dotnetutils import net_exceptions, net_sigs, net_emulator, net_emu_types
from dotnetutils import net_deobfuscate_funcs
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

    def remove_constant_method_calls(self, dotnet):
        LDARG_INSTRS = [Opcodes.Ldarg, Opcodes.Ldarg_S, Opcodes.Ldarg_0, Opcodes.Ldarg_1, Opcodes.Ldarg_2, Opcodes.Ldarg_3]
        LDC_INSTRS = [Opcodes.Ldc_I4, Opcodes.Ldc_I4_S, Opcodes.Ldc_I4_M1, Opcodes.Ldc_I4_0, Opcodes.Ldc_I4_1, Opcodes.Ldc_I4_2, Opcodes.Ldc_I4_3, Opcodes.Ldc_I4_4, Opcodes.Ldc_I4_5, Opcodes.Ldc_I4_6, Opcodes.Ldc_I4_7, Opcodes.Ldc_I4_8]
        MATH_OPS = [Opcodes.Not, Opcodes.Sub, Opcodes.Add, Opcodes.Neg, Opcodes.Xor, Opcodes.Shr, Opcodes.Shl, Opcodes.Or, Opcodes.Shr_Un, Opcodes.And, Opcodes.Mul, Opcodes.Div, Opcodes.Div_Un, Opcodes.Rem, Opcodes.Rem_Un]
        OTHER_ALLOWED = [Opcodes.Pop, Opcodes.Nop, Opcodes.Switch, Opcodes.Ret]
        STLOC = [Opcodes.Stloc_S, Opcodes.Stloc, Opcodes.Stloc_0, Opcodes.Stloc_1, Opcodes.Stloc_2, Opcodes.Stloc_3]
        LDLOC = [Opcodes.Ldloc_S, Opcodes.Ldloc, Opcodes.Ldloc_0, Opcodes.Ldloc_1, Opcodes.Ldloc_2, Opcodes.Ldloc_3]
        BRANCHES = [Opcodes.Br, Opcodes.Br_S, Opcodes.Brtrue, Opcodes.Brtrue_S, Opcodes.Brfalse, Opcodes.Brfalse_S, Opcodes.Beq, Opcodes.Beq_S, Opcodes.Bne_Un, Opcodes.Bne_Un_S, \
                Opcodes.Bge, Opcodes.Bge_S, Opcodes.Bge_Un, Opcodes.Bge_Un_S, Opcodes.Bgt, Opcodes.Bgt_S, Opcodes.Bgt_Un, Opcodes.Bgt_Un_S, \
                Opcodes.Ble, Opcodes.Ble_S, Opcodes.Ble_Un, Opcodes.Ble_Un_S, Opcodes.Blt, Opcodes.Blt_S, Opcodes.Blt_Un, Opcodes.Blt_Un_S, Opcodes.Switch]
        MUST_BE_IN = [LDARG_INSTRS, LDC_INSTRS, MATH_OPS, OTHER_ALLOWED, STLOC, LDLOC, BRANCHES]
        for method in dotnet.get_metadata_table('MethodDef'):
            debug = method.get_token() == 0
            debug and print('Checking method for junk')
            if not method.is_static_method():
                debug and print('is static')
                continue
            if not method.has_body():
                debug and print('no body')
                continue
            msig = method.get_method_signature()
            if msig is None:
                debug and print('no msig')
                continue

            if len(msig.get_parameters()) != 1:
                debug and print('no parmams')
                continue

            if msig.get_parameters()[0] != msig.get_return_type():
                debug and print('sigs not eq')
                continue

            if msig.get_return_type() != net_sigs.get_CorSig_Int32():
                debug and print('return types')
                continue
            disasm = method.disassemble_method()
            if len(disasm) > 200:
                debug and print('disasm len')
                continue
            misidentified = False
            
            for instr in disasm:
                op = instr.get_opcode()
                is_in = any(op in item for item in MUST_BE_IN)
                if not is_in:
                    debug and print('misidentifying instr', instr)
                    misidentified = True
                    break

            if misidentified:
                debug and print('msiidentified')
                continue
            debug and print('removing xrefs')
            try:
                for xref_rid, xref_offset in method.get_xrefs():
                    xfm = dotnet.get_method_by_rid(xref_rid)
                    disasm = xfm.disassemble_method()
                    xref_instr = disasm.get_instr_at_offset(xref_offset)
                    if xref_instr.get_opcode() != Opcodes.Call:
                        continue
                    idx = xref_instr.get_instr_index()
                    needed = 1
                    target_instrs = list()
                    for x in range(idx - 1, -1, -1):

                        instr = disasm[x]
                        if instr.get_opcode() == Opcodes.Nop:
                            continue

                        added = instr.get_astack()
                        pulled = instr.get_pstack()
                        needed = needed - added + pulled
                        target_instrs.append(instr)
                        if needed == 0:
                            break
                    if len(target_instrs) != 1:
                        continue

                    if target_instrs[0].get_opcode() not in LDC_INSTRS:
                        continue

                    emu = net_emulator.DotNetEmulator(method, dont_execute_cctor=True)
                    num = net_emu_types.DotNetInt32(emu, None)
                    num.from_int(target_instrs[0].get_argument())
                    emu.setup_method_params([num])
                    emu.run_function()

                    obj = emu.get_stack().pop_obj()
                    if not isinstance(obj, net_emu_types.DotNetNumber):
                        continue
                    obj = obj.as_python_obj()
                    patch_bytes = b'\x20' + int.to_bytes(obj, 4, 'little', signed=True)
                    print('Replacing junk method call in method {} at offset {}'.format(xfm, hex(xref_offset)))
                    dotnet.patch_instruction(xfm, patch_bytes, xref_instr.get_instr_offset(), len(xref_instr))
                    patch_bytes = b'\x00' * len(target_instrs[0])
                    dotnet.patch_instruction(xfm, patch_bytes, target_instrs[0].get_instr_offset(), len(patch_bytes))
            except Exception as e:
                debug and print('error {}'.format(str(e)))
                if debug:
                    raise e
                continue


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
        print('string method {}, actual string method {}'.format(string_method, actual_string_method))
        for xref_rid, xref_offset in actual_string_method.get_xrefs():
            xfm = dotnet.get_method_by_rid(xref_rid)
            dis = xfm.disassemble_method()
            instr = dis.get_instr_at_offset(xref_offset)
            instrs = list()
            for x in range(instr.get_instr_index() - 1, -1, -1):
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
    
    def clean_code(self, dotnet):
        print('removing constant method calls')
        self.remove_constant_method_calls(dotnet)
        print('Deobfuscating control flow')
        net_deobfuscate_funcs.deobfuscate_control_flow(dotnet)
        print('Code cleaned')
        
    def deobfuscate(self, dotnet, ctx):
        print('Removing Babel String obfuscation')
        if not self.remove_string_obfuscation(dotnet):
            return True
        self.clean_code(dotnet)
        dotnet.add_string('DNU_BABEL_DEOB')
        return True