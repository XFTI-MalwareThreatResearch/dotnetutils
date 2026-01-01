from dotnetutils.deobfuscators.deobfuscator import Deobfuscator
from dotnetutils import net_row_objects, net_sigs, net_emulator, net_exceptions, net_emu_types, net_opcodes

def dnr_skip_obf_methods(emulator, argument):
    method_obj = emulator.get_method_obj()
    instr = emulator.get_instr()
    if method_obj['Name'].get_value() == b'.cctor':
        if isinstance(instr.get_argument(), net_row_objects.MethodDef):
            msig = instr.get_argument().get_method_signature()
            if msig.get_return_type() == net_sigs.get_CorSig_Void():
                if len(msig.get_parameters()) == 0:
                    return False
    return True

class NETReactor(Deobfuscator):

    NAME = 'DotNetReactor'

    def __init__(self):
        pass

    def identify_unpack(self, dotnet, ctx):
        return False
    
    def identify_deobfuscate(self, dotnet, ctx):
        if dotnet.has_string(b'DNU_NETREACTOR_WATERMARK'):
            return False
        return self.identify_delegate_method(dotnet) is not None or self.identify_string_method(dotnet) is not None

    def identify_delegate_method(self, dotnet):
        delegate_class = dotnet.get_typeref_by_full_name(b'System.MulticastDelegate')
        if delegate_class is None:
            return None
        child_classes = delegate_class.get_child_classes()
        for tdef in child_classes:
            if isinstance(tdef, net_row_objects.TypeDef):
                cctor = tdef.get_static_constructor()
                if cctor is None:
                    continue
                dis = cctor.disassemble_method()
                for instr in dis:
                    if instr.get_name() == 'call':
                        arg = instr.get_argument()
                        if not arg.is_static_method():
                            continue
                        if isinstance(arg, net_row_objects.MethodDef):
                            msig = arg.get_method_signature()
                            if msig.get_return_type() == net_sigs.get_CorSig_Void():
                                params = msig.get_parameters()
                                if len(params) == 1:
                                    param = params[0]
                                    if isinstance(param, net_sigs.TypeDefOrRefSig):
                                        ptype = param.get_type()
                                        if ptype.get_full_name() == b'System.RuntimeTypeHandle':
                                            return arg
        return None
    
    def identify_string_method(self, dotnet):
        toint32 = dotnet.get_methods_by_full_name(b'System.BitConverter.ToInt32')
        if len(toint32) != 1:
            return None
        toint32 = toint32[0]
        for xref_rid, xref_offset in toint32.get_xrefs():
            xfm = dotnet.get_method_by_rid(xref_rid)
            if xfm is None:
                continue
            msig = xfm.get_method_signature()
            if msig.get_return_type() != net_sigs.get_CorSig_Void():
                continue
            params = msig.get_parameters()
            if len(params) != 1:
                continue
            typedef = params[0]
            if not isinstance(typedef, net_sigs.CorLibTypeSig):
                continue
            if typedef != net_sigs.get_CorSig_Int32():
                continue
            return xfm
        return None

    def unpack(self, dotnet, ctx):
        raise net_exceptions.OperationNotSupportedException()
    
    def remove_constant_static_fields(self, dotnet):
        constants_classes = list()
        for typedef in dotnet.get_metadata_table('TypeDef'):
            type_name = typedef['TypeName'].get_value()
            if type_name == b'<Module>':
                continue
            if type_name.startswith(b'<Module>'):
                type_name = type_name.replace(b'<Module>', '', 1)
                if type_name.startswith(b'{') and type_name.endswith(b'}') and type_name.count(b'-') == 5:
                    constants_classes.append(typedef)
        if len(constants_classes) == 0:
            print('no constant field classes found.')
            return
        
    def fix_encrypted_methods(self, dotnet):
        pass
    
    def remove_delegates(self, dotnet, del_method):
        start_offset = -1
        end_offset = -1
        for instr in del_method.disassemble_method():
            if instr.get_name() == 'call':
                arg = instr.get_argument()
                if isinstance(arg, net_row_objects.MemberRef):
                    if arg.get_full_name() == b'System.Threading.Monitor.Enter' and start_offset == -1:
                        start_offset = instr.get_instr_offset() + len(instr)

            if instr.get_name() == 'stsfld':
                end_offset = instr.get_instr_offset()

            if start_offset > 0 and end_offset > 0:
                break

        if start_offset == -1 or end_offset == -1:
            print('error 1')
            return
        
        emu_obj = net_emulator.DotNetEmulator(del_method, start_offset=start_offset, end_offset=end_offset)
        emu_obj.get_appdomain().register_instr_handler(net_opcodes.Opcodes.Call, dnr_skip_obf_methods, None)
        emu_obj.setup_method_params([])
        worked = False
        try:
            emu_obj.run_function()
        except net_exceptions.EmulatorEndExecutionException:
            worked = True

        if not worked:
            print('error 2')
            return
        
        tokens_dict = emu_obj.get_stack().pop_obj()
        if not isinstance(tokens_dict, net_emu_types.DotNetDictionary):
            print('error 3')
            return
        tokens_dict = tokens_dict.as_python_obj()
        
        for field_token, method_token in tokens_dict.items():
            is_virt = method_token & 0x40000000 > 0
            method_token &= 0x3fffffff
            field_obj = dotnet.get_token_value(field_token)
            mdef_obj = dotnet.get_token_value(method_token)
            msig = mdef_obj.get_method_signature()
            if field_obj is None or mdef_obj is None:
                print('error invalid token?')
                continue
            if is_virt:
                patch_bytes = bytes([net_opcodes.Opcodes.Callvirt]) + int.to_bytes(method_token, 4, 'little')
            else:
                patch_bytes = bytes([net_opcodes.Opcodes.Call]) + int.to_bytes(method_token, 4, 'little')

            for xref_rid, xref_offset in field_obj.get_xrefs():
                xfm = dotnet.get_method_by_rid(xref_rid)
                dis = xfm.disassemble_method()
                xfm_instr = dis.get_instr_at_offset(xref_offset)

                invoke_func = None
                for x in range(xfm_instr.get_instr_index(), len(dis)):
                    instr = dis[x]
                    if instr.is_branch() or instr.is_absolute_jmp():
                        break

                    if instr.get_name() == 'call':
                        arg = instr.get_argument()
                        if arg.get_parent_type() != field_obj.get_parent_type():
                            continue
                        msig_invoke = arg.get_method_signature()
                        if msig_invoke.get_return_type() != msig.get_return_type():
                            continue

                        amt_args = len(msig.get_parameters())
                        if mdef_obj.method_has_this():
                            amt_args += 1
                        if amt_args != (len(msig_invoke.get_parameters()) - 1):
                            continue

                        #TODO add this comparison
                        is_equal = True
                        z = 0
                        for y in range(len(msig_invoke.get_parameters()) - 1):
                            if y == 0 and mdef_obj.method_has_this():
                                continue
                            if msig.get_parameters()[z] != msig_invoke.get_parameters()[y]:
                                is_equal = False
                                break
                            z += 1
                        if is_equal:
                            invoke_func = instr
                            break

                if invoke_func is None:
                    print('error no invoke func')
                    continue
                #patch and replace instrs
                dotnet.patch_instruction(xfm, b'\x00' * len(xfm_instr), xfm_instr.get_instr_offset(), len(xfm_instr))
                dotnet.patch_instruction(xfm, patch_bytes, invoke_func.get_instr_offset(), len(invoke_func))

    

    def deobfuscate(self, dotnet, ctx):
        string_method = self.identify_string_method(dotnet)
        delegate_method = self.identify_delegate_method(dotnet)
        print('delegate method identified as {}'.format(delegate_method))
        self.remove_delegates(dotnet, delegate_method)
        dotnet.add_string('DNU_NETREACTOR_WATERMARK')
        return True