from dotnetutils.deobfuscators.deobfuscator import Deobfuscator
from dotnetutils import net_row_objects, net_sigs, net_emulator, net_exceptions, net_emu_types, net_opcodes, net_graph_analyzer
from dotnetutils import net_structs, dotnetpefile

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

def dnr_encrypt_skip_conv_u(emulator, argument):
    obj = emulator.get_stack().peek_obj()
    if isinstance(obj, net_emu_types.BoxedReference):
        emulator.get_stack().remove_obj()
        new_obj = net_emu_types.DotNetUIntPtr(emulator, None)
        new_obj.init_zero()
        emulator.get_stack().append_obj(new_obj)
        return False
    return True

def dnr_encrypt_skip_intptr_newobjs(emulator, argument):
    instr = emulator.get_instr()
    arg = instr.get_argument()
    if isinstance(arg, net_row_objects.MemberRef):
        if arg.get_full_name() == b'System.IntPtr..ctor':
            emulator.get_stack().remove_obj()
            new_obj = net_emu_types.DotNetIntPtr(emulator, None)
            new_obj.init_zero()
            emulator.get_stack().append_obj(new_obj)
            return False
    return True

def dnr_encrypt_skip_marshal_calls(emulator, argument):
    instr = emulator.get_instr()
    stack = emulator.get_stack()
    method_obj = emulator.get_method_obj()
    if method_obj['Name'].get_value() == b'.cctor':
        if isinstance(instr.get_argument(), net_row_objects.MethodDef):
            msig = instr.get_argument().get_method_signature()
            if msig.get_return_type() == net_sigs.get_CorSig_Void():
                if len(msig.get_parameters()) == 0:
                    return False
    if instr.get_name() == 'call':
        instr_arg = instr.get_argument()
        if isinstance(instr_arg, net_row_objects.MemberRef):
            full_name = instr_arg.get_full_name()
            if full_name.startswith(b'System.Runtime.InteropServices.Marshal.'):
                full_name = full_name.replace(b'System.Runtime.InteropServices.Marshal.', b'', 1)
                if full_name == b'Copy':
                    stack.remove_obj()
                    stack.remove_obj()
                    stack.remove_obj()
                    stack.remove_obj()
                    return False
                else:
                    for x in range(len(instr_arg.get_param_types())):
                        stack.remove_obj()
                    intptr = net_emu_types.DotNetIntPtr(emulator, None)
                    intptr.init_zero()
                    stack.append_obj(intptr)
                    return False
            elif full_name == b'System.Type.GetType':
                stack.remove_obj()
                stack.remove_obj()
                stack.append_obj(None) #Append a null to fool check.
                return False
    return True

def dnr_encrypt_stop_ldelema(emulator, argument):
    instr = emulator.get_instr()
    if instr.get_opcode() == net_opcodes.Opcodes.Ldelema:
        raise net_exceptions.EmulatorEndExecutionException(emulator, emulator.get_method_obj().get_rid(), 0, 0, 0)
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
    
    def identify_encryption_method(self, dotnet):
        m_pdata = 'm_pData'.encode('utf-16le')
        m_ptr = 'm_ptr'.encode('utf-16le')
        for method in dotnet.get_methods_by_name(b'.cctor'):
            if method.has_body():
                for instr in method.disassemble_method():
                    if instr.get_name() == 'call':
                        instr_arg = instr.get_argument()
                        if not isinstance(instr_arg, net_row_objects.MethodDef):
                            continue

                        if not instr_arg.is_static_method():
                            continue
                        if instr_arg.has_return_value():
                            continue
                        if len(instr_arg.get_param_types()) != 0:
                            continue
                        has_pdata = False
                        has_mptr = False
                        for instr2 in instr_arg.disassemble_method():
                            if instr2.get_name() == 'ldstr':
                                instr2_arg = instr2.get_argument()
                                if instr2_arg == m_pdata:
                                    has_pdata = True
                                if instr2_arg == m_ptr:
                                    has_mptr = True
                            if has_mptr and has_pdata:
                                return instr_arg
                            
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
        encryption_method = self.identify_encryption_method(dotnet)
        print('Encryption method identified as {}'.format(encryption_method))
        emu_obj = net_emulator.DotNetEmulator(encryption_method)
        emu_obj.setup_method_params([])
        appdomain = emu_obj.get_appdomain()
        appdomain.register_instr_handler(net_opcodes.Opcodes.Ldelema, dnr_encrypt_stop_ldelema, None)
        appdomain.register_instr_handler(net_opcodes.Opcodes.Call, dnr_encrypt_skip_marshal_calls, None)
        appdomain.register_instr_handler(net_opcodes.Opcodes.Conv_U, dnr_encrypt_skip_conv_u, None)
        appdomain.register_instr_handler(net_opcodes.Opcodes.Newobj, dnr_encrypt_skip_intptr_newobjs, None)
        worked = False
        try:
            emu_obj.run_function()
        except net_exceptions.EmulatorEndExecutionException:
            worked = True
        if not worked:
            print('initial emulation failed.')
            return
        emu_obj.get_stack().remove_obj()
        encrypted_data = emu_obj.get_stack().pop_obj()
        if not isinstance(encrypted_data, net_emu_types.DotNetArray):
            print('error with emulation')
            return
        last_ldc_i8 = None
        prev_instr = None
        for instr in encryption_method.disassemble_method():
            if instr.get_opcode() == net_opcodes.Opcodes.Ldc_I8:
                last_ldc_i8 = instr

            if instr.get_opcode() == net_opcodes.Opcodes.Conv_I8:
                if prev_instr.get_opcode() == net_opcodes.Opcodes.Ldc_I4:
                    last_ldc_i8 = prev_instr
            
            if instr.get_opcode() == net_opcodes.Opcodes.Stind_I8:
                break
            prev_instr = instr
        if last_ldc_i8 is None:
            print('error cant get xor val')
            return
        xor_val = last_ldc_i8.get_argument()
        encrypted_data = encrypted_data.as_bytes()
        amt = len(encrypted_data) // 8
        decrypted_data = bytearray()
        index = 0
        for _ in range(amt):
            new_val = int.from_bytes(encrypted_data[index:index+8], 'little') ^ xor_val
            index += 8
            decrypted_data.extend(int.to_bytes(new_val, 8, 'little'))
        reader = net_structs.DotNetDataReader(bytes(decrypted_data))
        reader.read_int32()
        reader.read_int32()
        reader.read_int32()
        num1 = reader.read_int32()
        num2 = reader.read_int32()
        if num2 == 4 or num2 == 1:
            print('not supported yet')
            return
        initial_entries = dict()
        rva_offset = 0
        exe_data = dotnet.get_exe_data()
        for x in range(num1):
            rva = reader.read_int32() + rva_offset
            towrite = reader.read_int32()
            initial_entries[rva] = towrite
            offset = dotnet.get_pe().get_offset_from_rva(rva)
            exe_data = exe_data[:offset] + int.to_bytes(towrite, 4, 'little') + exe_data[offset + 4:]
        amt_entries = reader.read_int32()
        second_entries = dict()
        while not reader.is_end():
            rva = reader.read_int32() + rva_offset
            num = reader.read_int32() # we dont really care about this number its something for how the code is injected.
            code_length = reader.read_int32()
            code = reader.read(code_length)
            second_entries[rva] = code
        new_dpe = dotnetpefile.DotNetPeFile(pe_data=exe_data)
        for method_obj in dotnet.get_metadata_table('MethodDef'):
            rva = method_obj['RVA'].get_value()
            if method_obj.has_body():
                new_mdef = new_dpe.get_token_value(method_obj.get_token())
                new_dis = new_mdef.disassemble_method()
                test_rva = new_dis.get_header_size() + rva
                if test_rva in second_entries:
                    mdata = new_mdef.get_method_data()
                    print('Found encrypted func {}'.format(hex(method_obj.get_token())))
                    code = second_entries[test_rva]                        
                    new_mdata = mdata[:new_dis.get_header_size()] + code + mdata[new_dis.get_header_size() + new_dis.get_code_size():]
                    if new_dis.get_header_size() == 1:
                        if len(code) > 63:
                            raise Exception()
                        new_mdata = int.to_bytes((len(code) << 2) | 0x2, 1, 'little') + new_mdata[1:]
                    else:
                        new_mdata = new_mdata[:4] + int.to_bytes(len(code), 4, 'little') + new_mdata[8:]
                    new_mdata = bytearray(new_mdata)
                    if len(new_dis.get_exception_blocks()) != 0:
                        eh_offset = new_dis.get_header_size() + new_dis.get_code_size()
                        amt_padding = 0
                        if eh_offset % 4 != 0:
                            amt_padding = 0
                            while (eh_offset + amt_padding) % 4 != 0:
                                amt_padding += 1
                        new_eh_offset = new_dis.get_header_size() + len(code)
                        extra_data = new_mdata[new_eh_offset + amt_padding:]
                        new_mdata = new_mdata[:new_eh_offset]
                        while len(new_mdata) % 4 != 0:
                            new_mdata.append(0)
                        new_mdata.extend(extra_data)
                    method_obj.set_method_data(bytes(new_mdata))
        new_table = new_dpe.get_metadata_table('MethodDef')
        old_table = dotnet.get_metadata_table('MethodDef')
        for x in range(1, len(new_table) + 1):
            new_mdef = new_table.get(x)
            old_mdef = old_table.get(x)
            old_mdef.get_column('ImplFlags').set_raw_value(old_mdef.get_column('ImplFlags').get_raw_value())
            old_mdef.get_column('Flags').set_raw_value(old_mdef.get_column('Flags').get_raw_value())
            old_mdef.get_column('Signature').set_raw_value(old_mdef.get_column('Signature').get_raw_value())
            old_mdef.get_column('ParamList').set_raw_value(old_mdef.get_column('ParamList').get_raw_value())
        rva = dotnet.get_pe().get_rva_from_offset(dotnet.get_metadata_table('Module').get(1).get_file_offset())
        dotnet.patch_dpe(rva, 0, b'#~', rva + 1, None, 0, False)
        dotnet.reinit_dpe(False)
            
        print('Done decrypting {} methods'.format(amt_entries))
    
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
        print('handling code encryption.')
        #encrypted methods doesnt work yet, its close.
        #self.fix_encrypted_methods(dotnet)
        dotnet.add_string('DNU_NETREACTOR_WATERMARK')
        return True