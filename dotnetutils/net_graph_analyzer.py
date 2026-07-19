from dotnetutils import net_row_objects, net_graphing, net_exceptions, net_emu_types, net_emulator, net_structs
from dotnetutils.net_opcodes import Opcodes
from dotnetutils.net_graphing import FunctionBlock, FunctionGraph
from dotnetutils import net_cil_disas

#Set to True to enable verbose control-flow-deobfuscation diagnostics.
DEBUG = False

DEBUG_METHOD = 0

class GraphAnalyzer:

    MATH_OPS = [Opcodes.Not, Opcodes.Sub, Opcodes.Add, Opcodes.Neg, Opcodes.Xor, Opcodes.Shr, Opcodes.Shl, Opcodes.Or, Opcodes.Shr_Un, Opcodes.And, Opcodes.Mul, Opcodes.Div, Opcodes.Div_Un, Opcodes.Rem, Opcodes.Rem_Un]
    BRANCHES = [Opcodes.Brtrue, Opcodes.Brtrue_S, Opcodes.Brfalse, Opcodes.Brfalse_S, Opcodes.Beq, Opcodes.Beq_S, Opcodes.Bne_Un, Opcodes.Bne_Un_S, \
                Opcodes.Bge, Opcodes.Bge_S, Opcodes.Bge_Un, Opcodes.Bge_Un_S, Opcodes.Bgt, Opcodes.Bgt_S, Opcodes.Bgt_Un, Opcodes.Bgt_Un_S, \
                Opcodes.Ble, Opcodes.Ble_S, Opcodes.Ble_Un, Opcodes.Ble_Un_S, Opcodes.Blt, Opcodes.Blt_S, Opcodes.Blt_Un, Opcodes.Blt_Un_S, Opcodes.Switch]
    STLOC = [Opcodes.Stloc_S, Opcodes.Stloc, Opcodes.Stloc_0, Opcodes.Stloc_1, Opcodes.Stloc_2, Opcodes.Stloc_3]
    LDLOC = [Opcodes.Ldloc_S, Opcodes.Ldloc, Opcodes.Ldloc_0, Opcodes.Ldloc_1, Opcodes.Ldloc_2, Opcodes.Ldloc_3]
    ALLOWED_STACK_OPS = LDLOC + [Opcodes.Br, Opcodes.Pop, Opcodes.Br_S, Opcodes.Ldc_I4, Opcodes.Ldc_I4_S, Opcodes.Ldloc, Opcodes.Ldloc_S, Opcodes.Dup, Opcodes.Ldc_I4_M1, Opcodes.Ldc_I4_0, Opcodes.Ldc_I4_1, Opcodes.Ldc_I4_2, Opcodes.Ldc_I4_3, Opcodes.Ldc_I4_4, Opcodes.Ldc_I4_5, Opcodes.Ldc_I4_6, Opcodes.Ldc_I4_7, Opcodes.Ldc_I4_8]
    ALLOWED_SWITCH_LOOP_INSTRS = LDLOC + STLOC + BRANCHES + MATH_OPS + ALLOWED_STACK_OPS
    LDC_INSTRS = [Opcodes.Ldc_I4, Opcodes.Ldc_I4_S, Opcodes.Ldc_I4_M1, Opcodes.Ldc_I4_0, Opcodes.Ldc_I4_1, Opcodes.Ldc_I4_2, Opcodes.Ldc_I4_3, Opcodes.Ldc_I4_4, Opcodes.Ldc_I4_5, Opcodes.Ldc_I4_6, Opcodes.Ldc_I4_7, Opcodes.Ldc_I4_8]
    ALLOWED_MODIFIERS = LDC_INSTRS + STLOC + LDLOC
    ALLOWED_MODIFIER_INSTRS = ALLOWED_MODIFIERS + MATH_OPS + [Opcodes.Dup, Opcodes.Nop]



    def __init__(self, method_obj: net_row_objects.MethodDefOrRef, func_graph: net_graphing.FunctionGraph):
        self.__graph = func_graph
        self.__disasm = self.__graph.get_disassembler()
        self.__method = method_obj


    def __are_additional_instrs_needed(self, block, instrs, start, end):
        if len(instrs) <= 1:
            raise net_exceptions.InvalidArgumentsException()
        #dont allow single instrs blocks, dont allow only checking one instruction.
        amt_on_stack = 0
        first_instr = instrs[start]
        if first_instr.get_pstack() != amt_on_stack:
            return True
        amt_on_stack = first_instr.get_nstack()
        second_instr = instrs[start + 1]
        if second_instr.get_pstack() > amt_on_stack:
            return True
        
        return False
    
    """
    Eventually going to want to move instruction generation out of here but for the prototype
    """
    def emit_branch_instr(self, opcode, offset, target, small):
        #target = argument + instr.size + instr.offset
        #target - instr.size - instr.offset = argument
        instr_one = self.__disasm.emit_instruction(opcode)

        encoded_target = target - offset
        if small:
            if not -126 <= encoded_target <= 129:
                raise net_exceptions.InvalidArgumentsException()
            instr_one.setup_instr_size(2)
            encoded_target -= 2
            instr_one.setup_argument_from_int8(encoded_target)
        else:
            encoded_target -= 5
            instr_one.setup_argument_from_int32(encoded_target)
            instr_one.setup_instr_size(5)
        return instr_one

    def emit_ldc_num(self, number):
        instrs = list()
        use_ldc_i4 = False
        if not isinstance(number, net_emu_types.DotNetNumber) or isinstance(number, int):
            raise net_exceptions.InvalidArgumentsException()
        pobj = number.as_python_obj()
        if isinstance(number, net_emu_types.DotNetSingle):
            instr_one = self.__disasm.emit_instruction(0x22)
            instr_one.setup_arguments_from_float(pobj)
            instr_one.setup_instr_size(5)
            instrs.append(instr_one)
        elif isinstance(number, net_emu_types.DotNetDouble):
            instr_one = self.__disasm.emit_instruction(0x23)
            instr_one.setup_instr_size(9)
            instr_one.setup_arguments_from_double(pobj)
            instrs.append(instr_one)
        elif isinstance(number, net_emu_types.DotNetBoolean):
            if pobj:
                instr_one = self.__disasm.emit_instruction(0x17)
            else:
                instr_one = self.__disasm.emit_instruction(0x16)
            instr_one.setup_instr_size(1)
            instrs.append(instr_one)
        else:
            if number.is_signed():
                if pobj == -1:
                    use_ldc_i4 = True
                    instr_one = self.__disasm.emit_instruction(0x15)
                    instr_one.setup_instr_size(1)
                    instrs.append(instr_one)
        if len(instrs) == 0:
            amt_needed = (pobj.bit_length() + 7) // 8
            if amt_needed <= 4 and -2147483648 <= pobj <= 2147483647:
                if 0 <= pobj <= 8:
                    opcode = 0x16 + pobj
                    instr_one = self.__disasm.emit_instruction(opcode)
                    instr_one.setup_instr_size(1)
                    instrs.append(instr_one)
                    use_ldc_i4 = True
                else:
                    if amt_needed == 1 and -128 <= pobj <= 127:
                        instr_one = self.__disasm.emit_instruction(0x1F)
                        instr_one.setup_arguments_from_int8(pobj)
                        instr_one.setup_instr_size(2)
                        instrs.append(instr_one)
                        use_ldc_i4 = True
                    elif amt_needed <= 4:
                        instr_one = self.__disasm.emit_instruction(0x20)
                        instr_one.setup_arguments_from_int32(pobj)
                        instr_one.setup_instr_size(5)
                        instrs.append(instr_one)
                        use_ldc_i4 = True
                    else:
                        raise net_exceptions.InvalidArgumentsException()
            elif amt_needed <= 8:
                instr_one = self.__disasm.emit_instruction(0x1E)
                instr_one.setup_arguments_from_int64(pobj)
                instr_one.setup_instr_size(9)
                instrs.append(instr_one)
            else:
                raise net_exceptions.InvalidArgumentsException()
            
            if isinstance(number, net_emu_types.DotNetUInt32):
                instr_one = self.__disasm.emit_instruction(0x6D)
                instr_one.setup_instr_size(1)
                instrs.append(instr_one)
            elif isinstance(number, net_emu_types.DotNetIntPtr):
                instr_one = self.__disasm.emit_instruction(0xD3)
                instr_one.setup_instr_size(1)
                instrs.append(instr_one)
            elif isinstance(number, net_emu_types.DotNetUIntPtr):
                instr_one = self.__disasm.emit_instruction(0xE0)
                instr_one.setup_instr_size(1)
                instrs.append(instr_one)
            elif isinstance(number, net_emu_types.DotNetInt64) and use_ldc_i4:
                instr_one = self.__disasm.emit_instruction(0x6A)
                instr_one.setup_instr_size(1)
                instrs.append(instr_one)
            elif isinstance(number, net_emu_types.DotNetUInt64):
                instr_one = self.__disasm.emit_instruction(0x6E)
                instr_one.setup_instr_size(1)
                instrs.append(instr_one)
        return instrs
    
    def __handle_math_instrs(self, block, instrs, start_index, end_index, amt_deleted):
        instr = instrs[end_index]
        start_instr = instrs[start_index]
        start_offset = start_instr.get_instr_offset()
        end_offset = instr.get_instr_offset()
        emu_obj = net_emulator.DotNetEmulator(self.__method, start_offset=start_offset, end_offset=end_offset, dont_execute_cctor=True, init_open_generics_as_object=True)
        try:
            emu_obj.run_function()
        except net_exceptions.EmulatorEndExecutionException:
            pass
        instrs_result = list()
        for x in range(len(emu_obj.get_stack())):
            result = emu_obj.get_stack().pop_obj()
            instrs_result = self.emit_ldc_num(result) + instrs_result
        amt_instrs = end_index - start_index

        block.remove_instrs(start_index + amt_deleted, end_index + amt_deleted)
        for x in range(len(instrs_result)):
            block.insert_instr(start_index + x + amt_deleted, instrs_result[x])
        return len(instrs_result) - amt_instrs
    
    def __get_all_paths_to_block(self, current_block: FunctionBlock, start_instr: net_cil_disas.Instruction, on_path: set, has_started=False, current_stack=list(), current_var_no=-1):
        DEBUG and print(f'__get_all_paths_to_block({current_block}, {start_instr}, {on_path})')
        DEBUG and print('current prevs {}'.format(current_block.get_prev()))
        if len(current_block.get_prev()) == 0:
            if has_started:
                return [[current_block]]
            else:
                if current_block.has_offset(start_instr.get_instr_offset()):
                    return [[current_block]]
                return []
        usable_stack = list(current_stack)
        results = list()
        if has_started or (not has_started and current_block.has_offset(start_instr.get_instr_offset())):
                
            for instr in reversed(list(current_block.get_instrs())):
                if not has_started and instr.get_instr_offset() == start_instr.get_instr_offset():
                    usable_stack.append(True)
                    has_started = True
                    continue
                if not has_started:
                    continue
                ins_op = instr.get_opcode()                

                if current_var_no != -1:
                    if ins_op in self.STLOC and current_var_no == instr.get_argument():
                        usable_stack.clear()
                        usable_stack.append(True)
                        current_var_no = -1
                        continue
                    continue

                added = instr.get_astack()
                pulled = instr.get_pstack()
                outputs = usable_stack[len(usable_stack) - added:] if added else []
                del usable_stack[len(usable_stack) - added:]
                in_slice = any(outputs)          
                if in_slice:
                    if ins_op not in self.ALLOWED_MODIFIER_INSTRS:
                        DEBUG and print('misidentify due to invaid ins_op', instr)
                        raise net_exceptions.ControlFlowDeobfuscationMisidentify('Not obfuscated')
                usable_stack.extend([in_slice] * pulled)  
                if not any(usable_stack):
                    if not in_slice or ins_op not in self.ALLOWED_MODIFIERS:
                        DEBUG and print('misidenitfy 2 due to invalid ins_op', instr)
                        raise net_exceptions.ControlFlowDeobfuscationMisidentify('Not obfuscated.')
                    else:
                        if ins_op in self.LDLOC:
                            current_var_no = instr.get_argument()
                            continue
                        return [[current_block]]
                
        if has_started:
            on_path = on_path | {current_block}
        cut_by_cycle = False
        for prev in current_block.get_prev():
            if prev in on_path:
                cut_by_cycle = True
                continue
            res = self.__get_all_paths_to_block(prev, start_instr, on_path, has_started, usable_stack, current_var_no)
            for sub in res:    
                results.append(sub + [current_block])
        if not results:
            if has_started and cut_by_cycle:
                return [[current_block]]
            return []
        return results

    def get_all_paths_to_block(self, to_block: FunctionBlock, start_instr: net_cil_disas.Instruction):
        return self.__get_all_paths_to_block(to_block, start_instr, set(), False, list())
    
    def __find_var_sets(self, path: list, var_no: int):
        for x in range(len(path)):
            blk = path[x]
            instrs = blk.get_instrs()
            for y in range(len(instrs)):
                instr = instrs[y]
                if instr.get_opcode() in self.STLOC:
                    if instr.get_argument() == var_no:
                        return instr, blk, x
        return None, None, None
    
    def __find_value_source(self, path: list, start_instr, modifier_instrs: list):
        started = False
        live = []
        for x in range(len(path)):
            blk = path[x]
            instrs = blk.get_instrs()
            for y in range(len(instrs) - 1, -1, -1):
                instr = instrs[y]
                ins_op = instr.get_opcode()
                if instr == start_instr:
                    started = True
                    live.append(True)          
                    continue
                if not started:
                    continue
                added = instr.get_astack()
                pulled = instr.get_pstack()
                outputs = live[len(live) - added:] if added else []
                del live[len(live) - added:]
                in_slice = any(outputs)            
                if in_slice:
                    modifier_instrs.append(instr)
                    if ins_op not in self.ALLOWED_MODIFIER_INSTRS:
                        return None, None, None
                live.extend([in_slice] * pulled)  
                if not any(live):
                    if in_slice and ins_op in self.ALLOWED_MODIFIERS:
                        return instr, blk, x
                    return None, None, None
        return None, None, None
    
    def __find_all_var_sets(self, var_no: int):
        result = list()
        for block in self.__graph.blocks():
            for instr in block.get_instrs():
                if instr.get_opcode() in self.STLOC:
                    if instr.get_argument() == var_no:
                        result.append((block, instr))
        return result
    
    def __find_all_var_sets_reachable_from(self, var_no: int, from_block: FunctionBlock, crawled=set()):
        if from_block.get_start_offset() in crawled:
            return []
        DEBUG and print(f'__find_all_var_sets_reachable_from({var_no}, {from_block}, {from_block.get_prev()})')
        crawled.add(from_block.get_start_offset())
        results = list()
        for instr in from_block.get_instrs():
            if instr.get_opcode() in self.STLOC and instr.get_argument() == var_no:
                results.append((from_block, instr))
        for prev in from_block.get_prev():
            results.extend(self.__find_all_var_sets_reachable_from(var_no, prev, crawled))
        return results
    
    def __is_reachable_from(self, instr: net_cil_disas.Instruction, from_block: FunctionBlock, crawled=set()):
        if from_block.get_start_offset() in crawled:
            return False
        DEBUG and print(f'__is_reachable_from({instr}, {from_block}, {from_block.get_prev()}) {from_block.get_instrs()}')
        crawled.add(from_block.get_start_offset())
        if from_block.has_offset(instr.get_instr_offset()):
            return True
        for prev in from_block.get_prev():
            if self.__is_reachable_from(instr, prev, crawled):
                return True
        return False
    
    def __find_value_sources_reachable_from(self, target: net_cil_disas.Instruction, from_block: FunctionBlock, is_start=True, needed=None, crawled=set()):
        if from_block.get_start_offset() in crawled:
            return []
        if needed is None:
            needed = target.get_pstack()
        started = not is_start
        DEBUG and print(f'__find_value_sources_reachable_from({target}, {from_block}, {from_block.get_prev()})')
        crawled.add(from_block.get_start_offset())
        results = list()
        for instr in reversed(from_block.get_instrs()):
            if is_start and target.get_instr_offset() == instr.get_instr_offset():
                started = True
                continue
            if not started:
                continue
            added = instr.get_astack()
            pulled = instr.get_pstack()
            DEBUG and print('checking instr {} {}'.format(needed, instr))
            needed = needed - added + pulled
            if needed == 0:
                return [instr]
        for prev in from_block.get_prev():
            results.extend(self.__find_value_sources_reachable_from(target, prev, False, needed, crawled))
        return results

    def new_switch_detection(self, switch_block: FunctionBlock):
        additional_work_traces = dict()

        if switch_block.get_last_instr() is None or switch_block.get_last_instr().get_opcode() != Opcodes.Switch:
            return False, [], [], [], [], additional_work_traces
        try:
            switch_paths = self.get_all_paths_to_block(switch_block, switch_block.get_last_instr())
        except net_exceptions.ControlFlowDeobfuscationMisidentify:
            DEBUG and print('bailing due to misidentify exception')
            return False, [], [], [], [], additional_work_traces
        all_modifiers = list()
        all_src_instrs = list()
        requires_additional_work = list()
        x = 0
        for switch_path in switch_paths:
            DEBUG and print('handling switch path', switch_path)
            switch_path.reverse()
            first_blk = switch_path[0]
            if first_blk.get_last_instr() is None:
                DEBUG and print('bailing 1')
                return False, [], [], [], [], additional_work_traces
            last_instr = first_blk.get_last_instr()
            if last_instr.get_opcode() != Opcodes.Switch:
                DEBUG and print('bailing 2')

                return False, [], [], [], [], additional_work_traces
            modifier_instrs = list()

            src_instr, src_blk, src_blk_index = self.__find_value_source(switch_path, last_instr, modifier_instrs)
            if src_instr is None:
                DEBUG and print('bailing 3')

                return False, [], [], [], [], additional_work_traces
            src_op = src_instr.get_opcode()
            modifier_instrs.reverse()
            amt = 0

            search_base = src_blk_index
            while src_op in self.LDLOC:
                if amt > 10:
                    DEBUG and print('bailing 4')

                    return False, [], [], [], [], additional_work_traces
                amt += 1
                var_no = src_instr.get_argument()

                DEBUG and print('trying to find var sets {} {}'.format(src_instr, search_base))
                var_set_instr, var_set_blk, rel_set_idx = self.__find_var_sets(switch_path[search_base:], var_no)
                if var_set_instr is None:
                    all_var_sets = self.__find_all_var_sets(var_no)

                    is_failure = False
                    source_entries = list()  
                    for var_block, var_instr in all_var_sets:
                        try:
                            var_paths = self.get_all_paths_to_block(var_block, var_instr)
                        except net_exceptions.ControlFlowDeobfuscationMisidentify:
                            DEBUG and print('bailing 5')

                            return False, [], [], [], [], additional_work_traces

                        for var_path in var_paths:
                            DEBUG and print('checking var path', var_path)
                            var_path.reverse()
                            child_modifiers = list()
                            resolved_src, var_set_blk, var_blk_index = self.__find_value_source(var_path, var_instr, child_modifiers)
                            if resolved_src is None:
                                DEBUG and print('is failure var_set_instr', resolved_src)
                                is_failure = True
                                break
                            DEBUG and print('Child modifiers', child_modifiers, modifier_instrs)
                            child_modifiers.reverse()
                            source_modifiers = list(child_modifiers) + [var_instr]
                            seen_vars = set()
                            while resolved_src.get_opcode() in self.LDLOC:

                                chained_var = resolved_src.get_argument()
                                if chained_var in seen_vars:
                                    break
                                seen_vars.add(chained_var)
                                DEBUG and print('Checking chained var', resolved_src)
                                chained_set, _, chained_idx = self.__find_var_sets(var_path[var_blk_index + 1:], chained_var)
                                if chained_set is None:
                                    break
                                chained_modifiers = list()
                                resolved, _, resolved_idx = self.__find_value_source(var_path[var_blk_index + 1 + chained_idx:], chained_set, chained_modifiers)
                                if resolved is None:
                                    break
                                DEBUG and print('Chained modifier instrs', chained_modifiers, modifier_instrs)
                                chained_modifiers.reverse()
                                source_modifiers = chained_modifiers + [chained_set] + source_modifiers
                                resolved_src = resolved
                                var_blk_index = var_blk_index + 1 + chained_idx + resolved_idx

                            if resolved_src.get_opcode() not in self.LDC_INSTRS and resolved_src.get_opcode() not in self.LDLOC:
                                is_failure = True
                                break
                            combined_path = list(switch_path) + list(var_path)
                            source_entries.append((resolved_src, combined_path, source_modifiers + modifier_instrs))

                        if is_failure:
                            DEBUG and print('bailing 6')

                            return False, [], [], [], [], additional_work_traces

                    if not is_failure:
                        requires_additional_work.append(x)
                        additional_work_traces[x] = source_entries
                        break
                    DEBUG and print('bailing 7')

                    return False, [], [], [], [], additional_work_traces
                var_blk_index = search_base + rel_set_idx
                child_modifiers = list()
                src_instr, src_blk, rel_src_idx = self.__find_value_source(switch_path[var_blk_index:], var_set_instr, child_modifiers)
                if src_instr is None:
                    DEBUG and print('bailing 8')

                    return False, [], [], [], [], additional_work_traces
                
                src_blk_index = var_blk_index + rel_src_idx
                src_op = src_instr.get_opcode()
                child_modifiers.reverse()
                modifier_instrs = child_modifiers + [var_set_instr] + modifier_instrs
                search_base = var_blk_index + 1
            if src_op not in self.LDC_INSTRS and (x not in requires_additional_work and src_op not in self.LDLOC):
                DEBUG and print('bailing 9')

                return False, [], [], [], []. additional_work_traces
            all_modifiers.append(modifier_instrs)
            all_src_instrs.append(src_instr)
            x += 1
        DEBUG and print('Detected as initial switch')
        return True, switch_paths, all_modifiers, all_src_instrs, requires_additional_work, additional_work_traces

    def __collapse_switch_to_case(self, new_graph, switch_block, orig_switch_block, value):
        """ Rewrite a single-valued switch blocks terminator into an unconditional branch to the one
        case it always takes, keeping the block (it may be a try-start or hold real code) and its
        predecessors. """
        case = new_graph.get_block_by_offset(orig_switch_block.get_next()[value].get_start_offset())
        last_instr = switch_block.get_last_instr()
        br = self.__disasm.emit_instruction(Opcodes.Br)
        br.setup_instr_size(5)
        br.setup_instr_offset(last_instr.get_instr_offset(), last_instr.get_instr_index())
        br.setup_arguments_from_int32(case.get_start_offset() - last_instr.get_instr_offset() - 5)
        switch_block.replace_instr(len(switch_block.get_instrs()) - 1, br)
        for nxt in list(switch_block.get_next()):
            switch_block.remove_next(nxt)
        switch_block.add_next(case)

    def __is_pure_dispatch(self, block):
        """ True if every instruction before the terminator is state-management junk (loads,
        stores, constants, arithmetic, dup/pop/nop/br) with no real, side-effecting code.  Rerouting
        predecessors past such a block is safe."""
        allowed = set(self.LDLOC) | set(self.STLOC) | set(self.LDC_INSTRS) | set(self.MATH_OPS) | \
                  {Opcodes.Nop, Opcodes.Pop, Opcodes.Dup, Opcodes.Br, Opcodes.Br_S}
        return all(instr.get_opcode() in allowed for instr in block.get_instrs()[:-1])

    def new_switch_deob(self, switch_block: FunctionBlock):
        if switch_block is None:
            raise Exception()
        is_obf, switch_paths, all_modifiers, all_src_instrs, needs_more_work, additional_work_traces = self.new_switch_detection(switch_block)
        if not is_obf:
            return None
        if not (len(switch_paths) == len(all_modifiers) == len(all_src_instrs)):
            raise Exception()
        path_values = list()
        
        switch_paths_by_value = dict()
        x = 0
        for switch_path, modifiers, src_instrs in zip(switch_paths, all_modifiers, all_src_instrs):
            if x in needs_more_work:
                path_values.append(None)
                x += 1
                continue
            DEBUG and print('emulating instructions {} {}'.format(modifiers, switch_path))
            emu = net_emulator.DotNetEmulator(self.__method, force_instrs=modifiers, dont_execute_cctor=True, init_open_generics_as_object=True)
            emu.run_function()
            num = emu.get_stack().pop_obj()
            if not isinstance(num, net_emu_types.DotNetNumber):
                raise Exception()
            DEBUG and print('emulation returned {}'.format(num))
            num = num.as_python_obj()
            path_values.append(num)
            if num not in switch_paths_by_value:
                switch_paths_by_value[num] = list()
            switch_paths_by_value[num].append((switch_path, modifiers, src_instrs))
            x += 1

        largest_path = 0
        all_paths = list(zip(switch_paths, path_values, all_modifiers))
        for num, switch_infos in switch_paths_by_value.items():
            for switch_info in switch_infos:
                switch_path, modifiers, src_instrs = switch_info
                largest_path = max(len(switch_path), largest_path)
        #now extend the paths to be the same size
        for path, n, m in all_paths:
            path.extend([None] * (largest_path - len(path)))
        path_diverges = dict()
        for x in range(largest_path):
            for y in range(len(all_paths)):
                curr_path, curr_num, modifiers = all_paths[y]
                if len(curr_path) <= x or curr_path[x] is None:
                    continue

                is_unique = True
                curr_blk = curr_path[x]
                for switch_path, other_num, src_instrs in all_paths:
                    if other_num != curr_num and curr_blk in switch_path[x:]:
                        is_unique = False
                        break

                if is_unique and y not in path_diverges:
                    path_diverges[y] = x
        if  len(path_diverges) != len(all_paths):
            return None
        
        to_remove_instrs = dict()
        for modifiers in all_modifiers:
            for modifier in modifiers:
                to_remove_instrs[modifier.get_instr_offset()] = modifier
        new_graph = self.__graph.duplicate()
        new_switch_block = new_graph.get_block_by_offset(switch_block.get_start_offset())
        switch_nexts = switch_block.get_next()
        if len(set(path_values)) == 1:
            self.__collapse_switch_to_case(new_graph, new_switch_block, switch_block, path_values[0])
        else:

            if not self.__is_pure_dispatch(new_switch_block):
                return None
            for path_no, block_index in path_diverges.items():
                if path_no in needs_more_work:
                    continue
                curr_path, curr_num, modifier_instrs = all_paths[path_no]
                target = path_values[path_no]
                new_target = new_graph.get_block_by_offset(curr_path[block_index].get_start_offset())

                if not (0 < len(new_target.get_next()) < 3):
                    return None
                if len(new_target.get_next()) == 2:
                    target_prev = new_target.get_next()[0]
                    nstack_original = 0
                    nstack_modified = 0
                    for instr in new_target.get_instrs():
                        nstack_original += instr.get_nstack()
                        if instr.get_instr_offset() not in to_remove_instrs:
                            nstack_modified += instr.get_nstack()

                    if nstack_original - nstack_modified >= 2:
                        raise Exception() #Bail, weird amount of adds

                    if (nstack_original - nstack_modified) == 1:
                        check = new_target.get_next()[1]
                        should_remove = len(check.get_instrs()) > 0 and check.get_instrs()[0].get_opcode() == Opcodes.Pop
                        if should_remove:
                            check.remove_instrs(0, 1)
                else:
                    target_prev = new_graph.get_block_by_offset(curr_path[block_index - 1].get_start_offset())
                target = target & 0xFFFFFFFF
                if target >= len(switch_nexts):
                    target = len(switch_nexts) - 1
                DEBUG and print('target', len(switch_nexts), target, curr_path)
                next_block = new_graph.get_block_by_offset(switch_nexts[target].get_start_offset())
                
                if new_target.has_next(target_prev):
                    DEBUG and print('MAIN-REROUTE: new_target=%s (term=%s) target_prev=%s next=%s' % (
                        hex(new_target.get_start_offset()),
                        new_target.get_last_instr().get_name() if new_target.get_last_instr() else None,
                        hex(target_prev.get_start_offset()), hex(next_block.get_start_offset())))
                    new_target.replace_next(target_prev, next_block)
                else:
                    if next_block != new_switch_block and new_switch_block.has_next(next_block):
                        new_switch_block.remove_next(next_block)
        if len(needs_more_work) > 0:
            DEBUG and print('needs more work {}'.format(needs_more_work))
            DEBUG and print('additional work traces', additional_work_traces)
            for index in needs_more_work:
                curr_path, curr_num, modifier_instrs = all_paths[index]
                DEBUG and print('curr path {} {} {}'.format(curr_path, curr_num, modifier_instrs))
                if index in additional_work_traces:
                    ncases = len(switch_block.get_last_instr().get_argument())
                    DEBUG and print('Checking index ', index)
                    values = list()
                    for base_src, combined_path, full_modifiers in additional_work_traces[index]:
                        DEBUG and print('base src', base_src)
                        if len(combined_path) < 2 or combined_path[-1] is None or combined_path[-2] is None:
                            continue
                        try:
                            emu = net_emulator.DotNetEmulator(self.__method, force_instrs=full_modifiers, dont_execute_cctor=True, init_open_generics_as_object=True)
                            emu.run_function()
                            num = emu.get_stack().pop_obj()
                        except Exception:
                            continue
                        if not isinstance(num, net_emu_types.DotNetNumber):
                            continue
                        DEBUG and print('num', num)
                        val = num.as_python_obj()
                        val = val & 0xFFFFFFFF
                        values.append(val)
                else:
                    raise Exception()
                instr = modifier_instrs[0]
                if instr.get_opcode() not in self.LDLOC:
                    raise Exception()
                orig_instr = instr
                orig_instr_block = self.__graph.get_block_by_offset(orig_instr.get_instr_offset())
                if not orig_instr_block.get_last_instr().is_branch() or orig_instr_block.get_last_instr().get_pstack() != 2:
                    for block in curr_path:
                        if block is None:
                            continue
                        for instr2 in reversed(block.get_instrs()):
                            if instr2.get_opcode() in self.LDLOC:
                                if instr.get_argument() == instr2.get_argument():
                                    instr = instr2
                                    break
                        if orig_instr != instr:
                            break
                DEBUG and print('Finding all reachable sets from {}'.format(instr))
                if len(values) > 1:
                    ncases = len(switch_block.get_last_instr().get_argument())
                    path_offsets = {b.get_start_offset() for b in curr_path if b is not None}
                    entry_idx = next((i for i, nb in enumerate(switch_nexts)
                                        if nb.get_start_offset() in path_offsets), None)
                    if entry_idx is not None and entry_idx >= ncases:
                        ranged = {v for v in values if v >= ncases}
                        if ranged:
                            values = ranged
                start_index = len(curr_path) - 1
                while curr_path[start_index] is None:
                    start_index -= 1
                DEBUG and print('reachable values {} {} {}'.format(values, switch_block.has_next(curr_path[start_index]), curr_path[start_index]))
                if len(values) == 0 and switch_block.has_next(curr_path[start_index]):
                    idx = switch_block.get_next().index(curr_path[start_index])
                    DEBUG and print('idx', idx)
                    if idx == (len(switch_block.get_next()) - 1):
                        if not any(v is not None and v >= (len(switch_block.get_next()) - 1) for v in path_values):
                            DEBUG and print('skipping because fallthrough literally cant happen')
                            last_blk = new_graph.get_block_by_offset(curr_path[start_index].get_start_offset())
                            new_switch_block.remove_next(last_blk)
                            continue
                    else:
                        if idx not in path_values:
                            DEBUG and print('skipping because block literally cant happen')
                            last_blk = new_graph.get_block_by_offset(curr_path[start_index].get_start_offset())
                            new_switch_block.remove_next(last_blk)
                            continue

                if len(values) != 1:
                    #TODO: multiple distinct definitions  split, routing each source to its own case.
                    return None
                var_value = values.pop()
                orig_var_value = var_value
                if var_value >= len(switch_nexts):
                    var_value = len(switch_nexts) - 1
                case_block = new_graph.get_block_by_offset(switch_nexts[var_value].get_start_offset())

                fidx = path_diverges[index]
                if fidx <= 0:
                    return None
                detach = new_graph.get_block_by_offset(curr_path[fidx].get_start_offset())
                feed = new_graph.get_block_by_offset(curr_path[fidx - 1].get_start_offset())
                detach_last = detach.get_last_instr()
                if detach_last is None or not detach.has_next(feed):
                    return None
                DEBUG and print('NMW-DETACH: detach=%s (term=%s) feed=%s case=%s var_value=%s' % (
                    hex(detach.get_start_offset()), detach_last.get_name(),
                    hex(feed.get_start_offset()), hex(case_block.get_start_offset()), var_value))
                
                if detach_last.is_branch() and detach_last.get_pstack() == 2:
                    replaced = False
                    for pblk in reversed(curr_path):
                        if pblk is None:
                            continue
                        blk = new_graph.get_block_by_offset(pblk.get_start_offset())
                        last = blk.get_last_instr()
                        if last is None or last.get_opcode() not in (Opcodes.Beq, Opcodes.Beq_S):
                            continue
                        for idx, bi in enumerate(blk.get_instrs()):
                            if bi.get_opcode() in self.LDLOC and bi.get_argument() == instr.get_argument():
                                ldc = self.__disasm.emit_instruction(Opcodes.Ldc_I4)
                                ldc.setup_instr_size(5)
                                ldc.setup_instr_offset(bi.get_instr_offset(), bi.get_instr_index())
                                ldc.setup_arguments_from_int32(orig_var_value)
                                DEBUG and print('Replacing instr {} with {} '.format(blk.get_instrs()[idx], ldc))
                                blk.replace_instr(idx, ldc)
                                replaced = True
                                break
                        if replaced:
                            break
                    if not replaced:
                        return None


                    detach.replace_next(feed, case_block)
                elif detach_last.get_opcode() in (Opcodes.Br, Opcodes.Br_S):
                    detach_instrs = detach.get_instrs()
                    if len(detach_instrs) >= 2 and detach_instrs[-2].get_astack() == 1 and detach_instrs[-2].get_pstack() == 0:
                        DEBUG and print('detatching instrs ', detach_instrs[-2])
                        to_remove_instrs[detach_instrs[-2].get_instr_offset()] = detach_instrs[-2]
                    detach.replace_next(feed, case_block)
                else:
                    return None
                if new_switch_block.has_next(case_block):
                    new_switch_block.remove_next(case_block)

        #for now make the assumption that all modifier instructions can be removed, however that isnt guaranteed to be the case.
        if new_switch_block.get_last_instr() is not None and new_switch_block.get_last_instr().get_opcode() == Opcodes.Switch:
            to_remove_instrs[new_switch_block.get_last_instr().get_instr_offset()] = new_switch_block.get_last_instr()

        for block in new_graph.blocks():
            instrs = list(block.get_instrs())
            actual_index = 0
            original_nstack = 0
            modified_nstack = 0
            for x in range(len(instrs)):
                instr = instrs[x]
                original_nstack += instr.get_nstack()
                if instr.get_instr_offset() in to_remove_instrs:
                    block.remove_instrs(actual_index,actual_index+1)
                    continue
                modified_nstack += instr.get_nstack()
                actual_index += 1
            if (original_nstack - modified_nstack) == 1 and len(block.get_next()) == 2:
                check = block.get_next()[1]
                if len(check.get_instrs()) > 0 and check.get_instrs()[0].get_opcode() == Opcodes.Pop:
                    check.remove_instrs(0, 1)
        changed = True
        while changed:
            changed = False
            to_remove = set()
            for block in new_graph.blocks():
                last_instr = block.get_last_instr()
                if last_instr is None:
                    nxts = list(block.get_next())
                    prvs = list(block.get_prev())
                    if len(prvs) == len(nxts) <= 0:
                        if len(nxts) == 1:
                            prev = prvs[0]
                            nxt = nxts[0]
                            prev.replace_next(block, nxt)
                            block.remove_next(nxt)
                        to_remove.add(block)
                    else:
                        if len(nxts) == 1:
                            if block.is_block_start():
                                nxt = nxts[0]
                                DEBUG and print('CLEANUP-STARTMERGE: block %s (nexts %s) merges nxt %s (nexts %s)' % (
                                    hex(block.get_start_offset()), [hex(n.get_start_offset()) for n in block.get_next()],
                                    hex(nxt.get_start_offset()), [hex(n.get_start_offset()) for n in nxt.get_next()]))
                                if len(nxt.get_prev()) != 1:
                                    new_br = self.__disasm.emit_instruction(Opcodes.Br)
                                    new_br.setup_instr_size(5)
                                    new_br.setup_instr_offset(block.get_start_offset(), block.get_start_index())
                                    new_br.setup_arguments_from_int32(nxt.get_start_offset() - block.get_start_offset() - 5)
                                    block.add_instr(new_br)
                                    continue
                                block.merge_block(nxt)
                                for nxtblk in list(nxt.get_next()):
                                    block.add_next(nxtblk)
                                nxt.clear_next()
                                to_remove.add(nxt)
                            else:
                                nxt = nxts[0]
                                DEBUG and print('CLEANUP-MERGE: empty block %s -> nxt %s, repointing prevs %s' % (
                                    hex(block.get_start_offset()), hex(nxt.get_start_offset()),
                                    [hex(p.get_start_offset()) for p in prvs]))
                                for prev in prvs:
                                    prev.replace_next(block, nxt)
                                to_remove.add(block)
                        elif len(prvs) == 0 and not block.is_block_start():
                            block.clear_next()
                            to_remove.add(block)
                        elif len(prvs) == 1 and not block.is_block_start():
                            DEBUG and print('CLEANUP-CASCADE: empty block %s prev %s <- nexts %s' % (
                                hex(block.get_start_offset()), hex(prvs[0].get_start_offset()),
                                [hex(n.get_start_offset()) for n in nxts]))
                            for nxt in nxts:
                                block.remove_next(nxt)
                                prvs[0].add_next(nxt)
                            to_remove.add(block)
                        else:
                            if len(nxts) == 2:
                                if nxts[0] == nxts[1]:
                                    block.remove_next(nxts[0])
                            continue
                else:
                    if len(block.get_next()) == len(block.get_prev()) == 0 and not block.is_block_start():
                        to_remove.add(block)
                        continue
                    if last_instr.get_opcode() not in (Opcodes.Throw, Opcodes.Ret, Opcodes.Rethrow, Opcodes.Endfinally, Opcodes.Leave, Opcodes.Leave_S):
                        nxts = list(block.get_next())
                        if len(nxts) == 0:
                            if block.get_start_offset() in (0x281, 0xbe, 0x27c, 0x93e):
                                DEBUG and print('DEAD-0NEXTS: removing %s (term=%s) prevs=%s' % (
                                    hex(block.get_start_offset()), last_instr.get_name(),
                                    [hex(p.get_start_offset()) for p in block.get_prev()]))
                            to_remove.add(block)
                            for prv in block.get_prev():
                                prv.remove_next(block)
                    if not block.is_block_start():
                        if len(block.get_prev()) == 0:
                            if block.get_start_offset() in (0x281, 0xbe, 0x27c, 0x93e):
                                DEBUG and print('DEAD-0PREV: removing %s (term=%s) nexts=%s' % (
                                    hex(block.get_start_offset()), last_instr.get_name(),
                                    [hex(n.get_start_offset()) for n in block.get_next()]))
                            for nxt in list(block.get_next()):
                                block.remove_next(nxt)
                            to_remove.add(block)
                    if len(block.get_next()) == 2:
                        nxts = block.get_next()
                        if nxts[0] == nxts[1]:
                            last_instr = block.get_last_instr()
                            DEBUG and print('BOTH-NEXTS-SAME collapse: block %s term=%s pstack=%d converged-next=%s instrs=%s' % (
                                hex(block.get_start_offset()), last_instr.get_name(), last_instr.get_pstack(),
                                hex(nxts[0].get_start_offset()),
                                [i.get_name() for i in block.get_instrs()]))
                            if not last_instr.is_branch():
                                raise Exception()
                            nxt = nxts[0]
                            block.remove_next(nxt)
                            #Need to replace with pop, br
                            for x in range(last_instr.get_pstack()):
                                new_instr = self.__disasm.emit_instruction(Opcodes.Pop)
                                new_instr.setup_instr_size(1)
                                new_instr.setup_instr_offset(last_instr.get_instr_offset() + x, last_instr.get_instr_index() + x) 
                                if x == 0:
                                    block.replace_instr(len(block.get_instrs()) - 1, new_instr)
                                else:
                                    block.add_instr(new_instr)

                            new_instr = self.__disasm.emit_instruction(Opcodes.Br)
                            new_instr.setup_instr_size(5)
                            new_instr.setup_instr_offset(last_instr.get_instr_offset() + 1, last_instr.get_instr_index() + 1)
                            new_instr.setup_arguments_from_int32(nxt.get_start_offset() - (last_instr.get_instr_offset() + 1) - 5)
                            block.add_instr(new_instr)
                    last_instr = block.get_last_instr()
                    if last_instr.get_opcode() == Opcodes.Switch:
                        if len(block.get_next()) == 1:
                            nxt = block.get_next()[0]
                            DEBUG and print('SWITCH-COLLAPSE: switch-block %s -> nxt %s (nxt nexts %s, same-list=%s)' % (
                                hex(block.get_start_offset()), hex(nxt.get_start_offset()),
                                [hex(n.get_start_offset()) for n in nxt.get_next()],
                                block.get_next() is nxt.get_next()))
                            new_pop = self.__disasm.emit_instruction(Opcodes.Pop)
                            new_pop.setup_instr_size(1)
                            new_pop.setup_instr_offset(last_instr.get_instr_offset(), last_instr.get_instr_index())
                            block.replace_instr(len(block.get_instrs()) - 1, new_pop)
                            new_br = self.__disasm.emit_instruction(Opcodes.Br)
                            new_br.setup_instr_size(5)
                            new_br.setup_instr_offset(last_instr.get_instr_offset() + 1, last_instr.get_instr_index() + 1)
                            new_br.setup_arguments_from_int32(nxt.get_start_offset() - (last_instr.get_instr_offset() + 1) - 5)
                            block.add_instr(new_br)
                            DEBUG and print('  after collapse: switch-block %s nexts %s ; nxt %s nexts %s' % (
                                hex(block.get_start_offset()), [hex(n.get_start_offset()) for n in block.get_next()],
                                hex(nxt.get_start_offset()), [hex(n.get_start_offset()) for n in nxt.get_next()]))
                            changed = True
                            continue

            if to_remove:
                DEBUG and print('TO-REMOVE this pass: %s' % [hex(b.get_start_offset()) for b in to_remove])
            for block in to_remove:
                changed = True
                if any(p.get_start_offset() == 0x26e for p in block.get_prev()):
                    DEBUG and print('  removing %s which is a next of 0x26e (its prevs=%s, nexts=%s)' % (
                        hex(block.get_start_offset()),
                        [hex(p.get_start_offset()) for p in block.get_prev()],
                        [hex(n.get_start_offset()) for n in block.get_next()]))
                block.clear_next()
                block.clear_prev()
                new_graph.unregister_block(block.get_start_offset())
        new_graph.repopulate_prevs()
        DEBUG and print('pre validation')
        DEBUG and new_graph.print_root()
        new_graph.validate_blocks()
        new_analyzer = GraphAnalyzer(self.__method, new_graph)
        new_analyzer.repair_blocks()
        DEBUG and print('post deob')
        DEBUG and new_graph.print_root()
        return new_graph

    def simplify_control_flow(self, max_attempts=-1):
        graph = self.__graph
        is_obfuscated_at_all = False
        attempts = 0
        if DEBUG and DEBUG_METHOD != self.__method.get_token():
            return None
        (DEBUG or DEBUG_METHOD == 1) and print('deobfuscating method {}'.format(hex(self.__method.get_token())))
        while True:
            graph = self.__graph
            is_obfuscated = False
            out = None
            candidate = graph.duplicate()
            if self.__fold_constant_branches(candidate) > 0:
                #deal with branch folds first since it makes DNR deobfuscation much easier.
                try:
                    candidate.validate_blocks()
                    GraphAnalyzer(self.__method, candidate).repair_blocks()
                    candidate.update_offsets()
                    candidate.sort_blocks()
                    candidate.validate_blocks()
                except net_exceptions.InvalidBlockException:
                    candidate = None
                if candidate is not None:
                    out = candidate
                    is_obfuscated = True
                    is_obfuscated_at_all = True
            if out is None:
                DEBUG and self.__graph.print_root()
                for block in list(graph.blocks()):
                    start_offsets = list()
                    bad_instrs = set()
                    if self.__is_cex_style_switch(block, start_offsets, bad_instrs):
                        graph.validate_blocks()
                        out = graph.duplicate()
                        is_obfuscated = True
                        is_obfuscated_at_all = True
                        self.__deobfuscate_switch(block, start_offsets, block.get_last_instr(), out, bad_instrs)
                        out.validate_blocks()
                        break
                    new_graph = self.new_switch_deob(block)
                    if new_graph is not None:
                        new_graph.validate_blocks()
                        out = new_graph
                        is_obfuscated = True
                        is_obfuscated_at_all = True
                        out.validate_blocks()
                        break

            if is_obfuscated:
                attempts += 1
                instrs = out.emit_instructions_as_list()
                localsigtok = self.__disasm.get_local_var_sig_token()
                exc = out.get_raw_exception_clauses()
                recompiler = MethodRecompiler(instrs, exc, localsigtok)
                data = recompiler.compile_method()
                if isinstance(self.__method, net_row_objects.MethodSpec):
                    self.__method.get_method().set_method_data(data)
                else:
                    self.__method.set_method_data(data)
                self.__graph = out
                if isinstance(self.__method, net_row_objects.MethodSpec):
                    self.__disasm = self.__method.get_method().disassemble_method()
                else:
                    self.__disasm = self.__method.disassemble_method()
                graph = out
                if max_attempts > 0 and attempts >= max_attempts:
                    break
            elif not is_obfuscated_at_all:
                return None
            else:
                break
        return graph

    def __fold_constant_branches(self, graph):
        """ Fold every conditional branch in the graph whose outcome is a compile-time constant.

        Args:
            graph (net_graphing.FunctionGraph): The graph to fold branches in (mutated in place).

        Returns:
            int: The number of branches that were folded.
        """
        count = 0
        for block in list(graph.blocks()):
            if self.__fold_constant_branch(block):
                count += 1
        return count
    
    def __fold_constant_branch_num(self, block):
        """ Replace a brtrue/brfalse fed by a single constant with an unconditional Br.

        The taken target is always get_next()[0] and the fallthrough get_next()[1]
        (see FunctionGraph.__parse_block).  The surviving edge and a Br pointing at it are
        kept; repair_blocks normalizes offsets/short forms afterwards.

        Args:
            block (net_graphing.FunctionBlock): The block whose terminating branch to examine.

        Returns:
            bool: True if the branch was folded.
        """
        last_instr = block.get_last_instr()
        if last_instr is None or not last_instr.is_branch() or last_instr.is_absolute_jmp():
            return False
        last_op = last_instr.get_opcode()
        if last_op not in (Opcodes.Beq, Opcodes.Beq_S):
            return False
        block_instrs = block.get_instrs()
        if len(block_instrs) <= 2:
            return False

        target_instrs = list()
        needed = last_instr.get_pstack()
        for i in range(len(block_instrs) - 2, -1, -1):
            if needed == 0:
                break
            instr = block_instrs[i]
            needed = needed - instr.get_astack() + instr.get_pstack()
            if instr.get_opcode() != Opcodes.Nop:
                target_instrs.append(instr)
        target_instrs.reverse()

        if needed != 0 or len(target_instrs) != 2:
            return False
        first_instr = target_instrs[0]
        if first_instr.is_branch():
            return False
        if first_instr.get_opcode() in self.LDLOC and False:
            arg = first_instr.get_argument()
            set_instrs = self.__find_all_var_sets(arg)
            if len(set_instrs) == 0:
                ldc_instr = self.__disasm.emit_instruction(Opcodes.Ldc_I4_0)
                ldc_instr.setup_instr_size(1)
                first_instr = ldc_instr
        if first_instr.get_opcode() not in self.LDC_INSTRS and first_instr.get_opcode() != Opcodes.Ldnull:
            return False
        
        second_instr = target_instrs[1]
        if second_instr.is_branch():
            return False
        if second_instr.get_opcode() in self.LDLOC and False:
            arg = second_instr.get_argument()
            set_instrs = self.__find_all_var_sets(arg)
            if len(set_instrs) == 0:
                ldc_instr = self.__disasm.emit_instruction(Opcodes.Ldc_I4_0)
                ldc_instr.setup_instr_size(1)
                second_instr = ldc_instr
        if second_instr.get_opcode() not in self.LDC_INSTRS and second_instr.get_opcode() != Opcodes.Ldnull:
            return False
        
        should_jmp = first_instr.get_argument() == second_instr.get_argument()

        to_keep = block.get_next()[0 if should_jmp else 1]
        to_remove = block.get_next()[1 if should_jmp else 0]
        DEBUG and print('BEQ-FOLD: block %s cmp %s==%s -> jmp=%s keep=%s remove=%s' % (
            hex(block.get_start_offset()), first_instr.get_argument(), second_instr.get_argument(),
            should_jmp, hex(to_keep.get_start_offset()), hex(to_remove.get_start_offset())))
        if to_remove is to_keep:
            return False
        block.remove_next(to_remove)
        operand_index = block.get_instr_index(target_instrs[0])
        block.remove_instrs(operand_index, block.get_instr_index(target_instrs[1]) + 1)
        new_instr = self.__disasm.emit_instruction(Opcodes.Br)
        new_instr.setup_instr_size(5)
        new_instr.setup_instr_offset(last_instr.get_instr_offset(), last_instr.get_instr_index())
        new_instr.setup_arguments_from_int32(to_keep.get_start_offset() - last_instr.get_instr_offset() - 5)
        block.replace_instr(len(block.get_instrs()) - 1, new_instr)
        return True

    def __fold_constant_branch(self, block):
        """ Replace a brtrue/brfalse fed by a single constant with an unconditional Br.

        The taken target is always get_next()[0] and the fallthrough get_next()[1]
        (see FunctionGraph.__parse_block).  The surviving edge and a Br pointing at it are
        kept; repair_blocks normalizes offsets/short forms afterwards.

        Args:
            block (net_graphing.FunctionBlock): The block whose terminating branch to examine.

        Returns:
            bool: True if the branch was folded.
        """
        last_instr = block.get_last_instr()
        if last_instr is None or not last_instr.is_branch() or last_instr.is_absolute_jmp():
            return False
        last_op = last_instr.get_opcode()
        if last_op in (Opcodes.Beq, Opcodes.Beq_S):
            return self.__fold_constant_branch_num(block)
        if last_op not in (Opcodes.Brtrue, Opcodes.Brtrue_S, Opcodes.Brfalse, Opcodes.Brfalse_S):
            return False
        block_instrs = block.get_instrs()
        if len(block_instrs) <= 1:
            return False

        target_instrs = list()
        needed = last_instr.get_pstack()
        for i in range(len(block_instrs) - 2, -1, -1):
            if needed == 0:
                break
            instr = block_instrs[i]
            needed = needed - instr.get_astack() + instr.get_pstack()
            if instr.get_opcode() != Opcodes.Nop:
                target_instrs.append(instr)
        target_instrs.reverse()

        if needed != 0 or len(target_instrs) != 1:
            return False
        const_instr = target_instrs[0]
        if const_instr.is_branch():
            return False
        if not const_instr.get_name().startswith('ldc.') and const_instr.get_opcode() != Opcodes.Ldnull:
            return False

        const_val = const_instr.get_argument()
        is_zero = const_val == 0 or const_val is None
        if last_op in (Opcodes.Brfalse, Opcodes.Brfalse_S):
            taken = is_zero
        else:
            taken = not is_zero

        to_keep = block.get_next()[0 if taken else 1]
        to_remove = block.get_next()[1 if taken else 0]
        if to_remove is to_keep:
            return False
        block.remove_next(to_remove)
        operand_index = block.get_instr_index(const_instr)
        block.remove_instrs(operand_index, operand_index + 1)
        new_instr = self.__disasm.emit_instruction(Opcodes.Br)
        new_instr.setup_instr_size(5)
        new_instr.setup_instr_offset(last_instr.get_instr_offset(), last_instr.get_instr_index())
        new_instr.setup_arguments_from_int32(to_keep.get_start_offset() - last_instr.get_instr_offset() - 5)
        block.replace_instr(len(block.get_instrs()) - 1, new_instr)
        return True
    
    def __emit_small_instr_for_big(self, instr):
        if not instr.is_branch() and not instr.is_absolute_jmp():
            return None
        ins_op = instr.get_opcode()
        new_instr = None
        if ins_op == Opcodes.Br:
            new_instr = self.__disasm.emit_instruction(Opcodes.Br_S)
        elif ins_op == Opcodes.Brfalse:
            new_instr = self.__disasm.emit_instruction(Opcodes.Brfalse_S)
        elif ins_op == Opcodes.Brtrue:
            new_instr = self.__disasm.emit_instruction(Opcodes.Brtrue_S)
        elif ins_op == Opcodes.Beq:
            new_instr = self.__disasm.emit_instruction(Opcodes.Beq_S)
        elif ins_op == Opcodes.Bge:
            new_instr = self.__disasm.emit_instruction(Opcodes.Bge_S)
        elif ins_op == Opcodes.Bgt:
            new_instr = self.__disasm.emit_instruction(Opcodes.Bgt_S)
        elif ins_op == Opcodes.Ble:
            new_instr = self.__disasm.emit_instruction(Opcodes.Ble_S)
        elif ins_op == Opcodes.Blt:
            new_instr = self.__disasm.emit_instruction(Opcodes.Blt_S)
        elif ins_op == Opcodes.Bne_Un:
            new_instr = self.__disasm.emit_instruction(Opcodes.Bne_Un_S)
        elif ins_op == Opcodes.Bge_Un:
            new_instr = self.__disasm.emit_instruction(Opcodes.Bge_Un_S)
        elif ins_op == Opcodes.Bgt_Un:
            new_instr = self.__disasm.emit_instruction(Opcodes.Bgt_Un_S)
        elif ins_op == Opcodes.Ble_Un:
            new_instr = self.__disasm.emit_instruction(Opcodes.Ble_Un_S)
        elif ins_op == Opcodes.Blt_Un:
            new_instr = self.__disasm.emit_instruction(Opcodes.Blt_Un_S)
        elif ins_op == Opcodes.Leave:
            new_instr = self.__disasm.emit_instruction(Opcodes.Leave_S)
        
        if new_instr is None:
            return None
        new_instr.setup_instr_size(2)
        return new_instr
    
    def __emit_big_instr_for_small(self, instr):
        if not instr.is_branch() and not instr.is_absolute_jmp():
            return None
        ins_op = instr.get_opcode()
        new_instr = None
        if ins_op == Opcodes.Br_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Br)
        elif ins_op == Opcodes.Brfalse_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Brfalse)
        elif ins_op == Opcodes.Brtrue_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Brtrue)
        elif ins_op == Opcodes.Beq_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Beq)
        elif ins_op == Opcodes.Bge_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Bge)
        elif ins_op == Opcodes.Bgt_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Bgt)
        elif ins_op == Opcodes.Ble_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Ble)
        elif ins_op == Opcodes.Blt_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Blt)
        elif ins_op == Opcodes.Bne_Un_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Bne_Un)
        elif ins_op == Opcodes.Bge_Un_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Bge_Un)
        elif ins_op == Opcodes.Bgt_Un_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Bgt_Un)
        elif ins_op == Opcodes.Ble_Un_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Ble_Un)
        elif ins_op == Opcodes.Blt_Un_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Blt_Un)
        elif ins_op == Opcodes.Leave_S:
            new_instr = self.__disasm.emit_instruction(Opcodes.Leave)
        
        if new_instr is None:
            return None
        new_instr.setup_instr_size(5)
        return new_instr
    
    def __is_context_switch(self, old_block, new_block):
        #TODO: I believe the issue here is with context switching.
        old_exc = old_block.get_exception_handlers()
        new_exc = new_block.get_exception_handlers()
        if old_exc != new_exc:
           if (len(new_exc) - 1) == len(old_exc) and set(old_exc).issubset(set(new_exc)) and self.__is_block_try_start(new_block):
               return False
           return True
        return False
    
    def get_all_handler_blocks(self, initial_handler_block):
        results = set()
        for block in self.__graph.blocks():
            is_in_handler = True
            for exc1 in initial_handler_block.get_exception_handlers():
                if exc1 not in block.get_exception_handlers():
                    is_in_handler = False
                    break
            if is_in_handler:
                results.add(block)
        return results
    
    def __is_block_try_start(self, block): #TODO: remove this.
        for cl_flag, try_block, handler_blk, token in self.__graph.get_exception_blocks():
            if block == try_block:
                return True
        return False
    
    def get_all_full_try_handlers(self, try_block):
        result = set()
        for item in self.__graph.get_exception_blocks():
            if item[1] == try_block:
                result.add(item)
        return result

    def __drain_deferred_for_region(self, region_blocks, handled, deferred_blocks):
        #A handler region can contain blocks reachable only via `leave` (e.g. a leave-target shared
        #with a nested region), which get deferred instead of walked from the handler entry.  Unlike a
        #try-start, a handler entry has no deferred-pickup, so place them here - within the handler's
        #contiguous range - so they don't fall through to the deferred guard in repair_blocks.
        changed = True
        while changed:
            changed = False
            for dblock in list(deferred_blocks):
                if dblock in region_blocks and dblock not in handled:
                    self.__block_walker(dblock, handled, deferred_blocks, region_blocks)
                    changed = True

    def __block_walker(self, block, handled, deferred_blocks, must_finish_first=None):
        if block not in handled:
            current_offset = 0
            for blk in handled:
                current_offset += blk.get_current_size()
            new_must_finish_first = must_finish_first
            #The block hasnt been laid out yet.
            handled.append(block) #Goal is to get the layout of blocks in order, then recalculate offsets.
            last_instr = block.get_last_instr()
            if self.__is_block_try_start(block):
                new_must_finish_first = self.get_all_handler_blocks(block)
            if last_instr is None:
                return
            last_op = last_instr.get_opcode()
            new_last_instr = self.__emit_big_instr_for_small(last_instr)
            if new_last_instr is not None: #for now normalize all jumps to their big counterparts.
                last_index = len(block.get_instrs()) - 1
                new_last_instr.setup_arguments_from_int32(0)
                new_last_instr.setup_instr_offset(last_instr.get_instr_offset(), last_instr.get_instr_index())
                block.replace_instr(last_index, new_last_instr)

            last_instr = block.get_last_instr()
            last_op = last_instr.get_opcode()
            #the fallthrough case is always the last one in the nexts, so theres that.
            blk_next = block.get_next()
            if len(blk_next) > 0:
                target = blk_next[-1]
                if new_must_finish_first is None or target in new_must_finish_first:
                    self.__block_walker(target, handled, deferred_blocks, new_must_finish_first)
                elif target not in deferred_blocks and target not in handled:
                    deferred_blocks.append(target)
            
            if last_instr.is_branch() and not last_instr.is_absolute_jmp():
                if last_op == Opcodes.Switch:
                    for x in range(0, len(blk_next) - 1):
                        target = blk_next[x]
                        if new_must_finish_first is None or target in new_must_finish_first:
                            self.__block_walker(target, handled, deferred_blocks, new_must_finish_first)
                        elif target not in deferred_blocks and target not in handled:
                            deferred_blocks.append(target)
                else:
                    #For try context switches, dont output the leave instructions block yet.  That should be after all tries are finished.
                    target = blk_next[0]
                    if new_must_finish_first is None or target in new_must_finish_first:
                        self.__block_walker(target, handled, deferred_blocks, new_must_finish_first)
                    elif target not in deferred_blocks and target not in handled:
                        deferred_blocks.append(target)

            if self.__is_block_try_start(block):
                for dblock in deferred_blocks:
                    if dblock in new_must_finish_first:
                        self.__block_walker(dblock, handled, deferred_blocks, new_must_finish_first)
                for exc_handler in block.get_exception_handlers():
                    if exc_handler[1] == block:
                        full_handlers = self.get_all_full_try_handlers(block)
                        for full_handler in full_handlers:
                            catch_blocks = self.get_all_handler_blocks(full_handler[2])
                            self.__block_walker(full_handler[2], handled, deferred_blocks, catch_blocks)
                            self.__drain_deferred_for_region(catch_blocks, handled, deferred_blocks)
                            if isinstance(full_handler[3], net_graphing.FunctionBlock):
                                catch_blocks = self.get_all_handler_blocks(full_handler[3])
                                self.__block_walker(full_handler[3], handled, deferred_blocks, catch_blocks)
                                self.__drain_deferred_for_region(catch_blocks, handled, deferred_blocks)
    
    def __start_block_walker(self, start_block, end_block, not_in, handled):
        """
        Is it possible to go from start_block to switch_block without hitting not_in
        Because we are individually deobfuscating all loops, we should be able to reliably start from entry.
        """
        debug = False
        results = set()
        if start_block in handled:
            if debug:
                print(start_block, 'in handled')
            return results
        if debug:
            print('Running __start_block_walker start_block={}, end_block={}, not_in={}'.format(start_block, end_block, not_in))
        handled.append(start_block)
        if start_block == end_block:
            if debug:
                print('returning {}'.format([start_block]))
            return {end_block}
        if start_block in not_in:
            if debug:
                print('returning results', results)
            return results


        for nxt in start_block.get_next():
            res = self.__start_block_walker(nxt, end_block, not_in, handled)
            results |= res
        if debug:
            print('returning results', results)
        return results

    def __math_block_walker(self, block, start_block, needed, handled=set()):
        if block in handled:
            return set()
        instrs = block.get_instrs()
        handled.add(block)
        for x in range(len(instrs) -1, -1, -1):
            instr = instrs[x]
            added = instr.get_astack()
            pulled = instr.get_pstack()
            needed = needed - added + pulled
        
        if needed <= 0:
            return {(start_block, block)}
        result = set()
        for prev in block.get_prev():
            result |= self.__math_block_walker(prev, start_block, needed, handled)
        return result

    def __find_math_blocks(self, start_blocks):
        result = set()
        for start_block in start_blocks:
            instrs = start_block.get_instrs()
            needed = 0
            for x in range(len(instrs)-1, -1, -1):
                instr = instrs[x]
                added = instr.get_astack()
                pulled = instr.get_pstack()
                needed = needed - added + pulled
            
            if needed <= 0:
                result.add((start_block, start_block))
            else:
                for prev in start_block.get_prev():
                    result |= self.__math_block_walker(prev, start_block, needed)
        return result

    def __determine_start_block(self, switch_block):
        debug = False
        results = set()
        needed = 0
        instrs = switch_block.get_instrs()
        for x in range(len(instrs) - 1, -1, -1):
            instr = instrs[x]
            ins_op = instr.get_opcode()
            added = instr.get_astack()
            pulled = instr.get_pstack()
            needed = needed - added + pulled
            if debug:
                print('instr {} needed {}'.format(instr, needed))
            if ins_op in self.LDLOC:
                break
            if needed == 0:
                if debug:
                    print('start block is the switch block.', instr)
                results.add((switch_block, switch_block))
                return results
        #at this point, we need to search a bit for the start block.  We need to find the block that the switch will execute from FIRST.
        #If the order is messed up, deobfuscation will be incorrect.
        if debug:
            print('running walker')
        entry_blocks = set([self.__graph.get_block_by_start_offset(0)])
        for eh_flag, try_block, catch_block, token in self.__graph.get_exception_blocks():
            entry_blocks.add(catch_block)
            if isinstance(token, net_graphing.FunctionBlock):
                entry_blocks.add(token)
        
            
        for prev in switch_block.get_prev():
            #check if the previous block has a way to get to the switch statement that doesnt start from the switch statement.\
            not_in = [b for b in switch_block.get_prev() if b is not prev]
            for entry_block in entry_blocks:
                handled = list()
                res = self.__start_block_walker(entry_block, prev, not_in, handled)
                results |= res
        if debug:
            print('results of determine start block', results)
        return self.__find_math_blocks(results)

    def __add_to_bad_instrs(self, block, start_offset, switch_block, bad_instrs, handled=set()):
        if block in handled:
            return
        handled.add(block)
        is_first = block.has_offset(start_offset)
        past_start = not is_first
        for instr in block.get_instrs():
            if instr.is_absolute_jmp() or instr.is_branch():
                continue
            if past_start:
                bad_instrs.add(instr.get_instr_offset())
            else:
                if start_offset == instr.get_instr_offset():
                    past_start = True
                    bad_instrs.add(start_offset)
        
        if block == switch_block:
            return
        
        for nxt in block.get_next():
            self.__add_to_bad_instrs(nxt, start_offset, switch_block, bad_instrs, handled)

    def __switch_block_walker(self, block, new_switch_block, switch_instr, offsets_grouped, new_graph, already_handled, initial_emu, base_local_var, stloc_num, nexts_added):
        debug = False
        if block.get_start_offset() in already_handled:
            base_vars = already_handled[block.get_start_offset()]
            if base_local_var.as_python_obj() in base_vars:
                return
        else:
            already_handled[block.get_start_offset()] = list()
        already_handled[block.get_start_offset()].append(base_local_var.as_python_obj())
        if debug:
            print('walking switch statement case: Block={}, base_local_var={}'.format(block, base_local_var))
        if block.get_start_offset() in offsets_grouped:
            offsets = offsets_grouped[block.get_start_offset()]
            for offset in offsets:
                if debug:
                    print('Handling offset {}'.format(hex(offset)))
                #absolute jmp, it can only go one place.
                start_offset = offset
                end_offset = switch_instr.get_instr_offset()
                emu = initial_emu.spawn_new_emulator(self.__method, start_offset=start_offset, end_offset=end_offset, init_open_generics_as_object=True)
                emu.set_local_obj(stloc_num, base_local_var)
                emu.setup_method_params([])
                worked = False
                try:
                    emu.run_function()
                except net_exceptions.EmulatorEndExecutionException:
                    worked = True
                if not worked:
                    raise Exception()
                new_target = emu.get_stack().pop_obj()
                if not isinstance(new_target, net_emu_types.DotNetNumber):
                    raise Exception()
                new_local_var = emu.get_local_obj(stloc_num)
                switch_targets = switch_instr.get_argument()
                new_target = new_target.as_python_obj()
                if new_target < 0 or new_target >= len(switch_targets):
                    new_offset = len(switch_instr) + switch_instr.get_instr_offset() 
                else:
                    new_offset = switch_targets[new_target]
                new_start_block = new_graph.get_block_by_offset(start_offset)
                old_start_block = self.__graph.get_block_by_offset(start_offset)
                new_next_block = new_graph.get_block_by_offset(new_offset)
                if debug:
                    print('Got result {} which maps to block {} which should be next'.format(new_target, new_next_block))
                if len(old_start_block.get_next()) != 1:
                    raise Exception()
                old_next = old_start_block.get_next()[0]
                new_next = new_graph.get_block_by_offset(old_next.get_start_offset())
                end_block = new_graph.get_block_by_start_offset(block.get_start_offset())

                if debug:
                    print('attempting to remove {} as prev from {}: (switch block prevs {})'.format(end_block, new_switch_block, new_switch_block.get_prev()))
                nexts_added.append((end_block, new_start_block, new_next, new_next_block))
                self.__switch_block_walker(self.__graph.get_block_by_offset(new_offset), new_switch_block, switch_instr, offsets_grouped, new_graph, already_handled, initial_emu, new_local_var, stloc_num, nexts_added)
            return
        for nxt in block.get_next():
            self.__switch_block_walker(nxt, new_switch_block, switch_instr, offsets_grouped, new_graph, already_handled, initial_emu, base_local_var, stloc_num, nexts_added)

    def __determine_loop_blocks(self, switch_block):
        forward = set()
        blocks = [switch_block]
        while blocks:
            blk = blocks.pop()
            if blk in forward:
                continue
            forward.add(blk)
            for nxt in blk.get_next():
                blocks.append(nxt)

        backwards = set()
        blocks = [switch_block]
        while blocks:
            blk = blocks.pop()
            if blk in backwards:
                continue
            backwards.add(blk)
            for prv in blk.get_prev():
                blocks.append(prv)
        return forward & backwards

    def __collect_preswitch_chain(self, switch_block):
        blocks = set()
        work = list(switch_block.get_prev())

        while work:
            blk = work.pop()
            if blk in blocks:
                continue
            if len(blk.get_next()) == 1:
                blocks.add(blk)
                work.extend(blk.get_prev())
        return blocks

    def __target_walker(self, block, needed, already_checked, stloc_instr, start_offsets, child_addr, bad_instr_offsets, counter=0):
        """
        This method is definitely going to need some testing and work but I mean its okay for now.
        """
        instrs = block.get_instrs()
        debug = False
        if block.get_start_offset() in already_checked:
            if debug:
                print(0, block, needed)
            return False
        already_checked.append(block.get_start_offset())
        if debug:
            print('Checking block {} {} {}'.format(hex(block.get_start_offset()), needed, stloc_instr.get_argument()))
        need_local = False
        for x in range(len(instrs) - 1, -1, -1):
            instr = instrs[x]
            ins_op = instr.get_opcode()
            pulled = instr.get_pstack()
            added = instr.get_astack()
            if instr.is_absolute_jmp():
                continue
            if debug:
                print('Checking instr {} {} {} {} {}'.format(hex(instr.get_instr_offset()), instr.get_name(), needed, added, pulled))
            if ins_op not in (self.MATH_OPS + self.ALLOWED_STACK_OPS + [Opcodes.Switch] + self.STLOC + self.LDLOC):
                if pulled > 0 or added > 0:
                    if debug:
                        print(1, hex(instr.get_instr_offset()))
                    return False
            if ins_op in self.LDLOC:
                if instr.get_argument() == stloc_instr.get_argument():
                    if needed <= 0:
                        raise Exception()
                    needed -= 1

                    if needed == 0:
                        #Gate this off if theres a stloc above.
                        skip = False
                        if x > 0:
                            if instrs[x-1].get_opcode() in self.STLOC:
                                if instrs[x-1].get_argument() == stloc_instr.get_argument():
                                    bad_instr_offsets.add(instr.get_instr_offset())
                                    debug and print('setting needs local 1', hex(instr.get_instr_offset()))
                                    need_local = True
                                    continue
                        elif x == 0:
                            skip = True
                            for prev_blk in block.get_prev():
                                for y in range(len(prev_blk.get_instrs()) - 1, -1, -1):
                                    instr2 = prev_blk.get_instrs()[y]
                                    if instr2.is_absolute_jmp():
                                        continue
                                    if instr2.get_opcode() not in self.STLOC:
                                        skip = False
                                        break
                                    if instr2.get_argument() != stloc_instr.get_argument():
                                        skip = False
                                        break
                                    break
                                        
                                if not skip:
                                    break

                            if skip:
                                need_local = True
                                bad_instr_offsets.add(instr.get_instr_offset())
                                continue

                        if not skip:
                            bad_instr_offsets.add(instr.get_instr_offset())
                            start_offsets.append((child_addr, instr.get_instr_offset()))
                            if debug:
                                print(2, hex(instr.get_instr_offset()))
                            return True
                    needed += 1
            needed = needed - added + pulled
            if debug:
                print('needed is now 1 {} {} {}'.format(needed, added, pulled))
            if needed < 0:
                needed = 0
            if debug:
                print('needed is now 2 {}'.format(needed))
            if needed == 0:
                bad_instr_offsets.add(instr.get_instr_offset())
                start_offsets.append((child_addr, instr.get_instr_offset()))
                if debug:
                    print(3, hex(instr.get_instr_offset()), hex(child_addr))
                return True
            if ins_op in self.STLOC:
                if instr.get_argument() == stloc_instr.get_argument():
                    bad_instr_offsets.add(instr.get_instr_offset())
                    continue
                elif instr.get_argument() != stloc_instr.get_argument():
                    if needed == 0:
                        bad_instr_offsets.add(instr.get_instr_offset())
                        start_offsets.append((child_addr, instr.get_instr_offset()))
                        if debug:
                            print(4, hex(instr.get_instr_offset()))
                        return True
                    else:
                        if debug:
                            print(5, hex(instr.get_instr_offset()))
                        return False
            if ins_op not in (self.MATH_OPS + self.ALLOWED_STACK_OPS + [Opcodes.Switch]):
                if debug:
                    print(6, hex(instr.get_instr_offset()))
                return False
            bad_instr_offsets.add(instr.get_instr_offset())
            
        if needed != 0 or need_local:
            if debug:
                print('needed ', needed, 'needs local ', need_local)
            for prev in block.get_prev():
                if prev == block:
                    continue
                if debug:
                    print('Checking prev {} {} {} {}'.format(block, prev, counter, block.get_prev()))
                if counter == 0:
                    result = not self.__target_walker(prev, needed, already_checked, stloc_instr, start_offsets, prev.get_start_offset(), bad_instr_offsets, counter=counter+1)
                else:
                    result = not self.__target_walker(prev, needed, already_checked, stloc_instr, start_offsets, child_addr, bad_instr_offsets, counter=counter+1)
                if result:
                    if debug:
                        print(7, prev)
                    return False
        if debug:
            print(8, hex(block.get_start_offset()), hex(child_addr))
        return True

    def __is_cex_style_switch(self, block, start_offsets, bad_instr_offsets):
        #check if all paths have a relatively constant value.
        instrs = block.get_instrs()
        debug = False
        if debug:
            print('Checking {} {}'.format(block, block.get_instrs()))
        if block.get_last_instr().get_opcode() != Opcodes.Switch:
            if debug:
                print('not switch')
            return False
        if len(instrs) < 2:
            if debug:
                print('instr len')
            return False
        if instrs[-2].get_opcode() not in self.MATH_OPS:
            if debug:
                print('not math ops')
            return False
        
        if len(block.get_prev()) <= 1:
            if debug:
                print('Not enough previous blocks for a loop.')
            return False
        #make sure theres at least one branch thats a fall through or a 1-1 ration
        already_checked = list()
        stloc_instr = None
        for x in range(len(instrs) - 1, -1, -1):
            ins_op = instrs[x].get_opcode()
            bad_instr_offsets.add(instrs[x].get_instr_offset())
            if ins_op in self.STLOC:
                stloc_instr = instrs[x]
                break
            #if ins_op not in (self.MATH_OPS + self.ALLOWED_STACK_OPS + self.BRANCHES):
            #    break
        if stloc_instr is None:
            for prv in block.get_prev():
                if (prv.get_start_offset() + prv.get_original_length()) == block.get_start_offset():
                    instrs = prv.get_instrs()
                    for x in range(len(instrs) - 1, -1, -1):
                        ins_op = instrs[x].get_opcode()
                        bad_instr_offsets.add(instrs[x].get_instr_offset())
                        if ins_op in self.STLOC:
                            stloc_instr = instrs[x]
                            break
                        #if ins_op not in (self.MATH_OPS + self.ALLOWED_STACK_OPS + self.BRANCHES):
                        #    break
            if stloc_instr is None:
                if debug:
                    print('no stloc instr')
                return False
        start_offsets.clear()
        in_loop_blocks = self.__determine_loop_blocks(block) | self.__collect_preswitch_chain(block)
        #calculate needed for switch:
        needed = 0
        for x in range(len(block.get_instrs()) - 1, -1, -1):
            instr = block.get_instrs()[x]
            if debug:
                print('getting needed loop: checking instr {}'.format(instr))
            added = instr.get_astack()
            pulled = instr.get_pstack()
            needed = needed - added + pulled
            if instr.get_opcode() not in self.ALLOWED_SWITCH_LOOP_INSTRS:
                if debug:
                    print('Returning false because instruction isnt allowed.')
                return False

        if debug:
            print('determined loop blocks', in_loop_blocks)
            
        for prev in block.get_prev():
            if prev not in in_loop_blocks:
                continue
            if debug:
                print('checking prev {} {}'.format(prev, needed))
            if not self.__target_walker(prev, needed, already_checked, stloc_instr, start_offsets, prev.get_start_offset(), bad_instr_offsets, counter=1):
                if debug:
                    print('prev is false')
                return False
        if debug:
            print('Returning true due to fallthrough.')
        return True
    
    def __has_path_to_entry(self, b):
        blocks = [b] + b.get_prev()
        handled = set()
        while blocks:
            block = blocks.pop()
            if block in handled:
                continue

            handled.add(block)
            if block.is_block_start():
                return True
            for prv in block.get_prev():
                if prv not in handled:
                    blocks.append(prv)
        return False

    
    def __find_switch_case_mappings_internal(self, block, switch_block, offsets_grouped, already_done):
        if block.get_start_offset() in offsets_grouped:
            return [block]
        if block in already_done:
            return list()
        already_done.add(block)
        res = list()
        for nxt in block.get_next():
            res.extend(self.__find_switch_case_mappings_internal(nxt, switch_block, offsets_grouped, already_done))
        if len(block.get_next()) == 0:
            res.append(block)
        return res

    def __find_switch_case_mappings(self, switch_block, offsets_grouped):
        result = dict()
        for nxt in switch_block.get_next():
            end_blocks = self.__find_switch_case_mappings_internal(nxt, switch_block, offsets_grouped, set())
            for end_block in end_blocks:
                if end_block not in result:
                    result[end_block] = list()
                result[end_block].append(nxt)
        for prv in switch_block.get_prev():
            end_blocks = self.__find_switch_case_mappings_internal(prv, switch_block, offsets_grouped, set())
            for end_block in end_blocks:
                if end_block not in result:
                    result[end_block] = list()
                result[end_block].append(nxt)
        return result

    def __deobfuscate_switch(self, block, offsets, switch_instr, new_graph, bad_instrs):
        #first group the offsets together.
        offsets_grouped = dict()
        for block_offset, offset in offsets:
            if block_offset not in offsets_grouped:
                offsets_grouped[block_offset] = list()
            offsets_grouped[block_offset].append(offset)

        debug = False
        if debug:
            print('deobfuscating switch {}'.format(block))
        if debug:
            for block_offset, offsets in offsets_grouped.items():
                for offset in offsets:
                    print('block offset {} -> start {}'.format(hex(block_offset), hex(offset)))
        start_blocks = self.__determine_start_block(block)
        if len(start_blocks) == 0:
            raise net_exceptions.ControlFlowDeobfuscationMisidentify('Could not determine start blocks.  Its possible a legitimate switch was misidentified.  Contact devs if wrong.')
        if debug:
            print('Start blocks {}'.format(start_blocks))
        stloc_instr = None
        for instr in reversed(block.get_instrs()):
            if instr.get_opcode() in self.STLOC:
                stloc_instr = instr
                break

        if stloc_instr is None:
            for prv in block.get_prev():
                if (prv.get_start_offset() + prv.get_original_length()) == block.get_start_offset():
                    instrs = prv.get_instrs()
                    for x in range(len(instrs) - 1, -1, -1):
                        ins_op = instrs[x].get_opcode()
                        bad_instrs.add(instrs[x].get_instr_offset())
                        if ins_op in self.STLOC:
                            bad_instrs.add(instrs[x].get_instr_offset())
                            stloc_instr = instrs[x]
                            break
                if stloc_instr is not None:
                    break
            if stloc_instr is None:
                raise Exception()

        if debug:
            print('Our switch state stloc instruction is {}'.format(stloc_instr))
        nexts_added = list()

        for start_block, math_block in start_blocks:
            #we already have the first start offset somewhere in offsets grouped
            first_start_offset = -1
            end_block_offset = -1
            for end, start_offsets in offsets_grouped.items():
                for start_offset in start_offsets:
                    if math_block.has_offset(start_offset):
                        end_block_offset = end
                        first_start_offset = start_offset
                        break
            if debug:
                print('Determined the start offset for the first case to be {}'.format(hex(first_start_offset)))
            #get the initial feed value.
            if first_start_offset == -1:
                #This case happens if the switch doesnt have a reference back to the start math block.
                #See if we can pull it from here.
                for x in range(len(math_block.get_instrs()) - 1, - 1, - 1):
                    instr = math_block.get_instrs()[x]
                    if instr.get_opcode() not in self.MATH_OPS:
                        first_start_offset = instr.get_instr_offset() + len(instr)
                        break
                #at this point its kinda a guess - some refinement could probably be used here.

            if first_start_offset == -1:
                raise Exception()
            self.__add_to_bad_instrs(math_block, first_start_offset, block, bad_instrs)
            emu = net_emulator.DotNetEmulator(self.__method, start_offset=first_start_offset, end_offset=switch_instr.get_instr_offset(), dont_execute_cctor=True, init_open_generics_as_object=True)
            emu.setup_method_params([])
            worked = False
            try:
                emu.run_function()
            except net_exceptions.EmulatorEndExecutionException as e:
                worked = True
            except:
                #If theres any other error, there are two possibilities:
                # First is a misidentified switch statement, second is an internal error.
                #A misidentification is pretty likely to be caught here so I am going to raise the misidentify exception
                #But if theres issues on switches being identified as not obfuscated that are obfuscated, this is a pretty good place to check.
                #TODO: fix up the identification logic to better catch switch statements that are legitimate.
                # the above is a more complete fix, will work on it at some point.
                pass
            if not worked:
                raise net_exceptions.ControlFlowDeobfuscationMisidentify('Could not finish emulating the entry case.  Could be a misidentification, could be an internal error with determining start offsets.')
            result = emu.get_stack().pop_obj()
            base_local = emu.get_local_obj(stloc_instr.get_argument())
            if not isinstance(result, net_emu_types.DotNetNumber) or not isinstance(base_local, net_emu_types.DotNetNumber):
                raise Exception()
            result = result.as_python_obj()
            orig_base_local = base_local
            base_local = base_local.as_python_obj()
            switch_targets = switch_instr.get_argument()
            if result < 0 or result >= len(switch_targets):
                starting_offset = switch_instr.get_instr_offset() + len(switch_instr)
            else:
                starting_offset = switch_targets[result]

            #unlink the switch block
            new_switch_block = new_graph.get_block_by_offset(block.get_start_offset())
            new_start_block = new_graph.get_block_by_offset(first_start_offset)
            new_initial_block = new_graph.get_block_by_offset(starting_offset)
            initial_block = self.__graph.get_block_by_offset(starting_offset)
            if debug:
                print('For the first case, the result is {} which maps to block {}'.format(result, new_initial_block))
            #new_switch_block.clear_next()
            if debug:
                print('cleared out all switch nexts and prevs')
            potential_start_block = new_graph.get_block_by_offset(start_block.get_start_offset())
            if debug:
                print('adding block {} to {} nexts as the initial entry of the switch.'.format(new_initial_block, potential_start_block))
                print('new start block is {}'.format(new_start_block))
            if new_switch_block == new_start_block:
                nexts_added.append((potential_start_block, new_start_block, new_switch_block, new_initial_block))
            else:
                if len(new_start_block.get_next()) != 1:
                    raise Exception()
                nexts_added.append((potential_start_block, new_start_block, new_start_block.get_next()[0], new_initial_block))
            already_handled = {new_start_block.get_start_offset(): [base_local]}
            stloc_num = stloc_instr.get_argument()
            self.__switch_block_walker(initial_block, new_switch_block, switch_instr, offsets_grouped, new_graph, already_handled, emu, orig_base_local, stloc_num, nexts_added)
        start_mappings = self.__find_switch_case_mappings(new_switch_block, offsets_grouped)
        end_block_handled = set()
        for end_block, start_blocks in list(start_mappings.items()):
            start_mappings[end_block] = [b for b in start_blocks if new_switch_block in b.get_prev()]
        nexts_grouped = dict()
        for new_end_block, block_to_change, old_next, new_next_block in nexts_added:
            if new_end_block not in nexts_grouped:
                nexts_grouped[new_end_block] = list()
            nexts_grouped[new_end_block].append((block_to_change, new_next_block))

        if debug:
            print('Bad instruction dump:')
            for bad_instr in bad_instrs:
                print(hex(bad_instr))
        if debug:
            print('Start mappings')
            for end_blk, start_blocks in start_mappings.items():
                print('end blk {} maps to start blocks {}'.format(end_blk, start_blocks))

        for new_end_block, block_to_change, old_next, new_next_block in nexts_added:
            if new_end_block not in start_mappings:
                #TODO: Go through all these ControlFlowDeobfuscationMisidentify exceptions and try to tighten __is_target_switch() to prevent them from hitting.
                raise net_exceptions.ControlFlowDeobfuscationMisidentify('new end block isnt in start mappings.  This could either be an internal error or a misidentify.')
            start_blocks = start_mappings[new_end_block]
            if debug:
                print('new_end_block={}, block_to_change={}, old_next={}, new_next_block={}, start_blocks={}'.format(new_end_block, block_to_change, old_next, new_next_block, start_blocks))
            if len(start_blocks) > 0:
                for block_after_switch in start_blocks:
                    if new_switch_block.has_next(block_after_switch):
                        if block_to_change == new_switch_block and block_after_switch == old_next:
                            continue
                        new_switch_block.remove_next(block_after_switch)
            if block_to_change.has_next(old_next):
                if debug:
                    print('For block {}, replacing next {} with new next {}'.format(block_to_change, old_next, new_next_block))
                block_to_change.replace_next(old_next, new_next_block)
            
            end_block_handled.add(new_end_block)
            if new_switch_block.has_prev(new_end_block):
                new_switch_block.remove_prev(new_end_block)
        if debug:
            print('Start mappings dump')
            print(start_mappings)
            print('before new switch block', new_switch_block, new_switch_block.get_prev(), new_switch_block.get_next())
        #clean off the old switch block.
        #now remove any instructions that we know are junk.
        for blk in new_graph.blocks():
            amt_deleted = 0
            instrs = list(blk.get_instrs())
            for x in range(len(instrs)):
                instr = instrs[x]
                if instr.get_instr_offset() in bad_instrs and ((not instr.is_branch() and not instr.is_absolute_jmp()) or instr.get_opcode() == Opcodes.Switch):
                    blk.remove_instrs(x - amt_deleted, x - amt_deleted + 1)
                    amt_deleted += 1
        switch_nexts = list()
        for new_end_block, block_to_change, old_next, new_next in nexts_added:
            if block_to_change == new_switch_block:
                switch_nexts.append(new_next)

        for nxt in list(new_switch_block.get_next()):
            if nxt in switch_nexts:
                switch_nexts.remove(nxt)
            else:
                new_switch_block.remove_next(nxt)
        
        if debug:
            print('after new switch block', new_switch_block, new_switch_block.get_prev(), new_switch_block.get_next())

        for blk in list(new_graph.blocks()):
            if len(blk.get_next()) == 0 and len(blk.get_prev()) == 0 and not blk.is_block_start():
                new_graph.unregister_block(blk.get_start_offset())

            elif len(blk.get_prev()) == 0 and not blk.is_block_start():
                new_graph.unregister_block(blk.get_start_offset())
            elif not blk.is_block_start() and len(blk.get_instrs()) == 0 and len(blk.get_prev()) == len(blk.get_next()) == 1:
                if blk.get_prev()[0] == blk.get_next()[0] == blk:
                    new_graph.unregister_block(blk.get_start_offset())
        new_graph.repopulate_prevs()
        #here check if theres any blocks that have 2 nexts but only link back to 1 block and have no instrs.
        for block in list(new_graph.blocks()):
            if not self.__has_path_to_entry(block):
                block.clear_next()
                block.clear_prev()
                new_graph.unregister_block(block.get_start_offset())

        if debug:
            new_graph.dump_block_relations()
        new_graph.validate_blocks()
        #For the switch block, prune any previous that are illegal.
        #new_graph.validate_blocks()
        #First remove any useless blocks.
        #new_graph.repopulate_prevs()
        blocks = list(new_graph.blocks())
        removed_blocks = list()
        #if a block only has one next block and no jump, merge them.
        for blk in blocks:
            if blk.get_start_offset() in removed_blocks:
                continue
            last_instr = blk.get_last_instr()
            if last_instr is not None:
                last_op = last_instr.get_opcode()
                instrs = blk.get_instrs()
                if last_op in (Opcodes.Ret, Opcodes.Throw, Opcodes.Endfinally, Opcodes.Rethrow):
                    continue
                if last_instr.is_branch():
                    continue

                if last_instr.is_absolute_jmp():
                    continue
            if len(blk.get_prev()) == len(blk.get_next()) == len(blk.get_instrs()) == 0:
                if new_graph.has_block(blk.get_start_offset()):
                    removed_blocks.append(blk.get_start_offset())
                    new_graph.unregister_block(blk.get_start_offset())
                continue

            if debug:
                print('doing br checks for block {}'.format(blk))

            nxts = blk.get_next()
            if len(nxts) != 1:
                print(blk, blk.get_prev(), nxts, blk.get_instrs())
                raise Exception()
            nxt = nxts[0]
            if nxt.is_block_try() or nxt.is_block_catch() or nxt.is_block_finally() or nxt.is_block_filter():
                shouldnt_remove = False
                for cl_flags, cl_blk in nxt.get_exception_handlers():
                    if cl_blk == nxt:
                        shouldnt_remove = True
                        break 
                if shouldnt_remove:
                    continue
            if len(nxt.get_prev()) == 1:
                if debug:
                    print(1)
                blk.remove_next(nxt)
                blk.merge_block(nxt)
                blk_nxts = list(nxt.get_next())
                nxt.clear_next()
                for n in blk_nxts:
                    blk.add_next(n)
                removed_blocks.append(nxt.get_start_offset())
                new_graph.unregister_block(nxt.get_start_offset())
            else:
                if debug:
                    print(2)
                if (blk.get_start_offset() + blk.get_original_length()) == nxt.get_start_offset():
                    if debug:
                        print(3)
                    if last_instr is None:
                        for prev_blk in list(blk.get_prev()):
                            prev_blk.replace_next(blk, nxt)
                        blk.remove_next(nxt)
                        new_graph.unregister_block(blk.get_start_offset())
                        if debug:
                            print(4)
                        removed_blocks.append(blk.get_start_offset())
                    continue
                if not blk.is_block_try() and not blk.is_block_catch() and not blk.is_block_finally() and not blk.is_block_filter():
                    new_instr = self.__disasm.emit_instruction(Opcodes.Br)
                else:
                    new_instr = self.__disasm.emit_instruction(Opcodes.Leave)
                target = nxt.get_start_offset() - (blk.get_start_offset() + blk.get_current_size()) - 5
                new_instr.setup_instr_size(5)
                ins_index = blk.get_start_index()
                if last_instr is not None:
                    ins_index = last_instr.get_instr_index() + 1
                new_instr.setup_instr_offset(blk.get_start_offset() + blk.get_current_size(), ins_index)
                new_instr.setup_arguments_from_int32(target)
                blk.add_instr(new_instr)
        new_graph.validate_blocks()

        #lastly update all the offsets for branches
        for blk in new_graph.blocks():
            last_instr = blk.get_last_instr()
            if last_instr is None:
                continue
            last_op = last_instr.get_opcode()
            if last_instr.is_absolute_jmp():
                if len(blk.get_next()) != 1:
                    raise Exception()
                nxt = blk.get_next()[0]
                argument = nxt.get_start_offset() - last_instr.get_instr_offset() - len(last_instr)
                last_instr.setup_arguments_from_int32(argument)
            else:
                if last_instr.is_branch():
                    if last_instr.get_opcode() == Opcodes.Switch:
                        args = list()
                        nxts = blk.get_next()
                        for x in range(len(nxts) - 1): #last case is fallthrough
                            target = nxts[x]
                            argument = target.get_start_offset() - last_instr.get_instr_offset() - len(last_instr)
                            args.append(argument)
                        last_instr.setup_arguments_from_argslist(args)
                    else:
                        if len(blk.get_next()) != 2:
                            raise Exception()
                        nxt = blk.get_next()[1]
                        argument = nxt.get_start_offset() - last_instr.get_instr_offset() - len(last_instr)
                        last_instr.setup_arguments_from_int32(argument)
        new_graph.validate_blocks()
        new_graph.sort_blocks()

        new_analyzer = GraphAnalyzer(self.__method, new_graph)
        new_analyzer.repair_blocks()
        new_graph.update_offsets()
        new_graph.sort_blocks()
        new_graph.validate_blocks()


    def repair_blocks(self):
        #Goal of this method is to fixup block relationships and make it look pretty.
        #TODO: When stiching together blocks try blocks need to be together, filter clause needs to follow the rules etc.
        #TODO: need to test this with filter clause I think block ordering is off.
        self.__graph.validate_blocks()
        was_unregistered = list()
        self.__graph.repopulate_prevs()
        for block in list(self.__graph.blocks()):
            if block.get_start_offset() in was_unregistered:
                continue
            if block.is_block_start():
                continue
            block_prev = list(block.get_prev())
            block_next = list(block.get_next())
            if len(block_prev) == 1:
                prev = block_prev[0]
                if prev is block:
                    continue
                prev_last = prev.get_last_instr()
                if prev_last is None or prev_last.get_opcode() in (Opcodes.Br, Opcodes.Br_S):
                    #Remove the jmp on the prev
                    if prev_last is not None:
                        prev_index = len(prev.get_instrs()) - 1
                        prev.remove_instrs(prev_index, prev_index + 1)
                    prev.remove_next(block)
                    prev.merge_block(block)
                    assert len(prev.get_next()) == 0
                    prev.clear_next_raw()
                    for n in block_next:
                        prev.add_next(n)
                        if n.has_prev(block):
                            n.remove_prev(block)
                    was_unregistered.append(block.get_start_offset())
                    self.__graph.unregister_block(block.get_start_offset())
        self.__graph.validate_blocks()

        blocks_order = list()
        deferred_blocks = list()
        self.__block_walker(self.__graph.get_block_by_start_offset(0), blocks_order, deferred_blocks)
        while deferred_blocks:
            block = deferred_blocks.pop()
            if len(block.get_exception_handlers()) != 0 and block not in blocks_order and not block.is_block_start():
                raise Exception(str(block))
            self.__block_walker(block, blocks_order, deferred_blocks)

        for _dead in list(self.__graph.blocks()):
            if _dead not in blocks_order and not _dead.is_block_start():
                for _nxt in list(_dead.get_next()):
                    _dead.remove_next(_nxt)
                for _prv in list(_dead.get_prev()):
                    _dead.remove_prev(_prv)
                self.__graph.unregister_block(_dead.get_start_offset())
        #check over the blocks, make sure theres a jmp if its needed.
        total_compiled = len(blocks_order)
        #Do an initial offset update to ensure the next loop works.
        current_offset = 0
        current_index = 0
        remove_from_ordered = list()
        #lay out the offsets
        for x in range(total_compiled):
            block = blocks_order[x]
            if len(block.get_instrs()) == 0:
                remove_from_ordered.append(block)
                self.__graph.unregister_block(block.get_start_offset())
                continue
            if len(block.get_prev()) == 0 and current_offset != 0 and (block.get_start_offset() != 0 and not block.is_block_start()):
                #dead block.
                for nxt in list(block.get_next()):
                    block.remove_next(nxt)
                    if nxt.has_prev(block):
                        nxt.remove_prev(block)
                remove_from_ordered.append(block)
                self.__graph.unregister_block(block.get_start_offset())
                continue
            block.update_start_offset(current_offset, current_index)
            block.update_size(block.get_current_size())
            current_offset += block.get_original_length()
            current_index += len(block.get_instrs())
        self.__graph.update_offsets()
        for block in remove_from_ordered:
            if block in blocks_order:
                blocks_order.remove(block)
        remove_from_ordered.clear()
        self.__graph.sort_blocks()
        new_blocks_offset = 0
        new_blocks_index = 0
        for _blk in self.__graph.blocks():
            _end = _blk.get_start_offset() + _blk.get_current_size()
            if _end >= new_blocks_offset:
                new_blocks_offset = _end
                new_blocks_index = _blk.get_start_index() + len(_blk.get_instrs())
        total_compiled = len(blocks_order)
        new_blocks = list()
        for x in range(total_compiled):
            block = blocks_order[x]
            last_instr = block.get_last_instr()
            new_blocks.append(block)
            if last_instr is None:
                continue
            if not last_instr.is_absolute_jmp() and last_instr.is_branch():
                if x == (total_compiled - 1) or blocks_order[x+1] != block.get_next()[-1]:
                    new_block = net_graphing.FunctionBlock(self.__method, self.__disasm, self.__graph)
                    new_block.update_start_offset(new_blocks_offset, new_blocks_index)
                    for exc in block.get_exception_handlers():
                        new_block.add_exception_handler(exc)
                    new_instr = self.__disasm.emit_instruction(Opcodes.Br)
                    new_instr.setup_instr_size(5)
                    new_instr.setup_instr_offset(new_blocks_offset, new_blocks_index)

                    target = block.get_next()[-1].get_start_offset() - new_blocks_offset - 5
                    new_instr.setup_arguments_from_int32(target)
                    new_block.add_instr(new_instr)
                    orig_next = block.get_next()[-1]
                    block.replace_next_index(-1, new_block)
                    new_block.add_next(orig_next)

                    new_blocks.append(new_block)
                    self.__graph.register_block(new_blocks_offset, new_block)
                    new_blocks_offset += 5
                    new_blocks_index += 1
        self.__graph.update_offsets()
        self.__graph.repopulate_prevs()
        blocks_order = new_blocks
        #check the list for any dead blocks
        for block in list(self.__graph.blocks()):
            if len(block.get_next()) == len(block.get_prev()) == 0:
                if not block.is_block_start():
                    self.__graph.unregister_block(block.get_start_offset())
        
        try:
            self.__graph.validate_blocks()
        except Exception as e:
            self.__graph.print_root()
            raise e
        total_compiled = len(blocks_order)
        #remove any dead blocks.
        new_blocks = list()
        for block in blocks_order:
            if len(block.get_prev()) == 0 and len(block.get_next()) == 0 and not block.is_block_start():
                self.__graph.unregister_block(block.get_start_offset())
                continue
            new_blocks.append(block) #TODO: something here seems to be messing up exception blocks maybe - not entirely sure yet.
        blocks_order = new_blocks
        total_compiled = len(blocks_order)
        #Here is where it gets messed up
        for x in range(total_compiled):
            #check if any jumps need to be added.
            blk = blocks_order[x]
            is_valid_last = True
            last_instr = blk.get_last_instr()
            #I think this should work for try clauses as well but not sure yet.
            if not last_instr.is_absolute_jmp() and not last_instr.is_branch():
                if last_instr.get_opcode() not in (Opcodes.Throw, Opcodes.Ret, Opcodes.Rethrow, Opcodes.Endfinally):
                    is_valid_last = False
            if not is_valid_last:
                if len(blk.get_next()) != 1:
                    raise Exception()
                nxt = blk.get_next()[0]
                if x == (total_compiled - 1) or blocks_order[x+1].get_start_offset() != nxt.get_start_offset():
                    new_instr = self.__disasm.emit_instruction(Opcodes.Br)
                    new_instr.setup_instr_size(5)
                    new_instr.setup_instr_offset(last_instr.get_instr_offset() + len(last_instr), last_instr.get_instr_index() + 1)
                    new_instr.setup_arguments_from_int32(nxt.get_start_offset() - len(new_instr) - new_instr.get_instr_offset())
                    blk.add_instr(new_instr)
        self.__graph.validate_blocks()

        #Before we finish, do any cleanups to make it pretty.
        for block in blocks_order:
            instrs = block.get_instrs()
            if len(instrs) <= 3:
                continue
            for x in range(len(instrs) - 3):
                instr = instrs[x]
                if instr.get_opcode() in (Opcodes.Ldc_I4_0, Opcodes.Ldc_I4, Opcodes.Ldc_I4_S):
                    if instr.get_argument() == 0:
                        instr2 = instrs[x+1]
                        if instr2.get_opcode() in self.STLOC:
                            instr3 = instrs[x+2]
                            if instr3.get_opcode() in self.LDLOC:
                                if instr3.get_argument() == instr2.get_argument():
                                    instr4 = instrs[x+3]
                                    if instr4.get_opcode() in (Opcodes.Brfalse, Opcodes.Brfalse_S):
                                        #replace with ldc.i4.0, stloc, no ldloc, br
                                        new_instr = self.__disasm.emit_instruction(Opcodes.Br)
                                        new_instr.setup_instr_size(5)
                                        new_instr.setup_instr_offset(instr3.get_instr_offset(), instr3.get_instr_index())
                                        new_instr.setup_arguments_from_int32(instr4.get_argument())
                                        block.remove_instrs(x+2, x+4)
                                        block.add_instr(new_instr)
                                        dead_nxt = block.get_next()[1]
                                        block.remove_next(dead_nxt)
                                        if dead_nxt.has_prev(block):
                                            dead_nxt.remove_prev(block)
                                        continue

        current_offset = 0
        current_index = 0
        self.__graph.validate_blocks()
        for x in range(total_compiled):
            block = blocks_order[x]
            orig_offset = block.get_start_offset()
            block.update_start_offset(current_offset, current_index)
            block.update_size(block.get_current_size())
            y = 0
            for instr in block.get_instrs():
                ins_op = instr.get_opcode()
                if not block.is_block_start() and ins_op in (Opcodes.Br, Opcodes.Br_S) and x < (total_compiled - 1):
                    if block.get_next()[0] == blocks_order[x+1]:
                        block.remove_instrs(y, y+1)
                        if len(block.get_instrs()) == 0:
                            nxts = list(block.get_next())
                            prvs = list(block.get_prev())
                            for prev in prvs:
                                for nxt in nxts:
                                    prev.replace_next(block, nxt)
                            for nxt in list(block.get_next()):
                                block.remove_next(nxt)
                            for prv in list(block.get_prev()):
                                block.remove_prev(prv)
                            remove_from_ordered.append(block)
                            self.__graph.unregister_block(orig_offset)
                        continue
                instr.setup_instr_offset(current_offset, current_index)
                current_offset += len(instr)
                current_index += 1
                y += 1
        for block in remove_from_ordered:
            if block in blocks_order:
                blocks_order.remove(block)
        total_compiled = len(blocks_order)
        remove_from_ordered.clear()
        for blk in blocks_order:
            last_instr = blk.get_last_instr()
            index = len(blk.get_instrs()) - 1
            if last_instr is not None and last_instr.get_opcode() in (Opcodes.Brtrue, Opcodes.Brfalse):
                if blk.get_next()[0] == blk.get_next()[1]:
                    new_instr = self.__disasm.emit_instruction(Opcodes.Pop)
                    new_instr.setup_instr_size(1)
                    new_instr.setup_instr_offset(last_instr.get_instr_offset(), last_instr.get_instr_index())
                    blk.replace_instr(index, new_instr)
                    new_instr = self.__disasm.emit_instruction(Opcodes.Br)
                    new_instr.setup_instr_size(5)
                    new_instr.setup_instr_offset(last_instr.get_instr_offset() + 1, last_instr.get_instr_index() + 1)
                    new_instr.setup_arguments_from_int32(last_instr.get_argument())
                    blk.add_instr(new_instr)
                    blk.remove_next(blk.get_next()[0])

        self.__graph.update_offsets()
        self.__graph.validate_blocks()
        #Do one final pass to make sure instr and block offsets are  good.   # relayout FIRST
        current_offset = 0
        current_index = 0
        for block in blocks_order:
            if block not in self.__graph.blocks():
                raise Exception()
            block.update_start_offset(current_offset, current_index)
            block.update_size(block.get_current_size())
            for instr in block.get_instrs():
                instr.setup_instr_offset(current_offset, current_index)
                current_index += 1
                current_offset += len(instr)
        #fixup the branches of any blocks - AFTER the relayout, so args use the final offsets
        for block in list(self.__graph.blocks()):
            last_instr = block.get_last_instr()
            last_op = last_instr.get_opcode()
            blk_next = block.get_next()
            if last_op == Opcodes.Switch:
                args = list()
                for x in range(len(blk_next) - 1):
                    target = blk_next[x].get_start_offset()
                    argument = target - len(last_instr) - last_instr.get_instr_offset()
                    args.append(argument)
                last_instr.setup_arguments_from_argslist(args)
            elif last_instr.is_absolute_jmp() or last_instr.is_branch():
                target = blk_next[0].get_start_offset()
                argument = target - len(last_instr) - last_instr.get_instr_offset()
                last_instr.setup_arguments_from_int32(argument)
            block.update_size(block.get_current_size())

        for block in list(self.__graph.blocks()):
            if block not in blocks_order:
                for nxt in list(block.get_next()):
                    block.remove_next(nxt)
                for prv in list(block.get_prev()):
                    block.remove_prev(prv)
                self.__graph.unregister_block(block.get_start_offset())
                #raise Exception(str(block)) #The block that isnt in blocks_order is a second exception clause.

        self.__graph.update_offsets()
        self.__graph.sort_blocks()

        self.__graph.validate_blocks()
        self.__graph.update_exc_handlers()

    def remove_useless_math(self):
        """ Remove math expressions that compute to a constant value.
        """

        MATH_INSTRS = [Opcodes.Nop, Opcodes.Not, Opcodes.Ldc_I4, Opcodes.Sub, Opcodes.Add, Opcodes.Neg, Opcodes.Xor, \
                       Opcodes.Ldc_I4_M1, Opcodes.Ldc_I4_S, Opcodes.Ldc_I8, Opcodes.Ldc_R4, Opcodes.Ldc_R8, \
                        Opcodes.Ldc_I4_0, Opcodes.Ldc_I4_1, Opcodes.Ldc_I4_2, Opcodes.Ldc_I4_3, Opcodes.Ldc_I4_4, Opcodes.Ldc_I4_5, \
                            Opcodes.Ldc_I4_6, Opcodes.Ldc_I4_7, Opcodes.Ldc_I4_8, Opcodes.Shr, Opcodes.Shl, Opcodes.Or, Opcodes.Shr_Un, Opcodes.And, \
                                Opcodes.Mul, Opcodes.Div, Opcodes.Div_Un, Opcodes.Rem, Opcodes.Rem_Un]
        MATH_OPS = [Opcodes.Not, Opcodes.Sub, Opcodes.Add, Opcodes.Neg, Opcodes.Xor, Opcodes.Shr, Opcodes.Shl, Opcodes.Or, Opcodes.Shr_Un, Opcodes.And, Opcodes.Mul, Opcodes.Div, Opcodes.Div_Un, Opcodes.Rem, Opcodes.Rem_Un]
        was_anything_changed = False
        block: net_graphing.FunctionBlock
        for block in self.__graph.blocks():
            start_index = -1
            end_index = -1
            nstack = 0
            orig_block_instrs = list(block.get_instrs())
            amt_deleted = 0
            for x in range(len(orig_block_instrs)):
                instr = orig_block_instrs[x]
                opcode = instr.get_opcode()
                if opcode not in MATH_INSTRS:
                    y = x
                    end_index = y 
                    nstack = 0
                    if start_index >= 0 and end_index > 0 and (end_index - start_index) > 1:
                        has_math_op = False
                        for z in range(start_index, end_index):
                            instr2 = orig_block_instrs[z]
                            if instr2.get_opcode() in MATH_OPS:
                                has_math_op = True
                                break
                        if has_math_op and not self.__are_additional_instrs_needed(block, orig_block_instrs, start_index, end_index):
                            was_anything_changed = True
                            amt_deleted += self.__handle_math_instrs(block, orig_block_instrs, start_index, end_index, amt_deleted)
                    start_index = -1
                    end_index = -1
                else:
                    if start_index < 0:
                        if instr.get_pstack() > nstack:
                            nstack = 0
                            continue
                        start_index = x
                    else:
                        #Test the instruction for stack consistency.
                        if nstack < instr.get_pstack():
                            y = x
                            end_index = y 
                            nstack = 0
                            if start_index > 0 and (end_index - start_index) > 1 and not self.__are_additional_instrs_needed(block, orig_block_instrs, start_index, end_index):
                                has_math_op = False
                                for z in range(start_index, end_index):
                                    instr2 = orig_block_instrs[z]
                                    if instr2.get_opcode() in MATH_OPS:
                                        has_math_op = True
                                        break
                                if has_math_op:
                                    was_anything_changed = True
                                    amt_deleted += self.__handle_math_instrs(block, orig_block_instrs, start_index, end_index, amt_deleted)
                            start_index = -1
                            end_index = -1
                    nstack += instr.get_nstack()
        return was_anything_changed


class MethodRecompiler:

    def __init__(self, instrs: list, exception_blocks: list=list(), local_var_sig_tok: int=0):
        self.__localvarsigtok = local_var_sig_tok
        self.__exception_blocks = exception_blocks
        self.__instrs = instrs
        self.__code_size = 0
        for instr in self.__instrs:
            self.__code_size += len(instr)

    def compile_method(self):
        use_fat = False
        if self.__code_size > 63:
            use_fat = True
        if self.__localvarsigtok != 0:
            use_fat = True

        fgraph = net_graphing.FunctionGraph(None, self.__instrs, self.__exception_blocks)
        calculated_max_stack = fgraph.calculate_max_stack_size()
        if calculated_max_stack > 8:
            use_fat = True
        result = bytearray()
        if not use_fat:
            result.extend(int.to_bytes((self.__code_size << 2) | 0x2, 1, 'little'))
            for instr in self.__instrs:
                result.extend(instr.to_bytes())
            return bytes(result)
        else:
            flags = 0x0003
            if len(self.__exception_blocks) != 0:
                flags |= 0x0008
            
            if self.__localvarsigtok != 0:
                flags |= 0x0010
            flags |= (3 << 12)
            #we need a function graph to calculate the max stack size.
            result.extend(int.to_bytes(flags, 2, 'little'))
            result.extend(int.to_bytes(calculated_max_stack, 2, 'little'))
            result.extend(int.to_bytes(self.__code_size, 4, 'little'))
            result.extend(int.to_bytes(self.__localvarsigtok, 4, 'little'))

            for instr in self.__instrs:
                b = instr.to_bytes()
                result.extend(b)
            if len(self.__exception_blocks) == 0:
                return bytes(result)
            def calc_int_size(num: int):
                return (num.bit_length() + 7) // 8
            
            new_length = (len(result) + 3) & ~3
            while len(result) != new_length:
                result.append(0)
            use_fat_exceptions = False

            if len(self.__exception_blocks) > 20:
                use_fat_exceptions = True

            if not use_fat_exceptions:
                for x in range(len(self.__exception_blocks)):
                    clause_flags, try_offset, try_length, handler_offset, handler_length, token = self.__exception_blocks[x]
                    cflags_size = calc_int_size(clause_flags)
                    tryoff_size = calc_int_size(try_offset)
                    trylen_size = calc_int_size(try_length)
                    handleroff_size = calc_int_size(handler_offset)
                    handlerlen_size = calc_int_size(handler_length)

                    if not (cflags_size <= 2 and tryoff_size <= 2 and trylen_size <= 1 and handleroff_size <= 2 and handlerlen_size <= 1):
                        use_fat_exceptions = True
                        break

            if not use_fat_exceptions:
                result.append(net_structs.CorILMethod.Sect_EHTable)
                data_size = (len(self.__exception_blocks) * 12) + 4
                result.extend(int.to_bytes(data_size, 1, 'little'))
                result.append(0)
                result.append(0)
                for exc in self.__exception_blocks:
                    clause_flags, try_offset, try_length, handler_offset, handler_length, token = exc
                    result.extend(int.to_bytes(clause_flags, 2, 'little'))
                    result.extend(int.to_bytes(try_offset, 2, 'little'))
                    result.extend(int.to_bytes(try_length, 1, 'little'))
                    result.extend(int.to_bytes(handler_offset, 2, 'little'))
                    result.extend(int.to_bytes(handler_length, 1, 'little'))
                    result.extend(int.to_bytes(token, 4, 'little'))
            else:
                result.append(net_structs.CorILMethod.Sect_FatFormat | net_structs.CorILMethod.Sect_EHTable)
                data_size = (len(self.__exception_blocks) * 24) + 4
                result.extend(int.to_bytes(data_size, 3, 'little'))
                for exc in self.__exception_blocks:
                    clause_flags, try_offset, try_length, handler_offset, handler_length, token = exc
                    result.extend(int.to_bytes(clause_flags, 4, 'little'))
                    result.extend(int.to_bytes(try_offset, 4, 'little'))
                    result.extend(int.to_bytes(try_length, 4, 'little'))
                    result.extend(int.to_bytes(handler_offset, 4, 'little'))
                    result.extend(int.to_bytes(handler_length, 4, 'little'))
                    result.extend(int.to_bytes(token, 4, 'little'))
            return bytes(result)