from dotnetutils import net_row_objects, net_graphing, net_exceptions, net_emu_types, net_emulator, net_structs
from dotnetutils.net_opcodes import Opcodes
from dotnetutils.net_graphing import FunctionBlock, FunctionGraph
from dotnetutils import net_cil_disas

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
        emu_obj = net_emulator.DotNetEmulator(self.__method, start_offset=start_offset, end_offset=end_offset, dont_execute_cctor=True)
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
                        raise net_exceptions.ControlFlowDeobfuscationMisidentify('Not obfuscated')
                usable_stack.extend([in_slice] * pulled)  
                if not any(usable_stack):
                    if not in_slice or ins_op not in self.ALLOWED_MODIFIERS:
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
    
    def __find_all_var_sets_reachable_from(self, var_no: int, from_block: FunctionBlock, crawled={}):
        if from_block.get_start_offset() in crawled:
            return []
        crawled.add(from_block.get_start_offset())
        results = list()
        for instr in from_block.get_instrs():
            if instr.get_opcode() in self.STLOC and instr.get_argument() == var_no:
                results.append((from_block, instr))
        for prev in from_block.get_prev():
            results.extend(self.__find_all_var_sets_reachable_from(var_no, prev, crawled))
        return results

    def new_switch_detection(self, switch_block: FunctionBlock):
        if switch_block.get_last_instr() is None or switch_block.get_last_instr().get_opcode() != Opcodes.Switch:
            return False, [], [], [], []
        try:
            switch_paths = self.get_all_paths_to_block(switch_block, switch_block.get_last_instr())
        except net_exceptions.ControlFlowDeobfuscationMisidentify:
            return False, [], [], [], []
        all_modifiers = list()
        all_src_instrs = list()
        requires_additional_work = list()
        x = 0
        for switch_path in switch_paths:
            switch_path.reverse()
            first_blk = switch_path[0]
            if first_blk.get_last_instr() is None:
                return False, [], [], [], []
            last_instr = first_blk.get_last_instr()
            if last_instr.get_opcode() != Opcodes.Switch:
                return False, [], [], [], []
            modifier_instrs = list()

            src_instr, src_blk, src_blk_index = self.__find_value_source(switch_path, last_instr, modifier_instrs)
            if src_instr is None:
                return False, [], [], [], []
            src_op = src_instr.get_opcode()
            modifier_instrs.reverse()
            amt = 0
            while src_op in self.LDLOC:
                if amt > 10:
                    return False, [], [], [], []
                amt += 1
                var_no = src_instr.get_argument()
                var_set_instr, var_set_blk, var_blk_index = self.__find_var_sets(switch_path[src_blk_index:], var_no)
                if var_set_instr is None:
                    all_var_sets = self.__find_all_var_sets(var_no)
                        
                    is_failure = False
                    for var_block, var_instr in all_var_sets:
                        try:
                            var_paths = self.get_all_paths_to_block(var_block, var_instr)
                        except net_exceptions.ControlFlowDeobfuscationMisidentify:
                            return False, [], [], [], []
                        
                        for var_path in var_paths:
                            var_path.reverse()
                            child_modifiers = list()
                            var_set_instr, var_set_blk, var_blk_index = self.__find_value_source(var_path, var_instr, child_modifiers)
                            if var_set_instr is None or var_set_instr.get_opcode() not in self.LDC_INSTRS:
                                is_failure = True
                                break


                        if is_failure:
                            return False, [], [], [], []
                        
                    if not is_failure:
                        requires_additional_work.append(x)
                        break
                    return False, [], [], [], []
                child_modifiers = list()
                src_instr, src_blk, src_blk_index = self.__find_value_source(switch_path[var_blk_index:], var_set_instr, child_modifiers)
                if src_instr is None:
                    return False, [], [], [], []
                src_op = src_instr.get_opcode()
                child_modifiers.reverse()
                modifier_instrs = child_modifiers + [var_set_instr] + modifier_instrs
            if src_op not in self.LDC_INSTRS and (x not in requires_additional_work and src_op not in self.LDLOC):
                return False, [], [], [], []
            all_modifiers.append(modifier_instrs)
            all_src_instrs.append(src_instr)
            x += 1
        return True, switch_paths, all_modifiers, all_src_instrs, requires_additional_work

    def __collapse_switch_to_case(self, new_graph, switch_block, orig_switch_block, value):
        """ Rewrite a single-valued switch block's terminator into an unconditional branch to the one
        case it always takes, keeping the block (it may be a try-start or hold real code) and its
        predecessors.  The index-producing instructions are dropped by the modifier sweep, which keeps
        the stack balanced (they pushed the value the switch popped). """
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
        """ True if every instruction before the terminator is DNR state-management junk (loads,
        stores, constants, arithmetic, dup/pop/nop/br) with no real, side-effecting code.  Rerouting
        predecessors past such a block is safe; doing it to a block with real code would drop it. """
        allowed = set(self.LDLOC) | set(self.STLOC) | set(self.LDC_INSTRS) | set(self.MATH_OPS) | \
                  {Opcodes.Nop, Opcodes.Pop, Opcodes.Dup, Opcodes.Br, Opcodes.Br_S}
        return all(instr.get_opcode() in allowed for instr in block.get_instrs()[:-1])

    def new_switch_deob(self, switch_block: FunctionBlock):
        if switch_block is None:
            raise Exception()
        is_obf, switch_paths, all_modifiers, all_src_instrs, needs_more_work = self.new_switch_detection(switch_block)
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
            emu = net_emulator.DotNetEmulator(self.__method, force_instrs=modifiers, dont_execute_cctor=True)
            emu.run_function()
            num = emu.get_stack().pop_obj()
            if not isinstance(num, net_emu_types.DotNetNumber):
                raise Exception()
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
            path.extend([None] * (len(path) - largest_path))
        path_diverges = dict()
        for x in range(largest_path):
            for y in range(len(all_paths)):
                curr_path, curr_num, modifiers = all_paths[y]
                if len(curr_path) <= x or y in needs_more_work:
                    if y in needs_more_work:
                        path_diverges[y] = None
                    continue

                is_unique = True
                options = switch_paths_by_value[curr_num]
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
            #Single-valued: the switch always takes one case (the value is committed within the switch
            #block itself).  Collapse it in place - keep the block (it may be a try-start / hold real
            #code) and its predecessors, rewriting the terminator to a branch to that case.  Every
            #block_index would be 0 here, which the reroute below can't handle (curr_path[-1] wraps).
            self.__collapse_switch_to_case(new_graph, new_switch_block, switch_block, path_values[0])
        else:
            #Multi-valued dispatcher.  Rerouting predecessors past the switch block is only safe if the
            #block is pure dispatch; if it holds real code, bypassing it drops that code.  In this
            #branch block_index >= 1 for every path (the switch block is never value-unique when there
            #are multiple values), so curr_path[block_index - 1] is always a real predecessor.
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
                if target >= len(switch_nexts):
                    target = len(switch_nexts) - 1
                next_block = new_graph.get_block_by_offset(switch_nexts[target].get_start_offset())
                
                if new_target.has_next(target_prev):
                    new_target.replace_next(target_prev, next_block)
                else:
                    if next_block != new_switch_block and new_switch_block.has_next(next_block):
                        new_switch_block.remove_next(next_block)
        if len(needs_more_work) > 0:
            fake_emu_obj = net_emulator.DotNetEmulator(self.__method)
            for index in needs_more_work:
                curr_path, curr_num, modifier_instrs = all_paths[index]
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
                last_num = -1 
                if curr_path[last_num] is None:
                    last_num -= 1
                new_target = new_graph.get_block_by_offset(curr_path[last_num].get_start_offset())
                
                from_block = new_graph.get_block_by_offset(instr.get_instr_offset())
                all_reachable_sets = self.__find_all_var_sets_reachable_from(instr.get_argument(), from_block, set())
                if len(all_reachable_sets) == 0:
                    dnint = net_emu_types.DotNetInt32(fake_emu_obj, None)
                    dnint.from_int(0)
                    new_instr = self.emit_ldc_num(dnint)
                    if len(new_instr) != 1:
                        raise Exception()
                    new_instr = new_instr[0]
                    new_instr.setup_instr_offset(instr.get_instr_offset(), instr.get_instr_index())
                    instr_block = new_graph.get_block_by_offset(instr.get_instr_offset())
                    instr_block.replace_instr(instr_block.get_instr_index(instr), new_instr)
                    if instr.get_instr_offset() in to_remove_instrs:
                        del to_remove_instrs[instr.get_instr_offset()]
                else:
                    if len(all_reachable_sets) != 1:
                        raise Exception()
                    for set_block, set_instr in all_reachable_sets:
                        try:
                            all_paths = self.get_all_paths_to_block(set_block, set_instr)
                        except net_exceptions.ControlFlowDeobfuscationMisidentify:
                            return None
                        if len(all_paths) != 1:
                            raise Exception()
                        for set_path in all_paths:
                            set_path.reverse()
                            child_modifiers = list()
                            var_set_instr, var_set_blk, var_blk_index = self.__find_value_source(set_path, set_instr, child_modifiers)
                            if var_set_instr is None:
                                var_value = 0
                            else:
                                if var_set_instr.get_opcode() in self.LDC_INSTRS:
                                    var_value = var_set_instr.get_opcode()
                                else:
                                    child_modifiers = list()
                                    src_instr, src_blk, src_blk_index = self.__find_value_source(set_path[var_blk_index:], var_set_instr, child_modifiers)
                                    raise Exception()
                            dnint = net_emu_types.DotNetInt32(fake_emu_obj, None)
                            dnint.from_int(var_value)
                            new_instr = self.emit_ldc_num(dnint)
                            if len(new_instr) != 1:
                                raise Exception()
                            new_instr = new_instr[0]

                            new_instr.setup_instr_offset(instr.get_instr_offset(), instr.get_instr_index())
                            instr_block = new_graph.get_block_by_offset(instr.get_instr_offset())
                            instr_block.replace_instr(instr_block.get_instr_index(instr), new_instr)
                            if instr.get_instr_offset() in to_remove_instrs:
                                del to_remove_instrs[instr.get_instr_offset()]
                if orig_instr != instr:
                    #Loop does not have edge from value, its reused
                    orig_instr_block = new_graph.get_block_by_offset(orig_instr.get_instr_offset())
                    new_target = new_graph.get_block_by_offset(switch_block.get_next()[0].get_start_offset())
                    instr_block.replace_next(orig_instr_block, new_target)
                new_switch_block.remove_next(new_target)
                                
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
                                block.merge_block(nxt)
                                for nxtblk in list(nxt.get_next()):
                                    block.add_next(nxtblk)
                                nxt.clear_next()
                                to_remove.add(nxt)
                            else:
                                nxt = nxts[0]
                                for prev in prvs:
                                    prev.replace_next(block, nxt)
                                to_remove.add(block)
                        elif len(prvs) == 0 and not block.is_block_start():
                            block.clear_next()
                            to_remove.add(block)
                        elif len(prvs) == 1 and not block.is_block_start():
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
                    if last_instr.get_opcode() not in (Opcodes.Throw, Opcodes.Ret, Opcodes.Rethrow, Opcodes.Endfinally):
                        nxts = list(block.get_next())
                        if len(nxts) == 0:
                            to_remove.add(block)
                            for prv in block.get_prev():
                                prv.remove_next(block)
                    if not block.is_block_start():
                        if len(block.get_prev()) == 0:
                            for nxt in list(block.get_next()):
                                block.remove_next(nxt)
                            to_remove.add(block)
                    if len(block.get_next()) == 2:
                        nxts = block.get_next()
                        if nxts[0] == nxts[1]:
                            last_instr = block.get_last_instr()
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
                    if len(block.get_next()) == 1 and last_instr.is_branch() and not last_instr.is_absolute_jmp() and last_instr.get_opcode() != Opcodes.Switch:
                        nxt = block.get_next()[0]
                        block.add_next(nxt)
                        changed = True
                        continue

            for block in to_remove:
                changed = True
                block.clear_next()
                block.clear_prev()
                new_graph.unregister_block(block.get_start_offset())
        new_graph.repopulate_prevs()
        new_graph.validate_blocks()
        new_analyzer = GraphAnalyzer(self.__method, new_graph)
        new_analyzer.repair_blocks()
        return new_graph

    def simplify_control_flow(self, max_attempts=-1):
        graph = self.__graph
        is_obfuscated_at_all = False
        attempts = 0
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
                for block in list(graph.blocks()):
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
        if not first_instr.get_name().startswith('ldc.') and first_instr.get_opcode() != Opcodes.Ldnull:
            return False
        
        second_instr = target_instrs[1]
        if second_instr.is_branch():
            return False
        if not second_instr.get_name().startswith('ldc.') and second_instr.get_opcode() != Opcodes.Ldnull:
            return False
        
        should_jmp = first_instr.get_argument() == second_instr.get_argument()

        to_keep = block.get_next()[0 if should_jmp else 1]
        to_remove = block.get_next()[1 if should_jmp else 0]
        if to_remove is to_keep:
            return False
        block.remove_next(to_remove)
        operand_index = block.get_instr_index(first_instr)
        block.remove_instrs(operand_index, block.get_instr_index(second_instr) + 1)
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