from dotnetutils import net_row_objects, net_graphing, net_exceptions, net_emu_types, net_emulator, net_structs
from dotnetutils.net_opcodes import Opcodes

class GraphAnalyzer:

    MATH_OPS = [Opcodes.Not, Opcodes.Sub, Opcodes.Add, Opcodes.Neg, Opcodes.Xor, Opcodes.Shr, Opcodes.Shl, Opcodes.Or, Opcodes.Shr_Un, Opcodes.And, Opcodes.Mul, Opcodes.Div, Opcodes.Div_Un, Opcodes.Rem, Opcodes.Rem_Un]
    BRANCHES = [Opcodes.Brtrue, Opcodes.Brtrue_S, Opcodes.Brfalse, Opcodes.Brfalse_S, Opcodes.Beq, Opcodes.Beq_S, Opcodes.Bne_Un, Opcodes.Bne_Un_S, \
                Opcodes.Bge, Opcodes.Bge_S, Opcodes.Bge_Un, Opcodes.Bge_Un_S, Opcodes.Bgt, Opcodes.Bgt_S, Opcodes.Bgt_Un, Opcodes.Bgt_Un_S, \
                Opcodes.Ble, Opcodes.Ble_S, Opcodes.Ble_Un, Opcodes.Ble_Un_S, Opcodes.Blt, Opcodes.Blt_S, Opcodes.Blt_Un, Opcodes.Blt_Un_S]
    STLOC = [Opcodes.Stloc_S, Opcodes.Stloc, Opcodes.Stloc_0, Opcodes.Stloc_1, Opcodes.Stloc_2, Opcodes.Stloc_3]
    LDLOC = [Opcodes.Ldloc_S, Opcodes.Ldloc, Opcodes.Ldloc_0, Opcodes.Ldloc_1, Opcodes.Ldloc_2, Opcodes.Ldloc_3]
    ALLOWED_STACK_OPS = LDLOC + [Opcodes.Br, Opcodes.Pop, Opcodes.Br_S, Opcodes.Ldc_I4, Opcodes.Ldc_I4_S, Opcodes.Ldloc, Opcodes.Ldloc_S, Opcodes.Dup, Opcodes.Ldc_I4_M1, Opcodes.Ldc_I4_0, Opcodes.Ldc_I4_1, Opcodes.Ldc_I4_2, Opcodes.Ldc_I4_3, Opcodes.Ldc_I4_4, Opcodes.Ldc_I4_5, Opcodes.Ldc_I4_6, Opcodes.Ldc_I4_7, Opcodes.Ldc_I4_8]
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
        if not isinstance(number, net_emu_types.DotNetNumber):
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

    """
    An attempt at control flow deobfuscation.
    """

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
                                    print('setting needs local 1', hex(instr.get_instr_offset()))
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
                                print('setting needs local 2', hex(instr.get_instr_offset()))
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

    def __is_target_switch(self, block, start_offsets, bad_instr_offsets):
        #check if all paths have a relatively constant value.
        instrs = block.get_instrs()
        MATH_OPS = [Opcodes.Not, Opcodes.Sub, Opcodes.Add, Opcodes.Neg, Opcodes.Xor, Opcodes.Shr, Opcodes.Shl, Opcodes.Or, Opcodes.Shr_Un, Opcodes.And, Opcodes.Mul, Opcodes.Div, Opcodes.Div_Un, Opcodes.Rem, Opcodes.Rem_Un]
        debug = False
        if debug:
            print('Checking {} {}'.format(block, block.get_instrs()))
        if len(instrs) < 2:
            if debug:
                print('instr len')
            return False
        if instrs[-2].get_opcode() not in MATH_OPS:
            if debug:
                print('not math ops')
            return False
        if block.get_last_instr().get_opcode() != Opcodes.Switch:
            if debug:
                print('not switch')
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
            added = instr.get_astack()
            pulled = instr.get_pstack()
            needed = needed - added + pulled

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
        return True
    
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
            print('Checking ', start_block, not_in)
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
        for prev in switch_block.get_prev():
            if debug:
                print('Checking start block {} {} {} {}'.format(prev, prev.get_original_length(), prev.get_current_size(), switch_block))
            if (prev.get_start_offset() + prev.get_original_length()) == switch_block.get_start_offset():
                if debug:
                    print('adding prev', prev)
                results.add(prev)        
        #at this point, we need to search a bit for the start block.  We need to find the block that the switch will execute from FIRST.
        #If the order is messed up, deobfuscation will be incorrect.
        if debug:
            print('running walker')
        for prev in switch_block.get_prev():
            #check if the previous block has a way to get to the switch statement that doesnt start from the switch statement.\
            handled = list()
            res = self.__start_block_walker(self.__graph.get_block_by_start_offset(0), prev, switch_block.get_prev(), handled)
            results |= res
        if debug:
            print('results of determine start block', results)
        return self.__find_math_blocks(results)
    
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
                emu = initial_emu.spawn_new_emulator(self.__method, start_offset=start_offset, end_offset=end_offset)
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
            emu = net_emulator.DotNetEmulator(self.__method, start_offset=first_start_offset, end_offset=switch_instr.get_instr_offset(), dont_execute_cctor=True)
            emu.setup_method_params([])
            worked = False
            try:
                emu.run_function()
            except net_exceptions.EmulatorEndExecutionException as e:
                worked = True
            if not worked:
                raise Exception()
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
        for end_block, start_blocks in start_mappings.items():
            while len(start_blocks) > 0:
                start_block = start_blocks.pop()
                if new_switch_block not in start_block.get_prev():
                    continue
                last_instr = start_block.get_last_instr()
                if last_instr.get_opcode() in (Opcodes.Ret, Opcodes.Endfinally, Opcodes.Throw):
                    new_switch_block.remove_next(start_block)
                usable_block = start_block
                already_checked = set()
                while len(usable_block.get_next()) == 1:
                    usable_block = usable_block.get_next()[0]
                    if usable_block in already_checked:
                        break
                    already_checked.add(usable_block)
                    last_instr = usable_block.get_last_instr()
                    if last_instr.get_opcode() in (Opcodes.Ret, Opcodes.Endfinally, Opcodes.Throw):
                        new_switch_block.remove_next(start_block)
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

        for blk in list(new_graph.blocks()):
            if len(blk.get_next()) == 0 and len(blk.get_prev()) == 0 and blk.get_start_offset() != 0:
                new_graph.unregister_block(blk.get_start_offset())

            elif len(blk.get_prev()) == 0 and not blk.is_block_start():
                new_graph.unregister_block(blk.get_start_offset())
        new_graph.repopulate_prevs()
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
                if last_op in (Opcodes.Ret, Opcodes.Throw, Opcodes.Endfinally):
                    continue
                if last_instr.is_branch():
                    continue

                if last_instr.is_absolute_jmp():
                    continue
            if len(blk.get_next()) == len(blk.get_prev()) == len(blk.get_instrs()) == 0:
                if new_graph.has_block(blk.get_start_offset()):
                    removed_blocks.append(blk.get_start_offset())
                    new_graph.unregister_block(blk.get_start_offset())
                continue

            if debug:
                print('doing br checks for block {}'.format(blk))

            nxts = blk.get_next()
            if len(nxts) != 1:
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

    def simplify_control_flow(self, max_attempts=-1):
        graph = self.__graph
        is_obfuscated_at_all = False
        x = 0
        while True:
            blocks = graph.blocks()
            is_obfuscated = False
            for block in blocks:
                start_offsets = list()
                bad_instrs = set()
                if self.__is_target_switch(block, start_offsets, bad_instrs):
                    graph.validate_blocks()
                    out = graph.duplicate()
                    is_obfuscated = True
                    is_obfuscated_at_all = True
                    print('removing switch number {} {} {}'.format(x, block, block.get_instrs()))
                    out.validate_blocks()
                    self.__deobfuscate_switch(block, start_offsets, block.get_last_instr(), out, bad_instrs)
                    out.validate_blocks()
                    x += 1
                    break
            if is_obfuscated:
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
                if max_attempts > 0 and x == max_attempts:
                    break
            elif not is_obfuscated_at_all:
                return None
            else:
                break
        return graph
    
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
        
    
    def __block_walker(self, block, handled):
        if block not in handled:
            #The block hasnt been laid out yet.
            handled.append(block) #Goal is to get the layout of blocks in order, then recalculate offsets.
            last_instr = block.get_last_instr()
                
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
            if len(blk_next) > 0 and not block.get_last_instr().get_opcode() in (Opcodes.Leave, Opcodes.Leave_S):
                self.__block_walker(blk_next[-1], handled)
            
            if last_instr.is_branch() and not last_instr.is_absolute_jmp():
                if last_op == Opcodes.Switch:
                    for x in range(0, len(blk_next) - 1):
                        self.__block_walker(blk_next[x], handled)
                else:
                    #For try context switches, dont output the leave instructions block yet.  That should be after all tries are finished.
                    self.__block_walker(blk_next[0], handled)
            if block.is_block_start() and block.get_start_offset() != 0 and block.is_block_try():
                #its the start of an exception block.  Walk those blocks next.
                for exc_flag, try_block, catch_block, token in self.__graph.get_exception_blocks():
                    for exc_flag2, clause_block in block.get_exception_handlers():
                        if exc_flag == exc_flag2 and clause_block == try_block:
                            self.__block_walker(catch_block, handled)
                            if exc_flag == net_structs.CorILExceptionClause.Filter:
                                self.__block_walker(token, handled)

    def repair_blocks(self):
        #Goal of this method is to fixup block relationships and make it look pretty.
        #TODO: When stiching together blocks try blocks need to be together, filter clause needs to follow the rules etc.
        #TODO: need to test this with filter clause I think block ordering is off.
        self.__graph.validate_blocks()
        was_unregistered = list()
        for block in list(self.__graph.blocks()):
            if block.get_start_offset() in was_unregistered:
                continue
            block_prev = list(block.get_prev())
            block_next = list(block.get_next())
            if len(block_prev) == 1:
                prev = block_prev[0]
                prev_last = prev.get_last_instr()
                if prev_last.get_opcode() in (Opcodes.Br, Opcodes.Br_S):
                    #Remove the jmp on the prev
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
        for block in self.__graph.blocks():
            self.__block_walker(block, blocks_order)
        #self.__graph.print_root()


        #check over the blocks, make sure theres a jmp if its needed.
        total_compiled = len(blocks_order)
        #Do an initial offset update to ensure the next loop works.
        current_offset = 0
        current_index = 0
        #lay out the offsets
        for x in range(total_compiled):
            block = blocks_order[x]
            if len(block.get_instrs()) == 0:
                self.__graph.unregister_block(block.get_instr_offset())
                continue
            if len(block.get_prev()) == 0 and current_offset != 0 and (block.get_start_offset() != 0 and not block.is_block_start()):
                #dead block.
                for nxt in list(block.get_next()):
                    block.remove_next(nxt)
                    if nxt.has_prev(block):
                        nxt.remove_prev(block)
                self.__graph.unregister_block(block.get_start_offset())
                continue
            block.update_start_offset(current_offset, current_index)
            block.update_size(block.get_current_size())
            current_offset += block.get_original_length()
            current_index += len(block.get_instrs())
        self.__graph.update_offsets()
        self.__graph.validate_blocks()

        #remove any dead blocks.
        new_blocks = list()
        for block in blocks_order:
            if len(block.get_prev()) == 0 and len(block.get_next()) == 0 and not block.is_block_start():
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
                if last_instr.get_opcode() not in (Opcodes.Throw, Opcodes.Ret, Opcodes.Endfinally):
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
        #lay out the offsets
        #self.__graph.print_root()
        for x in range(total_compiled):
            block = blocks_order[x]
            orig_offset = block.get_start_offset()
            block.update_start_offset(current_offset, current_index)
            block.update_size(block.get_current_size())
            y = 0
            for instr in block.get_instrs():
                ins_op = instr.get_opcode()
                if ins_op in (Opcodes.Br, Opcodes.Br_S) and x < (total_compiled - 1):
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
                            self.__graph.unregister_block(orig_offset)
                        continue
                instr.setup_instr_offset(current_offset, current_index)
                current_offset += len(instr)
                current_index += 1
                y += 1
        for blk in blocks_order:
            last_instr = blk.get_last_instr()
            index = len(blk.get_instrs()) - 1
            if last_instr is not None and last_instr.get_opcode() in (Opcodes.Brtrue, Opcodes.Brfalse):
                if blk.get_next()[0] == blk.get_next()[1]:
                    new_instr = self.__disasm.emit_instruction(Opcodes.Br)
                    new_instr.setup_instr_size(5)
                    new_instr.setup_instr_offset(last_instr.get_instr_offset(), last_instr.get_instr_index())
                    new_instr.setup_arguments_from_int32(last_instr.get_argument())
                    blk.remove_instrs(index, index+1)
                    blk.add_instr(new_instr)
                    blk.remove_next(blk.get_next()[0])
        self.__graph.update_offsets()
        self.__graph.validate_blocks()
        #fixup the branches of any blocks
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
            import binascii
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
            
            while len(result) % 4 != 0: 
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