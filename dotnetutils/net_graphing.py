from dotnetutils import net_cil_disas, net_emulator, net_structs, net_opcodes, net_row_objects, net_exceptions

class FunctionBlock:
    def __init__(self, method_object, disasm_object, graph_id):
        self.__method_object = method_object
        self.__disasm_object = disasm_object
        self.__instrs = list()
        self.__previous = list()
        self.__next = list()
        self.__start_offset = -1
        self.__original_length = 0
        self.__was_cleared = False
        self.__original_cleared = False
        self.__original_nexts = list()
        self.__graph_id = graph_id
        self.__is_junk_block = False
        self.__is_switch_case = False
        self.__was_switch_block = False
        self.__is_block_finished = False
        self.__is_block_try = False
        self.__is_block_catch = False
        self.__is_block_finally = False
        self.__try_block_offset = -1
        self.__catch_block_offset = -1
        self.__finally_block_offset = -1

    def set_try_block_offset(self, offset):
        self.__try_block_offset = offset

    def set_catch_block_offset(self, offset):
        self.__catch_block_offset = offset

    def set_finally_block_offset(self, offset):
        self.__finally_block_offset = offset

    def get_try_block_offset(self):
        return self.__try_block_offset
    
    def get_catch_block_offset(self):
        return self.__catch_block_offset
    
    def get_finally_block_offset(self):
        return self.__finally_block_offset

    def mark_block_try(self):
        self.__is_block_try = True

    def mark_block_catch(self):
        self.__is_block_catch = True

    def mark_block_finally(self):
        self.__is_block_finally = True

    def is_block_try(self):
        return self.__is_block_try
    
    def is_block_catch(self):
        return self.__is_block_catch
    
    def is_block_finally(self):
        return self.__is_block_finally

    def mark_block_finished(self):
        self.__is_block_finished = True

    def mark_switch_block(self):
        self.__was_switch_block = True

    def was_switch_block(self):
        return self.__was_switch_block

    def is_block_return(self):
        return self.get_last_instr().get_name() == 'ret'

    def __hash__(self):
        return hash(self.__start_offset)

    def get_current_size(self):
        result = 0
        for instr in self.get_instrs():
            result += len(instr)
        return result

    def mark_switch_case(self):
        self.__is_switch_case = True

    def is_switch_case(self):
        return self.__is_switch_case
    
    def get_instr_index(self, instr):
        for x in range(len(self.get_instrs())):
            pt_instr = self.get_instrs()[x]
            if pt_instr.offset == instr.offset:
                return x
        return -1
    
    def mark_junk(self):
        self.__is_junk_block = True

    def is_junk_block(self):
        return self.__is_junk_block
    
    def reverse_next(self):
        self.__next.reverse()

    def is_start(self):
        return self.__start_offset == 0

    def get_original_length(self):
        return self.__original_length

    def has_absolute_path_to_zero(self):
        if self.__start_offset == 0:
            return prev
        for prev in self.get_prev():
            if prev.has_absolute_path_to_zero():
                return True

        return False
    
    def block_leads_switch(self):
        if self.is_block_switch():
            return True
        if self.is_block_absolutejmp():
            usable = self
            while len(usable.get_next()) == 1 and usable.is_block_absolutejmp():
                usable = usable.ge_next()[0]
                if usable.is_block_switch():
                    return True
        return False

    def get_instr_at_index(self, index):
        return self.__instrs[index]

    def replace_instr(self, index, new_instr):
        del self.__instrs[index]
        self.__instrs.insert(index, new_instr)

    def insert_instr(self, index, instr):
        self.__instrs.insert(index, instr)

    def is_block_conditional(self):
        instr = self.get_last_instr()
        if not self.is_block_absolutejmp():
            if instr.get_name() != 'switch':
                return instr.is_branch()

        return False

    def contains_instr(self, name):
        for instr in self.__instrs:
            if instr.get_name() == name:
                return True
        return False

    def clear_next(self):
        nxt = self.get_next().copy()
        for n in nxt:
            self.remove_next(n)

    def clear_prev(self):
        prv = self.get_prev().copy()
        for p in prv:
            self.remove_prev(p)

    def clear_original_next(self):
        nxt = self.get_next().copy()
        if not self.__original_cleared:
            for n in nxt:
                if n.get_start_offset() in self.__original_nexts:
                    self.remove_next(n)
            self.__original_cleared = True

    def clear_next_once(self):
        if not self.__was_cleared:
            self.__was_cleared = True
            self.clear_next()

    def is_block_switch(self):
        return self.get_last_instr().get_name() == 'switch'

    def is_block_absolutejmp(self):
        instr = self.get_last_instr()
        return instr.get_name() == 'br' or instr.get_name() == 'br.s' or instr.get_name() == 'leave' or instr.get_name() == 'leave.s'
    
    def is_block_direct(self):
        return not self.is_block_absolutejmp() and not self.is_block_conditional() and not self.get_last_instr().is_branch() and len(self.get_next()) == 1
    
    def add_instr(self, instr):
        self.__instrs.append(instr)
        if self.__start_offset == -1:
            self.__start_offset = instr.offset

        self.__original_length += len(instr)

    def remove_instrs_after_index(self, index):
        self.__instrs = self.__instrs[:index + 1]

    def get_instrs(self):
        return self.__instrs

    def get_start_offset(self):
        return self.__start_offset

    def get_last_instruction(self):
        return self.get_instrs()[-1]

    def has_prev(self, block):
        return block in self.__previous
    
    def add_original_next(self, block):
        #Problem here: switch fallthrough case.  How do I handle it?  TODO: fix
        self.__original_nexts.append(block.get_start_offset())
        self.add_next(block)

    def add_next(self, block):
        if not self.has_next(block):
            if block and not self.has_next(block):
                self.__next.append(block)
            if block and not block.has_prev(self):
                block.__previous.append(self)

    def has_next(self, block):
        return block in self.__next

    def get_next(self):
        return self.__next

    def get_prev(self):
        return self.__previous
    
    def remove_prev(self, prev):
        prev.__next.remove(self)
        self.__previous.remove(prev)

    def get_last_instr(self):
        return self.get_instrs()[-1]

    def has_offset(self, offset):
        if self.__is_block_finished:
            if self.__start_offset <= offset <= (self.__start_offset + self.__original_length):
                return True
        for instr in self.get_instrs():
            if instr.offset == offset:
                return True
        return False

    def validate_block(self):
        last_instr = self.get_last_instr()
        if not last_instr.is_branch():
            if last_instr.get_name() == 'ret':
                if not len(self.__next) == 0:
                    raise net_exceptions.InvalidBlockException
            else:
                if not len(self.__next) == 1:
                    raise net_exceptions.InvalidBlockException
        else:
            if last_instr.get_name() == 'switch':
                if not len(self.__next) == len(self.__disasm_object.get_argument(last_instr)):
                    raise net_exceptions.InvalidBlockException
            elif last_instr.get_name() == 'br.s' or last_instr.get_name() == 'br' or last_instr.get_name() == 'leave' or last_instr.get_name() == 'leave.s':
                if not len(self.__next) == 1:
                    raise net_exceptions.InvalidBlockException
            else:
                if not len(self.__next) == 2:
                    raise net_exceptions.InvalidBlockException

    def split_block(self, split_offset):
        new_instrs = list()
        split_instrs = list()
        start_splitting = False
        new_size = 0
        for instr in self.__instrs:
            if instr.offset == split_offset:
                start_splitting = True
            if not start_splitting:
                new_size += len(instr)
                new_instrs.append(instr)
            else:
                split_instrs.append(instr)

        self.__instrs = new_instrs
        self.__original_length = new_size

        new_block = FunctionBlock(self.__method_object, self.__disasm_object, self.__graph_id)
        if self.__is_block_try:
            new_block.mark_block_try()
        
        if self.__is_block_catch:
            new_block.mark_block_catch()

        if self.__is_block_finally:
            new_block.mark_block_finally()
        
        for instr in split_instrs:
            new_block.add_instr(instr)

        new_next = self.__next.copy()
        for next in self.__next:
            self.remove_next(next)

        for next in new_next:
            new_block.add_original_next(next)
        self.__next = list()
        self.add_original_next(new_block)
        return new_block

    def remove_next(self, block):
        if self.has_next(block):
            self.__next.remove(block)
            block.__previous.remove(self)
            if block.get_start_offset() in self.__original_nexts:
                self.__original_nexts.remove(block.get_start_offset())

    def replace_next(self, block, new_block):
        if self.has_next(block):
            current_index = self.__next.index(block)
            if current_index == -1:
                raise net_exceptions.InvalidBlockException
            self.remove_next(block)
            if self.has_next(new_block):
                #if the block is already there, in order to preserve order remove it.
                self.remove_next(new_block)

            if not self.has_next(new_block):
                if new_block and not self.has_next(new_block):
                    self.__next.insert(current_index, new_block)
                if new_block and not new_block.has_prev(self):
                    new_block.__previous.append(self)

    def __str__(self):
        return 'Block at offset {}'.format(hex(self.get_start_offset()))

    def __eq__(self, other):
        return isinstance(other, FunctionBlock) and self.get_start_offset() == other.get_start_offset()
    
graph_id = 0
class FunctionGraph:
    #TODO: Add support for multiple switch statements - in the works.
    #TODO: Add support for try catch finally exception handling - Going to be very annoying.
    def __init__(self, method_object, init_blocks=True, debug_print=False):
        global graph_id
        self.__graph_id = graph_id
        graph_id += 1
        self.__method_object = method_object
        self.__debug_print = debug_print
        if init_blocks:
            if not self.__method_object.has_body():
                raise net_exceptions.InvalidBlockException
            self.__disasm_object = method_object.disassemble_method()
            self.__blocks_start = dict()
            self.__handle_try_catch_finally_blocks() # first handle try catch finally since thats a special case.
            self.__sort_blocks()
            if 0 not in self.__blocks_start:
                self.__root_block = self.__parse_block(self.__disasm_object, 0)
            else:
                self.__root_block = self.__blocks_start[0]

            self.__sort_blocks()

            for block in self.__blocks_start.values():
                block.mark_block_finished() #Tell each block that we are done with our initial setup, anything else is a modification.

    def __sort_blocks(self):
        keys = list(self.__blocks_start.keys())
        keys.sort()
        self.__blocks_start = {i: self.__blocks_start[i] for i in keys}
    
    def enable_debug_printing(self):
        self.__debug_print = True

    def debug_printing_enabled(self):
        return self.__debug_print

    def set_root_block(self, root_block):
        self.__root_block = root_block

    def get_root_block(self):
        return self.__root_block

    def __should_split_block(self, split_offset):
        for block in self.__blocks_start.values():
            instrs = block.get_instrs()
            if len(instrs) > 1:
                for instr in instrs[1:]:
                    if instr.offset == split_offset:
                        return block
        return None

    def __get_block_for_offset(self, offset):
        for block in self.__blocks_start.values():
            if block.has_offset(offset):
                return block
        return None

    def analyze(self):
        return self.__analyze_switch_statements()

    def __handle_switch_block(self, emu: net_emulator.DotNetEmulator, switch_block: FunctionBlock, child_block: FunctionBlock, usable_graph, var_id_no: int, handled_blocks: list, localvars: dict, previous_block: FunctionBlock, initial_child_block: FunctionBlock):
        if child_block.get_start_offset() in handled_blocks:
            if self.__debug_print:
                print('Returning from __handle_switch_statement because child block {} is in handled_blocks'.format(hex(child_block.get_start_offset())))
            return
        #first check to see if this is a switch block. 
        if child_block.is_block_switch() and child_block.get_start_offset() != switch_block.get_start_offset():
            #if it is a switch block, we need to find the initial block.
            if self.__is_suspicious_switch(child_block): 
                if initial_child_block is None:
                    raise net_exceptions.InvalidBlockException
                if initial_child_block.is_switch_case():
                    #find the actual child block - this wont do.
                    shortest_path = self.get_shortest_path(initial_child_block, child_block)
                    actual_child_block = None
                    for actual_child_block in shortest_path:
                        if actual_child_block.get_start_offset() == initial_child_block.get_start_offset():
                            continue
                        if not actual_child_block.is_switch_case() and len(actual_child_block.get_next()) == 1:
                            break
                    if self.__debug_print:
                        print('1 calling analyze_switch_statement_internal with switch block {} and starting block {}'.format(hex(child_block.get_start_offset()), hex(actual_child_block.get_start_offset())))
                    return self.__analyze_switch_statement_internal(child_block, actual_child_block, usable_graph, handled_blocks)
                else:
                    if self.__debug_print:
                        print('2 calling analyze_switch_statement_internal with switch block {} and starting block {}'.format(hex(child_block.get_start_offset()), hex(initial_child_block.get_start_offset())))

                    return self.__analyze_switch_statement_internal(child_block, initial_child_block, usable_graph, handled_blocks)
        handled_blocks.append(child_block.get_start_offset())
        if self.__debug_print:
            print(child_block.is_block_absolutejmp(), (not child_block.get_last_instr().is_branch() and child_block.get_last_instr().get_name() == 'switch'))
        if (child_block.is_block_absolutejmp() or child_block.is_block_direct()) or (not child_block.get_last_instr().is_branch() and child_block.get_last_instr().get_name() == 'switch'):
            if not len(child_block.get_next()) == 1:
                raise net_exceptions.InvalidBlockException 
            next_block: FunctionBlock = child_block.get_next()[0]
            if self.__debug_print:
                print('next block stats {} {} {} {}'.format(hex(next_block.get_start_offset()), next_block.is_junk_block(), next_block.is_switch_case(), next_block.is_block_switch()))
            if not next_block.is_block_switch() or switch_block.get_start_offset() != next_block.get_start_offset():
                if self.__debug_print:
                    print('Going from block {} to {}'.format(hex(child_block.get_start_offset()), hex(next_block.get_start_offset())))
                if initial_child_block == None:
                    if self.__debug_print:
                        print('Calling handle_switch_block (1)')
                    return self.__handle_switch_block(emu, switch_block, next_block, usable_graph, var_id_no, handled_blocks, localvars.copy(), None, child_block)
                else:
                    if self.__debug_print:
                        print('Calling handle_switch_block (2)')
                    return self.__handle_switch_block(emu, switch_block, next_block, usable_graph, var_id_no, handled_blocks, localvars.copy(), None, initial_child_block)
        
        #our next check - do we have a switch block that we need to handle?
        
        usable_child_block = usable_graph.__get_block_for_offset(child_block.get_start_offset())
        if self.__debug_print:
            print('Calling __handle_switch_statement with child_block {}'.format(hex(child_block.get_start_offset())))

        #if all the block does is take our switch var and modify it, mark it as junk.

        if child_block.is_switch_case():
            instrs = child_block.get_instrs()
            if instrs[0].get_name().startswith('ldloc'):
                if instrs[0].get_argument() == var_id_no:
                    allowed_instrs = ['ldc.i4', 'mul', 'pop', 'br', 'br.s', 'xor', 'nop']
                    check_failed = False
                    for instr in instrs[1:]:
                        if instr.get_name() not in allowed_instrs:
                            check_failed = True

                    if not check_failed:
                        usable_child_block.mark_junk()

        #run the same check on the initial child_block just to be safe
        if initial_child_block != None:
            usable_initial_block = usable_graph.__get_block_for_offset(initial_child_block.get_start_offset())
            if not usable_initial_block.is_junk_block():
                instrs = initial_child_block.get_instrs()
                if instrs[0].get_name().startswith('ldloc'):
                    if instrs[0].get_argument() == var_id_no:
                        allowed_instrs = ['ldc.i4', 'mul', 'pop', 'br', 'br.s', 'xor', 'nop']
                        check_failed = False
                        for instr in instrs[1:]:
                            if instr.get_name() not in allowed_instrs:
                                check_failed = True

                        if not check_failed:
                            usable_initial_block.mark_junk()

        if child_block.is_block_return():
            if self.__debug_print:
                print('child_block.is_block_return(): {}'.format(hex(child_block.get_start_offset())))
            return

        if child_block.is_block_conditional():
            # this may have the potential for issues if this isnt the last block in the case - FIXME
            true_case = child_block.get_next()[0]
            other_case = child_block.get_next()[1]
            usable_child_block.clear_next_once()
            usable_true_case = usable_graph.__get_block_for_offset(true_case.get_start_offset())
            usable_other_case = usable_graph.__get_block_for_offset(other_case.get_start_offset())
            if self.__debug_print:
                print('Adding next of {} to {} as usable_true_case'.format(hex(usable_true_case.get_start_offset()), hex(usable_child_block.get_start_offset())))
            usable_child_block.add_next(usable_true_case)
            if self.__debug_print:
                print('Adding next of {} to {} as usable_other_case'.format(hex(usable_other_case.get_start_offset()), hex(usable_child_block.get_start_offset())))
            usable_child_block.add_next(usable_other_case)
            self.__handle_switch_block(
                emu, switch_block, true_case, usable_graph, var_id_no, handled_blocks, localvars.copy(), child_block, None)
            self.__handle_switch_block(
                emu, switch_block, other_case, usable_graph, var_id_no, handled_blocks, localvars.copy(), child_block, None)
        else:
            if len(child_block.get_next()) == 0:
                if self.__debug_print:
                    print('returning from __handle_switch_block because child_block has no next {}'.format(hex(child_block.get_start_offset())))
                return
            # not an if statement
            math_instrs = list()
            found = False
            # this wont work in cases where its a pop etc
            # FIXME: figure out a better way to determine this.
            if initial_child_block:
                if self.__debug_print:
                    print('initial child block = {} {} {}'.format(initial_child_block.is_block_switch(), initial_child_block.is_switch_case(), initial_child_block.is_junk_block()))
                    print('Checking initial child block {} for math instrs'.format(hex(initial_child_block.get_start_offset())))
                for instr in initial_child_block.get_instrs():
                    if instr.get_name().startswith('ldloc'):
                        if instr.get_argument() == var_id_no:
                            found = True
                    if instr.is_branch():
                        break
                    if found:
                        math_instrs.append(instr)
                if not found:
                    if self.__debug_print:
                        print('Checking previous blocks just in case')
                    #check from the initial child block
                    check_block = initial_child_block
                    prev_block = None
                    while True:
                        for instr in check_block.get_instrs():
                            if instr.get_name().startswith('ldloc'):
                                if instr.get_argument() == var_id_no:
                                    found = True
                                    math_instrs.insert(0, instr)
                        if found:
                            #check the previous block if theres only one
                            if prev_block:
                                if len(prev_block.get_instrs()) == 2 or (prev_block.is_block_absolutejmp() and len(prev_block.get_instrs()) == 3):
                                    if prev_block.get_instrs()[0].get_name() == 'ldc.i4':
                                        if prev_block.get_instrs()[1].get_name() == 'dup':
                                            math_instrs.insert(0, prev_block.get_instrs()[0])
                            break
                        if check_block == child_block:
                            break
                        prev_block = check_block
                        check_block = check_block.get_next()[0]

            if not found:
                if self.__debug_print:
                    print('Checking child block {} for math instrs'.format(hex(child_block.get_start_offset())))
                    print('{} {} {} '.format(child_block.is_block_switch(), child_block.is_switch_case(), child_block.is_junk_block()))
                for instr in child_block.get_instrs():
                    if instr.get_name().startswith('ldloc'):
                        if instr.get_argument() == var_id_no:
                            found = True
                    if instr.is_branch():
                        break
                    if found:
                        math_instrs.append(instr)
                """if len(math_instrs) == 0:
                    #check if the last instruction is an ldc.i4.
                    if len(child_block.get_instrs()) >= 2:
                        if len(child_block.get_next()) == 1 and child_block.get_next()[0].is_block_switch():
                            if child_block.get_instrs()[-2].get_name() == 'ldc.i4':
                                math_instrs.append(child_block.get_instrs()[-2])"""
            
            #do the ldloc check on the path.
            
        
            #if it directly leads to another block without a branch, check that block too.
            if self.__debug_print:
                print('Amount of math instrs found after child block check {}'.format(len(math_instrs)))
            if len(math_instrs) == 0:
                ucb: FunctionBlock = child_block
                prev_block: FunctionBlock = ucb
                while len(ucb.get_next()) == 1 and (not ucb.get_last_instr().is_branch() or ucb.is_block_absolutejmp()) and not found:
                    prev_block = ucb
                    ucb = ucb.get_next()[0]
                    for instr in ucb.get_instrs():
                        if instr.get_name().startswith('ldloc'):
                            if instr.get_argument() == var_id_no:
                                found = True
                                #additionally check if the previous block has just math instrs
                                allowed_instrs = ['ldc.i4', 'mul', 'pop', 'br', 'br.s', 'xor', 'nop', 'dup']
                                check_worked = True
                                for instr2 in prev_block.get_instrs():
                                    if instr2.get_name() not in allowed_instrs:
                                        check_worked = False
                                        break
                                if check_worked:
                                    math_instrs.append(prev_block.get_instrs()[0])
                            if instr.is_branch():
                                break
                            if found:
                                math_instrs.append(instr)
            if self.__debug_print:
                print('Amount of math instrs found so far {}'.format(len(math_instrs)))
            if len(math_instrs) == 0:
                # there may be a case where its not based on that variable and is more so based off of a direct number, check that here.
                # FIXME: This is not the greatest solution to this problem, but it might work.
                if initial_child_block == None:
                    path = self.get_shortest_path(
                        child_block.get_start_offset(), switch_block.get_start_offset())
                else:
                    path = self.get_shortest_path(initial_child_block.get_start_offset(), switch_block.get_start_offset())
                last_ldc_instr = None
                if path:
                    for item in path:
                        if item == switch_block:
                            continue
                        for instr in item.get_instrs():
                            if instr.get_name().startswith('ldc.'):
                                last_ldc_instr = instr
                if last_ldc_instr:
                    math_instrs.append(last_ldc_instr)

            if not len(math_instrs):
                raise net_exceptions.InvalidBlockException

            if self.__debug_print:
                print('(handle_switch_block): Running DotNetEmulator from {} to {}'.format(hex(math_instrs[0].offset), hex(switch_block.get_last_instr().offset)))
            new_emu = net_emulator.DotNetEmulator(self.__method_object, start_offset=math_instrs[0].offset,
                                                  end_offset=switch_block.get_last_instr().offset, dont_execute_cctor=True)
            new_emu.locals = localvars
            new_emu.run_function()
            if not len(new_emu.stack) > 0:
                raise net_exceptions.EmulatorFailureException
            value = new_emu.stack.pop()
            if not hasattr(value, 'dtype'):
                raise net_exceptions.EmulatorFailureException
            if value < len(switch_block.get_next()):
                next_block = switch_block.get_next()[value]
            else:
                next_block = switch_block.get_next()[-1]
            index = len(usable_child_block.get_instrs()) - 2
            num_index = 4 + (value * 4)
            instr_offset = switch_block.get_last_instr().get_arguments()[num_index:num_index + 4]
            new_instr1 = net_cil_disas.Instruction(net_opcodes.OpcodeCollection.get_opcode_by_name('nop'), self.__method_object.disassemble_method(),
                                                   offset=usable_child_block.get_last_instr().offset)
            new_instr2 = net_cil_disas.Instruction(net_opcodes.OpcodeCollection.get_opcode_by_name('br'), self.__method_object.disassemble_method(),
                                                   offset=usable_child_block.get_last_instr().offset + len(new_instr1))
            for arg in instr_offset:
                new_instr2.add_argument(arg)
            if usable_child_block.get_last_instr().is_branch():
                usable_child_block.replace_instr(index, new_instr1)
                usable_child_block.replace_instr(index + 1, new_instr2)
            if not usable_child_block.is_block_absolutejmp():
                usable_child_block.clear_original_next()
                if self.__debug_print:
                    print('1: Adding next of {} to {}'.format(hex(next_block.get_start_offset()), hex(usable_child_block.get_start_offset())))
                usable_child_block.add_next(
                    usable_graph.__get_block_for_offset(next_block.get_start_offset()))
            else:
                #This code is probably busted.  Take a look at what it was meant to do.
                actual_block: FunctionBlock = usable_child_block
                switch_path = self.get_shortest_path(0, switch_block.get_start_offset())
                if self.__debug_print:
                    print('Starting at actual block {}'.format(hex(actual_block.get_start_offset())))
                while actual_block.is_block_absolutejmp() and len(actual_block.get_next()) == 1:
                    #ok so what were looking for here is either the that is hit immediately before a switch statement.
                    potential_block = actual_block.get_next()[0]
                    old_block: FunctionBlock = self.__get_block_for_offset(potential_block.get_start_offset())
                    if len(old_block.get_next()) == 1:
                        old_next: FunctionBlock = old_block.get_next()[0]
                        if old_next.is_block_switch():
                            break
                    if potential_block in switch_path:
                        break
                    if self.__debug_print:
                        print('Going to block {}'.format(hex(potential_block.get_start_offset())))
                    actual_block = potential_block
                actual_block.clear_original_next()
                if not actual_block.is_block_return(): #this appears to solve the issue of blocks with returns having children, not sure if this code is causing other issues though.
                    if self.__debug_print:
                        print('2: Adding next of {} to {}'.format(hex(next_block.get_start_offset()), hex(actual_block.get_start_offset())))
                    actual_block.add_next(usable_graph.__get_block_for_offset(next_block.get_start_offset()))

            self.__handle_switch_block(emu, switch_block, next_block, usable_graph, var_id_no, handled_blocks, localvars, child_block, None)
            if self.__debug_print:
                print('Finished handling child block {}'.format(hex(child_block.get_start_offset())))

    def __cleanup_junk_blocks(self):
        #handle root block being junk
        usable_root: FunctionBlock = self.__root_block
        while usable_root.is_junk_block():
            if not len(usable_root.get_next()) == 1:
                raise net_exceptions.InvalidBlockException
            usable_root = usable_root.get_next()[0]
        if usable_root.get_start_offset() != self.__root_block.get_start_offset():
            self.__root_block = usable_root
        block: FunctionBlock
        for block in self.__blocks_start.values():
            #function block relations should be pretty consistent here.  junk blocks should only have ONE next.
            if not block.is_junk_block():
                continue
            if len(block.get_next()) == 1:
                new_next = block.get_next()[0]
                previous_block: FunctionBlock
                for previous_block in block.get_prev().copy():
                    previous_block.replace_next(block, new_next)
                #so block is a junk block, just leads to another one with random crap.
                block.remove_next(new_next)
            elif block.was_switch_block():
                #wipe this block out entirely.
                block.clear_prev()
                block.clear_next()
            elif len(block.get_next()) == 0 and block.is_junk_block():
                pass # yaay our work is somehow already done for us.
            else:
                print(len(block.get_next()), hex(block.get_start_offset()))
                print(block.get_last_instr().get_name())
                for blk in block.get_next():
                    print(hex(blk.get_start_offset()))
                raise Exception() # what do we do here???
        #additionally remove nexts to blocks that are returns.
        for block in self.__blocks_start.values():
            if block.is_junk_block():
                continue
            if block.is_block_return():
                if len(block.get_next()) > 0:
                    block.clear_next()        

    def __is_suspicious_switch(self, block):
        instrs = block.get_instrs()
        if len(instrs) < 6:
            return False
        has_rem = instrs[-2].get_name() == 'rem' or instrs[-2].get_name() == 'rem.un'
        has_args = instrs[-3].get_name().startswith('ldc.i4') and \
            instrs[-3].get_argument() == len(
            instrs[-1].get_argument())
        has_stloc = instrs[-4].get_name().startswith('stloc')
        has_dup = instrs[-5].get_name() == 'dup'
        return has_rem and has_stloc and has_dup and has_args

    def __handle_try_block(self, try_offset, try_length, handler_offset, handler_length):
        self.__parse_block(self.__disasm_object, try_offset, try_offset + try_length, is_try=True)
        self.__parse_block(self.__disasm_object, handler_offset, handler_offset + handler_length, is_catch=True)

    def __handle_finally_block(self, handler_offset, handler_length):
        self.__parse_block(self.__disasm_object, handler_offset, handler_offset + handler_length, False, False, True)

    def __handle_try_catch_finally_blocks(self):
        """
        Ensure that try catch finally blocks are treated as their own blocks.  
        """
        disasm_obj: net_cil_disas.MethodDisassembler = self.__disasm_object

        for clause_flags, try_offset, try_length, handler_offset, handler_length, class_token in disasm_obj.exception_blocks:
            if clause_flags == net_structs.COR_ILEXCEPTION_CLAUSE_EXCEPTION:
                self.__handle_try_block(try_offset, try_length, handler_offset, handler_length)
            elif clause_flags == net_structs.COR_ILEXCEPTION_CLAUSE_FINALLY:
                self.__handle_finally_block(handler_offset, handler_length)
            else:
                raise net_exceptions.OperationNotSupportedException()
 

    def __analyze_switch_statement_internal(self, switch_block: FunctionBlock, starting_block: FunctionBlock, usable_graph, handled_blocks: list):
        """
        Some problems here:
        TODO
        We are assuming that the path to the switch block is direct - that may not be the case.  ConfuserEx may jump around a bit within the switch block
        Current possible solution would be to potentially iterate all possible paths of the function until we hit a switch block that is suspicious - then go through that path to determine the first one.
        It kindof has to be like handle_switch_block works in order to ensure the variables stay consistent - start with a copy of localvars etc etc.
        Solving this issue may be sortof hard, but is definitely needed for it to work.
        """
        # first identify the main source of the initial variable
        def __find_math_instrs(block, path):
            # find the instructions executed to get the math for the initial switch done.
            MATH_INSTRS = ['xor']
            instrs = block.get_instrs()
            math_instr = instrs[-6]
            if math_instr.get_name() not in MATH_INSTRS:
                if self.__debug_print:
                    print('Find math instrs returning none due to invalid operand instr?')
                return None

            result = list()
            USABLE_INSTRS = ['ldc.i4', 'rem.un'] + MATH_INSTRS
            for x in range(len(instrs) - 1, -1, -1):
                instr = instrs[x]
                is_usable = False
                for u_instr in USABLE_INSTRS:
                    if instr.get_name().startswith(u_instr):
                        is_usable = True
                        break
                if is_usable:
                    result.insert(0, instr)

            def __requires_more_instructions(instrs):
                # does the initial math instruction have enough in the block to do its stuff?  Assume theres only one for now.
                # which one do we use?
                amt_ldc = 0
                for instr in instrs:
                    if instr.get_name().startswith('ldc.'):
                        amt_ldc += 1
                    if instr.get_name() == 'pop':
                        amt_ldc -= 1
                    if instr.get_name() == 'dup':
                        amt_ldc += 1
                    if instr.get_name() in MATH_INSTRS:
                        if amt_ldc != 2:
                            return 2 - amt_ldc
                        else:
                            break
                return 0

            req_instrs = __requires_more_instructions(result)
            if req_instrs:
                if self.__debug_print:
                    print('find math instrs requires more instrs')
                block: FunctionBlock
                
                reversed_usable_path = path[:-1][::-1]
                ALLOWED_INSTRS = USABLE_INSTRS + ['dup', 'pop']
                BREAK_INSTRS = ['call', 'callvirt', 'starg.s']
                for block in reversed_usable_path:
                    if block.get_start_offset() == starting_block.get_start_offset():
                        break
                    should_end = False
                    if block.is_block_conditional():
                        break
                    for instr in block.get_instrs()[::-1]:
                        if instr.get_name().startswith('stloc') or instr.get_name() in BREAK_INSTRS:
                            should_end = True
                            break
                        is_allowed = False
                        for allowed_instr in ALLOWED_INSTRS:
                            if instr.get_name().startswith(allowed_instr):
                                is_allowed = True
                        if is_allowed:
                            result.insert(0, instr)
                    if should_end:
                        break


                req_instrs = __requires_more_instructions(result)
                if self.__debug_print:
                    print('requires instrs = {}'.format(req_instrs))
                    print('Initial child block = {} {}'.format(hex(starting_block.get_start_offset()), hex(switch_block.get_start_offset())))
                    print('Result start = {} {} {}'.format(hex(result[0].offset), result[0].get_name(), result[0].get_argument()))
                
                #TODO: revamp math instr getting.  Need to be able to properly account for different variables etc.
                if not req_instrs == 0:
                    raise net_exceptions.InvalidBlockException
            return result

        # Generate a new function graph to modify.
        usable_switch_block: FunctionBlock = usable_graph.__get_block_for_offset(
            switch_block.get_start_offset())
        var_id_no = switch_block.get_instrs()[-4].get_argument()
        if self.__is_suspicious_switch(switch_block):
            block_paths = self.get_paths_to_block(starting_block, switch_block)
            one_path = len(block_paths) == 1
            for path in block_paths:
                #ok so how do we determine which block to add the next at?
                math_instrs = __find_math_instrs(switch_block, path)
                if self.__debug_print:
                    print('(analyze_switch_statement): Handling switch statement {} path {} to {}'.format(hex(switch_block.get_start_offset()), hex(path[0].get_start_offset()), hex(path[-1].get_start_offset())))
                if math_instrs:
                    if self.__debug_print:
                        print('(analyze_switch_statement): Running DotNetEmulator from {} to {}'.format(hex(math_instrs[0].offset), hex(math_instrs[-1].offset + 1)))
                    emu = net_emulator.DotNetEmulator(self.__method_object, start_offset=math_instrs[0].offset,
                                                    end_offset=math_instrs[-1].offset + 1, dont_execute_cctor=True)
                    emu.run_function()
                    if not len(emu.stack) > 0:
                        raise net_exceptions.EmulatorFailureException
                    value = emu.stack.pop()
                    if not hasattr(value, 'dtype'):
                        raise net_exceptions.EmulatorFailureException
                    if value < len(switch_block.get_next()):
                        next_block = switch_block.get_next()[value]
                    else:
                        next_block = switch_block.get_next()[-1]
                    usable_switch_block.mark_switch_block()
                    usable_prev_block = usable_switch_block
                    if not one_path:
                        if self.__debug_print:
                            print('not one path = True {}'.format(hex(math_instrs[0].offset)))
                            for tblock in usable_graph.__blocks_start.values():
                                print('usable graph has block {}'.format(hex(tblock.get_start_offset())))
                        usable_prev_block = usable_graph.__get_block_for_offset(math_instrs[0].offset)
                    #make sure math instrs are cleaned off in usable blocks.
                    for math_instr in math_instrs:
                        math_block: FunctionBlock = usable_graph.__get_block_for_offset(math_instr.offset)
                        if math_block:
                            math_index = math_block.get_instr_index(math_instr)
                            if math_index >= 0:
                                block_len = len(math_block.get_instrs())
                                should_remove = False

                                if math_index == (block_len - 1):
                                    should_remove = True

                                if math_index == (block_len - 2) and (math_block.get_last_instr().is_branch() or math_block.is_block_absolutejmp()):
                                    should_remove = True

                                if should_remove:
                                    if math_index != 0:
                                        math_block.remove_instrs_after_index(math_index - 1)
                                
                        

                    usable_prev_block.clear_original_next()
                    if self.__debug_print:
                        print('3: Adding next of {} to {}'.format(hex(next_block.get_start_offset()), hex(usable_prev_block.get_start_offset())))
                    usable_prev_block.add_next(
                        usable_graph.__get_block_for_offset(next_block.get_start_offset()))
                    # remove the switch, replace with jmp - for graphing purposes mostly.
                    index = len(usable_switch_block.get_instrs()) - 1
                    num_index = 4 + (value * 4)
                    instr_offset = switch_block.get_last_instr().get_arguments()[num_index:num_index + 4]
                    new_instr1 = net_cil_disas.Instruction(net_opcodes.OpcodeCollection.get_opcode_by_name('nop'), self.__method_object.disassemble_method(),
                                                        offset=switch_block.get_last_instr().offset)
                    new_instr2 = net_cil_disas.Instruction(net_opcodes.OpcodeCollection.get_opcode_by_name('br'), self.__method_object.disassemble_method(),
                                                        offset=switch_block.get_last_instr().offset + len(new_instr1))
                    for arg in instr_offset:
                        new_instr2.add_argument(arg)
                    usable_switch_block.replace_instr(index - 1, new_instr1)
                    usable_switch_block.replace_instr(index, new_instr2)
                    usable_switch_block.mark_junk()
                    # figure out noping math instrs later, for now pop the value off the stack.
                    self.__handle_switch_block(emu, switch_block, next_block, usable_graph, var_id_no, handled_blocks, emu.locals.copy(), None, None)
                    usable_block: FunctionBlock
                    for usable_block in usable_graph.__blocks_start.values():
                        if usable_block.is_junk_block():
                            continue
                        if usable_block.is_switch_case():
                            if len(usable_block.get_instrs()) == 1:
                                if usable_block.get_instrs()[0].get_name() == 'ldc.i4':
                                    usable_block.mark_junk()
                        elif len(usable_block.get_instrs()) == 2:
                            instr1 = usable_block.get_instrs()[0]
                            instr2 = usable_block.get_instrs()[1]
                            if instr1.get_name() == 'nop' or instr1.get_name() == 'pop':
                                if instr2.get_name() == 'br.s' or instr2.get_name() == 'br':
                                    usable_block.mark_junk()
                        elif len(usable_block.get_instrs()) == 3:
                            instr1 = usable_block.get_instrs()[0]
                            instr2 = usable_block.get_instrs()[1]
                            instr3 = usable_block.get_instrs()[2]
                            if instr1.get_name() == 'ldc.i4' and (instr2.get_name() == 'nop' or instr2.get_name() == 'dup'):
                                if instr3.get_name() == 'br.s' or instr3.get_name() == 'br':
                                    usable_block.mark_junk()

                        if not usable_block.is_junk_block():
                            instrs = usable_block.get_instrs()

                            for x in range(1, len(instrs)):
                                instr = instrs[x]
                                if instr.get_name().startswith('ldloc') and instr.get_argument() == var_id_no:
                                    usable_block.remove_instrs_after_index(x - 1)
                                    break
                            if len(instrs) == 2:
                                if instrs[0].get_name() == 'ldc.i4' and instrs[1].get_name() == 'dup':
                                    if len(usable_block.get_next()) == 1 and usable_block.get_next()[0].is_switch_case():
                                        usable_block.mark_junk()
                            elif len(instrs) == 1:
                                if instrs[0].get_name() == 'ldc.i4':
                                    if len(usable_block.get_next()) == 1 and usable_block.get_next()[0].is_switch_case():
                                        usable_block.mark_junk()
                            elif len(instrs) == 3:
                                if instrs[0].get_name() == 'ldc.i4' and instrs[1].get_name() == 'dup':
                                    if instrs[2].get_name() == 'br' or instrs[2].get_name() == 'br.s':
                                        if len(usable_block.get_next()) == 1 and usable_block.get_next()[0].is_switch_case():
                                            usable_block.mark_junk()

                    for usable_block in usable_graph.__blocks_start.values():
                        if usable_block.is_junk_block():
                            continue
                        if len(usable_block.get_prev()) == 1:
                            if usable_block.get_prev()[0].is_junk_block():
                                if len(usable_block.get_instrs()) == 1 and usable_block.get_instrs()[0].get_name() == 'pop':
                                    usable_block.mark_junk()
            return usable_graph
        return None
    
    def get_shortest_path(self, from_offset, to_offset):
        if isinstance(to_offset, FunctionBlock) and isinstance(from_offset, FunctionBlock):
            to_block = to_offset
            from_block = from_offset
        else:
            to_block = self.__get_block_for_offset(to_offset)
            from_block = self.__get_block_for_offset(from_offset)
        if to_block == None or from_block == None:
            raise net_exceptions.InvalidBlockException

        explored = []
        queue = [[from_block]]
        if to_block.get_start_offset() == from_block.get_start_offset():
            return [from_block]

        while queue:
            path = queue.pop(0)
            node = path[-1]
            if node not in explored:
                neighbours = node.get_next()
                for neighbor in neighbours:
                    new_path = list(path)
                    new_path.append(neighbor)
                    queue.append(new_path)

                    if neighbor.get_start_offset() == to_block.get_start_offset():
                        return new_path
                explored.append(node)

        return None

    def get_paths_to_block(self, to_offset, from_offset):
        to_block = to_offset
        from_block = from_offset
        if not isinstance(to_block, FunctionBlock) or not isinstance(from_block, FunctionBlock):
            to_block = self.__get_block_for_offset(to_block)
            from_block = self.__get_block_for_offset(from_block)
        def path_checker(one: FunctionBlock, two: FunctionBlock, current_path, paths, visited):
            if one == two:
                paths.append(current_path)
                return
            
            if len(one.get_next()) == 0 or one.is_block_return():
                return
            
            if one.get_start_offset() in visited:
                return
            
            visited.append(one.get_start_offset())
            
            nxt: FunctionBlock
            for nxt in one.get_next():
                if nxt == two:
                    paths.append(current_path + [nxt])
                else:
                    path_checker(nxt, two, current_path + [nxt], paths, visited.copy())

        paths = list()
        visited = list()
        path_checker(to_block, from_block, [to_block], paths, visited)
        return paths

    def __analyze_switch_statements(self):
        usable_graph = FunctionGraph(self.__method_object)
        if self.__debug_print:
            print('Before analyze graph:\n')
            usable_graph.print_root()

        handled_blocks = list()
        for block in self.__blocks_start.values():
            if self.__debug_print:
                print('Checking block {} {}'.format(hex(block.get_start_offset()), hex(block.get_last_instr().offset)))
            if block.contains_instr('switch'):
                if self.__debug_print:
                    print('block contains switch')
                #for now start at block zero, this will need to be changed to support multiple switch statements.
                if self.__debug_print:
                    print('3: calling analyze_switch_statement_internal with switch block {} and starting block 0x0'.format(hex(block.get_start_offset())))

                res = self.__analyze_switch_statement_internal(block, self.__get_block_for_offset(0), usable_graph, handled_blocks)
                if self.__debug_print:
                    print('Dumping usable graph before cleanup:\n')
                    usable_graph.print_root()

                if res != None:
                    usable_graph.__cleanup_junk_blocks()

                if self.__debug_print:
                    print('Dumping usable graph post cleanup:\n')
                    usable_graph.print_root()
                if res != None:
                    return usable_graph
        return None

    def __parse_block(self, disasm_obj, start_offset, max_end_offset=-1, is_try=False, is_catch=False, is_finally=False):
        usable_offset = start_offset
        x = disasm_obj.get_instr_index_by_offset(start_offset)
        print('parsing block with offset {}'.format(hex(start_offset)))
        block = FunctionBlock(self.__method_object, disasm_obj, self.__graph_id)
        if start_offset in self.__blocks_start:
            blk =  self.__blocks_start[start_offset]
            return blk
        else:
            self.__blocks_start[start_offset] = block

        if is_finally:
            block.mark_block_finally()

        if is_catch:
            block.mark_block_catch()

        if is_try:
            block.mark_block_try()

        while x >= 0 and x < len(disasm_obj):
            if usable_offset in self.__blocks_start and usable_offset != start_offset:
                new_block = self.__blocks_start[usable_offset]
                if not block.has_next(new_block):
                    block.add_original_next(new_block)
                break
            if max_end_offset != -1 and usable_offset >= max_end_offset:
                break
            instr = disasm_obj[x]
            block.add_instr(instr)
            if instr.is_branch():
                #leave br and br.s are treated as absolute jumps since they basically are.
                if instr.get_name() == 'br' or instr.get_name() == 'br.s' or instr.get_name() == 'leave' or instr.get_name() == 'leave.s':
                    potential_offset = usable_offset + \
                        len(instr) + instr.get_argument()
                    split_block = self.__should_split_block(potential_offset)
                    if split_block == None:
                        new_block = self.__parse_block(
                            disasm_obj, potential_offset, max_end_offset=max_end_offset, is_try=is_try, is_catch=is_catch, is_finally=is_finally)
                        usable_block = self.__get_block_for_offset(
                            usable_offset)
                        if new_block is None:
                            raise net_exceptions.InvalidBlockException
                        usable_block.add_original_next(new_block)
                    else:
                        new_block = split_block.split_block(potential_offset)
                        self.__blocks_start[new_block.get_start_offset(
                        )] = new_block
                        block.add_original_next(new_block)
                else:
                    if instr.get_name() == 'switch':
                        targets = instr.get_argument()
                        for target in targets:
                            split_block = self.__should_split_block(target)
                            if split_block == None:
                                new_block = self.__parse_block(
                                    disasm_obj, target, max_end_offset, is_try, is_catch, is_finally)
                                usable_block = self.__get_block_for_offset(
                                    usable_offset)
                                usable_block.add_original_next(new_block)
                                new_block.mark_switch_case()
                            else:
                                new_block = split_block.split_block(target)
                                self.__blocks_start[new_block.get_start_offset(
                                )] = new_block
                                usable_block = self.__get_block_for_offset(
                                    instr.offset)
                                usable_block.add_original_next(new_block)
                                new_block.mark_switch_case()

                        fallthrough_offset = instr.offset + len(instr)
                        split_block = self.__should_split_block(fallthrough_offset)
                        if split_block == None:
                            new_block = self.__parse_block(
                                disasm_obj, fallthrough_offset, max_end_offset, is_try, is_catch, is_finally)
                            usable_block = self.__get_block_for_offset(
                                usable_offset)
                            usable_block.add_original_next(new_block)
                            new_block.mark_switch_case()
                        else:
                            new_block = split_block.split_block(fallthrough_offset)
                            self.__blocks_start[new_block.get_start_offset(
                            )] = new_block
                            usable_block = self.__get_block_for_offset(
                                instr.offset)
                            usable_block.add_original_next(new_block)
                            new_block.mark_switch_case()

                    else:
                        #this block of code is to handle conditional branches.
                        potential_offset1 = usable_offset + \
                            len(instr) + instr.get_argument()
                        potential_offset2 = usable_offset + len(instr)
                        split_block = self.__should_split_block(
                            potential_offset1)
                        if split_block == None:
                            new_block = self.__parse_block(
                                disasm_obj, potential_offset1, max_end_offset, is_try, is_catch, is_finally)
                            usable_block = self.__get_block_for_offset(
                                usable_offset)
                            usable_block.add_original_next(new_block)
                        else:
                            new_block = split_block.split_block(
                                potential_offset1)
                            self.__blocks_start[new_block.get_start_offset(
                            )] = new_block
                            usable_block = self.__get_block_for_offset(
                                instr.offset)
                            usable_block.add_original_next(new_block)
                        split_block = self.__should_split_block(
                            potential_offset2)
                        if split_block == None:
                            new_block = self.__parse_block(
                                disasm_obj, potential_offset2, max_end_offset, is_try, is_catch, is_finally)
                            usable_block = self.__should_split_block(
                                usable_offset)
                            usable_block.add_original_next(new_block)
                        else:
                            new_block = split_block.split_block(
                                potential_offset2)
                            self.__blocks_start[new_block.get_start_offset(
                            )] = new_block
                            usable_block = self.__get_block_for_offset(
                                instr.offset)
                            usable_block.add_original_next(new_block)
                break

            usable_offset += len(instr)

            if instr.get_name() == 'ret':
                break

            if instr.is_branch() and instr.get_name() != 'br.s' and instr.get_name() != 'br' and instr.get_name() != 'leave' and instr.get_name() != 'leave.s':
                break

            x = disasm_obj.get_instr_index_by_offset(usable_offset)
        #block.validate_block()
        if block is None:
            raise net_exceptions.InvalidBlockException

        return block

    def print_root(self):
        dont_print_again = list()
        self.__print_block(self.__root_block, dont_print_again)

    def debug_print_nexts(self):
        block: FunctionBlock
        print('Debug printing blocks')
        for block in self.__blocks_start.values():
            print('Block {} is_junk={} is_switch_case={}'.format(hex(block.get_start_offset()), block.is_junk_block(), block.is_switch_case()))
            nxt: FunctionBlock
            for nxt in block.get_next():
                print('Next: {}'.format(hex(nxt.get_start_offset())))

    def get_block_offsets(self):
        return self.__blocks_start

    def __print_block(self, block, already_printed):

        instrs = block.get_instrs()
        if block.get_start_offset() not in already_printed:
            print('Printing block with offset {} (is junk: {}, is switch case: {}, is_try: {}, is_catch: {}, is_finally: {})'.format(
                hex(block.get_start_offset()), block.is_junk_block(), block.is_switch_case(), block.is_block_try(), block.is_block_catch(), block.is_block_finally()))
            already_printed.append(block.get_start_offset())
            for instr in block.get_instrs():
                if instr.is_branch() and not instr.is_absolute_jmp():
                    break
                if instr.is_absolute_jmp():
                    print('{}: jump to {}'.format(hex(instr.offset),
                                                  hex(instr.offset + len(instr) + instr.get_argument())))
                else:
                    print('{}: {} {}'.format(hex(instr.offset), instr.get_name(),
                                             instr.get_argument()))

            if instrs[-1].get_name() == 'switch':
                print('switch ({}):'.format(hex(instrs[-1].offset)))
                x = 0
                for case in instrs[-1].get_argument():
                    print('case {}: ({}:{})'.format(x, hex(case), hex(instrs[-1].offset)))
                    self.__print_block(block.get_next()[x], already_printed)
                    x += 1
                fallthrough = block.get_next()[-1]
                print('default({}:{}):'.format(hex(fallthrough.get_start_offset()), hex(instrs[-1].offset)))
                self.__print_block(fallthrough, already_printed)

            else:
                if instrs[-1].is_branch() and not instrs[-1].is_absolute_jmp():
                    print('if ({}): {} {}'.format(hex(instrs[-1].offset), instrs[-1].get_name(),instrs[-1].get_argument()))
                    self.__print_block(block.get_next()[0], already_printed)
                    print('else ({}):'.format(hex(instrs[-1].offset)))
                    if len(block.get_next()) == 1:
                        print('Error: No secondary block!!!!')
                    else:
                        self.__print_block(block.get_next()[1], already_printed)
                else:
                    if not instrs[-1].is_branch() and len(block.get_next()) == 1:
                        self.__print_block(
                            block.get_next()[0], already_printed)
                    elif instrs[-1].is_absolute_jmp() and instrs[-1].is_branch():
                        self.__print_block(block.get_next()[0], already_printed)
        else:
            print('goto block {}'.format(hex(block.get_start_offset())))

class GraphRecompiler:
    def __init__(self, method_obj: net_row_objects.MethodDef, func_graph: FunctionGraph):
        self.__method_obj: net_row_objects.MethodDef = method_obj
        self.__func_graph: FunctionGraph = func_graph
        self.__function_data = bytearray()
        self.__block_locations = dict()

    def __convert_small_instructions(self, opcode):
        #for usability sake, convert a small instruction to its large counterpart.  For example, blt.s -> blt.
        match opcode:
            case 0x2E:
                return 0x3B
            case 0x2F:
                return 0x3C
            case 0x34:
                return 0x41
            case 0x30:
                return 0x3D
            case 0x35:
                return 0x42
            case 0x31:
                return 0x3E
            case 0x36:
                return 0x43
            case 0x32:
                return 0x3F
            case 0x37:
                return 0x44
            case 0x33:
                return 0x40
            case 0x2B:
                return 0x38
            case 0x2C:
                return 0x39
            case 0x2D:
                return 0x3A
        return opcode

    def __compile_block(self, block:FunctionBlock):
        if block in self.__block_locations:
            return
        current_offset = len(self.__function_data)
        self.__block_locations[block] = current_offset
        instrs = block.get_instrs()
        last_instr_index = len(instrs) - 1
        for x in range(len(instrs)):
            instr = instrs[x]
            if x == last_instr_index:
                if instr.is_branch():
                    if block.is_block_absolutejmp():
                        #if the block is absolute jump it means this instr is br or br.s
                        #two options here: either we already compiled the block and need a new br instruction, or we havent and we can compile it without this br instr.
                        if not len(block.get_next()) == 1:
                            raise net_exceptions.InvalidBlockException
                        next_block = block.get_next()[0]
                        if next_block in self.__block_locations:
                            #we need a new BR to jump to it probably
                            block_offset = self.__block_locations[next_block]
                            if block_offset != len(self.__function_data): #TODO: This probably wont ever be false.
                                br_offset = len(self.__function_data)
                                new_br_offset = block_offset - br_offset - 5
                                br_instr = bytearray(bytes([0x38]) + int.to_bytes(new_br_offset, 4, 'little', signed=True))
                                self.__function_data += br_instr
                        else:
                            #just compile the block right after
                            self.__compile_block(next_block)
                    elif block.is_block_switch():
                        raise Exception("switch statements are not currently supported.") #TODO: add support for actual legitimate switch statements.
                    elif block.is_block_conditional():
                        if not len(block.get_next()) == 2:
                            raise net_exceptions.InvalidBlockException
                        instr_offset = len(self.__function_data) # offset of the placeholder.
                        true_case = block.get_next()[0] # This should be the jump case
                        false_case = block.get_next()[1] #this should be fallthrough.
                        #first check if the fallthrough case has been compiled - reserve enough bytes for the conditional instruction and then compile it if it hasnt already.
                        if false_case not in self.__block_locations:
                            #we need to compile the false case.  add the placeholder
                            placeholder = b'\x00' * 5
                            self.__function_data += placeholder
                            self.__compile_block(false_case)
                        else:
                            placeholder = b'\x00' * 5
                            self.__function_data += placeholder
                            block_offset = self.__block_locations[false_case]
                            if block_offset != len(self.__function_data): #TODO: This probably wont ever be false.
                                br_offset = len(self.__function_data)
                                new_br_offset = block_offset - br_offset - 5
                                br_instr = bytearray(bytes([0x38]) + int.to_bytes(new_br_offset, 4, 'little', signed=True))
                                self.__function_data += br_instr
                        #now for the true case and replacing the placeholder.
                        if true_case in self.__block_locations:
                            block_offset = self.__block_locations[true_case]
                            if block_offset != instr_offset: #TODO: This probably wont ever be false.
                                br_offset = instr_offset
                                new_br_offset = block_offset - br_offset - 5
                                br_instr = bytearray(bytes([self.__convert_small_instructions(instr.get_opcode().value)]) + int.to_bytes(new_br_offset, 4, 'little', signed=True))
                                self.__function_data = self.__function_data[:instr_offset] + br_instr + self.__function_data[instr_offset + len(placeholder):] # remove the placeholder.

                        else:
                            #its not compiled.  compile it and then remove the placeholder.
                            compilation_offset = len(self.__function_data)
                            self.__compile_block(true_case)
                            br_offset = instr_offset
                            new_br_offset = compilation_offset - br_offset - 5
                            if not isinstance(instr.get_opcode().value, int):
                                raise net_exceptions.InvalidBlockException
                            br_instr = bytearray(bytes([self.__convert_small_instructions(instr.get_opcode().value)]) + int.to_bytes(new_br_offset, 4, 'little', signed=True))
                            self.__function_data = self.__function_data[:instr_offset] + br_instr + self.__function_data[instr_offset + len(placeholder):] # again remove the placeholder
                    else:
                        raise net_exceptions.InvalidAssemblyException()
                else:
                    self.__function_data += instr.to_bytes()
                    #check if the block was already compiled, if so add a BR
                    if len(block.get_next()) > 0:
                        if not len(block.get_next()) == 1:
                            raise net_exceptions.InvalidBlockException
                        next_block = block.get_next()[0]
                        if next_block in self.__block_locations:
                            #add a br to the start of the block.
                            block_offset = self.__block_locations[next_block]
                            if block_offset != len(self.__function_data):
                                br_offset = len(self.__function_data)
                                new_br_offset = block_offset - br_offset - 5
                                br_instr = bytearray(bytes([0x38]) + int.to_bytes(new_br_offset, 4, 'little', signed=True))
                                self.__function_data += br_instr
                        else:
                            self.__compile_block(next_block)
            else:
                self.__function_data += instr.to_bytes()
    
    
    def recompile_graph(self):
        disasm_obj: net_cil_disas.MethodDisassembler = self.__method_obj.disassemble_method()
        header_bytes = self.__method_obj.get_method_data()[:disasm_obj.header_size]
        #now we have the original header.  only thing we should need to change is the size.
        #compile
        self.__compile_block(self.__func_graph.get_root_block())
        #check the header to make sure we dont need to update size
        header_ident = header_bytes[0]
        val = header_ident & 7
        if val == 2 or val == 6:
            code_size = header_ident >> 2 # ok so if we right shift by 2 bits that gives us the method code meaning lower 2 bits are flags
        
            if code_size != len(self.__function_data):
                pass
            raise Exception("tiny headers are not currently supported.") # TODO: add tiny header support.
        else:
            header_bytes = header_bytes[:4] + int.to_bytes(len(self.__function_data), 4, 'little') + header_bytes[8:]
        return header_bytes + self.__function_data
    
    def get_function_data(self):
        return self.__function_data