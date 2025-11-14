from dotnetutils import net_cil_disas, net_emulator, net_cil_disas, net_structs, net_opcodes, net_row_objects, net_exceptions, net_emu_types
from dotnetutils.net_opcodes import Opcodes

"""
This file is meant to eventually be a grapher and maybe a recompiler + analyzer for method code.
Currently the graphing functionality actually works pretty well.
So far using the graphing functionality I managed to implement a max stack size calculator, which is used for patching methods
Additionally, I was able to implement a math instruction compressor - useful for studying Babel.NET.
Currently working out some of the issues with instruction patching, control flow deobfuscation and stuff so this file isnt really ready for use.
This file will be cythonized once complete.  Its also possible that I may split up the classes into separate files.
Methods and such may change within this file as I continue working on it.
"""

class FunctionBlock:
    def __init__(self, method_object, disasm_object, graph):
        """ Setup a new FunctionBlock
        
        Args:
            method_object (net_row_object.MethodDef): The method object the block belongs to.
            disasm_object (net_row_objects.MethodDisassembler): The disassembler object associated with the method (can be None for patching.)
            graph: (FunctionGraph): The graph associated with the block.
        """
        self.__method_object = method_object
        self.__disasm_object = disasm_object
        self.__graph = graph
        self.__instrs = list()
        self.__previous = list()
        self.__next = list()
        self.__start_offset = -1
        self.__start_index = -1
        self.__original_length = 0
        self.__was_cleared = False
        self.__original_cleared = False
        self.__is_junk_block = False
        self.__is_switch_case = False
        self.__was_switch_block = False
        self.__is_block_finished = False
        self.__is_block_try = False
        self.__is_block_catch = False
        self.__is_block_finally = False
        self.__is_block_filter = False
        self.__try_block_offset = -1
        self.__catch_block_offset = -1
        self.__finally_block_offset = -1
        self.__filter_block_offset = -1
        self.__exception_handler = None
        self.__new_offset = -1
        self.__new_index = -1

    def get_start_index(self):
        """ Obtain the index of the first instruction within the block relative to index 0 of the method.

        Returns:
            unsigned int: The start index of the block
        """
        return self.__start_index
    
    def update_start_offset(self, start_offset, start_index):
        """ Updates the stored offset and index for the block.

        Args:
            start_offset (unsigned int): The new start offset.
            start_index (unsigned int): The new start index.
        """
        self.__start_offset = start_offset
        self.__start_index = start_index

    def setup_new_block_location(self, new_offset, new_index):
        """ Updates the stored new offset and index for the block.
        
            Likely to be removed.

        Args:
            start_offset (unsigned int): The new start offset.
            start_index (unsigned int): The new start index.
        """
        self.__new_offset = new_offset
        self.__new_index = new_index

    def update_size(self, new_size):
        """ Update the stored byte size of the block.

        Args:
            new_size (unsigned int): The new byte size of the block.
        """
        self.__original_length = new_size 

    def get_new_offset(self):
        """ Obtains the stored value for the new offset after changes.
            Likely to be removed.
        
        Returns:
            unsigned int: The stored value for the new offset after changes.
        """
        return self.__new_offset
    
    def get_new_index(self):
        """ Obtains the stored value for the new index after changes.
            Likely to be removed.
        
        Returns:
            unsigned int: The stored value for the new index after changes.
        """
        return self.__new_index

    def get_exception_handler(self):
        """ Obtains a single exception handler associated with a block.
            see net_cil_disas for result format.
        
        Returns:
            list: An exception handler associated with the block.
        """
        return self.__exception_handler
    
    def set_exception_handler(self, exception_handler):
        """ Sets the block's exception handler.

        Args:
            exception_handler (list): The exception handler to set.
        """
        self.__exception_handler = exception_handler

    def set_filter_block_offset(self, offset):
        """ Sets the offset of the filter handler associated with the block.

        Args:
            offset (unsigned int): The offset of a filter clause holding the block.
        """
        self.__filter_block_offset = offset

    def set_try_block_offset(self, offset):
        """ Sets the offset of the try handler associated with the block.

        Args:
            offset (unsigned int): The offset of a try clause holding the block.
        """
        self.__try_block_offset = offset

    def set_catch_block_offset(self, offset):
        """ Sets the offset of the catch handler associated with the block.

        Args:
            offset (unsigned int): The offset of a catch clause holding the block.
        """
        self.__catch_block_offset = offset

    def set_finally_block_offset(self, offset):
        """ Sets the offset of the finally handler associated with the block.

        Args:
            offset (unsigned int): The offset of a finally clause holding the block.
        """
        self.__finally_block_offset = offset

    def get_try_block_offset(self):
        return self.__try_block_offset
    
    def get_catch_block_offset(self):
        return self.__catch_block_offset
    
    def get_finally_block_offset(self):
        return self.__finally_block_offset
    
    def get_filter_block_offset(self):
        return self.__filter_block_offset

    def mark_block_try(self):
        self.__is_block_try = True

    def mark_block_catch(self):
        self.__is_block_catch = True

    def mark_block_finally(self):
        self.__is_block_finally = True

    def mark_block_filter(self):
        self.__is_block_filter = True

    def is_block_try(self):
        return self.__is_block_try
    
    def is_block_catch(self):
        return self.__is_block_catch
    
    def is_block_finally(self):
        return self.__is_block_finally
    
    def is_block_filter(self):
        return self.__is_block_filter

    def mark_block_finished(self):
        self.__is_block_finished = True

    def mark_switch_block(self):
        self.__was_switch_block = True

    def was_switch_block(self):
        return self.__was_switch_block

    def is_block_return(self):
        return self.get_last_instr().get_opcode() == Opcodes.Ret

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
            if pt_instr.get_instr_offset() == instr.get_instr_offset():
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
        self.__instrs[index] = new_instr

    def insert_instr(self, index, instr):
        self.__instrs.insert(index, instr)

    def is_block_conditional(self):
        instr = self.get_last_instr()
        if not self.is_block_absolutejmp():
            if instr.get_opcode() != Opcodes.Switch:
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


    def clear_next_once(self):
        if not self.__was_cleared:
            self.__was_cleared = True
            self.clear_next()

    def is_block_switch(self):
        return self.get_last_instr().get_opcode() == Opcodes.Switch

    def is_block_absolutejmp(self):
        instr = self.get_last_instr()
        opcode = instr.get_opcode()
        return opcode == Opcodes.Br or opcode == Opcodes.Br_S or opcode == Opcodes.Leave or opcode == Opcodes.Leave_S
    
    def is_block_direct(self):
        return not self.is_block_absolutejmp() and not self.is_block_conditional() and not self.get_last_instr().is_branch() and len(self.get_next()) == 1
    
    def add_instr(self, instr):
        self.__instrs.append(instr)
        if self.__start_offset == -1:
            self.__start_offset = instr.get_instr_offset()
            self.__start_index = instr.get_instr_index()

        self.__original_length += len(instr)

    def remove_instrs_after_index(self, index):
        self.__instrs = self.__instrs[:index + 1]

    def replace_instr(self, index, instr):
        self.__instrs[index] = instr
    
    def remove_instrs(self, start, end):
        if not 0 <= start < len(self.__instrs) or not 0 <= end <= len(self.__instrs) or start > end:
            raise net_exceptions.InvalidArgumentsException()
        del self.__instrs[start:end]

    def insert_instr(self, index, instr):
        self.__instrs.insert(index, instr)

    def get_instrs(self):
        return self.__instrs

    def get_start_offset(self):
        return self.__start_offset

    def get_last_instruction(self):
        return self.get_instrs()[-1]

    def has_prev(self, block):
        return block in self.__previous

    def add_next(self, block):
        if not self.has_next(block):
            if block and not self.has_next(block):
                self.__next.append(block)
            if block and not block.has_prev(self):
                block.__previous.append(self)

    def has_next(self, block):
        return block in self.__next

    def get_next(self):
        if self.get_last_instr().get_opcode() == Opcodes.Switch:
            result = list()
            instr = self.get_last_instr()
            for target in instr.get_argument():
                result.append(self.__graph.get_block_by_offset(target))
            result.append(self.__graph.get_block_by_offset(instr.get_instr_offset() + len(instr)))
            return result
        return self.__next

    def get_prev(self):
        return self.__previous
    
    def remove_prev(self, prev):
        prev.__next.remove(self)
        self.__previous.remove(prev)

    def get_last_instr(self):
        if len(self.__instrs) == 0:
            return None
        return self.get_instrs()[-1]

    def has_offset(self, offset):
        if self.__is_block_finished:
            if self.__start_offset <= offset < (self.__start_offset + self.__original_length):
                return True
        for instr in self.get_instrs():
            if instr.get_instr_offset() == offset:
                return True
        return False
    
    def merge_block(self, block):
        #merge a block with another.
        last_instr = self.get_last_instr()
        if last_instr is None:
            last_instr_offset = self.__start_offset
            last_instr_size = 0
            last_instr_index = 0
        else:
            last_instr_offset = last_instr.get_instr_offset()
            last_instr_size = len(last_instr)
            last_instr_index = last_instr.get_instr_index()
            
        new_offset = last_instr_offset + last_instr_size
        new_index = last_instr_index
        new_length = self.get_original_length()
        for instr in block.get_next():
            instr.setup_instr_offset(new_offset, new_index)
            new_offset += len(instr)
            new_index += 1
            new_length += len(instr)
        self.__original_length = new_length

    def validate_block(self):
        last_instr = self.get_last_instr()
        opcode = last_instr.get_opcode()
        if not last_instr.is_branch():
            if opcode == Opcodes.Ret:
                if not len(self.__next) == 0:
                    raise net_exceptions.InvalidBlockException
            else:
                if opcode == Opcodes.Throw or opcode == Opcodes.Endfinally:
                    #TODO: I think this is correct for endfinally since it doesnt really have a hard transfer, thats handled internally.
                    if len(self.__next) != 0:
                        raise net_exceptions.InvalidBlockException
                else:
                    if len(self.__next) != 1:
                        raise net_exceptions.InvalidBlockException
        else:
            if opcode == Opcodes.Switch:
                amt_of_unique_targets = 0
                already_counted = list()
                for target in last_instr.get_argument():
                    if target not in already_counted:
                        amt_of_unique_targets += 1
                        already_counted.append(target)
                fallthrough_target = last_instr.get_instr_offset() + len(last_instr)
                if fallthrough_target not in already_counted:
                    amt_of_unique_targets += 1
                if len(self.__next) != amt_of_unique_targets:
                    raise net_exceptions.InvalidBlockException
            elif opcode == Opcodes.Br_S or opcode == Opcodes.Br or opcode == Opcodes.Leave or opcode == Opcodes.Leave_S:
                if len(self.__next) != 1:
                    raise net_exceptions.InvalidBlockException
            else:
                if len(self.__next) != 2:
                    raise net_exceptions.InvalidBlockException

    def split_block(self, split_offset):
        new_instrs = list()
        split_instrs = list()
        start_splitting = False
        new_size = 0
        for instr in self.__instrs:
            if instr.get_instr_offset() == split_offset:
                start_splitting = True
            if not start_splitting:
                new_size += len(instr)
                new_instrs.append(instr)
            else:
                split_instrs.append(instr)

        self.__instrs = new_instrs
        self.__original_length = new_size

        new_block = FunctionBlock(self.__method_object, self.__disasm_object, self.__graph)
        if self.__is_block_try:
            new_block.mark_block_try()
        
        if self.__is_block_catch:
            new_block.mark_block_catch()

        if self.__is_block_finally:
            new_block.mark_block_finally()
        
        if self.__is_block_filter:
            new_block.mark_block_filter()
    
        new_block.set_exception_handler(self.get_exception_handler())
        
        for instr in split_instrs:
            new_block.add_instr(instr)

        new_next = self.__next.copy()
        for next in self.__next:
            self.remove_next(next)

        for next in new_next:
            new_block.add_next(next)
        self.__next = list()
        self.add_next(new_block)
        return new_block

    def remove_next(self, block):
        if self.has_next(block):
            self.__next.remove(block)
            block.__previous.remove(self)

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

    def get_nstack(self):
        result = 0
        for instr in self.get_instrs():
            result += instr.get_nstack()
        return result

    def __str__(self):
        return 'Block at offset {}'.format(hex(self.get_start_offset()))

    def __eq__(self, other):
        return isinstance(other, FunctionBlock) and self.get_start_offset() == other.get_start_offset()
    
class FunctionGraph:
    def __init__(self, method_object, force_instrs=None, force_exc_blocks=None, init_blocks=True, debug_print=False):
        self.__method_object = method_object
        self.__debug_print = debug_print
        self.__disasm_object = None
        self.__instr_offsets = dict()
        self.__instrs = list()
        self.__blocks_start = dict()

        if force_instrs is None:
            if init_blocks:
                if not self.__method_object.has_body():
                    raise net_exceptions.InvalidBlockException
                self.__disasm_object = method_object.disassemble_method()
                self.__exception_blocks = self.__disasm_object.get_exception_blocks()
                self.__instrs = self.__disasm_object.get_list_of_instrs()
                for instr in self.__instrs:
                    self.__instr_offsets[instr.get_instr_offset()] = instr
                self.__handle_try_catch_finally_blocks() # first handle try catch finally since thats a special case.
                self.__sort_blocks()
                if 0 not in self.__blocks_start:
                    self.__root_block = self.__parse_block(0)
                else:
                    self.__root_block = self.__blocks_start[0]

                self.__sort_blocks()

                for block in self.__blocks_start.values():
                    block.mark_block_finished() #Tell each block that we are done with our initial setup, anything else is a modification.
            else:
                self.__disasm_object = method_object.disassemble_method()
        else:
            if force_exc_blocks is None:
                raise net_exceptions.InvalidArgumentsException()
            self.__exception_blocks = force_exc_blocks
            self.__instrs = force_instrs
            for instr in self.__instrs:
                self.__instr_offsets[instr.get_instr_offset()] = instr
            self.__handle_try_catch_finally_blocks() # first handle try catch finally since thats a special case.
            self.__sort_blocks()
            if 0 not in self.__blocks_start:
                self.__root_block = self.__parse_block(0)
            else:
                self.__root_block = self.__blocks_start[0]

            self.__sort_blocks()

            for block in self.__blocks_start.values():
                block.mark_block_finished() #Tell each block that we are done with our initial setup, anything else is a modification.

        if self.__disasm_object is None:
            self.__exception_blocks = list()
    
    def register_block(self, offset, block):
        self.__blocks_start[offset] = block

    def update_exception_blocks(self, blocks):
        self.__exception_blocks = blocks
    
    def get_exception_blocks(self):
        return self.__exception_blocks

    def get_disassembler(self):
        return self.__disasm_object

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

    def get_block_by_offset(self, offset):
        for block in self.__blocks_start.values():
            if block.has_offset(offset):
                return block
        return None

    def __handle_try_block(self, try_offset, try_length, handler_offset, handler_length, exc):
        self.__parse_block(try_offset, try_offset + try_length, True, False, False, False, exc)
        self.__parse_block(handler_offset, handler_offset + handler_length, False, True, False, False, exc)

    def __handle_finally_block(self, try_offset, try_length, handler_offset, handler_length, exc):
        self.__parse_block(try_offset, try_offset + try_length, True, False, False, False, exc)
        self.__parse_block(handler_offset, handler_offset + handler_length, False, False, True, False, exc)

    def __handle_filter_block(self, try_offset, try_length, handler_offset, handler_length, filter_offset, filter_length, exc):
        self.__parse_block(try_offset, try_offset + try_length, True, False, False, False, exc)
        self.__parse_block(handler_offset, handler_offset + handler_length, False, True, False, False, exc)
        self.__parse_block(filter_offset, filter_offset + filter_length, False, False, False, True, exc)

    def __handle_try_catch_finally_blocks(self):
        """
        Ensure that try catch finally blocks are treated as their own blocks.  
        """
        for exc in self.__exception_blocks:
            clause_flags, try_offset, try_length, handler_offset, handler_length, class_token = exc
            if clause_flags == net_structs.CorILExceptionClause.Exception:
                self.__handle_try_block(try_offset, try_length, handler_offset, handler_length, exc)
            elif clause_flags == net_structs.CorILExceptionClause.Finally:
                self.__handle_finally_block(try_offset, try_length, handler_offset, handler_length, exc)
            elif clause_flags == net_structs.CorILExceptionClause.Fault:
                self.__handle_try_block(try_offset, try_length, handler_offset, handler_length, exc)
            elif clause_flags == net_structs.CorILExceptionClause.Filter:
                filter_size = handler_offset - class_token
                self.__handle_filter_block(try_offset, try_length, handler_offset, handler_length, class_token, filter_size, exc)
            else:
                raise net_exceptions.OperationNotSupportedException()
    
    def get_shortest_path(self, from_offset, to_offset):
        if isinstance(to_offset, FunctionBlock) and isinstance(from_offset, FunctionBlock):
            to_block = to_offset
            from_block = from_offset
        else:
            to_block = self.get_block_by_offset(to_offset)
            from_block = self.get_block_by_offset(from_offset)
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
    
    def __walk_path_max_stack(self, block, already_analyzed):
        if block in already_analyzed:
            return 0
        already_analyzed.append(block)
        max_value = 0
        result = 0
        for instr in block.get_instrs():
            result += instr.get_nstack()
            max_value = max(max_value, result)
        next_val = 0
        for blk in block.get_next():
            val = self.__walk_path_max_stack(blk, already_analyzed)
            next_val = max(val, next_val)
        return max(max_value, next_val)        
    
    def calculate_max_stack_size(self):
        max_val = 0
        already_analyzed = list()
        for block in self.__blocks_start.values():
            max_val = max(self.__walk_path_max_stack(block, already_analyzed), max_val)
        return max_val

    def get_paths_to_block(self, to_offset, from_offset):
        to_block = to_offset
        from_block = from_offset
        if not isinstance(to_block, FunctionBlock) or not isinstance(from_block, FunctionBlock):
            to_block = self.get_block_by_offset(to_block)
            from_block = self.get_block_by_offset(from_block)
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

    def __parse_block(self, start_offset, max_end_offset=-1, is_try=False, is_catch=False, is_finally=False, is_filter=False, exc_clause=None):
        usable_offset = start_offset
        x = self.__instr_offsets[start_offset].get_instr_index()
        if start_offset in self.__blocks_start:
            blk =  self.__blocks_start[start_offset]
            return blk
        else:
            block = self.get_block_by_offset(start_offset)
            if block is None:
                block = FunctionBlock(self.__method_object, self.__disasm_object, self)
                self.__blocks_start[start_offset] = block
            else:
                block = block.split_block(start_offset)
                block.set_exception_handler(exc_clause)
                if is_try:
                    block.mark_block_try()
                if is_catch:
                    block.mark_block_catch()
                if is_finally:
                    block.mark_block_finally()
                if is_filter:
                    block.mark_block_filter()
                self.__blocks_start[start_offset] = block
                return block

        if is_finally:
            block.set_exception_handler(exc_clause)
            block.mark_block_finally()

        if is_catch:
            block.set_exception_handler(exc_clause)
            block.mark_block_catch()

        if is_try:
            block.set_exception_handler(exc_clause)
            block.mark_block_try()

        if is_filter:
            block.set_exception_handler(exc_clause)
            block.mark_block_filter()

        while x >= 0 and x < len(self.__instrs):
            if usable_offset in self.__blocks_start and usable_offset != start_offset:
                new_block = self.__blocks_start[usable_offset]
                if not block.has_next(new_block):
                    block.add_next(new_block)
                break
            if max_end_offset != -1 and usable_offset >= max_end_offset:
                break
            instr = self.__instrs[x]
            opcode = instr.get_opcode()
            block.add_instr(instr)
            if instr.is_branch():
                #leave br and br.s are treated as absolute jumps since they basically are.
                if opcode == Opcodes.Br or opcode == Opcodes.Br_S or opcode == Opcodes.Leave or opcode == Opcodes.Leave_S:
                    potential_offset = usable_offset + len(instr) + instr.get_argument()
                    if opcode == Opcodes.Br or opcode == Opcodes.Br_S:
                        new_block = self.__parse_block(potential_offset, max_end_offset, is_try, is_catch, is_finally, is_filter, exc_clause)
                    else:
                        #check if it should be marked as filters etc.
                        should_be_try = False
                        should_be_catch = False
                        should_be_finally = False
                        should_be_filter = False
                        clause_flags = exc_clause[0]
                        if clause_flags == net_structs.CorILExceptionClause.Exception or clause_flags == net_structs.CorILExceptionClause.Fault or net_structs.CorILExceptionClause.Finally:
                            try_offset = exc_clause[1]
                            try_end = exc_clause[2] + try_offset
                            handler_offset = exc_clause[3]
                            handler_end = exc_clause[4] + handler_offset
                            if try_offset <= potential_offset < try_end:
                                should_be_try = True
                            elif handler_offset <= potential_offset < handler_end:
                                if clause_flags == net_structs.CorILExceptionClause.Finally:
                                    should_be_finally = True
                                else:
                                    should_be_catch = True
                        elif clause_flags == net_structs.CorILExceptionClause.Filter:
                            try_offset = exc_clause[1]
                            try_end = exc_clause[2] + try_offset
                            handler_offset = exc_clause[3]
                            handler_end = exc_clause[4] + handler_offset
                            filter_offset = exc_clause[5]
                            filter_end = filter_offset + (handler_offset - filter_offset)
                            if try_offset <= potential_offset < try_end:
                                should_be_try = True
                            elif handler_offset <= potential_offset < handler_end:
                                should_be_catch = True
                            elif filter_offset <= potential_offset < filter_end:
                                should_be_filter = True
                        if not should_be_try and not should_be_catch and not should_be_filter and not should_be_finally:
                            new_block = self.__parse_block(potential_offset, -1, should_be_try, should_be_catch, should_be_finally, should_be_filter, exc_clause)

                        else:
                            new_block = self.__parse_block(potential_offset, max_end_offset, should_be_try, should_be_catch, should_be_finally, should_be_filter, exc_clause)

                    usable_block = self.get_block_by_offset(
                        usable_offset)
                    if new_block is None:
                        raise net_exceptions.InvalidBlockException
                    usable_block.add_next(new_block)
                else:
                    if opcode == Opcodes.Switch:
                        targets = instr.get_argument()
                        for target in targets:
                            new_block = self.__parse_block(target, max_end_offset, is_try, is_catch, is_finally, is_filter, exc_clause)
                            usable_block = self.get_block_by_offset(
                                usable_offset)
                            usable_block.add_next(new_block)
                            new_block.mark_switch_case()

                        fallthrough_offset = instr.get_instr_offset() + len(instr)
                        new_block = self.__parse_block(
                            fallthrough_offset, max_end_offset, is_try, is_catch, is_finally, is_filter, exc_clause)
                        usable_block = self.get_block_by_offset(
                            usable_offset)
                        usable_block.add_next(new_block)
                        new_block.mark_switch_case()

                    else:
                        #this block of code is to handle conditional branches.
                        potential_offset1 = usable_offset + \
                            len(instr) + instr.get_argument()
                        potential_offset2 = usable_offset + len(instr)
                        new_block = self.__parse_block(
                            potential_offset1, max_end_offset, is_try, is_catch, is_finally, is_filter, exc_clause)
                        usable_block = self.get_block_by_offset(
                            usable_offset)
                        usable_block.add_next(new_block)
                        new_block = self.__parse_block(
                            potential_offset2, max_end_offset, is_try, is_catch, is_finally, is_filter, exc_clause)
                        usable_block = self.get_block_by_offset(
                            usable_offset)
                        usable_block.add_next(new_block)
                break
            else:
                if opcode == Opcodes.Throw:
                    break

            usable_offset += len(instr)

            if opcode == Opcodes.Ret or opcode == Opcodes.Endfinally:
                break

            if instr.is_branch():
                break

            x = self.__instr_offsets[usable_offset].get_instr_index()
        block.validate_block()
        if block is None:
            raise net_exceptions.InvalidBlockException
        return block

    def print_root(self):
        dont_print_again = set()
        print('Printing graph for method {} {}'.format(self.__method_object, hex(self.__method_object.get_token())))
        print('Calculated max stack {}'.format(self.calculate_max_stack_size()))
        self.__print_block(self.__root_block, dont_print_again)

    def debug_print_blocks(self):
        print('debug printing blocks')
        for block in self.__blocks_start.values():
            print('Block {}'.format(hex(block.get_start_offset())))
            for instr in block.get_instrs():
                print('{}: {}'.format(hex(instr.get_instr_offset()), instr.get_name()))

    def debug_print_nexts(self):
        block: FunctionBlock
        print('Debug printing blocks')
        for block in self.__blocks_start.values():
            print('Block {} is_junk={} is_switch_case={}'.format(hex(block.get_start_offset()), block.is_junk_block(), block.is_switch_case()))
            nxt: FunctionBlock
            for nxt in block.get_next():
                print('Next: {}'.format(hex(nxt.get_start_offset())))

    def update_offsets(self):
        blocks = dict(self.__blocks_start)
        self.__blocks_start.clear()
        for offset, block in blocks.items():
            self.__blocks_start[block.get_start_offset()] = block

        self.__instr_offsets.clear()
        for offset, block in blocks.items():
            for instr in block.get_instrs():
                self.__instr_offsets[instr.get_instr_offset()] = instr
    
    def unregister_block(self, offset):
        del self.__blocks_start[offset]

    def get_block_offsets(self):
        return self.__blocks_start
    
    def blocks(self):
        return self.__blocks_start.values()
    
    def __stack_checker(self, block, stack_count, checked):
        curr_count = stack_count
        for instr in block.get_instrs():
            needed = instr.get_pstack()
            if curr_count < needed:
                print('error on stack at {} {} {}: not enough elements'.format(hex(instr.get_instr_offset()), instr.get_name(), instr.get_argument()))
                raise Exception()
            curr_count += instr.get_nstack()

        for nxt in block.get_next():
            if (block.get_start_offset(), nxt.get_start_offset()) not in checked:
                checked.append((block.get_start_offset(), nxt.get_start_offset()))
                self.__stack_checker(nxt, curr_count, checked)

    def stack_checker(self):
        checked = list()
        self.__stack_checker(self.__blocks_start[0], 0, checked)

    def __print_block(self, block, already_printed, indent=0):
        instrs = block.get_instrs()
        is_block_try = False
        is_leave = False

        if block.get_start_offset() not in already_printed:
            print((' ' * indent) + 'Printing block with offset {} size {} num_instrs {} (is junk: {}, is switch case: {}, is_try: {}, is_catch: {}, is_finally: {}, is_filter: {})'.format(
                hex(block.get_start_offset()), hex(block.get_original_length()), len(block.get_instrs()), block.is_junk_block(), block.is_switch_case(), block.is_block_try(), block.is_block_catch(), block.is_block_finally(), block.is_block_filter()))
            exc_handler = block.get_exception_handler()
            if block.is_block_try():
                if exc_handler[1] == block.get_start_offset():
                    is_block_try = True
                    print((' ' * indent) + 'try:')
                    indent += 4
            elif block.is_block_catch():
                if exc_handler[3] == block.get_start_offset():
                    print((' ' * indent) + 'catch:')
                    indent += 4
            elif block.is_block_finally():
                if exc_handler[3] == block.get_start_offset():
                    print((' ' * indent) + 'finally:')
                    indent += 4
            elif block.is_block_filter():
                if exc_handler[5] == block.get_start_offset():
                    print((' ' * indent) + 'filter:')
                    indent += 4

            already_printed.add(block.get_start_offset())
            for instr in block.get_instrs():
                if instr.is_branch() and not instr.is_absolute_jmp():
                    break
                if instr.is_absolute_jmp():
                    print((' ' * indent) + '{}: jump to {}'.format(hex(instr.get_instr_offset()),
                                                  hex(instr.get_instr_offset() + len(instr) + instr.get_argument())))
                else:
                    print((' ' * indent) + '{}: {} {}'.format(hex(instr.get_instr_offset()), instr.get_name(),
                                             instr.get_argument()))

            if instrs[-1].get_opcode() == Opcodes.Switch:
                print((' ' * indent) + 'switch ({}):'.format(hex(instrs[-1].get_instr_offset())))
                x = 0
                for case in instrs[-1].get_argument():
                    print( (' ' * (indent + 4)) +'case {}: ({}:{})'.format(x, hex(case), hex(instrs[-1].get_instr_offset())))
                    self.__print_block(self.get_block_by_offset(case), already_printed, indent + 8)
                    x += 1
                fallthrough = instrs[-1].get_instr_offset() + len(instrs[-1])
                fallthrough = self.get_block_by_offset(fallthrough)
                print((' ' * (indent + 4)) + 'default({}:{}):'.format(hex(fallthrough.get_start_offset()), hex(instrs[-1].get_instr_offset())))
                self.__print_block(fallthrough, already_printed, indent + 8)

            else:
                if instrs[-1].is_branch() and not instrs[-1].is_absolute_jmp():
                    print((' ' * indent) + 'if ({}): {} {}'.format(hex(instrs[-1].get_instr_offset()), instrs[-1].get_name(),instrs[-1].get_argument()))
                    self.__print_block(block.get_next()[0], already_printed, indent + 4)
                    print((' ' * indent ) + 'else ({}):'.format(hex(instrs[-1].get_instr_offset())))
                    if len(block.get_next()) == 1:
                        print((' ' * (indent + 4)) + 'Error: No secondary block!!!!')
                    else:
                        self.__print_block(block.get_next()[1], already_printed, indent + 4)
                else:
                    if instrs[-1].get_opcode() == Opcodes.Leave or instrs[-1].get_opcode() == Opcodes.Leave_S:
                        is_leave = True
                    if is_leave:
                        next_block = block.get_next()[0]

                        if block.is_block_try() and next_block.is_block_try():
                            is_leave = False
                    if not is_leave:
                        if not instrs[-1].is_branch() and len(block.get_next()) == 1:
                            self.__print_block(
                                block.get_next()[0], already_printed, indent)
                        elif instrs[-1].is_absolute_jmp() and instrs[-1].is_branch():
                            self.__print_block(block.get_next()[0], already_printed, indent)
            if is_block_try:
                catch_block = self.get_block_by_offset(exc_handler[3])
                if catch_block is None:
                    print((' ' * indent) + 'could not find catch block at offset {}'.format(hex(exc_handler[3])))
                else:
                    if exc_handler[0] == net_structs.CorILExceptionClause.Exception:
                        self.__print_block(catch_block, already_printed, indent - 4)
                for exc in self.__exception_blocks:
                    flags = exc[0]
                    if flags != net_structs.CorILExceptionClause.Finally:
                        continue
                    try_offset = exc[1]
                    if block.get_start_offset() == try_offset:
                        finally_offset = exc[3]
                        finally_block = self.get_block_by_offset(finally_offset)
                        if finally_block is None:
                            print((' ' * indent) + 'Could not find finally block at offset {}'.format(hex(finally_offset)))
                        else:
                            self.__print_block(finally_block, already_printed, indent - 4)
            if is_leave:
                next_block = block.get_next()[0]
                if next_block.get_start_offset() not in already_printed:
                    if not instrs[-1].is_branch() and len(block.get_next()) == 1:
                        self.__print_block(next_block, already_printed, indent - 4)
                    elif instrs[-1].is_absolute_jmp() and instrs[-1].is_branch():
                        self.__print_block(next_block, already_printed, indent - 4)
        else:
            print((' ' * indent) + 'goto block {}'.format(hex(block.get_start_offset())))

    def emit_instructions_as_list(self):
        if self.__disasm_object is None:
            raise Exception('Cant emit a instruction without a disassembler object.')
        current_offset = 0
        result = list()
        current_index = 0
        for offset, block in self.__blocks_start.items():
            if offset > current_offset:
                amt_pad = offset - current_offset
                for x in range(amt_pad):
                    #If a branch is just not used, the graph will ignore it.  Account for that here.
                    instr = self.__disasm_object.emit_instruction(0x0)
                    instr.setup_instr_size(1)
                    instr.setup_instr_offset(current_offset, current_index)
                    result.append(instr)
                    current_index += 1
                    current_offset += 1
            assert current_offset == offset
            for instr in block.get_instrs():
                instr.setup_instr_offset(current_offset, current_index)
                result.append(instr)
                current_offset += len(instr)
                current_index += 1
        return result
    
    def set_exception_blocks(self, exc_blocks):
        self.__exception_blocks = exc_blocks

class GraphAnalyzer:
    def __init__(self, method_obj: net_row_objects.MethodDefOrRef, func_graph: FunctionGraph):
        self.__graph = func_graph
        self.__disasm = self.__graph.get_disassembler()
        self.__method = method_obj

    """
    An attempt at control flow deobfuscation.
    """

    def __repair_switch_block(self, block, start_offset, output_graph):
        last_instr = block.get_last_instr()

    def __target_walker(self, block, nstack, already_checked):
        """
        This method is definitely going to need some testing and work but I mean its okay for now.
        """
        MATH_OPS = [Opcodes.Not, Opcodes.Sub, Opcodes.Add, Opcodes.Neg, Opcodes.Xor, Opcodes.Shr, Opcodes.Shl, Opcodes.Or, Opcodes.Shr_Un, Opcodes.And, Opcodes.Mul, Opcodes.Div, Opcodes.Div_Un, Opcodes.Rem, Opcodes.Rem_Un]
        ALLOWED_STACK_OPS = [Opcodes.Br, Opcodes.Br_S, Opcodes.Ldc_I4, Opcodes.Ldc_I4_S, Opcodes.Ldloc, Opcodes.Ldloc_S, Opcodes.Dup, Opcodes.Ldc_I4_M1, Opcodes.Ldc_I4_0, Opcodes.Ldc_I4_1, Opcodes.Ldc_I4_2, Opcodes.Ldc_I4_3, Opcodes.Ldc_I4_5, Opcodes.Ldc_I4_6, Opcodes.Ldc_I4_7, Opcodes.Ldc_I4_8]
        current_nstack = nstack
        instrs = block.get_instrs()
        if block.get_start_offset() in already_checked:
            return False
        block_nstack = block.get_nstack()
        already_checked.append(block.get_start_offset())
        for x in range(len(instrs) - 1, -1, -1):
            instr = instrs[x]
            ins_op = instr.get_opcode()
            if instr.get_pstack() > (current_nstack + 1) and instr.get_opcode() not in (MATH_OPS + ALLOWED_STACK_OPS):
                return False
            elif current_nstack == 0 and instr.get_opcode() not in (MATH_OPS + ALLOWED_STACK_OPS):
                return True
            if instr.get_pstack() == 0 and current_nstack == 0:
                return True
            current_nstack += instr.get_nstack()
        if current_nstack != block_nstack:
            for prev in block.get_prev():
                if not self.__target_walker(prev, current_nstack, already_checked):
                    return False
            return True
        else:
            return True

    def __is_target_switch(self, block):
        #check if all paths have a relatively constant value.
        instrs = block.get_instrs()
        MATH_OPS = [Opcodes.Not, Opcodes.Sub, Opcodes.Add, Opcodes.Neg, Opcodes.Xor, Opcodes.Shr, Opcodes.Shl, Opcodes.Or, Opcodes.Shr_Un, Opcodes.And, Opcodes.Mul, Opcodes.Div, Opcodes.Div_Un, Opcodes.Rem, Opcodes.Rem_Un]
        ALLOWED_STACK_OPS = [Opcodes.Br, Opcodes.Br_S, Opcodes.Ldc_I4, Opcodes.Ldc_I4_S, Opcodes.Stloc, Opcodes.Stloc_S, Opcodes.Ldloc, Opcodes.Ldloc_S, Opcodes.Dup, Opcodes.Ldc_I4_M1, Opcodes.Ldc_I4_0, Opcodes.Ldc_I4_1, Opcodes.Ldc_I4_2, Opcodes.Ldc_I4_3, Opcodes.Ldc_I4_5, Opcodes.Ldc_I4_6, Opcodes.Ldc_I4_7, Opcodes.Ldc_I4_8]
        if len(instrs) < 2:
            print(1)
            return False
        if instrs[-2].get_opcode() not in MATH_OPS:
            print(2)
            return False
        if block.get_last_instr().get_opcode() != Opcodes.Switch:
            print(3)
            return False
        #make sure theres at least one branch thats a fall through or a 1-1 ration
        already_checked = list()
        return self.__target_walker(block, 1, already_checked)
            
        

    





    def __simplify_control_flow(self, block, already_done, output_graph):
        if block.get_start_offset() not in already_done:
            already_done.add(block.get_start_offset())
            last_instr = block.get_last_instr()
            last_opcode = last_instr.get_opcode()
            if last_opcode == Opcodes.Switch:
                if self.__is_target_switch(block):
                    print('Block {} is target switch'.format(hex(block.get_start_offset())))

    def simplify_control_flow(self):
        already_done = set()
        out = FunctionGraph(self.__method, None, None, False, False)
        block = self.__graph.get_block_by_offset(0)
        for block in self.__graph.blocks():
            print('checking block {}'.format(hex(block.get_start_offset())))
            if self.__is_target_switch(block):
                print('is target switch {}'.format(hex(block.get_start_offset())))
        return out

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
                            
    def repair_blocks(self):
        #repair the relations between blocks and such
        original_blocks = dict()
        for offset, block in self.__graph.get_block_offsets().items():
            original_blocks[offset] = offset + block.get_original_length()
        changed_blocks = dict()
        current_offset = 0
        current_index = 0
        current_offsets = dict()

        for offset, block in self.__graph.get_block_offsets().items(): #This will already be sorted.
            instrs = block.get_instrs()
            block.setup_new_block_location(current_offset, current_index)
            changed_blocks[offset] = current_offset
            index = 0
            new_instr = None
            start_offset = current_offset
            for instr in instrs:
                opcode = instr.get_opcode()
                if instr.is_absolute_jmp() or instr.is_branch():
                    if opcode != Opcodes.Switch:
                        current_offsets[current_offset] = instr.get_instr_offset() + len(instr) + instr.get_argument()
                    else:
                        current_offsets[current_offset] = instr.get_argument()
                if instr.is_absolute_jmp():
                    if opcode == Opcodes.Leave_S:
                        new_instr = self.__disasm.emit_instruction(Opcodes.Leave)
                        new_instr.setup_arguments_from_int32(instr.get_argument())
                        new_instr.setup_instr_offset(current_offset, current_index)
                        new_instr.setup_instr_size(5)
                        block.replace_instr(index, new_instr)
                    elif opcode == Opcodes.Br_S:
                        new_instr = self.__disasm.emit_instruction(Opcodes.Br)
                        new_instr.setup_arguments_from_int32(instr.get_argument())
                        new_instr.setup_instr_offset(current_offset, current_index)
                        new_instr.setup_instr_size(5)
                        block.replace_instr(index, new_instr)
                elif instr.is_branch():
                    if opcode == Opcodes.Beq_S:
                        new_instr = self.__disasm.emit_instruction(Opcodes.Beq)
                    elif opcode == Opcodes.Bge_S:
                        new_instr = self.__disasm.emit_instruction(Opcodes.Bge)
                    elif opcode == Opcodes.Bgt_S:
                        new_instr = self.__disasm.emit_instruction(Opcodes.Bgt)
                    elif opcode == Opcodes.Ble_S:
                        new_instr = self.__disasm.emit_instruction(Opcodes.Ble)
                    elif opcode == Opcodes.Blt_S:
                        new_instr = self.__disasm.emit_instruction(Opcodes.Blt)
                    elif opcode == Opcodes.Bne_Un_S:
                        new_instr = self.__disasm.emit_instruction(Opcodes.Bne_Un)
                    elif opcode == Opcodes.Bge_Un_S:
                        new_instr = self.__disasm.emit_instruction(Opcodes.Bge_Un)
                    elif opcode == Opcodes.Bgt_Un_S:
                        new_instr = self.__disasm.emit_instruction(Opcodes.Bgt_Un)
                    elif opcode == Opcodes.Ble_Un_S:
                        new_instr = self.__disasm.emit_instruction(Opcodes.Ble_Un)
                    elif opcode == Opcodes.Blt_Un_S:
                        new_instr = self.__disasm.emit_instruction(Opcodes.Blt_Un)
                    if new_instr is not None:
                        new_instr.setup_arguments_fmo_int32(instr.get_argument())
                        new_instr.setup_instr_offset(current_offset, current_index)
                        new_instr.setup_instr_size(5)
                        block.replace_instr(index, new_instr)

                if new_instr is None:
                    instr.setup_instr_offset(current_offset, current_index)
                if new_instr is not None:
                    current_offset += len(new_instr)
                else:
                    current_offset += len(instr)
                current_index += 1
                index += 1
            block.update_size(current_offset - start_offset)
            block.update_start_offset(block.get_new_offset(), block.get_new_index())

        self.__graph.update_offsets()

        #first pass makes sure that block and instruction offsets are initialized.
        #second pass is for adjusting branches
        for new_offset, old_argument in current_offsets.items():
            blk = self.__graph.get_block_by_offset(new_offset)
            instr = blk.get_last_instr()
            if new_offset != instr.get_instr_offset():
                raise net_exceptions.OperationNotSupportedException()
            
            if instr.get_opcode() != Opcodes.Switch:
                new_target = changed_blocks[old_argument]
                #target = instr.offset + len(instr) + argument
                #argument   = target - instr.offset - len(instr)
                argument = new_target - instr.get_instr_offset() - len(instr)
                instr.setup_arguments_from_int32(argument)
            else:
                args = list()
                for target in old_argument:
                    new_target = changed_blocks[target]
                    argument = new_target - instr.get_instr_offset() - len(instr)
                    args.append(argument)
                instr.setup_arguments_from_argslist(args)

            exceptions = self.__graph.get_exception_blocks()
            new_handlers = list()
            for exc in exceptions:
                clause_flags, try_offset, try_length, catch_offset, catch_length, token = exc
                new_try_offset = changed_blocks[try_offset]
                new_catch_offset = changed_blocks[catch_offset]
                new_token = token
                new_try_length = try_length
                new_catch_length = catch_length
                if clause_flags == net_structs.CorILExceptionClause.Fault:
                    new_token = changed_blocks[token]
                
                total_try_size = 0
                total_catch_size = 0
                block: FunctionBlock
                for block in self.__graph.blocks():
                    exc_handler = block.get_exception_handler()
                    if block.is_block_try():
                        if exc_handler[1] == try_offset:
                            total_try_size += block.get_original_length()
                    elif block.is_block_catch() or block.is_block_finally():
                        if exc_handler[3] == catch_offset:
                            total_catch_size += block.get_original_length()
                new_try_length = total_try_size
                new_catch_length = total_catch_size
                new_handler = [clause_flags, new_try_offset, new_try_length, new_catch_offset, new_catch_length, new_token]
                new_handlers.append(new_handler)
            for x in range(len(exceptions)):
                old_handler = exceptions[x]
                new_handler = new_handlers[x]
                for block in self.__graph.blocks():
                    exc_handler = block.get_exception_handler()
                    if exc_handler == old_handler:
                        block.set_exception_handler(new_handler)
            self.__graph.set_exception_blocks(new_handlers)

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
        block: FunctionBlock
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
        if len(self.__exception_blocks) != 0:
            use_fat = True

        fgraph = FunctionGraph(None, self.__instrs, self.__exception_blocks)
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
                result.extend(instr.to_bytes())

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